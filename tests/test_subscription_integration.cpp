// CR-004 §12 集成测试：业务订阅快照端到端
// 覆盖：首次启动两种先后顺序、MQTT 重启重提交、REJECTED 整体回滚保留旧 generation、
//       新 generation 原子替换、本地 ACCEPTED ≠ SUBACK/Cloud Ready、FOTA 用目录 Topic。
#include <gtest/gtest.h>
#include "subscription_registrar.h"
#include "subscription_catalog.h"
#include "subscription_store.h"
#include "vehicle_message_gateway.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/types.h"
#include "mocks.h"
#include "vehicle_message_test_util.h"
#include "yaml-cpp/yaml.h"

#include <chrono>
#include <cstdlib>
#include <thread>

using namespace tbox::tsp;
using namespace tbox::tsp::test;

namespace {

std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_subint_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}

const char* kCatalogYaml =
    "- route_id: fota.uplink\n"
    "  topic_template: vehicle/{ecu_uid}/up/fota\n"
    "  direction: UP\n"
    "  qos: 1\n"
    "  target: tsp.fota\n"
    "  mandatory: false\n"
    "- route_id: fota.downlink\n"
    "  topic_template: vehicle/{ecu_uid}/down/fota\n"
    "  direction: DOWN\n"
    "  qos: 1\n"
    "  target: tsp.fota\n"
    "  mandatory: true\n";

std::shared_ptr<SubscriptionCatalog> make_catalog() {
    auto cat = std::make_shared<SubscriptionCatalog>();
    std::string err;
    EXPECT_TRUE(cat->load_from_yaml(YAML::Load(kCatalogYaml), err)) << err;
    return cat;
}

bool wait_for(MqttSubscriptionRegistrar& r, std::function<bool()> pred,
              int timeout_ms = 1500) {
    for (int i = 0; i < timeout_ms / 20; ++i) {
        if (pred()) return true;
        r.tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

} // namespace

class SubscriptionIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        catalog_ = make_catalog();
        store_ = std::make_shared<SubscriptionStore>(temp_root());
        registrar_ = std::make_unique<MqttSubscriptionRegistrar>(
            mqtt_, catalog_, store_);
    }
    void TearDown() override { if (registrar_) registrar_->stop(); }

    std::shared_ptr<MockMqttFacade> mqtt_;
    std::shared_ptr<SubscriptionCatalog> catalog_;
    std::shared_ptr<SubscriptionStore> store_;
    std::unique_ptr<MqttSubscriptionRegistrar> registrar_;
};

// 首次启动：MQTT 先就绪，TSP 启动即提交 -> REGISTERED (CR-004 §6, §12)
TEST_F(SubscriptionIntegrationTest, MqttReadyFirstAccepted) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;

    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    EXPECT_EQ(registrar_->status().generation, 1u);
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);
    EXPECT_TRUE(registrar_->is_registration_ready());
    // 本地 ACCEPTED ≠ Broker SUBACK / Cloud Ready (CR-004 §1, REQ §4.2)
    EXPECT_EQ(registrar_->status().last_result, SnapshotStatus::ACCEPTED);
}

// 首次启动：TSP 先提交、MQTT 后连接 (CR-004 §6, §12)
TEST_F(SubscriptionIntegrationTest, TspFirstThenMqttConnects) {
    mqtt_->connected = false;  // MQTT 未就绪
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;  // 连上后接受
    ASSERT_TRUE(registrar_->start(false));
    // 已尝试本地提交，不阻塞启动
    EXPECT_TRUE(registrar_->is_registration_ready());
    EXPECT_NE(registrar_->status().state, RegistrationState::REGISTERED);

    // MQTT 连接恢复 -> 重连重提交（相同 generation）
    mqtt_->connected = true;
    ASSERT_TRUE(wait_for(*registrar_,
        [&] { return registrar_->status().state == RegistrationState::REGISTERED; },
        1500));
    EXPECT_EQ(registrar_->status().generation, 1u);  // 同 generation
    EXPECT_GE(mqtt_->snapshot_call_count(), 2u);
    for (const auto& snap : mqtt_->snapshot_calls()) {
        EXPECT_EQ(snap.generation, 1u);  // 全程相同 generation
    }
}

// MQTT 重启：REGISTERED -> 断开 NOT_REGISTERED -> 重连重提交 (CR-004 §7, §12)
TEST_F(SubscriptionIntegrationTest, MqttRestartResubmits) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);

    mqtt_->connected = false;
    registrar_->tick();
    EXPECT_EQ(registrar_->status().state, RegistrationState::NOT_REGISTERED);

    mqtt_->connected = true;
    registrar_->tick();
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    ASSERT_EQ(mqtt_->snapshot_call_count(), 2u);
    EXPECT_EQ(mqtt_->snapshot_calls().back().generation, 1u);
}

// REJECTED 整体回滚：业务变更被拒，保留旧 generation 与旧集合 (CR-004 §8, §12)
TEST_F(SubscriptionIntegrationTest, RejectedChangeKeepsOldGeneration) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    uint64_t gen_before = registrar_->status().generation;
    ASSERT_EQ(catalog_->items().size(), 2u);

    // 变更：新增一条路由 -> 新 generation；但 MQTT 拒绝
    mqtt_->snapshot_result.status = SnapshotStatus::REJECTED;
    mqtt_->snapshot_result.reason_code = "route_register_failed";
    auto items = catalog_->items();
    items.push_back({"remote.uplink", "vehicle/{ecu_uid}/up/remote",
                     Direction::UP, 1, "tsp.remote", false});
    ASSERT_TRUE(registrar_->apply_catalog_change(items));

    // 旧 generation 保留、旧集合保留（catalog 仍 2 项）
    EXPECT_EQ(registrar_->status().state, RegistrationState::DEGRADED);
    EXPECT_EQ(registrar_->status().generation, gen_before);
    EXPECT_EQ(catalog_->items().size(), 2u);
}

// 新 generation 原子替换：ACCEPTED 后切换 (CR-004 §8, §12)
TEST_F(SubscriptionIntegrationTest, AcceptedChangeAtomicReplace) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(registrar_->status().generation, 1u);

    auto items = catalog_->items();
    items[0].qos = 2;  // 语义变化
    ASSERT_TRUE(registrar_->apply_catalog_change(items));

    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    EXPECT_EQ(registrar_->status().generation, 2u);
    EXPECT_EQ(catalog_->items()[0].qos, 2u);
    ASSERT_GE(mqtt_->snapshot_call_count(), 2u);
    EXPECT_EQ(mqtt_->snapshot_calls().back().generation, 2u);
}

// FOTA 上行经 VehicleMessageGateway 使用目录 Route（CR-009 §Route 映射）
TEST_F(SubscriptionIntegrationTest, FotaUplinkUsesCatalogRoute) {
    mqtt_->connected = true;
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    ASSERT_TRUE(registrar_->start(false));

    // 真实 gateway：按 catalog 稳定 route_id 上行，不展开 Topic/不缓存 UID
    VehicleMessageGatewayConfig cfg;
    cfg.limits.allowed_services = {"vehicle.fota"};
    cfg.limits.allowed_protocol_majors = {1};
    cfg.default_exchange_timeout_ms = 200;
    VehicleMessageGateway gw(mqtt_);
    ASSERT_TRUE(gw.initialize(cfg));
    ASSERT_TRUE(gw.start());

    ExchangeOptions opt;
    opt.timeout = std::chrono::milliseconds(100);
    auto r = gw.exchange(to_msg(make_request_envelope("m-up")), opt, CallContext{});

    // 上行按 owner=tsp + route_id=fota.uplink（目录 SSOT），不传完整 Topic/UID
    ASSERT_EQ(mqtt_->publish_route_calls().size(), 1u);
    EXPECT_EQ(mqtt_->publish_route_calls()[0].owner, "tsp");
    EXPECT_EQ(mqtt_->publish_route_calls()[0].route_id, "fota.uplink");
    EXPECT_EQ(mqtt_->publish_route_calls()[0].msg_id, "m-up");
    // 无业务 RESPONSE -> 超时（Timeout）
    EXPECT_EQ(r.outcome, TransportOutcome::Timeout);
    gw.stop();
}

// 响应丢失后相同 generation 幂等重试 (CR-004 §5, §11.3, §12)
TEST_F(SubscriptionIntegrationTest, ResponseLossIdempotentRetry) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::UNKNOWN;
    ASSERT_TRUE(registrar_->start(false));

    // 多次重试，generation 始终为 1
    ASSERT_TRUE(wait_for(*registrar_,
        [&] { return mqtt_->snapshot_call_count() >= 3; }, 2000));
    for (const auto& snap : mqtt_->snapshot_calls()) {
        EXPECT_EQ(snap.generation, 1u);
    }

    // 恢复后最终 ACCEPTED
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(wait_for(*registrar_,
        [&] { return registrar_->status().state == RegistrationState::REGISTERED; },
        2000));
    EXPECT_EQ(registrar_->status().generation, 1u);
}

// 删除订阅通过新快照缺少对应 route_id 表达 (CR-004 §8, §11.4)
TEST_F(SubscriptionIntegrationTest, DeleteRouteViaMissingRouteId) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(catalog_->items().size(), 2u);

    // 新快照仅保留 downlink（删除 uplink）
    std::vector<SubscriptionItem> fewer;
    for (const auto& it : catalog_->items()) {
        if (it.direction == Direction::DOWN) fewer.push_back(it);
    }
    ASSERT_EQ(fewer.size(), 1u);
    ASSERT_TRUE(registrar_->apply_catalog_change(fewer));

    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    EXPECT_EQ(registrar_->status().generation, 2u);
    EXPECT_EQ(catalog_->items().size(), 1u);  // uplink 已删除
}

// 安全：store 不泄露完整设备 Topic / 身份实例值 (CR-004 §12 安全测试)
TEST_F(SubscriptionIntegrationTest, StoreNoLeakOfDeviceIdentityOrTopic) {
    mqtt_->connected = true;
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));

    // SubscriptionStore 不接触设备身份（registrar 身份无关）；
    // store 仅持久化 generation 与 content_digest（SHA-256 hex），
    // 不得包含展开后的设备 Topic 或身份实例值。
    uint64_t gen = 0;
    std::string digest;
    ASSERT_TRUE(store_->load(gen, digest));
    EXPECT_EQ(gen, 1u);
    EXPECT_EQ(digest.size(), 64u);  // SHA-256 hex
    EXPECT_EQ(digest.find("vehicle"), std::string::npos);
    EXPECT_EQ(digest.find("ECU"), std::string::npos);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
