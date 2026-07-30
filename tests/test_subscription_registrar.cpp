// CR-004 §12 单元测试：订阅快照注册器（提交/状态/幂等/断连恢复/原子替换）
#include <gtest/gtest.h>
#include "subscription_registrar.h"
#include "subscription_catalog.h"
#include "subscription_store.h"
#include "mocks.h"
#include "yaml-cpp/yaml.h"

#include <chrono>
#include <cstdlib>
#include <thread>

using namespace tbox::tsp;
using namespace tbox::tsp::test;

namespace {

std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_reg_test_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}

std::shared_ptr<SubscriptionCatalog> make_catalog() {
    auto cat = std::make_shared<SubscriptionCatalog>();
    std::string err;
    EXPECT_TRUE(cat->load_from_yaml(YAML::Load(
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
        "  mandatory: true\n"), err)) << err;
    return cat;
}

// 轮询 tick 直到谓词为真或超时
bool wait_for(MqttSubscriptionRegistrar& r,
              std::function<bool()> pred, int timeout_ms = 1000) {
    for (int i = 0; i < timeout_ms / 20; ++i) {
        if (pred()) return true;
        r.tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

} // namespace

class RegistrarTest : public ::testing::Test {
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

// 首次提交 ACCEPTED -> REGISTERED (CR-004 §6, §9)
TEST_F(RegistrarTest, StartAccepted) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));

    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    EXPECT_EQ(registrar_->status().generation, 1u);
    EXPECT_EQ(registrar_->status().last_result, SnapshotStatus::ACCEPTED);
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);
    EXPECT_TRUE(registrar_->is_registration_ready());
}

// REJECTED -> DEGRADED (CR-004 §9)
TEST_F(RegistrarTest, StartRejectedDegraded) {
    mqtt_->snapshot_result.status = SnapshotStatus::REJECTED;
    mqtt_->snapshot_result.reason_code = "route_register_failed";
    ASSERT_TRUE(registrar_->start(false));

    EXPECT_EQ(registrar_->status().state, RegistrationState::DEGRADED);
    EXPECT_EQ(registrar_->status().last_result, SnapshotStatus::REJECTED);
    EXPECT_TRUE(registrar_->is_registration_ready());  // 已尝试本地提交，不阻塞启动
}

// UNKNOWN -> REGISTERING，相同 generation 重试 (CR-004 §5, §11.3)
TEST_F(RegistrarTest, StartUnknownRetriesSameGeneration) {
    mqtt_->snapshot_result.status = SnapshotStatus::UNKNOWN;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERING);

    // 退避后重试，generation 不变
    ASSERT_TRUE(wait_for(*registrar_,
        [&] { return mqtt_->snapshot_call_count() >= 2; }, 1500));
    EXPECT_EQ(mqtt_->snapshot_calls().back().generation, 1u);
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERING);
}

// 幂等：REGISTERED 后 tick 不重复提交 (CR-004 §5)
TEST_F(RegistrarTest, IdempotentNoResubmitWhenRegistered) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);

    for (int i = 0; i < 5; ++i) {
        registrar_->tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);  // 不重复提交
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
}

// MQTT 断开 -> NOT_REGISTERED；重连 -> 相同 generation 重新提交 (CR-004 §7, §11.3)
TEST_F(RegistrarTest, DisconnectThenReconnectResubmits) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);

    // 断开
    mqtt_->connected = false;
    registrar_->tick();
    EXPECT_EQ(registrar_->status().state, RegistrationState::NOT_REGISTERED);
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);  // 断开不提交

    // 重连 -> 相同 generation 重新提交
    mqtt_->connected = true;
    registrar_->tick();
    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    ASSERT_EQ(mqtt_->snapshot_call_count(), 2u);
    EXPECT_EQ(mqtt_->snapshot_calls().back().generation, 1u);  // 同 generation
}

// 业务变更：新 generation 原子替换 (CR-004 §8)
TEST_F(RegistrarTest, ApplyCatalogChangeNewGeneration) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(registrar_->status().generation, 1u);

    // 修改 QoS -> 语义变化 -> 新 generation
    auto items = catalog_->items();
    ASSERT_FALSE(items.empty());
    items[0].qos = 2;
    ASSERT_TRUE(registrar_->apply_catalog_change(items));

    EXPECT_EQ(registrar_->status().state, RegistrationState::REGISTERED);
    EXPECT_EQ(registrar_->status().generation, 2u);
    ASSERT_EQ(mqtt_->snapshot_call_count(), 2u);
    EXPECT_EQ(mqtt_->snapshot_calls().back().generation, 2u);
}

// 业务变更：摘要未变化不提交
TEST_F(RegistrarTest, ApplyCatalogChangeNoDigestChangeNoop) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);

    // 相同集合 -> 无变化 -> 不提交
    ASSERT_TRUE(registrar_->apply_catalog_change(catalog_->items()));
    EXPECT_EQ(mqtt_->snapshot_call_count(), 1u);
    EXPECT_EQ(registrar_->status().generation, 1u);
}

// 业务变更：影子校验失败不替换 (CR-004 §8, §11.4)
TEST_F(RegistrarTest, ApplyCatalogChangeValidationFailed) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));
    uint64_t gen_before = registrar_->status().generation;

    std::vector<SubscriptionItem> bad = catalog_->items();
    bad.push_back({"fota.uplink", "dup", Direction::UP, 1, "t", false});  // 重复 route_id
    EXPECT_FALSE(registrar_->apply_catalog_change(bad));
    EXPECT_EQ(registrar_->status().generation, gen_before);  // 保留上一已确认
}

// ACCEPTED 后重连重提交仍是相同 generation（幂等语义）
TEST_F(RegistrarTest, ReconnectAfterAcceptedStaysSameGeneration) {
    mqtt_->snapshot_result.status = SnapshotStatus::ACCEPTED;
    ASSERT_TRUE(registrar_->start(false));

    mqtt_->connected = false;
    registrar_->tick();
    mqtt_->connected = true;
    registrar_->tick();

    EXPECT_EQ(registrar_->status().generation, 1u);
    EXPECT_EQ(mqtt_->snapshot_calls()[0].generation, 1u);
    EXPECT_EQ(mqtt_->snapshot_calls()[1].generation, 1u);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
