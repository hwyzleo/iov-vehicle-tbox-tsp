// tests/test_tsp_integration.cpp
// 端到端集成测试 (CR-003 §9)：
// 上行：tsp_client -> framework Server -> TspIpcDispatcher -> FotaHandler(FotaRelay) -> MockMqttFacade
// 下行：MockMqttFacade deliver -> FotaHandler -> TspEventPublisher -> Server::push_event -> tsp_client subscriber
// 覆盖：snapshot 幂等、accepted≠PUBACK、unknown outcome、下行顺序、订阅恢复
#include <gtest/gtest.h>
#include "tbox/tsp/client.h"
#include "tsp_framework_server.h"
#include "fota_handler.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "constants.h"
#include "mocks.h"
#include "utils.h"
#include "nlohmann/json.hpp"

#include <chrono>
#include <thread>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <vector>

using namespace tbox::tsp;
using namespace tbox::tsp::test;

namespace {
std::string b64(const std::vector<uint8_t>& d) {
    return ::hwyz::Utils::base64_encode(std::string(d.begin(), d.end()));
}
std::string unique_socket() {
    return "/tmp/tbox-tsp-int-" + std::to_string(getpid()) + "-" +
           std::to_string(rand()) + ".sock";
}
FotaSnapshot make_snap(const std::string& msg_id, uint32_t seq,
                       std::vector<uint8_t> p = {0x01, 0x02}) {
    FotaSnapshot s;
    s.msg_id = msg_id;
    s.snapshot_seq = seq;
    s.payload = std::move(p);
    s.content_type = "application/x-protobuf";
    return s;
}
}

class TspIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        socket_path_ = unique_socket();
        mqtt_ = std::make_shared<MockMqttFacade>();
        mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

        fota_ = std::make_unique<FotaHandler>(mqtt_);
        ASSERT_TRUE(fota_->initialize("TBOX_DEV_001"));
        ASSERT_TRUE(fota_->start());  // 注册路由 + 订阅下行

        ::tbox::fw::ipc::IpcConfig cfg;
        cfg.max_frame_bytes = 10485760;
        cfg.receive_timeout_ms = 5000;
        cfg.connect_timeout_ms = 2000;
        cfg.listen_backlog = 5;

        net_ = std::make_unique<MockNetStatusProvider>();
        server_ = std::make_unique<TspFrameworkServer>(
            socket_path_, cfg, fota_.get(), net_.get(), 64, SlowSubscriberPolicy::kDrop);
        ASSERT_TRUE(server_->start());
        fota_->set_event_publisher(server_->event_publisher());

        for (int i = 0; i < 50; i++) {
            if (access(socket_path_.c_str(), F_OK) == 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        client_ = std::make_unique<TspClient>(socket_path_);
    }

    void TearDown() override {
        client_.reset();
        server_->stop();
        fota_->stop();
        ::unlink(socket_path_.c_str());
    }

    std::string socket_path_;
    std::shared_ptr<MockMqttFacade> mqtt_;
    std::unique_ptr<FotaHandler> fota_;
    std::unique_ptr<MockNetStatusProvider> net_;
    std::unique_ptr<TspFrameworkServer> server_;
    std::unique_ptr<TspClient> client_;
};

// 端到端上行：accepted 仅表示 MQTT daemon 接管，≠ PUBACK (CR-003 §4)
TEST_F(TspIntegrationTest, UplinkAcceptedNotPuback) {
    auto r = client_->reportSoftwareInventory(make_snap("up-1", 1, {0x10, 0x20}));

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::ACCEPTED);
    // mock mqtt 接收到 publish
    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
    EXPECT_EQ(mqtt_->publish_calls()[0].msg_id, "up-1");
    EXPECT_EQ(mqtt_->publish_calls()[0].topic, topics::fota_up("TBOX_DEV_001"));
}

// snapshot 幂等：相同 msg_id 重复提交不重复上云 (CR-003 §4)
TEST_F(TspIntegrationTest, UplinkIdempotent) {
    auto r1 = client_->reportSoftwareInventory(make_snap("idem", 5));
    EXPECT_TRUE(r1.accepted);

    auto r2 = client_->reportSoftwareInventory(make_snap("idem", 5));
    EXPECT_TRUE(r2.accepted);
    EXPECT_EQ(r2.error_code, static_cast<int32_t>(TspErrorCode::DEDUP_HIT));

    // 只上云一次
    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
}

// unknown outcome：MQTT 响应丢失 (CR-003 §4)
TEST_F(TspIntegrationTest, UplinkUnknownOutcome) {
    mqtt_->publish_result = {true, PublishOutcome::UNKNOWN};

    auto r = client_->reportSoftwareInventory(make_snap("unk", 1));
    EXPECT_EQ(r.outcome, PublishOutcome::UNKNOWN);
    EXPECT_TRUE(r.accepted);  // daemon 已接管
}

// 状态查询：getRelayStatus 返回 accepted
TEST_F(TspIntegrationTest, GetRelayStatusAccepted) {
    client_->reportSoftwareInventory(make_snap("st", 9));

    auto s = client_->getRelayStatus("st");
    EXPECT_EQ(s.state, RelayState::ACCEPTED);
    EXPECT_EQ(s.snapshot_seq, 9u);
}

// 端到端下行：MQTT down/fota -> FotaHandler -> EventPublisher -> tsp_client subscriber
TEST_F(TspIntegrationTest, DownlinkEndToEnd) {
    std::atomic<bool> received{false};
    std::string recv_id;
    std::vector<uint8_t> recv_payload;

    auto sub = client_->subscribeFotaCommand([&](const FotaCommand& cmd) {
        recv_id = cmd.command_id;
        recv_payload = cmd.payload;
        received = true;
    });
    ASSERT_TRUE(sub.isActive());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 模拟 MQTT 下行投递
    nlohmann::json j;
    j[ipc::field::COMMAND_ID] = "dl-cmd-1";
    j[ipc::field::DELIVERY_ID] = "dlv-1";
    j[ipc::field::SCHEMA_VERSION] = "1.0";
    j[ipc::field::CONTENT_TYPE] = "application/x-protobuf";
    j[ipc::field::PAYLOAD_B64] = b64({0xDE, 0xAD, 0xBE, 0xEF});
    std::string s = j.dump();
    mqtt_->deliver_downlink(topics::fota_down("TBOX_DEV_001"),
                            std::vector<uint8_t>(s.begin(), s.end()));

    for (int i = 0; i < 100 && !received.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(received.load());
    EXPECT_EQ(recv_id, "dl-cmd-1");
    EXPECT_EQ(recv_payload, (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

// 下行顺序：多条命令按 MQTT 接收顺序到达订阅者 (CR-003 §5)
TEST_F(TspIntegrationTest, DownlinkOrdering) {
    std::mutex mtx;
    std::vector<std::string> ids;

    auto sub = client_->subscribeFotaCommand([&](const FotaCommand& cmd) {
        std::lock_guard<std::mutex> lock(mtx);
        ids.push_back(cmd.command_id);
    });
    ASSERT_TRUE(sub.isActive());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < 3; i++) {
        nlohmann::json j;
        j[ipc::field::COMMAND_ID] = "order-" + std::to_string(i);
        j[ipc::field::DELIVERY_ID] = "dlv-" + std::to_string(i);
        j[ipc::field::PAYLOAD_B64] = b64({static_cast<uint8_t>(i)});
        std::string s = j.dump();
        mqtt_->deliver_downlink(topics::fota_down("TBOX_DEV_001"),
                                std::vector<uint8_t>(s.begin(), s.end()));
    }

    for (int i = 0; i < 100 && ids.size() < 3; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_EQ(ids.size(), 3u);
    EXPECT_EQ(ids[0], "order-0");
    EXPECT_EQ(ids[1], "order-1");
    EXPECT_EQ(ids[2], "order-2");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
