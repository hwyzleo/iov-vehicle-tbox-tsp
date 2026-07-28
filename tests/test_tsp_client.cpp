// tests/test_tsp_client.cpp
// 端到端：tsp_client (framework-ipc Client) <-> TSP Server (framework-ipc Server + Dispatcher)
// 验证 wire protocol 契约：reportSoftwareInventory / getRelayStatus / subscribeFotaCommand
#include <gtest/gtest.h>
#include "tbox/tsp/client.h"
#include "tsp_framework_server.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "mocks.h"
#include "utils.h"

#include <chrono>
#include <thread>
#include <unistd.h>
#include <atomic>

using namespace tbox::tsp;
using namespace tbox::tsp::test;

namespace {
std::string b64(const std::vector<uint8_t>& d) {
    return ::hwyz::Utils::base64_encode(std::string(d.begin(), d.end()));
}

std::string unique_socket() {
    return "/tmp/tbox-tsp-test-" + std::to_string(getpid()) + "-" +
           std::to_string(rand()) + ".sock";
}
}

class TspClientServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        socket_path_ = unique_socket();
        relay_ = std::make_unique<MockFotaRelay>();
        net_ = std::make_unique<MockNetStatusProvider>();

        ::tbox::fw::ipc::IpcConfig cfg;
        cfg.max_frame_bytes = 10485760;
        cfg.receive_timeout_ms = 5000;
        cfg.connect_timeout_ms = 2000;
        cfg.listen_backlog = 5;

        server_ = std::make_unique<TspFrameworkServer>(
            socket_path_, cfg, relay_.get(), net_.get(), 64, SlowSubscriberPolicy::kDrop);
        ASSERT_TRUE(server_->start());

        // 等待 socket 就绪
        for (int i = 0; i < 50; i++) {
            if (access(socket_path_.c_str(), F_OK) == 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        client_ = std::make_unique<TspClient>(socket_path_);
    }

    void TearDown() override {
        client_.reset();
        server_->stop();
        server_.reset();
        ::unlink(socket_path_.c_str());
    }

    std::string socket_path_;
    std::unique_ptr<MockFotaRelay> relay_;
    std::unique_ptr<MockNetStatusProvider> net_;
    std::unique_ptr<TspFrameworkServer> server_;
    std::unique_ptr<TspClient> client_;
};

// reportSoftwareInventory: accepted
TEST_F(TspClientServerTest, ReportSoftwareInventoryAccepted) {
    relay_->uplink_result = {true, PublishOutcome::ACCEPTED, 0, ""};

    FotaSnapshot snap;
    snap.snapshot_seq = 10;
    snap.msg_id = "integration-10";
    snap.content_type = "application/x-protobuf";
    snap.payload = {0x01, 0x02, 0x03, 0x04};
    snap.trace_id = "trace-x";

    auto r = client_->reportSoftwareInventory(snap);

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::ACCEPTED);
    EXPECT_EQ(r.msg_id, "integration-10");
    EXPECT_TRUE(relay_->uplink_called);
    EXPECT_EQ(relay_->uplink_calls.back().snapshot.snapshot_seq, 10u);
}

// reportSoftwareInventory: dedup
TEST_F(TspClientServerTest, ReportSoftwareInventoryDedup) {
    relay_->uplink_result = {true, PublishOutcome::ACCEPTED,
        static_cast<int32_t>(TspErrorCode::DEDUP_HIT), ""};

    FotaSnapshot snap;
    snap.msg_id = "dup-1";
    snap.payload = {0x01};

    auto r = client_->reportSoftwareInventory(snap);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::DEDUP_HIT));
}

// getRelayStatus
TEST_F(TspClientServerTest, GetRelayStatus) {
    relay_->status_result.state = RelayState::ACCEPTED;
    relay_->status_result.snapshot_seq = 3;
    relay_->status_result.error_code = 0;

    auto s = client_->getRelayStatus("m-3");
    EXPECT_EQ(s.state, RelayState::ACCEPTED);
    EXPECT_EQ(s.msg_id, "m-3");
    EXPECT_EQ(s.snapshot_seq, 3u);
}

// subscribeFotaCommand: 订阅后收到下行事件 (CR-003 §5)
TEST_F(TspClientServerTest, SubscribeAndReceiveFotaCommand) {
    std::atomic<bool> received{false};
    std::string recv_command_id;
    std::vector<uint8_t> recv_payload;

    auto sub = client_->subscribeFotaCommand([&](const FotaCommand& cmd) {
        recv_command_id = cmd.command_id;
        recv_payload = cmd.payload;
        received = true;
    });
    ASSERT_TRUE(sub.isActive());

    // 等待订阅注册完成
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 服务端推送下行命令
    FotaCommand cmd;
    cmd.command_id = "cmd-down-1";
    cmd.delivery_id = "dlv-1";
    cmd.schema_version = "1.0";
    cmd.payload = {0xAA, 0xBB, 0xCC};
    server_->event_publisher()->publish_fota_command(cmd);

    // 等待事件到达
    for (int i = 0; i < 100 && !received.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(received.load());
    EXPECT_EQ(recv_command_id, "cmd-down-1");
    EXPECT_EQ(recv_payload, (std::vector<uint8_t>{0xAA, 0xBB, 0xCC}));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
