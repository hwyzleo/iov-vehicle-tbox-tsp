// tests/test_tsp_client.cpp
// 端到端：tsp_client (framework-ipc Client) <-> TSP Server (framework-ipc Server + Dispatcher)
// 验证 CR-009 wire protocol 契约：exchangeVehicleMessage / subscribeVehicleMessage。
// 使用 MockVehicleMessageRelay（blocking 模式完成业务 RESPONSE）与 TspEventPublisher
// 推送 EVENT Envelope。
#include <gtest/gtest.h>
#include "tbox/tsp/client.h"
#include "tsp_framework_server.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "mocks.h"
#include "vehicle_message_test_util.h"

#include <chrono>
#include <thread>
#include <unistd.h>
#include <atomic>

using namespace tbox::tsp;
using namespace tbox::tsp::test;

namespace {
std::string unique_socket() {
    return "/tmp/tbox-tsp-test-" + std::to_string(getpid()) + "-" +
           std::to_string(rand()) + ".sock";
}

// 等待函数
template <typename F>
bool wait_for(F&& f, int ms = 2000) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return f();
}
}

class TspClientServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        socket_path_ = unique_socket();
        relay_ = std::make_unique<MockVehicleMessageRelay>();
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
        relay_.reset();
        ::unlink(socket_path_.c_str());
    }

    std::string socket_path_;
    std::unique_ptr<MockVehicleMessageRelay> relay_;
    std::unique_ptr<MockNetStatusProvider> net_;
    std::unique_ptr<TspFrameworkServer> server_;
    std::unique_ptr<TspClient> client_;
};

// exchangeVehicleMessage: accepted + 业务 RESPONSE Envelope（blocking relay 完成）
TEST_F(TspClientServerTest, ExchangeAcceptedWithResponse) {
    relay_->blocking = true;
    relay_->reset_blocking();

    const std::string msg_id = "client-req-1";
    ExchangeOptions options;
    options.timeout = std::chrono::milliseconds(3000);
    CallContext ctx;
    ctx.trace_id = "trace-client";
    ctx.request_id = "req-client-1";

    std::atomic<bool> done{false};
    TransportResult<VehicleMessage> result;
    std::thread t([&] {
        result = client_->exchangeVehicleMessage(
            to_msg(make_request_envelope(msg_id)), options, ctx);
        done = true;
    });

    // 等待 relay 收到请求
    ASSERT_TRUE(wait_for([&] { return relay_->call_count() == 1; }));

    // relay 完成：Accepted + RESPONSE Envelope
    TransportResult<VehicleMessage> r;
    r.outcome = TransportOutcome::Accepted;
    r.value = to_msg(make_response_envelope(msg_id, "resp-1"));
    relay_->complete(std::move(r));

    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();

    EXPECT_EQ(result.outcome, TransportOutcome::Accepted);
    ASSERT_TRUE(result.value.has_value());
    EXPECT_EQ(bytes_to_string(result.value->envelope_bytes),
              bytes_to_string(make_response_envelope(msg_id, "resp-1")));

    // wire 校验：relay 收到单一 Envelope bytes（无外层 payload/service 重复）
    const auto& call = relay_->last_call();
    EXPECT_EQ(bytes_to_string(call.request.envelope_bytes),
              bytes_to_string(make_request_envelope(msg_id)));
    EXPECT_EQ(call.ctx.trace_id, "trace-client");
    EXPECT_EQ(call.ctx.request_id, "req-client-1");
}

// exchangeVehicleMessage: relay 拒绝 -> Rejected
TEST_F(TspClientServerTest, ExchangeRejected) {
    TransportResult<VehicleMessage> rej;
    rej.outcome = TransportOutcome::Rejected;
    rej.error = "ttl_expired";
    relay_->default_result = rej;

    auto result = client_->exchangeVehicleMessage(
        to_msg(make_request_envelope("client-req-rej")), ExchangeOptions{}, CallContext{});
    EXPECT_EQ(result.outcome, TransportOutcome::Rejected);
    EXPECT_EQ(result.error, "ttl_expired");
    EXPECT_FALSE(result.value.has_value());
}

// exchangeVehicleMessage: 超时（relay 返回 Timeout）
TEST_F(TspClientServerTest, ExchangeTimeout) {
    TransportResult<VehicleMessage> tmo;
    tmo.outcome = TransportOutcome::Timeout;
    tmo.error = "business_response_timeout";
    relay_->default_result = tmo;

    auto result = client_->exchangeVehicleMessage(
        to_msg(make_request_envelope("client-req-tmo")), ExchangeOptions{}, CallContext{});
    EXPECT_EQ(result.outcome, TransportOutcome::Timeout);
}

// subscribeVehicleMessage: 订阅后收到 EVENT Envelope（CR-009 §EVENT 下行）
TEST_F(TspClientServerTest, SubscribeAndReceiveEvent) {
    std::atomic<bool> received{false};
    std::vector<std::byte> recv_bytes;

    auto sub = client_->subscribeVehicleMessage("vehicle.fota",
        [&](const VehicleMessage& msg) {
            recv_bytes = msg.envelope_bytes;
            received = true;
        });
    ASSERT_TRUE(sub.isActive());

    // 等待订阅注册完成
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 服务端推送下行 EVENT Envelope
    auto evt = make_event_envelope("evt-client-1");
    server_->event_publisher()->publish_vehicle_message("vehicle.fota", evt, "tr", "rq");

    // 等待事件到达
    for (int i = 0; i < 100 && !received.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(received.load());
    EXPECT_EQ(bytes_to_string(recv_bytes), bytes_to_string(evt));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
