// tests/test_vehicle_message_gateway.cpp
// VehicleMessageGateway 单元测试（CR-009 §测试矩阵）：
//   Envelope 校验/allowlist/方向/TTL/大小、correlation reserve/complete、
//   RESPONSE 匹配与错配/迟到/重复、并发 message_id、超时、EVENT 分流、
//   max_in_flight、STOPPING。
#include <gtest/gtest.h>
#include "vehicle_message_gateway.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/types.h"
#include "mocks.h"
#include "vehicle_message_test_util.h"
#include "nlohmann/json.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using vehicle::common::v1::MessageKind;

namespace {

// 默认 gateway 配置：较小上限，便于测试
VehicleMessageGatewayConfig test_config() {
    VehicleMessageGatewayConfig c;
    c.limits.allowed_services = {"vehicle.fota"};
    c.limits.allowed_protocol_majors = {1};
    c.limits.max_envelope_bytes = 16384;
    c.limits.max_payload_bytes = 8192;
    c.max_in_flight = 64;
    c.downlink_queue_capacity = 256;
    c.worker_count = 1;
    c.default_exchange_timeout_ms = 200;
    return c;
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

} // namespace

class VehicleMessageGatewayTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        gw_ = std::make_unique<VehicleMessageGateway>(mqtt_);
        ASSERT_TRUE(gw_->initialize(test_config()));
        ASSERT_TRUE(gw_->start());
    }

    void TearDown() override {
        gw_->stop();
    }

    std::shared_ptr<MockMqttFacade> mqtt_;
    std::unique_ptr<VehicleMessageGateway> gw_;
    ExchangeOptions opt_;
    CallContext ctx_;
};

// ============================================================
// Envelope 校验（US-012 / §测试矩阵 2）
// ============================================================

TEST_F(VehicleMessageGatewayTest, EmptyEnvelopeRejected) {
    auto r = gw_->exchange(to_msg({}), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::ProtocolError);
}

TEST_F(VehicleMessageGatewayTest, OversizeEnvelopePayloadTooLarge) {
    VehicleMessageGatewayConfig c = test_config();
    c.limits.max_envelope_bytes = 64;
    VehicleMessageGateway gw2(mqtt_);
    ASSERT_TRUE(gw2.initialize(c));
    auto bytes = make_request_envelope("m-oversize");
    // 64B 上限 < 序列化长度
    auto r = gw2.exchange(to_msg(bytes), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::PayloadTooLarge);
}

TEST_F(VehicleMessageGatewayTest, WrongServiceRejected) {
    auto bytes = make_request_envelope("m-svc", "req", "vehicle.fota.v1.FotaRequest",
                                       {0x01}, 0, "vehicle.diag");
    auto r = gw_->exchange(to_msg(bytes), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::ProtocolError);
    EXPECT_EQ(r.error, "service_not_allowed");
}

TEST_F(VehicleMessageGatewayTest, WrongPayloadTypeRejected) {
    auto bytes = make_request_envelope("m-pt", "req", "vehicle.fota.v1.Bad.Type");
    auto r = gw_->exchange(to_msg(bytes), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::VersionMismatch);
}

TEST_F(VehicleMessageGatewayTest, TtlExpiredRejected) {
    auto past = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - 1000;
    auto bytes = make_request_envelope("m-ttl", "req", "vehicle.fota.v1.FotaRequest",
                                       {0x01}, past);
    auto r = gw_->exchange(to_msg(bytes), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Rejected);
    EXPECT_EQ(r.error, "ttl_expired");
}

// ============================================================
// REQUEST -> publishRoute -> RESPONSE correlation（US-014）
// ============================================================

TEST_F(VehicleMessageGatewayTest, ExchangeCompletesWithResponse) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    const std::string msg_id = "req-100";

    std::atomic<bool> done{false};
    TransportResult<VehicleMessage> result;
    std::thread t([&] {
        result = gw_->exchange(to_msg(make_request_envelope(msg_id)), opt_, ctx_);
        done = true;
    });

    // 等待请求已发布（correlation 已建立）
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));

    // 云端 RESPONSE 下行
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope(msg_id, "resp-" + msg_id)));

    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();

    EXPECT_EQ(result.outcome, TransportOutcome::Accepted);
    ASSERT_TRUE(result.value.has_value());
    // RESPONSE Envelope 原样返回
    auto resp = make_response_envelope(msg_id, "resp-" + msg_id);
    EXPECT_EQ(bytes_to_string(result.value->envelope_bytes), bytes_to_string(resp));

    // publishRoute 参数正确（owner/tsp, route_id=fota.uplink, msg_id）
    ASSERT_EQ(mqtt_->publish_route_calls().size(), 1u);
    EXPECT_EQ(mqtt_->publish_route_calls()[0].owner, "tsp");
    EXPECT_EQ(mqtt_->publish_route_calls()[0].route_id, "fota.uplink");
    EXPECT_EQ(mqtt_->publish_route_calls()[0].msg_id, msg_id);
    // payload 为完整序列化 Envelope（原样转发，不解析）
    const auto calls = mqtt_->publish_route_calls();
    std::string pub_str(calls[0].payload.begin(), calls[0].payload.end());
    EXPECT_EQ(pub_str, bytes_to_string(make_request_envelope(msg_id)));
}

TEST_F(VehicleMessageGatewayTest, ExchangeMqttLocalReject) {
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted};
    auto r = gw_->exchange(to_msg(make_request_envelope("req-rej")), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Rejected);
}

TEST_F(VehicleMessageGatewayTest, ExchangeMqttUnknown) {
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Unknown};
    auto r = gw_->exchange(to_msg(make_request_envelope("req-unk")), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Unknown);
}

TEST_F(VehicleMessageGatewayTest, ExchangeTimeout) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    ExchangeOptions opt;
    opt.timeout = std::chrono::milliseconds(100);
    auto r = gw_->exchange(to_msg(make_request_envelope("req-tmo")), opt, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Timeout);
    EXPECT_EQ(r.error, "business_response_timeout");
}

// 重复 RESPONSE：仅第一次完成（§测试矩阵 4）
TEST_F(VehicleMessageGatewayTest, DuplicateResponseOnlyFirstCompletes) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    const std::string msg_id = "req-dup";
    std::atomic<bool> done{false};
    TransportResult<VehicleMessage> result;
    std::thread t([&] {
        result = gw_->exchange(to_msg(make_request_envelope(msg_id)), opt_, ctx_);
        done = true;
    });
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));

    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope(msg_id, "r1")));
    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();
    EXPECT_EQ(result.outcome, TransportOutcome::Accepted);

    // 第二次相同 RESPONSE：应被拒绝（计数器 response_rejected 增加），不重复 callback
    auto before = gw_->counters().response_rejected;
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope(msg_id, "r1")));
    EXPECT_GT(gw_->counters().response_rejected, before);
}

// 未知/迟到 RESPONSE：不完成（§测试矩阵 4）
TEST_F(VehicleMessageGatewayTest, UnknownResponseRejected) {
    auto before = gw_->counters().response_rejected;
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope("no-such-request", "r-orphan")));
    EXPECT_GT(gw_->counters().response_rejected, before);
}

// RESPONSE 超出 max_response_bytes：以 PayloadTooLarge 完成（US-016）
TEST_F(VehicleMessageGatewayTest, ResponseOversizePayloadTooLarge) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    const std::string msg_id = "req-oversize-resp";
    ExchangeOptions opt;
    opt.max_response_bytes = 8;  // 极小上限
    std::atomic<bool> done{false};
    TransportResult<VehicleMessage> result;
    std::thread t([&] {
        result = gw_->exchange(to_msg(make_request_envelope(msg_id)), opt, ctx_);
        done = true;
    });
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope(msg_id, "r-big")));
    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();
    EXPECT_EQ(result.outcome, TransportOutcome::PayloadTooLarge);
}

// RESPONSE service 错配：拒绝
TEST_F(VehicleMessageGatewayTest, ResponseServiceMismatchRejected) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    const std::string msg_id = "req-mismatch";
    std::atomic<bool> done{false};
    TransportResult<VehicleMessage> result;
    std::thread t([&] {
        result = gw_->exchange(to_msg(make_request_envelope(msg_id)), opt_, ctx_);
        done = true;
    });
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));

    // 错误 service 的 RESPONSE
    mqtt_->deliver_routed_downlink(make_downlink_event(
        make_response_envelope(msg_id, "r-wrong", {0x01}, 0, "vehicle.diag")));

    // exchange 不应被完成（应超时）
    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();
    EXPECT_EQ(result.outcome, TransportOutcome::Timeout);
}

// max_in_flight 上限（§测试矩阵 6）
TEST_F(VehicleMessageGatewayTest, MaxInFlightRejected) {
    VehicleMessageGatewayConfig c = test_config();
    c.max_in_flight = 1;
    VehicleMessageGateway gw2(mqtt_);
    ASSERT_TRUE(gw2.initialize(c));
    ASSERT_TRUE(gw2.start());

    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    std::atomic<bool> done{false};
    std::thread t([&] {
        gw2.exchange(to_msg(make_request_envelope("req-inflight")), opt_, ctx_);
        done = true;
    });
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));

    // 第二个 exchange：in-flight 满 -> Rejected
    auto r = gw2.exchange(to_msg(make_request_envelope("req-inflight-2")), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Rejected);
    EXPECT_EQ(r.error, "max_in_flight");

    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope("req-inflight", "r1")));
    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();
    gw2.stop();
}

// message_id 身份冲突：tombstone 窗口内复用被拒（§测试矩阵 4）
TEST_F(VehicleMessageGatewayTest, MessageIdReuseRejectedWithinTombstone) {
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted};
    const std::string msg_id = "req-reuse";
    std::atomic<bool> done{false};
    std::thread t([&] {
        gw_->exchange(to_msg(make_request_envelope(msg_id)), opt_, ctx_);
        done = true;
    });
    ASSERT_TRUE(wait_for([&] { return mqtt_->publish_route_calls().size() == 1; }));
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_response_envelope(msg_id, "r1")));
    ASSERT_TRUE(wait_for([&] { return done.load(); }));
    t.join();

    // 立即复用同一 message_id -> 身份冲突
    auto r = gw_->exchange(to_msg(make_request_envelope(msg_id)), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::ProtocolError);
    EXPECT_EQ(r.error, "message_identity_conflict");
}

// ============================================================
// EVENT 下行分流（US-014 / §EVENT 下行）
// ============================================================

TEST_F(VehicleMessageGatewayTest, EventForwardsToPublisher) {
    std::atomic<int> pushed{0};
    std::string pushed_service;
    std::mutex mtx;
    TspEventPublisher pub(64, SlowSubscriberPolicy::kDrop);
    pub.set_push_fn([&](uint32_t, const std::string& payload_json) -> bool {
        auto j = nlohmann::json::parse(payload_json);
        std::lock_guard<std::mutex> lock(mtx);
        pushed_service = j.value("service", "");
        pushed++;
        return true;
    });
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());
    gw_->set_event_publisher(&pub);

    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_event_envelope("evt-1")));

    ASSERT_TRUE(wait_for([&] { return pushed.load() == 1; }));
    pub.stop();
    EXPECT_EQ(pushed_service, "vehicle.fota");
    EXPECT_GT(gw_->counters().event_forwarded, 0u);
}

// 非法 REQUEST 下行：拒绝，不落入 EVENT 默认路径
TEST_F(VehicleMessageGatewayTest, IllegalDownlinkRequestRejected) {
    auto before = gw_->counters().envelope_invalid;
    mqtt_->deliver_routed_downlink(
        make_downlink_event(make_request_envelope("req-downlink")));
    EXPECT_GT(gw_->counters().envelope_invalid, before);
}

// 未知 route/target：gateway 防御式复核拒绝（绕过 dispatcher 直接调用）
TEST_F(VehicleMessageGatewayTest, UnknownRouteRejected) {
    auto before = gw_->counters().envelope_invalid;
    RoutedDownlinkEvent ev = make_downlink_event(make_event_envelope("evt-x"));
    ev.owner = "other";
    gw_->handle_routed_downlink(ev);
    EXPECT_GT(gw_->counters().envelope_invalid, before);
}

// ============================================================
// STOPPING（§生命周期停止）
// ============================================================

TEST_F(VehicleMessageGatewayTest, StoppingRejectsNewExchange) {
    gw_->stop();  // 停后 stopping=true
    auto r = gw_->exchange(to_msg(make_request_envelope("req-stop")), opt_, ctx_);
    EXPECT_EQ(r.outcome, TransportOutcome::Stopping);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
