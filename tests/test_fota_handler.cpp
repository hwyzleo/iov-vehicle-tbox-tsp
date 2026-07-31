// tests/test_fota_handler.cpp
//
// CR-006: route 模式测 publishRoute/routed downlink/错误映射(1007/1001)；
// legacy 模式测 publish/full-topic downlink。
#include <gtest/gtest.h>
#include "fota_handler.h"
#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "tsp_build_config.h"
#include "tbox/tsp/errors.h"
#include "constants.h"
#include "mocks.h"
#include "nlohmann/json.hpp"
#include "utils.h"

#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>
#include <thread>

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using json = nlohmann::json;

namespace {
std::string b64(const std::vector<uint8_t>& d) {
    return ::hwyz::Utils::base64_encode(std::string(d.begin(), d.end()));
}

FotaSnapshot make_snapshot(const std::string& msg_id, uint32_t seq, std::vector<uint8_t> payload = {0x01}) {
    FotaSnapshot s;
    s.msg_id = msg_id;
    s.snapshot_seq = seq;
    s.content_type = "application/x-protobuf";
    s.payload = std::move(payload);
    s.trace_id = "trace-" + msg_id;
    s.request_id = "req-" + msg_id;
    return s;
}

json make_downlink_json(const std::string& command_id, const std::vector<uint8_t>& payload) {
    json j;
    j[ipc::field::COMMAND_ID] = command_id;
    j[ipc::field::DELIVERY_ID] = "dlv-" + command_id;
    j[ipc::field::SCHEMA_VERSION] = "1.0";
    j[ipc::field::CONTENT_TYPE] = "application/x-protobuf";
    j[ipc::field::PAYLOAD_B64] = b64(payload);
    j[ipc::field::TRACE_ID] = "trace-dl";
    return j;
}

void wait_for_pushed(std::vector<std::string>& pushed, std::mutex& mtx, size_t n) {
    for (int i = 0; i < 100; i++) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (pushed.size() >= n) return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}
} // namespace

class FotaHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        handler_ = std::make_unique<FotaHandler>(mqtt_);
        ASSERT_TRUE(handler_->initialize("TBOX_DEV_001"));

        publisher_ = std::make_unique<TspEventPublisher>(64, SlowSubscriberPolicy::kDrop);
        publisher_->set_push_fn([this](uint32_t, const std::string& payload) -> bool {
            std::lock_guard<std::mutex> lock(mtx_);
            pushed_.push_back(payload);
            return true;
        });
        publisher_->set_has_subscriber_fn([](uint32_t) { return true; });
        ASSERT_TRUE(publisher_->start());
        handler_->set_event_publisher(publisher_.get());
        ASSERT_TRUE(handler_->start());  // route: subscribeRoutedDownlink; legacy: subscribe
    }

    void TearDown() override {
        if (publisher_) publisher_->stop();
        handler_->stop();
    }

    std::shared_ptr<MockMqttFacade> mqtt_;
    std::unique_ptr<FotaHandler> handler_;
    std::unique_ptr<TspEventPublisher> publisher_;
    std::vector<std::string> pushed_;
    std::mutex mtx_;
};

// ============================================================
// route 模式 (CR-006)
// ============================================================
#if TSP_MQTT_ROUTE_API

// 上行：publishRoute accepted（accepted ≠ PUBACK），校验 owner/route_id/msg_id
TEST_F(FotaHandlerTest, UplinkRouteAccepted) {
    mqtt_->publish_route_result = {true, PublishOutcome::ACCEPTED};

    auto r = handler_->handle_uplink(make_snapshot("m1", 1));

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::ACCEPTED);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::SUCCESS));
    EXPECT_EQ(r.msg_id, "m1");
    // route 模式不调用 legacy publish
    EXPECT_EQ(mqtt_->publish_calls().size(), 0u);
    auto calls = mqtt_->publish_route_calls();
    ASSERT_EQ(calls.size(), 1u);
    EXPECT_EQ(calls[0].owner, "tsp");
    EXPECT_EQ(calls[0].route_id, "fota.uplink");
    EXPECT_EQ(calls[0].msg_id, "m1");
}

// 幂等去重：相同 msg_id 重复提交不重复上云 (CR-003 §4)
TEST_F(FotaHandlerTest, UplinkRouteDuplicateReturnsExisting) {
    mqtt_->publish_route_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r1.accepted);

    auto r2 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r2.accepted);
    EXPECT_EQ(r2.error_code, static_cast<int32_t>(TspErrorCode::DEDUP_HIT));

    ASSERT_EQ(mqtt_->publish_route_calls().size(), 1u);
}

// daemon 显式拒绝 route publish -> TBOX-TSP-1007 (CR-006 §9)
TEST_F(FotaHandlerTest, UplinkRouteRejectedMapsTo1007) {
    mqtt_->publish_route_result = {false, PublishOutcome::ACCEPTED};

    auto r = handler_->handle_uplink(make_snapshot("rej", 1));

    EXPECT_FALSE(r.accepted);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::ROUTE_API_INCOMPATIBLE));
    auto s = handler_->get_relay_status("rej");
    EXPECT_EQ(s.state, RelayState::FAILED);
}

// 传输失败/响应丢失 (outcome=UNKNOWN) -> TBOX-TSP-1001 (CR-006 §9)
TEST_F(FotaHandlerTest, UplinkRouteUnknownOutcomeMapsTo1001) {
    mqtt_->publish_route_result = {false, PublishOutcome::UNKNOWN};

    auto r = handler_->handle_uplink(make_snapshot("unk1", 1));

    EXPECT_FALSE(r.accepted);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED));
}

// accepted + UNKNOWN outcome：daemon 已接管但响应丢失 (CR-003 §4)
TEST_F(FotaHandlerTest, UplinkRouteAcceptedUnknownOutcome) {
    mqtt_->publish_route_result = {true, PublishOutcome::UNKNOWN};

    auto r = handler_->handle_uplink(make_snapshot("unk2", 1));

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::UNKNOWN);
}

TEST_F(FotaHandlerTest, GetRelayStatus) {
    mqtt_->publish_route_result = {true, PublishOutcome::ACCEPTED};
    handler_->handle_uplink(make_snapshot("q1", 5));

    auto s = handler_->get_relay_status("q1");
    EXPECT_EQ(s.state, RelayState::ACCEPTED);
    EXPECT_EQ(s.msg_id, "q1");
    EXPECT_EQ(s.snapshot_seq, 5u);

    auto s2 = handler_->get_relay_status("unknown");
    EXPECT_EQ(s2.state, RelayState::UNKNOWN);
}

// 下行：routed event -> FotaHandler -> EventPublisher (CR-006 §6)
TEST_F(FotaHandlerTest, DownlinkRoutedForwarded) {
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
    json j = make_downlink_json("cmd-1", payload);
    std::string s = j.dump();
    std::vector<uint8_t> raw(s.begin(), s.end());

    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "fota.downlink";
    ev.target = "tsp.fota";
    ev.qos = 1;
    ev.payload = raw;
    ev.request_id = "req-dl";
    ev.trace_id = "trace-dl";
    mqtt_->deliver_routed_downlink(ev);

    wait_for_pushed(pushed_, mtx_, 1);
    ASSERT_EQ(pushed_.size(), 1u);
    EXPECT_NE(pushed_[0].find("cmd-1"), std::string::npos);
}

// 下行：未知 route/target 被 dispatcher 拒绝，不推送 (CR-006 §6.2)
TEST_F(FotaHandlerTest, DownlinkRoutedUnknownRouteRejected) {
    std::vector<uint8_t> payload = {0xAA};
    json j = make_downlink_json("cmd-x", payload);
    std::string s = j.dump();
    std::vector<uint8_t> raw(s.begin(), s.end());

    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "unknown.route";
    ev.target = "tsp.fota";
    ev.payload = raw;
    mqtt_->deliver_routed_downlink(ev);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_EQ(pushed_.size(), 0u);
}

// 下行：解析失败不推送 (TBOX-TSP-1002)
TEST_F(FotaHandlerTest, DownlinkRoutedParseFailed) {
    std::string bad = "{not json";
    std::vector<uint8_t> raw(bad.begin(), bad.end());

    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "fota.downlink";
    ev.target = "tsp.fota";
    ev.payload = raw;
    mqtt_->deliver_routed_downlink(ev);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_EQ(pushed_.size(), 0u);
}

// 节流：连续上行被节流跳过
TEST_F(FotaHandlerTest, Throttle) {
    mqtt_->publish_route_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("t1", 1));
    EXPECT_TRUE(r1.accepted);

    auto r2 = handler_->handle_uplink(make_snapshot("t2", 2));
    EXPECT_TRUE(r2.accepted);  // 已接收，速率限制跳过

    ASSERT_EQ(mqtt_->publish_route_calls().size(), 1u);  // t2 被节流
}

// ---- CR-006 §7/§9/§10.1: route 能力状态与指标 ----

// 启动探测：subscribeRoutedDownlink 成功 -> route_api_supported=true, downlink=ACTIVE
TEST_F(FotaHandlerTest, RouteApiStatusSupportedOnStart) {
    auto s = handler_->getRouteApiStatus();
    EXPECT_TRUE(s.route_api_supported);
    EXPECT_EQ(s.downlink_route_state, "ACTIVE");
}

// 上行成功 -> route_publish_total++, uplink=ACTIVE
TEST_F(FotaHandlerTest, RouteMetricsUplinkSuccess) {
    mqtt_->publish_route_result = {true, PublishOutcome::ACCEPTED};
    handler_->handle_uplink(make_snapshot("m1", 1));

    auto m = handler_->getRouteMetrics();
    EXPECT_EQ(m.route_publish_total, 1u);
    EXPECT_EQ(m.route_publish_failure_total, 0u);
    EXPECT_EQ(handler_->getRouteApiStatus().uplink_route_state, "ACTIVE");
}

// 上行被 daemon 显式拒绝 -> 1007 + failure + api_incompatible + uplink=DEGRADED
TEST_F(FotaHandlerTest, RouteMetricsUplinkRejected1007) {
    mqtt_->publish_route_result = {false, PublishOutcome::ACCEPTED};
    handler_->handle_uplink(make_snapshot("rej", 1));

    auto m = handler_->getRouteMetrics();
    EXPECT_EQ(m.route_publish_total, 1u);
    EXPECT_EQ(m.route_publish_failure_total, 1u);
    EXPECT_EQ(m.route_api_incompatible, 1u);
    EXPECT_EQ(handler_->getRouteApiStatus().uplink_route_state, "DEGRADED");
}

// 下行 matched -> route_downlink_total++, unmatched 不增
TEST_F(FotaHandlerTest, RouteMetricsDownlinkMatched) {
    json j = make_downlink_json("cmd-1", {0xAA});
    std::string s = j.dump();
    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "fota.downlink";
    ev.target = "tsp.fota";
    ev.payload.assign(s.begin(), s.end());
    mqtt_->deliver_routed_downlink(ev);
    wait_for_pushed(pushed_, mtx_, 1);

    auto m = handler_->getRouteMetrics();
    EXPECT_EQ(m.route_downlink_total, 1u);
    EXPECT_EQ(m.route_downlink_unmatched_total, 0u);
}

// 下行 unmatched -> route_downlink_total++ + unmatched_total++
TEST_F(FotaHandlerTest, RouteMetricsDownlinkUnmatched) {
    json j = make_downlink_json("cmd-x", {0xAA});
    std::string s = j.dump();
    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "unknown.route";
    ev.target = "tsp.fota";
    ev.payload.assign(s.begin(), s.end());
    mqtt_->deliver_routed_downlink(ev);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    auto m = handler_->getRouteMetrics();
    EXPECT_EQ(m.route_downlink_total, 1u);
    EXPECT_EQ(m.route_downlink_unmatched_total, 1u);
}

// ============================================================
// legacy 模式 (deprecated, CR-006 §10.2)
// ============================================================
#else

TEST_F(FotaHandlerTest, UplinkAccepted) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

    auto r = handler_->handle_uplink(make_snapshot("m1", 1));

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::ACCEPTED);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::SUCCESS));
    EXPECT_EQ(r.msg_id, "m1");
    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
    EXPECT_EQ(mqtt_->publish_calls()[0].msg_id, "m1");
}

TEST_F(FotaHandlerTest, UplinkDuplicateReturnsExisting) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r1.accepted);

    auto r2 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r2.accepted);
    EXPECT_EQ(r2.error_code, static_cast<int32_t>(TspErrorCode::DEDUP_HIT));

    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
}

TEST_F(FotaHandlerTest, UplinkPublishFailed) {
    mqtt_->publish_result = {false, PublishOutcome::ACCEPTED};

    auto r = handler_->handle_uplink(make_snapshot("fail", 1));

    EXPECT_FALSE(r.accepted);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED));

    auto s = handler_->get_relay_status("fail");
    EXPECT_EQ(s.state, RelayState::FAILED);
}

TEST_F(FotaHandlerTest, UplinkUnknownOutcome) {
    mqtt_->publish_result = {true, PublishOutcome::UNKNOWN};

    auto r = handler_->handle_uplink(make_snapshot("unk", 1));

    EXPECT_TRUE(r.accepted);
    EXPECT_EQ(r.outcome, PublishOutcome::UNKNOWN);
}

TEST_F(FotaHandlerTest, GetRelayStatus) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};
    handler_->handle_uplink(make_snapshot("q1", 5));

    auto s = handler_->get_relay_status("q1");
    EXPECT_EQ(s.state, RelayState::ACCEPTED);
    EXPECT_EQ(s.msg_id, "q1");
    EXPECT_EQ(s.snapshot_seq, 5u);

    auto s2 = handler_->get_relay_status("unknown");
    EXPECT_EQ(s2.state, RelayState::UNKNOWN);
}

TEST_F(FotaHandlerTest, DownlinkForwarded) {
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
    json j = make_downlink_json("cmd-1", payload);
    std::string s = j.dump();
    std::vector<uint8_t> raw(s.begin(), s.end());

    mqtt_->deliver_downlink("vehicle/TBOX_DEV_001/down/fota", raw);

    wait_for_pushed(pushed_, mtx_, 1);
    ASSERT_EQ(pushed_.size(), 1u);
    EXPECT_NE(pushed_[0].find("cmd-1"), std::string::npos);
}

TEST_F(FotaHandlerTest, DownlinkParseFailed) {
    std::string bad = "{not json";
    std::vector<uint8_t> raw(bad.begin(), bad.end());

    mqtt_->deliver_downlink("vehicle/TBOX_DEV_001/down/fota", raw);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_EQ(pushed_.size(), 0u);
}

TEST_F(FotaHandlerTest, Throttle) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("t1", 1));
    EXPECT_TRUE(r1.accepted);

    auto r2 = handler_->handle_uplink(make_snapshot("t2", 2));
    EXPECT_TRUE(r2.accepted);

    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
}

#endif  // TSP_MQTT_ROUTE_API

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
