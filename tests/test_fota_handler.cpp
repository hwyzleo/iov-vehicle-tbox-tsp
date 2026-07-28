// tests/test_fota_handler.cpp
#include <gtest/gtest.h>
#include "fota_handler.h"
#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
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
}

class FotaHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        handler_ = std::make_unique<FotaHandler>(mqtt_);
        ASSERT_TRUE(handler_->initialize("TBOX_DEV_001"));

        // 默认事件推送器（记录 push 调用）
        publisher_ = std::make_unique<TspEventPublisher>(64, SlowSubscriberPolicy::kDrop);
        publisher_->set_push_fn([this](uint32_t, const std::string& payload) -> bool {
            std::lock_guard<std::mutex> lock(mtx_);
            pushed_.push_back(payload);
            return true;
        });
        publisher_->set_has_subscriber_fn([](uint32_t) { return true; });
        ASSERT_TRUE(publisher_->start());
        handler_->set_event_publisher(publisher_.get());
        ASSERT_TRUE(handler_->start());  // 注册路由 + 订阅下行
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

// 上行：新 msg_id -> accepted（accepted ≠ PUBACK）
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

// 幂等去重：相同 msg_id 重复提交不重复上云 (CR-003 §4)
TEST_F(FotaHandlerTest, UplinkDuplicateReturnsExisting) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r1.accepted);

    // 同 msg_id 重试 -> 返回已有状态，不重复上云
    auto r2 = handler_->handle_uplink(make_snapshot("dup", 1));
    EXPECT_TRUE(r2.accepted);
    EXPECT_EQ(r2.error_code, static_cast<int32_t>(TspErrorCode::DEDUP_HIT));

    // 只 publish 一次
    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
}

// publish 失败 -> FAILED
TEST_F(FotaHandlerTest, UplinkPublishFailed) {
    mqtt_->publish_result = {false, PublishOutcome::ACCEPTED};

    auto r = handler_->handle_uplink(make_snapshot("fail", 1));

    EXPECT_FALSE(r.accepted);
    EXPECT_EQ(r.error_code, static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED));

    // 状态查询返回 FAILED
    auto s = handler_->get_relay_status("fail");
    EXPECT_EQ(s.state, RelayState::FAILED);
}

// unknown outcome：响应丢失 (CR-003 §4)
TEST_F(FotaHandlerTest, UplinkUnknownOutcome) {
    mqtt_->publish_result = {true, PublishOutcome::UNKNOWN};

    auto r = handler_->handle_uplink(make_snapshot("unk", 1));

    EXPECT_TRUE(r.accepted);  // daemon 已接管
    EXPECT_EQ(r.outcome, PublishOutcome::UNKNOWN);
}

// getRelayStatus 查询已有状态
TEST_F(FotaHandlerTest, GetRelayStatus) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};
    handler_->handle_uplink(make_snapshot("q1", 5));

    auto s = handler_->get_relay_status("q1");
    EXPECT_EQ(s.state, RelayState::ACCEPTED);
    EXPECT_EQ(s.msg_id, "q1");
    EXPECT_EQ(s.snapshot_seq, 5u);

    // 未知 msg_id
    auto s2 = handler_->get_relay_status("unknown");
    EXPECT_EQ(s2.state, RelayState::UNKNOWN);
}

// 下行：有效 JSON -> 推送至 EventPublisher
TEST_F(FotaHandlerTest, DownlinkForwarded) {
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
    json j = make_downlink_json("cmd-1", payload);
    std::string s = j.dump();
    std::vector<uint8_t> raw(s.begin(), s.end());

    mqtt_->deliver_downlink("vehicle/TBOX_DEV_001/down/fota", raw);

    // 等待 worker
    for (int i = 0; i < 50 && pushed_.empty(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_EQ(pushed_.size(), 1u);
    EXPECT_NE(pushed_[0].find("cmd-1"), std::string::npos);
}

// 下行：解析失败不推送 (TBOX-TSP-1002)
TEST_F(FotaHandlerTest, DownlinkParseFailed) {
    std::string bad = "{not json";
    std::vector<uint8_t> raw(bad.begin(), bad.end());

    mqtt_->deliver_downlink("vehicle/TBOX_DEV_001/down/fota", raw);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_EQ(pushed_.size(), 0u);
}

// 节流：连续上行被节流跳过
TEST_F(FotaHandlerTest, Throttle) {
    mqtt_->publish_result = {true, PublishOutcome::ACCEPTED};

    auto r1 = handler_->handle_uplink(make_snapshot("t1", 1));
    EXPECT_TRUE(r1.accepted);

    // 立即再上行不同 msg_id -> 节流
    auto r2 = handler_->handle_uplink(make_snapshot("t2", 2));
    EXPECT_TRUE(r2.accepted);  // 已接收，速率限制跳过

    // 只 publish 一次（t2 被节流）
    ASSERT_EQ(mqtt_->publish_calls().size(), 1u);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
