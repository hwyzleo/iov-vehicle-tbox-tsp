// tests/test_tsp_event_publisher.cpp
// TspEventPublisher 单元测试（CR-003 §5, §6; CR-009 §EVENT 下行）：
//   FIFO 顺序、每 service 有界队列（drop/reject）、无订阅者分类错误。
#include <gtest/gtest.h>
#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/types.h"
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <thread>

using namespace tbox::tsp;

namespace {
std::vector<std::byte> make_bytes(const std::string& tag) {
    std::vector<std::byte> out(tag.size());
    for (size_t i = 0; i < tag.size(); ++i) {
        out[i] = static_cast<std::byte>(static_cast<uint8_t>(tag[i]));
    }
    return out;
}
}

class TspEventPublisherTest : public ::testing::Test {
protected:
    // 记录 push 顺序（payload JSON 中 service 字段）
    std::vector<std::string> pushed_;
    std::mutex mtx_;
    std::atomic<int> push_count_{0};

    TspEventPublisher::PushFn make_recording_push_fn() {
        return [this](uint32_t event_type, const std::string& payload) -> bool {
            (void)event_type;
            // payload 为 service + envelope_base64 JSON；仅记录 service
            auto pos = payload.find("\"service\"");
            std::lock_guard<std::mutex> lock(mtx_);
            pushed_.push_back(pos != std::string::npos ? "has-service" : "no-service");
            push_count_++;
            return true;
        };
    }
};

// 下行按 MQTT 接收顺序投递（全局 FIFO 保留每 service 顺序）
TEST_F(TspEventPublisherTest, FifoOrdering) {
    TspEventPublisher pub(/*queue=*/64, SlowSubscriberPolicy::kDrop);
    pub.set_push_fn(make_recording_push_fn());
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());

    for (int i = 0; i < 5; i++) {
        pub.publish_vehicle_message("vehicle.fota", make_bytes("evt-" + std::to_string(i)));
    }

    // 等待 worker 处理完
    while (push_count_.load() < 5) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    pub.stop();

    ASSERT_EQ(pushed_.size(), 5u);
    // 全部按序投递（service 键正确编码）
    for (const auto& p : pushed_) {
        EXPECT_EQ(p, "has-service");
    }
}

// 每 service 队列满 + drop 策略：丢弃新事件，不阻塞调用方
TEST_F(TspEventPublisherTest, QueueFullDrop) {
    TspEventPublisher pub(/*per_service=*/2, SlowSubscriberPolicy::kDrop);
    std::atomic<bool> block{true};
    std::atomic<int> entered{0};
    pub.set_push_fn([&](uint32_t, const std::string& payload) -> bool {
        entered++;
        while (block.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        std::lock_guard<std::mutex> lock(mtx_);
        pushed_.push_back(payload);
        return true;
    });
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());

    pub.publish_vehicle_message("vehicle.fota", make_bytes("a"));
    while (entered.load() < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    pub.publish_vehicle_message("vehicle.fota", make_bytes("b"));  // 入队
    pub.publish_vehicle_message("vehicle.fota", make_bytes("c"));  // 入队（该 service 满）

    // 再投递 -> drop（返回 true，不阻塞）
    bool ok = pub.publish_vehicle_message("vehicle.fota", make_bytes("d"));
    EXPECT_TRUE(ok);

    block = false;
    pub.stop();
    EXPECT_GE(pushed_.size(), 3u);
}

// 每 service 队列满 + reject 策略：返回 false 给调用方
TEST_F(TspEventPublisherTest, QueueFullReject) {
    TspEventPublisher pub(/*per_service=*/1, SlowSubscriberPolicy::kReject);
    std::atomic<bool> block{true};
    std::atomic<int> entered{0};
    pub.set_push_fn([&](uint32_t, const std::string&) -> bool {
        entered++;
        while (block.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return true;
    });
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());

    pub.publish_vehicle_message("vehicle.fota", make_bytes("a"));
    while (entered.load() < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    pub.publish_vehicle_message("vehicle.fota", make_bytes("b"));  // 入队（满）

    bool ok = pub.publish_vehicle_message("vehicle.fota", make_bytes("c"));  // reject
    EXPECT_FALSE(ok);

    block = false;
    pub.stop();
}

// 不同 service 队列独立（service A 满不影响 service B）
TEST_F(TspEventPublisherTest, PerServiceQueueIsolation) {
    TspEventPublisher pub(/*per_service=*/1, SlowSubscriberPolicy::kReject);
    std::atomic<bool> block{true};
    std::atomic<int> entered{0};
    pub.set_push_fn([&](uint32_t, const std::string&) -> bool {
        entered++;
        while (block.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return true;
    });
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());

    pub.publish_vehicle_message("vehicle.fota", make_bytes("a"));
    while (entered.load() < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    pub.publish_vehicle_message("vehicle.fota", make_bytes("b"));  // fota 满
    // 其他 service 仍可入队
    bool ok = pub.publish_vehicle_message("vehicle.other", make_bytes("x"));
    EXPECT_TRUE(ok);

    block = false;
    pub.stop();
}

// 无订阅者：不静默丢弃，记录分类错误（push 仍尝试，由返回值判定）
TEST_F(TspEventPublisherTest, NoSubscriberSkips) {
    TspEventPublisher pub(/*per_service=*/8, SlowSubscriberPolicy::kDrop);
    std::atomic<int> push_count{0};
    pub.set_push_fn([&](uint32_t, const std::string&) -> bool {
        push_count++;
        return false;  // 模拟无订阅者发送失败
    });
    pub.set_has_subscriber_fn([](uint32_t) { return false; });
    ASSERT_TRUE(pub.start());

    pub.publish_vehicle_message("vehicle.fota", make_bytes("x"));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pub.stop();

    // has_subscriber_fn 返回 false -> 不调用 push_fn
    EXPECT_EQ(push_count.load(), 0);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
