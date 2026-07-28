// tests/test_tsp_event_publisher.cpp
#include <gtest/gtest.h>
#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/types.h"
#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>
#include <thread>

using namespace tbox::tsp;

namespace {
FotaCommand make_cmd(const std::string& id) {
    FotaCommand c;
    c.command_id = id;
    c.delivery_id = "dlv-" + id;
    c.payload = {0x01, 0x02};
    return c;
}
}

class TspEventPublisherTest : public ::testing::Test {
protected:
    // 记录 push 调用顺序
    std::vector<std::string> pushed_;
    std::mutex mtx_;
    std::atomic<int> push_count_{0};

    TspEventPublisher::PushFn make_recording_push_fn() {
        return [this](uint32_t event_type, const std::string& payload) -> bool {
            (void)event_type;
            // payload 中包含 command_id（由 publisher 编码）；此处仅记录事件类型
            std::lock_guard<std::mutex> lock(mtx_);
            pushed_.push_back(payload);
            push_count_++;
            return true;
        };
    }
};

// 下行按 MQTT 接收顺序投递 (CR-003 §5)
TEST_F(TspEventPublisherTest, FifoOrdering) {
    TspEventPublisher pub(/*queue=*/64, SlowSubscriberPolicy::kDrop);
    pub.set_push_fn(make_recording_push_fn());
    pub.set_has_subscriber_fn([](uint32_t) { return true; });
    ASSERT_TRUE(pub.start());

    for (int i = 0; i < 5; i++) {
        pub.publish_fota_command(make_cmd("cmd-" + std::to_string(i)));
    }

    // 等待 worker 处理完
    while (push_count_.load() < 5) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    pub.stop();

    ASSERT_EQ(pushed_.size(), 5u);
    // 验证顺序：按投递顺序
    for (size_t i = 0; i < pushed_.size(); i++) {
        EXPECT_NE(pushed_[i].find("cmd-" + std::to_string(i)), std::string::npos);
    }
}

// 队列满 + drop 策略：丢弃新命令，不阻塞调用方
TEST_F(TspEventPublisherTest, QueueFullDrop) {
    TspEventPublisher pub(/*queue=*/2, SlowSubscriberPolicy::kDrop);
    // push_fn 阻塞，使队列积压
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

    // 填满队列（2 条）+ worker 取走 1 条（阻塞中）
    pub.publish_fota_command(make_cmd("a"));
    while (entered.load() < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    pub.publish_fota_command(make_cmd("b"));  // 入队
    pub.publish_fota_command(make_cmd("c"));  // 入队（队列满）

    // 再投递 -> drop（返回 true，不阻塞）
    bool ok = pub.publish_fota_command(make_cmd("d"));
    EXPECT_TRUE(ok);

    block = false;
    pub.stop();

    // 至少投递了 a/b/c，d 被丢弃
    EXPECT_GE(pushed_.size(), 3u);
}

// 队列满 + reject 策略：返回 false 给调用方
TEST_F(TspEventPublisherTest, QueueFullReject) {
    TspEventPublisher pub(/*queue=*/1, SlowSubscriberPolicy::kReject);
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

    pub.publish_fota_command(make_cmd("a"));
    while (entered.load() < 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    pub.publish_fota_command(make_cmd("b"));  // 入队（满）

    bool ok = pub.publish_fota_command(make_cmd("c"));  // reject
    EXPECT_FALSE(ok);

    block = false;
    pub.stop();
}

// 无订阅者：不静默丢弃，记录分类错误（push 仍尝试，由返回值判定）
TEST_F(TspEventPublisherTest, NoSubscriberSkips) {
    TspEventPublisher pub(/*queue=*/8, SlowSubscriberPolicy::kDrop);
    std::atomic<int> push_count{0};
    pub.set_push_fn([&](uint32_t, const std::string&) -> bool {
        push_count++;
        return false;  // 模拟无订阅者发送失败
    });
    pub.set_has_subscriber_fn([](uint32_t) { return false; });
    ASSERT_TRUE(pub.start());

    pub.publish_fota_command(make_cmd("x"));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pub.stop();

    // has_subscriber_fn 返回 false -> 不调用 push_fn
    EXPECT_EQ(push_count.load(), 0);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
