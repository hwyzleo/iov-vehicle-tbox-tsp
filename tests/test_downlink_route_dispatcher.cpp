// tests/test_downlink_route_dispatcher.cpp
//
// CR-006 §6.2: DownlinkRouteDispatcher 按 owner/route_id/target 分发，
// 未知 owner/route_id/target 被拒绝并记录，不进入默认 Handler。
#include <gtest/gtest.h>
#include "downlink_route_dispatcher.h"

#include <atomic>
#include <mutex>
#include <vector>

using namespace tbox::tsp;

namespace {
RoutedDownlinkEvent make_event(const std::string& owner,
                               const std::string& route_id,
                               const std::string& target,
                               std::vector<uint8_t> payload = {0x01}) {
    RoutedDownlinkEvent e;
    e.owner = owner;
    e.route_id = route_id;
    e.target = target;
    e.qos = 1;
    e.payload = std::move(payload);
    e.request_id = "req-test";
    e.trace_id = "trace-test";
    return e;
}
} // namespace

// 注册的 (owner, route_id, target) 命中 -> 分发 payload + request_id/trace_id
TEST(DownlinkRouteDispatcherTest, DispatchesToRegisteredHandler) {
    DownlinkRouteDispatcher d;
    std::mutex mtx;
    std::vector<std::vector<uint8_t>> received;
    std::vector<std::string> req_ids;
    std::vector<std::string> trace_ids;

    d.register_handler("tsp", "fota.downlink", "tsp.fota",
        [&](const std::vector<uint8_t>& payload,
            const std::string& request_id,
            const std::string& trace_id) {
            std::lock_guard<std::mutex> lock(mtx);
            received.push_back(payload);
            req_ids.push_back(request_id);
            trace_ids.push_back(trace_id);
        });

    d.dispatch(make_event("tsp", "fota.downlink", "tsp.fota", {0xAA, 0xBB}));

    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0], (std::vector<uint8_t>{0xAA, 0xBB}));
    ASSERT_EQ(req_ids.size(), 1u);
    EXPECT_EQ(req_ids[0], "req-test");
    ASSERT_EQ(trace_ids.size(), 1u);
    EXPECT_EQ(trace_ids[0], "trace-test");
}

// 未知 route_id -> 不分发 (CR-006 §6.2)
TEST(DownlinkRouteDispatcherTest, RejectsUnknownRouteId) {
    DownlinkRouteDispatcher d;
    std::atomic<int> count{0};
    d.register_handler("tsp", "fota.downlink", "tsp.fota",
        [&](const std::vector<uint8_t>&, const std::string&, const std::string&) {
            count++;
        });

    d.dispatch(make_event("tsp", "unknown.route", "tsp.fota"));
    EXPECT_EQ(count.load(), 0);
}

// 未知 target -> 不分发
TEST(DownlinkRouteDispatcherTest, RejectsUnknownTarget) {
    DownlinkRouteDispatcher d;
    std::atomic<int> count{0};
    d.register_handler("tsp", "fota.downlink", "tsp.fota",
        [&](const std::vector<uint8_t>&, const std::string&, const std::string&) {
            count++;
        });

    d.dispatch(make_event("tsp", "fota.downlink", "unknown.target"));
    EXPECT_EQ(count.load(), 0);
}

// 未知 owner -> 不分发
TEST(DownlinkRouteDispatcherTest, RejectsUnknownOwner) {
    DownlinkRouteDispatcher d;
    std::atomic<int> count{0};
    d.register_handler("tsp", "fota.downlink", "tsp.fota",
        [&](const std::vector<uint8_t>&, const std::string&, const std::string&) {
            count++;
        });

    d.dispatch(make_event("other", "fota.downlink", "tsp.fota"));
    EXPECT_EQ(count.load(), 0);
}

// 多个事件串行分发，顺序保留
TEST(DownlinkRouteDispatcherTest, MultipleEventsInOrder) {
    DownlinkRouteDispatcher d;
    std::mutex mtx;
    std::vector<std::string> order;
    d.register_handler("tsp", "fota.downlink", "tsp.fota",
        [&](const std::vector<uint8_t>& payload, const std::string&, const std::string&) {
            std::lock_guard<std::mutex> lock(mtx);
            order.emplace_back(payload.begin(), payload.end());
        });

    d.dispatch(make_event("tsp", "fota.downlink", "tsp.fota", {'1'}));
    d.dispatch(make_event("tsp", "fota.downlink", "tsp.fota", {'2'}));
    d.dispatch(make_event("tsp", "fota.downlink", "tsp.fota", {'3'}));

    ASSERT_EQ(order.size(), 3u);
    EXPECT_EQ(order[0], "1");
    EXPECT_EQ(order[1], "2");
    EXPECT_EQ(order[2], "3");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
