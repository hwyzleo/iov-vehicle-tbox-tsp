// TBOX-TSP 下行事件推送器 (CR-003 §5, §6)
//
// TspEventPublisher 将下行 FOTA 命令按 MQTT 接收顺序投递至有界队列，
// 由独立 worker 线程调用 framework-ipc Server::push_event 推送给已订阅的 tsp_client。
//
// 背压 (CR-003 §6)：
// - MQTT 下行 callback 只投递到有界队列，不直接阻塞写 SOMEIP client socket。
// - downlink_queue_size 有界；队列满时按 slow_subscriber_policy 处理并输出分类错误。
// - 同一 client fd 的 Response/Event 写入由 framework 串行化（per-fd write_mutex）。
//
// 注意：framework push_event 为同步阻塞写（顺序遍历订阅 fd）。worker 线程将推送
// 与 MQTT 回调线程隔离；队列满策略保证 MQTT 回调不被阻塞。

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include "tbox/tsp/types.h"

namespace tbox {
namespace tsp {

/// 慢消费者策略 (CR-003 §6)
enum class SlowSubscriberPolicy : uint8_t {
    kDisconnect = 0,  // 断开慢订阅者（framework 未暴露 kick，best-effort 记录并丢弃）
    kDrop       = 1,  // 丢弃新命令
    kReject     = 2   // 拒绝入队，返回 false 给调用方
};

class TspEventPublisher {
public:
    /// 推送回调：调用 framework Server::push_event(event_type, payload_json)
    using PushFn = std::function<bool(uint32_t event_type, const std::string& payload_json)>;
    /// 订阅者存在性查询回调
    using HasSubscriberFn = std::function<bool(uint32_t event_type)>;

    TspEventPublisher(uint32_t downlink_queue_size = 256,
                      SlowSubscriberPolicy policy = SlowSubscriberPolicy::kDisconnect);
    ~TspEventPublisher();

    TspEventPublisher(const TspEventPublisher&) = delete;
    TspEventPublisher& operator=(const TspEventPublisher&) = delete;

    void set_push_fn(PushFn fn);
    void set_has_subscriber_fn(HasSubscriberFn fn);

    bool start();
    void stop();

    /// 投递下行 FOTA 命令到有界队列（按 MQTT 接收顺序处理）。
    /// @return true=已入队；false=被拒绝（policy==kReject 且队列满）。
    bool publish_fota_command(const FotaCommand& cmd);

    /// 当前队列长度（测试/诊断用）
    size_t queue_size() const;

private:
    void worker_loop();

    uint32_t queue_capacity_;
    SlowSubscriberPolicy policy_;
    PushFn push_fn_;
    HasSubscriberFn has_subscriber_fn_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<FotaCommand> queue_;
    std::atomic<bool> running_{false};
    std::thread worker_;
};

} // namespace tsp
} // namespace tbox
