// TBOX-TSP 下行事件推送器 (CR-003 §5, §6; CR-009 §EVENT 下行)
//
// TspEventPublisher 将下行 EVENT Envelope 按 service 分流投递至有界队列，
// 由独立 worker 线程调用 framework-ipc Server::push_event 推送给已订阅的 tsp_client。
//
// CR-009：旧 FOTA 专用 publish_fota_command(FotaCommand) 已删除；通用载体为
// 单一序列化 vehicle.common.v1.VehicleMessageEnvelope（payload 不透明）。
//
// 背压 (CR-003 §6, CR-009 §EVENT 下行)：
// - MQTT 下行 callback 只投递到有界队列，不直接阻塞写 SOMEIP client socket。
// - 每 service 有界队列（downlink_queue_capacity）；队列满时按 slow_subscriber_policy
//   处理并输出分类错误。
// - 同一 client fd 的 Response/Event 写入由 framework 串行化（per-fd write_mutex）。
//
// 注意：framework push_event 为同步阻塞写（顺序遍历订阅 fd）。worker 线程将推送
// 与 MQTT 回调线程隔离；队列满策略保证 MQTT 回调不被阻塞。

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace tbox {
namespace tsp {

// 下行 EVENT Envelope（payload 不透明，TSP 只按 service 分流）
struct VehicleMessageEvent {
    std::string service;                 // 订阅分类键（如 vehicle.fota）
    std::vector<std::byte> envelope_bytes;  // 单一序列化 Envelope
    std::string trace_id;
    std::string request_id;
};

/// 慢消费者策略 (CR-003 §6)
enum class SlowSubscriberPolicy : uint8_t {
    kDisconnect = 0,  // 断开慢订阅者（framework 未暴露 kick，best-effort 记录并丢弃）
    kDrop       = 1,  // 丢弃新事件
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

    /// 投递下行 EVENT Envelope 到对应 service 的有界队列（按 MQTT 接收顺序处理）。
    /// @return true=已入队；false=被拒绝（policy==kReject 且队列满）。
    bool publish_vehicle_message(const std::string& service,
                                 const std::vector<std::byte>& envelope_bytes,
                                 const std::string& trace_id = "",
                                 const std::string& request_id = "");

    /// 当前队列长度（测试/诊断用）
    size_t queue_size() const;

private:
    void worker_loop();

    uint32_t queue_capacity_;   // 每 service 下行队列容量
    SlowSubscriberPolicy policy_;
    PushFn push_fn_;
    HasSubscriberFn has_subscriber_fn_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<VehicleMessageEvent> queue_;
    std::unordered_map<std::string, size_t> service_count_;  // 每 service 在队数
    std::atomic<bool> running_{false};
    std::thread worker_;
};

} // namespace tsp
} // namespace tbox
