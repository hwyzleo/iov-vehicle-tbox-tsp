// tests/mocks.h -- 测试用 mock 实现
#pragma once

#include "mqtt_facade.h"
#include "vehicle_message_gateway.h"
#include "net_status_provider.h"
#include "tbox/tsp/types.h"
#include <vector>
#include <mutex>
#include <atomic>
#include <condition_variable>

namespace tbox {
namespace tsp {
namespace test {

// ============================================================
// MockMqttFacade -- 记录 publishRoute/subscribeRoutedDownlink/快照调用，
// 可配置 publishRoute 返回结果；持有 routed downlink 回调以便测试投递下行。
// ============================================================
class MockMqttFacade : public MqttFacade {
public:
    struct PublishRouteCall {
        std::string owner;
        std::string route_id;
        std::string msg_id;
        std::vector<uint8_t> payload;
        int qos = 0;
        std::string content_type;
        std::string trace_id;
        std::string request_id;
    };

    // 配置 publishRoute 返回结果
    MqttPublishResult publish_route_result{true, MqttDeliveryOutcome::Accepted};
    // 配置 replaceSubscriptionSnapshot 返回结果 (CR-004)
    ReplaceSnapshotResult snapshot_result;
    // 连接状态（可由测试切换以模拟断/连, CR-004 §7）
    mutable bool connected = true;
    // 是否支持 routed downlink（subscribeRoutedDownlink 返回结果）
    bool routed_downlink_supported = true;

    bool initialize() override { return true; }
    bool start() override { return true; }
    void stop() override {}

    MqttPublishResult publishRoute(const std::string& owner,
                                   const std::string& route_id,
                                   const std::string& msg_id,
                                   const std::vector<uint8_t>& payload,
                                   int qos,
                                   const std::string& content_type = "application/x-protobuf",
                                   const std::string& trace_id = "",
                                   const std::string& request_id = "") override {
        std::lock_guard<std::mutex> lock(mutex_);
        publish_route_calls_.push_back({owner, route_id, msg_id, payload, qos, content_type, trace_id, request_id});
        return publish_route_result;
    }

    bool subscribeRoutedDownlink(const std::string& owner,
                                 RoutedDownlinkCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        routed_owner_ = owner;
        routed_callback_ = std::move(callback);
        return routed_downlink_supported;
    }

    ReplaceSnapshotResult replaceSubscriptionSnapshot(
            const SubscriptionSnapshot& snapshot) override {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_calls_.push_back(snapshot);
        ++snapshot_call_count_;
        // 模拟真实 adapter：MQTT 未连接时结果未知 (CR-004 §11.3)
        if (!connected) {
            ReplaceSnapshotResult r;
            r.status = SnapshotStatus::UNKNOWN;
            r.reason_code = "mqtt_not_connected";
            return r;
        }
        ReplaceSnapshotResult r = snapshot_result;
        if (r.status == SnapshotStatus::ACCEPTED) {
            r.accepted_generation = snapshot.generation;
        }
        return r;
    }

    SnapshotStatusResult getSubscriptionSnapshotStatus(
            const std::string& /*owner*/, uint64_t generation) override {
        SnapshotStatusResult r;
        r.generation = generation;
        r.status = snapshot_result.status;
        return r;
    }

    bool is_connected() const override { return connected; }

    // 测试辅助：模拟收到 routed downlink 事件 (CR-006 §6)
    void deliver_routed_downlink(const RoutedDownlinkEvent& event) {
        RoutedDownlinkCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = routed_callback_;
        }
        if (cb) cb(event);
    }

    std::vector<PublishRouteCall> publish_route_calls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return publish_route_calls_;
    }

    std::vector<SubscriptionSnapshot> snapshot_calls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_calls_;
    }

    uint64_t snapshot_call_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_call_count_;
    }

    mutable std::mutex mutex_;
    std::vector<PublishRouteCall> publish_route_calls_;
    std::string routed_owner_;
    RoutedDownlinkCallback routed_callback_;
    std::vector<SubscriptionSnapshot> snapshot_calls_;
    uint64_t snapshot_call_count_ = 0;
};

// ============================================================
// MockVehicleMessageRelay -- 实现 VehicleMessageRelayInterface。
// 默认返回配置好的结果（非阻塞）；blocking 模式下记录 in-flight 请求并阻塞，
// 直到测试调用 complete() 提供结果（用于 client<->server wire contract 测试）。
// ============================================================
class MockVehicleMessageRelay : public VehicleMessageRelayInterface {
public:
    struct ExchangeCall {
        VehicleMessage request;
        ExchangeOptions options;
        CallContext ctx;
    };

    // 非阻塞模式默认结果
    TransportResult<VehicleMessage> default_result;
    // blocking 模式开关
    bool blocking = false;

    TransportResult<VehicleMessage> exchange(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            calls_.push_back({request, options, ctx});
        }
        if (!blocking) {
            return default_result;
        }
        // blocking：等待测试 complete()
        std::unique_lock<std::mutex> lk(mutex_);
        cv_.wait(lk, [this] { return completed_ || cancelled_.load(); });
        if (cancelled_.load()) {
            TransportResult<VehicleMessage> r;
            r.outcome = TransportOutcome::Stopping;
            return r;
        }
        return pending_result_;
    }

    // blocking 模式：为下一个/当前 in-flight 请求提供结果并唤醒
    void complete(TransportResult<VehicleMessage> result) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_result_ = std::move(result);
            completed_ = true;
        }
        cv_.notify_all();
    }

    void reset_blocking() {
        std::lock_guard<std::mutex> lock(mutex_);
        completed_ = false;
        cancelled_ = false;
    }

    void cancel_waiting() {
        cancelled_.store(true);
        cv_.notify_all();
    }

    int call_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int>(calls_.size());
    }

    ExchangeCall last_call() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return calls_.back();
    }

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<ExchangeCall> calls_;
    TransportResult<VehicleMessage> pending_result_;
    bool completed_ = false;
    std::atomic<bool> cancelled_{false};
};

// ============================================================
// MockNetStatusProvider -- 使用 net_status_provider.h 中的 tbox::tsp::MockNetStatusProvider
// ============================================================

} // namespace test
} // namespace tsp
} // namespace tbox
