// tests/mocks.h -- 测试用 mock 实现
#pragma once

#include "mqtt_facade.h"
#include "vehicle_message_gateway.h"
#include "net_status_provider.h"
#include "sec_business_key_facade.h"
#include "tbox/tsp/types.h"
#include "tbox/sec/business_key.h"
#include "tbox/sec/errors.h"
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

    // ---- CR-014/015: readiness 可配置状态与事件投递 ----
    CloudReadiness cloud_readiness;
    CapabilityReadiness capability_readiness;
    bool cloud_ready_subscribe_ok = true;
    bool capability_subscribe_ok = true;

    CloudReadiness getCloudReadiness() override {
        std::lock_guard<std::mutex> lock(mutex_);
        return cloud_readiness;
    }
    bool subscribeCloudReadinessChanged(CloudReadinessCallback cb) override {
        std::lock_guard<std::mutex> lock(mutex_);
        cloud_callback_ = std::move(cb);
        return cloud_ready_subscribe_ok;
    }
    CapabilityReadiness getCapabilityReadiness(const std::string& capability) override {
        std::lock_guard<std::mutex> lock(mutex_);
        CapabilityReadiness r = capability_readiness;
        if (r.capability.empty()) r.capability = capability;
        return r;
    }
    bool subscribeCapabilityReadinessChanged(
            const std::string& /*capability*/, CapabilityReadinessCallback cb) override {
        std::lock_guard<std::mutex> lock(mutex_);
        capability_callback_ = std::move(cb);
        return capability_subscribe_ok;
    }

    // 测试辅助：投递 Cloud/Capability readiness 事件
    void deliver_cloud_readiness(const CloudReadiness& r) {
        CloudReadinessCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cloud_readiness = r;
            cb = cloud_callback_;
        }
        if (cb) cb(r);
    }
    void deliver_capability_readiness(const CapabilityReadiness& r) {
        CapabilityReadinessCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            capability_readiness = r;
            cb = capability_callback_;
        }
        if (cb) cb(r);
    }

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
    CloudReadinessCallback cloud_callback_;
    CapabilityReadinessCallback capability_callback_;
};

// ============================================================
// FakeSecClient -- SecBusinessKeyFacade 契约测试实现。
// 以普通可拷贝字段配置结果，方法内构造（SecureBuffer 不可复制）。
// ============================================================
class FakeSecClient : public SecBusinessKeyFacade {
public:
    struct StatusItem {
        std::string purpose;
        int state = 0;  // tbox::sec::BusinessKeyState
        uint64_t business_key_version = 0;
        std::string key_id_digest;
    };

    // 状态查询
    int status_error_code = 0;  // tbox::sec::ErrorCode
    std::vector<StatusItem> status_items;
    int status_calls = 0;

    // 导入
    int import_error_code = 0;
    int import_state = 2;  // COMMITTED
    std::vector<StatusItem> import_items;
    std::vector<uint8_t> import_proof;
    std::string proof_algorithm = "hmac-sha256";
    int import_calls = 0;
    std::vector<std::string> imported_request_ids;
    std::size_t last_import_item_count = 0;

    // 结果查询
    int query_error_code = 0;
    int query_state = 2;
    std::vector<StatusItem> query_items;
    int query_calls = 0;

    tbox::sec::ErrorCode get_business_key_status(
        const std::string& /*domain*/,
        const std::vector<std::string>& purposes,
        tbox::sec::BusinessKeyStatusSet& out) override {
        ++status_calls;
        out.items.clear();
        for (const auto& si : status_items) {
            tbox::sec::BusinessKeyStatus s;
            s.purpose = si.purpose;
            s.state = static_cast<tbox::sec::BusinessKeyState>(si.state);
            s.business_key_version = si.business_key_version;
            s.key_id_digest = si.key_id_digest;
            out.items.push_back(std::move(s));
        }
        (void)purposes;
        return static_cast<tbox::sec::ErrorCode>(status_error_code);
    }

    tbox::sec::ErrorCode import_wrapped_business_keys(
        const std::string& request_id,
        const std::string& business_domain,
        const std::vector<tbox::sec::WrappedKeyItem>& items,
        tbox::sec::ImportResult& out) override {
        ++import_calls;
        imported_request_ids.push_back(request_id);
        last_import_item_count = items.size();
        out = tbox::sec::ImportResult{};
        out.request_id = request_id;
        out.business_domain = business_domain;
        out.state = static_cast<tbox::sec::BusinessKeyImportState>(import_state);
        for (const auto& si : import_items) {
            tbox::sec::BusinessKeyStatus s;
            s.purpose = si.purpose;
            s.state = static_cast<tbox::sec::BusinessKeyState>(si.state);
            s.business_key_version = si.business_key_version;
            s.key_id_digest = si.key_id_digest;
            out.items.push_back(std::move(s));
        }
        out.import_proof.assign(import_proof);
        out.proof_algorithm = proof_algorithm;
        return static_cast<tbox::sec::ErrorCode>(import_error_code);
    }

    tbox::sec::ErrorCode get_business_key_import_result(
        const std::string& request_id,
        tbox::sec::ImportResult& out) override {
        ++query_calls;
        out = tbox::sec::ImportResult{};
        out.request_id = request_id;
        out.state = static_cast<tbox::sec::BusinessKeyImportState>(query_state);
        for (const auto& si : query_items) {
            tbox::sec::BusinessKeyStatus s;
            s.purpose = si.purpose;
            s.state = static_cast<tbox::sec::BusinessKeyState>(si.state);
            s.business_key_version = si.business_key_version;
            s.key_id_digest = si.key_id_digest;
            out.items.push_back(std::move(s));
        }
        out.import_proof.assign(import_proof);
        out.proof_algorithm = proof_algorithm;
        return static_cast<tbox::sec::ErrorCode>(query_error_code);
    }
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
