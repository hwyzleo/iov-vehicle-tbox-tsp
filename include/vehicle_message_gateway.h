// TBOX-TSP-DSN-CR-009 §16: VehicleMessageGateway —— TspRelayService 内聚组件。
//
// 在 tbox::tsp_client 与 MQTT Route 之间建立通用 VehicleMessage 桥接：
//   - 解析 vehicle.common.v1.VehicleMessageEnvelope 元数据做受控路由/关联/资源控制，
//     payload(10) 全程保持不透明（不解析 FOTA 业务字段）。
//   - 上行：exchange() 先在 publish 前以请求 message_id 建立有界 correlation 项，
//     再 publishRoute(owner=tsp, route_id=fota.uplink)；local accepted/PUBACK 只更新
//     投递阶段，不完成业务 exchange；阻塞等待合法 RESPONSE 或 deadline。
//   - 下行：handle_routed_downlink 校验 route 后按 message_kind 分流：
//     RESPONSE 以 correlation_id 唯一匹配并完成请求；EVENT 进入对应 service 的
//     有界队列经 TspEventPublisher 推送。
//   - 不持久化 Task/Execution/correlation 完成证据；可靠恢复由 CGW-FOTA
//     reconcile/outbox 负责。STOPPING 时拒绝新 exchange，in-flight 收敛为 Stopping。
//
// 状态：有界 correlation table、service/PayloadType/route capability catalog、
// 每 service 下行队列、transport counters 与脱敏诊断。

#pragma once

#include "mqtt_facade.h"
#include "tbox/tsp/types.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace tbox {
namespace tsp {

class TspEventPublisher;
class DownlinkRouteDispatcher;

// 资源/allowlist 限制（tsp.vehicle_message.*；有界默认由实现/容量测试回填）
struct VehicleMessageLimits {
    std::vector<std::string> allowed_services = {"vehicle.fota"};
    // protocol_version 是不透明版本串（SSOT canonical，如 "fota-v1"）；按整串 allowlist
    // 精确匹配，禁止从中解析数值 major（VEH-PROTO / iov-cloud-parent-proto SSOT）。
    std::vector<std::string> allowed_protocol_versions = {"fota-v1"};
    uint32_t max_envelope_bytes = 16384;   // 序列化 Envelope 总长上限
    uint32_t max_payload_bytes = 8192;     // payload(10) 上限
};

// Gateway 资源/背压限制（tsp.vehicle_message.*）
struct VehicleMessageGatewayConfig {
    VehicleMessageLimits limits;
    uint32_t max_in_flight = 64;            // 并发 correlation 上限
    uint32_t downlink_queue_capacity = 256; // 每 service 下行队列上限
    uint32_t worker_count = 1;              // correlation 超时收敛 worker 数
    uint32_t default_exchange_timeout_ms = 2500; // 默认 exchange deadline（须 < SOME/IP Method deadline）
};

// Dispatcher/FrameworkServer 依赖的通用中继 facade（CR-009 §Client 与 IPC 契约）
class VehicleMessageRelayInterface {
public:
    virtual ~VehicleMessageRelayInterface() = default;

    /// 通用车云消息交换（同步阻塞至业务 RESPONSE/超时）。STOPPING 时返回 Stopping。
    virtual TransportResult<VehicleMessage> exchange(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx) = 0;
};

class VehicleMessageGateway {
public:
    explicit VehicleMessageGateway(std::shared_ptr<MqttFacade> mqtt);
    ~VehicleMessageGateway();

    VehicleMessageGateway(const VehicleMessageGateway&) = delete;
    VehicleMessageGateway& operator=(const VehicleMessageGateway&) = delete;

    bool initialize(const VehicleMessageGatewayConfig& config);
    bool start();   // 注册 routed downlink + 启动 correlation 收敛 worker
    void stop();

    // 上行（dispatcher 线程调用，阻塞至业务 RESPONSE/deadline）
    TransportResult<VehicleMessage> exchange(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx);

    // 下行入口（DownlinkRouteDispatcher 分发 owner=tsp+fota.downlink+tsp.fota）
    void handle_routed_downlink(const RoutedDownlinkEvent& event);

    // EVENT 下行推送器接线（Application/Relay 在 IPC 构造后调用）
    void set_event_publisher(TspEventPublisher* publisher);

    // 传输计数器（脱敏诊断）
    struct TransportCounters {
        std::atomic<uint64_t> request_total{0};
        std::atomic<uint64_t> request_published{0};
        std::atomic<uint64_t> response_completed{0};
        std::atomic<uint64_t> response_rejected{0};  // 迟到/重复/错配/未知
        std::atomic<uint64_t> event_forwarded{0};
        std::atomic<uint64_t> event_dropped{0};
        std::atomic<uint64_t> exchange_timeout{0};
        std::atomic<uint64_t> envelope_invalid{0};
    };
    // 计数器快照（可拷贝，测试/诊断用）
    struct TransportCountersSnapshot {
        uint64_t request_total = 0;
        uint64_t request_published = 0;
        uint64_t response_completed = 0;
        uint64_t response_rejected = 0;
        uint64_t event_forwarded = 0;
        uint64_t event_dropped = 0;
        uint64_t exchange_timeout = 0;
        uint64_t envelope_invalid = 0;
    };
    TransportCountersSnapshot counters() const;

private:
    struct CorrelationEntry;
    struct EnvelopeValidation;

    EnvelopeValidation validate_envelope(const std::vector<std::byte>& bytes,
                                         bool expect_request) const;

    // correlation 超时收敛 worker 循环
    void sweeper_loop(int shard, int shard_count);

    std::shared_ptr<MqttFacade> mqtt_;
    VehicleMessageGatewayConfig config_;
    std::unique_ptr<DownlinkRouteDispatcher> route_dispatcher_;
    TspEventPublisher* event_publisher_ = nullptr;

    // correlation table：message_id -> 引用计数 entry
    std::mutex table_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CorrelationEntry>> table_;
    // 最近终止的 message_id tombstone（迟到响应保护）：message_id -> 终止时刻
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> recent_terminal_;

    // worker 线程池（worker_count 个 shard）
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    TransportCounters counters_;
};

} // namespace tsp
} // namespace tbox
