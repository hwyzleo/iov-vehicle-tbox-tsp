// TBOX-TSP 公共 DTO (TBOX-TSP-DSN-CR-009 §Client 与 IPC 契约, SPEC §5.2)
//
// 本头由 daemon (TspIpcDispatcher/TspEventPublisher/VehicleMessageGateway) 与
// client SDK (tbox::tsp::TspClient) 共享，构成双方的 protocol contract。
// 调用方不接触 method_id、JSON/base64、socket。
//
// CR-009：旧 FOTA snapshot/command DTO（FotaSnapshot/FotaCommand/RelayStatus/
// ReportResult）已删除；唯一业务载体为单一序列化
// vehicle.common.v1.VehicleMessageEnvelope（payload 保持不透明）。
// tbox::tsp_client 只暴露通用 exchange/subscribe，不暴露 FOTA 生成类型。

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

// ============================================================
// 通用车云消息（CR-009 §Client 与 IPC 契约）
// ============================================================
// 单一序列化 vehicle.common.v1.VehicleMessageEnvelope 的字节；业务 bytes 位于
// payload=10，本层保持不透明。wire 只对 envelope_bytes 做一次 base64。
struct VehicleMessage {
    std::vector<std::byte> envelope_bytes;
};

// 传输结果（CR-009 §错误与重试 / SPEC §16.4）：
// Accepted 不等于 MQTT PUBACK 或 FOTA 业务成功；value 仅在 TSP 收到对应业务
// RESPONSE Envelope 时存在。
enum class TransportOutcome : uint8_t {
    Accepted = 0,        // 已受理并完成业务 RESPONSE（value 为 RESPONSE Envelope）
    Rejected,            // 拒绝（TTL 过期、allowlist/容量/方向拒绝等）
    Timeout,             // 已由 MQTT 接受但业务 RESPONSE 超时
    Unknown,             // 结果不确定（MQTT 投递结果未知/响应丢失）
    Unavailable,         // MQTT route/能力不可用（DEGRADED）
    VersionMismatch,     // 协议/能力版本不兼容（不走 legacy fallback）
    PayloadTooLarge,     // 超出资源上限（不截断、不分片、不落盘）
    ProtocolError,       // Envelope/方向/route/关联错误
    Stopping             // 服务停止中，拒绝新请求
};

inline const char* transport_outcome_to_string(TransportOutcome o) {
    switch (o) {
        case TransportOutcome::Accepted:        return "Accepted";
        case TransportOutcome::Rejected:        return "Rejected";
        case TransportOutcome::Timeout:         return "Timeout";
        case TransportOutcome::Unknown:         return "Unknown";
        case TransportOutcome::Unavailable:     return "Unavailable";
        case TransportOutcome::VersionMismatch: return "VersionMismatch";
        case TransportOutcome::PayloadTooLarge: return "PayloadTooLarge";
        case TransportOutcome::ProtocolError:   return "ProtocolError";
        case TransportOutcome::Stopping:        return "Stopping";
        default: return "?";
    }
}

// 调用选项（CR-009 §Client 与 IPC 契约）
struct ExchangeOptions {
    std::chrono::milliseconds timeout{2500};     // 等待业务 RESPONSE 的 deadline（须 < SOME/IP Method deadline）
    std::size_t max_response_bytes = 16384;      // 业务 RESPONSE Envelope 上限
};

// 调用上下文（链路关联；非业务身份）
struct CallContext {
    std::string trace_id;     // 合法且长度受限的链路关联标识（原样传播）
    std::string request_id;   // 单次中继请求标识
};

// 通用交换结果（CR-009 §Client 与 IPC 契约）
template <typename T>
struct TransportResult {
    TransportOutcome outcome = TransportOutcome::Unknown;
    std::optional<T> value;            // 仅 Accepted 且存在业务 RESPONSE 时非空
    int32_t error_code = 0;            // TBOX-TSP-10xx 业务状态码（0 = 无）
    std::string error;                 // 受控摘要（不记录完整 Envelope/payload/身份）
};

// 下行 EVENT 回调：携带原始序列化 Envelope，TSP 直接推送。
using VehicleMessageHandler = std::function<void(const VehicleMessage&)>;

} // namespace tsp
} // namespace tbox
