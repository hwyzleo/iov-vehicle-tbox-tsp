// TBOX-TSP IPC 方法/事件 ID (TBOX-TSP-DSN-CR-009 §Client 与 IPC 契约)
//
// 传输层由 framework-ipc 负责，序列化/编解码在 TspIpcDispatcher / tsp_client 中完成。
// 本头定义方法号与 JSON 字段名，供 dispatcher、retry policy、client facade 共享。
//
// CR-009：旧 report/command/status 专用 API 已删除；IPC 只承载单一序列化
// vehicle.common.v1.VehicleMessageEnvelope。若 framework-ipc JSON wire 需要 base64，
// 只对完整 Envelope bytes 做一次编码，禁止外层独立 payload、service 或 PayloadType。
// build-time 共享（不随 SDK 安装）；安装的 SDK 契约为 <tbox/tsp/...>。

#pragma once

#include <cstdint>

namespace tbox {
namespace tsp {
namespace ipc {

// Socket 路径基线 (CR-003 §8)
constexpr const char* DEFAULT_SOCKET_PATH = "/tmp/tbox-tsp.sock";

// 方法 ID（与 framework-ipc RequestHeader.method_id 一致）
enum class MethodId : uint32_t {
    GET_NET_STATUS             = 1,   // 请求-响应（网络状态，保留）
    EXCHANGE_VEHICLE_MESSAGE   = 2,   // 请求-响应（通用车云消息交换，阻塞至业务 RESPONSE/超时）
    SUBSCRIBE_VEHICLE_MESSAGE  = 3,   // 注册订阅（下行 EVENT）
    SUBSCRIBE_NET_STATUS       = 4,   // 注册订阅（网络状态变化，保留）
};

// 推送事件类型（服务端主动推送给已订阅的客户端）
enum class EventType : uint32_t {
    NET_STATUS_CHANGED = 100,
    VEHICLE_MESSAGE    = 102,   // 通用下行 EVENT Envelope（service + 单一 Envelope bytes）
};

// ============================================================
// JSON envelope 字段名（上行/下行/订阅共享契约）
// ============================================================
// CR-009 §Client 与 IPC 契约：wire 只承载单一 envelope_base64；
// 禁止外层独立 payload、service 或 PayloadType（service 仅作为 EVENT 推送分类键）。
namespace field {
    constexpr const char* ENVELOPE_B64    = "envelope_base64";  // 完整 Envelope bytes 的 base64（仅一次）
    constexpr const char* SERVICE         = "service";          // EVENT 推送的服务分类键
    constexpr const char* OUTCOME         = "outcome";          // TransportOutcome 字符串
    constexpr const char* TIMEOUT_MS      = "timeout_ms";       // 调用方 ExchangeOptions.timeout（毫秒）
    constexpr const char* MAX_RESPONSE_BYTES = "max_response_bytes";
    constexpr const char* STATUS          = "status";           // TBOX-TSP-10xx 业务状态码
    constexpr const char* ERROR           = "error";            // 受控摘要
    constexpr const char* TRACE_ID        = "trace_id";
    constexpr const char* REQUEST_ID      = "request_id";
    constexpr const char* SUCCESS         = "success";
} // namespace field

} // namespace ipc
} // namespace tsp
} // namespace tbox
