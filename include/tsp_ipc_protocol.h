// TBOX-TSP IPC 方法/事件 ID (CR-003 §2)
//
// 传输层由 framework-ipc 负责，序列化/编解码在 TspIpcDispatcher / tsp_client 中完成。
// 此头定义方法号与 JSON 字段名，供 dispatcher、retry policy、client facade 共享。
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
    GET_NET_STATUS            = 1,   // 请求-响应
    REPORT_SOFTWARE_INVENTORY = 2,   // 请求-响应（上行）
    GET_RELAY_STATUS          = 3,   // 请求-响应（状态查询）
    SUBSCRIBE_NET_STATUS      = 4,   // 注册订阅
    SUBSCRIBE_FOTA_COMMAND    = 5,   // 注册订阅（下行）
};

// 推送事件类型（服务端主动推送给已订阅的客户端）
enum class EventType : uint32_t {
    NET_STATUS_CHANGED = 100,
    FOTA_COMMAND       = 102,
};

// ============================================================
// JSON envelope 字段名（上行/下行/状态共享契约）
// ============================================================
namespace field {
    constexpr const char* SNAPSHOT_SEQ   = "snapshot_seq";
    constexpr const char* MSG_ID         = "msg_id";
    constexpr const char* CONTENT_TYPE   = "content_type";
    constexpr const char* PAYLOAD_B64    = "payload_base64";
    constexpr const char* TRACE_ID       = "trace_id";
    constexpr const char* REQUEST_ID     = "request_id";
    constexpr const char* COMMAND_ID     = "command_id";
    constexpr const char* DELIVERY_ID    = "delivery_id";
    constexpr const char* SCHEMA_VERSION = "schema_version";
    constexpr const char* STATUS         = "status";
    constexpr const char* ACCEPTED       = "accepted";
    constexpr const char* OUTCOME        = "outcome";
    constexpr const char* STATE          = "state";
    constexpr const char* LAST_ERROR     = "last_error";
    constexpr const char* ERROR          = "error";
    constexpr const char* SUCCESS        = "success";
} // namespace field

} // namespace ipc
} // namespace tsp
} // namespace tbox
