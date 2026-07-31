// TBOX-TSP 公共错误码 (CR-003 §8, SPEC §7)
//
// 业务错误码 TBOX-TSP-10xx 嵌入 IPC 响应 JSON 的 status 字段；
// framework-ipc 传输层错误码 FW-0301~0307 写入 ResponseHeader.status_code。
// 两者语义独立：传输成功(fw_status==0) 时再从 JSON 解析业务 status。
// tsp_client SHALL 将 FW-03xx 映射为公开 client 错误，不泄露 framework 异常类型。

#pragma once

#include <cstdint>
#include <string>

namespace tbox {
namespace tsp {

// TBOX-TSP 业务/客户端错误码
enum class TspErrorCode : int32_t {
    SUCCESS = 0,

    // 业务中继失败 (SPEC §7, TBOX-TSP-10xx)
    PUBLISH_FAILED = 1001,        // 上行发布失败（MQTT 不可用 / 超时）
    PAYLOAD_PARSE_FAILED = 1002,  // 下行 payload 解析失败
    DEDUP_HIT = 1003,             // 去重命中，已丢弃重复上报
    ROUTE_REGISTER_FAILED = 1004, // 业务路由注册失败
    SUBSCRIPTION_INVALID = 1005,         // 业务订阅目录/快照无效 (CR-004 §10)
    SUBSCRIPTION_REGISTER_FAILED = 1006, // 订阅快照注册失败或持续无法恢复 (CR-004 §10)
    ROUTE_API_INCOMPATIBLE = 1007,       // MQTT route 能力不兼容/route 未实例化/route-based 调用失败 (CR-006 §9)

    // client 暴露错误（FW-03xx 传输失败映射，不泄露 framework 异常类型）
    INVALID_PARAMETER = 2001,
    FRAME_TOO_LARGE = 2002,
    NOT_INITIALIZED = 2003,
    CONNECTION_FAILED = 2004,     // 本机 IPC 传输失败（FW-03xx 映射）
    UNKNOWN_OUTCOME = 2005,       // 响应丢失，需用相同 msg_id 查询/重试
    NO_SUBSCRIBER = 2006,         // 下行无订阅者
    INTERNAL_ERROR = 9999
};

const char* error_code_to_string(TspErrorCode code);

/// 将 framework-ipc FW-03xx 传输状态码映射为公开 client 错误。
/// fw_status == 0  -> SUCCESS
/// fw_status > 0   -> 服务端处理/传输错误，映射为 CONNECTION_FAILED
/// fw_status < 0   -> 客户端传输错误，映射为 CONNECTION_FAILED
TspErrorCode map_fw_status(int32_t fw_status);

} // namespace tsp
} // namespace tbox
