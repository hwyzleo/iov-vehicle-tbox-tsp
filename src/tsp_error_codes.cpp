#include "tbox/tsp/errors.h"

namespace tbox {
namespace tsp {

const char* error_code_to_string(TspErrorCode code) {
    switch (code) {
        case TspErrorCode::SUCCESS:               return "SUCCESS";
        case TspErrorCode::PUBLISH_FAILED:        return "TBOX-TSP-1001: 上行发布失败";
        case TspErrorCode::PAYLOAD_PARSE_FAILED:  return "TBOX-TSP-1002: Envelope/Route/方向校验失败";
        case TspErrorCode::RESPONSE_CONFLICT:     return "TBOX-TSP-1003: 重复/迟到响应或消息身份冲突";
        case TspErrorCode::ROUTE_REGISTER_FAILED: return "TBOX-TSP-1004: 路由注册失败";
        case TspErrorCode::SUBSCRIPTION_INVALID:         return "TBOX-TSP-1005: 业务订阅目录/快照无效";
        case TspErrorCode::SUBSCRIPTION_REGISTER_FAILED: return "TBOX-TSP-1006: 订阅快照注册失败";
        case TspErrorCode::ROUTE_API_INCOMPATIBLE:       return "TBOX-TSP-1007: MQTT route能力不兼容/route未实例化/route调用失败";
        case TspErrorCode::INVALID_PARAMETER:     return "INVALID_PARAMETER";
        case TspErrorCode::FRAME_TOO_LARGE:       return "FRAME_TOO_LARGE";
        case TspErrorCode::NOT_INITIALIZED:       return "NOT_INITIALIZED";
        case TspErrorCode::CONNECTION_FAILED:     return "CONNECTION_FAILED";
        case TspErrorCode::UNKNOWN_OUTCOME:       return "UNKNOWN_OUTCOME";
        case TspErrorCode::NO_SUBSCRIBER:         return "NO_SUBSCRIBER";
        case TspErrorCode::INTERNAL_ERROR:        return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

TspErrorCode map_fw_status(int32_t fw_status) {
    if (fw_status == 0) {
        return TspErrorCode::SUCCESS;
    }
    // fw_status > 0: 服务端处理/传输错误 (FW-03xx)
    // fw_status < 0: 客户端传输错误
    // 统一映射为 CONNECTION_FAILED，不泄露 framework 异常类型
    return TspErrorCode::CONNECTION_FAILED;
}

} // namespace tsp
} // namespace tbox
