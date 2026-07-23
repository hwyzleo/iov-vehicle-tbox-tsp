// include/error_codes.h
#pragma once

#include <cstdint>

namespace tbox {
namespace tsp {

// TBOX-TSP 错误码（SPEC §6）
enum class ErrorCode : uint16_t {
    SUCCESS = 0,
    PUBLISH_FAILED = 1001,       // 上行发布失败（MQTT 不可用 / 超时）
    PAYLOAD_PARSE_FAILED = 1002, // 下行 payload 解析失败
    DEDUP_HIT = 1003,            // 去重命中，已丢弃重复上报
};

// 错误码转字符串
inline const char* error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS: return "SUCCESS";
        case ErrorCode::PUBLISH_FAILED: return "TBOX-TSP-1001: 上行发布失败";
        case ErrorCode::PAYLOAD_PARSE_FAILED: return "TBOX-TSP-1002: 下行payload解析失败";
        case ErrorCode::DEDUP_HIT: return "TBOX-TSP-1003: 去重命中";
        default: return "UNKNOWN";
    }
}

} // namespace tsp
} // namespace tbox
