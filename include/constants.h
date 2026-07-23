// include/constants.h
#pragma once

#include <string>

namespace tbox {
namespace tsp {

// FOTA topic 矩阵（SPEC §3）
namespace topics {
    // 上行：FOTA 版本清单快照上报
    inline std::string fota_up(const std::string& device_sn) {
        return "vehicle/" + device_sn + "/up/fota";
    }
    // 下行：云端 FOTA 业务下行
    inline std::string fota_down(const std::string& device_sn) {
        return "vehicle/" + device_sn + "/down/fota";
    }
} // namespace topics

// 默认 QoS
constexpr int FOTA_QOS = 1;

// 去重窗口（毫秒）—— 同一 snapshot 在此窗口内重复上报将被丢弃
constexpr uint64_t DEDUP_WINDOW_MS = 60000;

// 节流间隔（毫秒）—— 上行发布最小间隔
constexpr uint64_t THROTTLE_INTERVAL_MS = 5000;

} // namespace tsp
} // namespace tbox
