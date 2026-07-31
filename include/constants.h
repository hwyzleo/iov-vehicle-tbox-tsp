// include/constants.h
#pragma once

#include <string>
#include "tsp_build_config.h"

namespace tbox {
namespace tsp {

// FOTA topic 模板（SPEC §3, CR-006 §13.3）
// route 模式: TSP 只保存未展开模板 vehicle/{ecu_uid}/up|down/fota，
//   展开由 MQTT 按 PROV 身份完成，TSP 不拼装完整 Topic。
#if !TSP_MQTT_ROUTE_API
namespace topics {
    // legacy: 上行完整 Topic 拼装（deprecated, CR-006 §10.2）
    inline std::string fota_up(const std::string& device_sn) {
        return "vehicle/" + device_sn + "/up/fota";
    }
    // legacy: 下行完整 Topic 拼装（deprecated, CR-006 §10.2）
    inline std::string fota_down(const std::string& device_sn) {
        return "vehicle/" + device_sn + "/down/fota";
    }
} // namespace topics
#endif

// 默认 QoS
constexpr int FOTA_QOS = 1;

// 去重窗口（毫秒）-- 同一 snapshot 在此窗口内重复上报将被丢弃
constexpr uint64_t DEDUP_WINDOW_MS = 60000;

// 节流间隔（毫秒）-- 上行发布最小间隔
constexpr uint64_t THROTTLE_INTERVAL_MS = 5000;

} // namespace tsp
} // namespace tbox
