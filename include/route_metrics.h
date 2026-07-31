// include/route_metrics.h
//
// Route API 能力状态与指标计数器 (CR-006 §7, §9, §10.1)
//
// capability 状态：TSP 启动时经 subscribeRoutedDownlink 探测 MQTT route 能力
//   (§10.1)。MQTT client SDK 暂无 capability/version 查询接口，本状态基于
//   route API 调用结果（成功/失败）维护，能力不足时明确 DEGRADED，不静默双路径。
//
// 指标：TSP 当前无 framework 指标系统，本结构为局部原子计数，作为指标系统
//   就绪前的过渡；正式聚合/导出待 framework 指标库。日志不得作为指标唯一存储 (§6.3)。
//   route_degraded_duration_ms 需状态机时间跟踪 + 指标系统导出，暂未实现。
#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace tbox {
namespace tsp {

/// Route API 能力与路由状态 (CR-006 §7, §10.1)
struct RouteApiStatus {
    bool route_api_supported = false;            // MQTT route 能力（启动探测）
    std::string uplink_route_state = "UNKNOWN";   // ACTIVE/DEGRADED/FAILED/UNKNOWN
    std::string downlink_route_state = "UNKNOWN"; // ACTIVE/DEGRADED/FAILED/UNKNOWN
};

/// 指标快照（可拷贝，用于查询返回）
struct RouteMetricsSnapshot {
    uint64_t route_publish_total = 0;
    uint64_t route_publish_failure_total = 0;
    uint64_t route_downlink_total = 0;
    uint64_t route_downlink_unmatched_total = 0;
    uint64_t route_api_incompatible = 0;
};

/// Route 指标计数器 (CR-006 §9)
struct RouteMetrics {
    std::atomic<uint64_t> route_publish_total{0};
    std::atomic<uint64_t> route_publish_failure_total{0};
    std::atomic<uint64_t> route_downlink_total{0};
    std::atomic<uint64_t> route_downlink_unmatched_total{0};
    std::atomic<uint64_t> route_api_incompatible{0};
    // route_degraded_duration_ms: TODO，需状态机时间跟踪 + 指标系统导出

    /// 返回可拷贝快照（线程安全读取各计数器）
    RouteMetricsSnapshot snapshot() const {
        RouteMetricsSnapshot s;
        s.route_publish_total = route_publish_total.load();
        s.route_publish_failure_total = route_publish_failure_total.load();
        s.route_downlink_total = route_downlink_total.load();
        s.route_downlink_unmatched_total = route_downlink_unmatched_total.load();
        s.route_api_incompatible = route_api_incompatible.load();
        return s;
    }
};

} // namespace tsp
} // namespace tbox
