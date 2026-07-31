// include/fota_handler.h
#pragma once

#include "mqtt_facade.h"
#include "fota_relay_interface.h"
#include "subscription_catalog.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/types.h"
#include "tbox/tsp/errors.h"
#include "tsp_build_config.h"

#if TSP_MQTT_ROUTE_API
#include "downlink_route_dispatcher.h"
#include "route_metrics.h"
#endif

#ifdef HAS_FRAMEWORK_LOG
#include "log_adapter.h"
#endif

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <memory>

namespace tbox {
namespace tsp {

class TspEventPublisher;

// FOTA 业务中继处理器 (FotaRelay, CR-003 §2, §4; CR-006 route 迁移)
// SPEC §4.1: 上行 -- snapshot_seq/msg_id 去重/节流后经 tbox::mqtt_client 发布
// SPEC §4.2: 下行 -- 解析后经 TspEventPublisher 推送已订阅的 tsp_client
//
// route 模式 (CR-006): 上行 publishRoute(owner=tsp, route_id=fota.uplink)，
//   下行 subscribeRoutedDownlink + DownlinkRouteDispatcher 按 route_id/target 分发，
//   不缓存 UID、不拼装完整 Topic。
// legacy 模式 (deprecated): 上行 publish 完整 Topic，下行 subscribe 完整 Topic。
//
// accepted 仅表示 TSP 已校验并由 MQTT daemon 接管，不等于 Broker PUBACK (CR-003 §4)。
// 响应丢失时 outcome=unknown；复用相同 msg_id 重试时 TSP 返回已有状态而不重复上云。
class FotaHandler : public FotaRelayInterface {
public:
    FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                TspEventPublisher* event_publisher = nullptr);
    ~FotaHandler();

    // 初始化
    // route 模式 (CR-006): device_sn 被忽略（不缓存 UID，Topic 由 MQTT 展开）
    // legacy 模式: device_sn 必填，用于 Topic 拼装
    bool initialize(const std::string& device_sn);

    // 启动（route: 订阅 routed downlink；legacy: 订阅完整 Topic 下行）
    bool start();

    // 停止
    void stop();

    // 设置下行事件推送器（main 接线后调用）
    void set_event_publisher(TspEventPublisher* publisher);

    // 设置业务订阅目录（legacy: 从目录解析下行投递 Topic）
    void set_catalog(std::shared_ptr<SubscriptionCatalog> catalog);

    // ---- FotaRelayInterface ----
    ReportResult handle_uplink(const FotaSnapshot& snapshot) override;
    RelayStatus get_relay_status(const std::string& msg_id) override;

#if TSP_MQTT_ROUTE_API
    // Route API 能力状态与指标 (CR-006 §7, §9, §10.1)
    RouteApiStatus getRouteApiStatus() const;
    RouteMetricsSnapshot getRouteMetrics() const;
#endif

private:
    // 下行处理：解析 FOTA command payload 并经 EventPublisher 推送 (SPEC §4.2)
    // route 模式由 DownlinkRouteDispatcher 调用；legacy 由 subscribe 回调调用。
    void handle_downstream(const std::vector<uint8_t>& payload,
                           const std::string& request_id,
                           const std::string& trace_id);

    // 节流检查
    bool is_throttled();

#if !TSP_MQTT_ROUTE_API
    // legacy: 从目录解析 FOTA 上下行完整 Topic（目录未设置时回退到 constants）
    std::string resolve_up_topic() const;
    std::string resolve_down_topic() const;
    std::string device_sn_;
#endif

    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SubscriptionCatalog> catalog_;
    TspEventPublisher* event_publisher_ = nullptr;

#if TSP_MQTT_ROUTE_API
    std::unique_ptr<DownlinkRouteDispatcher> route_dispatcher_;
    RouteApiStatus route_api_status_;
    RouteMetrics route_metrics_;
    mutable std::mutex route_status_mutex_;
#endif

    // 中继状态：msg_id -> RelayStatus（同时作为去重表）
    std::unordered_map<std::string, RelayStatus> relay_status_map_;
    std::mutex relay_mutex_;

    // 节流：上次上行发布时间
    uint64_t last_publish_time_ms_ = 0;
    std::mutex throttle_mutex_;

    bool started_ = false;
};

} // namespace tsp
} // namespace tbox
