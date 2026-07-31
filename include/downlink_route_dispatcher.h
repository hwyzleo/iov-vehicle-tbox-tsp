// include/downlink_route_dispatcher.h
//
// DownlinkRouteDispatcher (CR-006 §6.2)
//
// 按 MQTT routed downlink 事件的 owner/route_id/target 分发到业务 Handler，
// 不解析完整 Topic。未知 owner/route_id/target 被拒绝并记录，不进入默认 Handler。
// 下行顺序、有界队列、慢消费者隔离和非幂等不重放由上层（MQTT SDK +
// TspEventPublisher）保证，本组件只做稳定路由键 -> Handler 的分发。
#pragma once

#include "mqtt_facade.h"  // RoutedDownlinkEvent

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace tbox {
namespace tsp {

class DownlinkRouteDispatcher {
public:
    /// 业务下行处理回调：接收 payload + 关联上下文 (request_id/trace_id)。
    using DownlinkHandler =
        std::function<void(const std::vector<uint8_t>& payload,
                           const std::string& request_id,
                           const std::string& trace_id)>;

    DownlinkRouteDispatcher();
    ~DownlinkRouteDispatcher();

    DownlinkRouteDispatcher(const DownlinkRouteDispatcher&) = delete;
    DownlinkRouteDispatcher& operator=(const DownlinkRouteDispatcher&) = delete;

    /// 注册 (owner, route_id, target) -> handler (CR-006 §6.2)
    void register_handler(const std::string& owner,
                          const std::string& route_id,
                          const std::string& target,
                          DownlinkHandler handler);

    /// 分发 routed downlink 事件 (CR-006 §6.2)
    /// 未知 owner/route_id/target 被拒绝并记录，不进入默认 Handler。
    /// @return true 表示匹配并分发到 Handler；false 表示未知 route/target 被拒绝。
    bool dispatch(const RoutedDownlinkEvent& event);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, DownlinkHandler> handlers_;
};

} // namespace tsp
} // namespace tbox
