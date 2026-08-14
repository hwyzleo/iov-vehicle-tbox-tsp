// src/downlink_route_dispatcher.cpp
//
// CR-006 §6.2: 按 owner/route_id/target 分发 routed downlink 事件。
#include "downlink_route_dispatcher.h"
#include "log_adapter.h"
#include "hash.h"

namespace tbox {
namespace tsp {

namespace {

// 稳定组合键：owner/route_id/target
std::string route_key(const std::string& owner,
                      const std::string& route_id,
                      const std::string& target) {
    return owner + "/" + route_id + "/" + target;
}

// route_id 不可逆摘要（日志脱敏，CR-006 §13.9）
std::string route_id_hash(const std::string& route_id) {
    return tbox::fw::hash::sha256_hex(std::string_view(route_id));
}

} // anonymous namespace

DownlinkRouteDispatcher::DownlinkRouteDispatcher() = default;
DownlinkRouteDispatcher::~DownlinkRouteDispatcher() = default;

void DownlinkRouteDispatcher::register_handler(const std::string& owner,
                                                const std::string& route_id,
                                                const std::string& target,
                                                DownlinkHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[route_key(owner, route_id, target)] = std::move(handler);
}

bool DownlinkRouteDispatcher::dispatch(const RoutedDownlinkEvent& event) {
    DownlinkHandler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = handlers_.find(route_key(event.owner, event.route_id, event.target));
        if (it != handlers_.end()) {
            handler = it->second;
        }
    }

    if (handler) {
        handler(event);
        LogAdapter::fota().info(
            "tsp.route.downlink.forwarded", "routed downlink 已分发", {
                {"owner", tbox::fw::log::FieldValue::makeString(event.owner)},
                {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                    route_id_hash(event.route_id))},
                {"target", tbox::fw::log::FieldValue::makeString(event.target)},
                {"payload_size", tbox::fw::log::FieldValue::makeInt(
                    static_cast<int64_t>(event.payload.size()))}
            });
        return true;
    } else {
        // 未知 owner/route_id/target，拒绝并记录 (CR-006 §6.2)
        LogAdapter::fota().warn(
            "tsp.route.downlink.unmatched", "未知 route/target，拒绝下行", {
                {"owner", tbox::fw::log::FieldValue::makeString(event.owner)},
                {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                    route_id_hash(event.route_id))},
                {"target", tbox::fw::log::FieldValue::makeString(event.target)},
                {"payload_size", tbox::fw::log::FieldValue::makeInt(
                    static_cast<int64_t>(event.payload.size()))}
            });
        return false;
    }
}

} // namespace tsp
} // namespace tbox
