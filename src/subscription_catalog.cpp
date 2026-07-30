// 业务订阅目录实现 (CR-004 §2, §4, §11.1)
#include "subscription_catalog.h"
#include "log_adapter.h"

#include <algorithm>
#include <unordered_set>

namespace tbox {
namespace tsp {

namespace {

// 校验单条订阅项，失败返回 false 并写入 error。
bool validate_item(const SubscriptionItem& item, std::string& error) {
    if (item.route_id.empty()) {
        error = "route_id is empty";
        return false;
    }
    if (item.topic_template.empty()) {
        error = "topic_template is empty for route_id=" + item.route_id;
        return false;
    }
    // 禁止旧 device_sn 模板静默兜底 (CR-004 §11.1, §11.5)
    if (item.topic_template.find("{device_sn}") != std::string::npos) {
        error = "topic_template uses deprecated {device_sn} for route_id=" +
                item.route_id + ", use {ecu_uid}";
        return false;
    }
    if (item.target.empty()) {
        error = "target is empty for route_id=" + item.route_id;
        return false;
    }
    if (item.qos > 2) {
        error = "qos out of range [0,2] for route_id=" + item.route_id;
        return false;
    }
    return true;
}

} // anonymous namespace

bool SubscriptionCatalog::load_from_yaml(const YAML::Node& node, std::string& error) {
    std::vector<SubscriptionItem> parsed;
    if (node && node.IsSequence()) {
        for (const auto& entry : node) {
            SubscriptionItem item;
            item.route_id = entry["route_id"].as<std::string>("");
            item.topic_template = entry["topic_template"].as<std::string>("");
            std::string dir_str = entry["direction"].as<std::string>("UP");
            if (!direction_from_string(dir_str, item.direction)) {
                error = "invalid direction '" + dir_str +
                        "' for route_id=" + item.route_id;
                LogAdapter::subscription().error(
                    "tsp.subscription.catalog.invalid",
                    "订阅目录加载失败：方向非法", {
                        {"reason_code",
                         tbox::fw::log::FieldValue::makeString("invalid_direction")}
                    });
                return false;
            }
            item.qos = static_cast<uint8_t>(
                entry["qos"].as<int>(1));
            item.target = entry["target"].as<std::string>("");
            item.mandatory = entry["mandatory"].as<bool>(false);
            parsed.push_back(std::move(item));
        }
    }

    if (!validate(parsed, error)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    items_ = std::move(parsed);
    mandatory_count_ = 0;
    for (const auto& it : items_) {
        if (it.mandatory) ++mandatory_count_;
    }
    return true;
}

bool SubscriptionCatalog::validate(const std::vector<SubscriptionItem>& items,
                                   std::string& error) const {
    std::unordered_set<std::string> seen;
    for (const auto& item : items) {
        if (!validate_item(item, error)) {
            return false;
        }
        if (!seen.insert(item.route_id).second) {
            error = "duplicate route_id=" + item.route_id;
            return false;
        }
    }
    return true;
}

void SubscriptionCatalog::replace(std::vector<SubscriptionItem> items) {
    std::lock_guard<std::mutex> lock(mutex_);
    items_ = std::move(items);
    mandatory_count_ = 0;
    for (const auto& it : items_) {
        if (it.mandatory) ++mandatory_count_;
    }
}

const std::vector<SubscriptionItem> SubscriptionCatalog::items() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_;
}

uint32_t SubscriptionCatalog::mandatory_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return mandatory_count_;
}

} // namespace tsp
} // namespace tbox
