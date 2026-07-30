// 业务订阅目录 SSOT (CR-004 §2, §4, §11.1)
//
// SubscriptionCatalog 是 TSP 业务 Topic、QoS、target 与 mandatory 属性的唯一事实来源。
// MQTT 配置不得复制业务 Topic。加载时校验唯一 route_id、Topic 模板、方向、QoS、target。
//
// Topic 模板保存占位符（如 {ecu_uid}），不固化设备实例值；展开由 expand_topic_template
// 完成（迁移期 TSP adapter 展开；未来 MQTT 批量接口收模板自行展开）。

#pragma once

#include "subscription_types.h"
#include "yaml-cpp/yaml.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

// 业务订阅目录 (CR-004 §2, §11.1)
class SubscriptionCatalog {
public:
    SubscriptionCatalog() = default;

    // 从配置节点加载 (tsp.subscriptions 序列)。失败返回 false 并写入 error。
    bool load_from_yaml(const YAML::Node& node, std::string& error);

    // 校验候选集合（影子校验），不替换当前集合 (CR-004 §8, §11.4)。
    bool validate(const std::vector<SubscriptionItem>& items,
                  std::string& error) const;

    // 替换当前集合（调用方应先 validate）。
    void replace(std::vector<SubscriptionItem> items);

    const std::vector<SubscriptionItem> items() const;
    uint32_t mandatory_count() const;

private:
    mutable std::mutex mutex_;
    std::vector<SubscriptionItem> items_;
    uint32_t mandatory_count_ = 0;
};

} // namespace tsp
} // namespace tbox
