// 快照构建器 (CR-004 §2, §3.1, §11.2)
//
// 对订阅项稳定排序、规范化、计算内容摘要并分配 generation。
// 摘要未变化时复用 generation；集合语义变化时原子递增。

#pragma once

#include "subscription_types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

class SnapshotBuilder {
public:
    // 构建完整快照。
    // owner: 固定服务身份（tsp）。
    // current_generation / current_digest: 持久化的当前值（generation=0 表示首次）。
    //   - 摘要未变化且 current_generation>0 -> 复用 current_generation
    //   - 摘要变化或首次 -> current_generation + 1
    SubscriptionSnapshot build(const std::vector<SubscriptionItem>& items,
                               const std::string& owner,
                               uint64_t current_generation,
                               const std::string& current_digest) const;

    // 计算规范化集合摘要（按 route_id 稳定排序后序列化取 SHA-256 hex）。
    std::string compute_digest(const std::vector<SubscriptionItem>& items) const;

private:
    std::string serialize_item(const SubscriptionItem& item) const;
};

} // namespace tsp
} // namespace tbox
