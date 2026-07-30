// 快照构建器实现 (CR-004 §3.1, §11.2)
#include "snapshot_builder.h"
#include "hash.h"

#include <algorithm>

namespace tbox {
namespace tsp {

namespace {

// 按 route_id 稳定排序（route_id 在 owner 内唯一，排序保证规范化）。
std::vector<SubscriptionItem> sorted_by_route_id(std::vector<SubscriptionItem> items) {
    std::stable_sort(items.begin(), items.end(),
        [](const SubscriptionItem& a, const SubscriptionItem& b) {
            return a.route_id < b.route_id;
        });
    return items;
}

} // anonymous namespace

std::string SnapshotBuilder::serialize_item(const SubscriptionItem& item) const {
    // 规范化序列化：字段以 '|' 分隔，顺序固定。
    // mandatory 以 0/1 表达，保证布尔不因平台表达差异影响摘要。
    return item.route_id + "|" +
           item.topic_template + "|" +
           direction_to_string(item.direction) + "|" +
           std::to_string(static_cast<int>(item.qos)) + "|" +
           item.target + "|" +
           (item.mandatory ? "1" : "0");
}

std::string SnapshotBuilder::compute_digest(const std::vector<SubscriptionItem>& items) const {
    auto sorted = sorted_by_route_id(items);
    std::string canonical;
    canonical.reserve(sorted.size() * 64);
    for (const auto& it : sorted) {
        canonical += serialize_item(it);
        canonical += "\n";
    }
    return tbox::fw::hash::sha256_hex(std::string_view(canonical));
}

SubscriptionSnapshot SnapshotBuilder::build(const std::vector<SubscriptionItem>& items,
                                            const std::string& owner,
                                            uint64_t current_generation,
                                            const std::string& current_digest) const {
    SubscriptionSnapshot snap;
    snap.owner = owner;
    snap.items = sorted_by_route_id(items);
    snap.content_digest = compute_digest(items);

    // generation 复用 / 递增 (CR-004 §3.1, §11.2)
    // 提交失败、响应丢失或进程重启不得单独递增；只有集合语义变化才递增。
    if (current_generation > 0 && snap.content_digest == current_digest) {
        snap.generation = current_generation;
    } else {
        snap.generation = current_generation + 1;
    }

    // registration_complete: 完整快照由目录构建，包含全部 Mandatory 项 (CR-004 REQ §4.2)
    snap.registration_complete = true;

    return snap;
}

} // namespace tsp
} // namespace tbox
