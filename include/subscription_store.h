// 订阅 generation 持久化 (CR-004 §3.1, §11.2)
//
// 封装 framework-store，保存 tsp/subscriptions/generation 与 content_digest。
// 启动时恢复/计算 generation；提交失败、响应丢失或进程重启不得单独递增 generation。

#pragma once

#include "store.h"

#include <cstdint>
#include <string>

namespace tbox {
namespace tsp {

class SubscriptionStore {
public:
    // store_root 默认 "/var/lib/tbox"（framework-store 默认）；测试可注入临时目录。
    explicit SubscriptionStore(const std::string& store_root = "/var/lib/tbox");

    // 读取持久化的 generation/digest。
    // 返回 false 表示尚未持久化（首次启动），generation 写 0、digest 写空。
    bool load(uint64_t& generation, std::string& digest) const;

    // 原子持久化 generation/digest。
    void save(uint64_t generation, const std::string& digest);

    bool is_ready() const;

private:
    hwyz::store::Store store_;
    static constexpr const char* kGenerationKey = "subscriptions.generation";
    static constexpr const char* kDigestKey = "subscriptions.content_digest";
};

} // namespace tsp
} // namespace tbox
