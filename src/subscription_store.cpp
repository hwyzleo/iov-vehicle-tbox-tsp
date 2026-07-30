// 订阅 generation 持久化实现 (CR-004 §3.1, §11.2)
#include "subscription_store.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

SubscriptionStore::SubscriptionStore(const std::string& store_root)
    : store_(hwyz::store::Store::open("tsp", store_root)) {
}

bool SubscriptionStore::load(uint64_t& generation, std::string& digest) const {
    generation = 0;
    digest.clear();
    if (!store_.isReady()) {
        return false;
    }
    // 仅当 generation 与 digest 均存在时才视为已持久化；否则按首次启动处理。
    if (!store_.has(kGenerationKey) || !store_.has(kDigestKey)) {
        return false;
    }
    try {
        // framework-store 仅实例化 string/int/double/bool，generation 以 string 存储。
        std::string gen_str = store_.loadOr<std::string>(kGenerationKey, std::string{});
        digest = store_.loadOr<std::string>(kDigestKey, std::string{});
        if (!gen_str.empty()) {
            generation = std::stoull(gen_str);
        }
    } catch (const std::exception& e) {
        LogAdapter::subscription().warn(
            "tsp.subscription.store.load_failed",
            "订阅持久化状态读取异常，按首次启动处理", {
                {"error", tbox::fw::log::FieldValue::makeString(e.what())}
            });
        generation = 0;
        digest.clear();
        return false;
    }
    return generation > 0;
}

void SubscriptionStore::save(uint64_t generation, const std::string& digest) {
    if (!store_.isReady()) {
        LogAdapter::subscription().warn(
            "tsp.subscription.store.not_ready",
            "订阅持久化存储不可用，generation 仅保留在内存");
        return;
    }
    store_.save<std::string>(kGenerationKey, std::to_string(generation));
    store_.save<std::string>(kDigestKey, digest);
    store_.flush();
}

bool SubscriptionStore::is_ready() const {
    return store_.isReady();
}

} // namespace tsp
} // namespace tbox
