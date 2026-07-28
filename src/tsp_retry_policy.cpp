#include "tsp_retry_policy.h"

namespace tbox {
namespace tsp {

TspRetryPolicy::Category TspRetryPolicy::categorize(uint32_t method_id) {
    switch (static_cast<ipc::MethodId>(method_id)) {
        // 只读/幂等：允许一次重试
        case ipc::MethodId::GET_NET_STATUS:
        case ipc::MethodId::GET_RELAY_STATUS:
            return Category::kReadOnly;

        // 业务幂等：reportSoftwareInventory（同 msg_id/snapshot_seq 由 TSP 去重）
        case ipc::MethodId::REPORT_SOFTWARE_INVENTORY:
            return Category::kBusinessIdempotent;

        // 一次性/订阅：禁止自动重放
        case ipc::MethodId::SUBSCRIBE_NET_STATUS:
        case ipc::MethodId::SUBSCRIBE_FOTA_COMMAND:
            return Category::kOneShot;

        default:
            return Category::kOneShot;  // 未知方法保守处理
    }
}

bool TspRetryPolicy::should_retry(uint32_t method_id) {
    Category cat = categorize(method_id);
    return cat == Category::kReadOnly || cat == Category::kBusinessIdempotent;
}

} // namespace tsp
} // namespace tbox
