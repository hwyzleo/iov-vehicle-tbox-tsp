#include "tsp_retry_policy.h"

namespace tbox {
namespace tsp {

TspRetryPolicy::Category TspRetryPolicy::categorize(uint32_t method_id) {
    switch (static_cast<ipc::MethodId>(method_id)) {
        // 只读/幂等：允许一次重试
        case ipc::MethodId::GET_NET_STATUS:
            return Category::kReadOnly;

        // 一次性/订阅：禁止自动重放。
        // EXCHANGE_VEHICLE_MESSAGE：CR-009 禁止不可见自动重试；重试由 CGW-FOTA
        //   以原 request/idempotency 身份发起，TSP 侧同 message_id 复用会被拒绝。
        case ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE:
        case ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE:
        case ipc::MethodId::SUBSCRIBE_NET_STATUS:
            return Category::kOneShot;

        default:
            return Category::kOneShot;  // 未知方法保守处理
    }
}

bool TspRetryPolicy::should_retry(uint32_t method_id) {
    Category cat = categorize(method_id);
    return cat == Category::kReadOnly;
}

} // namespace tsp
} // namespace tbox
