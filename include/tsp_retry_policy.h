// TBOX-TSP 方法重试策略 (CR-003 §4)
//
// framework-ipc Client 提供传输失败后的单次重连能力，
// 但 TspRetryPolicy 按 method 分类决定是否允许自动重放：
//
// - 只读/幂等（getRelayStatus）：允许一次重试
// - 业务幂等（reportSoftwareInventory，同 msg_id/snapshot_seq 去重）：允许一次重试
// - 一次性/订阅（subscribeFotaCommand）：禁止自动重放（callOnce 语义由 framework subscribe 保证）

#pragma once

#include <cstdint>
#include "tsp_ipc_protocol.h"

namespace tbox {
namespace tsp {

class TspRetryPolicy {
public:
    /// 方法安全类别
    enum class Category : uint8_t {
        kReadOnly,            ///< 只读/幂等，允许一次重试
        kBusinessIdempotent,  ///< 业务幂等（同 msg_id/snapshot_seq），允许一次重试
        kOneShot              ///< 一次性/订阅，禁止自动重放
    };

    /// 返回指定 method_id 的安全类别
    static Category categorize(uint32_t method_id);

    /// 传输失败后是否允许自动重试
    static bool should_retry(uint32_t method_id);
};

} // namespace tsp
} // namespace tbox
