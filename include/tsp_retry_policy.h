// TBOX-TSP 方法重试策略 (CR-003 §4; CR-009 §Client 与 IPC 契约)
//
// framework-ipc Client 提供传输失败后的单次重连能力，
// 但 TspRetryPolicy 按 method 分类决定是否允许自动重放：
//
// - 只读/幂等（GET_NET_STATUS）：允许一次重试
// - 一次性/订阅（EXCHANGE_VEHICLE_MESSAGE / SUBSCRIBE_*）：禁止自动重放。
//   EXCHANGE_VEHICLE_MESSAGE 禁止不可见自动重试（CR-009 §错误与重试）；重试由
//   CGW-FOTA 以原 request/idempotency 身份发起，TSP 侧同 message_id 复用会被拒绝。

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
        kOneShot              ///< 一次性/订阅，禁止自动重放
    };

    /// 返回指定 method_id 的安全类别
    static Category categorize(uint32_t method_id);

    /// 传输失败后是否允许自动重试
    static bool should_retry(uint32_t method_id);
};

} // namespace tsp
} // namespace tbox
