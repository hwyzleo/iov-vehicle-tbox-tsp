// 注册状态机 (CR-004 §2, §9, §11.4)
//
// 仅表达 TSP->MQTT 本地注册状态，不表达 Broker SUBACK / Cloud Ready。
// 状态迁移：NOT_REGISTERED -> REGISTERING -> REGISTERED/DEGRADED
//          REGISTERED -> NOT_REGISTERED (MQTT IPC 断开)
//          REGISTERED -> REGISTERING (新 generation)
//          DEGRADED -> REGISTERING (退避到期/IPC 恢复)

#pragma once

#include "subscription_types.h"

#include <cstdint>
#include <mutex>
#include <string>

namespace tbox {
namespace tsp {

class RegistrationStateHolder {
public:
    RegistrationStateHolder() = default;

    // 线程安全读取当前状态副本
    RegistrationStatus snapshot() const;
    RegistrationState state() const;

    // 状态迁移（调用方负责符合状态机约束）
    void transition_to(RegistrationState s);

    // 设置当前 generation / digest / 计数
    void set_generation(uint64_t generation,
                        const std::string& digest_hash,
                        uint32_t mandatory_count,
                        uint32_t item_count);

    // 设置最近一次提交结果与错误
    void set_result(SnapshotStatus result, const std::string& last_error);

    void increment_retry();
    void reset_retry();

    // 刷新 updated_at_ms
    void touch();

private:
    mutable std::mutex mutex_;
    RegistrationStatus status_;

    static uint64_t now_ms();
};

} // namespace tsp
} // namespace tbox
