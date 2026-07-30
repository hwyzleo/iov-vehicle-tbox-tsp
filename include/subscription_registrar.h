// 业务订阅注册器 (CR-004 §2, §5, §6, §7, §8, §9, §11.3)
//
// 通过 tbox::mqtt_client 提交完整快照、查询接受状态、执行相同 generation 幂等重试。
// 监听 MQTT transport 断/连：断开 -> NOT_REGISTERED（保留 catalog/generation/digest）；
// 重连 -> 立即以相同 generation 重新提交完整快照。带抖动指数退避。
//
// 边界：本地 REGISTERED 仅表示 MQTT daemon 接受快照，不表示 Broker SUBACK / Cloud Ready。

#pragma once

#include "mqtt_facade.h"
#include "registration_state.h"
#include "snapshot_builder.h"
#include "subscription_catalog.h"
#include "subscription_store.h"
#include "subscription_types.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tbox {
namespace tsp {

class MqttSubscriptionRegistrar {
public:
    MqttSubscriptionRegistrar(std::shared_ptr<MqttFacade> mqtt,
                              std::shared_ptr<SubscriptionCatalog> catalog,
                              std::shared_ptr<SubscriptionStore> store);
    ~MqttSubscriptionRegistrar();

    MqttSubscriptionRegistrar(const MqttSubscriptionRegistrar&) = delete;
    MqttSubscriptionRegistrar& operator=(const MqttSubscriptionRegistrar&) = delete;

    // 启动：恢复 generation、构建快照、首次提交、（可选）启动连接监控线程。
    // start_monitor=false 时不启动后台线程，供测试通过 tick() 驱动 (CR-004 §12)。
    bool start(bool start_monitor = true);

    // 停止：取消重试、关闭线程
    void stop();

    // 应用业务变更：影子校验 -> 新 generation -> 提交 (CR-004 §8)
    // 校验失败返回 false；ACCEPTED 前保留上一已确认 generation。
    bool apply_catalog_change(const std::vector<SubscriptionItem>& new_items);

    // 单次驱动连接检查与重试（测试用；生产由后台线程调用）
    void tick();

    // 当前注册状态
    RegistrationStatus status() const;

    // 是否已完成 Mandatory 快照本地提交（业务 relay ready 门闩, CR-004 §6, REQ §4.2）
    bool is_registration_ready() const;

private:
    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SubscriptionCatalog> catalog_;
    std::shared_ptr<SubscriptionStore> store_;
    SnapshotBuilder builder_;
    RegistrationStateHolder state_;

    // 提交上下文（submit_mutex_ 保护）
    mutable std::mutex submit_mutex_;
    SubscriptionSnapshot current_snapshot_;
    uint64_t accepted_generation_ = 0;
    std::string accepted_digest_;
    ReplaceSnapshotResult last_result_;
    uint32_t retry_count_ = 0;
    uint64_t next_retry_ms_ = 0;
    bool submitted_once_ = false;

    // 连接监控
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    bool last_connected_ = false;
    std::mutex monitor_mutex_;

    static constexpr uint32_t kPollIntervalMs = 500;
    static constexpr uint32_t kBackoffInitialMs = 200;
    static constexpr uint32_t kBackoffMaxMs = 5000;
    static constexpr double kBackoffMultiplier = 2.0;

    void monitor_loop();
    void check_connection_and_retry();
    // 对指定快照执行一次提交；返回结果状态（不触碰 catalog/current/persist）
    SnapshotStatus submit_snapshot_locked(const SubscriptionSnapshot& snap);
    void schedule_retry_locked();
    uint32_t current_backoff_ms() const;
    static uint64_t now_ms();
};

} // namespace tsp
} // namespace tbox
