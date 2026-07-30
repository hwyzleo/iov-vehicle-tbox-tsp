// 业务订阅注册器实现 (CR-004 §5, §6, §7, §8, §9, §11.3)
#include "subscription_registrar.h"
#include "log_adapter.h"
#include "tbox/tsp/errors.h"

#include <chrono>
#include <cmath>
#include <cstdlib>

namespace tbox {
namespace tsp {

namespace {
constexpr const char* kOwner = "tsp";

// 简单抖动：[0, base/2]
uint32_t jitter(uint32_t base) {
    if (base == 0) return 0;
    return static_cast<uint32_t>(std::rand() % (base / 2 + 1));
}
} // anonymous namespace

MqttSubscriptionRegistrar::MqttSubscriptionRegistrar(
        std::shared_ptr<MqttFacade> mqtt,
        std::shared_ptr<SubscriptionCatalog> catalog,
        std::shared_ptr<SubscriptionStore> store)
    : mqtt_(std::move(mqtt))
    , catalog_(std::move(catalog))
    , store_(std::move(store)) {
    std::srand(static_cast<unsigned>(now_ms()));
}

MqttSubscriptionRegistrar::~MqttSubscriptionRegistrar() {
    stop();
}

uint64_t MqttSubscriptionRegistrar::now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool MqttSubscriptionRegistrar::start(bool start_monitor) {
    std::lock_guard<std::mutex> lock(submit_mutex_);

    // 1. 恢复 generation (CR-004 §3.1, §11.3)
    uint64_t persisted_gen = 0;
    std::string persisted_digest;
    store_->load(persisted_gen, persisted_digest);

    // 2. 构建完整快照（摘要未变化复用 generation，变化则递增）
    auto items = catalog_->items();
    current_snapshot_ = builder_.build(items, kOwner, persisted_gen, persisted_digest);

    // 3. 持久化 generation/digest（提交失败/重启不单独递增）
    store_->save(current_snapshot_.generation, current_snapshot_.content_digest);

    state_.set_generation(current_snapshot_.generation,
                          current_snapshot_.content_digest,
                          catalog_->mandatory_count(),
                          static_cast<uint32_t>(current_snapshot_.items.size()));

    LogAdapter::subscription().info(
        "tsp.subscription.snapshot.submitting",
        "提交业务订阅快照", {
            {"generation",
             tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(current_snapshot_.generation))},
            {"item_count",
             tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(current_snapshot_.items.size()))},
            {"mandatory_count",
             tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(catalog_->mandatory_count()))}
        });

    // 4. 首次提交（同步）
    state_.transition_to(RegistrationState::REGISTERING);
    SnapshotStatus s = submit_snapshot_locked(current_snapshot_);
    submitted_once_ = true;

    if (s != SnapshotStatus::ACCEPTED) {
        // 调度重试，但不阻塞进程启动 (CR-004 §6: MQTT 不可用可进入 DEGRADED)
        schedule_retry_locked();
    }

    // 初始化连接基线（供 tick/monitor 检测断/连转换）
    last_connected_ = mqtt_->is_connected();
    if (start_monitor) {
        running_ = true;
        monitor_thread_ = std::thread([this] { monitor_loop(); });
    }
    return true;
}

void MqttSubscriptionRegistrar::stop() {
    running_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    // TSP 停止时取消重试并关闭 client (CR-004 §7)
    std::lock_guard<std::mutex> lock(submit_mutex_);
    state_.transition_to(RegistrationState::NOT_REGISTERED);
}

void MqttSubscriptionRegistrar::monitor_loop() {
    while (running_.load()) {
        for (uint32_t i = 0; i < kPollIntervalMs && running_.load(); i += 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!running_.load()) break;
        check_connection_and_retry();
    }
}

void MqttSubscriptionRegistrar::tick() {
    check_connection_and_retry();
}

void MqttSubscriptionRegistrar::check_connection_and_retry() {
    bool connected = mqtt_->is_connected();
    bool transition = false;
    {
        std::lock_guard<std::mutex> lk(monitor_mutex_);
        if (connected && !last_connected_) {
            transition = true;  // 重连
        } else if (!connected && last_connected_) {
            // 断开
            {
                std::lock_guard<std::mutex> slock(submit_mutex_);
                // 保留 catalog/generation/digest，仅置状态 (CR-004 §7)
                state_.transition_to(RegistrationState::NOT_REGISTERED);
            }
        }
        last_connected_ = connected;
    }

    if (transition) {
        // 重连后立即以相同 generation 重新提交 (CR-004 §7, §11.3)
        std::lock_guard<std::mutex> lock(submit_mutex_);
        LogAdapter::subscription().info(
            "tsp.subscription.snapshot.restored",
            "MQTT 重连，重新提交完整快照", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(current_snapshot_.generation))}
            });
        state_.transition_to(RegistrationState::REGISTERING);
        SnapshotStatus s = submit_snapshot_locked(current_snapshot_);
        if (s != SnapshotStatus::ACCEPTED) {
            schedule_retry_locked();
        }
        return;
    }

    // 连接可用且需要注册时，按退避重试
    if (connected) {
        std::lock_guard<std::mutex> lock(submit_mutex_);
        RegistrationState st = state_.state();
        if (st != RegistrationState::REGISTERED && now_ms() >= next_retry_ms_) {
            state_.transition_to(RegistrationState::REGISTERING);
            SnapshotStatus s = submit_snapshot_locked(current_snapshot_);
            if (s != SnapshotStatus::ACCEPTED) {
                schedule_retry_locked();
            }
        }
    }
}

SnapshotStatus MqttSubscriptionRegistrar::submit_snapshot_locked(
        const SubscriptionSnapshot& snap) {
    // digest 冲突：相同 generation 但 digest 不同属于协议错误，必须拒绝 (CR-004 §5, §11.2)
    // 幂等（相同 owner+generation+digest 返回已有结果）由 MQTT adapter 侧缓存保证；
    // 重连后 TSP 必须重新提交完整快照，不得跳过 (CR-004 §7)。
    if (accepted_generation_ == snap.generation &&
        accepted_generation_ > 0 &&
        accepted_digest_ != snap.content_digest) {
        last_result_.status = SnapshotStatus::REJECTED;
        last_result_.reason_code = "digest_conflict";
        state_.set_result(SnapshotStatus::REJECTED, "digest_conflict");
        state_.transition_to(RegistrationState::DEGRADED);
        LogAdapter::subscription().error(
            "tsp.subscription.snapshot.rejected",
            "订阅快照被拒：generation 冲突 digest 不一致", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snap.generation))},
                {"reason_code",
                 tbox::fw::log::FieldValue::makeString("digest_conflict")}
            });
        return SnapshotStatus::REJECTED;
    }

    auto t0 = now_ms();
    ReplaceSnapshotResult result = mqtt_->replaceSubscriptionSnapshot(snap);
    auto duration_ms = now_ms() - t0;
    last_result_ = result;

    if (result.status == SnapshotStatus::ACCEPTED) {
        accepted_generation_ = snap.generation;
        accepted_digest_ = snap.content_digest;
        retry_count_ = 0;
        next_retry_ms_ = 0;
        state_.set_result(SnapshotStatus::ACCEPTED, "");
        state_.reset_retry();
        state_.transition_to(RegistrationState::REGISTERED);
        LogAdapter::subscription().info(
            "tsp.subscription.snapshot.accepted",
            "订阅快照已被 MQTT 接受（≠ Broker SUBACK）", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snap.generation))},
                {"duration_ms",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(duration_ms))}
            });
    } else if (result.status == SnapshotStatus::UNKNOWN) {
        // 响应丢失：使用相同 generation 查询/重试，不得递增 (CR-004 §5, §11.3)
        state_.set_result(SnapshotStatus::UNKNOWN, result.reason_code);
        state_.increment_retry();
        LogAdapter::subscription().warn(
            "tsp.subscription.snapshot.unknown",
            "订阅快照结果未知，将使用相同 generation 重试", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snap.generation))},
                {"retry_count",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(state_.snapshot().retry_count))}
            });
    } else {  // REJECTED
        state_.set_result(SnapshotStatus::REJECTED, result.reason_code);
        state_.transition_to(RegistrationState::DEGRADED);
        state_.increment_retry();
        LogAdapter::subscription().error(
            "tsp.subscription.snapshot.rejected",
            "订阅快照被拒", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snap.generation))},
                {"reason_code",
                 tbox::fw::log::FieldValue::makeString(result.reason_code)},
                {"rejected_count",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result.rejected_route_ids.size()))}
            });
    }
    return result.status;
}

bool MqttSubscriptionRegistrar::apply_catalog_change(
        const std::vector<SubscriptionItem>& new_items) {
    // 影子校验 (CR-004 §8, §11.4)
    std::string error;
    if (!catalog_->validate(new_items, error)) {
        LogAdapter::subscription().error(
            "tsp.subscription.catalog.invalid",
            "业务变更校验失败", {
                {"reason_code",
                 tbox::fw::log::FieldValue::makeString("validation_failed")}
            });
        return false;
    }

    std::lock_guard<std::mutex> lock(submit_mutex_);
    // ACCEPTED 前保留上一已确认 generation：先在影子计算新 generation (CR-004 §8)
    uint64_t persisted_gen = 0;
    std::string persisted_digest;
    store_->load(persisted_gen, persisted_digest);
    SubscriptionSnapshot candidate = builder_.build(
        new_items, kOwner, persisted_gen, persisted_digest);

    // 摘要未变化 -> 无需提交
    if (candidate.content_digest == current_snapshot_.content_digest) {
        return true;
    }

    LogAdapter::subscription().info(
        "tsp.subscription.snapshot.submitting",
        "业务变更，提交新完整快照", {
            {"generation",
             tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(candidate.generation))},
            {"item_count",
             tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(candidate.items.size()))}
        });

    state_.transition_to(RegistrationState::REGISTERING);
    SnapshotStatus s = submit_snapshot_locked(candidate);

    if (s == SnapshotStatus::ACCEPTED) {
        // ACCEPTED 后切换本地 current generation 与目录 (CR-004 §8)
        catalog_->replace(new_items);
        current_snapshot_ = candidate;
        store_->save(candidate.generation, candidate.content_digest);
        state_.set_generation(candidate.generation,
                              candidate.content_digest,
                              catalog_->mandatory_count(),
                              static_cast<uint32_t>(candidate.items.size()));
    } else if (s == SnapshotStatus::UNKNOWN) {
        // 迁移期 UNKNOWN 仅在 MQTT 未连接时出现；乐观提交意图，待重连重试
        catalog_->replace(new_items);
        current_snapshot_ = candidate;
        store_->save(candidate.generation, candidate.content_digest);
        state_.set_generation(candidate.generation,
                              candidate.content_digest,
                              catalog_->mandatory_count(),
                              static_cast<uint32_t>(candidate.items.size()));
        schedule_retry_locked();
    } else {
        // REJECTED：保留旧集合与上一已确认 generation，进入 DEGRADED (CR-004 §8)
        schedule_retry_locked();
    }
    return true;
}

void MqttSubscriptionRegistrar::schedule_retry_locked() {
    ++retry_count_;
    next_retry_ms_ = now_ms() + current_backoff_ms();
    state_.increment_retry();
}

uint32_t MqttSubscriptionRegistrar::current_backoff_ms() const {
    uint32_t base = kBackoffInitialMs;
    for (uint32_t i = 1; i < retry_count_ && base < kBackoffMaxMs; ++i) {
        base = static_cast<uint32_t>(base * kBackoffMultiplier);
        if (base > kBackoffMaxMs) base = kBackoffMaxMs;
    }
    return std::min(base + jitter(base), kBackoffMaxMs);
}

RegistrationStatus MqttSubscriptionRegistrar::status() const {
    return state_.snapshot();
}

bool MqttSubscriptionRegistrar::is_registration_ready() const {
    std::lock_guard<std::mutex> lock(submit_mutex_);
    // Mandatory 快照至少在业务 relay ready 前完成本地提交 (CR-004 §6, REQ §4.2)
    // submitted_once_ 表示已尝试本地提交；MQTT 不可用时进入 DEGRADED 不阻塞启动。
    return submitted_once_;
}

} // namespace tsp
} // namespace tbox
