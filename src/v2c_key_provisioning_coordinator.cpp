// TBOX-TSP-DSN-CR-010 §3.1/§5/§7 / CR-013 §20: V2cKeyProvisioningCoordinator 实现。
#include "v2c_key_provisioning_coordinator.h"

#include "hash.h"
#include "keyprov_attempt.h"
#include "log_adapter.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <unistd.h>

namespace tbox {
namespace tsp {

using tbox::sec::BusinessKeyImportState;
using tbox::sec::BusinessKeyState;
using tbox::sec::ErrorCode;

namespace {

constexpr const char* kCapabilityKeyprov = "security.keyprov";

// systemd-timesyncd 启动即创建目录，首次同步成功后才创建 synchronized 标记；
// systemd-time-wait-sync 也以此标记为判据。
constexpr const char* kTimesyncDir = "/run/systemd/timesync";
constexpr const char* kTimesyncMarker = "/run/systemd/timesync/synchronized";

constexpr int kKeyProvStatusFailed = 5;   // KEY_PROVISIONING_STATUS_FAILED
constexpr int kKeyProvStatusUnspecified = 0;  // KEY_PROVISIONING_STATUS_UNSPECIFIED
constexpr int kKeyProvStatusRequested = 1;
constexpr int kKeyProvStatusIssued = 2;
constexpr int kKeyProvStatusAckPending = 3;

// 默认时钟同步判定：仅在 systemd-timesyncd 存在的平台上启用门禁
// （无该目录的开发机/CI 不阻塞 keyprov）。
bool default_clock_synchronized() {
    if (::access(kTimesyncDir, F_OK) != 0) {
        return true;
    }
    return ::access(kTimesyncMarker, F_OK) == 0;
}

// 64 小写 hex -> 32B fingerprint（失败返回 false）。
bool hex_to_fingerprint(const std::string& hex, KeyprovFingerprint& out) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (hex.size() != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        int hi = nib(hex[2 * i]);
        int lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// 从 SEC ImportResult 构造 ACK items（CR-012 §6 机械映射）。
// - key_id/version/format/digest/KCV/proof/certDigest 均取 SEC journal 返回值；
// - TSP 不构造 proofInput、不签名/验签、不修改 proof bytes；
// - 遗留 string proof_algorithm 留空，算法只由 import_proof_algorithm 承载。
std::vector<KeyProvImportItemResult> build_ack_items(
    const tbox::sec::ImportResult& result) {
    std::vector<KeyProvImportItemResult> out;
    out.reserve(result.items.size());
    for (const auto& it : result.items) {
        KeyProvImportItemResult a;
        a.purpose = keyprov_purpose_from_string(it.purpose);
        a.key_id = it.key_id;
        a.business_key_version = it.business_key_version;
        a.result = kKeyProvImportImported;
        a.envelope_format = static_cast<int>(it.envelope_format);
        a.envelope_digest = it.envelope_digest;
        if (it.key_check_value_present) {
            a.key_check_value.assign(it.key_check_value.begin(),
                                     it.key_check_value.end());
        }
        a.import_proof_algorithm =
            it.proof_algorithm == tbox::sec::kImportProofAlgorithmP1363
                ? kKeyProvImportProofAlgorithmEcdsaP256P1363
                : kKeyProvImportProofAlgorithmUnspecified;
        a.import_proof = it.import_proof;
        a.recipient_certificate_digest = it.recipient_certificate_digest;
        a.proof_algorithm.clear();
        out.push_back(std::move(a));
    }
    return out;
}

} // namespace

// ============================================================
// 状态名
// ============================================================
const char* v2c_key_prov_state_to_string(V2cKeyProvState s) {
    switch (s) {
        case V2cKeyProvState::DISABLED:      return "DISABLED";
        case V2cKeyProvState::WAIT_CLOUD:    return "WAIT_CLOUD";
        case V2cKeyProvState::CHECKING:      return "CHECKING";
        case V2cKeyProvState::REQUESTING:    return "REQUESTING";
        case V2cKeyProvState::WAIT_RESPONSE: return "WAIT_RESPONSE";
        case V2cKeyProvState::IMPORTING:     return "IMPORTING";
        case V2cKeyProvState::ACK_PENDING:   return "ACK_PENDING";
        case V2cKeyProvState::ACTIVE:        return "ACTIVE";
        case V2cKeyProvState::RETRY_WAIT:    return "RETRY_WAIT";
        case V2cKeyProvState::BLOCKED:       return "BLOCKED";
        case V2cKeyProvState::RECONCILE_OLD_ATTEMPT: return "RECONCILE_OLD_ATTEMPT";
        case V2cKeyProvState::SUPERSEDED_LOCAL:      return "SUPERSEDED_LOCAL";
        case V2cKeyProvState::SUPERSEDED_REMOTE:     return "SUPERSEDED_REMOTE";
        case V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION:
            return "BLOCKED_AWAIT_CLOUD_TERMINATION";
        case V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN:
            return "LEGACY_SNAPSHOT_UNKNOWN";
        default: return "?";
    }
}

bool v2c_key_prov_state_from_string(const std::string& s, V2cKeyProvState& out) {
    static const V2cKeyProvState all[] = {
        V2cKeyProvState::DISABLED, V2cKeyProvState::WAIT_CLOUD,
        V2cKeyProvState::CHECKING, V2cKeyProvState::REQUESTING,
        V2cKeyProvState::WAIT_RESPONSE, V2cKeyProvState::IMPORTING,
        V2cKeyProvState::ACK_PENDING, V2cKeyProvState::ACTIVE,
        V2cKeyProvState::RETRY_WAIT, V2cKeyProvState::BLOCKED,
        V2cKeyProvState::RECONCILE_OLD_ATTEMPT, V2cKeyProvState::SUPERSEDED_LOCAL,
        V2cKeyProvState::SUPERSEDED_REMOTE,
        V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION,
        V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN};
    for (auto s2 : all) {
        if (s == v2c_key_prov_state_to_string(s2)) {
            out = s2;
            return true;
        }
    }
    return false;
}

// ============================================================
// 构造 / 初始化
// ============================================================
V2cKeyProvisioningCoordinator::V2cKeyProvisioningCoordinator(
    std::shared_ptr<MqttFacade> mqtt,
    std::shared_ptr<SecBusinessKeyFacade> sec,
    std::shared_ptr<V2cKeyProvisioningStore> store)
    : mqtt_(std::move(mqtt)), sec_(std::move(sec)), store_(std::move(store)) {
}

V2cKeyProvisioningCoordinator::~V2cKeyProvisioningCoordinator() {
    stop();
}

bool V2cKeyProvisioningCoordinator::initialize(
    const V2cKeyProvisioningConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mqtt_ || !sec_ || !store_) {
        LogAdapter::keyprov().error(
            "tsp.keyprov.init_failed", "keyprov 依赖未注入");
        return false;
    }
    config_ = config;
    counters_.sec_api_available = true;

    record_ = store_->load();
    if (config_.enabled) {
        // CR-013：恢复 attempt 冻结状态（snapshot/fingerprint/submission/supersede/generation）。
        if (record_.valid) {
            frozen_snapshot_ = record_.snapshot;
            fingerprint_version_ = record_.fingerprint_version;
            if (!record_.attempt_fingerprint.empty()) {
                hex_to_fingerprint(record_.attempt_fingerprint,
                                   frozen_fingerprint_);
            }
            submission_ = record_.submission.empty()
                              ? keyprov_submission::kNone
                              : record_.submission;
            supersedes_request_id_ = record_.supersedes_request_id;
            superseded_by_request_id_ = record_.superseded_by_request_id;
            blocked_reason_ = record_.blocked_reason;
            store_generation_ = record_.store_generation;
            // CR-014：恢复 SEC import result 证据（Store 缺字段已在 load() 保守默认）。
            sec_import_result_contract_version_ =
                record_.sec_import_result_contract_version;
            last_sec_evidence_kind_ =
                static_cast<SecImportEvidenceKind>(record_.sec_import_evidence_kind);
            import_invocation_recorded_ = record_.import_invocation;
            // 重启后无法确认回调是否已收敛：保守按"可能待定"处理，
            // 首次 SEC 权威查询后会按结果修正。
            pending_callback_ = record_.import_invocation;
        }
        if (record_.legacy_snapshot_unknown) {
            // CR-013 §10：旧 Store 缺 snapshot/fingerprint，默认阻断发送；
            // 进入 LEGACY_SNAPSHOT_UNKNOWN，先查 SEC journal + VMD Status。
            legacy_snapshot_unknown_ = true;
            counters_.legacy_store_records++;
            blocked_reason_ = keyprov_blocked_reason::kLegacySnapshotUnknown;
            count_blocked_reason_locked(keyprov_blocked_reason::kLegacySnapshotUnknown);
            state_ = V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN;
        } else {
            V2cKeyProvState restored = V2cKeyProvState::WAIT_CLOUD;
            if (record_.valid && !record_.state.empty()) {
                v2c_key_prov_state_from_string(record_.state, restored);
            }
            // 恢复时不以 Store 覆盖 SEC/HSM 事实：先回 CHECKING，由 SEC 状态裁决。
            if (restored == V2cKeyProvState::ACTIVE) {
                state_ = V2cKeyProvState::WAIT_CLOUD;
            } else if (restored == V2cKeyProvState::ACK_PENDING) {
                state_ = V2cKeyProvState::WAIT_CLOUD;
                recovering_ack_ = true;  // SEC 已导入、云端未确认：恢复 ACK
            } else {
                state_ = V2cKeyProvState::WAIT_CLOUD;
            }
        }
    } else {
        state_ = V2cKeyProvState::DISABLED;
    }
    LogAdapter::keyprov().info(
        "tsp.keyprov.initialized", "V2cKeyProvisioningCoordinator 初始化", {
            {"enabled", tbox::fw::log::FieldValue::makeBool(config_.enabled)},
            {"state", tbox::fw::log::FieldValue::makeString(
                v2c_key_prov_state_to_string(state_))},
            {"fingerprint_version", tbox::fw::log::FieldValue::makeInt(
                static_cast<int64_t>(fingerprint_version_))},
            {"legacy", tbox::fw::log::FieldValue::makeBool(
                legacy_snapshot_unknown_)}
        });
    return true;
}

bool V2cKeyProvisioningCoordinator::start(bool start_monitor) {
    start_monitor_ = start_monitor;
    running_.store(true, std::memory_order_release);
    stopping_.store(false, std::memory_order_release);

    // 订阅 readiness 事件（失败不阻塞启动；gate 保持 false）
    if (!mqtt_->subscribeCloudReadinessChanged(
            [this](const CloudReadiness& r) { on_cloud_readiness(r); })) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.cloud_ready_subscribe_failed",
            "Cloud Readiness 订阅失败，keyprov 保持 NOT_READY");
    }
    if (!mqtt_->subscribeCapabilityReadinessChanged(
            kCapabilityKeyprov,
            [this](const CapabilityReadiness& r) { on_capability_readiness(r); })) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.capability_subscribe_failed",
            "Capability Readiness 订阅失败，keyprov 保持 NOT_READY");
    }

    if (start_monitor_) {
        worker_ = std::thread([this] { worker_loop(); });
    }
    // CR-011 §5.1: 订阅后主动拉取一次完整快照，避免仅依赖首个事件。
    {
        std::lock_guard<std::mutex> lock(mutex_);
        apply_cloud_readiness_locked(mqtt_->getCloudReadiness());
        apply_capability_readiness_locked(
            mqtt_->getCapabilityReadiness(kCapabilityKeyprov));
    }
    LogAdapter::keyprov().info(
        "tsp.keyprov.started", "V2cKeyProvisioningCoordinator 启动", {
            {"monitor", tbox::fw::log::FieldValue::makeBool(start_monitor_)}
        });
    return true;
}

void V2cKeyProvisioningCoordinator::beginShutdown() {
    stopping_.store(true, std::memory_order_release);
    cv_.notify_all();
    LogAdapter::keyprov().info(
        "tsp.keyprov.stopping", "keyprov 进入 STOPPING，拒绝新申请");
}

void V2cKeyProvisioningCoordinator::stop() {
    stopping_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    // 清零内存态 Wrapped Key 缓冲
    pending_items_.clear();
    ack_items_.clear();
}

void V2cKeyProvisioningCoordinator::worker_loop() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (running_.load(std::memory_order_acquire) &&
           !stopping_.load(std::memory_order_acquire)) {
        cv_.wait_for(lock, std::chrono::milliseconds(config_.poll_interval_ms),
                     [this] { return stopping_.load(std::memory_order_acquire); });
        if (stopping_.load(std::memory_order_acquire)) break;
        tick_locked();
    }
}

// ============================================================
// readiness 回调
// ============================================================
void V2cKeyProvisioningCoordinator::on_cloud_readiness(
    const CloudReadiness& readiness) {
    std::lock_guard<std::mutex> lock(mutex_);
    apply_cloud_readiness_locked(readiness);
    cv_.notify_all();
}

void V2cKeyProvisioningCoordinator::on_capability_readiness(
    const CapabilityReadiness& readiness) {
    std::lock_guard<std::mutex> lock(mutex_);
    apply_capability_readiness_locked(readiness);
    cv_.notify_all();
}

// CR-011 §5.1: ready 撤销 / epoch / connection / cert 变化 / IPC 重连 /
// 序列缺口先失效身份缓存与未发送任务（保留业务 requestId）。
void V2cKeyProvisioningCoordinator::invalidate_identity_locked(
    const char* reason) {
    if (identity_valid_) {
        LogAdapter::keyprov().info(
            "tsp.keyprov.identity_invalidated",
            "keyprov 会话身份失效", {
                {"reason", tbox::fw::log::FieldValue::makeString(reason)}
            });
    }
    identity_valid_ = false;
    identity_ = KeyprovSessionIdentity{};
    // 旧传输态不得跨上下文重发；Cloud deadline 必须暂停。
    pending_items_.clear();
    response_binding_.clear();
    last_response_message_id_.clear();
    deadline_ms_ = 0;
    // 业务 requestId 保留：网络代际不是业务幂等键（CR-011 §6 / CR-013 §20.3）。
}

void V2cKeyProvisioningCoordinator::apply_cloud_readiness_locked(
    const CloudReadiness& readiness) {
    const bool epoch_changed =
        readiness.session.daemon_epoch != cloud_.session.daemon_epoch;
    if (epoch_changed) {
        // epoch 变化时不跨生命周期比较 sequence。
        last_cloud_sequence_ = 0;
    }

    // 同 epoch 内乱序/重复事件：不覆盖新状态（迟到事件不得回退身份）。
    if (!epoch_changed && readiness.event_sequence != 0 &&
        last_cloud_sequence_ != 0 &&
        readiness.event_sequence <= last_cloud_sequence_) {
        return;
    }
    const bool sequence_gap =
        !epoch_changed && last_cloud_sequence_ != 0 &&
        readiness.event_sequence > last_cloud_sequence_ + 1;
    if (readiness.event_sequence != 0) {
        last_cloud_sequence_ = readiness.event_sequence;
    }

    const bool connection_changed =
        readiness.session.connection_generation !=
        cloud_.session.connection_generation;
    const bool cert_changed =
        readiness.session.cert_session_generation !=
        cloud_.session.cert_session_generation;

    cloud_ = readiness;
    if (readiness.cloud_ready) {
        counters_.cloud_ready_events++;
    }
    capability_event_seen_ = true;

    if (epoch_changed || connection_changed || cert_changed ||
        sequence_gap || !readiness.cloud_ready) {
        invalidate_identity_locked(epoch_changed ? "daemon_epoch_changed"
                                  : connection_changed ? "connection_changed"
                                  : cert_changed ? "cert_session_changed"
                                  : sequence_gap ? "event_sequence_gap"
                                                 : "cloud_not_ready");
    }
}

void V2cKeyProvisioningCoordinator::apply_capability_readiness_locked(
    const CapabilityReadiness& readiness) {
    if (readiness.capability != kCapabilityKeyprov) return;
    capability_ = readiness;
    capability_event_seen_ = true;
    if (!readiness.ready) {
        // capability 撤销：暂停网络操作并失效未发送任务（保留 requestId）。
        invalidate_identity_locked("capability_not_ready");
    }
}

void V2cKeyProvisioningCoordinator::refresh_readiness_locked() {
    apply_cloud_readiness_locked(mqtt_->getCloudReadiness());
    apply_capability_readiness_locked(
        mqtt_->getCapabilityReadiness(kCapabilityKeyprov));
}

// ============================================================
// 公共 tick / 下行
// ============================================================
void V2cKeyProvisioningCoordinator::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    tick_locked();
}

V2cKeyProvisioningSnapshot V2cKeyProvisioningCoordinator::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    V2cKeyProvisioningSnapshot s = counters_;
    s.state = state_;
    s.request_id = record_.request_id;
    s.capability_ready = capability_ready_;
    s.identity_valid = identity_valid_;
    s.publish_session_supported = publish_session_supported_;
    s.reason_code = gate_reason_;
    s.attempt_count = record_.attempt_count;
    s.last_error = record_.last_error;
    s.cloud_session_generation = record_.cloud_session_generation;
    s.clock_synced = clock_synced_;
    s.readiness = readiness_;
    // CR-013 可观测字段
    s.blocked_reason = blocked_reason_;
    s.fingerprint_version = fingerprint_version_;
    s.legacy_snapshot_unknown = legacy_snapshot_unknown_;
    s.conflict_vmd_code = conflict_vmd_code_;
    // CR-014 可观测字段（有限枚举，脱敏）
    s.sec_evidence_kind = sec_import_evidence_kind_to_string(last_sec_evidence_kind_);
    s.import_invocation_recorded = import_invocation_recorded_;
    s.blocked_attempts_current =
        (state_ == V2cKeyProvState::BLOCKED ||
         state_ == V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION ||
         state_ == V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN)
            ? 1u : 0u;
    return s;
}

void V2cKeyProvisioningCoordinator::set_clock_sync_check(
    std::function<bool()> check) {
    std::lock_guard<std::mutex> lock(mutex_);
    clock_sync_check_ = std::move(check);
}

bool V2cKeyProvisioningCoordinator::clock_check_ok() const {
    return clock_sync_check_ ? clock_sync_check_() : default_clock_synchronized();
}

void V2cKeyProvisioningCoordinator::handle_routed_downlink(
    const RoutedDownlinkEvent& event) {
    if (event.owner != "tsp" ||
        event.route_id != config_.route_down ||
        event.target != "tsp.keyprov") {
        return;  // 不属于 keyprov 路由
    }

    auto decoded = decode_keyprov_envelope(event.payload);
    std::lock_guard<std::mutex> lock(mutex_);
    if (decoded.status != KeyProvCodecStatus::Ok) {
        counters_.responses_rejected++;
        LogAdapter::keyprov().warn(
            "tsp.keyprov.downlink_invalid", "keyprov 下行校验失败", {
                {"reason", tbox::fw::log::FieldValue::makeString(
                    keyprov_codec_status_to_string(decoded.status))}
            });
        return;
    }
    if (decoded.decoded.request_id != record_.request_id ||
        record_.request_id.empty()) {
        counters_.responses_rejected++;
        LogAdapter::keyprov().warn(
            "tsp.keyprov.response_mismatch",
            "keyprov 下行 requestId 不匹配（迟到/重复/错配），忽略");
        return;
    }

    // CR-013 §11：迟到异步结果隔离（requestId + store_generation + fingerprint
    // 任一不匹配即丢弃/审计，不得推进当前 attempt）。
    if (awaiting_active_ &&
        (record_.store_generation != awaiting_generation_ ||
         !keyprov_fingerprint_equal(frozen_fingerprint_, awaiting_fingerprint_))) {
        counters_.responses_rejected++;
        LogAdapter::keyprov().warn(
            "tsp.keyprov.late_result_isolated",
            "keyprov 迟到异步结果被隔离（generation/fingerprint 不匹配）");
        return;
    }

    counters_.responses_received++;

    switch (decoded.decoded.kind) {
        case KeyProvMessageKind::Response: {
            if (state_ != V2cKeyProvState::WAIT_RESPONSE) {
                counters_.responses_rejected++;  // 重复/迟到响应
                return;
            }
            auto& resp = decoded.decoded.response;
            const int succeeded = kKeyProvResultSucceeded;
            if (resp.result != succeeded) {
                counters_.responses_rejected++;
                record_.last_error = "response_not_succeeded";
                // CR-013：806095 等幂等冲突 -> 停止自动重试，进入对账。
                if (keyprov_is_idempotency_conflict(resp.error)) {
                    counters_.idempotency_conflicts_total++;
                    record_conflict_facts_locked(resp.error.code.c_str());
                    enter_reconcile_old_attempt_locked(
                        "idempotency_conflict", resp.error.code.c_str());
                    return;
                }
                if (resp.error.retryable) {
                    state_ = V2cKeyProvState::RETRY_WAIT;
                    schedule_retry_locked();
                } else {
                    state_ = V2cKeyProvState::BLOCKED;
                }
                persist_locked();
                return;
            }
            // SUCCEEDED 必须恰为完整 purpose 集、版本非 0、算法/有效期合法
            std::string err;
            if (!keyprov_response_valid_locked(resp, err)) {
                counters_.responses_rejected++;
                record_.last_error = err;
                state_ = V2cKeyProvState::RETRY_WAIT;
                schedule_retry_locked();
                persist_locked();
                return;
            }
            // 保存原 Response 的非敏感 ACK 绑定材料（用于 SEC 结果逐项绑定校验）。
            response_binding_.clear();
            response_binding_.reserve(resp.items.size());
            for (const auto& it : resp.items) {
                AckBinding b;
                b.purpose = it.purpose;
                b.key_id = it.key_id;
                b.business_key_version = it.business_key_version;
                b.envelope_format = static_cast<int>(it.envelope_format);
                b.envelope_digest = it.envelope_digest;
                b.key_check_value = it.key_check_value;
                b.key_check_value_present = it.key_check_value_present;
                response_binding_.push_back(std::move(b));
            }
            pending_items_ = std::move(resp.items);  // move-only SecureBuffer
            last_response_message_id_ = decoded.decoded.message_id;
            import_attempted_ = false;
            state_ = V2cKeyProvState::IMPORTING;
            persist_locked();
            cv_.notify_all();
            return;
        }
        case KeyProvMessageKind::AckResult: {
            counters_.ack_results_received++;
            // CR-013：AckResult 幂等冲突 -> 停止重试，进入对账。
            if (keyprov_is_idempotency_conflict(decoded.decoded.ack_result.error)) {
                counters_.idempotency_conflicts_total++;
                record_conflict_facts_locked(
                    decoded.decoded.ack_result.error.code.c_str());
                enter_reconcile_old_attempt_locked(
                    "ack_result_idempotency_conflict",
                    decoded.decoded.ack_result.error.code.c_str());
                return;
            }
            bool ok = false;
            if (state_ == V2cKeyProvState::ACK_PENDING) {
                ok = decoded.decoded.ack_result.result == kKeyProvResultSucceeded;
                if (ok) {
                    state_ = V2cKeyProvState::ACTIVE;
                    import_attempted_ = false;
                    recovering_ack_ = false;
                    record_.last_error.clear();
                    counters_.active_transitions++;
                    mark_confirmed_locked();
                } else {
                    record_.last_error = "ack_result_rejected";
                    state_ = V2cKeyProvState::RETRY_WAIT;
                    schedule_retry_locked();
                }
                persist_locked();
            }
            return;
        }
        case KeyProvMessageKind::StatusResponse: {
            const auto& st = decoded.decoded.status_response;
            // CR-013：对账态（RECONCILE / LEGACY / 待云端终结）统一走终态对账。
            if (state_ == V2cKeyProvState::RECONCILE_OLD_ATTEMPT ||
                state_ == V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN ||
                state_ == V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION) {
                reconcile_status_sent_ = false;
                handle_reconcile_status_locked(st);
                return;
            }
            if (state_ != V2cKeyProvState::ACK_PENDING &&
                state_ != V2cKeyProvState::WAIT_RESPONSE &&
                state_ != V2cKeyProvState::CHECKING) {
                return;
            }
            // CR-013：主动 Status 对账期间收到幂等冲突同样进入对账。
            if (keyprov_is_idempotency_conflict(st.error)) {
                counters_.idempotency_conflicts_total++;
                record_conflict_facts_locked(st.error.code.c_str());
                enter_reconcile_old_attempt_locked(
                    "status_idempotency_conflict", st.error.code.c_str());
                return;
            }
            const int active = kKeyProvStatusActive;
            if (st.status == active) {
                if (!ack_items_.empty() || import_attempted_) {
                    state_ = V2cKeyProvState::ACK_PENDING;
                    ack_sent_ = false;
                } else {
                    state_ = V2cKeyProvState::ACTIVE;
                    counters_.active_transitions++;
                    mark_confirmed_locked();
                }
                persist_locked();
                cv_.notify_all();
            } else {
                state_ = V2cKeyProvState::RETRY_WAIT;
                schedule_retry_locked();
                persist_locked();
            }
            return;
        }
        default:
            counters_.responses_rejected++;
            return;
    }
}

// ============================================================
// CR-013：不可变 attempt / fingerprint / 对账
// ============================================================
bool V2cKeyProvisioningCoordinator::build_candidate_locked(
    KeyprovAttemptSnapshot& cand, KeyprovFingerprint& fp, std::string& err) {
    // 同一执行域内读取 SEC 版本 + 当前身份 + 协议锁版（CR-013 §5.1）。
    std::vector<std::string> purposes = config_.purposes;
    tbox::sec::BusinessKeyStatusSet set;
    ErrorCode ec = sec_->get_business_key_status(
        config_.business_domain, purposes, set);
    if (ec != ErrorCode::SUCCESS) {
        err = "sec_status_unavailable";
        return false;
    }
    if (!identity_valid_ ||
        !keyprov_validate_identity(identity_, err)) {
        if (err.empty()) err = "identity_unavailable";
        return false;
    }
    KeyprovFingerprint lock = keyprov_protocol_lock_digest_v1();
    if (!keyprov_build_attempt_snapshot(
            config_.business_domain, purposes, identity_, set.items, lock,
            cand, err)) {
        return false;
    }
    if (!keyprov_compute_attempt_fingerprint_v1(cand, fp, err)) {
        return false;
    }
    return true;
}

void V2cKeyProvisioningCoordinator::freeze_current_input_locked() {
    KeyprovAttemptSnapshot cand;
    KeyprovFingerprint fp;
    std::string err;
    if (!build_candidate_locked(cand, fp, err)) {
        // 构造失败：不产生可发送 attempt（由调用方转 RETRY_WAIT 处理）。
        return;
    }
    frozen_snapshot_ = std::move(cand);
    frozen_fingerprint_ = fp;
    fingerprint_version_ = kAttemptFingerprintVersionV1;
}

void V2cKeyProvisioningCoordinator::create_new_attempt_locked() {
    if (sec_outcome_unknown_) {
        // CR-013 §9：SEC outcome 仍未知时禁止新 attempt，保持原 requestId 对账。
        // 兜底保护：任何调用方不得绕过对账直接建新 attempt。
        blocked_reason_ = keyprov_blocked_reason::kSecOutcomeUnknown;
        count_blocked_reason_locked(keyprov_blocked_reason::kSecOutcomeUnknown);
        state_ = V2cKeyProvState::RECONCILE_OLD_ATTEMPT;
        schedule_retry_locked();
        persist_locked();
        return;
    }
    KeyprovAttemptSnapshot cand;
    KeyprovFingerprint fp;
    std::string err;
    if (!build_candidate_locked(cand, fp, err)) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = err.empty() ? "attempt_snapshot_failed" : err;
        schedule_retry_locked();
        persist_locked();
        return;
    }

    // 旧 attempt 终态化（append-only audit，有界），保留 supersede 关联。
    if (!record_.request_id.empty()) {
        if (supersedes_request_id_.empty()) {
            supersedes_request_id_ = record_.request_id;
        }
        if (record_.terminalized_request_ids.empty() ||
            record_.terminalized_request_ids.back() != record_.request_id) {
            record_.terminalized_request_ids.push_back(record_.request_id);
        }
        if (record_.terminalized_request_ids.size() > 16) {
            record_.terminalized_request_ids.erase(
                record_.terminalized_request_ids.begin(),
                record_.terminalized_request_ids.end() - 16);
        }
    }

    // 新 requestId + idempotency（wire 兼容）。
    record_.request_id = generate_id("kp");
    record_.idempotency_digest =
        tbox::fw::hash::sha256_hex(std::string_view(
            record_.request_id + "|" + config_.business_domain));
    record_.purposes = config_.purposes;

    // 冻结当前输入。
    frozen_snapshot_ = std::move(cand);
    frozen_fingerprint_ = fp;
    fingerprint_version_ = kAttemptFingerprintVersionV1;
    record_.snapshot = frozen_snapshot_;
    record_.attempt_fingerprint = keyprov_fingerprint_to_hex(frozen_fingerprint_);
    record_.fingerprint_version = fingerprint_version_;

    // 重置本 attempt 状态。
    import_attempted_ = false;
    ack_sent_ = false;
    status_sent_ = false;
    recovering_ack_ = false;
    pending_items_.clear();
    response_binding_.clear();
    ack_items_.clear();
    record_.attempt_count = 0;
    record_.last_error.clear();
    blocked_reason_.clear();
    conflict_vmd_code_.clear();
    submission_ = keyprov_submission::kNone;
    legacy_snapshot_unknown_ = false;
    sec_outcome_unknown_ = false;   // 新 attempt 与旧 SEC 事实解绑，重新对账
    sec_unknown_rounds_ = 0;
    sec_unknown_alerted_ = false;
    // CR-014：新 attempt 重置 SEC 证据（import invocation / no-side-effects / 三元组）。
    sec_no_side_effects_proven_ = false;
    import_invocation_recorded_ = false;
    pending_callback_ = false;
    last_sec_evidence_kind_ = SecImportEvidenceKind::ContractUnknown;
    last_obs_valid_ = false;
    counters_.attempts_created++;
    bump_store_generation_locked();
    awaiting_active_ = false;

    state_ = V2cKeyProvState::REQUESTING;
    persist_locked();
    do_request_locked();
}

void V2cKeyProvisioningCoordinator::enter_reconcile_old_attempt_locked(
    const char* reason, const char* vmd_code) {
    // 停止原 Request 自动重试，保留原 requestId 与提交事实。
    deadline_ms_ = 0;
    reconcile_status_sent_ = false;
    awaiting_active_ = false;
    if (vmd_code && *vmd_code) conflict_vmd_code_ = vmd_code;
    if (reason && *reason) record_.last_error = reason;
    transition_to_locked(V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    persist_locked();
}

void V2cKeyProvisioningCoordinator::record_conflict_facts_locked(
    const char* vmd_code) {
    if (vmd_code && *vmd_code) conflict_vmd_code_ = vmd_code;
    counters_.blocked_attempts_total++;
    count_blocked_reason_locked(keyprov_blocked_reason::kIdempotencyConflict);
    LogAdapter::keyprov().warn(
        "tsp.keyprov.idempotency_conflict",
        "keyprov 幂等冲突，进入对账", {
            {"vmd_code", tbox::fw::log::FieldValue::makeString(conflict_vmd_code_)},
            {"fingerprint_version", tbox::fw::log::FieldValue::makeInt(
                static_cast<int64_t>(fingerprint_version_))}
        });
}

bool V2cKeyProvisioningCoordinator::submission_evidence_locked() const {
    return submission_ != keyprov_submission::kNone ||
           record_.attempt_count > 0 ||
           import_attempted_ || ack_sent_ || status_sent_;
}

bool V2cKeyProvisioningCoordinator::reconcile_sec_journal_locked() {
    const std::string rid = record_.request_id;
    if (rid.empty()) return false;
    tbox::sec::ImportResult res;
    ErrorCode ec = sec_->get_business_key_import_result(rid, res);
    // CR-014 §3/§21.1：强类型分类（adapter exhaustive switch；除 NotFound 外
    // 所有新增、未知和失败路径均保持 fail-closed）。
    SecImportEvidence ev =
        sec_classify_import_result(ec, res, sec_import_result_contract_version_);
    auto rid_digest = tbox::fw::hash::sha256(std::string_view(rid));
    ev.request_id_digest.assign(rid_digest.begin(), rid_digest.end());
    ev.observed_store_generation = store_generation_;
    ev.import_invocation_recorded = import_invocation_recorded_;
    ev.pending_callback = pending_callback_;
    last_sec_evidence_kind_ = ev.kind;

    switch (ev.kind) {
        case SecImportEvidenceKind::Committed: {
            // 原 requestId 已完成双用途原子导入：恢复原 ACK（CR-012 journal proof
            // 复用，不重复导入、不建新 attempt）。
            ack_items_ = build_ack_items(res);
            if (ack_items_.size() == config_.purposes.size()) {
                sec_outcome_unknown_ = false;   // SEC 已给出明确事实
                sec_no_side_effects_proven_ = false;
                pending_callback_ = false;
                sec_unknown_rounds_ = 0;
                sec_unknown_alerted_ = false;
                blocked_reason_.clear();
                state_ = V2cKeyProvState::ACK_PENDING;
                ack_sent_ = false;
                status_sent_ = false;
                recovering_ack_ = false;
                persist_locked();
                do_ack_locked();
            } else {
                // items 不完整：安全异常 -> 保持阻断/对账，不发伪成功 ACK。
                sec_outcome_unknown_ = true;
                sec_no_side_effects_proven_ = false;
                blocked_reason_ = keyprov_blocked_reason::kSecOutcomeUnknown;
                count_blocked_reason_locked(
                    keyprov_blocked_reason::kSecOutcomeUnknown);
                state_ = V2cKeyProvState::RECONCILE_OLD_ATTEMPT;
                schedule_retry_locked();
                persist_locked();
            }
            return true;
        }
        case SecImportEvidenceKind::NotFound: {
            // 结构化 journal 证明无记录/无副作用（sec_no_side_effects_proven_）。
            sec_no_side_effects_proven_ = true;
            sec_outcome_unknown_ = false;
            sec_unknown_rounds_ = 0;
            sec_unknown_alerted_ = false;
            pending_callback_ = false;  // 无记录：回调不可能待定
            if (import_invocation_recorded_ || ev.pending_callback) {
                // 证据冲突：本地已调用 SEC import（或回调待定），SEC 却证明
                // 无记录。持续阻断直至新权威证据（SEC 重启/能力代际变化、
                // journal 状态变化、pending callback 收敛或人工治理），
                // 不按普通定时器自动重试或释放。
                const bool suppressed =
                    reconcile_obs_suppressed_locked(-3, ev.kind);
                blocked_reason_ = keyprov_blocked_reason::kEvidenceConflict;
                record_.last_error = "evidence_conflict";
                state_ = V2cKeyProvState::BLOCKED;
                schedule_retry_locked();
                if (!suppressed) {
                    count_blocked_reason_locked(
                        keyprov_blocked_reason::kEvidenceConflict);
                    persist_locked();
                }
                return true;  // 已消费：阻断，不发 VMD Status
            }
            // 无本地安全调用证据：交由调用方按 VMD 终态判定（FAILED -> 释放）。
            return false;
        }
        case SecImportEvidenceKind::Failed:
        case SecImportEvidenceKind::OutcomeUnknown:
        case SecImportEvidenceKind::QueryError:
        case SecImportEvidenceKind::ContractUnknown: {
            // fail-closed：所有非 NotFound 路径均保持 sec_outcome_unknown_，
            // 禁止新 attempt；但 VMD StatusRequest 只读对账必须继续
            // （CR-013 §8 / SPEC §20.2：SEC journal 与 VMD Status 双路收敛）。
            sec_outcome_unknown_ = true;
            sec_no_side_effects_proven_ = false;
            if (++sec_unknown_rounds_ >= config_.max_attempts_before_alert &&
                !sec_unknown_alerted_) {
                sec_unknown_alerted_ = true;
                LogAdapter::keyprov().warn(
                    "tsp.keyprov.sec_outcome_unknown_persistent",
                    "SEC 持续无法建立无副作用证明，保持原 requestId 对账", {
                        {"rounds", tbox::fw::log::FieldValue::makeInt(
                            static_cast<int64_t>(sec_unknown_rounds_))}
                    });
            }
            // 诊断区分：REQUESTED/STAGED（事务痕迹已存在）与真正 OUTCOME_UNKNOWN
            // 不混为一类（用户裁决）。
            const bool in_progress =
                ev.raw_import_state ==
                    static_cast<int>(tbox::sec::BusinessKeyImportState::REQUESTED) ||
                ev.raw_import_state ==
                    static_cast<int>(tbox::sec::BusinessKeyImportState::STAGED);
            const char* reason = in_progress
                ? keyprov_blocked_reason::kSecImportInProgress
                : keyprov_blocked_reason::kSecOutcomeUnknown;
            const bool suppressed = reconcile_obs_suppressed_locked(-1, ev.kind);
            blocked_reason_ = reason;
            // 从 LEGACY 对账时保持 LEGACY 可观测态（与 RECONCILE 同语义，仅区分诊断）；
            // 从 BLOCKED(EVIDENCE_CONFLICT) 重查时冲突前提已消失 -> 转常规对账。
            if (state_ != V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN) {
                state_ = V2cKeyProvState::RECONCILE_OLD_ATTEMPT;
            }
            schedule_retry_locked();
            if (!suppressed) {
                count_blocked_reason_locked(reason);
                persist_locked();
            }
            return false;  // 调用方继续 VMD Status 对账
        }
    }
    return false;
}

void V2cKeyProvisioningCoordinator::send_status_request_locked() {
    if (!identity_valid_) {
        // 无有效身份（如 legacy 恢复早期）：等待 gate 恢复后重试。
        schedule_retry_locked();
        persist_locked();
        return;
    }
    std::string message_id = generate_id("msg");
    auto enc = build_keyprov_status_request_envelope(
        identity_, record_.request_id, now_ms(), message_id, "");
    if (enc.status != KeyProvCodecStatus::Ok) {
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (publish_keyprov_locked(message_id, enc.envelope_bytes,
                               record_.request_id)) {
        reconcile_status_sent_ = true;
        counters_.status_requests_sent++;
        deadline_ms_ = now_ms() + config_.ack_timeout_ms;
        awaiting_active_ = true;
        awaiting_request_id_ = record_.request_id;
        awaiting_generation_ = store_generation_;
        awaiting_fingerprint_ = frozen_fingerprint_;
        persist_locked();
    } else {
        // publish 被拒：由 publish_keyprov_locked 已分流（STALE/REQUIRED/UNSUPPORTED/
        // INVALID/BLOCKED）；对账保留，退避后重试。
        persist_locked();
    }
}

void V2cKeyProvisioningCoordinator::do_reconcile_locked() {
    // 1) SEC journal 事实优先（原 requestId / operation 绑定）。
    //    COMMITTED 恢复 ACK / 安全异常 -> 已消费直接返回；
    //    UNKNOWN / clean -> 返回 false，继续 VMD Status 只读对账
    //    （CR-013 §8 / SPEC §20.2：SEC journal 与 VMD Status 双路收敛，
    //     SEC unknown 不得阻断 StatusRequest）。
    if (reconcile_sec_journal_locked()) return;
    // 2) 无已提交副作用：以原 requestId 查 VMD Status 确认批次事实。
    if (!reconcile_status_sent_) {
        send_status_request_locked();
        return;
    }
    if (deadline_ms_ > 0 && now_ms() >= deadline_ms_) {
        // 响应丢失：退避后重试（保留原 requestId）。
        reconcile_status_sent_ = false;
        schedule_retry_locked();
        persist_locked();
        return;
    }
    // 等待 StatusResponse（由 handle_reconcile_status_locked 收敛）。
}

void V2cKeyProvisioningCoordinator::handle_reconcile_status_locked(
    const KeyProvStatusResponseData& status) {
    // CR-013 §8：806095 等幂等冲突 -> VMD 存在旧批次且摘要失效 -> 待云端终结。
    if (keyprov_is_idempotency_conflict(status.error)) {
        counters_.idempotency_conflicts_total++;
        record_conflict_facts_locked(status.error.code.c_str());
        blocked_reason_ = keyprov_blocked_reason::kAwaitCloudTermination;
        count_blocked_reason_locked(keyprov_blocked_reason::kAwaitCloudTermination);
        state_ = V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION;
        schedule_retry_locked();
        persist_locked();
        return;
    }
    // CR-014 §21.4 步骤 1：requestId / fingerprint / 证书摘要 / store generation
    // 匹配由 handle_routed_downlink 入口的 awaiting_* 隔离覆盖（requestId +
    // store_generation + fingerprint；证书摘要变化体现为 fingerprint 变化）。

    switch (status.status) {
        case kKeyProvStatusActive: {
            // 云端已有 ACTIVE 批次：SEC COMMITTED -> 恢复 ACK；否则等待受控终结。
            if (reconcile_sec_journal_locked()) return;  // COMMITTED/EVIDENCE_CONFLICT
            if (sec_outcome_unknown_) return;  // fail-closed 状态已由 reconcile 设置
            // SEC NOT_FOUND 但 VMD 有 ACTIVE 批次：非终态，等待云端终结。
            blocked_reason_ = keyprov_blocked_reason::kSecImportNotFound;
            state_ = V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION;
            schedule_retry_locked();
            if (!reconcile_obs_suppressed_locked(
                    status.status, last_sec_evidence_kind_)) {
                count_blocked_reason_locked(
                    keyprov_blocked_reason::kSecImportNotFound);
                persist_locked();
            }
            return;
        }
        case kKeyProvStatusFailed: {
            // VMD 已终结（FAILED）——当前协议唯一被认可的可释放终态（用户裁决：
            // 不把无 error 的 UNSPECIFIED 当可释放）。
            if (reconcile_sec_journal_locked()) return;  // COMMITTED/EVIDENCE_CONFLICT
            if (sec_outcome_unknown_) {
                // SEC 未给出明确事实（Failed/OutcomeUnknown/QueryError/
                // ContractUnknown）：不得断言无副作用/建新 attempt，保持对账。
                return;  // reconcile 已设置 RECONCILE + blocked_reason + 退避
            }
            // 仅 SEC NOT_FOUND（sec_no_side_effects_proven_）且无本地冲突：
            // SUPERSEDED_REMOTE。原子终态化旧 record，带 supersedesRequestId
            // 创建新 record，再调度发送（CR-014 §21.4 步骤 5/6，不得先清空）。
            counters_.superseded_remote++;
            record_.last_error = "vmd_batch_terminated";
            state_ = V2cKeyProvState::SUPERSEDED_REMOTE;
            persist_locked();
            create_new_attempt_locked();
            return;
        }
        case kKeyProvStatusUnspecified: {
            // UNSPECIFIED 无协议冻结语义证明“批次不存在/已终结并释放”：
            // 一律 fail-closed（用户裁决），不得当作可释放终态。
            if (reconcile_sec_journal_locked()) return;
            if (sec_outcome_unknown_) return;
            blocked_reason_ = keyprov_blocked_reason::kSecImportNotFound;
            state_ = V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION;
            schedule_retry_locked();
            if (!reconcile_obs_suppressed_locked(
                    status.status, last_sec_evidence_kind_)) {
                count_blocked_reason_locked(
                    keyprov_blocked_reason::kSecImportNotFound);
                persist_locked();
            }
            return;
        }
        case kKeyProvStatusRequested:
        case kKeyProvStatusIssued:
        case kKeyProvStatusAckPending: {
            // VMD 有未终结批次：等待受控终结（不调用 MPT 治理接口）。
            if (reconcile_sec_journal_locked()) return;
            if (sec_outcome_unknown_) return;
            blocked_reason_ = keyprov_blocked_reason::kSecImportNotFound;
            state_ = V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION;
            schedule_retry_locked();
            if (!reconcile_obs_suppressed_locked(
                    status.status, last_sec_evidence_kind_)) {
                count_blocked_reason_locked(
                    keyprov_blocked_reason::kSecImportNotFound);
                persist_locked();
            }
            return;
        }
        case 6:  // KEY_PROVISIONING_STATUS_UNKNOWN
        default: {
            // VMD 状态未知：非终态，SEC NOT_FOUND 不足以覆盖 VMD 未知。
            if (reconcile_sec_journal_locked()) return;
            if (sec_outcome_unknown_) return;
            blocked_reason_ = keyprov_blocked_reason::kVmdOutcomeUnknown;
            state_ = V2cKeyProvState::RECONCILE_OLD_ATTEMPT;
            schedule_retry_locked();
            if (!reconcile_obs_suppressed_locked(
                    status.status, last_sec_evidence_kind_)) {
                count_blocked_reason_locked(
                    keyprov_blocked_reason::kVmdOutcomeUnknown);
                persist_locked();
            }
            return;
        }
    }
}

void V2cKeyProvisioningCoordinator::transition_to_locked(
    V2cKeyProvState next) {
    if (state_ == next) return;
    std::string key = std::string(v2c_key_prov_state_to_string(state_)) +
                      "->" + v2c_key_prov_state_to_string(next);
    counters_.attempt_transitions_total[key]++;
    state_ = next;
}

void V2cKeyProvisioningCoordinator::count_blocked_reason_locked(
    const char* reason) {
    const char* r = (reason && *reason) ? reason
                                        : keyprov_blocked_reason::kUnknown;
    static const char* const kKnown[] = {
        keyprov_blocked_reason::kLegacySnapshotUnknown,
        keyprov_blocked_reason::kIdempotencyConflict,
        keyprov_blocked_reason::kAwaitCloudTermination,
        keyprov_blocked_reason::kSecOutcomeUnknown,
        keyprov_blocked_reason::kVmdOutcomeUnknown,
        // CR-014：SEC 证据阻断细分
        keyprov_blocked_reason::kSecImportNotFound,
        keyprov_blocked_reason::kSecImportInProgress,
        keyprov_blocked_reason::kEvidenceConflict};
    const char* key = keyprov_blocked_reason::kUnknown;
    for (const char* k : kKnown) {
        if (std::strcmp(k, r) == 0) {
            key = k;
            break;
        }
    }
    counters_.blocked_reasons_total[key]++;
}

// CR-014 §21.5：相同三元组 {vmd_state, sec_evidence, store_generation} 不重复
// 写盘/计数/刷日志。vmd_status 编码：-1=SEC 阶段（VMD 未知），-3=BLOCKED
// EVIDENCE_CONFLICT 周期重查；>=0 为 VMD Status 数值。
bool V2cKeyProvisioningCoordinator::reconcile_obs_suppressed_locked(
    int vmd_status, SecImportEvidenceKind kind) {
    if (last_obs_valid_ && last_obs_vmd_status_ == vmd_status &&
        last_obs_kind_ == kind &&
        last_obs_generation_ == store_generation_) {
        return true;
    }
    last_obs_valid_ = true;
    last_obs_vmd_status_ = vmd_status;
    last_obs_kind_ = kind;
    last_obs_generation_ = store_generation_;
    return false;
}

void V2cKeyProvisioningCoordinator::mark_submitted_locked() {
    submission_ = keyprov_submission::kSubmitted;
}

void V2cKeyProvisioningCoordinator::mark_confirmed_locked() {
    submission_ = keyprov_submission::kConfirmed;
}

void V2cKeyProvisioningCoordinator::bump_store_generation_locked() {
    store_generation_++;
}

// ============================================================
// 状态推进
// ============================================================
void V2cKeyProvisioningCoordinator::refresh_sec_readiness_locked() {
    // build-lock 部分来自生成清单 + 启动自检；SEC 四项来自只读 capability 查询。
    KeyprovReadiness r = keyprov_build_lock_readiness();
    tbox::sec::V2cKeyProvisioningCapability cap;
    ErrorCode ec = sec_->get_v2c_key_provisioning_capability(cap);
    // 查询失败/未实现：SEC 四项保持 false（fail-closed），不得用 NOT_READY 归约。
    if (ec == ErrorCode::SUCCESS) {
        keyprov_apply_sec_capability(cap, r);
        // CR-014：观测时 capability 快照契约版本（仅诊断；失败记 0=UNKNOWN）。
        sec_import_result_contract_version_ = cap.capability_contract_version;
    } else {
        sec_import_result_contract_version_ = 0;
    }
    readiness_ = r;
}

bool V2cKeyProvisioningCoordinator::capability_gate_locked(
    std::string& reason) {
    if (!config_.enabled) {
        reason = "disabled";
        return false;
    }
    if (stopping_.load(std::memory_order_acquire)) {
        reason = "stopping";
        return false;
    }
    // CR-012 §8：协议锁版 + SEC capability 未就绪时不得发起/提交/ACK。
    refresh_sec_readiness_locked();
    if (!readiness_.all()) {
        reason = readiness_.first_missing_reason();
        return false;
    }
    // CR-011 §5.1: MQTT readiness v3 与 session-bound publish 能力必须分别确认。
    publish_session_supported_ =
        cloud_.publish_contract_version >= kMqttPublishSessionContractVersion;
    if (!cloud_.contract_supported ||
        cloud_.contract_version < kMqttCloudReadinessContractVersionV3) {
        reason = "readiness_v3_unsupported";
        return false;
    }
    if (!publish_session_supported_) {
        reason = "session_bound_publish_unsupported";
        return false;
    }
    if (!capability_.ready) {
        reason = capability_.reason_code.empty()
                     ? "capability_not_ready"
                     : capability_.reason_code;
        return false;
    }
    if (!cloud_.cloud_ready) {
        reason = "cloud_not_ready";
        return false;
    }
    // cloud/capability 必须同 epoch、同 connection/cert 代际。
    if (capability_.connection_generation !=
            cloud_.session.connection_generation ||
        capability_.cert_session_generation !=
            cloud_.session.cert_session_generation) {
        reason = "generation_mismatch";
        return false;
    }
    if (!keyprov_is_canonical_uid(cloud_.ecu_uid)) {
        reason = "uid_invalid";
        return false;
    }
    // 结构性完整性；不代表可发布/已认证，最终由 daemon guard 判定。
    identity_.ecu_uid = cloud_.ecu_uid;
    identity_.device_identity_digest = cloud_.device_identity_digest;
    identity_.certificate_ref = cloud_.certificate_ref;
    identity_.session = cloud_.session;
    std::string identity_reason;
    if (!keyprov_validate_identity(identity_, identity_reason)) {
        identity_ = KeyprovSessionIdentity{};
        reason = identity_reason;
        return false;
    }
    identity_valid_ = true;
    return true;
}

void V2cKeyProvisioningCoordinator::tick_locked() {
    if (!config_.enabled) {
        state_ = V2cKeyProvState::DISABLED;
        return;
    }
    std::string reason;
    bool gate = capability_gate_locked(reason);
    capability_ready_ = gate;
    clock_synced_ = clock_check_ok();

    if (!gate) {
        gate_reason_ = reason;
        // 网络操作暂停，保留非敏感流程状态与原 requestId。
        // 但若身份已不再有效（或门禁原因属身份/代际类），则同时失效未发送任务。
        if (identity_valid_) {
            invalidate_identity_locked(reason.c_str());
        }
        if (state_ == V2cKeyProvState::REQUESTING ||
            state_ == V2cKeyProvState::WAIT_RESPONSE ||
            state_ == V2cKeyProvState::IMPORTING ||
            state_ == V2cKeyProvState::ACK_PENDING) {
            deadline_ms_ = 0;
            state_ = V2cKeyProvState::WAIT_CLOUD;
            persist_locked();
        } else if (state_ == V2cKeyProvState::CHECKING ||
                   state_ == V2cKeyProvState::RETRY_WAIT) {
            state_ = V2cKeyProvState::WAIT_CLOUD;
        }
        // RECONCILE / LEGACY / BLOCKED_AWAIT / SUPERSEDED 保留，待 gate 恢复后继续。
        return;
    }

    // 时钟同步门禁：Request 携带绝对 expire_at_ms；冷启动早期系统时钟可能尚未
    // 被 NTP 校正，此时发布必然被云端按过期拒绝。保持状态等待同步，不失效身份。
    if (!clock_synced_) {
        gate_reason_ = "clock_not_synced";
        if (state_ == V2cKeyProvState::REQUESTING) {
            state_ = V2cKeyProvState::WAIT_CLOUD;
        }
        return;
    }

    gate_reason_.clear();

    const int64_t now = now_ms();
    switch (state_) {
        case V2cKeyProvState::DISABLED:
            state_ = V2cKeyProvState::WAIT_CLOUD;
            break;
        case V2cKeyProvState::WAIT_CLOUD:
            if (next_retry_ms_ > now) return;
            state_ = V2cKeyProvState::CHECKING;
            do_check_locked();
            break;
        case V2cKeyProvState::CHECKING:
            do_check_locked();
            break;
        case V2cKeyProvState::REQUESTING:
            do_request_locked();
            break;
        case V2cKeyProvState::WAIT_RESPONSE:
            if (deadline_ms_ == 0) {
                // CR-011 §5.1：身份/上下文失效暂停了网络 deadline；重读完整快照并
                // 重新评估（CR-013：candidate==frozen 则复用 requestId 重发，
                // !=frozen 则进入 RECONCILE_OLD_ATTEMPT）。
                state_ = V2cKeyProvState::CHECKING;
                do_check_locked();
            } else if (now >= deadline_ms_) {
                on_response_timeout_locked();
            }
            break;
        case V2cKeyProvState::IMPORTING:
            do_import_locked();
            break;
        case V2cKeyProvState::ACK_PENDING:
            do_ack_locked();
            break;
        case V2cKeyProvState::RETRY_WAIT:
            if (next_retry_ms_ > now) return;
            state_ = V2cKeyProvState::CHECKING;
            do_check_locked();
            break;
        case V2cKeyProvState::BLOCKED:
            if (blocked_reason_ == keyprov_blocked_reason::kEvidenceConflict) {
                // CR-014 §21.4/用户裁决：EVIDENCE_CONFLICT 持续阻断直至新权威证据。
                // 新权威事实（SEC 重启/能力代际变化 = capability 事件）立即只读重查
                // SEC journal；其余周期退避重查（journal 状态变化/pending callback
                // 收敛）。COMMITTED -> 恢复原 ACK；其余保持阻断并继续退避。
                // 不得经 do_check 自动回到申请/释放流程。
                const bool new_fact = capability_event_seen_;
                capability_event_seen_ = false;
                if (new_fact || next_retry_ms_ <= now) {
                    if (reconcile_sec_journal_locked()) break;  // 已消费（含重新退避）
                    // reconcile 返回 false：若冲突前提消失（转常规对账），状态已由
                    // reconcile 设置并退避；仍保持 BLOCKED 时只补一次退避。
                    if (state_ == V2cKeyProvState::BLOCKED) {
                        schedule_retry_locked();
                    }
                    break;
                }
                break;
            }
            if (capability_event_seen_) {
                capability_event_seen_ = false;
                state_ = V2cKeyProvState::CHECKING;
                do_check_locked();
            }
            break;
        case V2cKeyProvState::RECONCILE_OLD_ATTEMPT:
            // CR-014 §21.5：对账尊重有上限指数退避，避免约 200ms 固定 StatusRequest
            // 风暴；新 Cloud/SEC 权威事实经 readiness 事件提前唤醒（不绕过退避）。
            if (next_retry_ms_ > now) return;
            do_reconcile_locked();
            break;
        case V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN:
            if (next_retry_ms_ > now) return;
            do_reconcile_locked();
            break;
        case V2cKeyProvState::SUPERSEDED_LOCAL:
        case V2cKeyProvState::SUPERSEDED_REMOTE:
            create_new_attempt_locked();
            break;
        case V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION:
            // 周期观察 VMD 终态（CR-065 受控终结后由 StatusResponse -> SUPERSEDED_REMOTE）。
            if (next_retry_ms_ > now) return;
            if (!reconcile_status_sent_) {
                send_status_request_locked();
            } else if (deadline_ms_ > 0 && now >= deadline_ms_) {
                reconcile_status_sent_ = false;
                schedule_retry_locked();
                persist_locked();
            }
            break;
        case V2cKeyProvState::ACTIVE:
            break;
    }
}

void V2cKeyProvisioningCoordinator::do_check_locked() {
    std::vector<std::string> purposes = config_.purposes;
    tbox::sec::BusinessKeyStatusSet set;
    ErrorCode ec = sec_->get_business_key_status(
        config_.business_domain, purposes, set);
    if (ec == ErrorCode::SUCCESS) {
        bool all_active = purposes_complete_locked(set.items);
        if (all_active) {
            // 两用途均已 ACTIVE：开通目标已达（无论来源：本 attempt 导入/既有）。
            // 若存在待确认 ACK/导入，优先恢复原 ACK（SEC journal 事实优先）。
            if (recovering_ack_ || import_attempted_) {
                recovering_ack_ = false;
                state_ = V2cKeyProvState::ACK_PENDING;
                ack_sent_ = false;
                persist_locked();
                do_ack_locked();
            } else {
                state_ = V2cKeyProvState::ACTIVE;
                record_.last_error.clear();
                mark_confirmed_locked();
                counters_.active_transitions++;
                persist_locked();
            }
            return;
        }
        // 缺失/过期：需要申请。CR-013 §5.2 发送前校验 candidate fingerprint。
        KeyprovAttemptSnapshot cand;
        KeyprovFingerprint cand_fp;
        std::string err;
        if (!build_candidate_locked(cand, cand_fp, err)) {
            state_ = V2cKeyProvState::RETRY_WAIT;
            record_.last_error = err.empty() ? "attempt_snapshot_failed" : err;
            schedule_retry_locked();
            persist_locked();
            return;
        }
        if (fingerprint_version_ == 0 || record_.request_id.empty()) {
            // 首次创建 attempt：冻结 snapshot/fingerprint + requestId，原子持久化。
            create_new_attempt_locked();
            return;
        }
        if (!keyprov_fingerprint_equal(frozen_fingerprint_, cand_fp)) {
            // 业务输入变化：禁止复用原 requestId 发送变化后的 Request。
            AttemptChangeDimension d =
                keyprov_attempt_change_dimension(frozen_snapshot_, cand);
            counters_.fingerprint_changes_total[
                keyprov_attempt_change_dimension_to_string(d)]++;
            enter_reconcile_old_attempt_locked("fingerprint_changed", nullptr);
            return;
        }
        // candidate == frozen：沿原 requestId 申请（冻结内容构造，不动态覆盖）。
        state_ = V2cKeyProvState::REQUESTING;
        persist_locked();
        do_request_locked();
        return;
    }
    if (ec == ErrorCode::BUSINESS_KEY_NOT_READY) {
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "sec_not_ready";
        persist_locked();
        return;
    }
    if (ec == ErrorCode::BUSINESS_KEY_UNSUPPORTED ||
        ec == ErrorCode::NOT_IMPLEMENTED ||
        ec == ErrorCode::ACL_DENIED) {
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "sec_unsupported";
        persist_locked();
        return;
    }
    state_ = V2cKeyProvState::RETRY_WAIT;
    record_.last_error = "sec_unavailable";
    schedule_retry_locked();
    persist_locked();
}

void V2cKeyProvisioningCoordinator::do_request_locked() {
    // CR-013 §5.2：发送前重新读取当前输入计算 candidate；仅 candidate==frozen 才
    // 沿原 requestId 发送，且用 frozen snapshot 构造（不得动态覆盖业务字段）。
    KeyprovAttemptSnapshot cand;
    KeyprovFingerprint cand_fp;
    std::string err;
    if (!build_candidate_locked(cand, cand_fp, err)) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = err.empty() ? "attempt_snapshot_failed" : err;
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (fingerprint_version_ > 0 &&
        !keyprov_fingerprint_equal(frozen_fingerprint_, cand_fp)) {
        AttemptChangeDimension d =
            keyprov_attempt_change_dimension(frozen_snapshot_, cand);
        counters_.fingerprint_changes_total[
            keyprov_attempt_change_dimension_to_string(d)]++;
        enter_reconcile_old_attempt_locked("fingerprint_changed_before_send", nullptr);
        return;
    }

    // 用 frozen snapshot 构造 Request（内容不变）。
    KeyProvRequestData req;
    req.request_id = record_.request_id;
    req.idempotency_key = record_.idempotency_digest.empty()
                              ? record_.request_id
                              : record_.idempotency_digest;
    req.business_domain = frozen_snapshot_.business_domain.empty()
                              ? config_.business_domain
                              : frozen_snapshot_.business_domain;
    for (int p : frozen_snapshot_.purposes) {
        req.purposes.push_back(p);
    }
    req.certificate_ref.certificate_profile = config_.certificate_profile;
    req.supported_wrapping_suites = frozen_snapshot_.wrapping_suites;
    req.supported_envelope_formats = frozen_snapshot_.envelope_formats;
    for (const auto& kv : frozen_snapshot_.current_versions) {
        KeyProvCurrentVersion cv;
        cv.purpose = kv.first;
        cv.business_key_version = kv.second;
        req.current_versions.push_back(cv);
    }
    int64_t now = now_ms();
    req.timestamp_ms = now;
    req.expire_at_ms = now + static_cast<int64_t>(config_.request_timeout_ms) + 1000;

    std::string message_id = generate_id("msg");
    auto enc = build_keyprov_request_envelope(identity_, req, message_id, "");
    if (enc.status != KeyProvCodecStatus::Ok) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "request_encode_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (publish_keyprov_locked(message_id, enc.envelope_bytes, record_.request_id)) {
        state_ = V2cKeyProvState::WAIT_RESPONSE;
        deadline_ms_ = now + config_.request_timeout_ms;
        record_.attempt_count++;
        counters_.requests_published++;
        mark_submitted_locked();
        // 发送时快照（迟到结果隔离：requestId + generation + fingerprint）。
        awaiting_active_ = true;
        awaiting_request_id_ = record_.request_id;
        awaiting_generation_ = store_generation_;
        awaiting_fingerprint_ = frozen_fingerprint_;
        persist_locked();
    } else {
        persist_locked();
    }
}

void V2cKeyProvisioningCoordinator::on_response_timeout_locked() {
    if (record_.attempt_count >= config_.max_attempts_before_alert) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.max_attempts_alert",
            "keyprov 申请重试次数超过告警阈值", {
                {"attempts", tbox::fw::log::FieldValue::makeInt(
                    static_cast<int64_t>(record_.attempt_count))}
            });
    }
    // 原 requestId 不变；回到 CHECKING 重新查询 SEC 事实
    state_ = V2cKeyProvState::RETRY_WAIT;
    record_.last_error = "response_timeout";
    schedule_retry_locked();
    persist_locked();
}

void V2cKeyProvisioningCoordinator::do_import_locked() {
    if (import_attempted_) {
        tbox::sec::ImportResult res;
        ErrorCode ec = sec_->get_business_key_import_result(record_.request_id, res);
        handle_import_result_locked(ec, res);
        return;
    }
    // CR-014：先持久化 import invocation 证据再调用（崩溃点可审计"已调用"），
    // 避免"调用过但无记录"的窗口被误判为从未调用。
    if (!import_invocation_recorded_) {
        import_invocation_recorded_ = true;
        persist_locked();
    }
    tbox::sec::ImportResult res;
    ErrorCode ec = sec_->import_wrapped_business_keys(
        record_.request_id, config_.business_domain, pending_items_, res);
    import_attempted_ = true;
    handle_import_result_locked(ec, res);
}

bool V2cKeyProvisioningCoordinator::import_result_bindable_locked(
    const tbox::sec::ImportResult& result, std::string& err) const {
    if (result.items.size() != config_.purposes.size()) {
        err = "import_purpose_count_mismatch";
        return false;
    }
    for (const auto& p : config_.purposes) {
        bool found = false;
        for (const auto& it : result.items) {
            if (it.purpose != p) continue;
            if (found) {  // 重复 purpose
                err = "import_purpose_duplicate";
                return false;
            }
            found = true;
            // 只有两用途均 IMPORTED(ACTIVE) 且 attestation 完整才允许成功 ACK。
            if (it.state != BusinessKeyState::ACTIVE ||
                it.business_key_version == 0 || it.key_id.empty() ||
                it.envelope_format != tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1 ||
                it.envelope_digest.size() != kKeyprovEnvelopeDigestBytes ||
                !it.key_check_value_present ||
                it.import_proof.size() != kKeyprovImportProofP1363Bytes ||
                it.recipient_certificate_digest.size() !=
                    kKeyprovRecipientCertDigestBytes ||
                it.proof_algorithm != tbox::sec::kImportProofAlgorithmP1363) {
                err = "import_attestation_invalid";
                return false;
            }
            // 与原 Response 逐项绑定（若本进程仍持有绑定材料）。
            for (const auto& b : response_binding_) {
                if (b.purpose != p) continue;
                if (b.key_id != it.key_id ||
                    b.business_key_version != it.business_key_version ||
                    b.envelope_format != static_cast<int>(it.envelope_format) ||
                    b.envelope_digest != it.envelope_digest ||
                    b.key_check_value != it.key_check_value) {
                    err = "import_response_binding_conflict";
                    return false;
                }
                break;
            }
            break;
        }
        if (!found) {
            err = "import_purpose_missing";
            return false;
        }
    }
    return true;
}

void V2cKeyProvisioningCoordinator::handle_import_result_locked(
    ErrorCode ec, const tbox::sec::ImportResult& result) {
    // 无论结果如何，导入调用返回后立即清理临时 Wrapped Key 缓冲
    pending_items_.clear();

    if (ec == ErrorCode::SUCCESS &&
        result.state == BusinessKeyImportState::COMMITTED) {
        // CR-014：结果已确定，回调收敛。
        pending_callback_ = false;
        std::string bind_err;
        if (!import_result_bindable_locked(result, bind_err)) {
            // 结构性/绑定拒绝：不得发送成功 ACK，也不得盲目重试。
            counters_.imports_failed++;
            state_ = V2cKeyProvState::BLOCKED;
            record_.last_error = bind_err;
            persist_locked();
            return;
        }
        ack_items_ = build_ack_items(result);
        if (ack_items_.size() != config_.purposes.size()) {
            state_ = V2cKeyProvState::RETRY_WAIT;
            record_.last_error = "import_incomplete";
            schedule_retry_locked();
            persist_locked();
            return;
        }
        counters_.imports_committed++;
        state_ = V2cKeyProvState::ACK_PENDING;
        ack_sent_ = false;
        status_sent_ = false;
        persist_locked();
        do_ack_locked();
        return;
    }
    if (ec == ErrorCode::SUCCESS &&
        result.state == BusinessKeyImportState::NOT_FOUND) {
        // CR-014：import 已调用但 SEC 结构化证明无记录 -> 证据冲突，持续阻断
        // （不自动重试/释放；等待新权威证据）。
        pending_callback_ = false;
        blocked_reason_ = keyprov_blocked_reason::kEvidenceConflict;
        record_.last_error = "evidence_conflict";
        count_blocked_reason_locked(keyprov_blocked_reason::kEvidenceConflict);
        state_ = V2cKeyProvState::BLOCKED;
        persist_locked();
        return;
    }
    if (ec == ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN ||
        result.state == BusinessKeyImportState::UNKNOWN) {
        counters_.imports_unknown++;
        pending_callback_ = true;  // 结果待定，回调待收敛
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "import_unknown";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (ec == ErrorCode::SUCCESS &&
        (result.state == BusinessKeyImportState::REQUESTED ||
         result.state == BusinessKeyImportState::STAGED)) {
        pending_callback_ = true;  // 已受理/ staging 中，回调待定
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "import_pending";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (result.state == BusinessKeyImportState::FAILED ||
        ec == ErrorCode::WRAPPED_KEY_INVALID ||
        ec == ErrorCode::BUSINESS_KEY_CONFLICT ||
        ec == ErrorCode::BUSINESS_KEY_PARTIAL_ROLLBACK) {
        counters_.imports_failed++;
        import_attempted_ = false;  // 明确失败：允许以原 requestId 重新申请
        pending_callback_ = false;  // 结果已确定（失败）
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "import_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (ec == ErrorCode::BUSINESS_KEY_NOT_READY ||
        ec == ErrorCode::BUSINESS_KEY_UNSUPPORTED) {
        pending_callback_ = false;  // 能力问题，未受理，无待定回调
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "sec_not_ready";
        persist_locked();
        return;
    }
    pending_callback_ = false;
    state_ = V2cKeyProvState::RETRY_WAIT;
    record_.last_error = "import_error";
    schedule_retry_locked();
    persist_locked();
}

void V2cKeyProvisioningCoordinator::do_ack_locked() {
    // 恢复路径：ack_items_ 为空时从 SEC 取回非敏感 import proof
    if (ack_items_.empty()) {
        tbox::sec::ImportResult res;
        ErrorCode ec = sec_->get_business_key_import_result(record_.request_id, res);
        if (ec == ErrorCode::SUCCESS &&
            res.state == BusinessKeyImportState::COMMITTED) {
            ack_items_ = build_ack_items(res);
        } else {
            state_ = V2cKeyProvState::RETRY_WAIT;
            record_.last_error = "ack_proof_unavailable";
            schedule_retry_locked();
            persist_locked();
            return;
        }
    }

    int64_t now = now_ms();
    if (ack_sent_ && deadline_ms_ > 0 && now < deadline_ms_) {
        return;  // 等待 AckResult / 超时
    }
    if (ack_sent_ && now >= deadline_ms_) {
        // ACK 响应丢失：保留 requestId，重发 ACK（幂等）；超阈值后改为状态对账
        if (record_.attempt_count >= config_.max_attempts_before_alert && !status_sent_) {
            std::string message_id = generate_id("msg");
            auto enc = build_keyprov_status_request_envelope(
                identity_, record_.request_id, now, message_id, "");
            if (enc.status == KeyProvCodecStatus::Ok) {
                if (publish_keyprov_locked(message_id, enc.envelope_bytes,
                                           record_.request_id)) {
                    counters_.status_requests_sent++;
                    status_sent_ = true;
                    deadline_ms_ = now + config_.ack_timeout_ms;
                }
                persist_locked();
            }
            return;
        }
    }

    std::string message_id = generate_id("msg");
    auto enc = build_keyprov_ack_envelope(
        identity_, record_.request_id, ack_items_, now, message_id,
        last_response_message_id_);
    if (enc.status != KeyProvCodecStatus::Ok) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "ack_encode_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (publish_keyprov_locked(message_id, enc.envelope_bytes, record_.request_id)) {
        ack_sent_ = true;
        record_.attempt_count++;
        deadline_ms_ = now + config_.ack_timeout_ms;
        counters_.acks_sent++;
        persist_locked();
    } else {
        persist_locked();
    }
}

void V2cKeyProvisioningCoordinator::schedule_retry_locked() {
    uint32_t backoff = current_backoff_ms_locked();
    if (config_.retry_jitter && backoff > 0) {
        static thread_local std::mt19937 rng{std::random_device{}()};
        std::uniform_int_distribution<uint32_t> dist(0, backoff / 4 + 1);
        backoff += dist(rng);
    }
    next_retry_ms_ = now_ms() + backoff;
    // 指数增长
    uint64_t next = static_cast<uint64_t>(backoff_ms_ == 0 ? config_.retry_initial_ms
                                                           : backoff_ms_) *
                    static_cast<uint64_t>(config_.retry_multiplier <= 0 ? 2
                                                                        : config_.retry_multiplier);
    if (next > config_.retry_max_ms) next = config_.retry_max_ms;
    backoff_ms_ = static_cast<uint32_t>(next);
}

uint32_t V2cKeyProvisioningCoordinator::current_backoff_ms_locked() const {
    return backoff_ms_ == 0 ? config_.retry_initial_ms : backoff_ms_;
}

void V2cKeyProvisioningCoordinator::reset_to_checking_locked() {
    state_ = V2cKeyProvState::CHECKING;
}

void V2cKeyProvisioningCoordinator::persist_locked() {
    record_.state = v2c_key_prov_state_to_string(state_);
    record_.updated_at_ms = now_ms();
    record_.deadline_ms = deadline_ms_;
    record_.cloud_session_generation = cloud_.cert_session_generation;
    // CR-013 attempt 冻结状态（单聚合键原子持久化）。
    record_.schema_version = kV2cStoreSchemaVersion;
    record_.fingerprint_version = fingerprint_version_;
    record_.attempt_fingerprint =
        fingerprint_version_ > 0
            ? keyprov_fingerprint_to_hex(frozen_fingerprint_)
            : "";
    record_.snapshot = frozen_snapshot_;
    record_.submission = submission_;
    record_.supersedes_request_id = supersedes_request_id_;
    record_.superseded_by_request_id = superseded_by_request_id_;
    record_.blocked_reason = blocked_reason_;
    record_.store_generation = store_generation_;
    // CR-014 v3：SEC import result 证据（非敏感）
    record_.sec_import_result_contract_version = sec_import_result_contract_version_;
    record_.sec_import_evidence_kind =
        static_cast<int>(last_sec_evidence_kind_);
    record_.sec_evidence_observed_store_generation = store_generation_;
    record_.sec_evidence_observed_at_ms = now_ms();
    record_.import_invocation = import_invocation_recorded_;
    if (!frozen_snapshot_.purposes.empty()) {
        record_.purposes.clear();
        for (int p : frozen_snapshot_.purposes) {
            record_.purposes.push_back(keyprov_purpose_to_string(p));
        }
        record_.business_key_versions.clear();
        for (const auto& kv : frozen_snapshot_.current_versions) {
            record_.business_key_versions.emplace_back(
                keyprov_purpose_to_string(kv.first), kv.second);
        }
    }
    if (store_) store_->save(record_);
}

bool V2cKeyProvisioningCoordinator::purposes_complete_locked(
    const std::vector<tbox::sec::BusinessKeyStatus>& items) const {
    if (items.size() != config_.purposes.size()) return false;
    for (const auto& p : config_.purposes) {
        bool found = false;
        for (const auto& it : items) {
            if (it.purpose == p &&
                it.state == BusinessKeyState::ACTIVE &&
                it.business_key_version > 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

bool V2cKeyProvisioningCoordinator::keyprov_response_valid_locked(
    const KeyProvResponseData& resp, std::string& err) const {
    // SUCCEEDED 必须恰为配置的完整 purpose 集；每项版本非 0、keyId 非空、
    // wrapped_key 非空且在允许大小内；TTL 未过期。
    if (resp.items.size() != config_.purposes.size()) {
        err = "response_purpose_count_mismatch";
        return false;
    }
    const int64_t now = now_ms();
    if (resp.expire_at_ms > 0 && now >= resp.expire_at_ms) {
        err = "response_expired";
        return false;
    }
    for (const auto& p : config_.purposes) {
        bool found = false;
        for (const auto& it : resp.items) {
            if (it.purpose != p) continue;
            found = true;
            if (it.business_key_version == 0 || it.key_id.empty() ||
                it.wrapped_key.empty() ||
                it.wrapped_key.size() > kKeyprovMaxWrappedKeyBytes ||
                it.parameters.size() > kKeyprovMaxParametersBytes ||
                it.envelope_format !=
                    tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1 ||
                it.envelope_digest.size() != kKeyprovEnvelopeDigestBytes ||
                !it.key_check_value_present) {
                err = "response_item_invalid";
                return false;
            }
            break;
        }
        if (!found) {
            err = "response_purpose_missing";
            return false;
        }
    }
    return true;
}

// CR-011 §5.2/§6: 携 expected_session 发布 keyprov 上行并按 reason 分流。
// 返回 true 表示 daemon 已接管或结果未知（需用原 requestId 对账）。
bool V2cKeyProvisioningCoordinator::publish_keyprov_locked(
    const std::string& message_id,
    const std::vector<uint8_t>& envelope_bytes,
    const std::string& request_id) {
    if (!identity_valid_) {
        state_ = V2cKeyProvState::WAIT_CLOUD;
        record_.last_error = "identity_unavailable";
        return false;
    }
    // keyprov 必须携带同一快照的 session context；不得走无上下文重载降级。
    MqttPublishOptions options;
    options.qos = 1;
    options.content_type = "application/x-protobuf";
    options.request_id = request_id;
    options.expected_session = identity_.session;

    MqttPublishResult pr = mqtt_->publishRoute(
        "tsp", config_.route_up, message_id, envelope_bytes, options);
    if (pr.accepted || pr.outcome == MqttDeliveryOutcome::Unknown) {
        return true;
    }

    // CR-011 §6: 保留数字码 + reason，输出脱敏诊断（不含身份/payload）。
    LogAdapter::keyprov().warn(
        "tsp.keyprov.publish_rejected",
        "keyprov 上行被 MQTT 拒绝", {
            {"reason", tbox::fw::log::FieldValue::makeString(pr.reason_code)},
            {"error_code", tbox::fw::log::FieldValue::makeInt(
                static_cast<int64_t>(pr.error_code))},
            {"retryable", tbox::fw::log::FieldValue::makeBool(pr.retryable)}
        });

    const std::string& reason = pr.reason_code;
    if (reason == session_reason::kPublishContextStale) {
        // 构造/发送间切换：失效本地身份、暂停 deadline，刷新快照后先对账再重构。
        invalidate_identity_locked("publish_session_stale");
        state_ = V2cKeyProvState::WAIT_CLOUD;
        record_.last_error = "publish_session_stale";
        refresh_readiness_locked();
        return false;
    }
    if (reason == session_reason::kPublishContextRequired) {
        // 本地调用缺陷：阻断 keyprov 并告警，不改用 legacy。
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "publish_session_required";
        LogAdapter::keyprov().error(
            "tsp.keyprov.publish_session_required",
            "keyprov 发布未携会话上下文，阻断流程");
        return false;
    }
    if (reason == session_reason::kPublishContextUnsupported) {
        // 版本门禁失败：NOT_READY，不放宽 guard。
        publish_session_supported_ = false;
        state_ = V2cKeyProvState::WAIT_CLOUD;
        record_.last_error = "publish_session_unsupported";
        return false;
    }
    if (reason == session_reason::kSessionIdentityInvalid ||
        reason == session_reason::kSessionIdentityConflict ||
        reason == session_reason::kSessionIdentityMissing) {
        // 身份安全问题：阻断，不无限重发。
        invalidate_identity_locked("session_identity_invalid");
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "session_identity_invalid";
        return false;
    }

    state_ = V2cKeyProvState::RETRY_WAIT;
    record_.last_error = pr.retryable ? "route_publish_rejected"
                                      : "route_publish_rejected_fatal";
    schedule_retry_locked();
    return false;
}

int64_t V2cKeyProvisioningCoordinator::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string V2cKeyProvisioningCoordinator::generate_id(const char* prefix) {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t a = rng();
    uint64_t b = rng();
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s-%016llx%016llx", prefix,
                  static_cast<unsigned long long>(a),
                  static_cast<unsigned long long>(b));
    return std::string(buf);
}

} // namespace tsp
} // namespace tbox
