// TBOX-TSP-DSN-CR-010 §3.1/§5/§7: V2cKeyProvisioningCoordinator 实现。
#include "v2c_key_provisioning_coordinator.h"

#include "hash.h"
#include "log_adapter.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <random>

namespace tbox {
namespace tsp {

using tbox::sec::BusinessKeyImportState;
using tbox::sec::BusinessKeyState;
using tbox::sec::ErrorCode;

namespace {

constexpr const char* kCapabilityKeyprov = "security.keyprov";

bool is_hex(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::vector<uint8_t> hex_to_bytes(const std::string& s) {
    auto nib = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        return static_cast<uint8_t>(c - 'A' + 10);
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i + 1])));
    }
    return out;
}

// 从 SEC ImportResult 构造 ACK items（仅非敏感字段 + import_proof）
std::vector<KeyProvImportItemResult> build_ack_items(
    const tbox::sec::ImportResult& result) {
    std::vector<KeyProvImportItemResult> out;
    out.reserve(result.items.size());
    for (const auto& it : result.items) {
        KeyProvImportItemResult a;
        a.purpose = keyprov_purpose_from_string(it.purpose);
        a.key_id = it.key_id_digest;   // SEC 只返回摘要；不可逆、非敏感
        a.business_key_version = it.business_key_version;
        a.result = kKeyProvImportImported;
        // 首期 SEC ImportResult 的 proof 为批次级；ACK 以同一 proof 覆盖两用途。
        a.import_proof = result.import_proof.bytes();
        a.proof_algorithm = result.proof_algorithm;
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
        default: return "?";
    }
}

bool v2c_key_prov_state_from_string(const std::string& s, V2cKeyProvState& out) {
    static const V2cKeyProvState all[] = {
        V2cKeyProvState::DISABLED, V2cKeyProvState::WAIT_CLOUD,
        V2cKeyProvState::CHECKING, V2cKeyProvState::REQUESTING,
        V2cKeyProvState::WAIT_RESPONSE, V2cKeyProvState::IMPORTING,
        V2cKeyProvState::ACK_PENDING, V2cKeyProvState::ACTIVE,
        V2cKeyProvState::RETRY_WAIT, V2cKeyProvState::BLOCKED};
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
    } else {
        state_ = V2cKeyProvState::DISABLED;
    }
    LogAdapter::keyprov().info(
        "tsp.keyprov.initialized", "V2cKeyProvisioningCoordinator 初始化", {
            {"enabled", tbox::fw::log::FieldValue::makeBool(config_.enabled)},
            {"state", tbox::fw::log::FieldValue::makeString(
                v2c_key_prov_state_to_string(state_))}
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
    cloud_ = readiness;
    identity_digest_raw_ = readiness.device_identity_digest;
    certificate_ref_raw_ = readiness.certificate_ref;
    if (readiness.cloud_ready) {
        counters_.cloud_ready_events++;
    }
    capability_event_seen_ = true;
    cv_.notify_all();
}

void V2cKeyProvisioningCoordinator::on_capability_readiness(
    const CapabilityReadiness& readiness) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (readiness.capability == kCapabilityKeyprov) {
        capability_ = readiness;
        capability_event_seen_ = true;
    }
    cv_.notify_all();
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
    s.reason_code = gate_reason_;
    s.attempt_count = record_.attempt_count;
    s.last_error = record_.last_error;
    s.cloud_session_generation = record_.cloud_session_generation;
    return s;
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
            bool ok = false;
            if (state_ == V2cKeyProvState::ACK_PENDING) {
                ok = decoded.decoded.ack_result.result == kKeyProvResultSucceeded;
                if (ok) {
                    state_ = V2cKeyProvState::ACTIVE;
                    import_attempted_ = false;
                    recovering_ack_ = false;
                    record_.last_error.clear();
                    counters_.active_transitions++;
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
            if (state_ != V2cKeyProvState::ACK_PENDING &&
                state_ != V2cKeyProvState::WAIT_RESPONSE &&
                state_ != V2cKeyProvState::CHECKING) {
                return;
            }
            const int active = kKeyProvStatusActive;
            if (decoded.decoded.status_response.status == active) {
                if (!ack_items_.empty() || import_attempted_) {
                    state_ = V2cKeyProvState::ACK_PENDING;
                    ack_sent_ = false;
                } else {
                    state_ = V2cKeyProvState::ACTIVE;
                    counters_.active_transitions++;
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
// 状态推进
// ============================================================
bool V2cKeyProvisioningCoordinator::capability_gate_locked(
    std::string& reason) const {
    if (!config_.enabled) {
        reason = "disabled";
        return false;
    }
    if (stopping_.load(std::memory_order_acquire)) {
        reason = "stopping";
        return false;
    }
    if (!capability_.ready) {
        reason = capability_.reason_code.empty()
                     ? "capability_not_ready"
                     : capability_.reason_code;
        return false;
    }
    if (!cloud_.certificate_ref.empty() && cloud_.certificate_ref != certificate_ref_raw_) {
        reason = "identity_changed";
        return false;
    }
    if (identity_digest_raw_.empty() || certificate_ref_raw_.empty()) {
        reason = "identity_unavailable";
        return false;
    }
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
    gate_reason_ = gate ? "" : reason;

    if (!gate) {
        // 网络操作暂停，保留非敏感流程状态与原 requestId
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
        return;
    }

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
            if (deadline_ms_ > 0 && now >= deadline_ms_) {
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
            if (capability_event_seen_) {
                capability_event_seen_ = false;
                state_ = V2cKeyProvState::CHECKING;
                do_check_locked();
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
        record_.business_key_versions.clear();
        for (const auto& it : set.items) {
            record_.business_key_versions.emplace_back(
                it.purpose, it.business_key_version);
        }
        if (all_active) {
            if (recovering_ack_ || import_attempted_) {
                // SEC 已导入但云端未确认（或导入结果刚变未知后收敛）：恢复 ACK，不重复导入
                recovering_ack_ = false;
                state_ = V2cKeyProvState::ACK_PENDING;
                ack_sent_ = false;
                persist_locked();
                do_ack_locked();
            } else {
                state_ = V2cKeyProvState::ACTIVE;
                record_.last_error.clear();
                counters_.active_transitions++;
                persist_locked();
            }
            return;
        }
        // 缺失/过期：申请（复用稳定 requestId）
        if (record_.request_id.empty()) {
            record_.request_id = generate_id("kp");
            record_.purposes = purposes;
            record_.idempotency_digest =
                tbox::fw::hash::sha256_hex(std::string_view(
                    record_.request_id + "|" + config_.business_domain));
            import_attempted_ = false;
        }
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
    KeyProvRequestData req;
    req.request_id = record_.request_id;
    req.idempotency_key = record_.idempotency_digest.empty()
                              ? record_.request_id
                              : record_.idempotency_digest;
    req.business_domain = config_.business_domain;
    for (const auto& p : config_.purposes) {
        int v = keyprov_purpose_from_string(p);
        if (v != 0) req.purposes.push_back(v);
    }
    normalize_digest(identity_digest_raw_, req.device_identity_digest);
    req.certificate_ref.certificate_profile = config_.certificate_profile;
    normalize_digest(certificate_ref_raw_, req.certificate_ref.certificate_digest);
    req.supported_wrapping_suites = {
        keyprov_wrapping_suite_from_string(kKeyprovSuiteHpkeBaseX25519),
        keyprov_wrapping_suite_from_string(kKeyprovSuiteEcdhEsP256)};
    for (const auto& kv : record_.business_key_versions) {
        KeyProvCurrentVersion cv;
        cv.purpose = keyprov_purpose_from_string(kv.first);
        cv.business_key_version = kv.second;
        req.current_versions.push_back(cv);
    }
    int64_t now = now_ms();
    req.timestamp_ms = now;
    req.expire_at_ms = now + static_cast<int64_t>(config_.request_timeout_ms) + 1000;

    std::string message_id = generate_id("msg");
    auto enc = build_keyprov_request_envelope(req, message_id, "");
    if (enc.status != KeyProvCodecStatus::Ok) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "request_encode_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    MqttPublishResult pr = mqtt_->publishRoute(
        "tsp", config_.route_up, message_id, enc.envelope_bytes, 1,
        "application/x-protobuf", "", record_.request_id);
    if (pr.accepted || pr.outcome == MqttDeliveryOutcome::Unknown) {
        state_ = V2cKeyProvState::WAIT_RESPONSE;
        deadline_ms_ = now + config_.request_timeout_ms;
        record_.attempt_count++;
        counters_.requests_published++;
        persist_locked();
    } else {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "route_publish_rejected";
        schedule_retry_locked();
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
    tbox::sec::ImportResult res;
    ErrorCode ec = sec_->import_wrapped_business_keys(
        record_.request_id, config_.business_domain, pending_items_, res);
    import_attempted_ = true;
    handle_import_result_locked(ec, res);
}

void V2cKeyProvisioningCoordinator::handle_import_result_locked(
    ErrorCode ec, const tbox::sec::ImportResult& result) {
    // 无论结果如何，导入调用返回后立即清理临时 Wrapped Key 缓冲
    pending_items_.clear();

    if (ec == ErrorCode::SUCCESS &&
        result.state == BusinessKeyImportState::COMMITTED) {
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
    if (ec == ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN ||
        result.state == BusinessKeyImportState::UNKNOWN) {
        counters_.imports_unknown++;
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "import_unknown";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (ec == ErrorCode::SUCCESS &&
        (result.state == BusinessKeyImportState::REQUESTED ||
         result.state == BusinessKeyImportState::STAGED)) {
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
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "import_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    if (ec == ErrorCode::BUSINESS_KEY_NOT_READY ||
        ec == ErrorCode::BUSINESS_KEY_UNSUPPORTED) {
        state_ = V2cKeyProvState::BLOCKED;
        record_.last_error = "sec_not_ready";
        persist_locked();
        return;
    }
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
                record_.request_id, now, message_id, "");
            if (enc.status == KeyProvCodecStatus::Ok) {
                mqtt_->publishRoute("tsp", config_.route_up, message_id,
                                    enc.envelope_bytes, 1,
                                    "application/x-protobuf", "", record_.request_id);
                counters_.status_requests_sent++;
                status_sent_ = true;
            }
            deadline_ms_ = now + config_.ack_timeout_ms;
            return;
        }
    }

    std::string message_id = generate_id("msg");
    auto enc = build_keyprov_ack_envelope(
        record_.request_id, ack_items_, now, message_id, last_response_message_id_);
    if (enc.status != KeyProvCodecStatus::Ok) {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "ack_encode_failed";
        schedule_retry_locked();
        persist_locked();
        return;
    }
    MqttPublishResult pr = mqtt_->publishRoute(
        "tsp", config_.route_up, message_id, enc.envelope_bytes, 1,
        "application/x-protobuf", "", record_.request_id);
    if (pr.accepted || pr.outcome == MqttDeliveryOutcome::Unknown) {
        ack_sent_ = true;
        record_.attempt_count++;
        deadline_ms_ = now + config_.ack_timeout_ms;
        counters_.acks_sent++;
        persist_locked();
    } else {
        state_ = V2cKeyProvState::RETRY_WAIT;
        record_.last_error = "ack_publish_rejected";
        schedule_retry_locked();
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
                it.parameters.size() > kKeyprovMaxParametersBytes) {
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

bool V2cKeyProvisioningCoordinator::normalize_digest(
    const std::string& in, std::vector<uint8_t>& out) const {
    std::string s = in;
    const std::string prefix = "sha256:";
    if (s.rfind(prefix, 0) == 0) {
        s = s.substr(prefix.size());
    }
    if (is_hex(s)) {
        out = hex_to_bytes(s);
        return !out.empty() && out.size() <= kKeyprovMaxDigestBytes;
    }
    if (s.size() > kKeyprovMaxDigestBytes) {
        out.clear();
        return false;
    }
    out.assign(s.begin(), s.end());
    return true;
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
