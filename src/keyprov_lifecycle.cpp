// TBOX-TSP-DSN-CR-017：集中生命周期决策（纯函数）+ 持久预算账本 + 时间工具。
#include "keyprov_lifecycle.h"

#include <algorithm>

namespace tbox {
namespace tsp {

const char* keyprov_action_to_string(KeyprovAction a) {
    switch (a) {
        case KeyprovAction::WAIT_READY:         return "WAIT_READY";
        case KeyprovAction::SEND_REQUEST:       return "SEND_REQUEST";
        case KeyprovAction::IMPORT:             return "IMPORT";
        case KeyprovAction::SEND_ORIGINAL_ACK:  return "SEND_ORIGINAL_ACK";
        case KeyprovAction::QUERY_STATUS_OR_SEC: return "QUERY_STATUS_OR_SEC";
        case KeyprovAction::SUPERSEDE_CAS:      return "SUPERSEDE_CAS";
        case KeyprovAction::ACTIVE:             return "ACTIVE";
        case KeyprovAction::BLOCKED:            return "BLOCKED";
        case KeyprovAction::LATE_RESPONSE:      return "LATE_RESPONSE";
        case KeyprovAction::CONFLICT_806095:    return "CONFLICT_806095";
        case KeyprovAction::FRESHEN_SAME_ID:    return "FRESHEN_SAME_ID";
        case KeyprovAction::RESTORE_ORIGINAL_ACK: return "RESTORE_ORIGINAL_ACK";
        case KeyprovAction::RESTORE_SUCCESSOR:  return "RESTORE_SUCCESSOR";
        case KeyprovAction::RESPONSE_EXPIRED:   return "RESPONSE_EXPIRED";
        case KeyprovAction::LEASE_TOO_SHORT:    return "LEASE_TOO_SHORT";
        case KeyprovAction::REJECT:             return "REJECT";
        case KeyprovAction::TIME_UNTRUSTED:     return "TIME_UNTRUSTED";
        case KeyprovAction::CONTRACT_UNKNOWN:   return "CONTRACT_UNKNOWN";
        case KeyprovAction::READONLY:           return "READONLY";
        case KeyprovAction::BOUNDED_RETRY:      return "BOUNDED_RETRY";
        default:                                return "?";
    }
}

// ============================================================
// 时间工具（等号语义严格按共享向量）
// ============================================================
int64_t keyprov_ack_safe_deadline_ms(int64_t lease_expires_at_ms,
                                     const KeyprovKl1Params& p) {
    // D = E + ack_grace - skew（KL-REQ-005；E<=B-30000 必有 D<=B-2000）。
    return lease_expires_at_ms + static_cast<int64_t>(p.ack_grace_ms) -
           static_cast<int64_t>(p.skew_ms);
}

bool keyprov_lease_acceptable(int64_t utc_upper_ms,
                              int64_t lease_expires_at_ms,
                              const KeyprovKl1Params& p) {
    // E-U >= import_min；等号允许（LC02.min-import E-U=15000 -> IMPORT）。
    return lease_expires_at_ms - utc_upper_ms >=
           static_cast<int64_t>(p.import_min_ms);
}

bool keyprov_lease_expired(int64_t utc_upper_ms, int64_t lease_expires_at_ms) {
    // U>=E 即过期（等号即过期，LC02.0）。
    return utc_upper_ms >= lease_expires_at_ms;
}

bool keyprov_clock_healthy(const KeyprovClockSource& c) {
    if (c.rollback_detected) return false;
    if (c.uncertainty_ms > 1000) return false;        // LC21.uncertainty
    if (c.sample_age_ms > 300000) return false;       // LC21.stale
    if (c.skew_ms > 2000) return false;               // LC21.skew
    return true;                                      // LC21.healthy（等号允许）
}

// ============================================================
// 优先级 0..9 集中决策表
// ============================================================
KeyprovAction keyprov_lifecycle_decide(const KeyprovLifecycleInput& in) {
    const KeyprovKl1Params def;
    const KeyprovKl1Params& p = in.params ? *in.params : def;
    const int64_t utc_upper =
        in.clock.utc_now_ms + static_cast<int64_t>(in.clock.uncertainty_ms);

    // ---- P0：错绑定/旧 rid/终态 generation Response：丢弃 bundle ----
    // 精确 COMMITTED 反证由 Coordinator 单独保留并对账（不在此释放）。
    if (!in.attempt_valid || !in.binding_match || in.terminalized) {
        return KeyprovAction::LATE_RESPONSE;
    }
    if (in.idempotency_conflict) {
        // 同 rid 不同业务摘要：VMD 806095，停止自动重试进入对账（LC08）。
        return KeyprovAction::CONFLICT_806095;
    }

    // ---- P1：时钟不可信/契约不 ready/SEC 未知或残留 ----
    // 不 import、不新 ID；预算内只读，耗尽 BLOCKED。
    if (!keyprov_clock_healthy(in.clock) || !in.clock.trusted) {
        return KeyprovAction::TIME_UNTRUSTED;  // LC21.*
    }
    if (in.sec_contract_unknown || !in.contract_ready) {
        // 契约未知：fail-closed。已观测到云端事实时属恢复/对账路径（LC11 -> 只读）；
        // 纯契约 probe 时阻断诊断（LC23 -> CONTRACT_UNKNOWN）。
        return (in.cloud_status >= 0)
                   ? KeyprovAction::READONLY
                   : KeyprovAction::CONTRACT_UNKNOWN;
    }
    if (in.sec_unknown_or_error) {
        // SEC 未知/残留：预算内只读对账；预算耗尽 BLOCKED（LC10.SEC.*）。
        return (in.status_budget_ok && in.sec_query_budget_ok)
                   ? KeyprovAction::QUERY_STATUS_OR_SEC
                   : KeyprovAction::BLOCKED;
    }

    // ---- 传输层双准入（LC17.*）：Envelope TTL 与 payload 新鲜度独立，任一过期拒收 ----
    if (in.payload_present && (!in.envelope_fresh || !in.payload_fresh)) {
        return KeyprovAction::REJECT;
    }

    // ---- P2：cloud ACTIVE + 同 rid SEC COMMITTED + 双用途一致 -> ACTIVE ----
    if (in.cloud_status == kKeyProvStatusActive && in.sec_committed &&
        in.purposes_complete) {
        return KeyprovAction::ACTIVE;
    }

    // ---- P3：cloud FAILED + SEC COMMITTED / ACTIVE + SEC NF -> 冲突治理 ----
    if (in.sec_committed && in.cloud_status == kKeyProvStatusFailed) {
        return KeyprovAction::BLOCKED;  // BLOCKED_REMOTE_REPAIR（LC15；不删槽/不盲开新 ID）
    }
    if (in.sec_not_found_proven && in.cloud_status == kKeyProvStatusActive) {
        return KeyprovAction::BLOCKED;  // HARD_CONFLICT（云 ACTIVE + 件内 NF）
    }

    // ---- P4：SEC COMMITTED + cloud ACK_PENDING：仅恢复原 proof/ACK ----
    // D 与 ACK 预算允许才发送，否则只读 Status（LC14/LC14.after-D/LC09.ack-*）。
    if (in.sec_committed && in.cloud_status == kKeyProvStatusAckPending) {
        if (in.ack_budget_ok &&
            utc_upper < in.ack_safe_deadline_ms) {
            return KeyprovAction::RESTORE_ORIGINAL_ACK;
        }
        return KeyprovAction::READONLY;
    }

    // ---- P5：cloud terminal / releasable + NO_SIDE_EFFECT_PROVEN -> CAS 唯一后继 ----
    const bool releasable_unspecified =
        in.cloud_status == kKeyProvStatusUnspecified &&
        in.cloud_error.present &&
        in.cloud_error.code == kKeyProvErrorCodeNotFound &&
        !in.cloud_error.retryable &&
        in.cloud_error.action == ProtocolErrorAction::DO_NOT_RETRY;
    const bool cloud_terminal =
        in.cloud_status == kKeyProvStatusFailed || releasable_unspecified;
    if (in.no_side_effect_proven && cloud_terminal) {
        if (!in.chain_ok) {
            return KeyprovAction::BLOCKED;  // 链耗尽（LC22.*）
        }
        if (in.successor_preexisting) {
            return KeyprovAction::RESTORE_SUCCESSOR;  // LC12.cas
        }
        return KeyprovAction::SUPERSEDE_CAS;  // LC12 / LC12.unspecified-DO_NOT_RETRY
    }
    // proven + 云端 UNSPECIFIED 但非可释放四元组（LC12.unspecified-RETRY）：fail-closed
    // 有界只读对账，不得盲发新 Request。
    if (in.no_side_effect_proven && in.cloud_status == kKeyProvStatusUnspecified) {
        return KeyprovAction::READONLY;
    }

    // ---- P6：expired/too-short + ACK_PENDING + proven + 可交付 + freshen=0 ----
    // 一次同 rid freshen；预算/时间不够只读（LC16.first）。
    const bool expired_or_too_short =
        in.payload_present &&
        (keyprov_lease_expired(utc_upper, in.lease_expires_at_ms) ||
         !keyprov_lease_acceptable(utc_upper, in.lease_expires_at_ms, p) ||
         !in.payload_fresh);
    if (expired_or_too_short && !in.freshen_used &&
        in.cloud_status == kKeyProvStatusAckPending &&
        in.no_side_effect_proven && in.deliverable &&
        in.request_budget_ok) {
        return KeyprovAction::FRESHEN_SAME_ID;
    }

    // ---- P7：expired / 第二次 expired / EXPIRED / noitems：只读 ----
    // 不回通用 RETRY_WAIT。已用 freshen（第二次过期）-> READONLY（LC16）；
    // 新响应接受判定（LC02.0/LC02.1）-> RESPONSE_EXPIRED；
    // 未过期但余量不足（LC02.-1）-> LEASE_TOO_SHORT。
    if (in.payload_present && expired_or_too_short) {
        if (in.freshen_used) {
            return KeyprovAction::READONLY;
        }
        if (keyprov_lease_expired(utc_upper, in.lease_expires_at_ms)) {
            return KeyprovAction::RESPONSE_EXPIRED;
        }
        return KeyprovAction::LEASE_TOO_SHORT;  // LC02.-1
    }

    // ---- P8：新鲜响应 + 全部绑定/契约/epoch/预算通过 + 无 inflight -> import 一次 ----
    if (in.payload_present && in.payload_fresh && in.envelope_fresh &&
        in.response_binding_valid && in.contract_ready &&
        in.sec_capability_epoch_known && !in.import_already &&
        !in.inflight &&
        keyprov_lease_acceptable(utc_upper, in.lease_expires_at_ms, p)) {
        return KeyprovAction::IMPORT;  // LC02.fresh / LC02.min-import
    }

    // ---- P9：可恢复传输故障且 Request 预算未尽 -> 有界退避 ----
    if (in.transport_retryable_fault && in.request_budget_ok) {
        return KeyprovAction::BOUNDED_RETRY;
    }

    // ---- 尾部默认（无外部事实/无响应时的状态推进） ----
    if (in.purposes_complete) {
        return KeyprovAction::ACTIVE;
    }
    if (in.inflight) {
        return KeyprovAction::WAIT_READY;  // 等待在途结果
    }
    // 恢复/稳定化/对账阶段：只读，不得盲发 Request（LC13.*）。
    if (in.reconciliation_pending) {
        return (in.status_budget_ok && in.sec_query_budget_ok)
                   ? KeyprovAction::QUERY_STATUS_OR_SEC
                   : KeyprovAction::BLOCKED;
    }
    if (in.request_budget_ok) {
        return KeyprovAction::SEND_REQUEST;  // 沿原 requestId（内容未变）
    }
    // Request 预算耗尽：只读对账（LC09.count/time/restart），不回 RETRY_WAIT。
    if (in.status_budget_ok || in.sec_query_budget_ok) {
        return KeyprovAction::READONLY;
    }
    return KeyprovAction::BLOCKED;  // 只读周期也耗尽（LC10.*）
}

// ============================================================
// 持久预算账本
// ============================================================
bool KeyprovBudgetLedger::request_ok(const KeyprovKl1Params& p,
                                     int64_t now_utc_ms) const {
    if (request_send_count >= p.request_limit) return false;
    if (first_request_at_ms > 0 &&
        now_utc_ms - first_request_at_ms >=
            static_cast<int64_t>(p.request_window_ms)) {
        return false;
    }
    return true;
}

bool KeyprovBudgetLedger::status_ok(const KeyprovKl1Params& p,
                                    int64_t now_utc_ms) const {
    if (status_send_count >= p.readonly_limit) return false;
    if (first_readonly_at_ms > 0 &&
        now_utc_ms - first_readonly_at_ms >=
            static_cast<int64_t>(p.readonly_window_ms)) {
        return false;
    }
    return true;
}

bool KeyprovBudgetLedger::sec_query_ok(const KeyprovKl1Params& p,
                                       int64_t now_utc_ms) const {
    if (sec_query_count >= p.readonly_limit) return false;
    if (first_readonly_at_ms > 0 &&
        now_utc_ms - first_readonly_at_ms >=
            static_cast<int64_t>(p.readonly_window_ms)) {
        return false;
    }
    return true;
}

bool KeyprovBudgetLedger::ack_ok(const KeyprovKl1Params& p,
                                 int64_t now_utc_ms) const {
    if (ack_send_count >= p.ack_limit) return false;
    // D 后禁新 ACK（LC09.ack-D / LC14.after-D）。
    if (ack_safe_deadline_at_ms > 0 &&
        now_utc_ms >= ack_safe_deadline_at_ms) {
        return false;
    }
    return true;
}

bool KeyprovBudgetLedger::freshen_ok() const {
    return expiry_freshen_count < 1;
}

bool KeyprovBudgetLedger::chain_ok(const KeyprovKl1Params& p,
                                   int64_t now_utc_ms) const {
    if (chain_request_id_count >= p.chain_ids) return false;
    if (chain_started_at_ms > 0 &&
        now_utc_ms - chain_started_at_ms >=
            static_cast<int64_t>(p.chain_window_ms)) {
        return false;
    }
    return true;
}

void KeyprovBudgetLedger::preconsume_request(const KeyprovKl1Params& p,
                                             int64_t now_utc_ms) {
    if (request_send_count == 0) {
        first_request_at_ms = now_utc_ms;
        request_deadline_at_ms =
            now_utc_ms + static_cast<int64_t>(p.request_window_ms);
    }
    request_send_count++;
}

void KeyprovBudgetLedger::preconsume_status(const KeyprovKl1Params& p,
                                            int64_t now_utc_ms) {
    if (status_send_count == 0) {
        first_readonly_at_ms = now_utc_ms;
        readonly_deadline_at_ms =
            now_utc_ms + static_cast<int64_t>(p.readonly_window_ms);
    }
    status_send_count++;
}

void KeyprovBudgetLedger::preconsume_sec_query(const KeyprovKl1Params& p,
                                               int64_t now_utc_ms) {
    if (sec_query_count == 0) {
        first_readonly_at_ms = now_utc_ms;
        readonly_deadline_at_ms =
            now_utc_ms + static_cast<int64_t>(p.readonly_window_ms);
    }
    sec_query_count++;
}

void KeyprovBudgetLedger::preconsume_ack(const KeyprovKl1Params& p,
                                         int64_t now_utc_ms) {
    if (ack_safe_deadline_at_ms == 0) {
        ack_safe_deadline_at_ms = now_utc_ms;  // 由 Coordinator 覆写为 D
    }
    ack_send_count++;
}

void KeyprovBudgetLedger::preconsume_freshen() {
    expiry_freshen_count++;
}

void KeyprovBudgetLedger::preconsume_chain_id(const KeyprovKl1Params& p,
                                              int64_t now_utc_ms) {
    if (chain_id.empty()) {
        chain_started_at_ms = now_utc_ms;
        chain_deadline_at_ms =
            now_utc_ms + static_cast<int64_t>(p.chain_window_ms);
    }
    chain_request_id_count++;
}

void KeyprovBudgetLedger::reset_for_new_attempt() {
    // 仅新 attempt / 受控运维动作时调用。绝不在重连/重启/epoch flap/时钟回拨时调用。
    request_send_count = 0;
    first_request_at_ms = 0;
    request_deadline_at_ms = 0;
    status_send_count = 0;
    first_readonly_at_ms = 0;
    readonly_deadline_at_ms = 0;
    sec_query_count = 0;
    ack_send_count = 0;
    ack_safe_deadline_at_ms = 0;
    expiry_freshen_count = 0;
    budget_exhausted_reason.clear();
}

} // namespace tsp
} // namespace tbox
