// TBOX-TSP-DSN-CR-017 §6：集中生命周期决策纯函数单测。
// 以共享向量 keyprov-lifecycle-kl1-v1（PAR-PROTO-DSN-CR-010，SHA256
// 5226b927...）为语义基准；本文件驱动 keyprov_lifecycle_decide 与预算账本。
#include <gtest/gtest.h>

#include "keyprov_lifecycle.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <string>
#include <vector>

using namespace tbox::tsp;

namespace {

constexpr int64_t T0 = 1800000000000LL;

KeyprovKl1Params params() {
    KeyprovKl1Params p;
    return p;  // 与共享向量 parameters 一致
}

KeyprovLifecycleInput base_input() {
    KeyprovLifecycleInput in;
    in.params = nullptr;  // 默认参数
    in.attempt_valid = true;
    in.binding_match = true;
    in.clock.utc_now_ms = T0;
    in.clock.monotonic_ms = 0;
    in.clock.trusted = true;
    in.contract_ready = true;
    in.sec_capability_epoch_known = true;
    return in;
}

// 向量 expected action -> 期望枚举集合（CR-017 控制面与向量语义的规范化映射）。
bool action_matches(KeyprovAction got, const std::string& expected) {
    switch (got) {
        case KeyprovAction::SUPERSEDE_CAS:
            return expected == "SUPERSEDE_ONCE";
        case KeyprovAction::RESTORE_SUCCESSOR:
            return expected == "RESTORE_SUCCESSOR";
        case KeyprovAction::RESTORE_ORIGINAL_ACK:
            return expected == "RESTORE_ORIGINAL_ACK";
        case KeyprovAction::FRESHEN_SAME_ID:
            return expected == "FRESHEN_SAME_ID";
        case KeyprovAction::LATE_RESPONSE:
            return expected == "LATE_RESPONSE";
        case KeyprovAction::CONFLICT_806095:
            return expected == "CONFLICT_806095";
        case KeyprovAction::RESPONSE_EXPIRED:
            return expected == "RESPONSE_EXPIRED";
        case KeyprovAction::LEASE_TOO_SHORT:
            return expected == "LEASE_TOO_SHORT";
        case KeyprovAction::TIME_UNTRUSTED:
            return expected == "TIME_UNTRUSTED";
        case KeyprovAction::CONTRACT_UNKNOWN:
            return expected == "CONTRACT_UNKNOWN";
        case KeyprovAction::REJECT:
            return expected == "REJECT";
        case KeyprovAction::IMPORT:
            return expected == "IMPORT";
        case KeyprovAction::BLOCKED:
            return expected == "BLOCKED" || expected == "BLOCKED_REMOTE_REPAIR";
        case KeyprovAction::READONLY:
        case KeyprovAction::QUERY_STATUS_OR_SEC:
            return expected == "READONLY";
        case KeyprovAction::SEND_REQUEST:
            return expected == "FRESHEN_SAME_ID";  // 仅当映射失败时占位
        default:
            return false;
    }
}

} // namespace

// ============================================================
// 向量完整性对账（镜像 hash 与 case 数量）
// ============================================================
TEST(KeyprovLifecycleVectorTest, MirrorHashAndCaseSet) {
    std::ifstream f(std::string(TSP_SOURCE_TESTS_DIR) +
                    "/fixtures/keyprov-kl1-v1/lifecycle-vectors.json");
    ASSERT_TRUE(f.good()) << "vector mirror missing";
    nlohmann::json j;
    f >> j;
    ASSERT_EQ(j["case_set"], "keyprov-lifecycle-kl1-v1");
    ASSERT_EQ(j["T0"], T0);
    ASSERT_EQ(j["cases"].size(), 57u) << "57 子例基准";
    // 参数与共享向量一致
    auto& p = j["parameters"];
    ASSERT_EQ(p["response_ttl_ms"], 60000);
    ASSERT_EQ(p["batch_ms"], 300000);
    ASSERT_EQ(p["ack_grace_ms"], 30000);
    ASSERT_EQ(p["skew_ms"], 2000);
    ASSERT_EQ(p["import_min_ms"], 15000);
    ASSERT_EQ(p["request_limit"], 8);
    ASSERT_EQ(p["request_window_ms"], 120000);
    ASSERT_EQ(p["readonly_limit"], 12);
    ASSERT_EQ(p["readonly_window_ms"], 300000);
    ASSERT_EQ(p["ack_limit"], 3);
    ASSERT_EQ(p["chain_ids"], 3);
    ASSERT_EQ(p["chain_window_ms"], 600000);
    ASSERT_EQ(p["sec_nf_observations"], 3);
    ASSERT_EQ(p["sec_nf_span_ms"], 12000);
}

// ============================================================
// 时间工具（等号语义）
// ============================================================
TEST(KeyprovLifecycleTimeTest, LeaseBoundaryEquals) {
    auto p = params();
    // E-U == import_min：允许导入（LC02.min-import 等号）
    EXPECT_TRUE(keyprov_lease_acceptable(T0, T0 + 15000, p));
    // E-U < import_min：LEASE_TOO_SHORT（LC02.-1）
    EXPECT_FALSE(keyprov_lease_acceptable(T0, T0 + 14999, p));
    // U == E：已过期（LC02.0 等号即过期）
    EXPECT_TRUE(keyprov_lease_expired(T0, T0));
    EXPECT_FALSE(keyprov_lease_expired(T0 - 1, T0));
    // D = E + ack_grace - skew
    EXPECT_EQ(keyprov_ack_safe_deadline_ms(T0, p), T0 + 30000 - 2000);
}

TEST(KeyprovLifecycleTimeTest, ClockHealthGates) {
    KeyprovClockSource c;
    c.trusted = true;
    // LC21.healthy：等号允许
    c.uncertainty_ms = 1000;
    c.sample_age_ms = 300000;
    c.skew_ms = 2000;
    EXPECT_TRUE(keyprov_clock_healthy(c));
    // LC21.uncertainty
    c.uncertainty_ms = 1001;
    EXPECT_FALSE(keyprov_clock_healthy(c));
    c.uncertainty_ms = 1000;
    // LC21.stale
    c.sample_age_ms = 300001;
    EXPECT_FALSE(keyprov_clock_healthy(c));
    c.sample_age_ms = 300000;
    // LC21.skew
    c.skew_ms = 2001;
    EXPECT_FALSE(keyprov_clock_healthy(c));
    c.skew_ms = 2000;
    // LC21.rollback
    c.rollback_detected = true;
    EXPECT_FALSE(keyprov_clock_healthy(c));
}

// ============================================================
// 决策表：LC02 系列（import 准入/租约）
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc02ImportAdmission) {
    auto p = params();

    // LC02.-1: E-U=1 < import_min -> LEASE_TOO_SHORT, import_calls=0
    {
        auto in = base_input();
        in.clock.utc_now_ms = T0 + 5999;  // U
        in.lease_expires_at_ms = T0 + 6000;  // E
        in.payload_present = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "LEASE_TOO_SHORT"));
    }
    // LC02.0: U==E -> RESPONSE_EXPIRED
    {
        auto in = base_input();
        in.clock.utc_now_ms = T0 + 6000;
        in.lease_expires_at_ms = T0 + 6000;
        in.payload_present = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "RESPONSE_EXPIRED"));
    }
    // LC02.1: U>E -> RESPONSE_EXPIRED
    {
        auto in = base_input();
        in.clock.utc_now_ms = T0 + 6001;
        in.lease_expires_at_ms = T0 + 6000;
        in.payload_present = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "RESPONSE_EXPIRED"));
    }
    // LC02.fresh: 新鲜 -> IMPORT
    {
        auto in = base_input();
        in.clock.utc_now_ms = T0;
        in.lease_expires_at_ms = T0 + 60000;
        in.payload_present = true;
        in.payload_fresh = true;
        in.response_binding_valid = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "IMPORT"));
    }
    // LC02.min-import: E-U=15000 等号 -> IMPORT
    {
        auto in = base_input();
        in.clock.utc_now_ms = T0;
        in.lease_expires_at_ms = T0 + 15000;
        in.payload_present = true;
        in.payload_fresh = true;
        in.response_binding_valid = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "IMPORT"));
    }
}

// LC06：终态 attempt 收到旧 SUCCEEDED -> LATE_RESPONSE（import=0，无后继复活）
TEST(KeyprovLifecycleDecideTest, Lc06TerminalizedLateResponse) {
    auto in = base_input();
    in.terminalized = true;
    in.lease_expires_at_ms = T0 + 60000;
    in.payload_present = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "LATE_RESPONSE"));
}

// LC08：同 rid 不同业务摘要 -> CONFLICT_806095（provider_calls=0）
TEST(KeyprovLifecycleDecideTest, Lc08IdempotencyConflict) {
    auto in = base_input();
    in.idempotency_conflict = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "CONFLICT_806095"));
}

// ============================================================
// LC09/LC10：预算账本
// ============================================================
TEST(KeyprovBudgetLedgerTest, Lc09RequestBudget) {
    auto p = params();
    KeyprovBudgetLedger b;
    // LC09.count: count=8 -> 耗尽
    for (int i = 0; i < 8; ++i) b.preconsume_request(p, T0 + i);
    EXPECT_FALSE(b.request_ok(p, T0 + 8));
    EXPECT_FALSE(b.request_ok(p, T0 + 1 + p.request_window_ms));  // 窗口后仍耗尽
    // 重启不重置（LC09.restart：count=8 elapsed=1000 仍耗尽）
    EXPECT_FALSE(b.request_ok(p, T0 + 1000));
    // LC09.time: count=0 elapsed>=120000 -> 窗口耗尽
    KeyprovBudgetLedger b2;
    b2.preconsume_request(p, T0);
    EXPECT_TRUE(b2.request_ok(p, T0 + p.request_window_ms - 1));
    EXPECT_FALSE(b2.request_ok(p, T0 + p.request_window_ms));
}

TEST(KeyprovBudgetLedgerTest, Lc10StatusAndSecBudget) {
    auto p = params();
    // STATUS 12 次耗尽
    KeyprovBudgetLedger b;
    for (int i = 0; i < 12; ++i) b.preconsume_status(p, T0 + i);
    EXPECT_FALSE(b.status_ok(p, T0 + 12));
    EXPECT_FALSE(b.status_ok(p, T0 + p.readonly_window_ms));
    // SEC 独立 12 次耗尽
    KeyprovBudgetLedger b2;
    for (int i = 0; i < 12; ++i) b2.preconsume_sec_query(p, T0 + i);
    EXPECT_FALSE(b2.sec_query_ok(p, T0 + 12));
}

TEST(KeyprovBudgetLedgerTest, Lc09AckBudgetAndD) {
    auto p = params();
    // ACK 3 次耗尽（LC09.ack-count）
    KeyprovBudgetLedger b;
    int64_t E = T0 + 60000;
    int64_t D = keyprov_ack_safe_deadline_ms(E, p);
    b.ack_safe_deadline_at_ms = D;
    b.preconsume_ack(p, T0);
    b.preconsume_ack(p, T0 + 1);
    b.preconsume_ack(p, T0 + 2);
    EXPECT_FALSE(b.ack_ok(p, T0 + 3));  // count=3
    // D 后禁新 ACK（LC09.ack-D）
    KeyprovBudgetLedger b2;
    b2.ack_safe_deadline_at_ms = D;
    EXPECT_TRUE(b2.ack_ok(p, D - 1));
    EXPECT_FALSE(b2.ack_ok(p, D));
    EXPECT_FALSE(b2.ack_ok(p, D + 1));
}

TEST(KeyprovBudgetLedgerTest, Lc22ChainBudget) {
    auto p = params();
    KeyprovBudgetLedger b;
    // 链 3 个 ID（LC22.count）
    b.preconsume_chain_id(p, T0);
    b.preconsume_chain_id(p, T0 + 100);
    b.preconsume_chain_id(p, T0 + 200);
    EXPECT_FALSE(b.chain_ok(p, T0 + 300));
    // 重启不重置（LC22.restart）
    EXPECT_FALSE(b.chain_ok(p, T0 + 301));
    // 窗口耗尽（LC22.time）
    KeyprovBudgetLedger b2;
    b2.preconsume_chain_id(p, T0);
    EXPECT_TRUE(b2.chain_ok(p, T0 + p.chain_window_ms - 1));
    EXPECT_FALSE(b2.chain_ok(p, T0 + p.chain_window_ms));
}

TEST(KeyprovLifecycleDecideTest, Lc09RequestExhaustedReadonly) {
    auto in = base_input();
    in.request_budget_ok = false;  // count=8 / elapsed>=120000（LC09.count/time/restart）
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

TEST(KeyprovLifecycleDecideTest, Lc10StatusAndSecExhaustedBlocked) {
    auto in = base_input();
    in.request_budget_ok = false;
    in.status_budget_ok = false;
    in.sec_query_budget_ok = false;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "BLOCKED"));
}

// ============================================================
// LC11/LC23：契约未知阻断
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc11ContractUnknownReconcileReadonly) {
    auto in = base_input();
    in.sec_contract_unknown = true;
    in.cloud_status = kKeyProvStatusAckPending;
    in.reconciliation_pending = true;
    // 不 import、不 supersede、不产 NOT_FOUND：只读对账
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

TEST(KeyprovLifecycleDecideTest, Lc23ContractUnknownProbe) {
    auto in = base_input();
    in.sec_contract_unknown = true;
    in.contract_ready = false;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "CONTRACT_UNKNOWN"));
}

// ============================================================
// LC12/LC13：稳定化 + 唯一后继
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc12StabilizeSupersedeOnce) {
    auto in = base_input();
    in.no_side_effect_proven = true;  // 3NF 同 epoch 跨 12s 达成
    in.cloud_status = kKeyProvStatusFailed;
    in.chain_ok = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "SUPERSEDE_ONCE"));
}

TEST(KeyprovLifecycleDecideTest, Lc12CasRestoreSuccessor) {
    auto in = base_input();
    in.no_side_effect_proven = true;
    in.cloud_status = kKeyProvStatusFailed;
    in.chain_ok = true;
    in.successor_preexisting = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "RESTORE_SUCCESSOR"));
}

TEST(KeyprovLifecycleDecideTest, Lc12UnspecifiedDoNotRetrySupersede) {
    auto in = base_input();
    in.no_side_effect_proven = true;
    in.cloud_status = kKeyProvStatusUnspecified;
    in.cloud_error.present = true;
    in.cloud_error.code = kKeyProvErrorCodeNotFound;
    in.cloud_error.retryable = false;
    in.cloud_error.action = ProtocolErrorAction::DO_NOT_RETRY;
    in.chain_ok = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "SUPERSEDE_ONCE"));
}

TEST(KeyprovLifecycleDecideTest, Lc12UnspecifiedRetryFailClosed) {
    auto in = base_input();
    in.no_side_effect_proven = true;
    in.cloud_status = kKeyProvStatusUnspecified;
    in.cloud_error.present = true;
    in.cloud_error.code = kKeyProvErrorCodeNotFound;
    in.cloud_error.retryable = false;
    // action=RETRY（不匹配 DO_NOT_RETRY）-> fail-closed 只读
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

TEST(KeyprovLifecycleDecideTest, Lc13EpochChangeResetsStabilization) {
    auto in = base_input();
    in.no_side_effect_proven = false;  // 跨 epoch 稳定化清零
    in.reconciliation_pending = true;
    in.cloud_status = kKeyProvStatusFailed;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

TEST(KeyprovLifecycleDecideTest, Lc13UnknownAndStaged) {
    for (bool unknown_or_staged : {true, false}) {
        auto in = base_input();
        in.no_side_effect_proven = false;
        in.reconciliation_pending = true;
        if (unknown_or_staged) in.sec_unknown_or_error = true;
        EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
    }
}

TEST(KeyprovLifecycleDecideTest, Lc22ChainExhaustedBlocked) {
    auto in = base_input();
    in.no_side_effect_proven = true;
    in.cloud_status = kKeyProvStatusFailed;
    in.chain_ok = false;  // 3 ID 或 600s 窗口耗尽（重启不重置）
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "BLOCKED"));
}

// ============================================================
// LC14/LC15：原 ACK 恢复 / 远程修复阻断
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc14RestoreOriginalAck) {
    auto in = base_input();
    in.sec_committed = true;
    in.cloud_status = kKeyProvStatusAckPending;
    in.ack_budget_ok = true;
    int64_t E = T0 + 60000;
    in.ack_safe_deadline_ms = keyprov_ack_safe_deadline_ms(E, params());
    in.clock.utc_now_ms = T0;  // before D
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "RESTORE_ORIGINAL_ACK"));
}

TEST(KeyprovLifecycleDecideTest, Lc14AfterDReadonly) {
    auto in = base_input();
    in.sec_committed = true;
    in.cloud_status = kKeyProvStatusAckPending;
    in.ack_budget_ok = false;  // before_D=false：D 已过
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

TEST(KeyprovLifecycleDecideTest, Lc15CommittedCloudFailedBlocked) {
    auto in = base_input();
    in.sec_committed = true;
    in.cloud_status = kKeyProvStatusFailed;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "BLOCKED_REMOTE_REPAIR"));
}

// ============================================================
// LC16：过期只读 / freshen 一次
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc16FirstFreshenSameId) {
    auto in = base_input();
    in.clock.utc_now_ms = T0 + 90000;  // 过期
    in.lease_expires_at_ms = T0 + 60000;
    in.payload_present = true;
    in.payload_fresh = true;  // 显式传输判定不设 false；数值判定过期
    in.freshen_used = false;
    in.cloud_status = kKeyProvStatusAckPending;
    in.no_side_effect_proven = true;
    in.deliverable = true;
    in.request_budget_ok = true;
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "FRESHEN_SAME_ID"));
}

TEST(KeyprovLifecycleDecideTest, Lc16SecondExpiredReadonly) {
    auto in = base_input();
    in.clock.utc_now_ms = T0 + 90000;
    in.lease_expires_at_ms = T0 + 60000;
    in.payload_present = true;
    in.freshen_used = true;  // 第二次过期
    EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "READONLY"));
}

// ============================================================
// LC17：传输层双准入
// ============================================================
TEST(KeyprovLifecycleDecideTest, Lc17TransportAdmission) {
    for (bool env_fresh : {false, true}) {
        for (bool payload_fresh : {false, true}) {
            auto in = base_input();
            in.payload_present = true;
            in.envelope_fresh = env_fresh;
            in.payload_fresh = payload_fresh;
            in.response_binding_valid = true;  // 双新鲜时允许导入（LC02.fresh 前提）
            if (env_fresh && payload_fresh) {
                in.lease_expires_at_ms = T0 + 60000;  // 有效租约 E
                EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "IMPORT"))
                    << "双新鲜应可导入";
            } else {
                EXPECT_TRUE(action_matches(keyprov_lifecycle_decide(in), "REJECT"))
                    << "env=" << env_fresh << " payload=" << payload_fresh;
            }
        }
    }
}

// ============================================================
// 尾部默认：首次申请 / ACTIVE
// ============================================================
TEST(KeyprovLifecycleDecideTest, DefaultSendRequestWhenNoPayload) {
    auto in = base_input();
    in.payload_present = false;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::SEND_REQUEST);
}

TEST(KeyprovLifecycleDecideTest, DefaultActiveWhenPurposesComplete) {
    auto in = base_input();
    in.purposes_complete = true;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::ACTIVE);
}

TEST(KeyprovLifecycleDecideTest, P9BoundedRetry) {
    auto in = base_input();
    in.transport_retryable_fault = true;
    in.request_budget_ok = true;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::BOUNDED_RETRY);
}

TEST(KeyprovLifecycleDecideTest, P1TimeUntrusted) {
    auto in = base_input();
    in.clock.trusted = false;
    in.clock.uncertainty_ms = 1001;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::TIME_UNTRUSTED);
}

TEST(KeyprovLifecycleDecideTest, P2ActiveWhenCloudActiveCommitted) {
    auto in = base_input();
    in.cloud_status = kKeyProvStatusActive;
    in.sec_committed = true;
    in.purposes_complete = true;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::ACTIVE);
}

TEST(KeyprovLifecycleDecideTest, P3ActiveCloudNotFoundHardConflict) {
    auto in = base_input();
    in.cloud_status = kKeyProvStatusActive;
    in.sec_not_found_proven = true;
    EXPECT_EQ(keyprov_lifecycle_decide(in), KeyprovAction::BLOCKED);
}
