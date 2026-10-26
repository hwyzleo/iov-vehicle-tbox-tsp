// TBOX-TSP-DSN-CR-017 §1/§2/§6：集中生命周期决策（纯函数）+ 持久预算账本 + 时间工具。
//
// - keyprov_lifecycle_decide：优先级 0..9 集中决策表。输入为已冻结 attempt 的全部
//   事实（attempt/时间/契约/SEC 证据/cloud 状态/预算/链/绑定/inflight），输出唯一
//   决策动作。无副作用；副作用由 Coordinator（单执行器）在锁内重核 generation/CAS
//   后执行。
// - KeyprovBudgetLedger：持久预算账本（Request 8/120s、Status 12/300s、SEC 12/300s、
//   ACK 3 + D、freshen 1、链 3/600s）。计数与绝对截止均为可信 UTC；重启/重连/epoch
//   flap 不重置；时钟不可信/回拨不得重置为 0。发送前预占，拒绝/崩溃不退还。
// - 时间工具：U=E 比较、E-U>=import_min 准入、D=E+ack_grace-skew。
//
// 参数默认值与共享向量 keyprov-lifecycle-kl1-v1 一致（PAR-PROTO-DSN-CR-010）。
// 本模块为纯函数，不依赖真实时钟；时间由调用方传入（Coordinator 注入的时钟源）。

#pragma once

#include "keyprov_attempt.h"  // CloudProtocolError / CloudStatusDecisionInput

#include <cstdint>
#include <string>

namespace tbox {
namespace tsp {

// ============================================================
// KL1 参数（默认值与共享向量 manifest 一致；Coordinator 可按配置覆盖）
// ============================================================
struct KeyprovKl1Params {
    uint32_t response_ttl_ms = 60000;      // E 签发 TTL（VMD 侧；TSP 消费）
    uint32_t batch_ms = 300000;            // B=F+300s（VMD 侧；TSP 消费）
    uint32_t ack_grace_ms = 30000;         // D = E + ack_grace - skew
    uint32_t skew_ms = 2000;               // 跨端允许偏差（D 安全余量）
    uint32_t issue_min_ms = 20000;         // VMD 侧 E 余量（TSP 消费）
    uint32_t import_min_ms = 15000;        // 导入前 E-U 最小余量
    uint32_t request_limit = 8;            // 每 requestId 应用层 Request 上限
    uint32_t request_window_ms = 120000;   // 首次发送后窗口
    uint32_t readonly_limit = 12;          // StatusRequest 上限
    uint32_t readonly_window_ms = 300000;  // 首次进入只读后窗口
    uint32_t ack_limit = 3;                // ACK 应用投递上限
    uint32_t chain_ids = 3;                // 恢复链最多 requestId 数
    uint32_t chain_window_ms = 600000;     // 恢复链窗口
    uint32_t sec_nf_observations = 3;      // 稳定化连续强 NOT_FOUND 数
    uint32_t sec_nf_span_ms = 12000;       // 稳定化时间跨度（import 10s + grace 2s）
};

// ============================================================
// 时钟源（生产默认连接既有可信时间源；测试注入固定 UTC/monotonic/信任状态。
// fake clock 仅限测试装配，不得形成生产可配置的时间绕过开关）。
// ============================================================
struct KeyprovClockSource {
    // 可信 UTC 上界 U = utc_now + uncertainty（由调用方组合）。
    int64_t utc_now_ms = 0;         // 本端可信 UTC sample
    uint32_t uncertainty_ms = 0;    // sample 不确定度（<=1000ms 才健康）
    int64_t monotonic_ms = 0;       // 本端单调时钟（同进程相对计时）
    uint32_t sample_age_ms = 0;     // sample freshness（<=300000ms 才健康）
    uint32_t skew_ms = 0;           // 车云允许偏差（<=2000ms 才健康；等号允许）
    bool rollback_detected = false; // 回拨检测（检测到即不可信）
    bool trusted = false;           // 时间健康/信任状态（由 healthy() 或外部门禁设置）
};

// KL-REQ-001 时间健康门禁（等号允许）：uncertainty<=1000、freshness<=300000、
// skew<=2000、无回拨。超限/不可信禁止新签发/新导入；只读恢复仍须鉴权。
// 2000ms 是时间健康门禁，不是过期后的宽限。
bool keyprov_clock_healthy(const KeyprovClockSource& c);

// ============================================================
// 集中决策输出（CR-017 §1 主相位 + 向量断言细化动作）
// ============================================================
enum class KeyprovAction : uint8_t {
    // 主相位（CR-017 §1：仅一个动作；副作用由 Coordinator 执行）
    WAIT_READY = 0,          // 等待 readiness/时间健康
    SEND_REQUEST = 1,        // 发送新的应用层 Request（含 freshen）
    IMPORT = 2,              // 调用 SEC import（一次）
    SEND_ORIGINAL_ACK = 3,   // 恢复原 proof 并发送 ACK
    QUERY_STATUS_OR_SEC = 4, // 只读对账（Status/SEC）
    SUPERSEDE_CAS = 5,       // CAS 终态化旧 attempt + 唯一后继
    ACTIVE = 6,              // 两用途 ACTIVE（幂等）
    BLOCKED = 7,             // 可解释阻断（含原因）
    // 细化决策（LC 向量断言用；控制相位由上方聚合）
    LATE_RESPONSE = 8,       // 错绑定/旧 rid/终态 generation Response（丢弃）
    CONFLICT_806095 = 9,     // 同 rid 不同业务摘要（幂等冲突对账）
    FRESHEN_SAME_ID = 10,    // 一次同 rid freshen
    RESTORE_ORIGINAL_ACK = 11, // 恢复原 ACK（SEC COMMITTED + cloud ACK_PENDING）
    RESTORE_SUCCESSOR = 12,  // 已存在唯一后继：只恢复不新生成
    RESPONSE_EXPIRED = 13,   // U>=E：过期（不导入、不换 ID）
    LEASE_TOO_SHORT = 14,    // E-U<import_min：转只读对账
    REJECT = 15,             // 传输层 TTL/payload 准入拒绝
    TIME_UNTRUSTED = 16,     // 时钟不可信：不导入不新 ID
    CONTRACT_UNKNOWN = 17,   // 契约快照缺失/不一致：阻断
    READONLY = 18,           // 只读对账（不回通用 RETRY_WAIT）
    BOUNDED_RETRY = 19       // 可恢复传输故障：有界退避
};

const char* keyprov_action_to_string(KeyprovAction a);

// ============================================================
// 生命周期决策输入（已冻结 attempt 的事实快照；无密钥材料）
// ============================================================
struct KeyprovLifecycleInput {
    // ---- 绑定/attempt ----
    bool attempt_valid = false;        // 有当前 attempt（requestId 非空）
    bool binding_match = true;         // rid/generation/fingerprint 绑定匹配（false=迟到/错配）
    bool terminalized = false;         // 本 attempt 已终态化（不得复活）
    // ---- 时间 ----
    KeyprovClockSource clock;
    int64_t lease_expires_at_ms = 0;   // E（Response field4）
    int64_t ack_safe_deadline_ms = 0;  // D（= E + ack_grace - skew）
    bool freshen_used = false;         // 本次 attempt 已使用过期同 rid freshen
    bool deliverable = false;          // 租约可交付前提（ACK_PENDING 且身份/证书/代际一致；
                                       // 是否真可交付由 VMD 在收到一次 freshen 时权威判定）
    bool import_already = false;       // 已调用 SEC import（不得重复导入）
    bool idempotency_conflict = false; // 同 rid 但业务摘要不同（806095 -> 对账）
    bool successor_preexisting = false;// 唯一后继已持久化（崩溃恢复：只恢复不新生成）
    bool transport_retryable_fault = false; // 可恢复传输故障（publish 拒绝 retryable/超时）
    bool reconciliation_pending = false; // 处于恢复/稳定化/对账阶段（不得盲发 Request）
    // ---- 契约/readiness ----
    bool contract_ready = false;       // KL1 契约快照一致 + supports_lease_admission
    bool sec_capability_epoch_known = false;  // SEC epoch 已知且与 probe 一致
    // ---- SEC 证据 ----
    bool sec_committed = false;        // SEC COMMITTED（原 requestId 双用途原子提交）
    bool sec_not_found_proven = false; // 强 NOT_FOUND（同 epoch 连续 N 次跨 span）
    bool sec_unknown_or_error = false; // UNKNOWN/QUERY_ERROR/STAGED/FAILED（fail-closed）
    bool sec_contract_unknown = false; // ContractUnknown（capability=0/result=2 不一致）
    bool no_side_effect_proven = false;// resolution=NO_SIDE_EFFECT_PROVEN 且无反证
    // ---- cloud ----
    int cloud_status = -1;             // KEY_PROVISIONING_STATUS_*（-1=未观测）
    CloudProtocolError cloud_error;    // 规范化错误四元组（806099 释放判定）
    // ---- 预算/链 ----
    const KeyprovKl1Params* params = nullptr;  // 参数（nullptr 时用默认值）
    // 预算账本由 Coordinator 持有一份可变实例；决策表只读查询，由 Coordinator 预占。
    bool request_budget_ok = true;     // Request 预算允许
    bool status_budget_ok = true;      // Status 预算允许
    bool sec_query_budget_ok = true;   // SEC 查询预算允许
    bool ack_budget_ok = true;         // ACK 预算允许（count<limit 且 now<D）
    bool chain_ok = true;              // 恢复链预算允许（count<limit 且窗口内）
    // ---- inflight / 绑定 ----
    bool inflight = false;             // 有在途 Request/ACK/Status（不得新开）
    bool response_binding_valid = false; // 当前 Response 绑定校验通过
    bool purposes_complete = false;    // 两用途均已 ACTIVE（do_check 事实）
    // ---- 响应新鲜度（传输层） ----
    bool envelope_fresh = true;        // Envelope TTL 未过期
    bool payload_fresh = true;         // Response payload（field4 E）未过期
    bool payload_present = false;      // 是否收到可判定的 Response bundle（false=无响应）
};

// ============================================================
// 优先级 0..9 集中决策表（纯函数；无副作用）
// ============================================================
// 规则优先级（CR-017 §1 表）：
//   0 错绑定/旧rid/终态generation Response -> LATE_RESPONSE（精确 COMMITTED 反证单独保留对账）
//   1 时钟不可信/契约不ready/SEC未知/残留 -> 不import不新ID；预算内只读，耗尽 BLOCKED
//   2 cloud ACTIVE + 同rid SEC COMMITTED + 双用途一致 -> ACTIVE
//   3 cloud FAILED+SEC COMMITTED / ACTIVE+SEC NF -> 冲突治理（BLOCKED）
//   4 SEC COMMITTED + cloud ACK_PENDING -> 仅恢复原proof/ACK；D与ACK预算允许才发送
//   5 cloud terminal/releasable + proven -> CAS唯一后继；链耗尽 BLOCKED
//   6 expired/too-short + ACK_PENDING + proven + 租约可交付 + freshen=0 -> 一次同rid freshen
//   7 expired/第二次expired/EXPIRED/noitems -> 只读（不回通用 RETRY_WAIT）
//   8 新鲜响应 + 全部绑定/契约/epoch/预算通过 + 无inflight -> import一次
//   9 可恢复传输故障且Request预算未尽 -> 有界退避；其余只读/阻断
KeyprovAction keyprov_lifecycle_decide(const KeyprovLifecycleInput& in);

// ============================================================
// 时间工具（等号语义：U==E 即过期；E-U==import_min 允许导入）
// ============================================================
int64_t keyprov_ack_safe_deadline_ms(int64_t lease_expires_at_ms,
                                     const KeyprovKl1Params& p);
// 传输层/租约准入：E-U >= import_min（等号允许）。
bool keyprov_lease_acceptable(int64_t utc_upper_ms,
                              int64_t lease_expires_at_ms,
                              const KeyprovKl1Params& p);
// U>=E：已过期（等号即过期）。
bool keyprov_lease_expired(int64_t utc_upper_ms, int64_t lease_expires_at_ms);

// ============================================================
// 持久预算账本（先预占后执行；重启不重置；时钟不可信不归零）
// ============================================================
struct KeyprovBudgetLedger {
    // Request 预算（每 requestId；含首次与 freshen；8 次或首次发送后 120s 先到者）
    uint32_t request_send_count = 0;
    int64_t first_request_at_ms = 0;      // UTC 绝对
    int64_t request_deadline_at_ms = 0;   // = first + window（UTC 绝对）
    // StatusRequest 预算（12 或首次只读后 300s）
    uint32_t status_send_count = 0;
    int64_t first_readonly_at_ms = 0;
    int64_t readonly_deadline_at_ms = 0;
    // SEC 查询预算（独立 12/300s；含稳定化查询）
    uint32_t sec_query_count = 0;
    // ACK 应用投递预算（3 且未到 D）
    uint32_t ack_send_count = 0;
    int64_t ack_safe_deadline_at_ms = 0;  // D（UTC 绝对）
    // 过期同 rid freshen（至多 1 次，计入 Request 总预算）
    uint32_t expiry_freshen_count = 0;
    // 恢复链（最多 3 个 requestId，总 600s；跨重启持久）
    std::string chain_id;
    int64_t chain_started_at_ms = 0;      // UTC 绝对
    int64_t chain_deadline_at_ms = 0;
    uint32_t chain_request_id_count = 0;
    // 迁移门禁（v4->v5：迁移 token 只发放一次）
    std::string migration_token;
    bool migration_consumed = false;
    // 阻断原因（受控枚举/诊断）
    std::string budget_exhausted_reason;

    // ---- 查询（纯函数；now 为可信 UTC） ----
    bool request_ok(const KeyprovKl1Params& p, int64_t now_utc_ms) const;
    bool status_ok(const KeyprovKl1Params& p, int64_t now_utc_ms) const;
    bool sec_query_ok(const KeyprovKl1Params& p, int64_t now_utc_ms) const;
    bool ack_ok(const KeyprovKl1Params& p, int64_t now_utc_ms) const;   // count<limit 且 now<D
    bool freshen_ok() const;                     // count<1
    bool chain_ok(const KeyprovKl1Params& p, int64_t now_utc_ms) const; // count<limit 且窗口内

    // ---- 预占（发送前调用；拒绝/崩溃不退还） ----
    void preconsume_request(const KeyprovKl1Params& p, int64_t now_utc_ms);
    void preconsume_status(const KeyprovKl1Params& p, int64_t now_utc_ms);
    void preconsume_sec_query(const KeyprovKl1Params& p, int64_t now_utc_ms);
    void preconsume_ack(const KeyprovKl1Params& p, int64_t now_utc_ms);
    void preconsume_freshen();
    void preconsume_chain_id(const KeyprovKl1Params& p, int64_t now_utc_ms);

    // ---- 重置边界：仅在新 attempt/受控运维动作时由 Coordinator 显式调用 ----
    // 绝不因重连/重启/epoch flap/时钟回拨自动调用。
    void reset_for_new_attempt();
};

} // namespace tsp
} // namespace tbox
