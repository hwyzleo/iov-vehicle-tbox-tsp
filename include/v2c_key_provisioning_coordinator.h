// TBOX-TSP-DSN-CR-010 §3.1: V2cKeyProvisioningCoordinator。
//
// 在 TspRelayService 内聚：消费 MQTT Cloud/Capability Readiness，查询 SEC 件内状态，
// 创建/恢复稳定 requestId，经 keyprov.uplink 发起申请，接收 Wrapped Key bundle，
// 调用 SEC 原子导入并幂等回传 ACK，持久化非敏感状态。
//
// 安全边界（CR §7 / SEC CR-019）：TSP 不解析/打印/持久化 Wrapped Key 内容；
// wrapped_key/parameters 只在有界 SecureBuffer 中短暂存在并立即交给 SEC。
//
// 门禁（CR §8，采用 (c)：MQTT capability ready 已足够，不设独立云端能力条件）：
//   KEYPROV_READY = enabled
//     AND codec/SEC API 可用（编译期）
//     AND SEC 业务密钥能力可用（运行时由 SEC 返回码判定）
//     AND MQTT capability ready（含 contract/snapshot/uplink/downlink SUBACK/cloud session）
//     AND 当前证书身份摘要可见
// 任一不满足不得发送 Request、不得置 ACTIVE，且不阻塞共享 Cloud Ready。

#pragma once

#include "keyprov_protocol.h"
#include "keyprov_readiness.h"
#include "mqtt_facade.h"
#include "sec_business_key_facade.h"
#include "v2c_key_provisioning_store.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tbox {
namespace tsp {

struct V2cKeyProvisioningConfig {
    bool enabled = false;                 // production default false（release-set 显式开启）
    std::string business_domain = "V2C_COMM";
    std::vector<std::string> purposes = {"UPLINK_AEAD", "DOWNLINK_AEAD"};
    std::string route_up = "keyprov.uplink";
    std::string route_down = "keyprov.downlink";
    std::string certificate_profile = "mqtt";
    uint32_t request_timeout_ms = 10000;
    uint32_t ack_timeout_ms = 10000;
    uint32_t max_attempts_before_alert = 8;
    uint32_t retry_initial_ms = 500;
    uint32_t retry_max_ms = 30000;
    double retry_multiplier = 2.0;
    bool retry_jitter = true;
    uint32_t poll_interval_ms = 200;      // worker tick
    // ---- TBOX-TSP-DSN-CR-015 §22.4/§22.5：SEC NOT_FOUND 稳定化与 Status 退避 ----
    // 稳定窗 = sec_import_timeout_ms + sec_callback_grace_ms（独立配置，有界）；
    // 若 not_found_stabilization_window_ms>0 则显式覆盖（必须 >= 该下界，见校验）。
    uint32_t not_found_stabilization_count = 3;      // N（有界，1..8）
    uint32_t sec_import_timeout_ms = 5000;           // SEC import IPC 调用 deadline（有界）
    uint32_t sec_callback_grace_ms = 1000;           // 迟到回调宽限（有界）
    uint32_t not_found_stabilization_window_ms = 0;  // 0 → 自动 = import_timeout+callback_grace
    uint32_t status_request_initial_interval_ms = 1000;  // StatusRequest 退避起始（有界）
    uint32_t status_request_max_interval_ms = 30000;     // StatusRequest 退避上限（有界）
};

enum class V2cKeyProvState : uint8_t {
    DISABLED = 0,
    WAIT_CLOUD = 1,
    CHECKING = 2,
    REQUESTING = 3,
    WAIT_RESPONSE = 4,
    IMPORTING = 5,
    ACK_PENDING = 6,
    ACTIVE = 7,
    RETRY_WAIT = 8,
    BLOCKED = 9,
    // ---- TBOX-TSP-DSN-CR-013：不可变 attempt 与 requestId 幂等 ----------------
    RECONCILE_OLD_ATTEMPT = 10,              // 业务输入变化/806095：先对账 VMD Status + SEC journal
    SUPERSEDED_LOCAL = 11,                   // 可证明从未提交且 VMD 无批次：旧 record 终态化，建新 attempt
    SUPERSEDED_REMOTE = 12,                  // VMD 已终结旧批次且 SEC 无副作用：终态化，建新 attempt
    BLOCKED_AWAIT_CLOUD_TERMINATION = 13,    // VMD 有未终结旧批次/无法证明：等待受控终结
    LEGACY_SNAPSHOT_UNKNOWN = 14,            // 旧 Store 无 snapshot/fingerprint：默认阻断，先对账
    // ---- TBOX-TSP-DSN-CR-015 §22.4：证据收敛与恢复（显式追加，不重排既有值） ----
    RECONCILE_EVIDENCE = 15,                 // EVIDENCE_CONFLICT 恢复点/稳定化入口（v3 映射）
    STABILIZING_NOT_FOUND = 16,              // 强 NOT_FOUND 连续计数中（同能力代际）
    RECONCILE_REMOTE = 17,                   // resolution=NO_SIDE_EFFECT_PROVEN：完整云端矩阵
    AWAIT_REMOTE_REPAIR = 18,                // VMD ACTIVE/SUCCEEDED：不重开，等待云端终结/治理
    HARD_BLOCKED = 19                        // 矛盾证据（HARD_CONFLICT）：仅诊断查询，人工治理
};

const char* v2c_key_prov_state_to_string(V2cKeyProvState s);
bool v2c_key_prov_state_from_string(const std::string& s, V2cKeyProvState& out);

struct V2cKeyProvisioningSnapshot {
    V2cKeyProvState state = V2cKeyProvState::DISABLED;
    std::string request_id;
    bool capability_ready = false;
    bool identity_valid = false;            // CR-011 §18.3: 当前是否有有效会话身份
    bool publish_session_supported = false; // CR-011 §18.3: MQTT 支持 session-bound publish
    std::string reason_code;
    uint32_t attempt_count = 0;
    std::string last_error;
    uint64_t cloud_session_generation = 0;
    bool sec_api_available = false;
    bool clock_synced = false;               // 系统时钟是否已同步（时间敏感请求门禁）
    // CR-012 §8：9 项协议/SEC 前置门禁快照（脱敏，不含 proof/密钥）
    KeyprovReadiness readiness;
    // CR-013 可观测字段（有限枚举；无敏感值）
    std::string blocked_reason;          // keyprov_blocked_reason::*
    uint32_t fingerprint_version = 0;    // 0=legacy/未冻结
    bool legacy_snapshot_unknown = false;
    uint64_t blocked_attempts_current = 0;  // 当前是否处于阻断态（0/1）
    std::string conflict_vmd_code;       // 脱敏冲突 VMD code（如 806095，空=无）
    // ---- CR-014 可观测字段（有限枚举，脱敏） ----
    std::string sec_evidence_kind;       // SecImportEvidenceKind 名
    bool import_invocation_recorded = false;  // 已调用 SEC import API
    // ---- CR-015 可观测字段（有限枚举，脱敏） ----
    std::string import_invocation_resolution;  // UNRESOLVED/NO_SIDE_EFFECT_PROVEN/HARD_CONFLICT
    std::string recovery_phase;           // keyprov_recovery_phase::*（诊断）
    uint32_t sec_not_found_count = 0;    // 当前连续强 NOT_FOUND 计数
    uint64_t sec_capability_epoch = 0;   // 当前 SEC capability epoch（摘要值，仅诊断）
    bool sec_epoch_unknown = false;      // SEC capability epoch 未知（需重新查询）
    std::string successor_request_id_digest;  // 唯一后继 requestId 摘要（hex，审计）
    // 脱敏计数器
    uint64_t cloud_ready_events = 0;
    uint64_t requests_published = 0;
    uint64_t responses_received = 0;
    uint64_t responses_rejected = 0;
    uint64_t imports_committed = 0;
    uint64_t imports_failed = 0;
    uint64_t imports_unknown = 0;
    uint64_t acks_sent = 0;
    uint64_t ack_results_received = 0;
    uint64_t active_transitions = 0;
    uint64_t status_requests_sent = 0;
    // ---- CR-013 指标（有限枚举，不以 requestId/VIN/UID/证书摘要/fingerprint 为维度） ----
    uint64_t attempts_created = 0;
    uint64_t superseded_local = 0;
    uint64_t superseded_remote = 0;
    uint64_t idempotency_conflicts_total = 0;
    uint64_t blocked_attempts_total = 0;
    uint64_t legacy_store_records = 0;
    std::map<std::string, uint64_t> fingerprint_changes_total;   // AttemptChangeDimension 名
    std::map<std::string, uint64_t> blocked_reasons_total;       // keyprov_blocked_reason::*
    std::map<std::string, uint64_t> attempt_transitions_total;   // "FROM->TO"
    // ---- CR-015 指标（有限枚举；result/reason 受控） ----
    std::map<std::string, uint64_t> sec_not_found_stabilization_total;  // result：REACHED/RESET_*
    std::map<std::string, uint64_t> hard_conflicts_total;               // reason：keyprov_blocked_reason::*
};

class V2cKeyProvisioningCoordinator {
public:
    V2cKeyProvisioningCoordinator(std::shared_ptr<MqttFacade> mqtt,
                                  std::shared_ptr<SecBusinessKeyFacade> sec,
                                  std::shared_ptr<V2cKeyProvisioningStore> store);
    ~V2cKeyProvisioningCoordinator();

    V2cKeyProvisioningCoordinator(const V2cKeyProvisioningCoordinator&) = delete;
    V2cKeyProvisioningCoordinator& operator=(const V2cKeyProvisioningCoordinator&) = delete;

    // 恢复 Store 非敏感状态、订阅 readiness 事件（start 时）。
    bool initialize(const V2cKeyProvisioningConfig& config);

    // 订阅 Cloud/Capability readiness 事件并启动 worker（stop 前一直有效）。
    // start_monitor=false 时不启后台线程，供测试通过 tick() 驱动。
    bool start(bool start_monitor = true);

    // 进入 STOPPING：拒绝新申请与 callback。
    void beginShutdown();

    // 停止：join worker、清零临时 Wrapped Key 缓冲（内存态）。
    void stop();

    // 下行入口（TspRelayService 在 DownlinkRouteDispatcher 注册 owner=tsp +
    // route_id=keyprov.downlink + target=tsp.keyprov）。
    void handle_routed_downlink(const RoutedDownlinkEvent& event);

    // 单次状态推进（生产由 worker 调用；测试直接调用）。
    void tick();

    V2cKeyProvisioningSnapshot snapshot() const;

    // 注入时钟同步判定（默认读 systemd-timesyncd 同步标记；测试可覆盖）。
    // keyprov Request 携带绝对 expire_at_ms，冷启动早期时钟未同步时必须等待，
    // 否则发送即被云端按过期拒绝（见 /run/systemd/timesync/synchronized）。
    void set_clock_sync_check(std::function<bool()> check);

private:
    // ---- readiness 回调（MQTT SDK 执行器线程） ----
    void on_cloud_readiness(const CloudReadiness& readiness);
    void on_capability_readiness(const CapabilityReadiness& readiness);

    // 需持有 mutex_ 的状态推进
    void tick_locked();
    void do_check_locked();
    void do_request_locked();
    void do_import_locked();
    void handle_import_result_locked(tbox::sec::ErrorCode ec,
                                     const tbox::sec::ImportResult& result);
    void do_ack_locked();
    void on_response_timeout_locked();
    void schedule_retry_locked();
    void persist_locked();
    void worker_loop();
    void reset_to_checking_locked();

    // ---- CR-013：不可变 attempt / fingerprint / 对账 ----------------
    // 从当前输入构造 candidate snapshot + fingerprint（SEC 版本/身份/capability 同代际）。
    bool build_candidate_locked(KeyprovAttemptSnapshot& cand,
                                KeyprovFingerprint& fp,
                                std::string& err);
    // 创建新 attempt：生成 requestId/idempotency、冻结 snapshot+fingerprint、
    // 原子持久化后再允许发送。
    void create_new_attempt_locked();
    // 冻结当前输入为新 attempt（首次创建），供 create_new_attempt 复用。
    void freeze_current_input_locked();
    // 进入对账：停止原 Request 自动重试，记录脱敏冲突事实。
    void enter_reconcile_old_attempt_locked(const char* reason,
                                            const char* vmd_code);
    void do_reconcile_locked();
    // 处理 RECONCILE/LEGACY/待终结态收到的 StatusResponse 对账结果。
    void handle_reconcile_status_locked(const KeyProvStatusResponseData& status);
    // 是否有 accepted/PUBACK/timeout/崩溃等"可能已提交"证据。
    bool submission_evidence_locked() const;
    // SEC journal 对账：COMMITTED -> 恢复 ACK；UNKNOWN -> 保持对账（禁止新 attempt）
    // 但继续 VMD StatusRequest 只读对账；强 NOT_FOUND -> 稳定化计数；
    // 返回 ReconcileAction 决定调用方后续动作（CR-015 §22.5 替代旧 bool consumed）。
    ReconcileAction reconcile_sec_journal_locked();
    // 以原 requestId 发送 StatusRequest（对账/待终结观察）。
    void send_status_request_locked();
    // 记录幂等冲突脱敏事实并计数。
    void record_conflict_facts_locked(const char* vmd_code);
    // 状态迁移 + 计数（指标，仅可观测性）。
    void transition_to_locked(V2cKeyProvState next);
    void count_blocked_reason_locked(const char* reason);
    // 标记提交证据（persist 前调用）。
    void mark_submitted_locked();
    void mark_confirmed_locked();
    void bump_store_generation_locked();
    // CR-014 §21.5：对账保持路径的四元组抑制（相同则跳过写盘/计数，返回 true）。
    // CR-016 §23.6：抑制键扩展 error_tuple（code/action），缺省适配 SEC 阶段。
    bool reconcile_obs_suppressed_locked(int vmd_status,
                                         SecImportEvidenceKind kind,
                                         int error_code = 0,
                                         int error_action = -1);
    // ---- CR-015 §22.5：SEC NOT_FOUND 稳定化辅助 ----
    // 当前 resolution 是否已证明无副作用（NO_SIDE_EFFECT_PROVEN 且无相反本地证据）。
    bool no_side_effects_proven_locked() const;
    // 同一规范化 requestId / CAS generation 匹配（迟到/错配证据直接丢弃）。
    bool same_attempt_locked(const SecImportEvidence& ev) const;
    bool cas_generation_matches_locked(const SecImportEvidence& ev) const;
    // TSP 已知相反证据（staging/partial、ACK proof、已提交导入结果等）。
    bool contrary_local_evidence_locked() const;
    // 稳定化窗口（ms）：显式配置 > 0 用之；否则 = sec_import_timeout + callback_grace。
    uint32_t stabilization_window_ms_locked() const;
    // 清零稳定化计数/时间窗并记录 outcome 指标（result：REACHED/RESET_*）。
    void reset_not_found_stabilization_locked(const char* result);
    // SEC capability epoch 变化：为新 epoch 重启计数（保留已观测分类）。
    void restart_not_found_stabilization_for_locked(const SecImportEvidence& ev);
    // 记录一次强 NOT_FOUND 观测（同 epoch/attempt 才计数）。
    void observe_not_found_locked(const SecImportEvidence& ev);
    // 达成 N + 稳定窗：处置为 NO_SIDE_EFFECT_PROVEN 并进入 RECONCILE_REMOTE。
    void prove_no_side_effects_locked();
    // 矛盾证据（proven 后出现非 NOT_FOUND / 迟到 callback）：HARD_CONFLICT。
    void enter_hard_blocked_locked(const char* reason);
    // 进入证据对账（稳定化入口；旧 EVIDENCE_CONFLICT 恢复点）。
    void enter_reconcile_evidence_locked(const char* reason);
    // 完整云端决策矩阵（resolution proven 后执行；input 为最近观测 VMD
    // status + 规范化 ProtocolError）。
    void apply_cloud_matrix_locked(const CloudStatusDecisionInput& in);
    // CR-016 §4.2/§23.2：UNSPECIFIED + 806099/false/DO_NOT_RETRY 严格子集判定。
    bool is_releasable_unspecified_locked(
        const CloudStatusDecisionInput& in) const;
    // CR-016 §6.3/§23.5：终态化旧 attempt 并创建唯一 successor（幂等恢复：
    // 已存在 successor 时只恢复，不重复生成）。
    void supersede_remote_once_locked();
    // StatusRequest 专用退避（1s、2s、4s…max，有界+抖动）。
    void schedule_status_retry_locked();
    // 更新 SEC capability epoch（TSP 本地生成：查询失败→成功、契约版本变化、
    // NOT_FOUND 能力位变化时递增；CR-015 §22.4/§10）。
    void update_sec_capability_epoch_locked(
        tbox::sec::ErrorCode ec, const tbox::sec::V2cKeyProvisioningCapability& cap);

    bool capability_gate_locked(std::string& reason);
    // 系统时钟是否已同步（未注入时读 systemd-timesyncd 标记）。
    bool clock_check_ok() const;
    // CR-011 §5.1/§18.3: 失效缓存身份与未发送传输任务（保留业务 requestId）。
    void invalidate_identity_locked(const char* reason);
    // CR-011 §5.1: 对账并接受 readhip 快照（epoch/sequence/generation 变化处理）。
    void apply_cloud_readiness_locked(const CloudReadiness& readiness);
    void apply_capability_readiness_locked(const CapabilityReadiness& readiness);
    // 主动重查 MQTT 当前快照（构造后切换/STALE 后对账）。
    void refresh_readiness_locked();
    // CR-011 §5.2: 携 expected_session 发布；按 reason 分流，成功返回 true。
    bool publish_keyprov_locked(const std::string& message_id,
                                const std::vector<uint8_t>& envelope_bytes,
                                const std::string& request_id);
    bool keyprov_response_valid_locked(const KeyProvResponseData& resp,
                                       std::string& err) const;
    // CR-012 §8：查询并合并 build-lock + SEC capability，结果缓存在 readiness_。
    void refresh_sec_readiness_locked();
    // CR-012 §5/§6：校验 SEC 导入结果与原 Response 绑定，且具备完整 Import Attestation。
    bool import_result_bindable_locked(const tbox::sec::ImportResult& result,
                                       std::string& err) const;
    uint32_t current_backoff_ms_locked() const;
    bool purposes_complete_locked(const std::vector<tbox::sec::BusinessKeyStatus>& items) const;

    static int64_t now_ms();
    static int64_t now_monotonic_ms();
    static std::string generate_id(const char* prefix);

    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SecBusinessKeyFacade> sec_;
    std::shared_ptr<V2cKeyProvisioningStore> store_;
    V2cKeyProvisioningConfig config_;

    mutable std::mutex mutex_;
    V2cKeyProvState state_ = V2cKeyProvState::DISABLED;
    V2cKeyProvisioningRecord record_;

    // readiness 缓存
    CloudReadiness cloud_;
    CapabilityReadiness capability_;
    KeyprovSessionIdentity identity_;   // 门禁通过后由同一快照生成的不可变身份
    bool identity_valid_ = false;
    bool publish_session_supported_ = false;
    uint64_t last_cloud_sequence_ = 0;  // 同一 daemon epoch 内事件序列对账
    bool capability_ready_ = false;
    bool clock_synced_ = false;
    std::function<bool()> clock_sync_check_;
    std::string gate_reason_;

    // ---- CR-013 attempt 冻结状态 ----
    KeyprovAttemptSnapshot frozen_snapshot_;
    KeyprovFingerprint frozen_fingerprint_{};
    uint32_t fingerprint_version_ = 0;
    std::string submission_ = keyprov_submission::kNone;
    std::string supersedes_request_id_;
    std::string superseded_by_request_id_;
    std::string blocked_reason_;
    uint64_t store_generation_ = 0;
    bool legacy_snapshot_unknown_ = false;
    // CR-013 §9：SEC journal 是否仍处于 outcome unknown（true 时禁止建新 attempt）。
    bool sec_outcome_unknown_ = false;
    // CR-015：导入意图处置（替代 CR-014 的 sec_no_side_effects_proven_ 布尔）。
    // import_invocation_recorded 保留为审计事实；是否阻断由 resolution 决定。
    ImportInvocationResolution resolution_ =
        ImportInvocationResolution::UNRESOLVED;
    // CR-014：SEC import invocation 证据（已调用 import API，持久化恢复）。
    bool import_invocation_recorded_ = false;
    // CR-014：import 结果待定（回调待收敛；重启后按 Store 保守恢复）。
    bool pending_callback_ = false;
    // CR-014：最近一次 SEC 证据分类（有限枚举，可观测）。
    SecImportEvidenceKind last_sec_evidence_kind_ =
        SecImportEvidenceKind::ContractUnknown;
    // CR-014：观测时 SEC capability 快照契约版本（仅诊断；失败/未知记 0）。
    uint32_t sec_import_result_contract_version_ = 0;
    // ---- CR-015 §22.2：NOT_FOUND 稳定化状态 ----
    SecNotFoundStabilization stab_;
    std::string recovery_phase_;      // keyprov_recovery_phase::*（诊断）
    int cached_vmd_status_ = -1;      // 稳定化期间缓存的最新 VMD Status（-1=无）
    // CR-016：与 cached_vmd_status_ 配对的规范化错误（释放判定必须同时匹配
    // status 与错误四元组；无 error 时 present=false 保持 fail-closed）。
    CloudProtocolError cached_vmd_error_;
    // 唯一后继 requestId（supersede 幂等恢复：预生成后持久化）。
    std::string successor_request_id_;
    std::string successor_request_id_digest_;
    // SEC capability epoch（TSP 本地生成；0=unknown）。
    uint64_t current_sec_capability_epoch_ = 0;
    bool sec_capability_unavailable_ = false;   // capability 查询失败（epoch 未知）
    uint32_t last_sec_capability_contract_ = 0; // 上次成功查询的契约版本
    bool last_capability_not_found_flag_ = false;
    uint32_t status_backoff_ms_ = 0;            // StatusRequest 专用指数退避
    // wall clock 仅诊断（稳定窗判定使用 monotonic clock）。
    int64_t sec_not_found_first_observed_wall_ms_ = -1;
    int64_t sec_not_found_last_observed_wall_ms_ = -1;
    // CR-014 §21.5：相同三元组 {vmd_state, sec_evidence, store_generation}
    // 抑制重复写盘/日志（last_obs_vmd_status_=-1 表示 SEC 阶段；-3 表示 BLOCKED
    // EVIDENCE_CONFLICT 重查；>=0 为 VMD Status 值）。
    bool last_obs_valid_ = false;
    int last_obs_vmd_status_ = -1;
    SecImportEvidenceKind last_obs_kind_ = SecImportEvidenceKind::ContractUnknown;
    // CR-016：抑制键的 error 维度（-1=未观测到 error，SEC 阶段）。
    int last_obs_error_code_ = 0;
    int last_obs_error_action_ = -1;
    uint64_t last_obs_generation_ = 0;
    // SEC outcome unknown 连续轮次（>= max_attempts_before_alert 时告警一次）。
    uint32_t sec_unknown_rounds_ = 0;
    bool sec_unknown_alerted_ = false;
    bool reconcile_status_sent_ = false;   // 对账中已发 StatusRequest（等待响应）
    std::string conflict_vmd_code_;        // 脱敏冲突 VMD code（如 806095）
    // 发送时快照，用于异步结果迟到隔离（requestId+generation+fingerprint）。
    bool awaiting_active_ = false;
    std::string awaiting_request_id_;
    uint64_t awaiting_generation_ = 0;
    KeyprovFingerprint awaiting_fingerprint_{};

    // in-flight（内存态；pending_items_ 持有 move-only SecureBuffer）
    std::vector<tbox::sec::WrappedKeyItem> pending_items_;
    // 原 Response 的非敏感 ACK 绑定材料（仅内存；重启后由 SEC journal 裁决）。
    struct AckBinding {
        std::string purpose;
        std::string key_id;
        uint64_t business_key_version = 0;
        int envelope_format = 0;
        std::vector<uint8_t> envelope_digest;
        std::array<uint8_t, 3> key_check_value{};
        bool key_check_value_present = false;
    };
    std::vector<AckBinding> response_binding_;
    KeyprovReadiness readiness_;
    bool import_attempted_ = false;
    std::vector<KeyProvImportItemResult> ack_items_;
    bool ack_sent_ = false;
    bool status_sent_ = false;
    bool recovering_ack_ = false;
    std::string last_response_message_id_;
    int64_t deadline_ms_ = 0;
    int64_t next_retry_ms_ = 0;
    uint32_t backoff_ms_ = 0;
    bool capability_event_seen_ = false;

    // worker
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::thread worker_;
    std::condition_variable cv_;
    bool start_monitor_ = true;

    mutable V2cKeyProvisioningSnapshot counters_;
};

} // namespace tsp
} // namespace tbox
