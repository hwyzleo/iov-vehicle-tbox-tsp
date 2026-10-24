// TBOX-TSP-DSN-CR-013 §3/§4/§20: Keyprov 不可变 Attempt 快照与 attemptFingerprint。
//
// requestId 绑定一次不可变业务请求快照（KeyprovAttemptSnapshot）；每次 Request
// 发送前以当前输入计算 candidate fingerprint，与冻结 fingerprint 相同才允许复用
// 原 requestId，不同则进入 RECONCILE_OLD_ATTEMPT（先对账 VMD Status + SEC journal）。
//
// fingerprint 只用于 TSP 本地不可变性判断，不冒充 VMD 权威 requestDigest，不新增
// wire 字段。requestId 不进入 fingerprint（避免新旧 attempt 因 requestId 不同而
// 掩盖内容是否相同）；既有 idempotencyKey=sha256(requestId|businessDomain) 继续
// 按 wire 兼容生成，但不参与本地"内容未变"判断。
//
// 安全边界：snapshot 只含非敏感业务输入与受控摘要（digest/引用摘要），绝不包含
// 证书 DER、Wrapped Key、parameters、proof 或私钥引用。
//
// 版本化约定：
//   - fingerprint 版本写入 Store；未知版本不得重算或降级解释。
//   - 首版（V1）不含 derivationVersion：canonical Request 无该字段、TSP 配置值
//     不会成为 VMD 输入；PAR-PROTO 正式增加 Request 字段时提升 fingerprint 版本
//     再纳入（避免本地与 VMD 摘要口径伪对齐）。

#pragma once

#include "keyprov_protocol.h"
#include "hash.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

using KeyprovFingerprint = tbox::fw::hash::Sha256Digest;  // 32B

// 首版 attempt fingerprint 版本。未知版本（>V1）必须拒绝降级解释。
constexpr uint32_t kAttemptFingerprintVersionV1 = 1;
// 当前受支持的最高 fingerprint 版本。
constexpr uint32_t kAttemptFingerprintVersionCurrent = kAttemptFingerprintVersionV1;

// ============================================================
// 不可变业务请求快照（CR §3）
// ============================================================
struct KeyprovAttemptSnapshot {
    std::string business_domain;                // V2C_COMM
    std::vector<int> purposes;                  // 排序去重后的 KeyPurpose 枚举值
    std::vector<std::pair<int, uint64_t>> current_versions;  // (purpose, version) 按 purpose 排序
    std::vector<uint8_t> device_identity_digest;      // 32B raw
    std::vector<uint8_t> recipient_certificate_digest;  // 32B raw（Wrapped Key 接收者证书摘要）
    std::vector<uint8_t> certificate_ref_digest;      // 32B raw（certificate_ref 引用摘要，持久化用）
    std::vector<int> wrapping_suites;           // 排序去重的 WrappingSuite 枚举值
    std::vector<int> envelope_formats;          // 排序去重的 KeyEnvelopeFormat 枚举值
    std::vector<uint8_t> protocol_lock_digest;  // 32B raw（协议锁版受控摘要）
};

// ============================================================
// fingerprint 计算（CR §4 / §20.1）
// ============================================================
// 计算 attemptFingerprintV1。失败（非法输入）返回 false 并写入 err（脱敏）。
bool keyprov_compute_attempt_fingerprint_v1(
    const KeyprovAttemptSnapshot& snapshot,
    KeyprovFingerprint& out,
    std::string& err);

// 64 字符小写 hex 表示（日志/Store 用，不含原始摘要以外的敏感内容）。
std::string keyprov_fingerprint_to_hex(const KeyprovFingerprint& fp);

bool keyprov_fingerprint_equal(const KeyprovFingerprint& a,
                               const KeyprovFingerprint& b);

// 协议锁版受控摘要：版本化 tagged canonical 编码，仅使用稳定 release 常量
// （release / descriptorSetHash / canonicalRegistry / goldenVectorSetId）。
// 返回 32B raw；版本号单独导出。算法/字段集变化时提升 protocolLockDigestVersion。
KeyprovFingerprint keyprov_protocol_lock_digest_v1();
uint32_t keyprov_protocol_lock_digest_version();

// 从当前业务输入构造不可变 snapshot（排序/去重/受控摘要）。
// sec_status 为当前 SEC 各 purpose 状态（current_versions 来源）；失败返回 false。
bool keyprov_build_attempt_snapshot(
    const std::string& business_domain,
    const std::vector<std::string>& purposes,
    const KeyprovSessionIdentity& identity,
    const std::vector<tbox::sec::BusinessKeyStatus>& sec_status,
    const KeyprovFingerprint& protocol_lock_digest,
    KeyprovAttemptSnapshot& out,
    std::string& err);

// ============================================================
// 变化维度（有限枚举；仅可观测性，不作为业务正确性依据）
// ============================================================
enum class AttemptChangeDimension : uint8_t {
    None = 0,           // 内容未变
    Purposes,           // purpose 集合 / business_domain
    CurrentVersions,    // purpose->currentVersion 集合
    DeviceIdentity,     // deviceIdentityDigest
    Certificate,        // recipientCertificateDigest / certificateRefDigest
    SuiteFormat,        // wrapping_suites / envelope_formats
    ProtocolLock,       // protocolLockDigest
    Unknown             // 受控兜底，不直接用自由文本
};

const char* keyprov_attempt_change_dimension_to_string(AttemptChangeDimension d);

// 返回 frozen 与 candidate 首个不同的业务维度（None=相同）。
AttemptChangeDimension keyprov_attempt_change_dimension(
    const KeyprovAttemptSnapshot& frozen,
    const KeyprovAttemptSnapshot& candidate);

// ============================================================
// 806095 / 幂等冲突统一分类器（用户裁决口径）
// ============================================================
// canonical 判据：action == "KEYPROV_IDEMPOTENCY_CONFLICT"；
// 兼容：code == "KEYPROV_IDEMPOTENCY_CONFLICT"（映射）；
// VMD 原始码兼容：code == "806095"。
// 禁止仅凭 action=="DO_NOT_RETRY" / retryable==false 判定（其它确定性拒绝也具备
// 相同行为）；不解析 message 文本；code=804010 且 action 空或仅 DO_NOT_RETRY 时
// 按普通业务拒绝处理，不进入幂等冲突分支。
// 统一应用于 KeyProvisioningResponse / AckResult / StatusResponse 的 error。
bool keyprov_is_idempotency_conflict(const KeyProvProtocolError& error);

// ============================================================
// TBOX-TSP-DSN-CR-016 §4.1/§23.1：云端可释放 UNSPECIFIED 判定窄类型
// ============================================================
// VMD 对不存在批次按只读契约返回 status=UNSPECIFIED(0) + 806099 + retryable=false
// + action=DO_NOT_RETRY。TSP 只在 SEC 已证明无副作用（NO_SIDE_EFFECT_PROVEN）且
// 完整错误四元组匹配时才把该 UNSPECIFIED 分类为“明确可释放”；其余缺字段、未知
// 枚举或解析失败一律 fail-closed。错误分类只消费稳定 code/action，禁止 message
// 文本匹配（REQ-008/§7.3）。

// 规范化后的动作（有限枚举；UNSPECIFIED=未知/缺失，fail-closed）。
// 数值仅追加，不得重排。
enum class ProtocolErrorAction : uint8_t {
    UNSPECIFIED = 0,   // 未知/缺失 action（fail-closed）
    DO_NOT_RETRY = 1   // 云端建议不要重试（批次不存在的确定性语义）
};

// canonical VMD“批次不存在/未找到”码（ERR_NOT_FOUND）。只允许显式绑定该常量，
// 不得以 message 文本或其它 code 推断批次不存在。
constexpr int32_t kKeyProvErrorCodeNotFound = 806099;

// 规范化后的云端错误（Coordinator 矩阵输入；不直接依赖生成类型）。
struct CloudProtocolError {
    int32_t code = 0;   // 0=未识别/缺失；仅 806099 视为 ERR_NOT_FOUND
    bool retryable = false;
    ProtocolErrorAction action = ProtocolErrorAction::UNSPECIFIED;
    bool present = false;  // StatusResponse 是否携带 error（code 非空）
};

// 云端决策矩阵输入：同时携带 VMD status 与规范化 ProtocolError
// （REQ-009：不得仅传 status 整数）。
struct CloudStatusDecisionInput {
    int status = kKeyProvStatusUnspecified;  // KEY_PROVISIONING_STATUS_* 数值
    CloudProtocolError error;
};

// 规范化 wire ProtocolError -> CloudProtocolError。
// 只识别 code=="806099" -> kKeyProvErrorCodeNotFound、action=="DO_NOT_RETRY"；
// 其它 code/action、缺失 error、默认 error 均映射为不匹配值（fail-closed）。
CloudProtocolError keyprov_normalize_protocol_error(
    const KeyProvProtocolError& wire);

const char* keyprov_protocol_error_action_to_string(ProtocolErrorAction a);

// ============================================================
// blocked reason 受控枚举（指标/日志用，有限集合）
// ============================================================
namespace keyprov_blocked_reason {
constexpr const char* kLegacySnapshotUnknown = "LEGACY_SNAPSHOT_UNKNOWN";
constexpr const char* kIdempotencyConflict = "IDEMPOTENCY_CONFLICT";
constexpr const char* kAwaitCloudTermination = "AWAIT_CLOUD_TERMINATION";
constexpr const char* kSecOutcomeUnknown = "SEC_OUTCOME_UNKNOWN";
constexpr const char* kVmdOutcomeUnknown = "VMD_OUTCOME_UNKNOWN";
constexpr const char* kUnknown = "UNKNOWN";
// ---- TBOX-TSP-DSN-CR-014 §21.5：SEC 证据阻断细分 ----
constexpr const char* kSecImportNotFound = "SEC_IMPORT_NOT_FOUND";
constexpr const char* kSecImportInProgress = "SEC_IMPORT_IN_PROGRESS";
constexpr const char* kEvidenceConflict = "EVIDENCE_CONFLICT";
// ---- TBOX-TSP-DSN-CR-015 §22.2/§22.4：证据收敛与恢复阻断细分 ----
constexpr const char* kStabilizingSecNotFound = "STABILIZING_SEC_NOT_FOUND";
constexpr const char* kAwaitRemoteRepair = "AWAIT_REMOTE_REPAIR";
constexpr const char* kHardEvidenceConflict = "HARD_EVIDENCE_CONFLICT";
} // namespace keyprov_blocked_reason

// ============================================================
// CR-015 §22.2/§22.5：导入意图处置与恢复阶段（受控枚举）
// ============================================================
// import_invocation_recorded 不清零（历史审计事实）；是否仍构成阻断由
// ImportInvocationResolution 决定：
//   - NO_SIDE_EFFECT_PROVEN：已证明/无本地调用意图（import_invocation=false）
//   - UNRESOLVED：曾越过“调用前持久化”线性化点，尚需强 NOT_FOUND 稳定化
//   - HARD_CONFLICT：已证明后出现矛盾证据（禁止自动释放，人工治理）
// 数值为持久化格式，不得重排（仅追加）。
enum class ImportInvocationResolution : uint8_t {
    UNRESOLVED = 0,
    NO_SIDE_EFFECT_PROVEN = 1,
    HARD_CONFLICT = 2
};

const char* keyprov_import_invocation_resolution_to_string(
    ImportInvocationResolution r);
bool keyprov_import_invocation_resolution_from_string(
    const std::string& s, ImportInvocationResolution& out);

// 恢复/诊断阶段（recovery_phase 受控枚举；仅可观测性，不作为业务正确性依据）。
namespace keyprov_recovery_phase {
constexpr const char* kReconcileEvidence = "RECONCILE_EVIDENCE";
constexpr const char* kStabilizingSecNotFound = "STABILIZING_SEC_NOT_FOUND";
constexpr const char* kReconcileRemote = "RECONCILE_REMOTE";
constexpr const char* kAwaitCloudTermination = "AWAIT_CLOUD_TERMINATION";
constexpr const char* kAwaitRemoteRepair = "AWAIT_REMOTE_REPAIR";
constexpr const char* kHardEvidenceConflict = "HARD_EVIDENCE_CONFLICT";
} // namespace keyprov_recovery_phase

// ============================================================
// CR-015 §22.2：SEC NOT_FOUND 稳定化观测状态
// ============================================================
// 连续强 NOT_FOUND 的同 SEC 能力代际计数与时间窗。时间窗使用单调时钟
// （重启后不得跨重启复用单调时间：重启时 first/last 置 unset 重新开始）。
// wall-clock 仅用于诊断（persist 字段），不参与稳定窗判定。
struct SecNotFoundStabilization {
    uint32_t consecutive_count = 0;
    int64_t first_observed_monotonic_ms = -1;  // 单调时钟；-1=未开始
    int64_t last_observed_monotonic_ms = -1;
    uint64_t sec_capability_epoch = 0;         // 0=unknown（必须重新查询）
    uint32_t sec_contract_version = 0;         // 观测时 capability 契约版本
    std::vector<uint8_t> request_id_digest;    // 32B raw（稳定化绑定的 requestId）
    uint64_t attempt_generation = 0;           // store_generation（CAS 依据）
};

// ============================================================
// CR-015 §22.5：SEC 证据对账动作（替代旧 bool consumed）
// ============================================================
// TERMINAL_HANDLED      ：COMMITTED/硬错误已完成状态迁移（本轮无需再发 Status）
// WAIT_SEC              ：继续稳定化/阻断，本轮不发起新 import、不发 Status
// ALLOW_READONLY_REMOTE ：可发送只读 VMD StatusRequest（稳定化期间只读缓存；
//                         proven 后执行完整云端决策矩阵）
enum class ReconcileAction : uint8_t {
    TERMINAL_HANDLED = 0,
    WAIT_SEC = 1,
    ALLOW_READONLY_REMOTE = 2
};

// submission 状态受控枚举（persist_locked 使用）。
namespace keyprov_submission {
constexpr const char* kNone = "NONE";        // 尚未向云端提交
constexpr const char* kSubmitted = "SUBMITTED";  // 已 publish（accepted/unknown，提交证据存在）
constexpr const char* kConfirmed = "CONFIRMED";  // 业务已确认（ACTIVE）
} // namespace keyprov_submission

} // namespace tsp
} // namespace tbox
