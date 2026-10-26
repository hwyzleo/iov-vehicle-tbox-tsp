// TBOX-TSP-DSN-CR-010 §5 / CR-013 §10: V2C keyprov 非敏感流程状态持久化。
//
// Store namespace: tsp/keyprov/v2c（framework-store 逻辑 namespace "tsp" + 键前缀）。
// 只保存非敏感状态机字段，绝不保存 Wrapped Key、parameters 原文、证书、VIN/HSM UID
// 或任何可恢复密钥的材料。SEC/HSM 件内状态永远是事实来源，Store 不覆盖其结论。
//
// CR-013 §10（方案 A）：单一聚合记录 + 单键原子替换。
//   - 整个 active attempt（schema_version / fingerprint / snapshot / submission /
//     supersede 关联 / blocked_reason / store_generation / 状态与计数）序列化为一个
//     JSON 字符串，写入单个键 tsp/keyprov/v2c/state；
//   - framework Store 单键 save() 为原子替换（临时文件 + fsync + atomic rename +
//     目录同步），无部分写崩溃点；flush() 仅重置策略，持久化由原子写完成；
//   - store_generation 在聚合内单调递增，作为并发/迟到结果 CAS 依据；
//   - supersede 采用"旧 record 终态化 + 新 record 创建"，终态化 requestId 追加进
//     append-only audit 列表（有界）。
//
// legacy 兼容（CR-013 §10）：旧版多键记录（keyprov.v2c.present 等）仍可被读取；
// 旧记录缺 snapshot/fingerprint 时标记 legacy_snapshot_unknown=true，Coordinator
// 对 legacy 默认阻断发送，先查 SEC journal + VMD Status 再决定迁移/终结/新 attempt，
// 不得用当前动态字段反向伪造历史快照。

#pragma once

#include "keyprov_attempt.h"
#include "keyprov_lifecycle.h"
#include "store.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tbox {
namespace tsp {

// Store schema 版本（CR-013 §10 新增 v2；CR-014 §8/§21.6 新增 v3；
// CR-015 §22.3 新增 v4：导入意图处置与 NOT_FOUND 稳定化；
// TBOX-TSP-DSN-CR-017 §3 新增 v5：KL1 预算/时间/链/迁移门禁）。
// 未知/更高版本不得降级解释。
constexpr uint32_t kV2cStoreSchemaVersion = 5;

struct V2cKeyProvisioningRecord {
    bool valid = false;                    // Store 中是否存在记录

    // ---- v2 聚合字段（CR-013） ----
    uint32_t schema_version = 0;           // kV2cStoreSchemaVersion
    uint32_t fingerprint_version = 0;      // 0 = legacy（无 fingerprint）
    std::string attempt_fingerprint;       // 64 小写 hex（fingerprint_version>0 时非空）
    std::string request_id;                // 本次 attempt 幂等身份
    std::string idempotency_digest;        // sha256(requestId|businessDomain)（wire 兼容）
    std::string state;                     // 状态机名（非敏感）
    std::string submission;                // keyprov_submission::*（提交证据）
    KeyprovAttemptSnapshot snapshot;       // 不可变业务快照（受控摘要，无密钥材料）
    uint32_t attempt_count = 0;
    int64_t deadline_ms = 0;
    std::string last_error;                // 受控原因码，不含密钥/身份原文
    int64_t updated_at_ms = 0;
    uint64_t cloud_session_generation = 0;
    std::string supersedes_request_id;     // 本 attempt 取代的旧 requestId（空=无）
    std::string superseded_by_request_id;  // 取代本 attempt 的新 requestId（空=无）
    std::string blocked_reason;            // keyprov_blocked_reason::*（受控枚举）
    uint64_t store_generation = 0;         // 单调递增，CAS/迟到结果隔离依据
    std::vector<std::string> terminalized_request_ids;  // append-only audit（有界）

    // ---- v3 聚合字段（CR-014 §8/§21.6：SEC import result 证据） ----
    // sec_import_evidence_kind：SecImportEvidenceKind 数值（0..5）。
    // 旧记录（v2 及以下）缺字段时默认 ContractUnknown + import_invocation=true
    // （"可能已调用"，保持阻断），除非 SEC/VMD 权威查询重新建立证据。
    uint32_t sec_import_result_contract_version = 0;  // 0=UNKNOWN（仅诊断）
    int sec_import_evidence_kind = 5;                 // 默认 ContractUnknown
    uint64_t sec_evidence_observed_store_generation = 0;
    int64_t sec_evidence_observed_at_ms = 0;
    bool import_invocation = false;  // 已调用 SEC import API（缺字段默认 true）

    // ---- v4 聚合字段（CR-015 §22.2/§22.3：导入意图处置与稳定化） ----
    // import_invocation_resolution：ImportInvocationResolution 数值（0..2）。
    // v3→v4 迁移默认值：import_invocation=true → UNRESOLVED；
    // 字段显式存在且为 false → NO_SIDE_EFFECT_PROVEN；更老记录字段缺失
    // （import_invocation 保守默认 true）→ UNRESOLVED（不得因缺省值释放）。
    int import_invocation_resolution = 0;  // 默认 UNRESOLVED
    uint32_t sec_not_found_count = 0;     // 连续强 NOT_FOUND 计数（诊断；重启后重新稳定化）
    int64_t sec_not_found_first_observed_ms = -1;  // wall clock（仅诊断）
    int64_t sec_not_found_last_observed_ms = -1;
    uint64_t sec_capability_epoch = 0;    // 0=unknown（必须重新查询）
    uint32_t sec_contract_version = 0;    // 稳定化观测时 SEC capability 契约版本
    std::string recovery_phase;           // keyprov_recovery_phase::*（诊断）
    std::string successor_request_id;     // 预生成唯一后继 requestId（幂等恢复）
    std::string successor_request_id_digest;  // sha256(successor_request_id) hex（审计）

    // ---- v5 聚合字段（TBOX-TSP-DSN-CR-017 §3：KL1 预算/时间/链/迁移） ----
    // KL1 生命周期 profile（"keyprov-lifecycle-kl1-v1"；空=非 KL1 attempt）。
    std::string lifecycle_profile;
    // 持久预算账本（Request 8/120s、Status 12/300s、SEC 12/300s、ACK 3+D、
    // freshen 1、链 3/600s、迁移 token；跨重启不重置）。
    KeyprovBudgetLedger budget;
    // 当前 Response 交付租约 E（外层 field4；导入前 E-U>=import_min 准入）。
    int64_t lease_expires_at_ms = 0;
    // SEC KL1 契约快照（非敏感；缺省=UNAVAILABLE，不是支持）。
    uint32_t sec_result_contract_version = 0;   // 0=UNAVAILABLE
    uint32_t sec_query_semantics_version = 0;   // 0=UNAVAILABLE
    bool sec_supports_lease_admission = false;  // false=不得调用 KL1 import
    uint32_t sec_kl1_profile_version = 0;       // 0=UNAVAILABLE

    // ---- legacy 解析产物（非持久化，load() 派生） ----
    bool legacy_snapshot_unknown = false;  // 旧记录缺 snapshot/fingerprint

    // ---- 便捷镜像（与 snapshot 一致；load()/persist 维护） ----
    std::vector<std::string> purposes;     // 字符串 purpose 集
    std::vector<std::pair<std::string, uint64_t>> business_key_versions;  // purpose->version
};

class V2cKeyProvisioningStore {
public:
    // store_root 默认 "/var/lib/tbox"；测试可注入临时目录。
    explicit V2cKeyProvisioningStore(const std::string& store_root = "/var/lib/tbox");

    // 读取持久化记录；无记录时 valid=false。
    // legacy 多键旧格式可读；旧记录缺 fingerprint 时 legacy_snapshot_unknown=true。
    V2cKeyProvisioningRecord load() const;

    // 原子持久化非敏感记录（单聚合键 save + flush）。
    void save(const V2cKeyProvisioningRecord& record);

    // 清除记录（仅当云端明确终结旧请求且策略允许时）。
    void clear();

    bool is_ready() const;

private:
    hwyz::store::Store store_;
};

} // namespace tsp
} // namespace tbox
