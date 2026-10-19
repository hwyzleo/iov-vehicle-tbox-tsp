// TBOX-TSP-DSN-CR-012 §8: KEYPROV_READY 协议/安全前置门禁。
//
// KEYPROV_READY = 本结构 .all()
//   AND 既有 CR-010/011 门禁（enabled / MQTT capability / cloud ready / identity）
//   AND clock synced。
//
// 本结构只覆盖与协议锁版和 TBOX-SEC 事实相关的 9 项：
//   parProtoCr008ReleaseMatched / descriptorSetHashMatched /
//   packageServiceProtocolRegistryMatched / deterministicProtoRuntimeReady /
//   crossLanguageGoldenReady / secEnvelopeV1ImportReady /
//   secAtomicDualPurposeCommitReady / secImportProofSignEcdsaP256V1Ready /
//   secSecureJournalReplayReady。
//
// 前 5 项来自 BUILD/release 构建清单 + 启动自检（keyprov_release_lock.h）；
// 后 4 项来自 TBOX-SEC 只读 capability 查询（CR-012 Q1）。任一为 false 时不得
// 发送新 Request、转交 Response 或发送成功 ACK。

#pragma once

#include <tbox/sec/business_key.h>

#include <string>

namespace tbox {
namespace tsp {

struct KeyprovReadiness {
    // ---- build-lock (manifest + startup self-check) ----
    bool par_proto_cr008_release_matched = false;
    bool descriptor_set_hash_matched = false;
    bool package_service_protocol_registry_matched = false;
    bool deterministic_proto_runtime_ready = false;
    bool cross_language_golden_ready = false;

    // ---- SEC journal/capability facts ----
    bool sec_envelope_v1_import_ready = false;
    bool sec_atomic_dual_purpose_commit_ready = false;
    bool sec_import_proof_sign_ecdsa_p256_v1_ready = false;
    bool sec_secure_journal_replay_ready = false;

    bool all() const {
        return par_proto_cr008_release_matched &&
               descriptor_set_hash_matched &&
               package_service_protocol_registry_matched &&
               deterministic_proto_runtime_ready &&
               cross_language_golden_ready &&
               sec_envelope_v1_import_ready &&
               sec_atomic_dual_purpose_commit_ready &&
               sec_import_proof_sign_ecdsa_p256_v1_ready &&
               sec_secure_journal_replay_ready;
    }

    // 首个未满足门禁的稳定、脱敏 reason（用于日志/快照）。
    std::string first_missing_reason() const;
};

// 计算 build-lock 部分（编译期清单常量 + deterministic protobuf runtime 自检）。
KeyprovReadiness keyprov_build_lock_readiness();

// 合并 SEC capability 快照。契约版本不匹配时 SEC 四项保持 false（fail-closed）。
void keyprov_apply_sec_capability(
    const tbox::sec::V2cKeyProvisioningCapability& cap,
    KeyprovReadiness& io);

} // namespace tsp
} // namespace tbox
