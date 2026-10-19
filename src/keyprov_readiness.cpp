// TBOX-TSP-DSN-CR-012 §8 / Q2: keyprov readiness 门禁实现。
#include "keyprov_readiness.h"

#include "keyprov_protocol.h"
#include "keyprov_release_lock.h"

#include <cstring>

namespace tbox {
namespace tsp {

namespace {

bool str_eq(const char* a, const char* b) {
    return a != nullptr && b != nullptr && std::strcmp(a, b) == 0;
}

bool is_sha256_hex(const char* s) {
    if (s == nullptr || std::strlen(s) != 64) return false;
    for (const char* p = s; *p != '\0'; ++p) {
        const char c = *p;
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

} // namespace

std::string KeyprovReadiness::first_missing_reason() const {
    if (!par_proto_cr008_release_matched) return "par_proto_release_mismatch";
    if (!descriptor_set_hash_matched) return "descriptor_set_hash_missing";
    if (!package_service_protocol_registry_matched) return "registry_tuple_mismatch";
    if (!deterministic_proto_runtime_ready) return "deterministic_proto_runtime_not_ready";
    if (!cross_language_golden_ready) return "cross_language_golden_not_ready";
    if (!sec_envelope_v1_import_ready) return "sec_envelope_v1_import_not_ready";
    if (!sec_atomic_dual_purpose_commit_ready) return "sec_atomic_dual_commit_not_ready";
    if (!sec_import_proof_sign_ecdsa_p256_v1_ready) return "sec_import_proof_sign_not_ready";
    if (!sec_secure_journal_replay_ready) return "sec_journal_replay_not_ready";
    return "";
}

KeyprovReadiness keyprov_build_lock_readiness() {
    KeyprovReadiness r;
    r.par_proto_cr008_release_matched =
        str_eq(keyprov_lock::kParProtoRelease,
               keyprov_lock::kRequiredParProtoRelease);
    r.descriptor_set_hash_matched =
        is_sha256_hex(keyprov_lock::kDescriptorSetHash);
    r.package_service_protocol_registry_matched =
        str_eq(keyprov_lock::kPackage, kKeyprovPackage) &&
        str_eq(keyprov_lock::kService, kKeyprovService) &&
        str_eq(keyprov_lock::kProtocolVersion, kKeyprovProtocolVersion) &&
        keyprov_lock::kCanonicalRegistry != nullptr &&
        keyprov_lock::kCanonicalRegistry[0] != '\0';
    // 版本锁定 + 启动自检：descriptor/字段号一致且确定性序列化字节稳定。
    r.deterministic_proto_runtime_ready =
        keyprov_deterministic_proto_runtime_check();
    // 当前制品必须来自通过指定 golden vector-set 的 CI/release manifest。
    r.cross_language_golden_ready =
        keyprov_lock::kCrossLanguageGoldenReady &&
        is_sha256_hex(keyprov_lock::kGoldenVectorSetHash);
    return r;
}

void keyprov_apply_sec_capability(
    const tbox::sec::V2cKeyProvisioningCapability& cap,
    KeyprovReadiness& io) {
    // 契约版本缺失/未知：不得消费任何 SEC 能力位（fail-closed）。
    if (cap.capability_contract_version !=
        tbox::sec::V2cKeyProvisioningCapability::kContractVersion) {
        io.sec_envelope_v1_import_ready = false;
        io.sec_atomic_dual_purpose_commit_ready = false;
        io.sec_import_proof_sign_ecdsa_p256_v1_ready = false;
        io.sec_secure_journal_replay_ready = false;
        return;
    }
    io.sec_envelope_v1_import_ready = cap.envelope_v1_import_ready;
    io.sec_atomic_dual_purpose_commit_ready = cap.atomic_dual_purpose_commit_ready;
    io.sec_import_proof_sign_ecdsa_p256_v1_ready =
        cap.import_proof_sign_ecdsa_p256_v1_ready;
    io.sec_secure_journal_replay_ready = cap.secure_journal_replay_ready;
}

} // namespace tsp
} // namespace tbox
