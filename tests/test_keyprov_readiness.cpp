// TBOX-TSP-DSN-CR-012 §8: keyprov readiness 门禁单元测试。
//
// 覆盖：build-lock 清单 + 启动自检、SEC capability 契约版本校验、KeyprovReadiness 合取
// 与首个缺失 reason。
#include <gtest/gtest.h>

#include "keyprov_readiness.h"
#include "keyprov_release_lock.h"

using namespace tbox::tsp;

namespace {

tbox::sec::V2cKeyProvisioningCapability ready_cap() {
    tbox::sec::V2cKeyProvisioningCapability c;
    c.capability_contract_version =
        tbox::sec::V2cKeyProvisioningCapability::kContractVersion;
    c.envelope_v1_import_ready = true;
    c.atomic_dual_purpose_commit_ready = true;
    c.import_proof_sign_ecdsa_p256_v1_ready = true;
    c.secure_journal_replay_ready = true;
    return c;
}

} // namespace

TEST(KeyprovReadinessTest, BuildLockMatchesCanonicalCr008) {
    KeyprovReadiness r = keyprov_build_lock_readiness();
    EXPECT_TRUE(r.par_proto_cr008_release_matched);
    EXPECT_TRUE(r.descriptor_set_hash_matched);
    EXPECT_TRUE(r.package_service_protocol_registry_matched);
    EXPECT_TRUE(r.deterministic_proto_runtime_ready);
    EXPECT_TRUE(r.cross_language_golden_ready);
    // build-lock 本身不含 SEC 事实，不应整体 READY。
    EXPECT_FALSE(r.all());
    EXPECT_EQ(r.first_missing_reason(), "sec_envelope_v1_import_not_ready");
}

TEST(KeyprovReadinessTest, ManifestConstantsAreExact) {
    EXPECT_STREQ(keyprov_lock::kParProtoRelease, "PAR-PROTO-DSN-CR-008");
    EXPECT_STREQ(keyprov_lock::kPackage, "security.keyprov.v1");
    EXPECT_STREQ(keyprov_lock::kService, "security.keyprov");
    EXPECT_STREQ(keyprov_lock::kProtocolVersion, "keyprov-v1");
    EXPECT_TRUE(keyprov_lock::kCrossLanguageGoldenReady);
    EXPECT_EQ(std::string(keyprov_lock::kDescriptorSetHash).size(), 64u);
    EXPECT_EQ(std::string(keyprov_lock::kGoldenVectorSetHash).size(), 64u);
}

TEST(KeyprovReadinessTest, SecCapabilityCompletesReadiness) {
    KeyprovReadiness r = keyprov_build_lock_readiness();
    auto cap = ready_cap();
    keyprov_apply_sec_capability(cap, r);
    EXPECT_TRUE(r.all());
    EXPECT_EQ(r.first_missing_reason(), "");
}

TEST(KeyprovReadinessTest, SecCapabilityContractMismatchFailClosed) {
    KeyprovReadiness r = keyprov_build_lock_readiness();
    auto cap = ready_cap();
    cap.capability_contract_version = 999;  // 未知契约版本
    keyprov_apply_sec_capability(cap, r);
    EXPECT_FALSE(r.sec_envelope_v1_import_ready);
    EXPECT_FALSE(r.sec_atomic_dual_purpose_commit_ready);
    EXPECT_FALSE(r.sec_import_proof_sign_ecdsa_p256_v1_ready);
    EXPECT_FALSE(r.sec_secure_journal_replay_ready);
    EXPECT_FALSE(r.all());
}

TEST(KeyprovReadinessTest, EachSecGateIsMandatory) {
    auto check_missing = [](void (*clear)(tbox::sec::V2cKeyProvisioningCapability&),
                            const char* reason) {
        KeyprovReadiness r = keyprov_build_lock_readiness();
        auto cap = ready_cap();
        clear(cap);
        keyprov_apply_sec_capability(cap, r);
        EXPECT_FALSE(r.all());
        EXPECT_EQ(r.first_missing_reason(), reason);
    };
    check_missing([](auto& c) { c.envelope_v1_import_ready = false; },
                  "sec_envelope_v1_import_not_ready");
    check_missing([](auto& c) { c.atomic_dual_purpose_commit_ready = false; },
                  "sec_atomic_dual_commit_not_ready");
    check_missing([](auto& c) { c.import_proof_sign_ecdsa_p256_v1_ready = false; },
                  "sec_import_proof_sign_not_ready");
    check_missing([](auto& c) { c.secure_journal_replay_ready = false; },
                  "sec_journal_replay_not_ready");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
