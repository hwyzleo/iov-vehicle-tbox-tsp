// TBOX-TSP-DSN-CR-010 §5 / CR-013 §10: V2cKeyProvisioningStore 单元测试。
#include <gtest/gtest.h>

#include "keyprov_attempt.h"
#include "sec_business_key_facade.h"
#include "v2c_key_provisioning_store.h"

#include "store.h"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <string>

using namespace tbox::tsp;

namespace {
std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_keyprov_store_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}

// 构造完整 v2 记录（含 snapshot/fingerprint/submission/supersede/generation）。
V2cKeyProvisioningRecord make_v2_record(const std::string& rid) {
    V2cKeyProvisioningRecord rec;
    rec.valid = true;
    rec.schema_version = kV2cStoreSchemaVersion;
    rec.fingerprint_version = kAttemptFingerprintVersionV1;
    rec.request_id = rid;
    rec.idempotency_digest = "deadbeef";
    rec.state = "ACK_PENDING";
    rec.submission = keyprov_submission::kSubmitted;
    // snapshot（与 keyprov_build_attempt_snapshot 输出同构）。
    rec.snapshot.business_domain = kKeyprovBusinessDomainV2c;
    rec.snapshot.purposes = {1, 2};
    rec.snapshot.current_versions = {{1, 5}, {2, 7}};
    rec.snapshot.device_identity_digest = std::vector<uint8_t>(32, 0x01);
    rec.snapshot.recipient_certificate_digest = std::vector<uint8_t>(32, 0x02);
    rec.snapshot.certificate_ref_digest = std::vector<uint8_t>(32, 0x03);
    rec.snapshot.wrapping_suites = {2};
    rec.snapshot.envelope_formats = {1};
    {
        KeyprovFingerprint lock = keyprov_protocol_lock_digest_v1();
        rec.snapshot.protocol_lock_digest.assign(lock.begin(), lock.end());
    }
    KeyprovFingerprint fp{};
    std::string err;
    const bool fp_ok = keyprov_compute_attempt_fingerprint_v1(rec.snapshot, fp, err);
    if (fp_ok) {
        rec.attempt_fingerprint = keyprov_fingerprint_to_hex(fp);
    }
    (void)fp_ok; (void)err;
    rec.attempt_count = 3;
    rec.deadline_ms = 123456;
    rec.last_error = "response_timeout";
    rec.updated_at_ms = 999;
    rec.cloud_session_generation = 42;
    rec.supersedes_request_id = "";
    rec.superseded_by_request_id = "";
    rec.blocked_reason = "";
    rec.store_generation = 7;
    rec.terminalized_request_ids = {"kp-old1"};
    rec.purposes = {"UPLINK_AEAD", "DOWNLINK_AEAD"};
    rec.business_key_versions = {{"UPLINK_AEAD", 5}, {"DOWNLINK_AEAD", 7}};
    // ---- CR-014 v3：SEC import result 证据 ----
    rec.sec_import_result_contract_version = 2;
    rec.sec_import_evidence_kind =
        static_cast<int>(tbox::tsp::SecImportEvidenceKind::NotFound);
    rec.sec_evidence_observed_store_generation = 7;
    rec.sec_evidence_observed_at_ms = 111;
    rec.import_invocation = true;
    return rec;
}
} // namespace

TEST(V2cKeyProvisioningStoreTest, EmptyOnFirstRun) {
    V2cKeyProvisioningStore store(temp_root());
    auto rec = store.load();
    EXPECT_FALSE(rec.valid);
}

TEST(V2cKeyProvisioningStoreTest, SaveLoadRoundTripFullV2) {
    auto root = temp_root();
    auto saved = make_v2_record("kp-abc");
    {
        V2cKeyProvisioningStore store(root);
        store.save(saved);
    }
    V2cKeyProvisioningStore store(root);
    auto rec = store.load();
    ASSERT_TRUE(rec.valid);
    EXPECT_EQ(rec.schema_version, kV2cStoreSchemaVersion);
    EXPECT_EQ(rec.fingerprint_version, kAttemptFingerprintVersionV1);
    EXPECT_EQ(rec.request_id, "kp-abc");
    EXPECT_EQ(rec.attempt_fingerprint, saved.attempt_fingerprint);
    EXPECT_EQ(rec.state, "ACK_PENDING");
    EXPECT_EQ(rec.submission, keyprov_submission::kSubmitted);
    EXPECT_EQ(rec.snapshot.business_domain, kKeyprovBusinessDomainV2c);
    ASSERT_EQ(rec.snapshot.purposes.size(), 2u);
    EXPECT_EQ(rec.snapshot.purposes[0], 1);
    EXPECT_EQ(rec.snapshot.purposes[1], 2);
    ASSERT_EQ(rec.snapshot.current_versions.size(), 2u);
    EXPECT_EQ(rec.snapshot.current_versions[1].second, 7u);
    EXPECT_EQ(rec.snapshot.device_identity_digest,
              std::vector<uint8_t>(32, 0x01));
    EXPECT_EQ(rec.snapshot.protocol_lock_digest,
              saved.snapshot.protocol_lock_digest);
    EXPECT_EQ(rec.supersedes_request_id, "");
    ASSERT_EQ(rec.terminalized_request_ids.size(), 1u);
    EXPECT_EQ(rec.terminalized_request_ids[0], "kp-old1");
    EXPECT_EQ(rec.store_generation, 7u);
    EXPECT_EQ(rec.attempt_count, 3u);
    EXPECT_EQ(rec.cloud_session_generation, 42u);
    EXPECT_FALSE(rec.legacy_snapshot_unknown);
    ASSERT_EQ(rec.business_key_versions.size(), 2u);
    EXPECT_EQ(rec.business_key_versions[1].second, 7u);
    // CR-014 v3：SEC import result 证据 round-trip。
    EXPECT_EQ(rec.sec_import_result_contract_version, 2u);
    EXPECT_EQ(rec.sec_import_evidence_kind,
              static_cast<int>(SecImportEvidenceKind::NotFound));
    EXPECT_EQ(rec.sec_evidence_observed_store_generation, 7u);
    EXPECT_EQ(rec.sec_evidence_observed_at_ms, 111);
    EXPECT_TRUE(rec.import_invocation);
}

// CR-014 §8/§21.6：旧 v2 记录缺 SEC 证据字段 -> 保守默认
// （ContractUnknown + import_invocation=true“可能已调用”，保持阻断）。
TEST(V2cKeyProvisioningStoreTest, V2RecordDefaultsSecEvidenceConservative) {
    auto root = temp_root();
    // 用原始 framework Store 直接写 v2 聚合 JSON（无 sec 字段、schema_version=2）。
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", root);
        nlohmann::json j = nlohmann::json::object();
        j["schema_version"] = 2;
        j["fingerprint_version"] = 1;
        j["attempt_fingerprint"] = std::string(64, 'a');
        j["request_id"] = "kp-v2legacy";
        j["state"] = "RECONCILE_OLD_ATTEMPT";
        j["submission"] = keyprov_submission::kSubmitted;
        j["store_generation"] = 3;
        raw.save<std::string>("keyprov.v2c.attempt.v2", j.dump());
        raw.flush();
    }
    V2cKeyProvisioningStore store(root);
    auto rec = store.load();
    ASSERT_TRUE(rec.valid);
    // 有 fingerprint 不是 legacy_snapshot_unknown。
    EXPECT_FALSE(rec.legacy_snapshot_unknown);
    // SEC 证据字段缺省 -> 保守默认。
    EXPECT_EQ(rec.sec_import_result_contract_version, 0u);
    EXPECT_EQ(rec.sec_import_evidence_kind,
              static_cast<int>(SecImportEvidenceKind::ContractUnknown));
    EXPECT_TRUE(rec.import_invocation);  // “可能已调用”，不得推断为从未调用
}

TEST(V2cKeyProvisioningStoreTest, SaveLoadRoundTripSecEvidenceKinds) {
    auto root = temp_root();
    V2cKeyProvisioningRecord rec = make_v2_record("kp-seckind");
    rec.sec_import_evidence_kind =
        static_cast<int>(SecImportEvidenceKind::OutcomeUnknown);
    rec.import_invocation = false;
    {
        V2cKeyProvisioningStore store(root);
        store.save(rec);
    }
    V2cKeyProvisioningStore store(root);
    auto loaded = store.load();
    ASSERT_TRUE(loaded.valid);
    EXPECT_EQ(loaded.sec_import_evidence_kind,
              static_cast<int>(SecImportEvidenceKind::OutcomeUnknown));
    EXPECT_FALSE(loaded.import_invocation);  // v3 显式 false 不覆盖为 true
    // 越界 kind 防御：非法值归 ContractUnknown。
    V2cKeyProvisioningRecord bad = make_v2_record("kp-badkind");
    bad.sec_import_evidence_kind = 99;
    auto root2 = temp_root();
    {
        V2cKeyProvisioningStore store2(root2);
        store2.save(bad);
    }
    V2cKeyProvisioningStore store2(root2);
    EXPECT_EQ(store2.load().sec_import_evidence_kind,
              static_cast<int>(SecImportEvidenceKind::ContractUnknown));
}

TEST(V2cKeyProvisioningStoreTest, LegacyRecordMarkedSnapshotUnknown) {
    auto root = temp_root();
    // 用原始 framework Store 写入旧版多键格式（模拟 v1 记录）。
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", root);
        raw.save<std::string>("keyprov.v2c.present", "1");
        raw.save<std::string>("keyprov.v2c.request_id", "kp-legacy");
        raw.save<std::string>("keyprov.v2c.idempotency_digest", "deadbeef");
        raw.save<std::string>("keyprov.v2c.state", "WAIT_RESPONSE");
        raw.save<std::string>("keyprov.v2c.purposes", "UPLINK_AEAD,DOWNLINK_AEAD");
        raw.save<std::string>("keyprov.v2c.business_key_versions", "UPLINK_AEAD=3,DOWNLINK_AEAD=3");
        raw.save<std::string>("keyprov.v2c.attempt_count", "2");
        raw.save<std::string>("keyprov.v2c.deadline_ms", "0");
        raw.save<std::string>("keyprov.v2c.last_error", "response_timeout");
        raw.save<std::string>("keyprov.v2c.updated_at_ms", "123");
        raw.save<std::string>("keyprov.v2c.cloud_session_generation", "9");
        raw.flush();
    }
    V2cKeyProvisioningStore store(root);
    auto rec = store.load();
    ASSERT_TRUE(rec.valid);
    EXPECT_EQ(rec.request_id, "kp-legacy");
    EXPECT_EQ(rec.state, "WAIT_RESPONSE");
    EXPECT_EQ(rec.attempt_count, 2u);
    EXPECT_TRUE(rec.legacy_snapshot_unknown);  // 缺 snapshot/fingerprint
    EXPECT_EQ(rec.fingerprint_version, 0u);
    ASSERT_EQ(rec.business_key_versions.size(), 2u);
    EXPECT_EQ(rec.business_key_versions[0].second, 3u);
}

TEST(V2cKeyProvisioningStoreTest, V2RecordWithoutFingerprintIsLegacy) {
    auto root = temp_root();
    V2cKeyProvisioningRecord rec = make_v2_record("kp-nofp");
    rec.fingerprint_version = 0;
    rec.attempt_fingerprint.clear();
    {
        V2cKeyProvisioningStore store(root);
        store.save(rec);
    }
    V2cKeyProvisioningStore store(root);
    auto loaded = store.load();
    ASSERT_TRUE(loaded.valid);
    EXPECT_TRUE(loaded.legacy_snapshot_unknown);
}

TEST(V2cKeyProvisioningStoreTest, UnknownSchemaVersionIsLegacy) {
    auto root = temp_root();
    V2cKeyProvisioningRecord rec = make_v2_record("kp-badver");
    rec.schema_version = 999;  // 未知更高版本不得降级解释
    {
        V2cKeyProvisioningStore store(root);
        store.save(rec);
    }
    V2cKeyProvisioningStore store(root);
    auto loaded = store.load();
    ASSERT_TRUE(loaded.valid);
    EXPECT_TRUE(loaded.legacy_snapshot_unknown);
}

TEST(V2cKeyProvisioningStoreTest, ClearRemovesRecord) {
    auto root = temp_root();
    V2cKeyProvisioningStore store(root);
    store.save(make_v2_record("kp-xyz"));
    ASSERT_TRUE(store.load().valid);
    store.clear();
    EXPECT_FALSE(store.load().valid);
}

TEST(V2cKeyProvisioningStoreTest, StoreGenerationPersisted) {
    auto root = temp_root();
    auto rec = make_v2_record("kp-gen");
    rec.store_generation = 42;
    V2cKeyProvisioningStore store(root);
    store.save(rec);
    EXPECT_EQ(store.load().store_generation, 42u);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
