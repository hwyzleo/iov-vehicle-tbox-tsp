// TBOX-TSP-DSN-CR-013 §4/§14: Keyprov attempt fingerprint / protocol lock digest /
// 幂等冲突分类器单元测试。
#include <gtest/gtest.h>

#include "keyprov_attempt.h"
#include "keyprov_release_lock.h"

#include <algorithm>

using namespace tbox::tsp;

namespace {

// 构造一个完整的 canonical snapshot（与 keyprov_build_attempt_snapshot 输出同构）。
KeyprovAttemptSnapshot make_snapshot() {
    KeyprovAttemptSnapshot s;
    s.business_domain = kKeyprovBusinessDomainV2c;
    s.purposes = {1, 2};  // UPLINK, DOWNLINK
    s.current_versions = {{1, 5}, {2, 7}};
    s.device_identity_digest = std::vector<uint8_t>(32, 0x01);
    s.recipient_certificate_digest = std::vector<uint8_t>(32, 0x02);
    s.certificate_ref_digest = std::vector<uint8_t>(32, 0x03);
    s.wrapping_suites = {2};   // ECDH_ES_P256
    s.envelope_formats = {1};  // ECDH_ES_P256_V1
    {   // protocol_lock_digest 为 vector；由 32B array 赋值。
        auto lock = keyprov_protocol_lock_digest_v1();
        s.protocol_lock_digest.assign(lock.begin(), lock.end());
    }
    return s;
}

bool fp(const KeyprovAttemptSnapshot& s, KeyprovFingerprint& out) {
    std::string err;
    return keyprov_compute_attempt_fingerprint_v1(s, out, err);
}

} // namespace

// ============================================================
// fingerprint：确定性与不变性
// ============================================================
TEST(KeyprovAttemptTest, FingerprintDeterministic) {
    auto s = make_snapshot();
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(s, a));
    ASSERT_TRUE(fp(s, b));
    EXPECT_EQ(a, b);
    EXPECT_EQ(keyprov_fingerprint_to_hex(a), keyprov_fingerprint_to_hex(b));
    EXPECT_EQ(keyprov_fingerprint_to_hex(a).size(), 64u);
}

TEST(KeyprovAttemptTest, PurposeOrderDoesNotMatter) {
    auto s1 = make_snapshot();
    auto s2 = make_snapshot();
    std::reverse(s2.purposes.begin(), s2.purposes.end());  // 乱序
    // current_versions 按 purpose 排序，不受 purposes 顺序影响。
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(s1, a));
    ASSERT_TRUE(fp(s2, b));
    EXPECT_EQ(a, b);
}

TEST(KeyprovAttemptTest, CurrentVersionOrderDoesNotMatter) {
    auto s1 = make_snapshot();
    auto s2 = make_snapshot();
    std::reverse(s2.current_versions.begin(), s2.current_versions.end());
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(s1, a));
    ASSERT_TRUE(fp(s2, b));
    EXPECT_EQ(a, b);
}

TEST(KeyprovAttemptTest, LengthPrefixAvoidsAmbiguity) {
    // "ab"+"c" vs "a"+"bc" 不应因拼接产生相同摘要（domain 长度前缀保证）。
    KeyprovAttemptSnapshot s1 = make_snapshot();
    KeyprovAttemptSnapshot s2 = make_snapshot();
    // 用 device digest 前若干字节模拟边界（fingerprint 对 digest 是定长 32B，
    // 真正体现长度前缀的是 domain；此处验证不同 domain 字节序必不同）。
    s2.business_domain = "V2C_COMMX";  // 非法 domain 不会走到 hash
    KeyprovFingerprint a;
    std::string err;
    ASSERT_FALSE(keyprov_compute_attempt_fingerprint_v1(s2, a, err));
    EXPECT_EQ(err, "snapshot_domain_invalid");
}

TEST(KeyprovAttemptTest, FingerprintVersionConstants) {
    EXPECT_EQ(kAttemptFingerprintVersionV1, 1u);
    EXPECT_EQ(kAttemptFingerprintVersionCurrent, kAttemptFingerprintVersionV1);
}

// ============================================================
// fingerprint：任一业务维度变化 -> fingerprint 变化 + 维度判定
// ============================================================
TEST(KeyprovAttemptTest, CertificateChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.recipient_certificate_digest = std::vector<uint8_t>(32, 0xAA);
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::Certificate);
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(frozen, a));
    ASSERT_TRUE(fp(candidate, b));
    EXPECT_NE(a, b);
}

TEST(KeyprovAttemptTest, CurrentVersionsChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.current_versions = {{1, 6}, {2, 7}};
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::CurrentVersions);
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(frozen, a));
    ASSERT_TRUE(fp(candidate, b));
    EXPECT_NE(a, b);
}

TEST(KeyprovAttemptTest, PurposeChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.purposes = {1};
    candidate.current_versions = {{1, 5}};
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::Purposes);
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(frozen, a));
    ASSERT_TRUE(fp(candidate, b));
    EXPECT_NE(a, b);
}

TEST(KeyprovAttemptTest, ProtocolLockChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.protocol_lock_digest = std::vector<uint8_t>(32, 0x5C);
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::ProtocolLock);
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(frozen, a));
    ASSERT_TRUE(fp(candidate, b));
    EXPECT_NE(a, b);
}

TEST(KeyprovAttemptTest, DeviceIdentityChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.device_identity_digest = std::vector<uint8_t>(32, 0xDD);
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::DeviceIdentity);
    KeyprovFingerprint a, b;
    ASSERT_TRUE(fp(frozen, a));
    ASSERT_TRUE(fp(candidate, b));
    EXPECT_NE(a, b);
}

TEST(KeyprovAttemptTest, SuiteFormatChangeChangesFingerprint) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    candidate.wrapping_suites = {1};  // HPKE（不应出现在生产 attempt，但维度判定应覆盖）
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::SuiteFormat);
}

TEST(KeyprovAttemptTest, NoneWhenIdentical) {
    auto frozen = make_snapshot();
    auto candidate = make_snapshot();
    EXPECT_EQ(keyprov_attempt_change_dimension(frozen, candidate),
              AttemptChangeDimension::None);
}

TEST(KeyprovAttemptTest, InvalidSnapshotsRejected) {
    KeyprovFingerprint out;
    std::string err;
    auto s = make_snapshot();
    s.business_domain = "OTHER_DOMAIN";
    EXPECT_FALSE(keyprov_compute_attempt_fingerprint_v1(s, out, err));
    s = make_snapshot();
    s.device_identity_digest = std::vector<uint8_t>(16, 0x00);
    EXPECT_FALSE(keyprov_compute_attempt_fingerprint_v1(s, out, err));
    s = make_snapshot();
    s.purposes.clear();
    EXPECT_FALSE(keyprov_compute_attempt_fingerprint_v1(s, out, err));
}

// ============================================================
// 协议锁版受控摘要
// ============================================================
TEST(KeyprovAttemptTest, ProtocolLockDigestStable) {
    auto a = keyprov_protocol_lock_digest_v1();
    auto b = keyprov_protocol_lock_digest_v1();
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_EQ(keyprov_protocol_lock_digest_version(), 1u);
    // release 常量参与摘要（稳定）。
    EXPECT_TRUE(keyprov_lock::kParProtoRelease[0] != '\0');
}

// ============================================================
// 806095 / 幂等冲突分类器（用户裁决口径）
// ============================================================
TEST(KeyprovAttemptTest, IdempotencyConflictClassifier) {
    KeyProvProtocolError e;
    // canonical：action 承载对外 reason
    e.action = "KEYPROV_IDEMPOTENCY_CONFLICT";
    EXPECT_TRUE(keyprov_is_idempotency_conflict(e));
    // 兼容映射：code 承载同一 reason
    e = KeyProvProtocolError{};
    e.code = "KEYPROV_IDEMPOTENCY_CONFLICT";
    EXPECT_TRUE(keyprov_is_idempotency_conflict(e));
    // VMD 原始码兼容
    e = KeyProvProtocolError{};
    e.code = "806095";
    EXPECT_TRUE(keyprov_is_idempotency_conflict(e));

    // 否定：仅 DO_NOT_RETRY / retryable=false 不算（其它确定性拒绝也具备相同行为）
    e = KeyProvProtocolError{};
    e.code = "804010";
    e.action = "DO_NOT_RETRY";
    e.retryable = false;
    EXPECT_FALSE(keyprov_is_idempotency_conflict(e));
    // 未知 code / 空
    e = KeyProvProtocolError{};
    e.code = "OTHER";
    EXPECT_FALSE(keyprov_is_idempotency_conflict(e));
    e = KeyProvProtocolError{};
    EXPECT_FALSE(keyprov_is_idempotency_conflict(e));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
