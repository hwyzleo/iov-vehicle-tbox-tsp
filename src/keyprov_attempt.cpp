// TBOX-TSP-DSN-CR-013 §3/§4/§20: Keyprov 不可变 Attempt 快照与 fingerprint 实现。
#include "keyprov_attempt.h"

#include "keyprov_release_lock.h"

#include <algorithm>
#include <cstring>

namespace tbox {
namespace tsp {

namespace {

constexpr const char* kFingerprintTagV1 = "TSP-KEYPROV-ATTEMPT-V1";
constexpr const char* kProtocolLockTagV1 = "TSP-KEYPROV-PROTOCOL-LOCK-V1";

// ---- 定宽定序（大端序）canonical 编码工具 ----
void append_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

void append_u64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

// u64 长度前缀 + 原始字节（字符串/字节串统一）。
void append_bytes(std::vector<uint8_t>& b, const uint8_t* data, size_t len) {
    append_u64(b, static_cast<uint64_t>(len));
    b.insert(b.end(), data, data + len);
}

void append_bytes(std::vector<uint8_t>& b, const std::vector<uint8_t>& v) {
    append_bytes(b, v.data(), v.size());
}

void append_str(std::vector<uint8_t>& b, const std::string& s) {
    append_bytes(b, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// 排序去重 int 集合（32-bit 元素）。
void sort_dedup_int(std::vector<int>& v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
}

// sorted (purpose, version) 去重（按 purpose 排序；同 purpose 保留最新）。
void sort_dedup_versions(std::vector<std::pair<int, uint64_t>>& v) {
    std::sort(v.begin(), v.end(),
              [](const auto& a, const auto& b) {
                  if (a.first != b.first) return a.first < b.first;
                  return a.second < b.second;
              });
    std::vector<std::pair<int, uint64_t>> out;
    for (const auto& p : v) {
        if (!out.empty() && out.back().first == p.first) {
            out.back().second = p.second;  // 同 purpose 保留最大版本
        } else {
            out.push_back(p);
        }
    }
    v.swap(out);
}

// 协议锁版 field(name, value) = u64 len(name) || name || u64 len(value) || value。
void append_field(std::vector<uint8_t>& b, const char* name,
                  const uint8_t* value, size_t value_len) {
    append_str(b, name);
    append_bytes(b, value, value_len);
}

// 16 进制串 -> 原始字节（失败返回空）。
std::vector<uint8_t> decode_hex(const std::string& in) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (in.size() % 2 != 0) return out;
    for (size_t i = 0; i + 1 < in.size(); i += 2) {
        int hi = nib(in[i]);
        int lo = nib(in[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return out;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

bool digest_raw(const std::string& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> tmp;
    if (!keyprov_normalize_digest(in, tmp) || tmp.empty()) {
        return false;
    }
    out.swap(tmp);
    return true;
}

bool digest_raw_32(const std::string& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> tmp;
    if (!keyprov_normalize_digest(in, tmp) || tmp.size() != 32) {
        return false;
    }
    out.swap(tmp);
    return true;
}

} // namespace

// ============================================================
// 协议锁版受控摘要（CR-013 §4 用户裁决口径）
// ============================================================
KeyprovFingerprint keyprov_protocol_lock_digest_v1() {
    std::vector<uint8_t> b;
    // 版本 tag（无长度前缀，作为整体标识）
    b.insert(b.end(),
             reinterpret_cast<const uint8_t*>(kProtocolLockTagV1),
             reinterpret_cast<const uint8_t*>(kProtocolLockTagV1) +
                 std::strlen(kProtocolLockTagV1));
    // descriptorSetHash 归一化后解码为 32B raw；失败时按固定零向量（release 门禁
    // 已 fail-closed，此处仅为保持 digest 计算稳定）。
    std::vector<uint8_t> desc = decode_hex(keyprov_lock::kDescriptorSetHash);
    if (desc.size() != 32) desc.assign(32, 0x00);
    append_field(b, "release",
                 reinterpret_cast<const uint8_t*>(keyprov_lock::kParProtoRelease),
                 std::strlen(keyprov_lock::kParProtoRelease));
    append_field(b, "descriptor", desc.data(), desc.size());
    append_field(b, "registry",
                 reinterpret_cast<const uint8_t*>(keyprov_lock::kCanonicalRegistry),
                 std::strlen(keyprov_lock::kCanonicalRegistry));
    append_field(b, "golden",
                 reinterpret_cast<const uint8_t*>(keyprov_lock::kGoldenVectorSetId),
                 std::strlen(keyprov_lock::kGoldenVectorSetId));
    return tbox::fw::hash::sha256(
        tbox::fw::hash::ByteView{b.data(), b.size()});
}

uint32_t keyprov_protocol_lock_digest_version() { return 1; }

// ============================================================
// attemptFingerprintV1（CR §4 canonical 编码）
// ============================================================
bool keyprov_compute_attempt_fingerprint_v1(
    const KeyprovAttemptSnapshot& snapshot,
    KeyprovFingerprint& out,
    std::string& err) {
    if (snapshot.business_domain.empty() ||
        snapshot.business_domain != kKeyprovBusinessDomainV2c) {
        err = "snapshot_domain_invalid";
        return false;
    }
    if (snapshot.purposes.empty() ||
        snapshot.purposes.size() > kKeyprovMaxItems) {
        err = "snapshot_purposes_invalid";
        return false;
    }
    if (snapshot.device_identity_digest.size() != 32 ||
        snapshot.recipient_certificate_digest.size() != 32 ||
        snapshot.protocol_lock_digest.size() != 32) {
        err = "snapshot_digest_invalid";
        return false;
    }

    std::vector<uint8_t> b;
    b.insert(b.end(),
             reinterpret_cast<const uint8_t*>(kFingerprintTagV1),
             reinterpret_cast<const uint8_t*>(kFingerprintTagV1) +
                 std::strlen(kFingerprintTagV1));

    // domain（长度前缀）
    append_str(b, snapshot.business_domain);

    // purposeCount || each(sorted purpose)（内部规范化：排序去重，保证 canonical）
    std::vector<int> purposes = snapshot.purposes;
    sort_dedup_int(purposes);
    append_u32(b, static_cast<uint32_t>(purposes.size()));
    for (int p : purposes) {
        append_u32(b, static_cast<uint32_t>(p));
    }

    // versionCount || each(purpose, version)（按 purpose 排序去重）
    std::vector<std::pair<int, uint64_t>> versions = snapshot.current_versions;
    sort_dedup_versions(versions);
    append_u32(b, static_cast<uint32_t>(versions.size()));
    for (const auto& kv : versions) {
        append_u32(b, static_cast<uint32_t>(kv.first));
        append_u64(b, kv.second);
    }

    // deviceIdentityDigest / recipientCertificateDigest（32B raw）
    b.insert(b.end(), snapshot.device_identity_digest.begin(),
             snapshot.device_identity_digest.end());
    b.insert(b.end(), snapshot.recipient_certificate_digest.begin(),
             snapshot.recipient_certificate_digest.end());

    // canonicalSuiteSet / canonicalFormatSet（内部排序去重）
    std::vector<int> suites = snapshot.wrapping_suites;
    sort_dedup_int(suites);
    std::vector<int> formats = snapshot.envelope_formats;
    sort_dedup_int(formats);
    append_u32(b, static_cast<uint32_t>(suites.size()));
    for (int s : suites) {
        append_u32(b, static_cast<uint32_t>(s));
    }
    append_u32(b, static_cast<uint32_t>(formats.size()));
    for (int f : formats) {
        append_u32(b, static_cast<uint32_t>(f));
    }

    // protocolLockDigest（32B raw）
    b.insert(b.end(), snapshot.protocol_lock_digest.begin(),
             snapshot.protocol_lock_digest.end());

    out = tbox::fw::hash::sha256(
        tbox::fw::hash::ByteView{b.data(), b.size()});
    return true;
}

std::string keyprov_fingerprint_to_hex(const KeyprovFingerprint& fp) {
    return tbox::fw::hash::sha256_hex(
        tbox::fw::hash::ByteView{fp.data(), fp.size()});
}

bool keyprov_fingerprint_equal(const KeyprovFingerprint& a,
                               const KeyprovFingerprint& b) {
    return a == b;
}

// ============================================================
// snapshot 构造
// ============================================================
bool keyprov_build_attempt_snapshot(
    const std::string& business_domain,
    const std::vector<std::string>& purposes,
    const KeyprovSessionIdentity& identity,
    const std::vector<tbox::sec::BusinessKeyStatus>& sec_status,
    const KeyprovFingerprint& protocol_lock_digest,
    KeyprovAttemptSnapshot& out,
    std::string& err) {
    if (business_domain != kKeyprovBusinessDomainV2c) {
        err = "snapshot_domain_invalid";
        return false;
    }
    std::string id_reason;
    if (!keyprov_validate_identity(identity, id_reason)) {
        err = id_reason;
        return false;
    }

    KeyprovAttemptSnapshot s;
    s.business_domain = business_domain;

    // purpose 集：字符串 -> 枚举，拒绝 0/未知，排序去重。
    for (const auto& p : purposes) {
        int v = keyprov_purpose_from_string(p);
        if (v == 0) {
            err = "snapshot_purpose_unknown";
            return false;
        }
        s.purposes.push_back(v);
    }
    sort_dedup_int(s.purposes);
    if (s.purposes.empty() || s.purposes.size() > kKeyprovMaxItems) {
        err = "snapshot_purposes_invalid";
        return false;
    }

    // current_versions：仅保留本 attempt purpose 集的项；排序去重。
    for (const auto& item : sec_status) {
        int pv = keyprov_purpose_from_string(item.purpose);
        if (pv == 0) continue;
        if (std::find(s.purposes.begin(), s.purposes.end(), pv) ==
            s.purposes.end()) {
            continue;
        }
        s.current_versions.emplace_back(pv, item.business_key_version);
    }
    sort_dedup_versions(s.current_versions);

    // 身份受控摘要：device identity digest 与 recipient cert digest（Wrapped Key
    // 接收者绑定）必须可见且为 32B；certificate_ref 引用摘要另存一份供恢复核对。
    if (!digest_raw_32(identity.device_identity_digest,
                       s.device_identity_digest)) {
        err = "snapshot_device_identity_digest_invalid";
        return false;
    }
    if (!digest_raw_32(identity.certificate_ref,
                       s.recipient_certificate_digest)) {
        err = "snapshot_recipient_certificate_digest_invalid";
        return false;
    }
    {
        auto cert_digest = tbox::fw::hash::sha256(tbox::fw::hash::ByteView{
            reinterpret_cast<const uint8_t*>(identity.certificate_ref.data()),
            identity.certificate_ref.size()});
        s.certificate_ref_digest.assign(cert_digest.begin(), cert_digest.end());
    }

    // suite/format：首期唯一受支持组合（与 do_request 发送口径一致，属于协议锁版
    // 常量，不来自运行时配置）。
    s.wrapping_suites = {
        keyprov_wrapping_suite_from_string(kKeyprovSuiteEcdhEsP256)};
    s.envelope_formats = {kKeyProvEnvelopeFormatEcdhEsP256V1};
    sort_dedup_int(s.wrapping_suites);
    sort_dedup_int(s.envelope_formats);
    if (s.wrapping_suites.size() != 1 ||
        s.wrapping_suites[0] == 0 ||
        s.envelope_formats.size() != 1 ||
        s.envelope_formats[0] != kKeyProvEnvelopeFormatEcdhEsP256V1) {
        err = "snapshot_suite_format_invalid";
        return false;
    }

    s.protocol_lock_digest.assign(protocol_lock_digest.begin(),
                                  protocol_lock_digest.end());
    if (s.protocol_lock_digest.size() != 32) {
        err = "snapshot_protocol_lock_digest_invalid";
        return false;
    }

    out = std::move(s);
    return true;
}

// ============================================================
// 变化维度判定
// ============================================================
const char* keyprov_attempt_change_dimension_to_string(
    AttemptChangeDimension d) {
    switch (d) {
        case AttemptChangeDimension::None:            return "NONE";
        case AttemptChangeDimension::Purposes:        return "PURPOSES";
        case AttemptChangeDimension::CurrentVersions: return "CURRENT_VERSIONS";
        case AttemptChangeDimension::DeviceIdentity:  return "DEVICE_IDENTITY";
        case AttemptChangeDimension::Certificate:     return "CERTIFICATE";
        case AttemptChangeDimension::SuiteFormat:     return "SUITE_FORMAT";
        case AttemptChangeDimension::ProtocolLock:    return "PROTOCOL_LOCK";
        case AttemptChangeDimension::Unknown:         return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

AttemptChangeDimension keyprov_attempt_change_dimension(
    const KeyprovAttemptSnapshot& frozen,
    const KeyprovAttemptSnapshot& candidate) {
    if (frozen.business_domain != candidate.business_domain ||
        frozen.purposes != candidate.purposes) {
        return AttemptChangeDimension::Purposes;
    }
    if (frozen.current_versions != candidate.current_versions) {
        return AttemptChangeDimension::CurrentVersions;
    }
    if (frozen.device_identity_digest != candidate.device_identity_digest) {
        return AttemptChangeDimension::DeviceIdentity;
    }
    if (frozen.recipient_certificate_digest !=
            candidate.recipient_certificate_digest ||
        frozen.certificate_ref_digest != candidate.certificate_ref_digest) {
        return AttemptChangeDimension::Certificate;
    }
    if (frozen.wrapping_suites != candidate.wrapping_suites ||
        frozen.envelope_formats != candidate.envelope_formats) {
        return AttemptChangeDimension::SuiteFormat;
    }
    if (frozen.protocol_lock_digest != candidate.protocol_lock_digest) {
        return AttemptChangeDimension::ProtocolLock;
    }
    return AttemptChangeDimension::None;
}

// ============================================================
// 806095 / 幂等冲突分类器（用户裁决口径）
// ============================================================
bool keyprov_is_idempotency_conflict(const KeyProvProtocolError& error) {
    // canonical：action 承载 VAGW 对外 reason
    if (error.action == "KEYPROV_IDEMPOTENCY_CONFLICT") return true;
    // 兼容映射：code 承载同一 reason
    if (error.code == "KEYPROV_IDEMPOTENCY_CONFLICT") return true;
    // VMD 原始码兼容（旧链路/透传）
    if (error.code == "806095") return true;
    return false;
}

// ============================================================
// CR-015 §22.2：导入意图处置枚举字符串映射
// ============================================================
const char* keyprov_import_invocation_resolution_to_string(
    ImportInvocationResolution r) {
    switch (r) {
        case ImportInvocationResolution::UNRESOLVED: return "UNRESOLVED";
        case ImportInvocationResolution::NO_SIDE_EFFECT_PROVEN: return "NO_SIDE_EFFECT_PROVEN";
        case ImportInvocationResolution::HARD_CONFLICT: return "HARD_CONFLICT";
        default: return "?";
    }
}

bool keyprov_import_invocation_resolution_from_string(
    const std::string& s, ImportInvocationResolution& out) {
    static const ImportInvocationResolution all[] = {
        ImportInvocationResolution::UNRESOLVED,
        ImportInvocationResolution::NO_SIDE_EFFECT_PROVEN,
        ImportInvocationResolution::HARD_CONFLICT};
    for (auto r : all) {
        if (s == keyprov_import_invocation_resolution_to_string(r)) {
            out = r;
            return true;
        }
    }
    return false;
}

} // namespace tsp
} // namespace tbox
