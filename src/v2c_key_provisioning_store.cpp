// TBOX-TSP-DSN-CR-010 §5 / CR-013 §10: V2C keyprov 非敏感状态持久化实现。
#include "v2c_key_provisioning_store.h"

#include "log_adapter.h"
#include "sec_business_key_facade.h"

#include <nlohmann/json.hpp>

#include <sstream>

namespace tbox {
namespace tsp {

namespace {

constexpr const char* kStateKey = "keyprov.v2c.attempt.v2";  // 新聚合键（与 legacy 键不冲突）

// ---- legacy 多键（v1 格式，仍可读） ----
constexpr const char* kLegacyPresent = "keyprov.v2c.present";
constexpr const char* kLegacyRequestId = "keyprov.v2c.request_id";
constexpr const char* kLegacyIdemDigest = "keyprov.v2c.idempotency_digest";
constexpr const char* kLegacyState = "keyprov.v2c.state";
constexpr const char* kLegacyPurposes = "keyprov.v2c.purposes";
constexpr const char* kLegacyVersions = "keyprov.v2c.business_key_versions";
constexpr const char* kLegacyAttempt = "keyprov.v2c.attempt_count";
constexpr const char* kLegacyDeadline = "keyprov.v2c.deadline_ms";
constexpr const char* kLegacyLastError = "keyprov.v2c.last_error";
constexpr const char* kLegacyUpdatedAt = "keyprov.v2c.updated_at_ms";
constexpr const char* kLegacyCloudGen = "keyprov.v2c.cloud_session_generation";

std::string hex_encode(const std::vector<uint8_t>& v) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v) {
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (s.size() % 2 != 0) return out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = nib(s[i]);
        int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return out;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string join(const std::vector<std::string>& v, char sep) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out.push_back(sep);
        out += v[i];
    }
    return out;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    if (s.empty()) return out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

// ---- JSON 序列化（v2 聚合） ----
nlohmann::json snapshot_to_json(const KeyprovAttemptSnapshot& s) {
    nlohmann::json j = nlohmann::json::object();
    j["business_domain"] = s.business_domain;
    j["purposes"] = s.purposes;
    nlohmann::json versions = nlohmann::json::array();
    for (const auto& kv : s.current_versions) {
        versions.push_back({kv.first, kv.second});
    }
    j["current_versions"] = versions;
    j["device_identity_digest"] = hex_encode(s.device_identity_digest);
    j["recipient_certificate_digest"] = hex_encode(s.recipient_certificate_digest);
    j["certificate_ref_digest"] = hex_encode(s.certificate_ref_digest);
    j["wrapping_suites"] = s.wrapping_suites;
    j["envelope_formats"] = s.envelope_formats;
    j["protocol_lock_digest"] = hex_encode(s.protocol_lock_digest);
    return j;
}

KeyprovAttemptSnapshot snapshot_from_json(const nlohmann::json& j) {
    KeyprovAttemptSnapshot s;
    s.business_domain = j.value("business_domain", std::string{});
    for (const auto& v : j.value("purposes", nlohmann::json::array())) {
        s.purposes.push_back(v.get<int>());
    }
    for (const auto& arr : j.value("current_versions", nlohmann::json::array())) {
        if (arr.size() == 2) {
            s.current_versions.emplace_back(arr[0].get<int>(),
                                            arr[1].get<uint64_t>());
        }
    }
    s.device_identity_digest = hex_decode(j.value("device_identity_digest", std::string{}));
    s.recipient_certificate_digest =
        hex_decode(j.value("recipient_certificate_digest", std::string{}));
    s.certificate_ref_digest =
        hex_decode(j.value("certificate_ref_digest", std::string{}));
    for (const auto& v : j.value("wrapping_suites", nlohmann::json::array())) {
        s.wrapping_suites.push_back(v.get<int>());
    }
    for (const auto& v : j.value("envelope_formats", nlohmann::json::array())) {
        s.envelope_formats.push_back(v.get<int>());
    }
    s.protocol_lock_digest = hex_decode(j.value("protocol_lock_digest", std::string{}));
    return s;
}

nlohmann::json record_to_json(const V2cKeyProvisioningRecord& r) {
    nlohmann::json j = nlohmann::json::object();
    j["schema_version"] = r.schema_version;
    j["fingerprint_version"] = r.fingerprint_version;
    j["attempt_fingerprint"] = r.attempt_fingerprint;
    j["request_id"] = r.request_id;
    j["idempotency_digest"] = r.idempotency_digest;
    j["state"] = r.state;
    j["submission"] = r.submission;
    j["snapshot"] = snapshot_to_json(r.snapshot);
    j["attempt_count"] = r.attempt_count;
    j["deadline_ms"] = r.deadline_ms;
    j["last_error"] = r.last_error;
    j["updated_at_ms"] = r.updated_at_ms;
    j["cloud_session_generation"] = r.cloud_session_generation;
    j["supersedes_request_id"] = r.supersedes_request_id;
    j["superseded_by_request_id"] = r.superseded_by_request_id;
    j["blocked_reason"] = r.blocked_reason;
    j["store_generation"] = r.store_generation;
    j["terminalized_request_ids"] = r.terminalized_request_ids;
    // ---- CR-014 v3：SEC import result 证据（非敏感） ----
    j["sec_import_result_contract_version"] =
        r.sec_import_result_contract_version;
    j["sec_import_evidence_kind"] = r.sec_import_evidence_kind;
    j["sec_evidence_observed_store_generation"] =
        r.sec_evidence_observed_store_generation;
    j["sec_evidence_observed_at_ms"] = r.sec_evidence_observed_at_ms;
    j["import_invocation"] = r.import_invocation;
    return j;
}

} // namespace

V2cKeyProvisioningStore::V2cKeyProvisioningStore(const std::string& store_root)
    : store_(hwyz::store::Store::open("tsp", store_root)) {
}

V2cKeyProvisioningRecord V2cKeyProvisioningStore::load() const {
    V2cKeyProvisioningRecord r;
    if (!store_.isReady()) return r;

    // 1) v2 聚合记录
    if (store_.has(kStateKey)) {
        try {
            std::string raw = store_.loadOr<std::string>(kStateKey, "");
            if (raw.empty()) return V2cKeyProvisioningRecord{};
            nlohmann::json j = nlohmann::json::parse(raw);
            r.valid = true;
            r.schema_version = j.value("schema_version", 0u);
            r.fingerprint_version = j.value("fingerprint_version", 0u);
            r.attempt_fingerprint = j.value("attempt_fingerprint", std::string{});
            r.request_id = j.value("request_id", std::string{});
            r.idempotency_digest = j.value("idempotency_digest", std::string{});
            r.state = j.value("state", std::string{});
            r.submission = j.value("submission", std::string{});
            if (j.contains("snapshot") && j["snapshot"].is_object()) {
                r.snapshot = snapshot_from_json(j["snapshot"]);
            }
            r.attempt_count = j.value("attempt_count", 0u);
            r.deadline_ms = j.value("deadline_ms", static_cast<int64_t>(0));
            r.last_error = j.value("last_error", std::string{});
            r.updated_at_ms = j.value("updated_at_ms", static_cast<int64_t>(0));
            r.cloud_session_generation = j.value("cloud_session_generation", 0ull);
            r.supersedes_request_id = j.value("supersedes_request_id", std::string{});
            r.superseded_by_request_id = j.value("superseded_by_request_id", std::string{});
            r.blocked_reason = j.value("blocked_reason", std::string{});
            r.store_generation = j.value("store_generation", 0ull);
            for (const auto& v : j.value("terminalized_request_ids",
                                         nlohmann::json::array())) {
                r.terminalized_request_ids.push_back(v.get<std::string>());
            }
            // ---- CR-014 v3：SEC import result 证据读取（缺字段保守默认） ----
            r.sec_import_result_contract_version =
                j.value("sec_import_result_contract_version", 0u);
            const int ev_kind =
                j.value("sec_import_evidence_kind",
                        static_cast<int>(tbox::tsp::SecImportEvidenceKind::ContractUnknown));
            r.sec_import_evidence_kind =
                (ev_kind >= 0 && ev_kind <= 5)
                    ? ev_kind
                    : static_cast<int>(tbox::tsp::SecImportEvidenceKind::ContractUnknown);
            r.sec_evidence_observed_store_generation =
                j.value("sec_evidence_observed_store_generation", 0ull);
            r.sec_evidence_observed_at_ms =
                j.value("sec_evidence_observed_at_ms", static_cast<int64_t>(0));
            // 旧记录（v2 及以下）缺 import_invocation 字段 -> 默认 true
            // （"可能已调用"，保持阻断），不得推断为"从未调用"。
            if (j.contains("import_invocation")) {
                r.import_invocation = j.value("import_invocation", false);
            } else {
                r.import_invocation = true;
            }
            // schema/fingerprint 版本守卫：未知版本不得降级解释（CR-013 §4/§10）。
            if (r.schema_version > kV2cStoreSchemaVersion ||
                (r.fingerprint_version > kAttemptFingerprintVersionCurrent)) {
                r.legacy_snapshot_unknown = true;
            }
            // 缺 fingerprint 的 v2 记录（防御）按 legacy 处理。
            if (r.fingerprint_version == 0 || r.attempt_fingerprint.empty()) {
                r.legacy_snapshot_unknown = true;
            }
            // 便捷镜像（与 snapshot 一致）。
            r.purposes.clear();
            for (int p : r.snapshot.purposes) {
                r.purposes.push_back(keyprov_purpose_to_string(p));
            }
            r.business_key_versions.clear();
            for (const auto& kv : r.snapshot.current_versions) {
                r.business_key_versions.emplace_back(
                    keyprov_purpose_to_string(kv.first), kv.second);
            }
            r.valid = r.valid && !r.request_id.empty();
            return r;
        } catch (const std::exception& e) {
            LogAdapter::keyprov().warn(
                "tsp.keyprov.store.load_failed",
                "keyprov 持久化状态读取异常，按无记录处理", {
                    {"error", tbox::fw::log::FieldValue::makeString(e.what())}
                });
            return V2cKeyProvisioningRecord{};
        }
    }

    // 2) legacy 多键记录（v1 格式）：保留旧事实，标记 snapshot unknown。
    if (store_.has(kLegacyPresent)) {
        try {
            V2cKeyProvisioningRecord r2;
            r2.valid = store_.loadOr<std::string>(kLegacyPresent, "0") == "1";
            r2.request_id = store_.loadOr<std::string>(kLegacyRequestId, "");
            r2.idempotency_digest = store_.loadOr<std::string>(kLegacyIdemDigest, "");
            r2.state = store_.loadOr<std::string>(kLegacyState, "");
            r2.purposes = split(store_.loadOr<std::string>(kLegacyPurposes, ""), ',');
            std::vector<std::string> vs =
                split(store_.loadOr<std::string>(kLegacyVersions, ""), ',');
            for (const auto& part : vs) {
                auto eq = part.find('=');
                if (eq == std::string::npos) continue;
                uint64_t val = 0;
                try {
                    val = std::stoull(part.substr(eq + 1));
                } catch (const std::exception&) {
                    val = 0;
                }
                r2.business_key_versions.emplace_back(part.substr(0, eq), val);
            }
            r2.attempt_count = static_cast<uint32_t>(std::stoul(
                store_.loadOr<std::string>(kLegacyAttempt, "0")));
            r2.deadline_ms = std::stoll(store_.loadOr<std::string>(kLegacyDeadline, "0"));
            r2.last_error = store_.loadOr<std::string>(kLegacyLastError, "");
            r2.updated_at_ms = std::stoll(store_.loadOr<std::string>(kLegacyUpdatedAt, "0"));
            r2.cloud_session_generation = std::stoull(
                store_.loadOr<std::string>(kLegacyCloudGen, "0"));
            r2.valid = r2.valid && !r2.request_id.empty();
            if (r2.valid) {
                r2.legacy_snapshot_unknown = true;
            }
            return r2;
        } catch (const std::exception& e) {
            LogAdapter::keyprov().warn(
                "tsp.keyprov.store.legacy_load_failed",
                "keyprov legacy 状态读取异常，按无记录处理", {
                    {"error", tbox::fw::log::FieldValue::makeString(e.what())}
                });
            return V2cKeyProvisioningRecord{};
        }
    }

    return r;
}

void V2cKeyProvisioningStore::save(const V2cKeyProvisioningRecord& record) {
    if (!store_.isReady()) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.store.not_ready",
            "keyprov 持久化存储不可用，状态仅保留在内存");
        return;
    }
    nlohmann::json j = record_to_json(record);
    store_.save<std::string>(kStateKey, j.dump());
    store_.flush();
}

void V2cKeyProvisioningStore::clear() {
    if (!store_.isReady()) return;
    store_.remove(kStateKey);
    // 清理 legacy 键（幂等）。
    store_.remove(kLegacyPresent);
    store_.remove(kLegacyRequestId);
    store_.remove(kLegacyIdemDigest);
    store_.remove(kLegacyState);
    store_.remove(kLegacyPurposes);
    store_.remove(kLegacyVersions);
    store_.remove(kLegacyAttempt);
    store_.remove(kLegacyDeadline);
    store_.remove(kLegacyLastError);
    store_.remove(kLegacyUpdatedAt);
    store_.remove(kLegacyCloudGen);
    store_.flush();
}

bool V2cKeyProvisioningStore::is_ready() const {
    return store_.isReady();
}

} // namespace tsp
} // namespace tbox
