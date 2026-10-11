// TBOX-TSP-DSN-CR-010 §5: V2C keyprov 非敏感状态持久化实现。
#include "v2c_key_provisioning_store.h"

#include "log_adapter.h"

#include <sstream>

namespace tbox {
namespace tsp {

namespace {

constexpr const char* kPrefix = "keyprov.v2c.";
constexpr const char* kRequestId = "keyprov.v2c.request_id";
constexpr const char* kIdemDigest = "keyprov.v2c.idempotency_digest";
constexpr const char* kState = "keyprov.v2c.state";
constexpr const char* kPurposes = "keyprov.v2c.purposes";
constexpr const char* kVersions = "keyprov.v2c.business_key_versions";
constexpr const char* kAttempt = "keyprov.v2c.attempt_count";
constexpr const char* kDeadline = "keyprov.v2c.deadline_ms";
constexpr const char* kLastError = "keyprov.v2c.last_error";
constexpr const char* kUpdatedAt = "keyprov.v2c.updated_at_ms";
constexpr const char* kCloudGen = "keyprov.v2c.cloud_session_generation";
constexpr const char* kPresent = "keyprov.v2c.present";

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

std::string encode_versions(
    const std::vector<std::pair<std::string, uint64_t>>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out.push_back(',');
        out += v[i].first;
        out.push_back('=');
        out += std::to_string(v[i].second);
    }
    return out;
}

std::vector<std::pair<std::string, uint64_t>> decode_versions(const std::string& s) {
    std::vector<std::pair<std::string, uint64_t>> out;
    for (const auto& part : split(s, ',')) {
        auto eq = part.find('=');
        if (eq == std::string::npos) continue;
        std::string key = part.substr(0, eq);
        uint64_t val = 0;
        try {
            val = std::stoull(part.substr(eq + 1));
        } catch (const std::exception&) {
            val = 0;
        }
        out.emplace_back(std::move(key), val);
    }
    return out;
}

} // namespace

V2cKeyProvisioningStore::V2cKeyProvisioningStore(const std::string& store_root)
    : store_(hwyz::store::Store::open("tsp", store_root)) {
}

V2cKeyProvisioningRecord V2cKeyProvisioningStore::load() const {
    V2cKeyProvisioningRecord r;
    if (!store_.isReady()) return r;
    if (!store_.has(kPresent)) return r;
    try {
        r.valid = store_.loadOr<std::string>(kPresent, "0") == "1";
        r.request_id = store_.loadOr<std::string>(kRequestId, "");
        r.idempotency_digest = store_.loadOr<std::string>(kIdemDigest, "");
        r.state = store_.loadOr<std::string>(kState, "");
        r.purposes = split(store_.loadOr<std::string>(kPurposes, ""), ',');
        r.business_key_versions =
            decode_versions(store_.loadOr<std::string>(kVersions, ""));
        r.attempt_count = static_cast<uint32_t>(std::stoul(
            store_.loadOr<std::string>(kAttempt, "0")));
        r.deadline_ms = std::stoll(store_.loadOr<std::string>(kDeadline, "0"));
        r.last_error = store_.loadOr<std::string>(kLastError, "");
        r.updated_at_ms = std::stoll(store_.loadOr<std::string>(kUpdatedAt, "0"));
        r.cloud_session_generation = std::stoull(
            store_.loadOr<std::string>(kCloudGen, "0"));
        r.valid = r.valid && !r.request_id.empty();
    } catch (const std::exception& e) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.store.load_failed",
            "keyprov 持久化状态读取异常，按无记录处理", {
                {"error", tbox::fw::log::FieldValue::makeString(e.what())}
            });
        return V2cKeyProvisioningRecord{};
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
    store_.save<std::string>(kPresent, "1");
    store_.save<std::string>(kRequestId, record.request_id);
    store_.save<std::string>(kIdemDigest, record.idempotency_digest);
    store_.save<std::string>(kState, record.state);
    store_.save<std::string>(kPurposes, join(record.purposes, ','));
    store_.save<std::string>(kVersions, encode_versions(record.business_key_versions));
    store_.save<std::string>(kAttempt, std::to_string(record.attempt_count));
    store_.save<std::string>(kDeadline, std::to_string(record.deadline_ms));
    store_.save<std::string>(kLastError, record.last_error);
    store_.save<std::string>(kUpdatedAt, std::to_string(record.updated_at_ms));
    store_.save<std::string>(kCloudGen,
                             std::to_string(record.cloud_session_generation));
    store_.flush();
}

void V2cKeyProvisioningStore::clear() {
    if (!store_.isReady()) return;
    store_.remove(kPresent);
    store_.remove(kRequestId);
    store_.remove(kIdemDigest);
    store_.remove(kState);
    store_.remove(kPurposes);
    store_.remove(kVersions);
    store_.remove(kAttempt);
    store_.remove(kDeadline);
    store_.remove(kLastError);
    store_.remove(kUpdatedAt);
    store_.remove(kCloudGen);
    store_.flush();
}

bool V2cKeyProvisioningStore::is_ready() const {
    return store_.isReady();
}

} // namespace tsp
} // namespace tbox
