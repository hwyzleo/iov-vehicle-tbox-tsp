// TBOX-TSP-DSN-CR-010 §4.2 / VEH-PROTO §7: keyprov wire codec 实现。
#include "keyprov_protocol.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

#include <google/protobuf/descriptor.h>

#include <cctype>
#include <cstring>
#include <utility>

namespace tbox {
namespace tsp {

namespace {

using security::keyprov::v1::EcdhEsP256EnvelopeParametersV1;
using security::keyprov::v1::ImportProofAlgorithm;
using security::keyprov::v1::KeyEnvelopeFormat;
using security::keyprov::v1::KeyImportItemResult;
using security::keyprov::v1::KeyImportResult;
using security::keyprov::v1::KeyPurpose;
using security::keyprov::v1::KeyProvisioningAck;
using security::keyprov::v1::KeyProvisioningAckResult;
using security::keyprov::v1::KeyProvisioningRequest;
using security::keyprov::v1::KeyProvisioningResponse;
using security::keyprov::v1::KeyProvisioningResult;
using security::keyprov::v1::KeyProvisioningStatus;
using security::keyprov::v1::KeyProvisioningStatusRequest;
using security::keyprov::v1::KeyProvisioningStatusResponse;
using security::keyprov::v1::KeyPurposeStatus;
using security::keyprov::v1::WrappingSuite;

// 长度（字节）校验
bool str_within(const std::string& s, std::size_t max) {
    return s.size() <= max;
}

void fill_error(const ::security::keyprov::v1::ProtocolError& in,
                KeyProvProtocolError& out) {
    out.code = in.code();
    out.retryable = in.retryable();
    out.action = in.action();
    out.message = in.message();
}

KeyProvEncodeOutcome serialize_envelope(
    ::vehicle::common::v1::VehicleMessageEnvelope& env,
    KeyProvCodecStatus ok_status) {
    KeyProvEncodeOutcome out;
    std::string bytes;
    if (!env.SerializeToString(&bytes)) {
        out.status = KeyProvCodecStatus::Internal;
        out.reason = "envelope_serialize_failed";
        return out;
    }
    if (bytes.size() > kKeyprovMaxPayloadBytes) {
        out.status = KeyProvCodecStatus::SizeExceeded;
        out.reason = "envelope_too_large";
        return out;
    }
    out.status = ok_status;
    out.envelope_bytes.assign(bytes.begin(), bytes.end());
    return out;
}

// 公共 Envelope 字段填充（CR-011 §4）。
// identity 为必填有效身份：统一 set_device_id(identity.ecu_uid)，保留原
// request/message/correlation/service/timestamp/trace 语义；不修改字段号。
void fill_common(::vehicle::common::v1::VehicleMessageEnvelope& env,
                 const KeyprovSessionIdentity& identity,
                 const std::string& request_id,
                 const std::string& message_id,
                 const std::string& correlation_id,
                 const std::string& payload_type,
                 const std::string& trace_id,
                 int64_t timestamp_ms) {
    env.set_request_id(request_id);
    env.set_timestamp_ms(timestamp_ms);
    env.set_protocol_version(kKeyprovProtocolVersion);
    env.set_payload_type(payload_type);
    env.set_message_id(message_id);
    env.set_device_id(identity.ecu_uid);
    if (!correlation_id.empty()) {
        env.set_correlation_id(correlation_id);
    }
    env.set_service(kKeyprovService);
    if (!trace_id.empty()) {
        env.mutable_trace_context()->set_trace_id(trace_id);
    }
}

KeyProvDecodeOutcome decode_fail(KeyProvCodecStatus s, std::string reason) {
    KeyProvDecodeOutcome out;
    out.status = s;
    out.reason = std::move(reason);
    return out;
}

} // namespace

const char* keyprov_codec_status_to_string(KeyProvCodecStatus s) {
    switch (s) {
        case KeyProvCodecStatus::Ok:                      return "OK";
        case KeyProvCodecStatus::EnvelopeInvalid:         return "ENVELOPE_INVALID";
        case KeyProvCodecStatus::UnsupportedPayloadType:  return "UNSUPPORTED_PAYLOAD_TYPE";
        case KeyProvCodecStatus::ProtocolVersionMismatch: return "PROTOCOL_VERSION_MISMATCH";
        case KeyProvCodecStatus::ServiceMismatch:         return "SERVICE_MISMATCH";
        case KeyProvCodecStatus::SizeExceeded:            return "SIZE_EXCEEDED";
        case KeyProvCodecStatus::FieldInvalid:            return "FIELD_INVALID";
        case KeyProvCodecStatus::Internal:                return "INTERNAL";
        default: return "?";
    }
}

bool keyprov_is_canonical_uid(const std::string& uid) {
    if (uid.empty() || uid.size() > 64) return false;
    for (char c : uid) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        (c == '-');
        if (!ok) return false;
    }
    return true;
}

bool keyprov_normalize_digest(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    std::string s = in;
    const std::string prefix = "sha256:";
    if (s.rfind(prefix, 0) == 0) {
        s = s.substr(prefix.size());
    }
    if (!s.empty() && (s.size() % 2) == 0) {
        bool hex = true;
        for (char c : s) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) { hex = false; break; }
        }
        if (hex) {
            auto nib = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                return static_cast<uint8_t>(c - 'A' + 10);
            };
            out.reserve(s.size() / 2);
            for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
                out.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i + 1])));
            }
            return !out.empty() && out.size() <= kKeyprovMaxDigestBytes;
        }
    }
    if (s.size() > kKeyprovMaxDigestBytes) return false;
    out.assign(s.begin(), s.end());
    return true;
}

bool keyprov_validate_identity(const KeyprovSessionIdentity& identity,
                               std::string& reason) {
    if (!keyprov_is_canonical_uid(identity.ecu_uid)) {
        reason = "identity_uid_invalid";
        return false;
    }
    if (identity.device_identity_digest.empty() ||
        identity.certificate_ref.empty()) {
        reason = "identity_certificate_incomplete";
        return false;
    }
    if (identity.session.daemon_epoch.empty() ||
        identity.session.connection_generation == 0 ||
        identity.session.cert_session_generation == 0) {
        reason = "identity_session_incomplete";
        return false;
    }
    return true;
}

int keyprov_purpose_from_string(const std::string& name) {
    if (name == kKeyprovPurposeUplink) return static_cast<int>(KeyPurpose::KEY_PURPOSE_UPLINK_AEAD);
    if (name == kKeyprovPurposeDownlink) return static_cast<int>(KeyPurpose::KEY_PURPOSE_DOWNLINK_AEAD);
    return static_cast<int>(KeyPurpose::KEY_PURPOSE_UNSPECIFIED);
}

std::string keyprov_purpose_to_string(int purpose) {
    switch (static_cast<KeyPurpose>(purpose)) {
        case KeyPurpose::KEY_PURPOSE_UPLINK_AEAD:   return kKeyprovPurposeUplink;
        case KeyPurpose::KEY_PURPOSE_DOWNLINK_AEAD: return kKeyprovPurposeDownlink;
        default: return "UNSPECIFIED";
    }
}

int keyprov_wrapping_suite_from_string(const std::string& name) {
    if (name == kKeyprovSuiteHpkeBaseX25519) {
        return static_cast<int>(WrappingSuite::WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM);
    }
    if (name == kKeyprovSuiteEcdhEsP256) {
        return static_cast<int>(WrappingSuite::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
    }
    return static_cast<int>(WrappingSuite::WRAPPING_SUITE_UNSPECIFIED);
}

std::string keyprov_wrapping_suite_to_string(int suite) {
    switch (static_cast<WrappingSuite>(suite)) {
        case WrappingSuite::WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM:
            return kKeyprovSuiteHpkeBaseX25519;
        case WrappingSuite::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM:
            return kKeyprovSuiteEcdhEsP256;
        default:
            return "UNSPECIFIED";
    }
}

int keyprov_envelope_format_from_string(const std::string& name) {
    if (name == "ECDH_ES_P256_V1" || name == "KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1") {
        return static_cast<int>(KeyEnvelopeFormat::KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
    }
    if (name == "UNSPECIFIED" || name == "KEY_ENVELOPE_FORMAT_UNSPECIFIED") {
        return static_cast<int>(KeyEnvelopeFormat::KEY_ENVELOPE_FORMAT_UNSPECIFIED);
    }
    return -1;  // 未知值 fail-closed
}

std::string keyprov_envelope_format_to_string(int format) {
    switch (static_cast<KeyEnvelopeFormat>(format)) {
        case KeyEnvelopeFormat::KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1:
            return "ECDH_ES_P256_V1";
        case KeyEnvelopeFormat::KEY_ENVELOPE_FORMAT_UNSPECIFIED:
        default:
            return "UNSPECIFIED";
    }
}

const char* keyprov_import_proof_algorithm_to_string(int algorithm) {
    switch (static_cast<ImportProofAlgorithm>(algorithm)) {
        case ImportProofAlgorithm::IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363:
            return "ECDSA_P256_SHA256_P1363";
        case ImportProofAlgorithm::IMPORT_PROOF_ALGORITHM_UNSPECIFIED:
        default:
            return "UNSPECIFIED";
    }
}

const char* keyprov_import_result_to_string(int result) {
    switch (static_cast<KeyImportResult>(result)) {
        case KeyImportResult::KEY_IMPORT_RESULT_IMPORTED: return "IMPORTED";
        case KeyImportResult::KEY_IMPORT_RESULT_FAILED:   return "FAILED";
        case KeyImportResult::KEY_IMPORT_RESULT_UNKNOWN:  return "UNKNOWN";
        case KeyImportResult::KEY_IMPORT_RESULT_UNSPECIFIED:
        default: return "UNSPECIFIED";
    }
}

// ============================================================
// 编码
// ============================================================
KeyProvEncodeOutcome build_keyprov_request_envelope(
    const KeyprovSessionIdentity& identity,
    const KeyProvRequestData& in,
    const std::string& message_id,
    const std::string& trace_id) {
    std::string id_reason;
    if (!keyprov_validate_identity(identity, id_reason)) {
        return {KeyProvCodecStatus::FieldInvalid, {}, id_reason};
    }
    if (!str_within(in.request_id, kKeyprovMaxStringBytes) ||
        !str_within(in.idempotency_key, kKeyprovMaxStringBytes) ||
        !str_within(in.business_domain, kKeyprovMaxShortStringBytes)) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "request_field_too_large"};
    }
    if (in.request_id.empty() || in.idempotency_key.empty() ||
        in.business_domain.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "request_field_missing"};
    }
    // CR-012 §3：businessDomain 严格等于 V2C_COMM（区分大小写，禁止 trim/alias/fallback）。
    if (in.business_domain != kKeyprovBusinessDomainV2c) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "business_domain_invalid"};
    }
    if (in.purposes.size() > kKeyprovMaxItems ||
        in.supported_wrapping_suites.size() > kKeyprovMaxItems ||
        in.supported_envelope_formats.size() > kKeyprovMaxItems ||
        in.current_versions.size() > kKeyprovMaxItems) {
        return {KeyProvCodecStatus::SizeExceeded, {}, "request_items_too_many"};
    }
    // CR-007 §6.1：必须显式声明非 UNSPECIFIED 的 envelope 格式，否则不得请求该格式。
    bool envelope_format_declared = false;
    for (int f : in.supported_envelope_formats) {
        if (f == kKeyProvEnvelopeFormatEcdhEsP256V1) {
            envelope_format_declared = true;
        } else if (f == kKeyProvEnvelopeFormatUnspecified) {
            return {KeyProvCodecStatus::FieldInvalid, {}, "envelope_format_unspecified"};
        } else {
            return {KeyProvCodecStatus::FieldInvalid, {}, "envelope_format_unknown"};
        }
    }
    if (!envelope_format_declared) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "envelope_format_missing"};
    }

    // CR-011 §4: Request 的 deviceIdentityDigest/certificateRef 与该身份同源，
    // 不从 in 拼接，也不混合不同事件/查询的字段。
    std::vector<uint8_t> identity_digest;
    std::vector<uint8_t> certificate_digest;
    if (!keyprov_normalize_digest(identity.device_identity_digest, identity_digest) ||
        identity_digest.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "identity_digest_invalid"};
    }
    if (!keyprov_normalize_digest(identity.certificate_ref, certificate_digest) ||
        certificate_digest.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "identity_certificate_ref_invalid"};
    }

    KeyProvisioningRequest req;
    req.set_request_id(in.request_id);
    req.set_idempotency_key(in.idempotency_key);
    req.set_business_domain(in.business_domain);
    for (int p : in.purposes) {
        if (p == static_cast<int>(KeyPurpose::KEY_PURPOSE_UNSPECIFIED)) {
            return {KeyProvCodecStatus::FieldInvalid, {}, "invalid_purpose"};
        }
        req.add_purposes(static_cast<KeyPurpose>(p));
    }
    req.set_device_identity_digest(identity_digest.data(), identity_digest.size());
    auto* cref = req.mutable_certificate_ref();
    cref->set_certificate_profile(in.certificate_ref.certificate_profile);
    cref->set_certificate_digest(certificate_digest.data(), certificate_digest.size());
    cref->set_key_encipherment_key_id(in.certificate_ref.key_encipherment_key_id);
    for (int s : in.supported_wrapping_suites) {
        req.add_supported_wrapping_suites(static_cast<WrappingSuite>(s));
    }
    for (int f : in.supported_envelope_formats) {
        req.add_supported_envelope_formats(static_cast<KeyEnvelopeFormat>(f));
    }
    for (const auto& cv : in.current_versions) {
        auto* e = req.add_current_versions();
        e->set_purpose(static_cast<KeyPurpose>(cv.purpose));
        e->set_business_key_version(cv.business_key_version);
    }
    req.set_timestamp_ms(in.timestamp_ms);
    req.set_expire_at_ms(in.expire_at_ms);

    std::string payload;
    if (!req.SerializeToString(&payload)) {
        return {KeyProvCodecStatus::Internal, {}, "request_serialize_failed"};
    }

    ::vehicle::common::v1::VehicleMessageEnvelope env;
    fill_common(env, identity, in.request_id, message_id, "", kKeyprovPayloadRequest,
                trace_id, in.timestamp_ms);
    env.set_message_kind(::vehicle::common::v1::MESSAGE_KIND_REQUEST);
    env.set_idempotency_key(in.idempotency_key);
    if (in.expire_at_ms > 0) {
        env.set_expire_at_ms(in.expire_at_ms);
    }
    env.set_payload(std::move(payload));
    return serialize_envelope(env, KeyProvCodecStatus::Ok);
}

KeyProvEncodeOutcome build_keyprov_ack_envelope(
    const KeyprovSessionIdentity& identity,
    const std::string& request_id,
    const std::vector<KeyProvImportItemResult>& items,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& correlation_id) {
    std::string id_reason;
    if (!keyprov_validate_identity(identity, id_reason)) {
        return {KeyProvCodecStatus::FieldInvalid, {}, id_reason};
    }
    if (request_id.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "ack_request_id_missing"};
    }
    if (items.size() > kKeyprovMaxItems) {
        return {KeyProvCodecStatus::SizeExceeded, {}, "ack_items_too_many"};
    }
    KeyProvisioningAck ack;
    ack.set_request_id(request_id);
    for (const auto& it : items) {
        if (!str_within(it.key_id, kKeyprovMaxStringBytes) ||
            it.import_proof.size() > kKeyprovMaxImportProofBytes) {
            return {KeyProvCodecStatus::SizeExceeded, {}, "ack_item_too_large"};
        }
        // CR-007 §5 / CR-008 §3.1：成功 IMPORTED 项必须满足精确的 format/长度/算法组合。
        // TSP 只做枚举/长度/结构检查，绝不构造 proofInput、签名或验签。
        if (it.envelope_format == kKeyProvEnvelopeFormatEcdhEsP256V1) {
            if (it.import_proof_algorithm !=
                    kKeyProvImportProofAlgorithmEcdsaP256P1363 ||
                it.import_proof.size() != kKeyprovImportProofP1363Bytes ||
                it.recipient_certificate_digest.size() !=
                    kKeyprovRecipientCertDigestBytes ||
                it.envelope_digest.size() != kKeyprovEnvelopeDigestBytes ||
                it.key_check_value.size() != kKeyprovKeyCheckValueBytes) {
                return {KeyProvCodecStatus::FieldInvalid, {},
                        "ack_attestation_invalid"};
            }
        } else if (it.envelope_format == kKeyProvEnvelopeFormatUnspecified) {
            return {KeyProvCodecStatus::FieldInvalid, {},
                    "ack_envelope_format_unspecified"};
        } else {
            return {KeyProvCodecStatus::FieldInvalid, {},
                    "ack_envelope_format_unknown"};
        }
        auto* e = ack.add_items();
        e->set_purpose(static_cast<KeyPurpose>(it.purpose));
        e->set_key_id(it.key_id);
        e->set_business_key_version(it.business_key_version);
        e->set_result(static_cast<KeyImportResult>(it.result));
        e->set_envelope_format(static_cast<KeyEnvelopeFormat>(it.envelope_format));
        e->set_envelope_digest(it.envelope_digest.data(), it.envelope_digest.size());
        e->set_key_check_value(it.key_check_value.data(), it.key_check_value.size());
        e->set_import_proof_algorithm(
            static_cast<ImportProofAlgorithm>(it.import_proof_algorithm));
        if (!it.import_proof.empty()) {
            e->set_import_proof(it.import_proof.data(), it.import_proof.size());
        }
        if (!it.recipient_certificate_digest.empty()) {
            e->set_recipient_certificate_digest(
                it.recipient_certificate_digest.data(),
                it.recipient_certificate_digest.size());
        }
        // CR-008 §3.1：遗留 string 字段必须留空，不得形成第二算法事实源。
        // proto3 默认空串；不调用 deprecated setter（字段 6 保持未设置/空）。
    }
    ack.set_timestamp_ms(timestamp_ms);

    std::string payload;
    if (!ack.SerializeToString(&payload)) {
        return {KeyProvCodecStatus::Internal, {}, "ack_serialize_failed"};
    }
    ::vehicle::common::v1::VehicleMessageEnvelope env;
    fill_common(env, identity, request_id, message_id, correlation_id,
                kKeyprovPayloadAck, "", timestamp_ms);
    env.set_message_kind(::vehicle::common::v1::MESSAGE_KIND_REQUEST);
    env.set_payload(std::move(payload));
    return serialize_envelope(env, KeyProvCodecStatus::Ok);
}

KeyProvEncodeOutcome build_keyprov_status_request_envelope(
    const KeyprovSessionIdentity& identity,
    const std::string& request_id,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& trace_id) {
    std::string id_reason;
    if (!keyprov_validate_identity(identity, id_reason)) {
        return {KeyProvCodecStatus::FieldInvalid, {}, id_reason};
    }
    if (request_id.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "status_request_id_missing"};
    }
    KeyProvisioningStatusRequest req;
    req.set_request_id(request_id);
    req.set_timestamp_ms(timestamp_ms);

    std::string payload;
    if (!req.SerializeToString(&payload)) {
        return {KeyProvCodecStatus::Internal, {}, "status_request_serialize_failed"};
    }
    ::vehicle::common::v1::VehicleMessageEnvelope env;
    fill_common(env, identity, request_id, message_id, "",
                kKeyprovPayloadStatusRequest, trace_id, timestamp_ms);
    env.set_message_kind(::vehicle::common::v1::MESSAGE_KIND_REQUEST);
    env.set_payload(std::move(payload));
    return serialize_envelope(env, KeyProvCodecStatus::Ok);
}

// ============================================================
// 解码
// ============================================================
KeyProvDecodeOutcome decode_keyprov_envelope(
    const std::vector<uint8_t>& envelope_bytes) {
    if (envelope_bytes.size() > kKeyprovMaxPayloadBytes) {
        return decode_fail(KeyProvCodecStatus::SizeExceeded, "envelope_too_large");
    }
    ::vehicle::common::v1::VehicleMessageEnvelope env;
    if (!env.ParseFromArray(envelope_bytes.data(),
                            static_cast<int>(envelope_bytes.size()))) {
        return decode_fail(KeyProvCodecStatus::EnvelopeInvalid, "envelope_parse_failed");
    }
    if (env.protocol_version() != kKeyprovProtocolVersion) {
        return decode_fail(KeyProvCodecStatus::ProtocolVersionMismatch,
                           "protocol_version_mismatch");
    }
    if (env.service() != kKeyprovService) {
        return decode_fail(KeyProvCodecStatus::ServiceMismatch, "service_mismatch");
    }
    if (env.payload().size() > kKeyprovMaxPayloadBytes) {
        return decode_fail(KeyProvCodecStatus::SizeExceeded, "payload_too_large");
    }
    if (env.message_kind() != ::vehicle::common::v1::MESSAGE_KIND_RESPONSE) {
        // 只有 RESPONSE 形态（Response/AckResult/StatusResponse）经下行进入本函数
        return decode_fail(KeyProvCodecStatus::FieldInvalid, "not_response_kind");
    }

    const std::string& ptype = env.payload_type();
    KeyProvDecodeOutcome out;
    out.decoded.message_id = env.message_id();

    if (ptype == kKeyprovPayloadResponse) {
        KeyProvisioningResponse msg;
        if (!msg.ParseFromString(env.payload())) {
            return decode_fail(KeyProvCodecStatus::FieldInvalid, "response_parse_failed");
        }
        if (msg.items_size() > static_cast<int>(kKeyprovMaxItems)) {
            return decode_fail(KeyProvCodecStatus::SizeExceeded, "response_items_too_many");
        }
        out.decoded.kind = KeyProvMessageKind::Response;
        out.decoded.request_id = msg.request_id();
        auto& r = out.decoded.response;
        r.request_id = msg.request_id();
        r.result = static_cast<int>(msg.result());
        r.expire_at_ms = msg.expire_at_ms();
        if (msg.has_error()) fill_error(msg.error(), r.error);
        for (const auto& it : msg.items()) {
            if (it.wrapped_key().size() > kKeyprovMaxWrappedKeyBytes ||
                it.parameters().size() > kKeyprovMaxParametersBytes) {
                return decode_fail(KeyProvCodecStatus::SizeExceeded, "wrapped_item_too_large");
            }
            if (!str_within(it.key_id(), kKeyprovMaxStringBytes) ||
                !str_within(it.key_algorithm(), kKeyprovMaxShortStringBytes)) {
                return decode_fail(KeyProvCodecStatus::FieldInvalid, "wrapped_item_field_invalid");
            }
            // CR-012 §5/§9：TSP 只做外层枚举/长度校验（不是密码学验证）。
            // format/suite 必须命中首期 allowlist，否则整批拒绝。
            if (static_cast<int>(it.envelope_format()) !=
                    kKeyProvEnvelopeFormatEcdhEsP256V1) {
                return decode_fail(KeyProvCodecStatus::FieldInvalid,
                                   "wrapped_envelope_format_unsupported");
            }
            if (static_cast<int>(it.wrapping_suite()) !=
                keyprov_wrapping_suite_from_string(kKeyprovSuiteEcdhEsP256)) {
                return decode_fail(KeyProvCodecStatus::FieldInvalid,
                                   "wrapped_suite_unsupported");
            }
            if (it.envelope_digest().size() != kKeyprovEnvelopeDigestBytes ||
                it.key_check_value().size() != kKeyprovKeyCheckValueBytes) {
                return decode_fail(KeyProvCodecStatus::FieldInvalid,
                                   "wrapped_digest_or_kcv_invalid");
            }
            tbox::sec::WrappedKeyItem wi;
            wi.purpose = keyprov_purpose_to_string(static_cast<int>(it.purpose()));
            wi.key_id = it.key_id();
            wi.business_key_version = it.business_key_version();
            wi.algorithm = it.key_algorithm();
            wi.valid_from_ms = it.valid_from_ms();
            wi.valid_to_ms = it.valid_to_ms();
            // CR-012 §5：完整转交，不解析 parameters/不重算 digest/不检 KCV。
            wi.wrapping_suite = tbox::sec::kWrappingSuiteEcdhEsP256;
            wi.envelope_format = tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1;
            wi.envelope_digest.assign(it.envelope_digest().begin(),
                                      it.envelope_digest().end());
            const std::string& kcv = it.key_check_value();
            wi.key_check_value = {static_cast<uint8_t>(kcv[0]),
                                  static_cast<uint8_t>(kcv[1]),
                                  static_cast<uint8_t>(kcv[2])};
            wi.key_check_value_present = true;
            wi.wrapped_key.assign(
                reinterpret_cast<const uint8_t*>(it.wrapped_key().data()),
                it.wrapped_key().size());
            wi.parameters.assign(
                reinterpret_cast<const uint8_t*>(it.parameters().data()),
                it.parameters().size());
            r.items.push_back(std::move(wi));
        }
        out.status = KeyProvCodecStatus::Ok;
        return out;
    }

    if (ptype == kKeyprovPayloadAckResult) {
        KeyProvisioningAckResult msg;
        if (!msg.ParseFromString(env.payload())) {
            return decode_fail(KeyProvCodecStatus::FieldInvalid, "ack_result_parse_failed");
        }
        out.decoded.kind = KeyProvMessageKind::AckResult;
        out.decoded.request_id = msg.request_id();
        out.decoded.ack_result.request_id = msg.request_id();
        out.decoded.ack_result.result = static_cast<int>(msg.result());
        out.decoded.ack_result.occurred_at_ms = msg.occurred_at_ms();
        if (msg.has_error()) fill_error(msg.error(), out.decoded.ack_result.error);
        out.status = KeyProvCodecStatus::Ok;
        return out;
    }

    if (ptype == kKeyprovPayloadStatusResponse) {
        KeyProvisioningStatusResponse msg;
        if (!msg.ParseFromString(env.payload())) {
            return decode_fail(KeyProvCodecStatus::FieldInvalid, "status_response_parse_failed");
        }
        if (msg.items_size() > static_cast<int>(kKeyprovMaxItems)) {
            return decode_fail(KeyProvCodecStatus::SizeExceeded, "status_items_too_many");
        }
        out.decoded.kind = KeyProvMessageKind::StatusResponse;
        out.decoded.request_id = msg.request_id();
        auto& s = out.decoded.status_response;
        s.request_id = msg.request_id();
        s.status = static_cast<int>(msg.status());
        s.occurred_at_ms = msg.occurred_at_ms();
        if (msg.has_error()) fill_error(msg.error(), s.error);
        for (const auto& it : msg.items()) {
            if (!str_within(it.key_id(), kKeyprovMaxStringBytes)) {
                return decode_fail(KeyProvCodecStatus::FieldInvalid, "status_item_field_invalid");
            }
            KeyProvStatusItem si;
            si.purpose = static_cast<int>(it.purpose());
            si.key_id = it.key_id();
            si.business_key_version = it.business_key_version();
            si.import_result = static_cast<int>(it.import_result());
            s.items.push_back(std::move(si));
        }
        out.status = KeyProvCodecStatus::Ok;
        return out;
    }

    return decode_fail(KeyProvCodecStatus::UnsupportedPayloadType, "unsupported_payload_type");
}

// ============================================================
// 确定性 Protobuf runtime 启动自检（CR-012 §8 / Q2）
// ============================================================
bool keyprov_deterministic_proto_runtime_check() {
    // 1) 链接进来的 descriptor 必须与锁定的 canonical IDL 一致：
    //    package/消息存在，且 CR-007/CR-008 追加字段号在编译期已生效。
    const auto* req = KeyProvisioningRequest::descriptor();
    if (req == nullptr) return false;
    if (req->file() == nullptr ||
        req->file()->package() != kKeyprovPackage) {
        return false;
    }
    if (req->FindFieldByName("supported_envelope_formats") == nullptr) return false;

    const auto* wrap = security::keyprov::v1::WrappedKeyItem::descriptor();
    const auto* imp = KeyImportItemResult::descriptor();
    if (wrap == nullptr || imp == nullptr) return false;
    // WrappedKeyItem: envelope_digest=10, key_check_value=11, envelope_format=12
    const auto* wrap_digest = wrap->FindFieldByName("envelope_digest");
    const auto* wrap_kcv = wrap->FindFieldByName("key_check_value");
    const auto* wrap_fmt = wrap->FindFieldByName("envelope_format");
    if (!wrap_digest || wrap_digest->number() != 10 ||
        !wrap_kcv || wrap_kcv->number() != 11 ||
        !wrap_fmt || wrap_fmt->number() != 12) {
        return false;
    }
    // KeyImportItemResult: import_proof_algorithm=10, recipient_certificate_digest=11
    const auto* alg = imp->FindFieldByName("import_proof_algorithm");
    const auto* cert = imp->FindFieldByName("recipient_certificate_digest");
    if (!alg || alg->number() != 10 ||
        !cert || cert->number() != 11) {
        return false;
    }

    // 2) 确定性子消息在此 runtime 下重复序列化字节稳定。
    EcdhEsP256EnvelopeParametersV1 p;
    p.set_format_version(1);
    p.set_server_ephemeral_public_key(std::string(65, '\x04'));
    p.set_hkdf_salt(std::string(32, '\x01'));
    p.set_hkdf_context_version("v1");
    p.set_nonce(std::string(12, '\x02'));
    p.set_authentication_tag(std::string(16, '\x03'));
    p.set_canonical_aad("aad");
    p.set_aad_digest(std::string(32, '\x04'));
    p.set_root_key_version(1);
    p.set_derivation_version("v1");
    p.set_recipient_certificate_digest(std::string(32, '\x05'));
    p.set_operation_id("op");
    std::string a;
    std::string b;
    if (!p.SerializeToString(&a) || !p.SerializeToString(&b)) return false;
    return a == b && !a.empty();
}

} // namespace tsp
} // namespace tbox
