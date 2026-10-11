// TBOX-TSP-DSN-CR-010 §4.2 / VEH-PROTO §7: keyprov wire codec 实现。
#include "keyprov_protocol.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

#include <cstring>
#include <utility>

namespace tbox {
namespace tsp {

namespace {

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

// 公共 Envelope 字段填充
void fill_common(::vehicle::common::v1::VehicleMessageEnvelope& env,
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
    const KeyProvRequestData& in,
    const std::string& message_id,
    const std::string& trace_id) {
    if (!str_within(in.request_id, kKeyprovMaxStringBytes) ||
        !str_within(in.idempotency_key, kKeyprovMaxStringBytes) ||
        !str_within(in.business_domain, kKeyprovMaxShortStringBytes) ||
        in.device_identity_digest.size() > kKeyprovMaxDigestBytes) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "request_field_too_large"};
    }
    if (in.request_id.empty() || in.idempotency_key.empty() ||
        in.business_domain.empty()) {
        return {KeyProvCodecStatus::FieldInvalid, {}, "request_field_missing"};
    }
    if (in.purposes.size() > kKeyprovMaxItems ||
        in.supported_wrapping_suites.size() > kKeyprovMaxItems ||
        in.current_versions.size() > kKeyprovMaxItems) {
        return {KeyProvCodecStatus::SizeExceeded, {}, "request_items_too_many"};
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
    if (!in.device_identity_digest.empty()) {
        req.set_device_identity_digest(
            in.device_identity_digest.data(), in.device_identity_digest.size());
    }
    auto* cref = req.mutable_certificate_ref();
    cref->set_certificate_profile(in.certificate_ref.certificate_profile);
    if (!in.certificate_ref.certificate_digest.empty()) {
        cref->set_certificate_digest(
            in.certificate_ref.certificate_digest.data(),
            in.certificate_ref.certificate_digest.size());
    }
    cref->set_key_encipherment_key_id(in.certificate_ref.key_encipherment_key_id);
    for (int s : in.supported_wrapping_suites) {
        req.add_supported_wrapping_suites(static_cast<WrappingSuite>(s));
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
    fill_common(env, in.request_id, message_id, "", kKeyprovPayloadRequest,
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
    const std::string& request_id,
    const std::vector<KeyProvImportItemResult>& items,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& correlation_id) {
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
            !str_within(it.proof_algorithm, kKeyprovMaxStringBytes) ||
            it.import_proof.size() > kKeyprovMaxImportProofBytes) {
            return {KeyProvCodecStatus::SizeExceeded, {}, "ack_item_too_large"};
        }
        auto* e = ack.add_items();
        e->set_purpose(static_cast<KeyPurpose>(it.purpose));
        e->set_key_id(it.key_id);
        e->set_business_key_version(it.business_key_version);
        e->set_result(static_cast<KeyImportResult>(it.result));
        if (!it.import_proof.empty()) {
            e->set_import_proof(it.import_proof.data(), it.import_proof.size());
        }
        e->set_proof_algorithm(it.proof_algorithm);
    }
    ack.set_timestamp_ms(timestamp_ms);

    std::string payload;
    if (!ack.SerializeToString(&payload)) {
        return {KeyProvCodecStatus::Internal, {}, "ack_serialize_failed"};
    }
    ::vehicle::common::v1::VehicleMessageEnvelope env;
    fill_common(env, request_id, message_id, correlation_id, kKeyprovPayloadAck,
                "", timestamp_ms);
    env.set_message_kind(::vehicle::common::v1::MESSAGE_KIND_REQUEST);
    env.set_payload(std::move(payload));
    return serialize_envelope(env, KeyProvCodecStatus::Ok);
}

KeyProvEncodeOutcome build_keyprov_status_request_envelope(
    const std::string& request_id,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& trace_id) {
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
    fill_common(env, request_id, message_id, "", kKeyprovPayloadStatusRequest,
                trace_id, timestamp_ms);
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
            tbox::sec::WrappedKeyItem wi;
            wi.purpose = keyprov_purpose_to_string(static_cast<int>(it.purpose()));
            wi.key_id = it.key_id();
            wi.business_key_version = it.business_key_version();
            wi.algorithm = it.key_algorithm();
            wi.valid_from_ms = it.valid_from_ms();
            wi.valid_to_ms = it.valid_to_ms();
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

} // namespace tsp
} // namespace tbox
