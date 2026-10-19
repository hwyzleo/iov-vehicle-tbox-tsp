// TBOX-TSP-DSN-CR-010 §4.2 / VEH-PROTO §7: keyprov wire codec 单元测试。
#include <gtest/gtest.h>

#include "keyprov_protocol.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

using namespace tbox::tsp;
using namespace security::keyprov::v1;
using vehicle::common::v1::MESSAGE_KIND_RESPONSE;
using vehicle::common::v1::VehicleMessageEnvelope;

namespace {

std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

KeyprovSessionIdentity make_identity(const std::string& uid = "ECU-1") {
    KeyprovSessionIdentity id;
    id.ecu_uid = uid;
    id.device_identity_digest = std::string(64, 'a');
    id.certificate_ref = "sha256:" + std::string(64, 'b');
    id.session.daemon_epoch = "epoch-1";
    id.session.connection_generation = 1;
    id.session.cert_session_generation = 1;
    return id;
}

std::vector<uint8_t> make_response_envelope(bool good_purposes = true) {
    KeyProvisioningResponse resp;
    resp.set_request_id("req-1");
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    for (int i = 0; i < 2; ++i) {
        auto* it = resp.add_items();
        it->set_purpose(good_purposes
                            ? (i == 0 ? KEY_PURPOSE_UPLINK_AEAD
                                      : KEY_PURPOSE_DOWNLINK_AEAD)
                            : KEY_PURPOSE_UNSPECIFIED);
        it->set_key_id(i == 0 ? "kid-up" : "kid-down");
        it->set_business_key_version(3);
        it->set_key_algorithm("AES-256");
        it->set_wrapping_suite(
            WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        it->set_wrapped_key(std::string(48, 'W'));
        it->set_parameters(std::string(16, 'P'));
        // CR-007/CR-008：完整信封绑定字段。
        it->set_envelope_format(KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
        it->set_envelope_digest(std::string(32, '\xD1'));
        it->set_key_check_value(std::string(3, '\xC1'));
    }
    std::string payload;
    resp.SerializeToString(&payload);

    VehicleMessageEnvelope env;
    env.set_request_id("req-1");
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type("security.keyprov.v1.KeyProvisioningResponse");
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("msg-resp");
    env.set_payload(payload);
    std::string bytes;
    env.SerializeToString(&bytes);
    return to_bytes(bytes);
}

} // namespace

TEST(KeyProvProtocolTest, RequestEnvelopeCarriesExpectedFields) {
    KeyProvRequestData req;
    req.request_id = "req-1";
    req.idempotency_key = "req-1";
    req.business_domain = "V2C_COMM";
    req.purposes = {kKeyProvPurposeUplinkValue, kKeyProvPurposeDownlinkValue};
    req.certificate_ref.certificate_profile = "mqtt";
    req.supported_wrapping_suites = {
        keyprov_wrapping_suite_from_string(kKeyprovSuiteEcdhEsP256)};
    req.supported_envelope_formats = {kKeyProvEnvelopeFormatEcdhEsP256V1};
    req.timestamp_ms = 1000;
    req.expire_at_ms = 2000;

    auto out = build_keyprov_request_envelope(make_identity(), req, "msg-1", "trace-1");
    ASSERT_EQ(out.status, KeyProvCodecStatus::Ok);
    ASSERT_FALSE(out.envelope_bytes.empty());

    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(out.envelope_bytes.data(),
                                   (int)out.envelope_bytes.size()));
    EXPECT_EQ(env.service(), "security.keyprov");
    EXPECT_EQ(env.protocol_version(), "keyprov-v1");
    EXPECT_EQ(env.payload_type(), kKeyprovPayloadRequest);
    EXPECT_EQ(env.message_id(), "msg-1");
    // CR-011 §4: 公共 Envelope.device_id 由身份必填填写。
    EXPECT_EQ(env.device_id(), "ECU-1");

    KeyProvisioningRequest parsed;
    ASSERT_TRUE(parsed.ParseFromString(env.payload()));
    EXPECT_EQ(parsed.request_id(), "req-1");
    EXPECT_EQ(parsed.business_domain(), "V2C_COMM");
    ASSERT_EQ(parsed.purposes_size(), 2);
    EXPECT_EQ(parsed.purposes(0), KEY_PURPOSE_UPLINK_AEAD);
    EXPECT_EQ(parsed.purposes(1), KEY_PURPOSE_DOWNLINK_AEAD);
    // 64 hex -> 32 bytes，且证书摘要与 UID 同源（同一 identity）。
    EXPECT_EQ(parsed.device_identity_digest().size(), 32u);
    EXPECT_EQ(parsed.certificate_ref().certificate_digest().size(), 32u);
    // CR-007 §6.1：显式声明 envelope v1。
    ASSERT_EQ(parsed.supported_envelope_formats_size(), 1);
    EXPECT_EQ(parsed.supported_envelope_formats(0),
              KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
}

TEST(KeyProvProtocolTest, RequestRequiresExplicitEnvelopeFormat) {
    KeyProvRequestData req;
    req.request_id = "req-1";
    req.idempotency_key = "req-1";
    req.business_domain = "V2C_COMM";
    req.purposes = {kKeyProvPurposeUplinkValue, kKeyProvPurposeDownlinkValue};
    // 缺失
    auto missing = build_keyprov_request_envelope(make_identity(), req, "m", "");
    EXPECT_EQ(missing.status, KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(missing.reason, "envelope_format_missing");
    // UNSPECIFIED
    req.supported_envelope_formats = {kKeyProvEnvelopeFormatUnspecified};
    auto unspec = build_keyprov_request_envelope(make_identity(), req, "m", "");
    EXPECT_EQ(unspec.status, KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(unspec.reason, "envelope_format_unspecified");
    // 未知值
    req.supported_envelope_formats = {99};
    auto unknown = build_keyprov_request_envelope(make_identity(), req, "m", "");
    EXPECT_EQ(unknown.status, KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(unknown.reason, "envelope_format_unknown");
}

TEST(KeyProvProtocolTest, RequestRejectsNonCanonicalBusinessDomain) {
    KeyProvRequestData req;
    req.request_id = "req-1";
    req.idempotency_key = "req-1";
    req.business_domain = "v2c_comm";  // 小写/别名 fail-closed
    req.purposes = {kKeyProvPurposeUplinkValue, kKeyProvPurposeDownlinkValue};
    req.supported_envelope_formats = {kKeyProvEnvelopeFormatEcdhEsP256V1};
    auto out = build_keyprov_request_envelope(make_identity(), req, "m", "");
    EXPECT_EQ(out.status, KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(out.reason, "business_domain_invalid");
}

TEST(KeyProvProtocolTest, RequestRejectsOversizeFields) {
    KeyProvRequestData req;
    req.request_id = std::string(200, 'x');  // > 128
    req.idempotency_key = "idem";
    req.business_domain = "V2C_COMM";
    req.purposes = {1, 2};
    auto out = build_keyprov_request_envelope(make_identity(), req, "m", "");
    EXPECT_EQ(out.status, KeyProvCodecStatus::FieldInvalid);
}

TEST(KeyProvProtocolTest, AllUplinkBuildersFillDeviceId) {
    KeyProvRequestData req;
    req.request_id = "req-1";
    req.idempotency_key = "req-1";
    req.business_domain = "V2C_COMM";
    req.purposes = {kKeyProvPurposeUplinkValue};
    req.supported_envelope_formats = {kKeyProvEnvelopeFormatEcdhEsP256V1};
    auto id = make_identity();

    auto req_out = build_keyprov_request_envelope(id, req, "m1", "");
    ASSERT_EQ(req_out.status, KeyProvCodecStatus::Ok);
    VehicleMessageEnvelope env1;
    ASSERT_TRUE(env1.ParseFromArray(req_out.envelope_bytes.data(),
                                    (int)req_out.envelope_bytes.size()));
    EXPECT_EQ(env1.device_id(), "ECU-1");

    KeyProvImportItemResult a;
    a.purpose = kKeyProvPurposeUplinkValue;
    a.key_id = "kid-up";
    a.business_key_version = 1;
    a.result = kKeyProvImportImported;
    a.envelope_format = kKeyProvEnvelopeFormatEcdhEsP256V1;
    a.envelope_digest = std::vector<uint8_t>(32, 0xD1);
    a.key_check_value = std::vector<uint8_t>(3, 0xC1);
    a.import_proof_algorithm = kKeyProvImportProofAlgorithmEcdsaP256P1363;
    a.import_proof = std::vector<uint8_t>(64, 0xE1);
    a.recipient_certificate_digest = std::vector<uint8_t>(32, 0xB1);
    auto ack_out = build_keyprov_ack_envelope(id, "req-1", {a}, 1, "m2", "");
    ASSERT_EQ(ack_out.status, KeyProvCodecStatus::Ok);
    VehicleMessageEnvelope env2;
    ASSERT_TRUE(env2.ParseFromArray(ack_out.envelope_bytes.data(),
                                    (int)ack_out.envelope_bytes.size()));
    EXPECT_EQ(env2.device_id(), "ECU-1");

    auto st_out = build_keyprov_status_request_envelope(id, "req-1", 1, "m3", "");
    ASSERT_EQ(st_out.status, KeyProvCodecStatus::Ok);
    VehicleMessageEnvelope env3;
    ASSERT_TRUE(env3.ParseFromArray(st_out.envelope_bytes.data(),
                                    (int)st_out.envelope_bytes.size()));
    EXPECT_EQ(env3.device_id(), "ECU-1");
}

TEST(KeyProvProtocolTest, BuildersRejectMissingOrInvalidIdentity) {
    KeyProvRequestData req;
    req.request_id = "req-1";
    req.idempotency_key = "req-1";
    req.business_domain = "V2C_COMM";
    req.purposes = {kKeyProvPurposeUplinkValue};

    // 空 UID
    auto empty = make_identity();
    empty.ecu_uid.clear();
    EXPECT_EQ(build_keyprov_request_envelope(empty, req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);

    // 非规范 UID（小写/非法字符）
    EXPECT_EQ(build_keyprov_request_envelope(make_identity("lower-uid"), req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(build_keyprov_request_envelope(make_identity("ECU_1"), req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);

    // 证书身份缺失
    auto no_cert = make_identity();
    no_cert.certificate_ref.clear();
    EXPECT_EQ(build_keyprov_request_envelope(no_cert, req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);

    // session 不完整
    auto no_session = make_identity();
    no_session.session.daemon_epoch.clear();
    EXPECT_EQ(build_keyprov_request_envelope(no_session, req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    auto no_gen = make_identity();
    no_gen.session.cert_session_generation = 0;
    EXPECT_EQ(build_keyprov_request_envelope(no_gen, req, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);

    // ACK/StatusRequest 同样拒绝无身份（不产生可发送 Envelope）
    auto bad = make_identity();
    bad.ecu_uid.clear();
    EXPECT_EQ(build_keyprov_ack_envelope(bad, "req-1", {}, 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    EXPECT_EQ(build_keyprov_status_request_envelope(bad, "req-1", 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
}

TEST(KeyProvProtocolTest, CanonicalUidRules) {
    EXPECT_TRUE(keyprov_is_canonical_uid("ECU-1"));
    EXPECT_TRUE(keyprov_is_canonical_uid("A"));
    EXPECT_TRUE(keyprov_is_canonical_uid(std::string(64, 'A')));
    EXPECT_FALSE(keyprov_is_canonical_uid(""));
    EXPECT_FALSE(keyprov_is_canonical_uid(std::string(65, 'A')));
    EXPECT_FALSE(keyprov_is_canonical_uid("lower"));
    EXPECT_FALSE(keyprov_is_canonical_uid("ECU_1"));
    EXPECT_FALSE(keyprov_is_canonical_uid("ECU 1"));
}

TEST(KeyProvProtocolTest, DecodeResponseProducesSecureItems) {
    auto out = decode_keyprov_envelope(make_response_envelope());
    ASSERT_EQ(out.status, KeyProvCodecStatus::Ok);
    EXPECT_EQ(out.decoded.kind, KeyProvMessageKind::Response);
    EXPECT_EQ(out.decoded.request_id, "req-1");
    EXPECT_EQ(out.decoded.message_id, "msg-resp");
    ASSERT_EQ(out.decoded.response.items.size(), 2u);
    EXPECT_EQ(out.decoded.response.items[0].purpose, kKeyprovPurposeUplink);
    EXPECT_EQ(out.decoded.response.items[0].wrapped_key.size(), 48u);
    EXPECT_EQ(out.decoded.response.items[0].business_key_version, 3u);
    // CR-012 §5：完整转交 format/digest/KCV，TSP 不解析/不重算。
    EXPECT_EQ(out.decoded.response.items[0].envelope_format,
              tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1);
    EXPECT_EQ(out.decoded.response.items[0].envelope_digest.size(), 32u);
    EXPECT_TRUE(out.decoded.response.items[0].key_check_value_present);
}

TEST(KeyProvProtocolTest, DecodeRejectsLegacyVehicleService) {
    auto bytes = make_response_envelope();
    VehicleMessageEnvelope env;
    env.ParseFromArray(bytes.data(), (int)bytes.size());
    env.set_service(kKeyprovLegacyService);  // vehicle.security.keyprov
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::ServiceMismatch);
}

TEST(KeyProvProtocolTest, DecodeRejectsUnsupportedEnvelopeFormat) {
    KeyProvisioningResponse resp;
    resp.set_request_id("req-1");
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    auto* it = resp.add_items();
    it->set_purpose(KEY_PURPOSE_UPLINK_AEAD);
    it->set_key_id("kid");
    it->set_business_key_version(1);
    it->set_key_algorithm("AES-256");
    it->set_wrapping_suite(WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
    it->set_wrapped_key(std::string(32, 'W'));
    it->set_parameters(std::string(8, 'P'));
    it->set_envelope_format(KEY_ENVELOPE_FORMAT_UNSPECIFIED);
    it->set_envelope_digest(std::string(32, '\xD1'));
    it->set_key_check_value(std::string(3, '\xC1'));
    std::string payload;
    resp.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadResponse);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::FieldInvalid);
}

TEST(KeyProvProtocolTest, DecodeRejectsWrongProtocolVersion) {
    auto bytes = make_response_envelope();
    VehicleMessageEnvelope env;
    env.ParseFromArray(bytes.data(), (int)bytes.size());
    env.set_protocol_version("fota-v1");
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::ProtocolVersionMismatch);
}

TEST(KeyProvProtocolTest, DecodeRejectsWrongService) {
    auto bytes = make_response_envelope();
    VehicleMessageEnvelope env;
    env.ParseFromArray(bytes.data(), (int)bytes.size());
    env.set_service("vehicle.fota");
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::ServiceMismatch);
}

TEST(KeyProvProtocolTest, DecodeRejectsUnknownPayloadType) {
    auto bytes = make_response_envelope();
    VehicleMessageEnvelope env;
    env.ParseFromArray(bytes.data(), (int)bytes.size());
    env.set_payload_type("security.keyprov.v1.Unknown");
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::UnsupportedPayloadType);
}

TEST(KeyProvProtocolTest, DecodeRejectsOversizeWrappedKey) {
    KeyProvisioningResponse resp;
    resp.set_request_id("req-1");
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    auto* it = resp.add_items();
    it->set_purpose(KEY_PURPOSE_UPLINK_AEAD);
    it->set_key_id("kid");
    it->set_business_key_version(1);
    it->set_wrapped_key(std::string(kKeyprovMaxWrappedKeyBytes + 1, 'W'));
    std::string payload;
    resp.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type("security.keyprov.v1.KeyProvisioningResponse");
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("m");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    auto out = decode_keyprov_envelope(to_bytes(s));
    EXPECT_EQ(out.status, KeyProvCodecStatus::SizeExceeded);
}

TEST(KeyProvProtocolTest, AckEnvelopeCarriesImportAttestation) {
    KeyProvImportItemResult a;
    a.purpose = kKeyProvPurposeUplinkValue;
    a.key_id = "kid-up";
    a.business_key_version = 3;
    a.result = kKeyProvImportImported;
    a.envelope_format = kKeyProvEnvelopeFormatEcdhEsP256V1;
    a.envelope_digest = std::vector<uint8_t>(32, 0xD1);
    a.key_check_value = std::vector<uint8_t>(3, 0xC1);
    a.import_proof_algorithm = kKeyProvImportProofAlgorithmEcdsaP256P1363;
    a.import_proof = std::vector<uint8_t>(64, 0xE1);
    a.recipient_certificate_digest = std::vector<uint8_t>(32, 0xB1);
    auto out = build_keyprov_ack_envelope(make_identity(), "req-1", {a}, 1234, "msg-ack", "msg-resp");
    ASSERT_EQ(out.status, KeyProvCodecStatus::Ok);
    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(out.envelope_bytes.data(),
                                   (int)out.envelope_bytes.size()));
    EXPECT_EQ(env.payload_type(), kKeyprovPayloadAck);
    EXPECT_EQ(env.correlation_id(), "msg-resp");
    KeyProvisioningAck ack;
    ASSERT_TRUE(ack.ParseFromString(env.payload()));
    ASSERT_EQ(ack.items_size(), 1);
    const auto& item = ack.items(0);
    // CR-008 §3.1：算法 enum=1、64B proof、32B certDigest、legacy string 留空。
    EXPECT_EQ(item.import_proof_algorithm(),
              IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363);
    EXPECT_EQ(item.import_proof().size(), 64u);
    EXPECT_EQ(item.recipient_certificate_digest().size(), 32u);
    EXPECT_EQ(item.envelope_digest().size(), 32u);
    EXPECT_EQ(item.key_check_value().size(), 3u);
    EXPECT_TRUE(item.proof_algorithm().empty());
}

TEST(KeyProvProtocolTest, AckRejectsIncompleteAttestation) {
    KeyProvImportItemResult a;
    a.purpose = kKeyProvPurposeUplinkValue;
    a.key_id = "kid-up";
    a.business_key_version = 3;
    a.result = kKeyProvImportImported;
    a.envelope_format = kKeyProvEnvelopeFormatEcdhEsP256V1;
    a.envelope_digest = std::vector<uint8_t>(32, 0xD1);
    a.key_check_value = std::vector<uint8_t>(3, 0xC1);
    a.import_proof_algorithm = kKeyProvImportProofAlgorithmEcdsaP256P1363;
    a.recipient_certificate_digest = std::vector<uint8_t>(32, 0xB1);
    // 63B proof
    a.import_proof = std::vector<uint8_t>(63, 0xE1);
    EXPECT_EQ(build_keyprov_ack_envelope(make_identity(), "req-1", {a}, 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    // 65B proof
    a.import_proof = std::vector<uint8_t>(65, 0xE1);
    EXPECT_EQ(build_keyprov_ack_envelope(make_identity(), "req-1", {a}, 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    // 算法 0
    a.import_proof = std::vector<uint8_t>(64, 0xE1);
    a.import_proof_algorithm = kKeyProvImportProofAlgorithmUnspecified;
    EXPECT_EQ(build_keyprov_ack_envelope(make_identity(), "req-1", {a}, 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
    // 证书摘要非 32B
    a.import_proof_algorithm = kKeyProvImportProofAlgorithmEcdsaP256P1363;
    a.recipient_certificate_digest = std::vector<uint8_t>(31, 0xB1);
    EXPECT_EQ(build_keyprov_ack_envelope(make_identity(), "req-1", {a}, 1, "m", "").status,
              KeyProvCodecStatus::FieldInvalid);
}

TEST(KeyProvProtocolTest, DeterministicProtoRuntimeSelfCheckPasses) {
    EXPECT_TRUE(keyprov_deterministic_proto_runtime_check());
}

TEST(KeyProvProtocolTest, PurposeMappingRoundTrip) {
    EXPECT_EQ(keyprov_purpose_from_string("UPLINK_AEAD"), kKeyProvPurposeUplinkValue);
    EXPECT_EQ(keyprov_purpose_from_string("DOWNLINK_AEAD"), kKeyProvPurposeDownlinkValue);
    EXPECT_EQ(keyprov_purpose_to_string(kKeyProvPurposeUplinkValue), "UPLINK_AEAD");
    EXPECT_EQ(keyprov_purpose_to_string(kKeyProvPurposeDownlinkValue), "DOWNLINK_AEAD");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
