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
        it->set_key_algorithm("AES-256-GCM");
        it->set_wrapping_suite(
            WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        it->set_wrapped_key(std::string(48, 'W'));
        it->set_parameters(std::string(16, 'P'));
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
    req.device_identity_digest = std::vector<uint8_t>(32, 0xAB);
    req.certificate_ref.certificate_profile = "mqtt";
    req.certificate_ref.certificate_digest = std::vector<uint8_t>(32, 0xCD);
    req.supported_wrapping_suites = {
        keyprov_wrapping_suite_from_string(kKeyprovSuiteEcdhEsP256)};
    req.timestamp_ms = 1000;
    req.expire_at_ms = 2000;

    auto out = build_keyprov_request_envelope(req, "msg-1", "trace-1");
    ASSERT_EQ(out.status, KeyProvCodecStatus::Ok);
    ASSERT_FALSE(out.envelope_bytes.empty());

    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(out.envelope_bytes.data(),
                                   (int)out.envelope_bytes.size()));
    EXPECT_EQ(env.service(), "security.keyprov");
    EXPECT_EQ(env.protocol_version(), "keyprov-v1");
    EXPECT_EQ(env.payload_type(), kKeyprovPayloadRequest);
    EXPECT_EQ(env.message_id(), "msg-1");

    KeyProvisioningRequest parsed;
    ASSERT_TRUE(parsed.ParseFromString(env.payload()));
    EXPECT_EQ(parsed.request_id(), "req-1");
    EXPECT_EQ(parsed.business_domain(), "V2C_COMM");
    ASSERT_EQ(parsed.purposes_size(), 2);
    EXPECT_EQ(parsed.purposes(0), KEY_PURPOSE_UPLINK_AEAD);
    EXPECT_EQ(parsed.purposes(1), KEY_PURPOSE_DOWNLINK_AEAD);
    EXPECT_EQ(parsed.device_identity_digest().size(), 32u);
}

TEST(KeyProvProtocolTest, RequestRejectsOversizeFields) {
    KeyProvRequestData req;
    req.request_id = std::string(200, 'x');  // > 128
    req.idempotency_key = "idem";
    req.business_domain = "V2C_COMM";
    req.purposes = {1, 2};
    auto out = build_keyprov_request_envelope(req, "m", "");
    EXPECT_EQ(out.status, KeyProvCodecStatus::FieldInvalid);
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

TEST(KeyProvProtocolTest, AckEnvelopeHasNoWrappedKey) {
    KeyProvImportItemResult a;
    a.purpose = kKeyProvPurposeUplinkValue;
    a.key_id = "kid-up";
    a.business_key_version = 3;
    a.result = kKeyProvImportImported;
    a.import_proof = std::vector<uint8_t>(16, 0x01);
    a.proof_algorithm = "hmac-sha256";
    auto out = build_keyprov_ack_envelope("req-1", {a}, 1234, "msg-ack", "msg-resp");
    ASSERT_EQ(out.status, KeyProvCodecStatus::Ok);
    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(out.envelope_bytes.data(),
                                   (int)out.envelope_bytes.size()));
    EXPECT_EQ(env.payload_type(), kKeyprovPayloadAck);
    EXPECT_EQ(env.correlation_id(), "msg-resp");
    KeyProvisioningAck ack;
    ASSERT_TRUE(ack.ParseFromString(env.payload()));
    EXPECT_EQ(ack.items_size(), 1);
    EXPECT_EQ(ack.items(0).import_proof().size(), 16u);
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
