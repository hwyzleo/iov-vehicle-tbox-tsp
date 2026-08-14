// tests/vehicle_message_test_util.h -- Envelope 构造/序列化测试辅助
#pragma once

#include "vehicle/common/v1/envelope.pb.h"
#include "tbox/tsp/types.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {
namespace test {

using vehicle::common::v1::MessageKind;
using vehicle::common::v1::VehicleMessageEnvelope;

inline std::vector<std::byte> string_to_bytes(const std::string& s) {
    std::vector<std::byte> out(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(static_cast<uint8_t>(s[i]));
    }
    return out;
}

// Envelope bytes -> VehicleMessage（测试便捷构造）
inline VehicleMessage to_msg(const std::vector<std::byte>& bytes) {
    VehicleMessage m;
    m.envelope_bytes = bytes;
    return m;
}

inline std::string bytes_to_string(const std::vector<std::byte>& bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (auto b : bytes) {
        out.push_back(static_cast<char>(static_cast<uint8_t>(b)));
    }
    return out;
}

// 构造并序列化一个合法 REQUEST Envelope（vehicle.fota.v1.FotaRequest）
inline std::vector<std::byte> make_request_envelope(
    const std::string& message_id,
    const std::string& request_id = "req-1",
    const std::string& payload_type = "vehicle.fota.v1.FotaRequest",
    std::vector<uint8_t> payload = {0x10, 0x20, 0x30},
    int64_t expire_at_ms = 0,
    const std::string& service = "vehicle.fota") {
    VehicleMessageEnvelope env;
    env.set_request_id(request_id);
    env.set_timestamp_ms(0);
    env.set_protocol_version("1.0");
    env.set_device_id("dev-1");
    env.set_vin("VIN1");
    env.set_idempotency_key("idem-" + message_id);
    env.set_payload_type(payload_type);
    env.set_payload(std::string(payload.begin(), payload.end()));
    env.set_message_id(message_id);
    env.set_message_kind(MessageKind::MESSAGE_KIND_REQUEST);
    env.set_service(service);
    if (expire_at_ms > 0) {
        env.set_expire_at_ms(expire_at_ms);
    }
    return string_to_bytes(env.SerializeAsString());
}

// 构造并序列化一个合法 RESPONSE Envelope（correlation_id -> 请求 message_id）
inline std::vector<std::byte> make_response_envelope(
    const std::string& correlation_id,
    const std::string& message_id,
    std::vector<uint8_t> payload = {0xAA, 0xBB},
    int64_t expire_at_ms = 0,
    const std::string& service = "vehicle.fota") {
    VehicleMessageEnvelope env;
    env.set_request_id("req-r");
    env.set_timestamp_ms(0);
    env.set_protocol_version("1.0");
    env.set_device_id("dev-1");
    env.set_vin("VIN1");
    env.set_payload_type("vehicle.fota.v1.FotaResponse");
    env.set_payload(std::string(payload.begin(), payload.end()));
    env.set_message_id(message_id);
    env.set_correlation_id(correlation_id);
    env.set_message_kind(MessageKind::MESSAGE_KIND_RESPONSE);
    env.set_service(service);
    if (expire_at_ms > 0) {
        env.set_expire_at_ms(expire_at_ms);
    }
    return string_to_bytes(env.SerializeAsString());
}

// 构造并序列化一个合法 EVENT Envelope
inline std::vector<std::byte> make_event_envelope(
    const std::string& message_id,
    std::vector<uint8_t> payload = {0x01},
    const std::string& service = "vehicle.fota") {
    VehicleMessageEnvelope env;
    env.set_request_id("req-e");
    env.set_timestamp_ms(0);
    env.set_protocol_version("1.0");
    env.set_device_id("dev-1");
    env.set_vin("VIN1");
    env.set_payload_type("vehicle.fota.v1.FotaEvent");
    env.set_payload(std::string(payload.begin(), payload.end()));
    env.set_message_id(message_id);
    env.set_message_kind(MessageKind::MESSAGE_KIND_EVENT);
    env.set_service(service);
    return string_to_bytes(env.SerializeAsString());
}

// 构造 RoutedDownlinkEvent（tsp/fota.downlink/tsp.fota）
inline RoutedDownlinkEvent make_downlink_event(const std::vector<std::byte>& envelope) {
    RoutedDownlinkEvent ev;
    ev.owner = "tsp";
    ev.route_id = "fota.downlink";
    ev.target = "tsp.fota";
    ev.qos = 1;
    std::string s = bytes_to_string(envelope);
    ev.payload.assign(s.begin(), s.end());
    ev.request_id = "dl-req";
    ev.trace_id = "dl-trace";
    return ev;
}

} // namespace test
} // namespace tsp
} // namespace tbox
