// src/ipc_protocol.cpp
#include "ipc_protocol.h"
#include <cstring>
#include <stdexcept>

namespace tbox {
namespace tsp {
namespace ipc {

// Base64 编码表
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<uint8_t> IpcSerializer::serialize_request(MethodId method, const std::string& params_json) {
    RequestHeader header;
    header.method_id = static_cast<uint32_t>(method);
    header.params_length = static_cast<uint32_t>(params_json.size());

    std::vector<uint8_t> result(sizeof(header) + params_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), params_json.data(), params_json.size());

    return result;
}

bool IpcSerializer::deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json) {
    if (data.size() < sizeof(RequestHeader)) {
        return false;
    }

    RequestHeader header;
    memcpy(&header, data.data(), sizeof(header));

    if (data.size() < sizeof(header) + header.params_length) {
        return false;
    }

    method = static_cast<MethodId>(header.method_id);
    params_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.params_length);

    return true;
}

std::vector<uint8_t> IpcSerializer::serialize_response(int32_t status_code, const std::string& response_json) {
    ResponseHeader header;
    header.status_code = status_code;
    header.data_length = static_cast<uint32_t>(response_json.size());

    std::vector<uint8_t> result(sizeof(header) + response_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), response_json.data(), response_json.size());

    return result;
}

bool IpcSerializer::deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json) {
    if (data.size() < sizeof(ResponseHeader)) {
        return false;
    }

    ResponseHeader header;
    memcpy(&header, data.data(), sizeof(header));

    if (data.size() < sizeof(header) + header.data_length) {
        return false;
    }

    status_code = header.status_code;
    response_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.data_length);

    return true;
}

std::vector<uint8_t> IpcSerializer::serialize_event(EventType type, const std::string& payload_json) {
    EventHeader header;
    header.event_type = static_cast<uint32_t>(type);
    header.payload_length = static_cast<uint32_t>(payload_json.size());

    std::vector<uint8_t> result(sizeof(header) + payload_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), payload_json.data(), payload_json.size());

    return result;
}

bool IpcSerializer::deserialize_event(const std::vector<uint8_t>& data, EventType& type, std::string& payload_json) {
    if (data.size() < sizeof(EventHeader)) {
        return false;
    }

    EventHeader header;
    memcpy(&header, data.data(), sizeof(header));

    if (data.size() < sizeof(header) + header.payload_length) {
        return false;
    }

    type = static_cast<EventType>(header.event_type);
    payload_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.payload_length);

    return true;
}

std::string IpcSerializer::base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    for (auto byte : data) {
        char_array_3[i++] = byte;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                result += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++) {
            result += base64_chars[char_array_4[j]];
        }

        while (i++ < 3) {
            result += '=';
        }
    }

    return result;
}

std::vector<uint8_t> IpcSerializer::base64_decode(const std::string& encoded) {
    size_t in_len = encoded.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::vector<uint8_t> result;

    while (in_len-- && (encoded[in_] != '=') && (isalnum(encoded[in_]) || (encoded[in_] == '+') || (encoded[in_] == '/'))) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = static_cast<uint8_t>(base64_chars.find(char_array_4[i]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                result.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            char_array_4[j] = static_cast<uint8_t>(base64_chars.find(char_array_4[j]));
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) {
            result.push_back(char_array_3[j]);
        }
    }

    return result;
}

} // namespace ipc
} // namespace tsp
} // namespace tbox
