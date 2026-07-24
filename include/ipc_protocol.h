// include/ipc_protocol.h
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {
namespace ipc {

// Socket 路径
constexpr const char* DEFAULT_SOCKET_PATH = "/tmp/tbox-tsp.sock";

// 方法 ID
enum class MethodId : uint32_t {
    GET_NET_STATUS              = 1,   // 请求-响应
    REPORT_SOFTWARE_INVENTORY   = 2,   // 请求-响应
    SUBSCRIBE_NET_STATUS        = 3,   // 注册订阅
    SUBSCRIBE_REMOTE_COMMANDS   = 4,   // 注册订阅
    SUBSCRIBE_FOTA_COMMANDS     = 5,   // 注册订阅
};

// 推送事件类型（服务端主动推送给已订阅的客户端）
enum class EventType : uint32_t {
    NET_STATUS_CHANGED  = 100,
    REMOTE_COMMAND      = 101,
    FOTA_COMMAND         = 102,
};

// 请求头（与 SEC/PROV 一致）
struct RequestHeader {
    uint32_t method_id;
    uint32_t params_length;
} __attribute__((packed));

// 响应头（与 SEC/PROV 一致）
struct ResponseHeader {
    int32_t  status_code;
    uint32_t data_length;
} __attribute__((packed));

// 推送事件头（新增，用于服务端主动推送）
struct EventHeader {
    uint32_t event_type;    // EventType
    uint32_t payload_length;
} __attribute__((packed));

// 序列化工具
class IpcSerializer {
public:
    // 请求序列化
    static std::vector<uint8_t> serialize_request(MethodId method, const std::string& params_json);
    static bool deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json);

    // 响应序列化
    static std::vector<uint8_t> serialize_response(int32_t status_code, const std::string& response_json);
    static bool deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json);

    // 事件序列化
    static std::vector<uint8_t> serialize_event(EventType type, const std::string& payload_json);
    static bool deserialize_event(const std::vector<uint8_t>& data, EventType& type, std::string& payload_json);

    // Base64 工具
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

} // namespace ipc
} // namespace tsp
} // namespace tbox
