// src/someip_facade_impl.cpp
#include "someip_facade_impl.h"
#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

SomeipFacadeImpl::SomeipFacadeImpl() = default;
SomeipFacadeImpl::~SomeipFacadeImpl() = default;

bool SomeipFacadeImpl::initialize() {
    spdlog::info("[SomeipFacadeImpl] 初始化");

    // 创建网络状态提供者（当前使用 Mock）
    net_status_provider_ = std::make_unique<MockNetStatusProvider>();

    // 创建 IPC 服务器
    server_ = std::make_unique<ipc::IpcServer>();

    return true;
}

bool SomeipFacadeImpl::start() {
    if (!server_) {
        spdlog::error("[SomeipFacadeImpl] 未初始化");
        return false;
    }

    spdlog::info("[SomeipFacadeImpl] 启动");

    // 启动 IPC 服务器
    if (!server_->start(
        [this](ipc::MethodId method, const std::string& params_json, int client_fd) {
            return handle_request(method, params_json, client_fd);
        },
        [this](int client_fd) {
            handle_client_disconnect(client_fd);
        }
    )) {
        spdlog::error("[SomeipFacadeImpl] IPC 服务器启动失败");
        return false;
    }

    return true;
}

void SomeipFacadeImpl::stop() {
    spdlog::info("[SomeipFacadeImpl] 停止");
    if (server_) {
        server_->stop();
    }
}

bool SomeipFacadeImpl::is_connected() const {
    return server_ && server_->is_running();
}

void SomeipFacadeImpl::on_report_software_inventory(
    std::function<void(const std::vector<uint8_t>&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("[SomeipFacadeImpl] 注册上行回调");
    inventory_callback_ = std::move(callback);
}

bool SomeipFacadeImpl::push_fota_command(const std::vector<uint8_t>& payload) {
    if (!server_ || !server_->is_running()) {
        spdlog::warn("[SomeipFacadeImpl] 未连接，推送失败");
        return false;
    }

    spdlog::info("[SomeipFacadeImpl] push_fota_command: size={}", payload.size());

    // Base64 编码
    std::string payload_base64 = ipc::IpcSerializer::base64_encode(payload);

    // 构造 JSON
    nlohmann::json j;
    j["payload_base64"] = payload_base64;

    // 推送事件
    server_->push_event(ipc::EventType::FOTA_COMMAND, j.dump());

    return true;
}

std::string SomeipFacadeImpl::handle_request(ipc::MethodId method, const std::string& params_json, int client_fd) {
    spdlog::debug("[SomeipFacadeImpl] 处理请求: method={}, client_fd={}", static_cast<uint32_t>(method), client_fd);

    switch (method) {
        case ipc::MethodId::GET_NET_STATUS:
            return handle_get_net_status(params_json);

        case ipc::MethodId::REPORT_SOFTWARE_INVENTORY:
            return handle_report_software_inventory(params_json, client_fd);

        case ipc::MethodId::SUBSCRIBE_NET_STATUS:
            return handle_subscribe(ipc::EventType::NET_STATUS_CHANGED, params_json, client_fd);

        case ipc::MethodId::SUBSCRIBE_REMOTE_COMMANDS:
            return handle_subscribe(ipc::EventType::REMOTE_COMMAND, params_json, client_fd);

        case ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS:
            return handle_subscribe(ipc::EventType::FOTA_COMMAND, params_json, client_fd);

        default:
            spdlog::warn("[SomeipFacadeImpl] 未知方法: {}", static_cast<uint32_t>(method));
            return "{\"error\":\"Unknown method\"}";
    }
}

void SomeipFacadeImpl::handle_client_disconnect(int client_fd) {
    spdlog::info("[SomeipFacadeImpl] 客户端断开: client_fd={}", client_fd);
}

std::string SomeipFacadeImpl::handle_get_net_status(const std::string& params_json) {
    if (!net_status_provider_ || !net_status_provider_->is_available()) {
        return "{\"error\":\"Net status provider not available\"}";
    }

    auto status = net_status_provider_->get_net_status();

    nlohmann::json j;
    j["is_connected"] = status.is_connected;
    j["signal_strength"] = status.signal_strength;
    j["network_type"] = status.network_type;
    j["operator"] = status.operator_name;

    return j.dump();
}

std::string SomeipFacadeImpl::handle_report_software_inventory(const std::string& params_json, int client_fd) {
    try {
        nlohmann::json j = nlohmann::json::parse(params_json);
        std::string snapshot_base64 = j.value("snapshot_base64", "");

        if (snapshot_base64.empty()) {
            return "{\"success\":false,\"error\":\"Missing snapshot_base64\"}";
        }

        // Base64 解码
        std::vector<uint8_t> snapshot = ipc::IpcSerializer::base64_decode(snapshot_base64);

        // 调用上行回调
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (inventory_callback_) {
                inventory_callback_(snapshot);
            } else {
                spdlog::warn("[SomeipFacadeImpl] 无上行回调注册");
            }
        }

        return "{\"success\":true}";
    } catch (const std::exception& e) {
        spdlog::error("[SomeipFacadeImpl] 解析 snapshot 失败: {}", e.what());
        return "{\"success\":false,\"error\":\"Invalid JSON\"}";
    }
}

std::string SomeipFacadeImpl::handle_subscribe(ipc::EventType type, const std::string& params_json, int client_fd) {
    // 记录订阅
    server_->add_subscription(client_fd, type);

    return "{\"success\":true}";
}

} // namespace tsp
} // namespace tbox
