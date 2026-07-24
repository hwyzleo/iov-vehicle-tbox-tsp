// src/net_status_provider.cpp
#include "net_status_provider.h"
#include <fstream>
#include <sstream>
#include "log_adapter.h"

namespace tbox {
namespace tsp {

// MockNetStatusProvider 实现
NetStatusProvider::NetStatus MockNetStatusProvider::get_net_status() {
    return {
        .is_connected = true,
        .signal_strength = 85,
        .network_type = "4G",
        .operator_name = "CMCC"
    };
}

bool MockNetStatusProvider::is_available() const {
    return true;
}

// SystemNetStatusProvider 实现
NetStatusProvider::NetStatus SystemNetStatusProvider::get_net_status() {
    NetStatus status;

    try {
        status.is_connected = read_interface_status();
        status.signal_strength = read_signal_strength();
        status.network_type = read_network_type();
        status.operator_name = read_operator();
    } catch (const std::exception& e) {
        tbox::tsp::LogAdapter::ipc_server().error("tsp.ipc.net_status_read_failed",
            std::string("Failed to read system net status: ") + e.what());
    }

    return status;
}

bool SystemNetStatusProvider::is_available() const {
    // 检查系统是否有网络接口
    return true;  // 简化实现
}

bool SystemNetStatusProvider::read_interface_status() {
    // 读取 /sys/class/net/ 下的接口状态
    std::ifstream file("/sys/class/net/eth0/operstate");
    if (file.is_open()) {
        std::string state;
        std::getline(file, state);
        return state == "up";
    }
    return false;
}

int SystemNetStatusProvider::read_signal_strength() {
    // 简化实现，返回固定值
    return 80;
}

std::string SystemNetStatusProvider::read_network_type() {
    // 简化实现，返回固定值
    return "4G";
}

std::string SystemNetStatusProvider::read_operator() {
    // 简化实现，返回固定值
    return "CMCC";
}

// NetStatusProviderFactory 实现
std::unique_ptr<NetStatusProvider> NetStatusProviderFactory::create(ProviderType type) {
    switch (type) {
        case ProviderType::MOCK:
            return std::make_unique<MockNetStatusProvider>();
        case ProviderType::SYSTEM:
            return std::make_unique<SystemNetStatusProvider>();
        default:
            return std::make_unique<MockNetStatusProvider>();
    }
}

} // namespace tsp
} // namespace tbox
