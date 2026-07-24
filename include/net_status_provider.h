// include/net_status_provider.h
#pragma once

#include <string>
#include <memory>

namespace tbox {
namespace tsp {

class NetStatusProvider {
public:
    virtual ~NetStatusProvider() = default;

    struct NetStatus {
        bool is_connected = false;
        int signal_strength = 0;      // 0-100
        std::string network_type;     // "4G", "5G", "WiFi", etc.
        std::string operator_name;    // "CMCC", "CUCC", "CTCC", etc.
    };

    virtual NetStatus get_net_status() = 0;
    virtual bool is_available() const = 0;
};

// Mock 实现（当前阶段使用）
class MockNetStatusProvider : public NetStatusProvider {
public:
    NetStatus get_net_status() override;
    bool is_available() const override;
};

// 系统实现（读取系统文件）
class SystemNetStatusProvider : public NetStatusProvider {
public:
    NetStatus get_net_status() override;
    bool is_available() const override;

private:
    bool read_interface_status();
    int read_signal_strength();
    std::string read_network_type();
    std::string read_operator();
};

// 工厂方法
class NetStatusProviderFactory {
public:
    enum class ProviderType {
        MOCK,
        SYSTEM
    };

    static std::unique_ptr<NetStatusProvider> create(ProviderType type);
};

} // namespace tsp
} // namespace tbox
