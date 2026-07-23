// include/mqtt_facade_stub.h
#pragma once

#include "mqtt_facade.h"
#include <map>
#include <mutex>

namespace tbox {
namespace tsp {

// MqttFacade 的 Stub 实现
// 开发阶段使用，通过日志模拟 IPC 调用
// 后续替换为真正的 TBOX-MQTT IPC 客户端实现
class MqttFacadeStub : public MqttFacade {
public:
    MqttFacadeStub();
    ~MqttFacadeStub() override;

    bool initialize() override;
    bool start() override;
    void stop() override;

    bool registerRoute(const std::string& internal_addr,
                       const std::string& topic,
                       const std::string& direction,
                       int qos) override;

    bool publish(const std::string& topic,
                 const std::vector<uint8_t>& payload,
                 int qos) override;

    bool subscribe(const std::string& topic,
                   int qos,
                   MessageCallback callback) override;

    bool is_connected() const override;

    // 测试辅助：模拟收到下行消息
    void simulate_incoming(const std::string& topic,
                           const std::vector<uint8_t>& payload);

private:
    bool initialized_ = false;
    bool started_ = false;
    bool connected_ = false;

    struct RouteInfo {
        std::string internal_addr;
        std::string direction;
        int qos;
    };
    std::map<std::string, RouteInfo> routes_;

    struct SubscriptionInfo {
        int qos;
        MessageCallback callback;
    };
    std::map<std::string, SubscriptionInfo> subscriptions_;

    mutable std::mutex mutex_;
};

} // namespace tsp
} // namespace tbox
