// include/mqtt_facade.h
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace tbox {
namespace tsp {

// 消息回调：topic + payload
using MessageCallback = std::function<void(const std::string& topic,
                                            const std::vector<uint8_t>& payload)>;

// MQTT Facade —— 对 TBOX-MQTT 服务的 IPC 客户端接口
// SPEC §5.1: registerRoute(internalAddr, topic, direction, qos)
//           publish(topic, payload, qos) / onMessage(topic, handler)
class MqttFacade {
public:
    virtual ~MqttFacade() = default;

    // 初始化（建立与 TBOX-MQTT 的 IPC 连接）
    virtual bool initialize() = 0;

    // 启动（注册路由、订阅下行）
    virtual bool start() = 0;

    // 停止
    virtual void stop() = 0;

    // 注册路由（SPEC §5.1）
    // direction: "up" 或 "down"
    // 启动时调用，注册 fota 上下行路由
    virtual bool registerRoute(const std::string& internal_addr,
                               const std::string& topic,
                               const std::string& direction,
                               int qos) = 0;

    // 发布消息到云端（SPEC §5.1）
    // 经 TBOX-MQTT publish 到指定 topic
    virtual bool publish(const std::string& topic,
                         const std::vector<uint8_t>& payload,
                         int qos) = 0;

    // 订阅下行消息（SPEC §5.1）
    // 收到下行时通过 callback 通知
    virtual bool subscribe(const std::string& topic,
                           int qos,
                           MessageCallback callback) = 0;

    // 检查 TBOX-MQTT 连接状态
    virtual bool is_connected() const = 0;
};

} // namespace tsp
} // namespace tbox
