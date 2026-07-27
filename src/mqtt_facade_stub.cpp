// src/mqtt_facade_stub.cpp
#include "mqtt_facade_stub.h"
#include "spdlog/spdlog.h"
#include "log_adapter.h"
#include "log_types.h"

namespace tbox {
namespace tsp {

MqttFacadeStub::MqttFacadeStub() = default;
MqttFacadeStub::~MqttFacadeStub() = default;

bool MqttFacadeStub::initialize() {
    LogAdapter::mqtt_client().info("tsp.mqtt.initializing", "MqttFacadeStub 初始化（Stub 模式）");
    initialized_ = true;
    connected_ = true;  // Stub 假设始终连接
    return true;
}

bool MqttFacadeStub::start() {
    if (!initialized_) {
        LogAdapter::mqtt_client().error("tsp.mqtt.not_initialized", "未初始化");
        return false;
    }
    LogAdapter::mqtt_client().info("tsp.mqtt.starting", "MqttFacadeStub 启动（Stub 模式）");
    started_ = true;
    return true;
}

void MqttFacadeStub::stop() {
    LogAdapter::mqtt_client().info("tsp.mqtt.stopping", "MqttFacadeStub 停止");
    started_ = false;
    connected_ = false;
}

bool MqttFacadeStub::registerRoute(const std::string& internal_addr,
                                    const std::string& topic,
                                    const std::string& direction,
                                    int qos) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto start = std::chrono::steady_clock::now();

    LogAdapter::mqtt_client().info("tsp.mqtt.register_route", "注册路由", {
        {"addr", tbox::fw::log::FieldValue::makeString(internal_addr)},
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"direction", tbox::fw::log::FieldValue::makeString(direction)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)}
    });
    routes_[topic] = {internal_addr, direction, qos};

    auto end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    LogAdapter::route().info("tsp.route.register.succeeded", "路由注册成功", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"direction", tbox::fw::log::FieldValue::makeString(direction)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)},
        {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
    });

    return true;
}

bool MqttFacadeStub::publish(const std::string& topic,
                              const std::vector<uint8_t>& payload,
                              int qos) {
    if (!connected_) {
        LogAdapter::mqtt_client().warn("tsp.mqtt.not_connected", "未连接，发布失败", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)}
        });
        return false;
    }
    std::string payload_str(payload.begin(), payload.end());
    LogAdapter::mqtt_client().info("tsp.mqtt.publish", "发布消息", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)},
        {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))}
    });
    LogAdapter::mqtt_client().debug("tsp.mqtt.publish_payload", "发布消息内容", {
        {"payload", tbox::fw::log::FieldValue::makeString(payload_str)}
    });
    return true;
}

bool MqttFacadeStub::subscribe(const std::string& topic,
                                int qos,
                                MessageCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    LogAdapter::mqtt_client().info("tsp.mqtt.subscribe", "订阅主题", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)}
    });
    subscriptions_[topic] = {qos, std::move(callback)};
    return true;
}

bool MqttFacadeStub::is_connected() const {
    return connected_;
}

void MqttFacadeStub::simulate_incoming(const std::string& topic,
                                        const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(topic);
    if (it != subscriptions_.end() && it->second.callback) {
        LogAdapter::mqtt_client().info("tsp.mqtt.simulate_incoming", "模拟下行", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))}
        });
        it->second.callback(topic, payload);
    } else {
        LogAdapter::mqtt_client().warn("tsp.mqtt.no_subscribers", "无订阅者", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)}
        });
    }
}

} // namespace tsp
} // namespace tbox
