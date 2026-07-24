// src/mqtt_facade_stub.cpp
#include "mqtt_facade_stub.h"
#include "spdlog/spdlog.h"

#ifdef HAS_FRAMEWORK_LOG
#include "log_adapter.h"
#include "log_types.h"
#endif

namespace tbox {
namespace tsp {

MqttFacadeStub::MqttFacadeStub() = default;
MqttFacadeStub::~MqttFacadeStub() = default;

bool MqttFacadeStub::initialize() {
    spdlog::info("[MqttFacadeStub] 初始化（Stub 模式）");
    initialized_ = true;
    connected_ = true;  // Stub 假设始终连接
    return true;
}

bool MqttFacadeStub::start() {
    if (!initialized_) {
        spdlog::error("[MqttFacadeStub] 未初始化");
        return false;
    }
    spdlog::info("[MqttFacadeStub] 启动（Stub 模式）");
    started_ = true;
    return true;
}

void MqttFacadeStub::stop() {
    spdlog::info("[MqttFacadeStub] 停止");
    started_ = false;
    connected_ = false;
}

bool MqttFacadeStub::registerRoute(const std::string& internal_addr,
                                    const std::string& topic,
                                    const std::string& direction,
                                    int qos) {
    std::lock_guard<std::mutex> lock(mutex_);

#ifdef HAS_FRAMEWORK_LOG
    auto start = std::chrono::steady_clock::now();
#endif

    spdlog::info("[MqttFacadeStub] registerRoute: addr={}, topic={}, dir={}, qos={}",
                 internal_addr, topic, direction, qos);
    routes_[topic] = {internal_addr, direction, qos};

#ifdef HAS_FRAMEWORK_LOG
    auto end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto log = tbox::tsp::LogAdapter::route();
    log.info("tsp.route.register.succeeded", "路由注册成功", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"direction", tbox::fw::log::FieldValue::makeString(direction)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)},
        {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
    });
#endif

    return true;
}

bool MqttFacadeStub::publish(const std::string& topic,
                              const std::vector<uint8_t>& payload,
                              int qos) {
    if (!connected_) {
        spdlog::warn("[MqttFacadeStub] 未连接，发布失败: {}", topic);
        return false;
    }
    std::string payload_str(payload.begin(), payload.end());
    spdlog::info("[MqttFacadeStub] publish: topic={}, qos={}, size={}",
                 topic, qos, payload.size());
    spdlog::debug("[MqttFacadeStub] payload: {}", payload_str);
    return true;
}

bool MqttFacadeStub::subscribe(const std::string& topic,
                                int qos,
                                MessageCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("[MqttFacadeStub] subscribe: topic={}, qos={}", topic, qos);
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
        spdlog::info("[MqttFacadeStub] 模拟下行: topic={}, size={}", topic, payload.size());
        it->second.callback(topic, payload);
    } else {
        spdlog::warn("[MqttFacadeStub] 无订阅者: topic={}", topic);
    }
}

} // namespace tsp
} // namespace tbox
