// src/mqtt_client_adapter.cpp
#include "mqtt_client_adapter.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

MqttClientAdapter::MqttClientAdapter(const std::string& socket_path)
    : socket_path_(socket_path)
    , client_(std::make_unique<::tbox::mqtt::Client>(socket_path_)) {
}

MqttClientAdapter::~MqttClientAdapter() {
    stop();
}

bool MqttClientAdapter::initialize() {
    LogAdapter::mqtt_client().info("tsp.mqtt.initializing", "MqttClientAdapter 初始化");
    initialized_ = true;
    return true;
}

bool MqttClientAdapter::start() {
    if (!initialized_) {
        LogAdapter::mqtt_client().error("tsp.mqtt.not_initialized", "未初始化");
        return false;
    }
    LogAdapter::mqtt_client().info("tsp.mqtt.starting", "MqttClientAdapter 启动");
    started_ = true;
    return true;
}

void MqttClientAdapter::stop() {
    LogAdapter::mqtt_client().info("tsp.mqtt.stopping", "MqttClientAdapter 停止");
    // 取消下行订阅（RAII 析构）
    downlink_sub_.cancel();
    started_ = false;
    if (client_) {
        client_->disconnect();
    }
}

bool MqttClientAdapter::registerRoute(const std::string& internal_addr,
                                      const std::string& topic,
                                      const std::string& direction,
                                      int qos) {
    ::tbox::mqtt::RouteEntry entry;
    entry.internal_addr = internal_addr;
    entry.mqtt_topic = topic;
    entry.direction = (direction == "down")
        ? ::tbox::mqtt::RouteEntry::Direction::DOWN
        : ::tbox::mqtt::RouteEntry::Direction::UP;
    entry.qos = static_cast<::tbox::mqtt::QoS>(qos);

    auto result = client_->registerRoute(entry);

    auto log = LogAdapter::route();
    if (result.ok) {
        log.info("tsp.route.register.succeeded", "路由注册成功", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"direction", tbox::fw::log::FieldValue::makeString(direction)},
            {"qos", tbox::fw::log::FieldValue::makeInt(qos)}
        });
    } else {
        log.error("tsp.route.register.failed", "路由注册失败", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"direction", tbox::fw::log::FieldValue::makeString(direction)},
            {"qos", tbox::fw::log::FieldValue::makeInt(qos)}
        });
    }
    return result.ok;
}

MqttPublishResult MqttClientAdapter::publish(const std::string& msg_id,
                                             const std::string& topic,
                                             const std::vector<uint8_t>& payload,
                                             int qos,
                                             const std::string& content_type,
                                             const std::string& trace_id,
                                             const std::string& request_id) {
    ::tbox::mqtt::PublishEnvelope env;
    env.msg_id = msg_id;
    env.topic = topic;
    env.qos = static_cast<::tbox::mqtt::QoS>(qos);
    env.content_type = content_type;
    env.payload = payload;
    env.trace_id = trace_id;
    env.request_id = request_id;

    auto pr = client_->publish(env);

    MqttPublishResult out;
    out.accepted = pr.accepted;
    out.outcome = (pr.outcome == ::tbox::mqtt::PublishOutcome::UNKNOWN)
        ? PublishOutcome::UNKNOWN : PublishOutcome::ACCEPTED;
    return out;
}

bool MqttClientAdapter::subscribe(const std::string& topic,
                                  int qos,
                                  MessageCallback callback) {
    LogAdapter::mqtt_client().info("tsp.mqtt.subscribe", "订阅主题", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"qos", tbox::fw::log::FieldValue::makeInt(qos)}
    });

    ::tbox::mqtt::Route route;
    route.topic = topic;
    route.qos = static_cast<::tbox::mqtt::QoS>(qos);

    // 包装回调：tbox::mqtt::MessageCallback -> MqttFacade::MessageCallback
    ::tbox::mqtt::MessageCallback wrapped =
        [cb = std::move(callback)](const std::string& t, const std::vector<uint8_t>& payload) {
            if (cb) cb(t, payload);
        };

    downlink_sub_ = client_->subscribe(route, wrapped);
    return downlink_sub_.isActive();
}

bool MqttClientAdapter::is_connected() const {
    if (!client_) return false;
    return client_->getConnectionState() == ::tbox::mqtt::ConnectionState::CONNECTED;
}

} // namespace tsp
} // namespace tbox
