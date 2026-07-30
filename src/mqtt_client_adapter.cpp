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

void MqttClientAdapter::set_device_identity(const std::string& ecu_uid) {
    std::lock_guard<std::mutex> lock(mutex_);
    device_identity_ = ecu_uid;
}

ReplaceSnapshotResult MqttClientAdapter::replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) {
    ReplaceSnapshotResult result;

    std::string ecu_uid;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ecu_uid = device_identity_;
    }
    if (ecu_uid.empty()) {
        result.status = SnapshotStatus::REJECTED;
        result.reason_code = "device_identity_missing";
        LogAdapter::mqtt_client().error(
            "tsp.subscription.snapshot.rejected",
            "订阅快照提交失败：设备身份缺失", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.generation))},
                {"reason_code",
                 tbox::fw::log::FieldValue::makeString("device_identity_missing")}
            });
        return result;
    }

    // MQTT IPC 不可用时结果未知，使用相同 generation 查询/重试 (CR-004 §11.3)
    if (!is_connected()) {
        result.status = SnapshotStatus::UNKNOWN;
        result.reason_code = "mqtt_not_connected";
        return result;
    }

    // 迁移路径：逐条 registerRoute（CR-004 §11.5）。
    // 注意：非真正原子替换，部分失败时已注册路由不回滚。
    std::vector<std::string> rejected;
    bool all_ok = true;
    for (const auto& item : snapshot.items) {
        std::string topic = expand_topic_template(item.topic_template, ecu_uid);
        bool ok = false;
        if (item.direction == Direction::UP) {
            ok = registerRoute(item.route_id, topic, "up", item.qos);
        } else if (item.direction == Direction::DOWN) {
            ok = registerRoute(item.route_id, topic, "down", item.qos);
        } else {  // BIDIRECTIONAL：注册 up + down 两条映射
            bool up = registerRoute(item.route_id, topic, "up", item.qos);
            bool down = registerRoute(item.route_id, topic, "down", item.qos);
            ok = up && down;
        }
        if (!ok) {
            rejected.push_back(item.route_id);
            all_ok = false;
        }
    }

    if (all_ok) {
        result.status = SnapshotStatus::ACCEPTED;
        result.accepted_generation = snapshot.generation;
        std::lock_guard<std::mutex> lock(mutex_);
        last_snapshot_ = snapshot;
        last_result_ = result;
    } else {
        result.status = SnapshotStatus::REJECTED;
        result.rejected_route_ids = std::move(rejected);
        result.reason_code = "route_register_failed";
        LogAdapter::route().warn(
            "tsp.subscription.snapshot.partial_failed",
            "迁移路径部分路由注册失败（非原子，已注册项不回滚）", {
                {"generation",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.generation))},
                {"rejected_count",
                 tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result.rejected_route_ids.size()))}
            });
    }
    return result;
}

SnapshotStatusResult MqttClientAdapter::getSubscriptionSnapshotStatus(
        const std::string& owner, uint64_t generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    SnapshotStatusResult r;
    r.generation = generation;
    if (owner == last_snapshot_.owner && generation == last_snapshot_.generation) {
        r.status = last_result_.status;
        r.content_digest = last_snapshot_.content_digest;
        r.registration_complete = last_snapshot_.registration_complete;
    } else {
        r.status = SnapshotStatus::UNKNOWN;
    }
    return r;
}

} // namespace tsp
} // namespace tbox
