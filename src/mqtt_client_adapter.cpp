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

namespace {

// TSP Direction -> wire SnapshotDirection（枚举语义一致，显式映射避免依赖数值巧合）
::tbox::mqtt::SnapshotDirection to_wire_direction(Direction d) {
    switch (d) {
        case Direction::UP:            return ::tbox::mqtt::SnapshotDirection::UP;
        case Direction::DOWN:          return ::tbox::mqtt::SnapshotDirection::DOWN;
        case Direction::BIDIRECTIONAL: return ::tbox::mqtt::SnapshotDirection::BIDIRECTIONAL;
    }
    return ::tbox::mqtt::SnapshotDirection::UP;
}

// wire SnapshotAcceptStatus -> TSP SnapshotStatus
SnapshotStatus from_wire_status(::tbox::mqtt::SnapshotAcceptStatus s) {
    switch (s) {
        case ::tbox::mqtt::SnapshotAcceptStatus::ACCEPTED: return SnapshotStatus::ACCEPTED;
        case ::tbox::mqtt::SnapshotAcceptStatus::REJECTED: return SnapshotStatus::REJECTED;
        case ::tbox::mqtt::SnapshotAcceptStatus::UNKNOWN:  return SnapshotStatus::UNKNOWN;
    }
    return SnapshotStatus::UNKNOWN;
}

} // anonymous namespace

ReplaceSnapshotResult MqttClientAdapter::replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) {
    // CR-007 §4: 以完整版本化 owner 快照原子提交给 MQTT daemon
    // （REPLACE_SUBSCRIPTION_SNAPSHOT）。Topic 保存 {ecu_uid} 模板，由 MQTT 侧按
    // PROV 身份展开并驱动 Broker 订阅收敛；TSP 不再展开模板、不逐条 registerRoute。
    // ACCEPTED 仅表示 daemon 接受本地投影，≠ Broker SUBACK / Cloud Ready。
    // 传输失败由 client SDK 返回 UNKNOWN（同 generation 幂等重试，交由注册器调度）。
    ::tbox::mqtt::OwnerSubscriptionSnapshot wire;
    wire.owner = snapshot.owner;
    wire.generation = snapshot.generation;
    wire.content_digest = snapshot.content_digest;
    wire.registration_complete = snapshot.registration_complete;
    wire.items.reserve(snapshot.items.size());
    for (const auto& item : snapshot.items) {
        ::tbox::mqtt::SubscriptionItem wi;
        wi.route_id = item.route_id;
        wi.topic_template = item.topic_template;  // 原样传模板，MQTT 侧展开 {ecu_uid}
        wi.direction = to_wire_direction(item.direction);
        wi.qos = item.qos;
        wi.target = item.target;
        wi.mandatory = item.mandatory;
        wire.items.push_back(std::move(wi));
    }

    ::tbox::mqtt::ReplaceSnapshotResult wr =
        client_->replaceSubscriptionSnapshot(wire);

    ReplaceSnapshotResult result;
    result.status = from_wire_status(wr.status);
    result.accepted_generation = wr.accepted_generation;
    result.rejected_route_ids = wr.rejected_route_ids;
    result.reason_code = wr.reason_code;
    // 结果日志由注册器（MqttSubscriptionRegistrar）统一记录，避免重复。
    return result;
}

SnapshotStatusResult MqttClientAdapter::getSubscriptionSnapshotStatus(
        const std::string& owner, uint64_t generation) {
    // 响应丢失后的幂等收敛：直接向 MQTT daemon 查询该 owner/generation 的接受状态。
    ::tbox::mqtt::SnapshotStatusResult wr =
        client_->getSubscriptionSnapshotStatus(owner, generation);
    SnapshotStatusResult r;
    r.status = from_wire_status(wr.status);
    r.generation = wr.generation;
    r.content_digest = wr.content_digest;
    r.registration_complete = wr.registration_complete;
    return r;
}

} // namespace tsp
} // namespace tbox
