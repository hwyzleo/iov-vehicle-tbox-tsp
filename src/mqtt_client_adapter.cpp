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
    // 取消 routed 下行订阅与 readiness 事件订阅（RAII 析构，CR-006 §6 / CR-014 §5）
    routed_sub_.cancel();
    cloud_ready_sub_.cancel();
    capability_sub_.cancel();
    started_ = false;
    if (client_) {
        client_->disconnect();
    }
}

bool MqttClientAdapter::is_connected() const {
    if (!client_) return false;
    return client_->getConnectionState() == ::tbox::mqtt::ConnectionState::CONNECTED;
}

MqttPublishResult MqttClientAdapter::publishRoute(const std::string& owner,
                                                   const std::string& route_id,
                                                   const std::string& msg_id,
                                                   const std::vector<uint8_t>& payload,
                                                   int qos,
                                                   const std::string& content_type,
                                                   const std::string& trace_id,
                                                   const std::string& request_id) {
    // CR-006 §5: 按 owner + route_id 发布，不传完整 Topic/UID。
    // accepted 仅表示 MQTT daemon 接管，不等于 Broker PUBACK。
    auto pr = client_->publishRoute(owner, route_id, msg_id, payload,
        static_cast<::tbox::mqtt::QoS>(qos),
        ::tbox::mqtt::Priority::NORMAL,
        content_type, trace_id, request_id);

    MqttPublishResult out;
    out.accepted = pr.accepted;
    out.outcome = (pr.outcome == ::tbox::mqtt::PublishOutcome::UNKNOWN)
        ? MqttDeliveryOutcome::Unknown : MqttDeliveryOutcome::Accepted;
    return out;
}

bool MqttClientAdapter::subscribeRoutedDownlink(const std::string& owner,
                                                 RoutedDownlinkCallback callback) {
    // CR-006 §6: 仅建立 IPC 事件通道，不触发 Broker SUBSCRIBE。
    LogAdapter::mqtt_client().info("tsp.mqtt.subscribe_routed", "订阅 routed downlink", {
        {"owner", tbox::fw::log::FieldValue::makeString(owner)}
    });

    // 包装回调：tbox::mqtt::RoutedDownlinkEvent -> tbox::tsp::RoutedDownlinkEvent
    ::tbox::mqtt::RoutedDownlinkCallback wrapped =
        [cb = std::move(callback)](const ::tbox::mqtt::RoutedDownlinkEvent& ev) {
            if (!cb) return;
            RoutedDownlinkEvent out;
            out.owner = ev.owner;
            out.route_id = ev.route_id;
            out.target = ev.target;
            out.qos = ev.qos;
            out.payload = ev.payload;
            out.request_id = ev.request_id;
            out.trace_id = ev.trace_id;
            cb(out);
        };

    routed_sub_ = client_->subscribeRoutedDownlink(owner, wrapped);
    return routed_sub_.isActive();
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

// TSP SubscriptionCriticality -> wire
::tbox::mqtt::SubscriptionCriticality to_wire_criticality(
        SubscriptionCriticality c) {
    switch (c) {
        case SubscriptionCriticality::OPTIONAL:
            return ::tbox::mqtt::SubscriptionCriticality::OPTIONAL;
        case SubscriptionCriticality::GLOBAL_MANDATORY:
            return ::tbox::mqtt::SubscriptionCriticality::GLOBAL_MANDATORY;
        case SubscriptionCriticality::CAPABILITY_MANDATORY:
            return ::tbox::mqtt::SubscriptionCriticality::CAPABILITY_MANDATORY;
    }
    return ::tbox::mqtt::SubscriptionCriticality::OPTIONAL;
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
    wire.contract_version = snapshot.contract_version;
    wire.items.reserve(snapshot.items.size());
    for (const auto& item : snapshot.items) {
        ::tbox::mqtt::SubscriptionItem wi;
        wi.route_id = item.route_id;
        wi.topic_template = item.topic_template;  // 原样传模板，MQTT 侧展开 {ecu_uid}
        wi.direction = to_wire_direction(item.direction);
        wi.qos = item.qos;
        wi.target = item.target;
        wi.mandatory = item.mandatory;
        wi.enabled = item.enabled;                // CR-015
        wi.readiness_scope = item.readiness_scope;
        wi.criticality = to_wire_criticality(item.criticality);
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

// ============================================================
// CR-014/015: Cloud / Capability Readiness
// ============================================================
CloudReadiness MqttClientAdapter::getCloudReadiness() {
    CloudReadiness out;
    if (!client_) return out;
    auto wr = client_->getSubscriptionReadiness();
    out.cloud_ready = wr.cloud_ready;
    out.connection_generation = wr.connection_generation;
    out.cert_session_generation = wr.cert_session_generation;
    out.credential_id = wr.credential_id;
    out.credential_version = wr.credential_version;
    out.device_identity_digest = wr.device_identity_digest;
    out.certificate_ref = wr.certificate_ref;
    out.reason_code = wr.reason_code;
    out.contract_version = wr.contract_version;
    out.contract_supported = wr.contract_supported;
    return out;
}

bool MqttClientAdapter::subscribeCloudReadinessChanged(
        CloudReadinessCallback callback) {
    if (!client_) return false;
    ::tbox::mqtt::CloudReadinessCallback wrapped =
        [cb = std::move(callback)](const ::tbox::mqtt::CloudReadinessSnapshot& ev) {
            if (!cb) return;
            CloudReadiness out;
            out.cloud_ready = ev.cloud_ready;
            out.connection_generation = ev.connection_generation;
            out.cert_session_generation = ev.cert_session_generation;
            out.credential_id = ev.credential_id;
            out.credential_version = ev.credential_version;
            out.device_identity_digest = ev.device_identity_digest;
            out.certificate_ref = ev.certificate_ref;
            out.reason_code = ev.reason_code;
            out.contract_version = ev.contract_version;
            out.contract_supported = ev.contract_supported;
            cb(out);
        };
    cloud_ready_sub_ = client_->subscribeCloudReadinessChanged(std::move(wrapped));
    return cloud_ready_sub_.isActive();
}

CapabilityReadiness MqttClientAdapter::getCapabilityReadiness(
        const std::string& capability) {
    CapabilityReadiness out;
    out.capability = capability;
    if (!client_) return out;
    auto wr = client_->getCapabilityReadiness(capability);
    out.enabled = wr.enabled;
    out.contract_supported = wr.contract_supported;
    out.snapshot_accepted = wr.snapshot_accepted;
    out.uplink_ready = wr.uplink_ready;
    out.downlink_suback_ready = wr.downlink_suback_ready;
    out.ready = wr.ready;
    out.owner_generation = wr.owner_generation;
    out.connection_generation = wr.connection_generation;
    out.cert_session_generation = wr.cert_session_generation;
    out.reason_code = wr.reason_code;
    return out;
}

bool MqttClientAdapter::subscribeCapabilityReadinessChanged(
        const std::string& capability,
        CapabilityReadinessCallback callback) {
    if (!client_) return false;
    ::tbox::mqtt::CapabilityReadinessCallback wrapped =
        [cb = std::move(callback)](const ::tbox::mqtt::CapabilityReadiness& ev) {
            if (!cb) return;
            CapabilityReadiness out;
            out.capability = ev.capability;
            out.enabled = ev.enabled;
            out.contract_supported = ev.contract_supported;
            out.snapshot_accepted = ev.snapshot_accepted;
            out.uplink_ready = ev.uplink_ready;
            out.downlink_suback_ready = ev.downlink_suback_ready;
            out.ready = ev.ready;
            out.owner_generation = ev.owner_generation;
            out.connection_generation = ev.connection_generation;
            out.cert_session_generation = ev.cert_session_generation;
            out.reason_code = ev.reason_code;
            cb(out);
        };
    capability_sub_ = client_->subscribeCapabilityReadinessChanged(
        capability, std::move(wrapped));
    return capability_sub_.isActive();
}

} // namespace tsp
} // namespace tbox
