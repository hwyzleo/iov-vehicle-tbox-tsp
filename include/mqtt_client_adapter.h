// include/mqtt_client_adapter.h
#pragma once

#include "mqtt_facade.h"
#include "subscription_types.h"
#include "tbox/mqtt/client.h"
#include "ipc.h"

#include <memory>
#include <mutex>
#include <string>

namespace tbox {
namespace tsp {

// MqttClientAdapter -- MqttFacade 实现，内部使用 tbox::mqtt::Client (CR-003 §1)
//
// TSP 对 MQTT 只链接 tbox::mqtt_client，不操作其 socket/method/JSON，也不持有 MQTT 连接。
// CR-009：legacy 完整 Topic publish/subscribe/registerRoute 路径已删除；
// 唯一路径为 publishRoute + subscribeRoutedDownlink + replaceSubscriptionSnapshot。
// publishRoute accepted ≠ Broker PUBACK（仅投递阶段语义）。
class MqttClientAdapter : public MqttFacade {
public:
    explicit MqttClientAdapter(const std::string& socket_path = "/tmp/tbox-mqtt.sock");
    ~MqttClientAdapter() override;

    bool initialize() override;
    bool start() override;
    void stop() override;

    // ---- Route-based 发布与下行 (CR-006 §5, §6) ----
    MqttPublishResult publishRoute(const std::string& owner,
                                   const std::string& route_id,
                                   const std::string& msg_id,
                                   const std::vector<uint8_t>& payload,
                                   int qos,
                                   const std::string& content_type = "application/x-protobuf",
                                   const std::string& trace_id = "",
                                   const std::string& request_id = "") override;

    bool subscribeRoutedDownlink(const std::string& owner,
                                 RoutedDownlinkCallback callback) override;

    bool is_connected() const override;

    // ---- 业务订阅快照 (CR-007 §4) ----
    // 将完整版本化快照转换为 tbox::mqtt::OwnerSubscriptionSnapshot，经
    // client_->replaceSubscriptionSnapshot 原子提交给 MQTT daemon。
    // Topic 模板 {ecu_uid} 由 MQTT 侧按 PROV 身份展开并驱动 Broker 订阅收敛。
    ReplaceSnapshotResult replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) override;
    SnapshotStatusResult getSubscriptionSnapshotStatus(
        const std::string& owner, uint64_t generation) override;

private:
    std::string socket_path_;
    std::unique_ptr<::tbox::mqtt::Client> client_;
    bool initialized_ = false;
    bool started_ = false;

    // 持有 routed 下行订阅句柄（RAII），析构自动取消 (CR-006 §6)
    ::tbox::mqtt::RoutedSubscription routed_sub_;
    mutable std::mutex mutex_;
};

} // namespace tsp
} // namespace tbox
