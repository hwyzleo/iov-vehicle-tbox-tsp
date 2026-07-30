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
// publish 返回 accepted/unknown（accepted ≠ Broker PUBACK）。
class MqttClientAdapter : public MqttFacade {
public:
    explicit MqttClientAdapter(const std::string& socket_path = "/tmp/tbox-mqtt.sock");
    ~MqttClientAdapter() override;

    bool initialize() override;
    bool start() override;
    void stop() override;

    bool registerRoute(const std::string& internal_addr,
                       const std::string& topic,
                       const std::string& direction,
                       int qos) override;

    MqttPublishResult publish(const std::string& msg_id,
                              const std::string& topic,
                              const std::vector<uint8_t>& payload,
                              int qos,
                              const std::string& content_type = "application/x-protobuf",
                              const std::string& trace_id = "",
                              const std::string& request_id = "") override;

    bool subscribe(const std::string& topic,
                   int qos,
                   MessageCallback callback) override;

    bool is_connected() const override;

    // ---- 业务订阅快照 (CR-004 §5, §11.5 迁移实现) ----
    // 迁移期 MQTT 尚未提供批量原子接口，adapter 展开模板后逐条调用 registerRoute，
    // 不宣称真正原子替换；真正原子契约由配套 MQTT DSN-CR 提供。
    ReplaceSnapshotResult replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) override;
    SnapshotStatusResult getSubscriptionSnapshotStatus(
        const std::string& owner, uint64_t generation) override;

    // 设置当前设备身份（ecu_uid），用于 Topic 模板展开 (CR-004 §4)
    void set_device_identity(const std::string& ecu_uid);

private:
    std::string socket_path_;
    std::unique_ptr<::tbox::mqtt::Client> client_;
    bool initialized_ = false;
    bool started_ = false;

    // 持有下行订阅句柄（RAII），析构自动取消
    ::tbox::fw::ipc::Subscription downlink_sub_;
    std::string device_identity_;
    // 迁移期缓存最近一次快照与结果，用于 getSubscriptionSnapshotStatus 查询
    SubscriptionSnapshot last_snapshot_;
    ReplaceSnapshotResult last_result_;
    mutable std::mutex mutex_;
};

} // namespace tsp
} // namespace tbox
