// include/mqtt_facade.h
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include "subscription_types.h"

namespace tbox {
namespace tsp {

// MQTT 投递结果（CR-009：仅投递阶段语义，不完成业务 exchange）
// accepted 表示 MQTT daemon 已接管；outcome=Unknown 表示响应丢失、投递结果未知。
enum class MqttDeliveryOutcome : uint8_t {
    Accepted = 0,   // MQTT daemon 已接管（≠ Broker PUBACK）
    Unknown         // 响应丢失，投递结果未知
};

// MQTT 发布结果（CR-003 §4: accepted ≠ Broker PUBACK）
struct MqttPublishResult {
    bool accepted = false;                          // MQTT daemon 已接管
    MqttDeliveryOutcome outcome = MqttDeliveryOutcome::Accepted;
};

// Routed downlink 事件 (CR-006 §6.1)
// MQTT daemon 将 Broker 下行完整 Topic 映射为 owner/route_id/target 事件，
// TSP 按稳定业务路由分发，不解析完整 Topic。完整 Topic 默认不进入本契约。
struct RoutedDownlinkEvent {
    std::string owner;            // 订阅 owner，如 "tsp"
    std::string route_id;         // owner 内稳定路由标识，如 "fota.downlink"
    std::string target;           // 目标处理器，如 "tsp.fota"
    uint8_t qos = 0;              // 0/1/2
    std::vector<uint8_t> payload; // 业务二进制 payload（单一序列化 Envelope）
    std::string request_id;       // 关联标识
    std::string trace_id;         // 可选关联标识
};

// Routed downlink 业务回调 (CR-006 §6.1)
using RoutedDownlinkCallback =
    std::function<void(const RoutedDownlinkEvent&)>;

// MQTT Facade -- 对 TBOX-MQTT 服务的客户端接口
// SPEC §5.1 / CR-006: TSP 对 MQTT 只使用 tbox::mqtt_client 的
// publishRoute / subscribeRoutedDownlink / replaceSubscriptionSnapshot，
// 不操作其 socket/method/JSON，也不持有 MQTT 连接。
// CR-009: legacy 完整 Topic publish/subscribe/registerRoute 路径已删除。
class MqttFacade {
public:
    virtual ~MqttFacade() = default;

    // 初始化（建立与 TBOX-MQTT 的 IPC 连接）
    virtual bool initialize() = 0;

    // 启动
    virtual bool start() = 0;

    // 停止
    virtual void stop() = 0;

    // ---- Route-based 发布与下行 (CR-006 §5, §6) ----
    // 上行：按 owner + route_id 发布，不传完整 Topic/UID (CR-006 §5)。
    // accepted 仅表示 MQTT daemon 接管，不等于 Broker PUBACK；outcome=UNKNOWN
    // 表示响应丢失，需用相同 msg_id 查询/重试。
    virtual MqttPublishResult publishRoute(const std::string& owner,
                                           const std::string& route_id,
                                           const std::string& msg_id,
                                           const std::vector<uint8_t>& payload,
                                           int qos,
                                           const std::string& content_type = "application/x-protobuf",
                                           const std::string& trace_id = "",
                                           const std::string& request_id = "") = 0;

    // 下行：订阅 routed downlink 事件，仅建立 IPC 事件通道，不触发 Broker SUBSCRIBE
    // (CR-006 §6)。Broker 订阅由 replaceSubscriptionSnapshot 的 route 投影驱动。
    // 返回 bool；句柄由实现内部持有（RAII），stop/析构时取消。
    virtual bool subscribeRoutedDownlink(const std::string& owner,
                                         RoutedDownlinkCallback callback) = 0;

    // ---- 业务订阅快照 (CR-004 §5, §11) ----
    // TSP 以完整、版本化快照向 MQTT 提交当前订阅集合。
    // accepted 仅表示 MQTT daemon 接受本地投影，不等于 Broker SUBACK。
    virtual ReplaceSnapshotResult replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) = 0;

    // 查询指定 owner/generation 的接受状态，用于响应丢失后的幂等收敛。
    virtual SnapshotStatusResult getSubscriptionSnapshotStatus(
        const std::string& owner, uint64_t generation) = 0;

    // 检查 TBOX-MQTT 连接状态
    virtual bool is_connected() const = 0;
};

} // namespace tsp
} // namespace tbox
