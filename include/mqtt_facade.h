// include/mqtt_facade.h
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include "tbox/tsp/types.h"
#include "subscription_types.h"

namespace tbox {
namespace tsp {

// 消息回调：topic + payload（原始二进制）
using MessageCallback = std::function<void(const std::string& topic,
                                            const std::vector<uint8_t>& payload)>;

// MQTT 发布结果（CR-003 §4: accepted ≠ Broker PUBACK）
struct MqttPublishResult {
    bool accepted = false;                          // MQTT daemon 已接管
    PublishOutcome outcome = PublishOutcome::ACCEPTED;
};

// MQTT Facade -- 对 TBOX-MQTT 服务的客户端接口
// SPEC §5.1 / CR-003: TSP 对 MQTT 只使用 tbox::mqtt_client 的
// registerRoute/publish/subscribe，不操作其 socket/method/JSON，也不持有 MQTT 连接。
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
    virtual bool registerRoute(const std::string& internal_addr,
                               const std::string& topic,
                               const std::string& direction,
                               int qos) = 0;

    // 发布消息到云端（SPEC §5.1, CR-003 §4）
    // msg_id 为幂等关联键；accepted 仅表示 MQTT daemon 接管，不等于 Broker PUBACK。
    // outcome=UNKNOWN 表示响应丢失，需用相同 msg_id 查询/重试。
    virtual MqttPublishResult publish(const std::string& msg_id,
                                      const std::string& topic,
                                      const std::vector<uint8_t>& payload,
                                      int qos,
                                      const std::string& content_type = "application/x-protobuf",
                                      const std::string& trace_id = "",
                                      const std::string& request_id = "") = 0;

    // 订阅下行消息（SPEC §5.1）
    virtual bool subscribe(const std::string& topic,
                           int qos,
                           MessageCallback callback) = 0;

    // ---- 业务订阅快照 (CR-004 §5, §11) ----
    // TSP 以完整、版本化快照向 MQTT 提交当前订阅集合。
    // 最终 wire schema 由配套 MQTT DSN-CR 固化；本接口为 TSP 侧契约。
    // accepted 仅表示 MQTT daemon 接受本地投影，不等于 Broker SUBACK。
    virtual ReplaceSnapshotResult replaceSubscriptionSnapshot(
        const SubscriptionSnapshot& snapshot) {
        ReplaceSnapshotResult r;
        r.status = SnapshotStatus::REJECTED;
        r.reason_code = "not_supported";
        return r;
    }

    // 查询指定 owner/generation 的接受状态，用于响应丢失后的幂等收敛。
    virtual SnapshotStatusResult getSubscriptionSnapshotStatus(
        const std::string& /*owner*/, uint64_t /*generation*/) {
        return SnapshotStatusResult{};
    }

    // 检查 TBOX-MQTT 连接状态
    virtual bool is_connected() const = 0;
};

} // namespace tsp
} // namespace tbox
