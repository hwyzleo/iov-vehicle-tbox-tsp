// TBOX-TSP-DSN-CR-005 §3, §12.1; CR-009 §16: TspRelayService 业务聚合。
//
// 整体持有 SubscriptionCatalog / SubscriptionStore / MqttSubscriptionRegistrar /
// VehicleMessageGateway（correlation/EVENT 分流/下行投递），对 Dispatcher 暴露
// VehicleMessageRelayInterface facade。Application 是进程级组合根，负责构造/注入/
// 启停顺序；本聚合保持可独立测试。
//
// 边界（CR-005 §12.1, CR-009 §架构决策）：
// - 强内聚业务组件不得分别上提到 Application。
// - VehicleMessageGateway 为 RelayService 内聚组件；tbox::tsp_client 只暴露通用
//   exchange/subscribe，不暴露 FOTA 生成类型。
// - Dispatcher/EventPublisher 依赖本 facade，不访问 Application。
// - 下行有界队列留在 TspEventPublisher（IPC 层，Application 持有）。

#pragma once

#include "vehicle_message_gateway.h"
#include "mqtt_facade.h"
#include "subscription_types.h"

#include "yaml-cpp/yaml.h"

#include <atomic>
#include <memory>
#include <string>

namespace tbox {
namespace tsp {

class SubscriptionCatalog;
class SubscriptionStore;
class MqttSubscriptionRegistrar;
class TspEventPublisher;

class TspRelayService : public VehicleMessageRelayInterface {
public:
    explicit TspRelayService(std::shared_ptr<MqttFacade> mqtt);
    ~TspRelayService() override;

    TspRelayService(const TspRelayService&) = delete;
    TspRelayService& operator=(const TspRelayService&) = delete;

    // 初始化本地业务（不启动 MQTT transport）：
    //   加载并校验订阅目录、构造 store/registrar、构造并初始化 VehicleMessageGateway。
    // catalog_node 为 tsp.subscriptions 序列。失败返回 false 并清理已构造对象。
    bool initializeLocal(const std::string& store_root,
                         const YAML::Node& catalog_node,
                         const VehicleMessageGatewayConfig& gateway_config);

    // MQTT 集成启动：提交 owner=tsp 完整快照、订阅下行、启动恢复注册 timer。
    // MQTT 暂不可用时进入 DEGRADED/退避，不阻塞（返回 true）。
    bool startMqttIntegration();

    // 进入 STOPPING：reject-only，拒绝新 VehicleMessage exchange/订阅者注册 (CR-005 §7.1)。
    void beginShutdown();

    // 停止业务：停新 publish/重试/timer、取消下行 callback、in-flight 收敛为
    // Stopping/Unknown、持久化允许恢复的 generation/dedup/receipt 状态。
    void stop();

    // 下行事件推送器接线（Application 在 IPC 构造后调用）
    void set_event_publisher(TspEventPublisher* publisher);

    // 是否已完成 Mandatory 快照本地提交（业务 relay ready 门闩, CR-004 §6）
    bool is_registration_ready() const;

    // ---- VehicleMessageRelayInterface（委托 vehicle_message_gateway_；STOPPING 拒绝新 exchange）----
    TransportResult<VehicleMessage> exchange(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx) override;

private:
    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SubscriptionCatalog> catalog_;
    std::shared_ptr<SubscriptionStore> store_;
    std::unique_ptr<MqttSubscriptionRegistrar> registrar_;
    std::unique_ptr<VehicleMessageGateway> gateway_;
    std::atomic<bool> stopping_{false};
};

} // namespace tsp
} // namespace tbox
