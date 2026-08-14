// TBOX-TSP-DSN-CR-005 §3, §12.1; CR-009 §16: TspRelayService 实现。
//
// 业务聚合装配顺序：Catalog -> Store -> Registrar -> VehicleMessageGateway
// 停止顺序（CR-005 §7.1）：EVENT callback -> 注册器重试/timer/线程 -> 持久化
// （各组件内部完成 generation/dedup/receipt 持久化与线程 join）。

#include "tsp_relay_service.h"

#include "subscription_catalog.h"
#include "subscription_store.h"
#include "subscription_registrar.h"
#include "vehicle_message_gateway.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/errors.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

TspRelayService::TspRelayService(std::shared_ptr<MqttFacade> mqtt)
    : mqtt_(std::move(mqtt)) {
}

// 析构定义于 .cpp：此时 VehicleMessageGateway/MqttSubscriptionRegistrar 已完整可见，
// unique_ptr 析构方可实例化（避免 incomplete type）。
TspRelayService::~TspRelayService() {
    stop();
}

bool TspRelayService::initializeLocal(const std::string& store_root,
                                      const YAML::Node& catalog_node,
                                      const VehicleMessageGatewayConfig& gateway_config) {
    if (!mqtt_) {
        LogAdapter::application().error(
            "tsp.relay.init_failed", "MqttFacade 未注入");
        return false;
    }

    // CR-004 §11.1: 加载业务订阅目录（SSOT）
    catalog_ = std::make_shared<SubscriptionCatalog>();
    std::string catalog_error;
    if (!catalog_->load_from_yaml(catalog_node, catalog_error)) {
        LogAdapter::subscription().error(
            "tsp.subscription.catalog.invalid",
            "业务订阅目录加载失败: " + catalog_error);
        catalog_.reset();
        return false;
    }

    // CR-004 §11.2: generation 持久化
    store_ = std::make_shared<SubscriptionStore>(store_root);

    // CR-004 §11.3: 订阅快照注册器
    registrar_ = std::make_unique<MqttSubscriptionRegistrar>(
        mqtt_, catalog_, store_);

    // CR-009 §16: 通用 VehicleMessage 网关（correlation/EVENT 分流）
    gateway_ = std::make_unique<VehicleMessageGateway>(mqtt_);
    if (!gateway_->initialize(gateway_config)) {
        LogAdapter::relay().error(
            "tsp.vehicle_message.init_failed", "VehicleMessageGateway 初始化失败");
        gateway_.reset();
        registrar_.reset();
        store_.reset();
        catalog_.reset();
        return false;
    }

    LogAdapter::relay().info(
        "tsp.relay.initialized", "TspRelayService 本地初始化完成");
    return true;
}

bool TspRelayService::startMqttIntegration() {
    if (!registrar_ || !gateway_) {
        LogAdapter::application().error(
            "tsp.relay.start_failed", "TspRelayService 未初始化");
        return false;
    }

    // CR-004 §6: 提交业务订阅快照（Mandatory 完成本地提交前不宣告云路由 ready）
    if (!registrar_->start()) {
        LogAdapter::subscription().error(
            "tsp.subscription.start_failed", "订阅注册器启动失败");
        return false;
    }
    if (!registrar_->is_registration_ready()) {
        LogAdapter::subscription().warn(
            "tsp.subscription.not_ready", "Mandatory 快照未完成本地提交");
    }

    // CR-009: 启动 VehicleMessageGateway（订阅 routed downlink + 收敛 worker）
    if (!gateway_->start()) {
        LogAdapter::relay().error(
            "tsp.vehicle_message.start_failed", "VehicleMessageGateway 启动失败");
        // 回滚已启动的注册器（join 监控线程）
        registrar_->stop();
        return false;
    }

    LogAdapter::relay().info(
        "tsp.relay.mqtt_integration_started", "TspRelayService MQTT 集成已启动");
    return true;
}

void TspRelayService::beginShutdown() {
    stopping_.store(true, std::memory_order_release);
    LogAdapter::relay().info(
        "tsp.relay.stopping", "TspRelayService 进入 STOPPING，拒绝新中继请求");
}

void TspRelayService::stop() {
    stopping_.store(true, std::memory_order_release);
    // 停止顺序：VehicleMessageGateway（取消 routed downlink、收敛 in-flight）-> 
    // 注册器重试/timer/监控线程 -> 持久化
    if (gateway_) gateway_->stop();
    if (registrar_) registrar_->stop();
    LogAdapter::relay().info("tsp.relay.stopped", "TspRelayService 已停止");
}

void TspRelayService::set_event_publisher(TspEventPublisher* publisher) {
    if (gateway_) gateway_->set_event_publisher(publisher);
}

bool TspRelayService::is_registration_ready() const {
    return registrar_ && registrar_->is_registration_ready();
}

TransportResult<VehicleMessage> TspRelayService::exchange(
    const VehicleMessage& request,
    const ExchangeOptions& options,
    const CallContext& ctx) {
    // STOPPING：reject-only，拒绝新 exchange（CR-005 §7.1 step1）
    if (stopping_.load(std::memory_order_acquire)) {
        TransportResult<VehicleMessage> r;
        r.outcome = TransportOutcome::Stopping;
        r.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        r.error = "stopping";
        return r;
    }
    if (!gateway_) {
        TransportResult<VehicleMessage> r;
        r.outcome = TransportOutcome::Unavailable;
        r.error_code = static_cast<int32_t>(TspErrorCode::NOT_INITIALIZED);
        r.error = "gateway_not_ready";
        return r;
    }
    return gateway_->exchange(request, options, ctx);
}

} // namespace tsp
} // namespace tbox
