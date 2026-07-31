// TBOX-TSP-DSN-CR-005 §3, §12.1: TspRelayService 实现。
//
// 业务聚合装配顺序：Catalog -> Store -> Registrar -> FotaHandler
// 停止顺序（CR-005 §7.1）：FOTA callback -> 注册器重试/timer/线程 -> 持久化
// （各组件内部完成 generation/dedup/receipt 持久化与线程 join）。

#include "tsp_relay_service.h"

#include "subscription_catalog.h"
#include "subscription_store.h"
#include "subscription_registrar.h"
#include "fota_handler.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/errors.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

TspRelayService::TspRelayService(std::shared_ptr<MqttFacade> mqtt)
    : mqtt_(std::move(mqtt)) {
}

// 析构定义于 .cpp：此时 FotaHandler/MqttSubscriptionRegistrar 已完整可见，
// unique_ptr 析构方可实例化（避免 incomplete type）。
TspRelayService::~TspRelayService() {
    stop();
}

bool TspRelayService::initializeLocal(const std::string& device_sn,
                                      const std::string& store_root,
                                      const YAML::Node& catalog_node) {
    if (!mqtt_) {
        LogAdapter::application().error(
            "tsp.relay.init_failed", "MqttFacade 未注入");
        return false;
    }
    if (device_sn.empty()) {
        LogAdapter::application().error(
            "tsp.relay.init_failed", "device_sn 为空");
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

    // CR-003 §2, §4: FOTA 中继（去重/节流/回执）
    fota_handler_ = std::make_unique<FotaHandler>(mqtt_);
    if (!fota_handler_->initialize(device_sn)) {
        LogAdapter::fota().error("tsp.fota.init_failed", "FOTA 处理器初始化失败");
        fota_handler_.reset();
        registrar_.reset();
        store_.reset();
        catalog_.reset();
        return false;
    }
    fota_handler_->set_catalog(catalog_);

    LogAdapter::relay().info(
        "tsp.relay.initialized", "TspRelayService 本地初始化完成");
    return true;
}

bool TspRelayService::startMqttIntegration() {
    if (!registrar_ || !fota_handler_) {
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

    // CR-003 §4.2: 启动 FOTA 业务（订阅下行）
    if (!fota_handler_->start()) {
        LogAdapter::fota().error("tsp.fota.start_failed", "FOTA 处理器启动失败");
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
    // 停止顺序：FOTA 下行 callback -> 注册器重试/timer/监控线程 -> 持久化
    // （registrar_->stop() join 监控线程；fota_handler_->stop() 关闭下行处理）
    if (fota_handler_) fota_handler_->stop();
    if (registrar_) registrar_->stop();
    LogAdapter::relay().info("tsp.relay.stopped", "TspRelayService 已停止");
}

void TspRelayService::set_event_publisher(TspEventPublisher* publisher) {
    if (fota_handler_) fota_handler_->set_event_publisher(publisher);
}

bool TspRelayService::is_registration_ready() const {
    return registrar_ && registrar_->is_registration_ready();
}

ReportResult TspRelayService::handle_uplink(const FotaSnapshot& snapshot) {
    // STOPPING：reject-only，拒绝新上行（CR-005 §7.1 step1）
    if (stopping_.load(std::memory_order_acquire)) {
        ReportResult r;
        r.accepted = false;
        r.outcome = PublishOutcome::ACCEPTED;
        r.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        r.msg_id = snapshot.msg_id;
        return r;
    }
    if (!fota_handler_) {
        ReportResult r;
        r.accepted = false;
        r.msg_id = snapshot.msg_id;
        return r;
    }
    return fota_handler_->handle_uplink(snapshot);
}

RelayStatus TspRelayService::get_relay_status(const std::string& msg_id) {
    if (!fota_handler_) {
        RelayStatus s;
        s.msg_id = msg_id;
        return s;
    }
    return fota_handler_->get_relay_status(msg_id);
}

} // namespace tsp
} // namespace tbox
