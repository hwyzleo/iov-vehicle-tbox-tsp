// TBOX-TSP-DSN-CR-005 §3, §12.1; CR-009 §16: TspApplication 实现。
//
// 组合根装配顺序（CR-005 §4, §12.2, CR-009 §生命周期启动）：
//   Config snapshot -> mqtt_client(init+start) ->
//   TspRelayService(initializeLocal, 注入 VehicleMessageGatewayConfig) ->
//   NetStatusProvider -> TspFrameworkServer(construct) -> relay.set_event_publisher ->
//   relay.startMqttIntegration -> framework_server.start
// CR-006/CR-009: 唯一 route 模式，不获取 device_sn、不构造 prov_client。
// 清理顺序（§7.1, §12.4, §16.4）：见头文件不变量注释。

#include "tsp_application.h"
#include "tsp_build_config.h"

#include "tsp_relay_service.h"
#include "mqtt_client_adapter.h"
#include "tsp_framework_server.h"
#include "net_status_provider.h"
#include "tsp_ipc_protocol.h"
#include "log_adapter.h"

#include "config.h"
#include "log.h"
#include "utils.h"

#include <chrono>

namespace tbox {
namespace tsp {

TspApplication::TspApplication() = default;

// 析构定义于 .cpp：此时 TspRelayService/TspFrameworkServer 等已完整可见，
// unique_ptr 析构方可实例化（避免 incomplete type）。
TspApplication::~TspApplication() = default;

// ============================================================
// 服务标识
// ============================================================

std::string TspApplication::getServiceName() const {
    return "tsp";
}

// ============================================================
// 初始化
// ============================================================

bool TspApplication::initialize() {
    // Application::run 已完成 Config::load + Logger::init + 信号安装。
    // 此处只获取配置快照并装配业务组件（CR-005 §4.1：不再重复日志初始化）。
    auto cfg = getConfigSnapshot();
    if (!cfg) {
        LogAdapter::application().error(
            "tsp.application.config_unavailable",
            "Config snapshot unavailable after Application::load_config");
        return false;
    }

    // ---- 读取配置（framework-config 类型化访问，不使用 deprecated getConfig）----
    ipc_config_.max_frame_bytes = static_cast<uint32_t>(
        cfg->getInt("common.ipc.max_frame_bytes", 10485760));
    ipc_config_.receive_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.receive_timeout_ms", 60000));
    ipc_config_.connect_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.connect_timeout_ms", 3000));
    ipc_config_.listen_backlog =
        cfg->getInt("common.ipc.listen_backlog", 5);
    ipc_config_.reconnect.initial_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.initial_backoff_ms", 100));
    ipc_config_.reconnect.max_backoff_ms = static_cast<uint32_t>(
        cfg->getInt("common.ipc.reconnect.max_backoff_ms", 5000));
    ipc_config_.reconnect.multiplier =
        cfg->getDouble("common.ipc.reconnect.multiplier", 2.0);

    tsp_socket_path_ = cfg->getString("tsp.ipc.socket_path",
                                       tbox::tsp::ipc::DEFAULT_SOCKET_PATH);
    downlink_queue_size_ = static_cast<uint32_t>(
        cfg->getInt("tsp.ipc.downlink_queue_size", 256));
    slow_subscriber_policy_ = tbox::tsp::parse_slow_subscriber_policy(
        cfg->getString("tsp.ipc.slow_subscriber_policy", "disconnect"));

    std::string mqtt_socket_path = cfg->getString("tsp.mqtt.socket_path",
                                                   "/tmp/tbox-mqtt.sock");
    std::string store_root = cfg->getString("common.store.root", "/var/tbox");

    // ---- CR-009 §16.3: vehicle_message 资源/背压/allowlist 配置 ----
    vehicle_message_config_.limits.allowed_services.clear();
    // 首期固定 vehicle.fota（US-012）；后续新 service 经配置扩展。
    vehicle_message_config_.limits.allowed_services.push_back("vehicle.fota");
    vehicle_message_config_.limits.allowed_protocol_versions.clear();
    vehicle_message_config_.limits.allowed_protocol_versions.push_back(
        cfg->getString("tsp.vehicle_message.allowed_protocol_version", "fota-v1"));
    vehicle_message_config_.limits.max_envelope_bytes = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.max_envelope_bytes", 16384));
    vehicle_message_config_.limits.max_payload_bytes = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.max_payload_bytes", 8192));
    vehicle_message_config_.max_in_flight = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.max_in_flight", 64));
    vehicle_message_config_.downlink_queue_capacity = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.downlink_queue_capacity", 256));
    vehicle_message_config_.worker_count = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.worker_count", 1));
    vehicle_message_config_.default_exchange_timeout_ms = static_cast<uint32_t>(
        cfg->getInt("tsp.vehicle_message.default_exchange_timeout_ms", 2500));

    // 订阅目录节点：复杂嵌套序列，ImmutableConfigView 无通用数组访问，
    // 使用 ConfigManager::toYaml()（非 deprecated）取 tsp.subscriptions。
    YAML::Node catalog_node =
        hwyz::config::ConfigManager::instance().toYaml()["tsp"]["subscriptions"];

    // ---- a. mqtt_client（CR-003 §1: TSP 对 MQTT 只使用 tbox::mqtt_client）----
    mqtt_client_ = std::make_shared<MqttClientAdapter>(mqtt_socket_path);
    if (!mqtt_client_->initialize()) {
        LogAdapter::mqtt_client().error(
            "tsp.mqtt.init_failed", "MQTT 客户端初始化失败");
        mqtt_client_.reset();
        return false;
    }
    // transport 启动（当前实现仅置位，不阻塞；MQTT 不可用由注册器 DEGRADED 处理）
    if (!mqtt_client_->start()) {
        LogAdapter::mqtt_client().error(
            "tsp.mqtt.start_failed", "MQTT 客户端启动失败");
        mqtt_client_->stop();
        mqtt_client_.reset();
        return false;
    }
    init_stage_ = InitStage::MqttClientReady;

    // ---- b. TspRelayService 业务聚合（注入 MqttFacade& 与 gateway 配置）----
    relay_service_ = std::make_unique<TspRelayService>(mqtt_client_);
    if (!relay_service_->initializeLocal(store_root, catalog_node,
                                         vehicle_message_config_)) {
        LogAdapter::application().error(
            "tsp.application.relay_init_failed",
            "TspRelayService initializeLocal 失败");
        rollbackInitialization();
        return false;
    }

    // ---- c. NetStatusProvider ----
    net_status_provider_ = NetStatusProviderFactory::create(
        NetStatusProviderFactory::ProviderType::MOCK);

    // ---- d. TspFrameworkServer（Dispatcher + EventPublisher + IPC Server）----
    //        依赖 TspRelayService facade（VehicleMessageRelayInterface*），不访问 Application。
    framework_server_ = std::make_unique<TspFrameworkServer>(
        tsp_socket_path_, ipc_config_,
        relay_service_.get(),          // VehicleMessageRelayInterface
        net_status_provider_.get(),
        downlink_queue_size_, slow_subscriber_policy_);

    // ---- e. 接线：EVENT 下行经 EventPublisher 推送 ----
    relay_service_->set_event_publisher(framework_server_->event_publisher());

    // ---- f. MQTT 集成启动（提交快照、订阅下行、启动 gateway、恢复 timer）----
    if (!relay_service_->startMqttIntegration()) {
        LogAdapter::application().error(
            "tsp.application.mqtt_integration_failed",
            "TspRelayService startMqttIntegration 失败");
        rollbackInitialization();
        return false;
    }
    init_stage_ = InitStage::RelayReady;

    // ---- g. 启动 framework-ipc Server ----
    if (!framework_server_->start()) {
        LogAdapter::ipc_server().error(
            "tsp.ipc.start_failed", "IPC Server 启动失败", {});
        // bind/listen 失败不得遗留 socket 路径
        rollbackInitialization();
        return false;
    }
    init_stage_ = InitStage::IpcStarted;

    LogAdapter::ipc_server().info(
        "tsp.ipc.started", "IPC server started", {});
    return true;
}

void TspApplication::rollbackInitialization() {
    // 逆序释放已构造的组件（CR-005 §4.2, §12.2）；与 cleanup 共用幂等停止原语。
    // 无论失败发生在哪个阶段，按 IPC -> relay -> net_status -> mqtt 逆序安全拆解。
    if (framework_server_) {
        framework_server_->stop();
        framework_server_.reset();
    }
    if (relay_service_) {
        // 若已 startMqttIntegration，beginShutdown 置 reject-only 后 stop（join 线程/持久化）
        if (init_stage_ == InitStage::RelayReady ||
            init_stage_ == InitStage::IpcStarted) {
            relay_service_->beginShutdown();
        }
        relay_service_->stop();
        relay_service_.reset();
    }
    net_status_provider_.reset();
    if (mqtt_client_) {
        mqtt_client_->stop();
        mqtt_client_.reset();
    }
    init_stage_ = InitStage::None;
}

// ============================================================
// 长驻执行
// ============================================================

int TspApplication::execute() {
    // CR-005 §5: ready 不等于 snapshot REGISTERED、Broker SUBACK 或 Cloud Ready。
    tbox::fw::log::Logger::get("relay").info(
        "tsp.service.ready", "TSP local relay is ready");
    // 不维护私有 running/shutdown flag，不依赖 EINTR；统一等待 Application 退出状态。
    waitForShutdown(std::chrono::milliseconds{100});
    return 0;
}

// ============================================================
// 清理（幂等有序停机，CR-005 §7.1, §12.4, CR-009 §生命周期停止）
// ============================================================

void TspApplication::cleanup() {
    // 1. Quiesce：relay 进入 STOPPING，reject-only，拒绝新 VehicleMessage exchange/注册
    if (relay_service_) {
        relay_service_->beginShutdown();
    }
    // 2-5. 停止 relay 业务（停新 publish/重试/timer、取消下行 callback、
    //      in-flight 收敛为 Stopping/Unknown、持久化 generation/dedup/receipt）
    if (relay_service_) {
        relay_service_->stop();
    }
    // 6. 停止 framework-ipc Server（中断 accept/read、关闭连接、join 线程）
    if (framework_server_) {
        framework_server_->stop();
    }
    // 7. 销毁 relay（业务内核）后再销毁 mqtt_client（relay 持有 MqttFacade& 引用）
    relay_service_.reset();
    if (mqtt_client_) {
        mqtt_client_->stop();
        mqtt_client_.reset();
    }
    // 8. 释放 NetStatusProvider
    net_status_provider_.reset();
    init_stage_ = InitStage::None;
    // 9. 最终日志 flush 由 Application::run 在 cleanup 后统一完成。
}

} // namespace tsp
} // namespace tbox
