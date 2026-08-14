// TBOX-TSP-DSN-CR-005 §3, §12.1; CR-009 §16: TspApplication 进程级组合根。
//
// 继承 hwyz::Application，统一编排配置加载、framework-log 初始化、信号安装、
// 长驻执行与最终 flush；装配并释放 MqttClientAdapter / TspRelayService（业务聚合）/
// TspFrameworkServer（Dispatcher + EventPublisher + IPC Server）/ NetStatusProvider。
//
// 生命周期不变量（CR-005 §7.1, §12.4, CR-009 §生命周期）：
//   cleanup 顺序 = relay.beginShutdown -> relay.stop -> framework_server.stop
//                  -> relay.reset -> mqtt_client.stop/reset -> net_status.reset
//   relay 必须先于 mqtt_client 销毁（relay 持有 MqttFacade& 引用）；
//   IPC Server 必须先停并 join 线程后才销毁 dispatcher/eventpublisher（防 use-after-free）。
//
// 信号（CR-005 §6）：默认 graceful={SIGINT,SIGTERM}、ignored={SIGPIPE}、
//   fatal={SIGSEGV,SIGABRT}，由基类安装（SA_RESTART / SA_RESETHAND / SIG_IGN）。

#pragma once

#include "application.h"
#include "ipc.h"
#include "tsp_event_publisher.h"  // SlowSubscriberPolicy
#include "vehicle_message_gateway.h"  // VehicleMessageGatewayConfig

#include <memory>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

class MqttClientAdapter;
class TspRelayService;
class TspFrameworkServer;
class NetStatusProvider;

// 未标记 final，以便白盒单测通过派生访问 protected 生命周期钩子；
// 生产语义上 TspApplication 仍为组合根叶子类，不作为扩展基类。
class TspApplication : public hwyz::Application {
public:
    TspApplication();
    ~TspApplication() override;

protected:
    // ============ 服务标识 ============
    std::string getServiceName() const override;

    // ============ 生命周期 ============
    bool initialize() override;
    int execute() override;
    void cleanup() override;

private:
    enum class InitStage {
        None,
        MqttClientReady,
        RelayReady,
        IpcStarted
    };

    // 逆序释放已完成的初始化阶段（initialize 失败时调用，与 cleanup 共用停止原语）
    void rollbackInitialization();

    InitStage init_stage_{InitStage::None};

    // 组合根持有的组件（RAII）
    std::shared_ptr<MqttClientAdapter> mqtt_client_;
    std::unique_ptr<TspRelayService> relay_service_;
    std::unique_ptr<TspFrameworkServer> framework_server_;
    std::unique_ptr<NetStatusProvider> net_status_provider_;

    // initialize 读取、cleanup 复用的配置
    ::tbox::fw::ipc::IpcConfig ipc_config_{};
    std::string tsp_socket_path_;
    uint32_t downlink_queue_size_ = 256;
    SlowSubscriberPolicy slow_subscriber_policy_ = SlowSubscriberPolicy::kDisconnect;
    VehicleMessageGatewayConfig vehicle_message_config_;
};

} // namespace tsp
} // namespace tbox
