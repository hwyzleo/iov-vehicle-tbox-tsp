// TBOX-TSP framework-ipc Server 接线 (CR-003 §1, §3; CR-009 §Client 与 IPC 契约)
//
// TspFrameworkServer 持有 tbox::fw::ipc::Server、TspIpcDispatcher、TspEventPublisher，
// 将 framework RequestHandler 适配到 TSP 业务：
// - 订阅方法（SUBSCRIBE_VEHICLE_MESSAGE / SUBSCRIBE_NET_STATUS）在 dispatch 前注册 add_subscription。
// - TspIpcDispatcher 分发通用 VehicleMessage exchange / 网络状态方法。
// - TspEventPublisher 经 Server::push_event 推送下行 EVENT Envelope。
//
// stop 时先停止事件推送，再停 IPC Server，取消订阅，等待线程退出 (CR-003 §3)。

#pragma once

#include <memory>
#include <string>
#include "ipc.h"
#include "tsp_ipc_dispatcher.h"
#include "tsp_event_publisher.h"

namespace tbox {
namespace tsp {

class VehicleMessageRelayInterface;
class NetStatusProvider;

class TspFrameworkServer {
public:
    TspFrameworkServer(const std::string& socket_path,
                       const ::tbox::fw::ipc::IpcConfig& ipc_config,
                       VehicleMessageRelayInterface* relay,
                       NetStatusProvider* net_provider,
                       uint32_t downlink_queue_size = 256,
                       SlowSubscriberPolicy slow_policy = SlowSubscriberPolicy::kDisconnect);
    ~TspFrameworkServer();

    TspFrameworkServer(const TspFrameworkServer&) = delete;
    TspFrameworkServer& operator=(const TspFrameworkServer&) = delete;

    bool start();
    void stop();
    bool is_running() const;

    // 下行事件推送器（VehicleMessageGateway 经此推送 EVENT Envelope）
    TspEventPublisher* event_publisher();

private:
    std::string socket_path_;
    ::tbox::fw::ipc::IpcConfig ipc_config_;
    VehicleMessageRelayInterface* relay_;
    NetStatusProvider* net_provider_;

    std::unique_ptr<::tbox::fw::ipc::Server> server_;
    std::unique_ptr<TspIpcDispatcher> dispatcher_;
    std::unique_ptr<TspEventPublisher> event_publisher_;
};

// 从配置字符串解析慢消费者策略
SlowSubscriberPolicy parse_slow_subscriber_policy(const std::string& s);

} // namespace tsp
} // namespace tbox
