// TBOX-TSP framework-ipc Server 接线实现 (CR-003 §1, §3; CR-009)

#include "tsp_framework_server.h"
#include "vehicle_message_gateway.h"
#include "net_status_provider.h"
#include "tsp_ipc_protocol.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

SlowSubscriberPolicy parse_slow_subscriber_policy(const std::string& s) {
    if (s == "drop")       return SlowSubscriberPolicy::kDrop;
    if (s == "reject")     return SlowSubscriberPolicy::kReject;
    return SlowSubscriberPolicy::kDisconnect;  // default
}

TspFrameworkServer::TspFrameworkServer(const std::string& socket_path,
                                       const ::tbox::fw::ipc::IpcConfig& ipc_config,
                                       VehicleMessageRelayInterface* relay,
                                       NetStatusProvider* net_provider,
                                       uint32_t downlink_queue_size,
                                       SlowSubscriberPolicy slow_policy)
    : socket_path_(socket_path)
    , ipc_config_(ipc_config)
    , relay_(relay)
    , net_provider_(net_provider) {
    dispatcher_ = std::make_unique<TspIpcDispatcher>(
        relay_, net_provider_, ipc_config_.max_frame_bytes);
    event_publisher_ = std::make_unique<TspEventPublisher>(downlink_queue_size, slow_policy);
}

TspFrameworkServer::~TspFrameworkServer() {
    stop();
}

bool TspFrameworkServer::start() {
    if (server_) {
        return true;  // already started
    }

    server_ = std::make_unique<::tbox::fw::ipc::Server>(socket_path_, ipc_config_);

    // 接线 push_fn / has_subscriber_fn
    auto* server_ptr = server_.get();
    event_publisher_->set_push_fn(
        [server_ptr](uint32_t event_type, const std::string& payload_json) -> bool {
            return server_ptr->push_event(event_type, payload_json);
        });
    // framework 未暴露订阅者计数；best-effort 假设有订阅者，由 push_event 返回值判定
    event_publisher_->set_has_subscriber_fn([](uint32_t) { return true; });

    // 启动下行推送 worker（先于 IPC Server，确保就绪）
    event_publisher_->start();

    // request_handler：订阅方法先注册 add_subscription，再分发
    auto* dispatcher_ptr = dispatcher_.get();
    auto request_handler = [server_ptr, dispatcher_ptr](
            uint32_t method_id, std::string_view params_json, int client_fd) -> std::string {
        switch (static_cast<ipc::MethodId>(method_id)) {
            case ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE:
                server_ptr->add_subscription(client_fd,
                    static_cast<uint32_t>(ipc::EventType::VEHICLE_MESSAGE));
                break;
            case ipc::MethodId::SUBSCRIBE_NET_STATUS:
                server_ptr->add_subscription(client_fd,
                    static_cast<uint32_t>(ipc::EventType::NET_STATUS_CHANGED));
                break;
            default:
                break;
        }
        return dispatcher_ptr->dispatch(method_id, params_json, client_fd);
    };

    // disconnect handler：只清理 per-fd 订阅，不删除持久 route/dedup 状态 (CR-003 §3)
    auto disconnect_handler = [](int client_fd) {
        LogAdapter::ipc_server().debug(
            "tsp.ipc.client_disconnected",
            "Client disconnected (framework)",
            {tbox::fw::log::Field("client_fd", tbox::fw::log::FieldValue::makeInt(client_fd))}
        );
    };

    if (!server_->start(std::move(request_handler), std::move(disconnect_handler))) {
        LogAdapter::ipc_server().error(
            "tsp.ipc.server_start_failed",
            "IPC server 启动失败",
            {tbox::fw::log::Field("socket_path", tbox::fw::log::FieldValue::makeString(socket_path_))}
        );
        event_publisher_->stop();
        server_.reset();
        return false;
    }

    LogAdapter::ipc_server().info(
        "tsp.ipc.server_started",
        "IPC server started (framework-ipc)",
        {tbox::fw::log::Field("socket_path", tbox::fw::log::FieldValue::makeString(socket_path_))}
    );
    return true;
}

void TspFrameworkServer::stop() {
    // 先停事件推送（拒绝新下行），再停 IPC Server (CR-003 §3)
    if (event_publisher_) {
        event_publisher_->stop();
    }
    if (server_) {
        server_->stop();
        server_.reset();
        LogAdapter::ipc_server().info(
            "tsp.ipc.server_stopped",
            "IPC server stopped (framework-ipc)"
        );
    }
}

bool TspFrameworkServer::is_running() const {
    return server_ != nullptr;
}

TspEventPublisher* TspFrameworkServer::event_publisher() {
    return event_publisher_.get();
}

} // namespace tsp
} // namespace tbox
