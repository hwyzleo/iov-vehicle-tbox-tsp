// include/ipc_server.h
#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "ipc_protocol.h"

namespace tbox {
namespace tsp {
namespace ipc {

class IpcServer {
public:
    using RequestHandler = std::function<std::string(MethodId method, const std::string& params_json, int client_fd)>;
    using ClientDisconnectHandler = std::function<void(int client_fd)>;

    IpcServer(const std::string& socket_path = DEFAULT_SOCKET_PATH);
    ~IpcServer();

    bool start(RequestHandler request_handler, ClientDisconnectHandler disconnect_handler = nullptr);
    void stop();

    // 向所有已订阅指定事件的客户端推送事件
    void push_event(EventType type, const std::string& payload_json);

    // 订阅管理
    void add_subscription(int client_fd, EventType type);
    void remove_subscription(int client_fd, EventType type);
    void cleanup_client(int client_fd);

    bool is_running() const { return running_; }

private:
    std::string socket_path_;
    int server_fd_;
    int shutdown_pipe_[2];
    std::atomic<bool> running_;
    std::thread accept_thread_;

    RequestHandler request_handler_;
    ClientDisconnectHandler disconnect_handler_;

    // 客户端订阅管理：client_fd -> set<EventType>
    std::unordered_map<int, std::unordered_set<uint32_t>> subscriptions_;
    std::mutex subs_mutex_;

    // 活跃客户端连接
    std::unordered_set<int> active_clients_;
    std::mutex clients_mutex_;

    void accept_connections();
    void handle_client(int client_fd);
};

} // namespace ipc
} // namespace tsp
} // namespace tbox
