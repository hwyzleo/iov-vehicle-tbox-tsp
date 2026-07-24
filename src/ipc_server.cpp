// src/ipc_server.cpp
#include "ipc_server.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace tbox {
namespace tsp {
namespace ipc {

IpcServer::IpcServer(const std::string& socket_path)
    : socket_path_(socket_path), server_fd_(-1), running_(false) {
    shutdown_pipe_[0] = -1;
    shutdown_pipe_[1] = -1;
}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::start(RequestHandler request_handler, ClientDisconnectHandler disconnect_handler) {
    if (running_) {
        return true;
    }

    request_handler_ = request_handler;
    disconnect_handler_ = disconnect_handler;

    // 创建 shutdown pipe
    if (pipe(shutdown_pipe_) < 0) {
        std::cerr << "Failed to create shutdown pipe: " << strerror(errno) << std::endl;
        return false;
    }

    // 创建 Unix Socket
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }

    // 设置 socket 选项
    int opt = 1;
    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // 绑定地址
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    // 删除已存在的 socket 文件
    unlink(socket_path_.c_str());

    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // 监听连接
    if (listen(server_fd_, 5) < 0) {
        std::cerr << "Failed to listen on socket: " << strerror(errno) << std::endl;
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&IpcServer::accept_connections, this);

    std::cout << "IPC server started on " << socket_path_ << std::endl;
    return true;
}

void IpcServer::stop() {
    if (!running_) {
        return;
    }

    std::cout << "IpcServer::stop() called" << std::endl;
    running_ = false;

    // 通过 shutdown pipe 唤醒阻塞在 select/accept 上的线程
    if (shutdown_pipe_[1] >= 0) {
        char c = 1;
        write(shutdown_pipe_[1], &c, 1);
    }

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }

    if (shutdown_pipe_[0] >= 0) { close(shutdown_pipe_[0]); shutdown_pipe_[0] = -1; }
    if (shutdown_pipe_[1] >= 0) { close(shutdown_pipe_[1]); shutdown_pipe_[1] = -1; }

    // 删除 socket 文件
    unlink(socket_path_.c_str());

    // 清理所有客户端订阅
    {
        std::lock_guard<std::mutex> lock(subs_mutex_);
        subscriptions_.clear();
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        active_clients_.clear();
    }

    std::cout << "IPC server stopped" << std::endl;
}

void IpcServer::accept_connections() {
    std::cout << "[accept] thread started, server_fd=" << server_fd_ << std::endl;

    while (running_) {
        // 用 select 同时监听 server_fd 和 shutdown_pipe
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(server_fd_, &rfds);
        FD_SET(shutdown_pipe_[0], &rfds);
        int maxfd = (server_fd_ > shutdown_pipe_[0]) ? server_fd_ : shutdown_pipe_[0];

        int ret = select(maxfd + 1, &rfds, nullptr, nullptr, nullptr);
        if (ret < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[accept] select failed: " << strerror(errno) << std::endl;
            break;
        }

        // shutdown pipe 被唤醒，退出循环
        if (FD_ISSET(shutdown_pipe_[0], &rfds)) {
            std::cout << "[accept] shutdown pipe signaled, exiting" << std::endl;
            break;
        }

        if (!FD_ISSET(server_fd_, &rfds)) {
            continue;
        }

        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_) {
                std::cerr << "[accept] accept failed: " << strerror(errno) << std::endl;
            }
            continue;
        }

        std::cout << "[accept] new connection, client_fd=" << client_fd << std::endl;

        // 记录活跃客户端
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            active_clients_.insert(client_fd);
        }

        // 在新线程中处理客户端连接
        std::thread client_thread(&IpcServer::handle_client, this, client_fd);
        client_thread.detach();
    }

    std::cout << "[accept] thread exiting" << std::endl;
}

void IpcServer::handle_client(int client_fd) {
    std::cout << "[client:" << client_fd << "] handler started" << std::endl;
    try {
        // 设置空闲超时（60秒无数据则断开）
        struct timeval tv;
        tv.tv_sec = 60;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        std::cout << "[client:" << client_fd << "] long connection established" << std::endl;

        // 长连接循环处理多个请求
        while (running_) {
            // 读取请求头
            RequestHeader header;
            memset(&header, 0, sizeof(header));
            size_t header_received = 0;
            while (header_received < sizeof(header)) {
                ssize_t bytes_read = recv(client_fd, reinterpret_cast<uint8_t*>(&header) + header_received, sizeof(header) - header_received, 0);
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        std::cout << "[client:" << client_fd << "] connection closed by peer" << std::endl;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        std::cout << "[client:" << client_fd << "] idle timeout, closing" << std::endl;
                    } else {
                        std::cerr << "[client:" << client_fd << "] recv header failed: " << strerror(errno) << std::endl;
                    }
                    cleanup_client(client_fd);
                    return;
                }
                header_received += bytes_read;
            }

            std::cout << "[client:" << client_fd << "] header received, method=" << header.method_id
                      << " params_length=" << header.params_length << std::endl;

            // 合理性检查
            if (header.params_length > 10 * 1024 * 1024) {  // 最大 10MB
                std::cerr << "[client:" << client_fd << "] request too large: " << header.params_length << std::endl;
                cleanup_client(client_fd);
                return;
            }

            // 读取请求数据
            std::vector<uint8_t> request_data(sizeof(header) + header.params_length);
            memcpy(request_data.data(), &header, sizeof(header));

            size_t data_received = 0;
            while (data_received < header.params_length) {
                ssize_t bytes_read = recv(client_fd, request_data.data() + sizeof(header) + data_received, header.params_length - data_received, 0);
                if (bytes_read <= 0) {
                    std::cerr << "[client:" << client_fd << "] recv params failed" << std::endl;
                    cleanup_client(client_fd);
                    return;
                }
                data_received += bytes_read;
            }

            std::cout << "[client:" << client_fd << "] request fully read, dispatching" << std::endl;

            // 解析请求
            MethodId method;
            std::string params_json;
            if (!IpcSerializer::deserialize_request(request_data, method, params_json)) {
                std::cerr << "[client:" << client_fd << "] deserialize request failed" << std::endl;
                cleanup_client(client_fd);
                return;
            }

            // 调用请求处理器
            std::string response_json;
            if (request_handler_) {
                response_json = request_handler_(method, params_json, client_fd);
            } else {
                response_json = "{\"error\":\"No request handler\"}";
            }

            // 序列化响应
            auto response_data = IpcSerializer::serialize_response(0, response_json);

            // 发送响应
            size_t total_sent = 0;
            while (total_sent < response_data.size()) {
                ssize_t bytes_sent = send(client_fd, response_data.data() + total_sent, response_data.size() - total_sent, 0);
                if (bytes_sent <= 0) {
                    std::cerr << "[client:" << client_fd << "] send response failed" << std::endl;
                    cleanup_client(client_fd);
                    return;
                }
                total_sent += bytes_sent;
            }

            std::cout << "[client:" << client_fd << "] response sent, waiting for next request" << std::endl;
        }
    } catch (const std::length_error& e) {
        std::cerr << "[client:" << client_fd << "] std::length_error: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        std::cerr << "[client:" << client_fd << "] std::bad_alloc: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[client:" << client_fd << "] std::exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[client:" << client_fd << "] unknown exception type" << std::endl;
    }

    cleanup_client(client_fd);
}

void IpcServer::push_event(EventType type, const std::string& payload_json) {
    auto event_data = IpcSerializer::serialize_event(type, payload_json);

    std::lock_guard<std::mutex> lock(subs_mutex_);

    // 遍历所有订阅了该事件类型的客户端
    for (auto& [client_fd, event_types] : subscriptions_) {
        if (event_types.find(static_cast<uint32_t>(type)) != event_types.end()) {
            // 发送事件
            size_t total_sent = 0;
            while (total_sent < event_data.size()) {
                ssize_t bytes_sent = send(client_fd, event_data.data() + total_sent, event_data.size() - total_sent, 0);
                if (bytes_sent <= 0) {
                    std::cerr << "[push_event] send to client " << client_fd << " failed, removing" << std::endl;
                    // 发送失败，标记需要清理
                    // 注意：不能在遍历中直接修改 map，需要在外部清理
                    break;
                }
                total_sent += bytes_sent;
            }
        }
    }
}

void IpcServer::add_subscription(int client_fd, EventType type) {
    std::lock_guard<std::mutex> lock(subs_mutex_);
    subscriptions_[client_fd].insert(static_cast<uint32_t>(type));
    std::cout << "[subscription] client " << client_fd << " subscribed to event " << static_cast<uint32_t>(type) << std::endl;
}

void IpcServer::remove_subscription(int client_fd, EventType type) {
    std::lock_guard<std::mutex> lock(subs_mutex_);
    auto it = subscriptions_.find(client_fd);
    if (it != subscriptions_.end()) {
        it->second.erase(static_cast<uint32_t>(type));
        if (it->second.empty()) {
            subscriptions_.erase(it);
        }
    }
    std::cout << "[subscription] client " << client_fd << " unsubscribed from event " << static_cast<uint32_t>(type) << std::endl;
}

void IpcServer::cleanup_client(int client_fd) {
    // 清理订阅
    {
        std::lock_guard<std::mutex> lock(subs_mutex_);
        subscriptions_.erase(client_fd);
    }

    // 清理活跃客户端
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        active_clients_.erase(client_fd);
    }

    // 调用断开回调
    if (disconnect_handler_) {
        disconnect_handler_(client_fd);
    }

    // 关闭连接
    close(client_fd);
    std::cout << "[client:" << client_fd << "] connection cleaned up" << std::endl;
}

} // namespace ipc
} // namespace tsp
} // namespace tbox
