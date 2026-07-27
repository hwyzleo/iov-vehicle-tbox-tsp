// src/ipc_server.cpp
#include "ipc_server.h"
#include "log_adapter.h"
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
        LogAdapter::ipc_server().error("tsp.ipc.create_pipe_failed", "创建 shutdown pipe 失败", {
            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
        });
        return false;
    }

    // 创建 Unix Socket
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        LogAdapter::ipc_server().error("tsp.ipc.create_socket_failed", "创建 socket 失败", {
            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
        });
        return false;
    }

    // 设置 socket 选项
    int opt = 1;
    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LogAdapter::ipc_server().error("tsp.ipc.setsockopt_failed", "设置 socket 选项失败", {
            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
        });
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
        LogAdapter::ipc_server().error("tsp.ipc.bind_failed", "绑定 socket 失败", {
            {"path", tbox::fw::log::FieldValue::makeString(socket_path_)},
            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
        });
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    // 监听连接
    if (listen(server_fd_, 5) < 0) {
        LogAdapter::ipc_server().error("tsp.ipc.listen_failed", "监听 socket 失败", {
            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
        });
        close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&IpcServer::accept_connections, this);

    LogAdapter::ipc_server().info("tsp.ipc.started", "IPC 服务器启动", {
        {"socket_path", tbox::fw::log::FieldValue::makeString(socket_path_)}
    });
    return true;
}

void IpcServer::stop() {
    if (!running_) {
        return;
    }

    LogAdapter::ipc_server().info("tsp.ipc.stopping", "IPC 服务器停止中");
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

    LogAdapter::ipc_server().info("tsp.ipc.stopped", "IPC 服务器已停止");
}

void IpcServer::accept_connections() {
    LogAdapter::ipc_server().info("tsp.ipc.accept_thread_started", "接受连接线程启动", {
        {"server_fd", tbox::fw::log::FieldValue::makeInt(server_fd_)}
    });

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
            LogAdapter::ipc_server().error("tsp.ipc.select_failed", "select 失败", {
                {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
            });
            break;
        }

        // shutdown pipe 被唤醒，退出循环
        if (FD_ISSET(shutdown_pipe_[0], &rfds)) {
            LogAdapter::ipc_server().info("tsp.ipc.shutdown_signaled", "收到关闭信号");
            break;
        }

        if (!FD_ISSET(server_fd_, &rfds)) {
            continue;
        }

        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_) {
                LogAdapter::ipc_server().error("tsp.ipc.accept_failed", "accept 失败", {
                    {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
                });
            }
            continue;
        }

        LogAdapter::ipc_server().info("tsp.ipc.new_connection", "新连接", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
        });

        // 记录活跃客户端
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            active_clients_.insert(client_fd);
        }

        // 在新线程中处理客户端连接
        std::thread client_thread(&IpcServer::handle_client, this, client_fd);
        client_thread.detach();
    }

    LogAdapter::ipc_server().info("tsp.ipc.accept_thread_exiting", "接受连接线程退出");
}

void IpcServer::handle_client(int client_fd) {
    LogAdapter::ipc_server().info("tsp.ipc.client_handler_started", "客户端处理器启动", {
        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
    });
    try {
        // 设置空闲超时（60秒无数据则断开）
        struct timeval tv;
        tv.tv_sec = 60;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        LogAdapter::ipc_server().info("tsp.ipc.client_connected", "长连接建立", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
        });

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
                        LogAdapter::ipc_server().info("tsp.ipc.client_disconnected", "客户端关闭连接", {
                            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
                        });
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        LogAdapter::ipc_server().info("tsp.ipc.client_idle_timeout", "客户端空闲超时", {
                            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
                        });
                    } else {
                        LogAdapter::ipc_server().error("tsp.ipc.recv_header_failed", "接收请求头失败", {
                            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
                            {"error", tbox::fw::log::FieldValue::makeString(strerror(errno))}
                        });
                    }
                    cleanup_client(client_fd);
                    return;
                }
                header_received += bytes_read;
            }

            LogAdapter::ipc_server().debug("tsp.ipc.header_received", "收到请求头", {
                {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
                {"method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(header.method_id))},
                {"params_length", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(header.params_length))}
            });

            // 合理性检查
            if (header.params_length > 10 * 1024 * 1024) {  // 最大 10MB
                LogAdapter::ipc_server().error("tsp.ipc.request_too_large", "请求过大", {
                    {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
                    {"params_length", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(header.params_length))}
                });
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
                    LogAdapter::ipc_server().error("tsp.ipc.recv_params_failed", "接收请求参数失败", {
                        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
                    });
                    cleanup_client(client_fd);
                    return;
                }
                data_received += bytes_read;
            }

            LogAdapter::ipc_server().debug("tsp.ipc.request_fully_read", "请求读取完成，开始处理", {
                {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
            });

            // 解析请求
            MethodId method;
            std::string params_json;
            if (!IpcSerializer::deserialize_request(request_data, method, params_json)) {
                LogAdapter::ipc_server().error("tsp.ipc.deserialize_failed", "反序列化请求失败", {
                    {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
                });
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
                    LogAdapter::ipc_server().error("tsp.ipc.send_response_failed", "发送响应失败", {
                        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
                    });
                    cleanup_client(client_fd);
                    return;
                }
                total_sent += bytes_sent;
            }

            LogAdapter::ipc_server().debug("tsp.ipc.response_sent", "响应已发送", {
                {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
            });
        }
    } catch (const std::length_error& e) {
        LogAdapter::ipc_server().error("tsp.ipc.length_error", "长度错误异常", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
    } catch (const std::bad_alloc& e) {
        LogAdapter::ipc_server().error("tsp.ipc.bad_alloc", "内存分配失败", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
    } catch (const std::exception& e) {
        LogAdapter::ipc_server().error("tsp.ipc.exception", "标准异常", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
    } catch (...) {
        LogAdapter::ipc_server().error("tsp.ipc.unknown_exception", "未知异常", {
            {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
        });
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
                    LogAdapter::ipc_server().error("tsp.ipc.push_event_failed", "推送事件失败", {
                        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
                        {"event_type", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(type))}
                    });
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
    LogAdapter::ipc_server().info("tsp.ipc.subscription_added", "客户端订阅事件", {
        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
        {"event_type", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(type))}
    });
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
    LogAdapter::ipc_server().info("tsp.ipc.subscription_removed", "客户端取消订阅", {
        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)},
        {"event_type", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(type))}
    });
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
    LogAdapter::ipc_server().info("tsp.ipc.client_cleaned_up", "客户端连接清理完成", {
        {"client_fd", tbox::fw::log::FieldValue::makeInt(client_fd)}
    });
}

} // namespace ipc
} // namespace tsp
} // namespace tbox
