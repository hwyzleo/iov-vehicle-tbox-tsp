# TBOX-TSP IPC Server 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 将 TBOX-TSP 服务的 SomeipFacadeStub 替换为真正的 IPC 实现，使 TBOX-SOMEIP 能通过 Unix domain socket 与 TBOX-TSP 通信。

**架构：** 采用 TBOX-SOMEIP 作为 SOME/IP 统一出口的架构。TBOX-TSP 作为 IPC 服务端接收上行请求，作为 IPC 客户端通过 TBOX-SOMEIP 下行命令。使用策略模式支持多种网络状态获取实现。

**技术栈：** C++17, Unix domain socket, nlohmann/json, spdlog, CMake

---

## 文件结构

### 新增文件
| 文件 | 职责 |
|------|------|
| `include/ipc_protocol.h` | IPC 协议定义：MethodId、EventType 枚举、消息头结构、IpcSerializer |
| `src/ipc_protocol.cpp` | IPC 协议实现：序列化/反序列化、Base64 编码/解码 |
| `include/ipc_server.h` | IPC 服务端定义：Unix socket 服务器、连接管理、订阅管理 |
| `src/ipc_server.cpp` | IPC 服务端实现：accept、handle_client、push_event |
| `include/net_status_provider.h` | 网络状态提供者接口：NetStatusProvider 抽象类 |
| `src/net_status_provider.cpp` | 网络状态提供者实现：MockNetStatusProvider、SystemNetStatusProvider |
| `include/someip_facade_impl.h` | SomeipFacade 真实实现定义 |
| `src/someip_facade_impl.cpp` | SomeipFacade 真实实现：请求处理、事件推送 |

### 修改文件
| 文件 | 修改内容 |
|------|---------|
| `src/main.cpp` | 替换 SomeipFacadeStub 为 SomeipFacadeImpl |
| `CMakeLists.txt` | 添加新源文件、头文件目录 |

---

## 任务分解

### 任务 1：IPC 协议层实现

**文件：**
- 创建：`include/ipc_protocol.h`
- 创建：`src/ipc_protocol.cpp`

- [ ] **步骤 1：创建 ipc_protocol.h 头文件**

```cpp
// include/ipc_protocol.h
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {
namespace ipc {

// Socket 路径
constexpr const char* DEFAULT_SOCKET_PATH = "/tmp/tbox-tsp.sock";

// 方法 ID
enum class MethodId : uint32_t {
    GET_NET_STATUS              = 1,   // 请求-响应
    REPORT_SOFTWARE_INVENTORY   = 2,   // 请求-响应
    SUBSCRIBE_NET_STATUS        = 3,   // 注册订阅
    SUBSCRIBE_REMOTE_COMMANDS   = 4,   // 注册订阅
    SUBSCRIBE_FOTA_COMMANDS     = 5,   // 注册订阅
};

// 推送事件类型（服务端主动推送给已订阅的客户端）
enum class EventType : uint32_t {
    NET_STATUS_CHANGED  = 100,
    REMOTE_COMMAND      = 101,
    FOTA_COMMAND         = 102,
};

// 请求头（与 SEC/PROV 一致）
struct RequestHeader {
    uint32_t method_id;
    uint32_t params_length;
} __attribute__((packed));

// 响应头（与 SEC/PROV 一致）
struct ResponseHeader {
    int32_t  status_code;
    uint32_t data_length;
} __attribute__((packed));

// 推送事件头（新增，用于服务端主动推送）
struct EventHeader {
    uint32_t event_type;    // EventType
    uint32_t payload_length;
} __attribute__((packed));

// 序列化工具
class IpcSerializer {
public:
    // 请求序列化
    static std::vector<uint8_t> serialize_request(MethodId method, const std::string& params_json);
    static bool deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json);
    
    // 响应序列化
    static std::vector<uint8_t> serialize_response(int32_t status_code, const std::string& response_json);
    static bool deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json);
    
    // 事件序列化
    static std::vector<uint8_t> serialize_event(EventType type, const std::string& payload_json);
    static bool deserialize_event(const std::vector<uint8_t>& data, EventType& type, std::string& payload_json);
    
    // Base64 工具
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

} // namespace ipc
} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 2：创建 ipc_protocol.cpp 实现文件**

```cpp
// src/ipc_protocol.cpp
#include "ipc_protocol.h"
#include <cstring>
#include <stdexcept>

namespace tbox {
namespace tsp {
namespace ipc {

// Base64 编码表
static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<uint8_t> IpcSerializer::serialize_request(MethodId method, const std::string& params_json) {
    RequestHeader header;
    header.method_id = static_cast<uint32_t>(method);
    header.params_length = static_cast<uint32_t>(params_json.size());
    
    std::vector<uint8_t> result(sizeof(header) + params_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), params_json.data(), params_json.size());
    
    return result;
}

bool IpcSerializer::deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json) {
    if (data.size() < sizeof(RequestHeader)) {
        return false;
    }
    
    RequestHeader header;
    memcpy(&header, data.data(), sizeof(header));
    
    if (data.size() < sizeof(header) + header.params_length) {
        return false;
    }
    
    method = static_cast<MethodId>(header.method_id);
    params_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.params_length);
    
    return true;
}

std::vector<uint8_t> IpcSerializer::serialize_response(int32_t status_code, const std::string& response_json) {
    ResponseHeader header;
    header.status_code = status_code;
    header.data_length = static_cast<uint32_t>(response_json.size());
    
    std::vector<uint8_t> result(sizeof(header) + response_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), response_json.data(), response_json.size());
    
    return result;
}

bool IpcSerializer::deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json) {
    if (data.size() < sizeof(ResponseHeader)) {
        return false;
    }
    
    ResponseHeader header;
    memcpy(&header, data.data(), sizeof(header));
    
    if (data.size() < sizeof(header) + header.data_length) {
        return false;
    }
    
    status_code = header.status_code;
    response_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.data_length);
    
    return true;
}

std::vector<uint8_t> IpcSerializer::serialize_event(EventType type, const std::string& payload_json) {
    EventHeader header;
    header.event_type = static_cast<uint32_t>(type);
    header.payload_length = static_cast<uint32_t>(payload_json.size());
    
    std::vector<uint8_t> result(sizeof(header) + payload_json.size());
    memcpy(result.data(), &header, sizeof(header));
    memcpy(result.data() + sizeof(header), payload_json.data(), payload_json.size());
    
    return result;
}

bool IpcSerializer::deserialize_event(const std::vector<uint8_t>& data, EventType& type, std::string& payload_json) {
    if (data.size() < sizeof(EventHeader)) {
        return false;
    }
    
    EventHeader header;
    memcpy(&header, data.data(), sizeof(header));
    
    if (data.size() < sizeof(header) + header.payload_length) {
        return false;
    }
    
    type = static_cast<EventType>(header.event_type);
    payload_json = std::string(reinterpret_cast<const char*>(data.data() + sizeof(header)), header.payload_length);
    
    return true;
}

std::string IpcSerializer::base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    
    for (auto byte : data) {
        char_array_3[i++] = byte;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++) {
                result += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++) {
            result += base64_chars[char_array_4[j]];
        }
        
        while (i++ < 3) {
            result += '=';
        }
    }
    
    return result;
}

std::vector<uint8_t> IpcSerializer::base64_decode(const std::string& encoded) {
    size_t in_len = encoded.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::vector<uint8_t> result;
    
    while (in_len-- && (encoded[in_] != '=') && (isalnum(encoded[in_]) || (encoded[in_] == '+') || (encoded[in_] == '/'))) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = static_cast<uint8_t>(base64_chars.find(char_array_4[i]));
            }
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++) {
                result.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        
        for (j = 0; j < 4; j++) {
            char_array_4[j] = static_cast<uint8_t>(base64_chars.find(char_array_4[j]));
        }
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        
        for (j = 0; j < i - 1; j++) {
            result.push_back(char_array_3[j]);
        }
    }
    
    return result;
}

} // namespace ipc
} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 3：编译验证**

运行：`cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp && mkdir -p build && cd build && cmake .. && make -j4`
预期：编译通过，无错误

- [ ] **步骤 4：Commit**

```bash
git add include/ipc_protocol.h src/ipc_protocol.cpp
git commit -m "feat(tsp): add IPC protocol layer with serialization and base64"
```

---

### 任务 2：IPC 服务层实现

**文件：**
- 创建：`include/ipc_server.h`
- 创建：`src/ipc_server.cpp`

- [ ] **步骤 1：创建 ipc_server.h 头文件**

```cpp
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
```

- [ ] **步骤 2：创建 ipc_server.cpp 实现文件**

```cpp
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
```

- [ ] **步骤 3：编译验证**

运行：`cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp/build && make -j4`
预期：编译通过，无错误

- [ ] **步骤 4：Commit**

```bash
git add include/ipc_server.h src/ipc_server.cpp
git commit -m "feat(tsp): add IPC server with connection and subscription management"
```

---

### 任务 3：网络状态提供者实现

**文件：**
- 创建：`include/net_status_provider.h`
- 创建：`src/net_status_provider.cpp`

- [ ] **步骤 1：创建 net_status_provider.h 头文件**

```cpp
// include/net_status_provider.h
#pragma once

#include <string>
#include <memory>

namespace tbox {
namespace tsp {

class NetStatusProvider {
public:
    virtual ~NetStatusProvider() = default;
    
    struct NetStatus {
        bool is_connected = false;
        int signal_strength = 0;      // 0-100
        std::string network_type;     // "4G", "5G", "WiFi", etc.
        std::string operator_name;    // "CMCC", "CUCC", "CTCC", etc.
    };
    
    virtual NetStatus get_net_status() = 0;
    virtual bool is_available() const = 0;
};

// Mock 实现（当前阶段使用）
class MockNetStatusProvider : public NetStatusProvider {
public:
    NetStatus get_net_status() override;
    bool is_available() const override;
};

// 系统实现（读取系统文件）
class SystemNetStatusProvider : public NetStatusProvider {
public:
    NetStatus get_net_status() override;
    bool is_available() const override;
    
private:
    bool read_interface_status();
    int read_signal_strength();
    std::string read_network_type();
    std::string read_operator();
};

// 工厂方法
class NetStatusProviderFactory {
public:
    enum class ProviderType {
        MOCK,
        SYSTEM
    };
    
    static std::unique_ptr<NetStatusProvider> create(ProviderType type);
};

} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 2：创建 net_status_provider.cpp 实现文件**

```cpp
// src/net_status_provider.cpp
#include "net_status_provider.h"
#include <fstream>
#include <sstream>
#include <iostream>

namespace tbox {
namespace tsp {

// MockNetStatusProvider 实现
NetStatus MockNetStatusProvider::get_net_status() {
    return {
        .is_connected = true,
        .signal_strength = 85,
        .network_type = "4G",
        .operator_name = "CMCC"
    };
}

bool MockNetStatusProvider::is_available() const {
    return true;
}

// SystemNetStatusProvider 实现
NetStatus SystemNetStatusProvider::get_net_status() {
    NetStatus status;
    
    try {
        status.is_connected = read_interface_status();
        status.signal_strength = read_signal_strength();
        status.network_type = read_network_type();
        status.operator_name = read_operator();
    } catch (const std::exception& e) {
        std::cerr << "Failed to read system net status: " << e.what() << std::endl;
    }
    
    return status;
}

bool SystemNetStatusProvider::is_available() const {
    // 检查系统是否有网络接口
    return true;  // 简化实现
}

bool SystemNetStatusProvider::read_interface_status() {
    // 读取 /sys/class/net/ 下的接口状态
    std::ifstream file("/sys/class/net/eth0/operstate");
    if (file.is_open()) {
        std::string state;
        std::getline(file, state);
        return state == "up";
    }
    return false;
}

int SystemNetStatusProvider::read_signal_strength() {
    // 简化实现，返回固定值
    return 80;
}

std::string SystemNetStatusProvider::read_network_type() {
    // 简化实现，返回固定值
    return "4G";
}

std::string SystemNetStatusProvider::read_operator() {
    // 简化实现，返回固定值
    return "CMCC";
}

// NetStatusProviderFactory 实现
std::unique_ptr<NetStatusProvider> NetStatusProviderFactory::create(ProviderType type) {
    switch (type) {
        case ProviderType::MOCK:
            return std::make_unique<MockNetStatusProvider>();
        case ProviderType::SYSTEM:
            return std::make_unique<SystemNetStatusProvider>();
        default:
            return std::make_unique<MockNetStatusProvider>();
    }
}

} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 3：编译验证**

运行：`cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp/build && make -j4`
预期：编译通过，无错误

- [ ] **步骤 4：Commit**

```bash
git add include/net_status_provider.h src/net_status_provider.cpp
git commit -m "feat(tsp): add net status provider with mock and system implementations"
```

---

### 任务 4：SomeipFacadeImpl 实现

**文件：**
- 创建：`include/someip_facade_impl.h`
- 创建：`src/someip_facade_impl.cpp`

- [ ] **步骤 1：创建 someip_facade_impl.h 头文件**

```cpp
// include/someip_facade_impl.h
#pragma once

#include "someip_facade.h"
#include "ipc_server.h"
#include "net_status_provider.h"
#include <memory>
#include <mutex>

namespace tbox {
namespace tsp {

class SomeipFacadeImpl : public SomeipFacade {
public:
    SomeipFacadeImpl();
    ~SomeipFacadeImpl() override;

    // SomeipFacade 接口实现
    bool initialize() override;
    bool start() override;
    void stop() override;
    bool is_connected() const override;

    void on_report_software_inventory(
        std::function<void(const std::vector<uint8_t>&)> callback) override;

    bool push_fota_command(const std::vector<uint8_t>& payload) override;

private:
    std::unique_ptr<ipc::IpcServer> server_;
    std::function<void(const std::vector<uint8_t>&)> inventory_callback_;
    mutable std::mutex mutex_;
    
    // 网络状态提供者
    std::unique_ptr<NetStatusProvider> net_status_provider_;
    
    // 请求处理回调
    std::string handle_request(ipc::MethodId method, const std::string& params_json, int client_fd);
    
    // 客户端断开回调
    void handle_client_disconnect(int client_fd);
    
    // 具体方法处理
    std::string handle_get_net_status(const std::string& params_json);
    std::string handle_report_software_inventory(const std::string& params_json, int client_fd);
    std::string handle_subscribe(ipc::EventType type, const std::string& params_json, int client_fd);
};

} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 2：创建 someip_facade_impl.cpp 实现文件**

```cpp
// src/someip_facade_impl.cpp
#include "someip_facade_impl.h"
#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

SomeipFacadeImpl::SomeipFacadeImpl() = default;
SomeipFacadeImpl::~SomeipFacadeImpl() = default;

bool SomeipFacadeImpl::initialize() {
    spdlog::info("[SomeipFacadeImpl] 初始化");
    
    // 创建网络状态提供者（当前使用 Mock）
    net_status_provider_ = std::make_unique<MockNetStatusProvider>();
    
    // 创建 IPC 服务器
    server_ = std::make_unique<ipc::IpcServer>();
    
    return true;
}

bool SomeipFacadeImpl::start() {
    if (!server_) {
        spdlog::error("[SomeipFacadeImpl] 未初始化");
        return false;
    }
    
    spdlog::info("[SomeipFacadeImpl] 启动");
    
    // 启动 IPC 服务器
    if (!server_->start(
        [this](ipc::MethodId method, const std::string& params_json, int client_fd) {
            return handle_request(method, params_json, client_fd);
        },
        [this](int client_fd) {
            handle_client_disconnect(client_fd);
        }
    )) {
        spdlog::error("[SomeipFacadeImpl] IPC 服务器启动失败");
        return false;
    }
    
    return true;
}

void SomeipFacadeImpl::stop() {
    spdlog::info("[SomeipFacadeImpl] 停止");
    if (server_) {
        server_->stop();
    }
}

bool SomeipFacadeImpl::is_connected() const {
    return server_ && server_->is_running();
}

void SomeipFacadeImpl::on_report_software_inventory(
    std::function<void(const std::vector<uint8_t>&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("[SomeipFacadeImpl] 注册上行回调");
    inventory_callback_ = std::move(callback);
}

bool SomeipFacadeImpl::push_fota_command(const std::vector<uint8_t>& payload) {
    if (!server_ || !server_->is_running()) {
        spdlog::warn("[SomeipFacadeImpl] 未连接，推送失败");
        return false;
    }
    
    spdlog::info("[SomeipFacadeImpl] push_fota_command: size={}", payload.size());
    
    // Base64 编码
    std::string payload_base64 = ipc::IpcSerializer::base64_encode(payload);
    
    // 构造 JSON
    nlohmann::json j;
    j["payload_base64"] = payload_base64;
    
    // 推送事件
    server_->push_event(ipc::EventType::FOTA_COMMAND, j.dump());
    
    return true;
}

std::string SomeipFacadeImpl::handle_request(ipc::MethodId method, const std::string& params_json, int client_fd) {
    spdlog::debug("[SomeipFacadeImpl] 处理请求: method={}, client_fd={}", static_cast<uint32_t>(method), client_fd);
    
    switch (method) {
        case ipc::MethodId::GET_NET_STATUS:
            return handle_get_net_status(params_json);
            
        case ipc::MethodId::REPORT_SOFTWARE_INVENTORY:
            return handle_report_software_inventory(params_json, client_fd);
            
        case ipc::MethodId::SUBSCRIBE_NET_STATUS:
            return handle_subscribe(ipc::EventType::NET_STATUS_CHANGED, params_json, client_fd);
            
        case ipc::MethodId::SUBSCRIBE_REMOTE_COMMANDS:
            return handle_subscribe(ipc::EventType::REMOTE_COMMAND, params_json, client_fd);
            
        case ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS:
            return handle_subscribe(ipc::EventType::FOTA_COMMAND, params_json, client_fd);
            
        default:
            spdlog::warn("[SomeipFacadeImpl] 未知方法: {}", static_cast<uint32_t>(method));
            return "{\"error\":\"Unknown method\"}";
    }
}

void SomeipFacadeImpl::handle_client_disconnect(int client_fd) {
    spdlog::info("[SomeipFacadeImpl] 客户端断开: client_fd={}", client_fd);
}

std::string SomeipFacadeImpl::handle_get_net_status(const std::string& params_json) {
    if (!net_status_provider_ || !net_status_provider_->is_available()) {
        return "{\"error\":\"Net status provider not available\"}";
    }
    
    auto status = net_status_provider_->get_net_status();
    
    nlohmann::json j;
    j["is_connected"] = status.is_connected;
    j["signal_strength"] = status.signal_strength;
    j["network_type"] = status.network_type;
    j["operator"] = status.operator_name;
    
    return j.dump();
}

std::string SomeipFacadeImpl::handle_report_software_inventory(const std::string& params_json, int client_fd) {
    try {
        nlohmann::json j = nlohmann::json::parse(params_json);
        std::string snapshot_base64 = j.value("snapshot_base64", "");
        
        if (snapshot_base64.empty()) {
            return "{\"success\":false,\"error\":\"Missing snapshot_base64\"}";
        }
        
        // Base64 解码
        std::vector<uint8_t> snapshot = ipc::IpcSerializer::base64_decode(snapshot_base64);
        
        // 调用上行回调
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (inventory_callback_) {
                inventory_callback_(snapshot);
            } else {
                spdlog::warn("[SomeipFacadeImpl] 无上行回调注册");
            }
        }
        
        return "{\"success\":true}";
    } catch (const std::exception& e) {
        spdlog::error("[SomeipFacadeImpl] 解析 snapshot 失败: {}", e.what());
        return "{\"success\":false,\"error\":\"Invalid JSON\"}";
    }
}

std::string SomeipFacadeImpl::handle_subscribe(ipc::EventType type, const std::string& params_json, int client_fd) {
    // 记录订阅
    server_->add_subscription(client_fd, type);
    
    return "{\"success\":true}";
}

} // namespace tsp
} // namespace tbox
```

- [ ] **步骤 3：编译验证**

运行：`cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp/build && make -j4`
预期：编译通过，无错误

- [ ] **步骤 4：Commit**

```bash
git add include/someip_facade_impl.h src/someip_facade_impl.cpp
git commit -m "feat(tsp): add SomeipFacadeImpl with IPC server and event push"
```

---

### 任务 5：集成和配置更新

**文件：**
- 修改：`src/main.cpp`
- 修改：`CMakeLists.txt`

- [ ] **步骤 1：修改 main.cpp**

将：
```cpp
#include "someip_facade_stub.h"  // 后续替换为真正的 IPC 实现
```
替换为：
```cpp
#include "someip_facade_impl.h"
```

将：
```cpp
someip_facade_ = std::make_shared<tbox::tsp::SomeipFacadeStub>();
```
替换为：
```cpp
someip_facade_ = std::make_shared<tbox::tsp::SomeipFacadeImpl>();
```

- [ ] **步骤 2：修改 CMakeLists.txt**

将：
```cmake
add_executable(TspService
        src/main.cpp
        src/mqtt_facade_stub.cpp
        src/someip_facade_stub.cpp
        src/fota_handler.cpp
        src/security_manager.cpp
        src/tsp_http_client.cpp)
```
替换为：
```cmake
add_executable(TspService
        src/main.cpp
        src/ipc_protocol.cpp
        src/ipc_server.cpp
        src/net_status_provider.cpp
        src/someip_facade_impl.cpp
        src/mqtt_facade_stub.cpp
        src/someip_facade_stub.cpp
        src/fota_handler.cpp
        src/security_manager.cpp
        src/tsp_http_client.cpp)
```

- [ ] **步骤 3：编译验证**

运行：`cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp/build && cmake .. && make -j4`
预期：编译通过，无错误，无 warning

- [ ] **步骤 4：Commit**

```bash
git add src/main.cpp CMakeLists.txt
git commit -m "feat(tsp): integrate SomeipFacadeImpl and update build configuration"
```

---

### 任务 6：集成测试

**文件：**
- 创建：`tests/test_ipc_integration.cpp`

- [ ] **步骤 1：创建集成测试文件**

```cpp
// tests/test_ipc_integration.cpp
#include <gtest/gtest.h>
#include "someip_facade_impl.h"
#include "ipc_protocol.h"
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

class IpcIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        facade_ = std::make_unique<tbox::tsp::SomeipFacadeImpl>();
        ASSERT_TRUE(facade_->initialize());
        ASSERT_TRUE(facade_->start());
        
        // 等待服务器启动
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    void TearDown() override {
        if (facade_) {
            facade_->stop();
        }
    }
    
    std::unique_ptr<tbox::tsp::SomeipFacadeImpl> facade_;
    
    // 辅助函数：创建客户端连接
    int create_client() {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            return -1;
        }
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/tmp/tbox-tsp.sock", sizeof(addr.sun_path) - 1);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return -1;
        }
        
        return sock;
    }
    
    // 辅助函数：发送请求并接收响应
    std::string send_request(int sock, tbox::tsp::ipc::MethodId method, const std::string& params_json) {
        auto request_data = tbox::tsp::ipc::IpcSerializer::serialize_request(method, params_json);
        
        // 发送请求
        size_t total_sent = 0;
        while (total_sent < request_data.size()) {
            ssize_t bytes_sent = send(sock, request_data.data() + total_sent, request_data.size() - total_sent, 0);
            if (bytes_sent <= 0) {
                return "";
            }
            total_sent += bytes_sent;
        }
        
        // 接收响应头
        tbox::tsp::ipc::ResponseHeader header;
        memset(&header, 0, sizeof(header));
        size_t header_received = 0;
        while (header_received < sizeof(header)) {
            ssize_t bytes_read = recv(sock, reinterpret_cast<uint8_t*>(&header) + header_received, sizeof(header) - header_received, 0);
            if (bytes_read <= 0) {
                return "";
            }
            header_received += bytes_read;
        }
        
        // 接收响应数据
        std::vector<uint8_t> response_data(sizeof(header) + header.data_length);
        memcpy(response_data.data(), &header, sizeof(header));
        
        size_t data_received = 0;
        while (data_received < header.data_length) {
            ssize_t bytes_read = recv(sock, response_data.data() + sizeof(header) + data_received, header.data_length - data_received, 0);
            if (bytes_read <= 0) {
                return "";
            }
            data_received += bytes_read;
        }
        
        // 解析响应
        int32_t status_code;
        std::string response_json;
        if (!tbox::tsp::ipc::IpcSerializer::deserialize_response(response_data, status_code, response_json)) {
            return "";
        }
        
        return response_json;
    }
};

TEST_F(IpcIntegrationTest, SocketFileExists) {
    // 验证 socket 文件存在
    ASSERT_EQ(access("/tmp/tbox-tsp.sock", F_OK), 0);
}

TEST_F(IpcIntegrationTest, ClientCanConnect) {
    // 验证客户端可以连接
    int sock = create_client();
    ASSERT_GT(sock, 0);
    close(sock);
}

TEST_F(IpcIntegrationTest, GetNetStatus) {
    int sock = create_client();
    ASSERT_GT(sock, 0);
    
    // 发送 GET_NET_STATUS 请求
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::GET_NET_STATUS, "{}");
    ASSERT_FALSE(response.empty());
    
    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.contains("is_connected"));
    ASSERT_TRUE(j.contains("signal_strength"));
    ASSERT_TRUE(j.contains("network_type"));
    ASSERT_TRUE(j.contains("operator"));
    
    close(sock);
}

TEST_F(IpcIntegrationTest, ReportSoftwareInventory) {
    int sock = create_client();
    ASSERT_GT(sock, 0);
    
    // 注册上行回调
    bool callback_called = false;
    facade_->on_report_software_inventory([&callback_called](const std::vector<uint8_t>& snapshot) {
        callback_called = true;
    });
    
    // 发送 REPORT_SOFTWARE_INVENTORY 请求
    std::string params = "{\"snapshot_base64\":\"dGVzdA==\"}";
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::REPORT_SOFTWARE_INVENTORY, params);
    ASSERT_FALSE(response.empty());
    
    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.value("success", false));
    
    // 验证回调被调用
    ASSERT_TRUE(callback_called);
    
    close(sock);
}

TEST_F(IpcIntegrationTest, SubscribeAndPushEvent) {
    int sock = create_client();
    ASSERT_GT(sock, 0);
    
    // 订阅 FOTA_COMMAND 事件
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS, "{}");
    ASSERT_FALSE(response.empty());
    
    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.value("success", false));
    
    // 推送事件
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    facade_->push_fota_command(payload);
    
    // 接收事件
    tbox::tsp::ipc::EventHeader event_header;
    memset(&event_header, 0, sizeof(event_header));
    size_t header_received = 0;
    while (header_received < sizeof(event_header)) {
        ssize_t bytes_read = recv(sock, reinterpret_cast<uint8_t*>(&event_header) + header_received, sizeof(event_header) - header_received, 0);
        if (bytes_read <= 0) {
            break;
        }
        header_received += bytes_read;
    }
    
    if (header_received == sizeof(event_header)) {
        ASSERT_EQ(event_header.event_type, static_cast<uint32_t>(tbox::tsp::ipc::EventType::FOTA_COMMAND));
        ASSERT_GT(event_header.payload_length, 0);
    }
    
    close(sock);
}

TEST_F(IpcIntegrationTest, ClientDisconnectCleanup) {
    int sock = create_client();
    ASSERT_GT(sock, 0);
    
    // 订阅事件
    send_request(sock, tbox::tsp::ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS, "{}");
    
    // 断开连接
    close(sock);
    
    // 等待清理
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 验证服务器仍在运行
    ASSERT_TRUE(facade_->is_connected());
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
```

- [ ] **步骤 2：更新 CMakeLists.txt 添加测试**

在 CMakeLists.txt 末尾添加：
```cmake
# 集成测试
add_executable(IpcIntegrationTest tests/test_ipc_integration.cpp)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
target_link_libraries(IpcIntegrationTest PRIVATE gtest gtest_main pthread)
target_link_libraries(IpcIntegrationTest PRIVATE ${HWYZ_LIBRARIES})
```

- [ ] **步骤 3：编译并运行测试**

运行：
```bash
cd /Users/hwyz_leo/Projects/open-iov/vehicle/tbox/iov-vehicle-tbox-tsp/build
cmake .. -DBUILD_TESTS=ON
make -j4
./IpcIntegrationTest
```

预期：所有测试通过

- [ ] **步骤 4：Commit**

```bash
git add tests/test_ipc_integration.cpp CMakeLists.txt
git commit -m "test(tsp): add IPC integration tests"
```

---

## 验收检查清单

- [ ] TBOX-TSP 启动后 `/tmp/tbox-tsp.sock` 存在
- [ ] 外部客户端能连接并发送 GET_NET_STATUS 请求，收到有效响应
- [ ] 外部客户端能发送 REPORT_SOFTWARE_INVENTORY，FotaHandler 的上行回调被触发
- [ ] 外部客户端订阅后，TSP 能主动推送事件
- [ ] 客户端断开后服务端不崩溃，订阅被清理
- [ ] 服务端 stop() 后 socket 文件被清理
- [ ] 编译通过，无 warning
- [ ] 所有集成测试通过

---

## 执行交接

计划已完成并保存到 `docs/superpowers/plans/2026-07-24-tbox-tsp-ipc-server.md`。两种执行方式：

**1. 子代理驱动（推荐）** - 每个任务调度一个新的子代理，任务间进行审查，快速迭代

**2. 内联执行** - 在当前会话中使用 executing-plans 执行任务，批量执行并设有检查点

选哪种方式？