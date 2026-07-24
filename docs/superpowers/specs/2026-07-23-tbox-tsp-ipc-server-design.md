# TBOX-TSP IPC Server 设计规格

## 1. 项目概述

将 TBOX-TSP 服务的 `SomeipFacadeStub` 替换为真正的 IPC 实现，使 TBOX-SOMEIP 能通过 Unix domain socket 与 TBOX-TSP 通信。

## 2. 当前状态

### 2.1 现有架构
- `SomeipFacade`：抽象接口类，定义 initialize/start/stop/on_report_software_inventory/push_fota_command/is_connected
- `SomeipFacadeStub`：桩实现，通过日志模拟 IPC 调用
- `FotaHandler`：业务处理器，依赖 SomeipFacade 接口

### 2.2 参考实现
- **iov-vehicle-tbox-sec**：`/tmp/tbox-sec.sock`，完整的 IPC 协议层和服务层实现
- **iov-vehicle-tbox-prov**：`/tmp/tbox-prov.sock`，包含客户端实现示例

## 3. 设计方案

### 3.0 整体架构（方案A：统一出口）

采用 **TBOX-SOMEIP 作为 SOME/IP 统一出口** 的架构：

```
┌─────────────┐    IPC (上行)     ┌─────────────┐    SOME/IP     ┌─────────────┐
│  TBOX-TSP   │ ◄─────────────── │ TBOX-SOMEIP │ ◄───────────── │  CGW-FOTA   │
│  (服务端)    │                  │  (统一出口)  │               │  (外部服务)  │
│             │    IPC (下行)     │             │    SOME/IP     │             │
│             │ ────────────────►│             │ ──────────────►│             │
└─────────────┘                  └─────────────┘               └─────────────┘
        │
        │ IPC (上行)
        ▼
┌─────────────┐
│  TBOX-MQTT  │
│  (MQTT客户端)│
└─────────────┘
```

**数据流**：
- **上行**：CGW-FOTA → (SOME/IP) → TBOX-SOMEIP → (IPC) → TBOX-TSP → TBOX-MQTT → 云端
- **下行**：云端 → TBOX-MQTT → TBOX-TSP → (IPC) → TBOX-SOMEIP → (SOME/IP) → CGW-FOTA

**关键点**：
1. TBOX-SOMEIP 是 SOME/IP 协议的**统一出口**，所有业务服务通过它调用外部 SOME/IP 服务
2. TBOX-TSP 是 **IPC 服务端**，接收 TBOX-SOMEIP 的上行请求
3. TBOX-TSP 是 **IPC 客户端**，通过 TBOX-SOMEIP 下行命令给 CGW-FOTA

### 3.1 协议层设计

#### 3.1.1 命名空间
```
tbox::tsp::ipc
```

#### 3.1.2 Socket 路径
```
/tmp/tbox-tsp.sock
```

#### 3.1.3 方法 ID 枚举
```cpp
enum class MethodId : uint32_t {
    GET_NET_STATUS              = 1,   // 请求-响应
    REPORT_SOFTWARE_INVENTORY   = 2,   // 请求-响应
    SUBSCRIBE_NET_STATUS        = 3,   // 注册订阅
    SUBSCRIBE_REMOTE_COMMANDS   = 4,   // 注册订阅
    SUBSCRIBE_FOTA_COMMANDS     = 5,   // 注册订阅
};
```

#### 3.1.4 事件类型枚举
```cpp
enum class EventType : uint32_t {
    NET_STATUS_CHANGED  = 100,
    REMOTE_COMMAND      = 101,
    FOTA_COMMAND         = 102,
};
```

#### 3.1.5 消息头结构
```cpp
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
```

#### 3.1.6 序列化工具
```cpp
class IpcSerializer {
public:
    static std::vector<uint8_t> serialize_request(MethodId method, const std::string& params_json);
    static bool deserialize_request(const std::vector<uint8_t>& data, MethodId& method, std::string& params_json);
    static std::vector<uint8_t> serialize_response(int32_t status_code, const std::string& response_json);
    static bool deserialize_response(const std::vector<uint8_t>& data, int32_t& status_code, std::string& response_json);
    
    static std::vector<uint8_t> serialize_event(EventType type, const std::string& payload_json);
    static bool deserialize_event(const std::vector<uint8_t>& data, EventType& type, std::string& payload_json);
    
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};
```

### 3.2 服务层设计

#### 3.2.1 IpcServer 类
```cpp
class IpcServer {
public:
    using RequestHandler = std::function<std::string(MethodId method, const std::string& params_json)>;
    using SubscriptionHandler = std::function<void(int client_fd, EventType type, bool subscribed)>;

    IpcServer(const std::string& socket_path = DEFAULT_SOCKET_PATH);
    ~IpcServer();

    bool start(RequestHandler request_handler, SubscriptionHandler subscription_handler = nullptr);
    void stop();

    // 向所有已订阅指定事件的客户端推送事件
    void push_event(EventType type, const std::string& payload_json);

    bool is_running() const { return running_; }

private:
    std::string socket_path_;
    int server_fd_;
    int shutdown_pipe_[2];
    std::atomic<bool> running_;
    std::thread accept_thread_;
    
    RequestHandler request_handler_;
    SubscriptionHandler subscription_handler_;
    
    // 客户端订阅管理：client_fd -> set<EventType>
    std::unordered_map<int, std::unordered_set<uint32_t>> subscriptions_;
    std::mutex subs_mutex_;
    
    // 活跃客户端连接
    std::unordered_set<int> active_clients_;
    std::mutex clients_mutex_;

    void accept_connections();
    void handle_client(int client_fd);
    std::string handle_request(const std::string& request_data);
    
    void add_subscription(int client_fd, EventType type);
    void remove_subscription(int client_fd, EventType type);
    void cleanup_client(int client_fd);
};
```

#### 3.2.2 关键设计点
1. **长连接**：每个客户端独立线程，保持连接直到客户端断开或超时
2. **优雅退出**：select + shutdown_pipe 机制
3. **订阅管理**：客户端发送 SUBSCRIBE_xxx 请求后，记录该 client_fd 订阅了哪些 EventType
4. **事件推送**：push_event() 遍历 subscriptions_，向已订阅的客户端发送 EventHeader + payload
5. **连接清理**：客户端断开时清理其订阅和活跃连接记录

### 3.3 Facade 实现层设计

#### 3.3.1 SomeipFacadeImpl 类
```cpp
class SomeipFacadeImpl : public SomeipFacade {
public:
    SomeipFacadeImpl();
    ~SomeipFacadeImpl() override;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool is_connected() const override;

    void on_report_software_inventory(
        std::function<void(const std::vector<uint8_t>&)> callback) override;

    bool push_fota_command(const std::vector<uint8_t>& payload) override;

private:
    std::unique_ptr<IpcServer> server_;
    std::function<void(const std::vector<uint8_t>&)> inventory_callback_;
    mutable std::mutex mutex_;
    
    // 请求处理回调
    std::string handle_request(MethodId method, const std::string& params_json);
    
    // 订阅处理回调
    void handle_subscription(int client_fd, EventType type, bool subscribed);
    
    // 具体方法处理
    std::string handle_get_net_status(const std::string& params_json);
    std::string handle_report_software_inventory(const std::string& params_json);
    std::string handle_subscribe(EventType type, const std::string& params_json, int client_fd);
};
```

#### 3.3.2 方法分发逻辑

| MethodId | 处理方式 |
|----------|---------|
| `GET_NET_STATUS` | 调用内部网络状态获取逻辑，返回 JSON |
| `REPORT_SOFTWARE_INVENTORY` | 调用 `inventory_callback_`，返回成功/失败 |
| `SUBSCRIBE_NET_STATUS` | 记录订阅，返回成功 |
| `SUBSCRIBE_REMOTE_COMMANDS` | 记录订阅，返回成功 |
| `SUBSCRIBE_FOTA_COMMANDS` | 记录订阅，返回成功 |

#### 3.3.3 push_fota_command 实现
- 调用 `server_->push_event(EventType::FOTA_COMMAND, payload_json)`
- 向所有订阅了 FOTA_COMMAND 的客户端推送

### 3.4 数据格式约定

#### 3.4.1 GET_NET_STATUS

**请求：** `{}`

**响应：**
```json
{
  "is_connected": true,
  "signal_strength": 85,
  "network_type": "4G",
  "operator": "CMCC"
}
```

#### 3.4.2 REPORT_SOFTWARE_INVENTORY

**请求：** 原始 snapshot 字节（base64 编码放入 JSON）
```json
{
  "snapshot_base64": "..."
}
```

**响应：**
```json
{
  "success": true
}
```

#### 3.4.3 推送事件 payload

**NET_STATUS_CHANGED：**
```json
{
  "is_connected": true,
  "signal_strength": 85,
  "network_type": "4G"
}
```

**REMOTE_COMMAND / FOTA_COMMAND：**
```json
{
  "payload_base64": "..."
}
```

### 3.5 网络状态获取策略

采用**策略模式**，将网络状态获取抽象为接口，支持多种实现：

#### 3.5.1 NetStatusProvider 接口
```cpp
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
```

#### 3.5.2 三种实现

**实现1：MockNetStatusProvider（模拟状态）**
- 用于开发和测试阶段
- 返回预设的固定值
- 当前阶段使用此实现

**实现2：SystemNetStatusProvider（系统API）**
- 通过 Linux 系统命令获取真实网络状态
- 读取 `/sys/class/net/` 下的文件
- 调用 `iwconfig`、`nmcli` 等命令

**实现3：ModuleNetStatusProvider（模块集成）**
- 集成其他模块（如 TBOX 网络管理模块）
- 通过回调或查询方式获取网络状态

#### 3.5.3 工厂方法
```cpp
class NetStatusProviderFactory {
public:
    enum class ProviderType {
        MOCK,
        SYSTEM,
        MODULE
    };
    
    static std::unique_ptr<NetStatusProvider> create(ProviderType type);
};
```

#### 3.5.4 配置支持
通过配置文件或启动参数指定使用哪种实现：
```yaml
net_status_provider: mock  # mock, system, module
```

## 4. 文件结构

### 4.1 新增文件
```
include/ipc_protocol.h          # IPC 协议定义
include/ipc_server.h            # IPC 服务端
include/someip_facade_impl.h    # SomeipFacade 真实实现
src/ipc_protocol.cpp            # IPC 协议实现
src/ipc_server.cpp              # IPC 服务端实现
src/someip_facade_impl.cpp      # SomeipFacade 实现
```

### 4.2 修改文件
```
src/main.cpp                    # 替换 SomeipFacadeStub 为 SomeipFacadeImpl
CMakeLists.txt                  # 添加新源文件
```

## 5. 验收标准

1. TBOX-TSP 启动后 `/tmp/tbox-tsp.sock` 存在
2. 外部客户端能连接并发送 GET_NET_STATUS 请求，收到有效响应
3. 外部客户端能发送 REPORT_SOFTWARE_INVENTORY，FotaHandler 的上行回调被触发
4. 外部客户端订阅后，TSP 能主动推送事件
5. 客户端断开后服务端不崩溃，订阅被清理
6. 服务端 stop() 后 socket 文件被清理
7. 编译通过，无 warning

## 6. 实现步骤

1. 实现 IPC 协议层（ipc_protocol.h/cpp）
2. 实现 IPC 服务层（ipc_server.h/cpp）
3. 实现 SomeipFacadeImpl（someip_facade_impl.h/cpp）
4. 更新 main.cpp
5. 更新 CMakeLists.txt
6. 编译测试
7. 集成测试

## 7. 风险与注意事项

1. **线程安全**：多个客户端可能同时访问，需要确保订阅管理和事件推送的线程安全
2. **资源清理**：客户端断开时必须清理所有相关资源
3. **错误处理**：网络异常、序列化失败等情况需要妥善处理
4. **性能考虑**：事件推送时避免阻塞其他客户端
5. **兼容性**：保持与 SEC/PROV 项目一致的协议格式
6. **依赖管理**：确保 nlohmann/json 库可用
7. **系统兼容性**：SystemNetStatusProvider 可能因系统不同而有所差异

## 8. 验收标准

1. TBOX-TSP 启动后 `/tmp/tbox-tsp.sock` 存在
2. 外部客户端能连接并发送 GET_NET_STATUS 请求，收到有效响应
3. 外部客户端能发送 REPORT_SOFTWARE_INVENTORY，FotaHandler 的上行回调被触发
4. 外部客户端订阅后，TSP 能主动推送事件
5. 客户端断开后服务端不崩溃，订阅被清理
6. 服务端 stop() 后 socket 文件被清理
7. 编译通过，无 warning