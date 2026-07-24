# TBOX-TSP-DSN-CR-002: framework-log 集成设计

> **设计变更来源**：TBOX-TSP-DSN-CR-002（对应需求 TBOX-TSP-REQ-CR-002）
> **设计基线**：TBOX-TSP-SPEC设计
> **上位设计**：TBOX-FW-DSN-CR-004（framework-log）

---

## 1. 设计目标

TBOX-TSP 静态链接 `framework-log`，通过统一 Logger facade 输出结构化业务日志。framework 负责字段补齐、级别过滤、脱敏、异步队列、格式化与 sink；TBOX-TSP 仅负责业务事件、字段值、错误码和调用链上下文。

**迁移策略**：一步到位，将所有 spdlog 调用替换为 framework-log。

---

## 2. 初始化与模块划分

### 2.1 启动顺序

1. `Config::load("tsp")` — 已有
2. 读取 `common.log.*` 与 `tsp.log.*`
3. `Logger::init("tsp", logConfig)`
4. 创建模块 Logger：`relay`、`fota`、`route`、`mqtt_client`、`someip_bridge`
5. 注册上下行路由并进入服务循环

### 2.2 模块职责

| 模块 | 职责 | 对应组件 |
|------|------|----------|
| `relay` | 业务中继主流程 | FotaHandler |
| `fota` | FOTA 上下行处理 | FotaHandler |
| `route` | 路由注册与管理 | FotaHandler::start() |
| `mqtt_client` | MQTT 客户端操作 | MqttFacadeStub |
| `someip_bridge` | SOME/IP 桥接 | SomeipFacadeImpl |

### 2.3 错误处理

初始化失败、队列溢出和 sink 故障统一使用 FW-0201～FW-0204 语义；TBOX-TSP 不重复定义框架错误码。

---

## 3. 调用链上下文

### 3.1 上行（SOME/IP → TBOX-TSP → MQTT）

- SOME/IP/IPC 上行进入 TBOX-TSP 时，以 `request_id` 作为单次中继请求标识
- 上游已有 `trace_id` 时原样传播
- 通过 `ContextScope` 将上下文附加到解析、去重、路由、publish 和回执日志

### 3.2 下行（MQTT → TBOX-TSP → SOME/IP）

- MQTT 下行进入时，为单次消息处理建立 `request_id`
- 协议中已有可用关联标识时映射为 `trace_id` 或业务字段

### 3.3 约束

- 不将 payload 内容作为关联 ID
- 关联 ID 必须长度受限（≤ 36 字符）且通过字段校验

---

## 4. 业务事件清单

| 事件 | 级别 | 模块 | 触发条件 | 关键字段 | 错误码 |
|------|------|------|----------|----------|--------|
| `tsp.route.register.succeeded` | INFO | route | FOTA 上下行路由注册成功 | `topic`, `direction`, `qos` | — |
| `tsp.route.register.failed` | ERROR | route | 路由注册失败 | `topic`, `direction`, `qos`, `duration_ms` | `TBOX-TSP-1004` |
| `tsp.fota.uplink.received` | DEBUG | fota | 收到软件版本快照 | `snapshot_seq`, `item_count`, `payload_size` | — |
| `tsp.fota.uplink.published` | INFO | fota | 快照发布成功 | `topic`, `qos`, `snapshot_seq`, `duration_ms` | — |
| `tsp.fota.uplink.publish_failed` | ERROR | fota | MQTT 发布失败或超时 | `topic`, `qos`, `snapshot_seq`, `duration_ms`, `retry_count` | `TBOX-TSP-1001` |
| `tsp.fota.snapshot.duplicate` | INFO | fota | 去重命中并丢弃重复快照 | `snapshot_seq`, `dedup_key` | `TBOX-TSP-1003` |
| `tsp.fota.downlink.received` | DEBUG | fota | 收到 FOTA 下行 | `topic`, `payload_size` | — |
| `tsp.fota.downlink.parse_failed` | WARN | fota | 下行 payload 无法解析 | `topic`, `payload_size`, `schema_version` | `TBOX-TSP-1002` |
| `tsp.fota.downlink.forwarded` | INFO | fota | 下行成功转交 SOME/IP 门面 | `topic`, `duration_ms` | — |

**约束**：
- 事件名作为稳定检索契约
- `message` 仅面向人阅读，不承载可检索字段

---

## 5. 字段与脱敏

### 5.1 字段分类

| 字段 | 敏感度 | 处理方式 |
|------|--------|----------|
| `device_sn` | Identifier | 掩码（首尾各2字符），禁止写入 `message` |
| `snapshot_seq` | Normal | 直接输出 |
| `topic` | Normal | 直接输出 |
| `qos` | Normal | 直接输出 |
| `direction` | Normal | 直接输出 |
| `duration_ms` | Normal | 直接输出 |
| `retry_count` | Normal | 直接输出 |
| `payload_size` | Normal | 直接输出 |
| `dedup_key`（含设备标识） | Identifier | 输出不可逆摘要 |
| FOTA/MQTT payload | Payload | 不进入常规日志；DEBUG 诊断仅允许经协议过滤和长度限制后的摘要 |
| Token/证书私钥/密钥材料/安全访问种子 | Secret | 拒绝输出 |

### 5.2 脱敏实现

使用 framework-log 的 `Sensitivity` 枚举和 `Redactor` 组件：
- `Sensitivity::Identifier` → 掩码
- `Sensitivity::Payload` → 限长 + 过滤
- `Sensitivity::Secret` → 拒绝

---

## 6. 错误码调整

### 6.1 新增错误码

| 错误码 | 含义 | 处理 |
|--------|------|------|
| `TBOX-TSP-1004` | 业务路由注册失败 | 记录结构化错误事件，按启动/重试策略处理，不静默进入无路由状态 |

### 6.2 错误码边界

- FW-02xx 仅描述日志组件自身故障
- TBOX-TSP-10xx 描述业务中继失败
- 两者不得互相替代

---

## 7. 指标与日志边界

- 成功率、时延、重试次数、去重次数由指标系统聚合；日志只记录离散事件与诊断上下文
- 不通过解析 `message` 生成指标；需要聚合的维度使用稳定字段或独立 metric label
- 日志不得作为发送状态、去重状态、回执状态或审计事实的唯一存储

---

## 8. 文件变更清单

### 8.1 新增文件

| 文件 | 说明 |
|------|------|
| `include/log_adapter.h` | TSP 日志适配器头文件 |
| `src/log_adapter.cpp` | TSP 日志适配器实现 |
| `tests/test_log_adapter.cpp` | LogAdapter 单元测试 |

### 8.2 修改文件

| 文件 | 变更说明 |
|------|----------|
| `CMakeLists.txt` | 添加 framework-log 依赖 |
| `include/error_codes.h` | 新增 `TBOX-TSP-1004` |
| `src/main.cpp` | 替换 spdlog 为 framework-log 初始化 |
| `src/fota_handler.cpp` | 结构化事件 + 上下文传播 + 脱敏 |
| `src/mqtt_facade_stub.cpp` | 路由注册事件日志 |
| `src/someip_facade_impl.cpp` | 上下文生成 |
| `tests/test_fota_handler.cpp` | 集成测试更新 |

---

## 9. 测试设计

### 9.1 单元测试（test_log_adapter.cpp）

- Logger 初始化成功/失败
- 模块 Logger 获取（relay、fota、route、mqtt_client、someip_bridge）
- 上下文传播验证（ContextScope）
- 脱敏验证（device_sn 掩码、Secret 拒绝）

### 9.2 集成测试（test_fota_handler.cpp）

- 上行事件链路：`tsp.fota.uplink.received` → `tsp.fota.uplink.published`
- 下行事件链路：`tsp.fota.downlink.received` → `tsp.fota.downlink.forwarded`
- 失败事件：`tsp.fota.uplink.publish_failed`、`tsp.fota.downlink.parse_failed`
- 去重事件：`tsp.fota.snapshot.duplicate`
- 路由注册事件：`tsp.route.register.succeeded`、`tsp.route.register.failed`

### 9.3 故障测试

- 路由注册失败
- publish 超时
- payload 解析失败
- 队列满（由 framework-log 测试覆盖）

### 9.4 安全测试

- `device_sn` 不以明文输出
- 原始 payload 不进入常规日志
- Token/密钥材料被拒绝输出

---

## 10. 实现顺序

1. 更新 `CMakeLists.txt` 添加 framework-log 依赖
2. 更新 `include/error_codes.h` 新增 TBOX-TSP-1004
3. 实现 `include/log_adapter.h` 和 `src/log_adapter.cpp`
4. 修改 `src/main.cpp` 替换 spdlog 初始化
5. 修改 `src/fota_handler.cpp` 实现结构化事件
6. 修改 `src/mqtt_facade_stub.cpp` 添加路由事件
7. 编写 `tests/test_log_adapter.cpp`
8. 更新 `tests/test_fota_handler.cpp`
9. 运行测试验证

---

## 11. 影响范围

- TBOX-TSP 新增 `framework-log` 构建依赖与 Logger 初始化点
- 新增业务事件清单和 `TBOX-TSP-1004`
- 不修改 MQTT topic/QoS、SOME/IP/IPC 接口及 FOTA payload schema
- 不新增跨进程接口

---

## 12. 关联文档

- 需求变更：TBOX-TSP-REQ-CR-002
- 设计基线：TBOX-TSP-SPEC设计
- 上位设计：TBOX-FW-DSN-CR-004
