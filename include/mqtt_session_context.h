// TBOX-TSP-DSN-CR-011 §18.2: MQTT 只读会话身份类型（轻量头）。
//
// 该类型是 TSP 侧对 MQTT CR-017 SessionContext 的只读投影，字段语义与 MQTT
// 公开 SDK 的 tbox::mqtt::SessionContext 一致：
//   - daemon_epoch：MQTT 进程级生命周期标识，进程内不变、重启更新；
//   - connection_generation：Broker 连接代际；
//   - cert_session_generation：本次 TLS 会话不可复用代际。
//
// 设计约束（CR-011 §3/§4/§18.2）：
//   - TSP 不生成、不猜测、不用时间戳/PID 兜底任何字段；
//   - 字段来自同一不可变快照，调用方不得分别查询后拼接；
//   - 该上下文不是授权凭据，最终是否可发布由 MQTT daemon 的 guard 判定；
//   - 为让 keyprov_protocol.h 不依赖整个 mqtt_facade.h，单独抽出本轻量头，
//     由 mqtt_facade.h 与 keyprov_protocol.h 共同引用（不复制第二套定义）。

#pragma once

#include <cstdint>
#include <string>

namespace tbox {
namespace tsp {

struct MqttSessionContext {
    std::string daemon_epoch;
    uint64_t connection_generation = 0;
    uint64_t cert_session_generation = 0;
};

} // namespace tsp
} // namespace tbox
