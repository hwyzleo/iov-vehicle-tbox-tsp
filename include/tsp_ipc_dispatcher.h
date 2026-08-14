// TBOX-TSP IPC 请求分发适配器 (CR-003 §2; CR-009 §Client 与 IPC 契约)
//
// 将 framework-ipc 的 RequestHandler 签名适配到 TSP 业务。
// 只负责 JSON 解码/编码、调用业务 handler 及业务状态映射，
// 不复制 socket 逻辑（由 framework-ipc Server 负责）。
//
// CR-009：旧 report/relay-status 专用 method 已删除；IPC 只承载单一
// vehicle.common.v1.VehicleMessageEnvelope。EXCHANGE_VEHICLE_MESSAGE 为阻塞式
// 请求-响应：dispatcher 在线程目标上等待 VehicleMessageRelayInterface::exchange
// 返回（异步 MQTT RESPONSE correlation 完成同步 exchange）。
//
// 响应 JSON 中嵌入 status 字段（TBOX-TSP-10xx 业务状态码），
// framework 在 ResponseHeader.status_code 中写入 0（传输成功）或 FW-03xx（传输失败）。
//
// 订阅注册（add_subscription）由 TspFrameworkServer 的 request_handler lambda 完成，
// dispatcher 只返回订阅 ack。
//
// IPC 日志只记录 method_id、status、payload_bytes、duration，不记录原始 payload。

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace tbox {
namespace tsp {

class VehicleMessageRelayInterface;
class NetStatusProvider;

class TspIpcDispatcher {
public:
    /// @param relay         通用 VehicleMessage 中继业务接口
    /// @param net_provider  网络状态提供者（可为 nullptr）
    /// @param max_payload_bytes 单帧 payload 上限（超限在分配前拒绝，默认 10 MiB）
    TspIpcDispatcher(VehicleMessageRelayInterface* relay,
                     NetStatusProvider* net_provider,
                     uint32_t max_payload_bytes = 10485760);

    /// framework RequestHandler 回调入口
    /// @param method_id   TSP method ID
    /// @param params_json 请求参数 JSON
    /// @param client_fd   客户端 fd（预留）
    /// @return 响应 JSON 字符串
    std::string dispatch(uint32_t method_id,
                         std::string_view params_json,
                         int client_fd);

private:
    VehicleMessageRelayInterface* relay_;
    NetStatusProvider* net_provider_;
    uint32_t max_payload_bytes_;

    // 各 method handler，返回 (status_code, response_json)
    std::pair<int32_t, std::string> handle_exchange_vehicle_message(std::string_view params);
    std::pair<int32_t, std::string> handle_get_net_status();
    std::pair<int32_t, std::string> handle_subscribe();
};

} // namespace tsp
} // namespace tbox
