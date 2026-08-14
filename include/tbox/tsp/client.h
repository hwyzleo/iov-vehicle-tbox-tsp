// TBOX-TSP 客户端 facade (TBOX-TSP-DSN-CR-009 §Client 与 IPC 契约, SPEC §5.2)
//
// 调用方（TBOX-SOMEIP 等）通过此接口与 TSP daemon 交互。
// IPC 传输细节封装在库内部，对调用方不可见。
// 内部使用 framework-ipc Client。
//
// CR-009 边界：
// - 只暴露通用 exchangeVehicleMessage / subscribeVehicleMessage，不暴露 FOTA 生成类型。
// - IPC wire 只承载单一 Envelope bytes；若 framework-ipc JSON wire 需要 base64，
//   只对该 Envelope bytes 编码一次，禁止外层独立 payload/service/PayloadType。
// - exchangeVehicleMessage Accepted 不等于 MQTT PUBACK 或 FOTA 业务成功；value 仅在
//   收到对应业务 RESPONSE Envelope 时存在。Timeout/Unknown 由调用方（CGW-FOTA）以
//   原 request/idempotency 身份收敛，不生成新业务身份自动重试。
// - subscribeVehicleMessage 每次订阅建立独立连接，完成 Response 后进入 event-only。
//   framework push_event 不保证断线持久投递；非幂等 EVENT 重连后不得盲目重放。

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include "tbox/tsp/types.h"
#include "tbox/tsp/errors.h"
#include "ipc.h"  // framework-ipc Subscription (RAII 句柄)

namespace tbox {
namespace tsp {

/// TSP 客户端 facade
class TspClient {
public:
    /// @param socket_path TSP daemon IPC socket 路径（默认 /tmp/tbox-tsp.sock）
    explicit TspClient(const std::string& socket_path = "/tmp/tbox-tsp.sock");
    ~TspClient();

    TspClient(const TspClient&) = delete;
    TspClient& operator=(const TspClient&) = delete;
    TspClient(TspClient&&) = delete;
    TspClient& operator=(TspClient&&) = delete;

    /// 显式连接（也可惰性连接）
    bool connect();
    void disconnect();
    bool is_connected() const;

    /// 上行：通用车云消息交换（请求-响应，阻塞至业务 RESPONSE/超时）(CR-009)
    /// @return Accepted + value 仅当收到合法业务 RESPONSE Envelope；
    ///         Timeout/Unknown 由调用方以原 request/idempotency 身份收敛。
    TransportResult<VehicleMessage> exchangeVehicleMessage(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx);

    /// 下行：按 service 订阅云端 EVENT Envelope (CR-009)
    /// 每次订阅建立独立连接，完成订阅 Response 后进入 event-only loop。
    /// 返回 RAII Subscription 句柄，析构时自动取消。
    /// @return 活跃 Subscription；失败返回 isActive()==false 的空句柄。
    ::tbox::fw::ipc::Subscription subscribeVehicleMessage(
        std::string_view service, VehicleMessageHandler handler);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tsp
} // namespace tbox
