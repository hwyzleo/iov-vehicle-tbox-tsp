// TBOX-TSP 客户端 facade (CR-003 §7, SPEC §5.2)
//
// 调用方（TBOX-SOMEIP 等）通过此接口与 TSP daemon 交互。
// IPC 传输细节封装在库内部，对调用方不可见。
// 内部使用 framework-ipc Client + TspRetryPolicy。
//
// 边界 (CR-003 §4, §5)：
// - reportSoftwareInventory accepted 仅表示 TSP 已校验并由 MQTT daemon 接管，
//   不等于 Broker 已 PUBACK。
// - 响应丢失时 outcome=UNKNOWN，只能复用相同 msg_id 查询/单次重试，禁止生成新序号盲目重发。
// - subscribeFotaCommand 每次订阅建立独立连接，完成 Response 后进入 event-only。
//   framework push_event 不保证断线持久投递；非幂等命令重连后不得盲目重放。

#pragma once

#include <functional>
#include <memory>
#include <string>
#include "tbox/tsp/types.h"
#include "tbox/tsp/errors.h"
#include "ipc.h"  // framework-ipc Subscription (RAII 句柄)

namespace tbox {
namespace tsp {

/// 下行 FOTA 命令回调
using FotaCommandCallback = std::function<void(const FotaCommand& command)>;

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

    /// 上行：FOTA 版本清单上报 (CR-003 §4)
    /// @return accepted 仅表示 TSP 已校验并由 MQTT daemon 接管，不等于 Broker PUBACK。
    ///         outcome=UNKNOWN 时仅可复用相同 msg_id 查询/单次重试。
    ReportResult reportSoftwareInventory(const FotaSnapshot& snapshot);

    /// 下行：订阅 FOTA 云端命令 (CR-003 §5)
    /// 每次订阅建立独立连接，完成订阅 Response 后进入 event-only loop。
    /// 返回 RAII Subscription 句柄，析构时自动取消。
    /// @return 活跃 Subscription；失败返回 isActive()==false 的空句柄。
    ::tbox::fw::ipc::Subscription subscribeFotaCommand(FotaCommandCallback callback);

    /// 状态查询 (CR-003 §2, SPEC §5.2)
    /// 查询 accepted/published/acked/failed。
    RelayStatus getRelayStatus(const std::string& msg_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tsp
} // namespace tbox
