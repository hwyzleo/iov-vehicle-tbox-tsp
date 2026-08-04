//
// TBOX-TSP-DSN-CR-007 §13.2: installed-package consumer。
// 仅做编译期/链接期验证：构造 TspClient、检查 facade 方法签名可解析、
// 验证错误码与 DTO 类型来自安装后的公共头文件（tbox/tsp/...）。
// 不连接真实 daemon、不执行任何 IPC/MQTT 操作。
//

#include <tbox/tsp/client.h>
#include <tbox/tsp/errors.h>
#include <tbox/tsp/types.h>

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

int main() {
    // 构造（默认 socket 路径）——验证公开构造可用
    tbox::tsp::TspClient client("/tmp/tbox-tsp-consumer.sock");

    // 公开类型可解析（TspErrorCode 为强类型枚举）
    tbox::tsp::TspErrorCode ec = tbox::tsp::TspErrorCode::SUCCESS;
    (void)ec;

    // DTO 类型可实例化（FotaSnapshot / FotaCommand / RelayStatus / ReportResult）
    tbox::tsp::FotaSnapshot snapshot;
    snapshot.snapshot_seq = 1;
    snapshot.msg_id = "consumer-msg-1";
    snapshot.payload = std::vector<std::uint8_t>{0x01, 0x02};
    tbox::tsp::FotaCommand cmd;
    cmd.command_id = "consumer-cmd-1";
    tbox::tsp::RelayStatus status;
    status.state = tbox::tsp::RelayState::UNKNOWN;
    tbox::tsp::ReportResult result;
    result.outcome = tbox::tsp::PublishOutcome::ACCEPTED;
    (void)cmd;
    (void)status;
    (void)result;

    // facade 方法签名可解析（仅编译期；不连接 daemon）
    //  - reportSoftwareInventory: 上行 FOTA 版本清单（accepted ≠ Broker PUBACK）
    //  - subscribeFotaCommand:    下行命令订阅（RAII Subscription，framework-ipc 句柄）
    //  - getRelayStatus:          中继状态查询
    using ReportFn = tbox::tsp::ReportResult (tbox::tsp::TspClient::*)(const tbox::tsp::FotaSnapshot&);
    ReportFn report_fn = &tbox::tsp::TspClient::reportSoftwareInventory;
    using SubscribeFn = ::tbox::fw::ipc::Subscription (tbox::tsp::TspClient::*)(tbox::tsp::FotaCommandCallback);
    SubscribeFn subscribe_fn = &tbox::tsp::TspClient::subscribeFotaCommand;
    using StatusFn = tbox::tsp::RelayStatus (tbox::tsp::TspClient::*)(const std::string&);
    StatusFn status_fn = &tbox::tsp::TspClient::getRelayStatus;
    (void)report_fn;
    (void)subscribe_fn;
    (void)status_fn;

    std::printf("OK: tbox::tsp_client installed-package consumer compiles/links\n");
    return 0;
}
