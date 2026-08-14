//
// TBOX-TSP-DSN-CR-007 §13.2 / CR-009: installed-package consumer。
// 仅做编译期/链接期验证：构造 TspClient、检查通用 facade 方法签名可解析、
// 验证错误码与 DTO 类型来自安装后的公共头文件（tbox/tsp/...）。
// 不连接真实 daemon、不执行任何 IPC/MQTT 操作。
//

#include <tbox/tsp/client.h>
#include <tbox/tsp/errors.h>
#include <tbox/tsp/types.h>

#include <cstdio>
#include <cstdint>
#include <string>
#include <string_view>
#include <chrono>
#include <cstddef>
#include <vector>

int main() {
    // 构造（默认 socket 路径）——验证公开构造可用
    tbox::tsp::TspClient client("/tmp/tbox-tsp-consumer.sock");

    // 公开类型可解析（TspErrorCode 为强类型枚举）
    tbox::tsp::TspErrorCode ec = tbox::tsp::TspErrorCode::SUCCESS;
    (void)ec;

    // CR-009 公共类型可实例化（VehicleMessage / TransportOutcome / ExchangeOptions /
    // CallContext / TransportResult；payload 保持不透明 std::byte）
    tbox::tsp::VehicleMessage msg;
    msg.envelope_bytes = std::vector<std::byte>{
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
    tbox::tsp::TransportOutcome outcome = tbox::tsp::TransportOutcome::Accepted;
    (void)outcome;
    tbox::tsp::ExchangeOptions options;
    options.timeout = std::chrono::milliseconds(2500);
    options.max_response_bytes = 16384;
    tbox::tsp::CallContext ctx;
    ctx.trace_id = "consumer-trace";
    ctx.request_id = "consumer-req";
    tbox::tsp::TransportResult<tbox::tsp::VehicleMessage> result;
    result.outcome = tbox::tsp::TransportOutcome::Unknown;
    (void)result;

    // facade 方法签名可解析（仅编译期；不连接 daemon）
    //  - exchangeVehicleMessage: 通用车云消息交换（阻塞至业务 RESPONSE/超时）
    //  - subscribeVehicleMessage: 按 service 订阅 EVENT Envelope
    using ExchangeFn = tbox::tsp::TransportResult<tbox::tsp::VehicleMessage> (
        tbox::tsp::TspClient::*)(
            const tbox::tsp::VehicleMessage&,
            const tbox::tsp::ExchangeOptions&,
            const tbox::tsp::CallContext&);
    ExchangeFn exchange_fn = &tbox::tsp::TspClient::exchangeVehicleMessage;
    using SubscribeFn = ::tbox::fw::ipc::Subscription (tbox::tsp::TspClient::*)(
        std::string_view, tbox::tsp::VehicleMessageHandler);
    SubscribeFn subscribe_fn = &tbox::tsp::TspClient::subscribeVehicleMessage;
    (void)exchange_fn;
    (void)subscribe_fn;

    std::printf("OK: tbox::tsp_client installed-package consumer compiles/links\n");
    return 0;
}
