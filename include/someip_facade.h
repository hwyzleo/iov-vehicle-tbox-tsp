// include/someip_facade.h
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace tbox {
namespace tsp {

// SOMEIP Facade —— 对 TBOX-SOMEIP 的 IPC 客户端接口
// SPEC §5.2: 作为 tsp_client 来源，承接 SOMEIP FOTA 中继门面
//
// 上行：TBOX-SOMEIP 经 IPC 将 snapshot 交 TSP（被动接收）
// 下行：TSP 经 IPC 将下行数据交 TBOX-SOMEIP（主动推送）
class SomeipFacade {
public:
    virtual ~SomeipFacade() = default;

    // 初始化（建立与 TBOX-SOMEIP 的 IPC 连接）
    virtual bool initialize() = 0;

    // 启动（注册为 tsp_client，开始接收上行调用）
    virtual bool start() = 0;

    // 停止
    virtual void stop() = 0;

    // 注册上行回调（SPEC §4.1）
    // 当 TBOX-SOMEIP 收到 reportSoftwareInventory(snapshot) 时
    // 通过此回调将 snapshot 交 TSP 处理
    virtual void on_report_software_inventory(
        std::function<void(const std::vector<uint8_t>& snapshot)> callback) = 0;

    // 推送下行命令（SPEC §4.2）
    // TSP 收到 down/fota 后，经此接口将数据交 TBOX-SOMEIP
    // TBOX-SOMEIP 以 onFotaCommand event 下发 CGW-FOTA
    virtual bool push_fota_command(const std::vector<uint8_t>& payload) = 0;

    // 检查 IPC 连接状态
    virtual bool is_connected() const = 0;
};

} // namespace tsp
} // namespace tbox
