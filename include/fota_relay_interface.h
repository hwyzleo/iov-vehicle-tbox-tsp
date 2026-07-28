// FOTA 中继业务接口 (CR-003 §2)
//
// TspIpcDispatcher 通过此接口调用 FOTA 业务（FotaHandler 实现），
// 使 dispatcher 可独立于业务实现进行单元测试。
// TSP 持有去重/节流/回执语义，framework-ipc 不下沉业务状态。

#pragma once

#include <string>
#include "tbox/tsp/types.h"

namespace tbox {
namespace tsp {

class FotaRelayInterface {
public:
    virtual ~FotaRelayInterface() = default;

    /// 上行：校验 envelope、去重/节流后经 mqtt_client publish (CR-003 §4)
    /// @return accepted 仅表示 TSP 已校验并由 MQTT daemon 接管，不等于 Broker PUBACK。
    virtual ReportResult handle_uplink(const FotaSnapshot& snapshot) = 0;

    /// 状态查询：accepted/published/acked/failed (CR-003 §2)
    virtual RelayStatus get_relay_status(const std::string& msg_id) = 0;
};

} // namespace tsp
} // namespace tbox
