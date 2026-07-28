// include/fota_handler.h
#pragma once

#include "mqtt_facade.h"
#include "fota_relay_interface.h"
#include "tsp_event_publisher.h"
#include "tbox/tsp/types.h"
#include "tbox/tsp/errors.h"

#ifdef HAS_FRAMEWORK_LOG
#include "log_adapter.h"
#endif

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <memory>

namespace tbox {
namespace tsp {

class TspEventPublisher;

// FOTA 业务中继处理器 (FotaRelay, CR-003 §2, §4)
// SPEC §4.1: 上行 -- snapshot_seq/msg_id 去重/节流后经 tbox::mqtt_client publish
// SPEC §4.2: 下行 -- 解析后经 TspEventPublisher 推送已订阅的 tsp_client
//
// accepted 仅表示 TSP 已校验并由 MQTT daemon 接管，不等于 Broker PUBACK (CR-003 §4)。
// 响应丢失时 outcome=unknown；复用相同 msg_id 重试时 TSP 返回已有状态而不重复上云。
class FotaHandler : public FotaRelayInterface {
public:
    FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                TspEventPublisher* event_publisher = nullptr);
    ~FotaHandler();

    // 初始化
    bool initialize(const std::string& device_sn);

    // 启动（注册路由、订阅下行）
    bool start();

    // 停止
    void stop();

    // 设置下行事件推送器（main 接线后调用）
    void set_event_publisher(TspEventPublisher* publisher);

    // ---- FotaRelayInterface ----
    // 上行：校验 envelope、去重/节流后经 mqtt_client publish (CR-003 §4)
    ReportResult handle_uplink(const FotaSnapshot& snapshot) override;

    // 状态查询 (CR-003 §2)
    RelayStatus get_relay_status(const std::string& msg_id) override;

private:
    // 下行处理（SPEC §4.2）：收到 TBOX-MQTT 的 down/fota 后调用
    void handle_downstream(const std::string& topic,
                           const std::vector<uint8_t>& payload);

    // 节流检查
    bool is_throttled();

    std::shared_ptr<MqttFacade> mqtt_;
    TspEventPublisher* event_publisher_ = nullptr;
    std::string device_sn_;

    // 中继状态：msg_id -> RelayStatus（同时作为去重表）
    std::unordered_map<std::string, RelayStatus> relay_status_map_;
    std::mutex relay_mutex_;

    // 节流：上次上行发布时间
    uint64_t last_publish_time_ms_ = 0;
    std::mutex throttle_mutex_;

    bool started_ = false;
};

} // namespace tsp
} // namespace tbox
