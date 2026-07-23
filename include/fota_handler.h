// include/fota_handler.h
#pragma once

#include "mqtt_facade.h"
#include "someip_facade.h"
#include "error_codes.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <memory>

namespace tbox {
namespace tsp {

// FOTA 业务处理器
// SPEC §4.1: 上行 —— 去重/节流后经 TBOX-MQTT publish 到 up/fota
// SPEC §4.2: 下行 —— 解析后经 IPC 交 TBOX-SOMEIP
class FotaHandler {
public:
    FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                std::shared_ptr<SomeipFacade> someip);
    ~FotaHandler();

    // 初始化并注册回调
    bool initialize(const std::string& device_sn);

    // 启动（注册路由、订阅下行）
    bool start();

    // 停止
    void stop();

private:
    // 上行处理（SPEC §4.1）
    // 收到 TBOX-SOMEIP 的 reportSoftwareInventory(snapshot) 后调用
    ErrorCode handle_upstream(const std::vector<uint8_t>& snapshot);

    // 下行处理（SPEC §4.2）
    // 收到 TBOX-MQTT 的 down/fota 消息后调用
    ErrorCode handle_downstream(const std::string& topic,
                                const std::vector<uint8_t>& payload);

    // 去重检查
    bool is_duplicate(const std::string& snapshot_hash);

    // 节流检查
    bool is_throttled();

    // 计算 snapshot 哈希（用于去重）
    std::string compute_hash(const std::vector<uint8_t>& data);

    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SomeipFacade> someip_;
    std::string device_sn_;

    // 去重：snapshot_hash -> 最后上报时间
    std::unordered_map<std::string, uint64_t> dedup_map_;
    std::mutex dedup_mutex_;

    // 节流：上次上行发布时间
    uint64_t last_publish_time_ms_ = 0;
    std::mutex throttle_mutex_;

    bool started_ = false;
};

} // namespace tsp
} // namespace tbox
