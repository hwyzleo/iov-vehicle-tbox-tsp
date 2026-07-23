// src/fota_handler.cpp
#include "fota_handler.h"
#include "constants.h"
#include "spdlog/spdlog.h"
#include "nlohmann/json.hpp"

#include <sstream>
#include <iomanip>
#include <functional>
#include <cstring>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#define TSP_USE_CC_SHA256
#elif __linux__
#include <openssl/sha.h>
#define TSP_USE_OSSL_SHA256
#endif

namespace tbox {
namespace tsp {

FotaHandler::FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                         std::shared_ptr<SomeipFacade> someip)
    : mqtt_(std::move(mqtt))
    , someip_(std::move(someip)) {}

FotaHandler::~FotaHandler() {
    stop();
}

bool FotaHandler::initialize(const std::string& device_sn) {
    if (device_sn.empty()) {
        spdlog::error("[FotaHandler] device_sn 为空");
        return false;
    }
    device_sn_ = device_sn;
    spdlog::info("[FotaHandler] 初始化: device_sn={}", device_sn_);

    // 注册上行回调：当 TBOX-SOMEIP 收到 reportSoftwareInventory 时
    someip_->on_report_software_inventory(
        [this](const std::vector<uint8_t>& snapshot) {
            ErrorCode result = handle_upstream(snapshot);
            if (result != ErrorCode::SUCCESS) {
                spdlog::warn("[FotaHandler] 上行处理失败: {}",
                             error_code_to_string(result));
            }
        });

    return true;
}

bool FotaHandler::start() {
    if (device_sn_.empty()) {
        spdlog::error("[FotaHandler] 未初始化");
        return false;
    }

    // 注册路由（SPEC §5.1）
    std::string up_topic = topics::fota_up(device_sn_);
    std::string down_topic = topics::fota_down(device_sn_);

    mqtt_->registerRoute("tsp_fota_up", up_topic, "up", FOTA_QOS);
    mqtt_->registerRoute("tsp_fota_down", down_topic, "down", FOTA_QOS);

    // 订阅下行（SPEC §4.2）
    mqtt_->subscribe(down_topic, FOTA_QOS,
        [this](const std::string& topic, const std::vector<uint8_t>& payload) {
            ErrorCode result = handle_downstream(topic, payload);
            if (result != ErrorCode::SUCCESS) {
                spdlog::warn("[FotaHandler] 下行处理失败: {}",
                             error_code_to_string(result));
            }
        });

    started_ = true;
    spdlog::info("[FotaHandler] 启动完成");
    return true;
}

void FotaHandler::stop() {
    started_ = false;
    spdlog::info("[FotaHandler] 停止");
}

ErrorCode FotaHandler::handle_upstream(const std::vector<uint8_t>& snapshot) {
    spdlog::info("[FotaHandler] 收到上行 snapshot: size={}", snapshot.size());

    // 去重检查（TBOX-TSP-1003）
    std::string hash = compute_hash(snapshot);
    if (is_duplicate(hash)) {
        spdlog::info("[FotaHandler] 去重命中，丢弃重复上报: hash={}", hash);
        return ErrorCode::DEDUP_HIT;
    }

    // 节流检查
    if (is_throttled()) {
        spdlog::info("[FotaHandler] 节流中，跳过本次上报");
        return ErrorCode::SUCCESS;  // 节流不算错误
    }

    // 发布到 up/fota（SPEC §4.1）
    std::string up_topic = topics::fota_up(device_sn_);
    bool ok = mqtt_->publish(up_topic, snapshot, FOTA_QOS);
    if (!ok) {
        spdlog::error("[FotaHandler] 上行发布失败: topic={}", up_topic);
        return ErrorCode::PUBLISH_FAILED;
    }

    // 更新去重和节流状态
    {
        std::lock_guard<std::mutex> lock(dedup_mutex_);
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        dedup_map_[hash] = static_cast<uint64_t>(now);

        // 清理过期条目
        for (auto it = dedup_map_.begin(); it != dedup_map_.end(); ) {
            if (static_cast<uint64_t>(now) - it->second > DEDUP_WINDOW_MS) {
                it = dedup_map_.erase(it);
            } else {
                ++it;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(throttle_mutex_);
        last_publish_time_ms_ = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    spdlog::info("[FotaHandler] 上行发布成功: topic={}", up_topic);
    return ErrorCode::SUCCESS;
}

ErrorCode FotaHandler::handle_downstream(const std::string& topic,
                                          const std::vector<uint8_t>& payload) {
    spdlog::info("[FotaHandler] 收到下行: topic={}, size={}", topic, payload.size());

    // 解析 payload（TBOX-TSP-1002）
    try {
        std::string payload_str(payload.begin(), payload.end());
        auto json = nlohmann::json::parse(payload_str);
        spdlog::debug("[FotaHandler] 下行 JSON 解析成功: {}", json.dump());
    } catch (const std::exception& e) {
        spdlog::error("[FotaHandler] 下行 payload 解析失败: {}", e.what());
        return ErrorCode::PAYLOAD_PARSE_FAILED;
    }

    // 经 IPC 交 TBOX-SOMEIP（SPEC §4.2）
    bool ok = someip_->push_fota_command(payload);
    if (!ok) {
        spdlog::error("[FotaHandler] 推送下行到 SOMEIP 失败");
        return ErrorCode::PUBLISH_FAILED;
    }

    spdlog::info("[FotaHandler] 下行转发成功");
    return ErrorCode::SUCCESS;
}

bool FotaHandler::is_duplicate(const std::string& snapshot_hash) {
    std::lock_guard<std::mutex> lock(dedup_mutex_);
    auto it = dedup_map_.find(snapshot_hash);
    if (it == dedup_map_.end()) {
        return false;
    }
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (static_cast<uint64_t>(now) - it->second) < DEDUP_WINDOW_MS;
}

bool FotaHandler::is_throttled() {
    std::lock_guard<std::mutex> lock(throttle_mutex_);
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (static_cast<uint64_t>(now) - last_publish_time_ms_) < THROTTLE_INTERVAL_MS;
}

std::string FotaHandler::compute_hash(const std::vector<uint8_t>& data) {
    unsigned char hash[32];

#if defined(TSP_USE_CC_SHA256)
    CC_SHA256(data.data(), static_cast<CC_LONG>(data.size()), hash);
#elif defined(TSP_USE_OSSL_SHA256)
    SHA256(data.data(), data.size(), hash);
#else
    // Fallback: 简单哈希（开发用）
    size_t h = 0;
    for (auto byte : data) {
        h = h * 31 + byte;
    }
    return std::to_string(h);
#endif

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

} // namespace tsp
} // namespace tbox
