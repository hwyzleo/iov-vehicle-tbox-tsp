// src/fota_handler.cpp
#include "fota_handler.h"
#include "constants.h"
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
#ifdef HAS_FRAMEWORK_LOG
        LogAdapter::fota().error("tsp.fota.init.failed", "device_sn 为空");
#else
        LogAdapter::fota().error("tsp.fota.init.failed", "device_sn 为空");
#endif
        return false;
    }
    device_sn_ = device_sn;

#ifdef HAS_FRAMEWORK_LOG
    LogAdapter::fota().info("tsp.fota.initialized", "FOTA 处理器初始化完成", {
        {"device_sn", tbox::fw::log::FieldValue::makeString(device_sn_),
                      tbox::fw::log::Sensitivity::Identifier}
    });
#else
    LogAdapter::fota().info("tsp.fota.initialized", "FOTA 处理器初始化完成");
#endif

    // 注册上行回调：当 TBOX-SOMEIP 收到 reportSoftwareInventory 时
    someip_->on_report_software_inventory(
        [this](const std::vector<uint8_t>& snapshot) {
            ErrorCode result = handle_upstream(snapshot);
            if (result != ErrorCode::SUCCESS) {
#ifdef HAS_FRAMEWORK_LOG
                LogAdapter::fota().warn("tsp.fota.uplink.failed", "上行处理失败", {
                    {"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))}
                });
#else
                LogAdapter::fota().warn("tsp.fota.uplink.failed", "上行处理失败");
#endif
            }
        });

    return true;
}

bool FotaHandler::start() {
    if (device_sn_.empty()) {
#ifdef HAS_FRAMEWORK_LOG
        LogAdapter::fota().error("tsp.fota.start.failed", "未初始化");
#else
        LogAdapter::fota().error("tsp.fota.start.failed", "未初始化");
#endif
        return false;
    }

    // 注册路由（SPEC §5.1）
    std::string up_topic = topics::fota_up(device_sn_);
    std::string down_topic = topics::fota_down(device_sn_);

    // 路由注册事件日志
    auto route_log = LogAdapter::route();

    mqtt_->registerRoute("tsp_fota_up", up_topic, "up", FOTA_QOS);
    mqtt_->registerRoute("tsp_fota_down", down_topic, "down", FOTA_QOS);

    // 记录路由注册成功事件
    route_log.info("tsp.route.register.succeeded", "路由注册成功", {
        {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
        {"direction", tbox::fw::log::FieldValue::makeString("up")},
        {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)}
    });

    // 订阅下行（SPEC §4.2）
    mqtt_->subscribe(down_topic, FOTA_QOS,
        [this](const std::string& topic, const std::vector<uint8_t>& payload) {
            ErrorCode result = handle_downstream(topic, payload);
            if (result != ErrorCode::SUCCESS) {
#ifdef HAS_FRAMEWORK_LOG
                LogAdapter::fota().warn("tsp.fota.downlink.failed", "下行处理失败", {
                    {"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))}
                });
#else
                LogAdapter::fota().warn("tsp.fota.downlink.failed", "下行处理失败");
#endif
            }
        });

    started_ = true;
#ifdef HAS_FRAMEWORK_LOG
    LogAdapter::fota().info("tsp.fota.started", "FOTA 处理器启动完成");
#else
    LogAdapter::fota().info("tsp.fota.started", "FOTA 处理器启动完成");
#endif
    return true;
}

void FotaHandler::stop() {
    started_ = false;
#ifdef HAS_FRAMEWORK_LOG
    LogAdapter::fota().info("tsp.fota.stopped", "FOTA 处理器停止");
#else
    LogAdapter::fota().info("tsp.fota.stopped", "FOTA 处理器停止");
#endif
}

ErrorCode FotaHandler::handle_upstream(const std::vector<uint8_t>& snapshot) {
    // 生成 request_id 用于上下文传播
    std::string request_id = "req-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());

#ifdef HAS_FRAMEWORK_LOG
    // 创建上下文作用域
    tbox::fw::log::LogContext ctx;
    ctx.request_id = request_id;
    tbox::fw::log::ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.debug("tsp.fota.uplink.received", "收到软件版本快照", {
        {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.size()))}
    });
#else
    LogAdapter::fota().debug("tsp.fota.uplink.received", "收到软件版本快照");
#endif

    // 去重检查（TBOX-TSP-1003）
    std::string hash = compute_hash(snapshot);
    if (is_duplicate(hash)) {
#ifdef HAS_FRAMEWORK_LOG
        log.info("tsp.fota.snapshot.duplicate", "去重命中，丢弃重复上报", {
            {"dedup_key", tbox::fw::log::FieldValue::makeString(hash),
                          tbox::fw::log::Sensitivity::Identifier}
        });
#else
        LogAdapter::fota().info("tsp.fota.snapshot.duplicate", "去重命中，丢弃重复上报");
#endif
        return ErrorCode::DEDUP_HIT;
    }

    // 节流检查
    if (is_throttled()) {
#ifdef HAS_FRAMEWORK_LOG
        log.info("tsp.fota.uplink.throttled", "节流中，跳过本次上报");
#else
        LogAdapter::fota().info("tsp.fota.uplink.throttled", "节流中，跳过本次上报");
#endif
        return ErrorCode::SUCCESS;
    }

    // 发布到 up/fota（SPEC §4.1）
    auto publish_start = std::chrono::steady_clock::now();
    std::string up_topic = topics::fota_up(device_sn_);
    bool ok = mqtt_->publish(up_topic, snapshot, FOTA_QOS);
    auto publish_end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(publish_end - publish_start).count();

    if (!ok) {
#ifdef HAS_FRAMEWORK_LOG
        log.error("tsp.fota.uplink.publish_failed", "MQTT 发布失败或超时", {
            {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
#else
        LogAdapter::fota().error("tsp.fota.uplink.publish_failed", "MQTT 发布失败或超时");
#endif
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

#ifdef HAS_FRAMEWORK_LOG
    log.info("tsp.fota.uplink.published", "快照发布成功", {
        {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
        {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
        {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
    });
#else
    LogAdapter::fota().info("tsp.fota.uplink.published", "快照发布成功");
#endif
    return ErrorCode::SUCCESS;
}

ErrorCode FotaHandler::handle_downstream(const std::string& topic,
                                          const std::vector<uint8_t>& payload) {
#ifdef HAS_FRAMEWORK_LOG
    // 生成 request_id
    std::string request_id = "req-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());

    tbox::fw::log::LogContext ctx;
    ctx.request_id = request_id;
    tbox::fw::log::ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.debug("tsp.fota.downlink.received", "收到 FOTA 下行", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))}
    });
#else
    LogAdapter::fota().debug("tsp.fota.downlink.received", "收到 FOTA 下行");
#endif

    // 解析 payload（TBOX-TSP-1002）
    try {
        std::string payload_str(payload.begin(), payload.end());
        auto json = nlohmann::json::parse(payload_str);
#ifdef HAS_FRAMEWORK_LOG
        log.debug("tsp.fota.downlink.parsed", "下行 JSON 解析成功");
#else
        LogAdapter::fota().debug("tsp.fota.downlink.parsed", "下行 JSON 解析成功");
#endif
    } catch (const std::exception& e) {
#ifdef HAS_FRAMEWORK_LOG
        log.warn("tsp.fota.downlink.parse_failed", "下行 payload 解析失败", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))},
            {"error_code", tbox::fw::log::FieldValue::makeInt(1002)}
        });
#else
        LogAdapter::fota().warn("tsp.fota.downlink.parse_failed", "下行 payload 解析失败");
#endif
        return ErrorCode::PAYLOAD_PARSE_FAILED;
    }

    // 经 IPC 交 TBOX-SOMEIP（SPEC §4.2）
    auto forward_start = std::chrono::steady_clock::now();
    bool ok = someip_->push_fota_command(payload);
    auto forward_end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(forward_end - forward_start).count();

    if (!ok) {
#ifdef HAS_FRAMEWORK_LOG
        log.error("tsp.fota.downlink.forward_failed", "推送下行到 SOMEIP 失败", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
#else
        LogAdapter::fota().error("tsp.fota.downlink.forward_failed", "推送下行到 SOMEIP 失败");
#endif
        return ErrorCode::PUBLISH_FAILED;
    }

#ifdef HAS_FRAMEWORK_LOG
    log.info("tsp.fota.downlink.forwarded", "下行成功转交 SOME/IP 门面", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
    });
#else
    LogAdapter::fota().info("tsp.fota.downlink.forwarded", "下行成功转交 SOME/IP 门面");
#endif
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
