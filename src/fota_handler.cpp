// src/fota_handler.cpp
#include "fota_handler.h"
#include "constants.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "spdlog/spdlog.h"
#include "nlohmann/json.hpp"
#include "log_adapter.h"
#include "log_types.h"

#include <sstream>
#include <iomanip>
#include <functional>
#include <cstring>

#include "utils.h"

namespace tbox {
namespace tsp {

namespace {

std::string b64_decode(const std::string& encoded) {
    return ::hwyz::Utils::base64_decode(encoded);
}

} // anonymous namespace

FotaHandler::FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                         TspEventPublisher* event_publisher)
    : mqtt_(std::move(mqtt))
    , event_publisher_(event_publisher) {}

FotaHandler::~FotaHandler() {
    stop();
}

bool FotaHandler::initialize(const std::string& device_sn) {
    if (device_sn.empty()) {
        LogAdapter::fota().error("tsp.fota.init.failed", "device_sn 为空");
        return false;
    }
    device_sn_ = device_sn;

    LogAdapter::fota().info("tsp.fota.initialized", "FOTA 处理器初始化完成", {
        {"device_sn", tbox::fw::log::FieldValue::makeString(device_sn_),
                      tbox::fw::log::Sensitivity::Identifier}
    });
    return true;
}

void FotaHandler::set_event_publisher(TspEventPublisher* publisher) {
    event_publisher_ = publisher;
}

bool FotaHandler::start() {
    if (device_sn_.empty()) {
        LogAdapter::fota().error("tsp.fota.start.failed", "未初始化");
        return false;
    }

    // 注册路由（SPEC §5.1, CR-003 §3）
    std::string up_topic = topics::fota_up(device_sn_);
    std::string down_topic = topics::fota_down(device_sn_);

    if (!mqtt_->registerRoute("tsp_fota_up", up_topic, "up", FOTA_QOS)) {
        LogAdapter::fota().error("tsp.fota.route.up_failed", "上行路由注册失败");
        return false;
    }
    if (!mqtt_->registerRoute("tsp_fota_down", down_topic, "down", FOTA_QOS)) {
        LogAdapter::fota().error("tsp.fota.route.down_failed", "下行路由注册失败");
        return false;
    }

    // 订阅下行（SPEC §4.2）
    mqtt_->subscribe(down_topic, FOTA_QOS,
        [this](const std::string& topic, const std::vector<uint8_t>& payload) {
            handle_downstream(topic, payload);
        });

    started_ = true;
    LogAdapter::fota().info("tsp.fota.started", "FOTA 处理器启动完成");
    return true;
}

void FotaHandler::stop() {
    started_ = false;
    LogAdapter::fota().info("tsp.fota.stopped", "FOTA 处理器停止");
}

ReportResult FotaHandler::handle_uplink(const FotaSnapshot& snapshot) {
    // 上下文传播 (SPEC §6.2)
    tbox::fw::log::LogContext ctx;
    ctx.request_id = snapshot.request_id.empty()
        ? ("req-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()))
        : snapshot.request_id;
    if (!snapshot.trace_id.empty()) ctx.trace_id = snapshot.trace_id;
    tbox::fw::log::ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.debug("tsp.fota.uplink.received", "收到软件版本快照", {
        {"snapshot_seq", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.snapshot_seq))},
        {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.payload.size()))}
    });

    ReportResult result;
    result.msg_id = snapshot.msg_id;

    // 幂等去重：相同 msg_id 已有状态则返回已有状态，不重复上云 (CR-003 §4)
    {
        std::lock_guard<std::mutex> lock(relay_mutex_);
        auto it = relay_status_map_.find(snapshot.msg_id);
        if (it != relay_status_map_.end() &&
            it->second.state != RelayState::UNKNOWN) {
            log.info("tsp.fota.snapshot.duplicate", "去重命中，返回已有状态", {
                {"snapshot_seq", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(snapshot.snapshot_seq))}
            });
            result.accepted = (it->second.state != RelayState::FAILED);
            result.outcome = PublishOutcome::ACCEPTED;
            result.error_code = static_cast<int32_t>(TspErrorCode::DEDUP_HIT);
            return result;
        }
    }

    // 节流检查
    if (is_throttled()) {
        log.info("tsp.fota.uplink.throttled", "节流中，跳过本次上报");
        result.accepted = true;  // 已接收，速率限制跳过
        result.outcome = PublishOutcome::ACCEPTED;
        result.error_code = static_cast<int32_t>(TspErrorCode::SUCCESS);
        return result;
    }

    // 发布到 up/fota（SPEC §4.1, CR-003 §4）
    auto publish_start = std::chrono::steady_clock::now();
    std::string up_topic = topics::fota_up(device_sn_);
    MqttPublishResult pr = mqtt_->publish(
        snapshot.msg_id, up_topic, snapshot.payload, FOTA_QOS,
        snapshot.content_type, snapshot.trace_id, snapshot.request_id);
    auto publish_end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        publish_end - publish_start).count();

    result.accepted = pr.accepted;
    result.outcome = pr.outcome;

    // 记录中继状态（同时作为去重表）
    RelayStatus status;
    status.msg_id = snapshot.msg_id;
    status.snapshot_seq = snapshot.snapshot_seq;
    if (pr.accepted) {
        status.state = RelayState::ACCEPTED;
        result.error_code = static_cast<int32_t>(TspErrorCode::SUCCESS);
        log.info("tsp.fota.uplink.published", "快照已提交 MQTT daemon（accepted≠PUBACK）", {
            {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
    } else {
        status.state = RelayState::FAILED;
        status.last_error = "mqtt publish failed";
        result.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        log.error("tsp.fota.uplink.publish_failed", "MQTT 发布失败或超时", {
            {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
    }

    // outcome=UNKNOWN 时不覆盖已有状态语义：记录为 ACCEPTED（已接管）但告知客户端未知
    {
        std::lock_guard<std::mutex> lock(relay_mutex_);
        relay_status_map_[snapshot.msg_id] = status;
    }

    // 更新节流时间
    {
        std::lock_guard<std::mutex> lock(throttle_mutex_);
        last_publish_time_ms_ = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    return result;
}

RelayStatus FotaHandler::get_relay_status(const std::string& msg_id) {
    std::lock_guard<std::mutex> lock(relay_mutex_);
    auto it = relay_status_map_.find(msg_id);
    if (it != relay_status_map_.end()) {
        return it->second;
    }
    RelayStatus s;
    s.msg_id = msg_id;
    s.state = RelayState::UNKNOWN;
    return s;
}

void FotaHandler::handle_downstream(const std::string& topic,
                                    const std::vector<uint8_t>& payload) {
    tbox::fw::log::LogContext ctx;
    ctx.request_id = "req-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    tbox::fw::log::ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.debug("tsp.fota.downlink.received", "收到 FOTA 下行", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)},
        {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))}
    });

    // 解析下行 payload（TBOX-TSP-1002）
    FotaCommand cmd;
    try {
        std::string payload_str(payload.begin(), payload.end());
        auto j = nlohmann::json::parse(payload_str);
        cmd.command_id     = j.value(ipc::field::COMMAND_ID, "");
        cmd.delivery_id    = j.value(ipc::field::DELIVERY_ID, "");
        cmd.schema_version = j.value(ipc::field::SCHEMA_VERSION, "");
        cmd.content_type   = j.value(ipc::field::CONTENT_TYPE, "application/x-protobuf");
        cmd.trace_id       = j.value(ipc::field::TRACE_ID, "");
        cmd.request_id     = j.value(ipc::field::REQUEST_ID, "");
        std::string b64 = j.value(ipc::field::PAYLOAD_B64, "");
        if (!b64.empty()) {
            std::string decoded = b64_decode(b64);
            cmd.payload.assign(decoded.begin(), decoded.end());
        }
    } catch (const std::exception& e) {
        log.warn("tsp.fota.downlink.parse_failed", "下行 payload 解析失败", {
            {"topic", tbox::fw::log::FieldValue::makeString(topic)},
            {"payload_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload.size()))}
        });
        return;
    }

    // 经 TspEventPublisher 推送已订阅的 tsp_client（SPEC §4.2, CR-003 §5）
    if (!event_publisher_) {
        log.warn("tsp.fota.downlink.no_publisher", "下行事件推送器未设置");
        return;
    }

    if (!event_publisher_->publish_fota_command(cmd)) {
        log.warn("tsp.fota.downlink.rejected", "下行命令被拒（队列满）", {
            {"command_id", tbox::fw::log::FieldValue::makeString(cmd.command_id)}
        });
        return;
    }

    log.info("tsp.fota.downlink.forwarded", "下行命令已投递事件推送器", {
        {"topic", tbox::fw::log::FieldValue::makeString(topic)}
    });
}

bool FotaHandler::is_throttled() {
    std::lock_guard<std::mutex> lock(throttle_mutex_);
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (static_cast<uint64_t>(now) - last_publish_time_ms_) < THROTTLE_INTERVAL_MS;
}

} // namespace tsp
} // namespace tbox
