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

#if TSP_MQTT_ROUTE_API
#include "hash.h"
#endif

namespace tbox {
namespace tsp {

namespace {

std::string b64_decode(const std::string& encoded) {
    return ::hwyz::Utils::base64_decode(encoded);
}

#if TSP_MQTT_ROUTE_API
// route_id 不可逆摘要（日志脱敏，CR-006 §13.9）
std::string route_id_hash(const std::string& route_id) {
    return tbox::fw::hash::sha256_hex(std::string_view(route_id));
}
#endif

} // anonymous namespace

FotaHandler::FotaHandler(std::shared_ptr<MqttFacade> mqtt,
                         TspEventPublisher* event_publisher)
    : mqtt_(std::move(mqtt))
    , event_publisher_(event_publisher) {}

FotaHandler::~FotaHandler() {
    stop();
}

bool FotaHandler::initialize(const std::string& device_sn) {
#if TSP_MQTT_ROUTE_API
    // CR-006: route 模式不缓存 UID，Topic 由 MQTT 按 PROV 身份展开
    (void)device_sn;
    LogAdapter::fota().info(
        "tsp.fota.initialized", "FOTA 处理器初始化完成 (route 模式)");
#else
    if (device_sn.empty()) {
        LogAdapter::fota().error("tsp.fota.init.failed", "device_sn 为空");
        return false;
    }
    device_sn_ = device_sn;
    LogAdapter::fota().info("tsp.fota.initialized", "FOTA 处理器初始化完成", {
        {"device_sn", tbox::fw::log::FieldValue::makeString(device_sn_),
                      tbox::fw::log::Sensitivity::Identifier}
    });
#endif
    return true;
}

void FotaHandler::set_event_publisher(TspEventPublisher* publisher) {
    event_publisher_ = publisher;
}

void FotaHandler::set_catalog(std::shared_ptr<SubscriptionCatalog> catalog) {
    catalog_ = std::move(catalog);
}

#if !TSP_MQTT_ROUTE_API
std::string FotaHandler::resolve_up_topic() const {
    if (catalog_) {
        for (const auto& it : catalog_->items()) {
            if (it.target == "tsp.fota" && it.direction == Direction::UP) {
                return expand_topic_template(it.topic_template, device_sn_);
            }
        }
    }
    return topics::fota_up(device_sn_);
}

std::string FotaHandler::resolve_down_topic() const {
    if (catalog_) {
        for (const auto& it : catalog_->items()) {
            if (it.target == "tsp.fota" && it.direction == Direction::DOWN) {
                return expand_topic_template(it.topic_template, device_sn_);
            }
        }
    }
    return topics::fota_down(device_sn_);
}
#endif

bool FotaHandler::start() {
#if TSP_MQTT_ROUTE_API
    // CR-006 §6: route 模式订阅 routed downlink，按 route_id/target 分发
    route_dispatcher_ = std::make_unique<DownlinkRouteDispatcher>();
    route_dispatcher_->register_handler("tsp", "fota.downlink", "tsp.fota",
        [this](const std::vector<uint8_t>& payload,
               const std::string& request_id,
               const std::string& trace_id) {
            handle_downstream(payload, request_id, trace_id);
        });

    // CR-006 §10.1: route 能力探测 -- subscribeRoutedDownlink 成功表示 MQTT 支持
    //   route 下行能力；失败时明确 DEGRADED，不静默双路径。
    if (mqtt_->subscribeRoutedDownlink("tsp",
            [this](const RoutedDownlinkEvent& event) {
                if (route_dispatcher_) {
                    bool matched = route_dispatcher_->dispatch(event);
                    route_metrics_.route_downlink_total++;
                    if (!matched) route_metrics_.route_downlink_unmatched_total++;
                }
            })) {
        {
            std::lock_guard<std::mutex> lock(route_status_mutex_);
            route_api_status_.route_api_supported = true;
            route_api_status_.downlink_route_state = "ACTIVE";
        }
        LogAdapter::fota().info(
            "tsp.route.api.supported",
            "MQTT route 能力探测成功，下行订阅已建立");
    } else {
        route_metrics_.route_api_incompatible++;
        {
            std::lock_guard<std::mutex> lock(route_status_mutex_);
            route_api_status_.route_api_supported = false;
            route_api_status_.downlink_route_state = "DEGRADED";
        }
        LogAdapter::fota().warn(
            "tsp.route.api.incompatible",
            "MQTT route 能力不可用（subscribeRoutedDownlink 失败），进入 DEGRADED", {
                {"route_api_supported", tbox::fw::log::FieldValue::makeString("false")},
                {"downlink_route_state", tbox::fw::log::FieldValue::makeString("DEGRADED")}
            });
    }
#else
    if (device_sn_.empty()) {
        LogAdapter::fota().error("tsp.fota.start.failed", "未初始化");
        return false;
    }

    // 路由映射由订阅快照注册器统一提交（CR-004 §11.5），
    // FotaHandler 仅订阅下行投递（legacy 迁移期保留 subscribe）。
    std::string down_topic = resolve_down_topic();
    mqtt_->subscribe(down_topic, FOTA_QOS,
        [this](const std::string& /*topic*/, const std::vector<uint8_t>& payload) {
            std::string request_id = "req-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count());
            handle_downstream(payload, request_id, "");
        });
#endif
    started_ = true;
    LogAdapter::fota().info("tsp.fota.started", "FOTA 处理器启动完成");
    return true;
}

void FotaHandler::stop() {
    started_ = false;
#if TSP_MQTT_ROUTE_API
    // route_dispatcher_ 析构清理；routed 订阅由 MqttClientAdapter::stop 取消
    route_dispatcher_.reset();
#endif
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

    // 发布 (SPEC §4.1, CR-003 §4)
    auto publish_start = std::chrono::steady_clock::now();
#if TSP_MQTT_ROUTE_API
    // CR-006 §5: 按 owner + route_id 发布，不传完整 Topic/UID
    MqttPublishResult pr = mqtt_->publishRoute(
        "tsp", "fota.uplink", snapshot.msg_id, snapshot.payload, FOTA_QOS,
        snapshot.content_type, snapshot.trace_id, snapshot.request_id);
    route_metrics_.route_publish_total++;
    if (!pr.accepted) {
        route_metrics_.route_publish_failure_total++;
    }
#else
    std::string up_topic = resolve_up_topic();
    MqttPublishResult pr = mqtt_->publish(
        snapshot.msg_id, up_topic, snapshot.payload, FOTA_QOS,
        snapshot.content_type, snapshot.trace_id, snapshot.request_id);
#endif
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
#if TSP_MQTT_ROUTE_API
        {
            std::lock_guard<std::mutex> lock(route_status_mutex_);
            route_api_status_.uplink_route_state = "ACTIVE";
        }
        log.info("tsp.fota.uplink.published", "快照已提交 MQTT daemon（accepted≠PUBACK）", {
            {"owner", tbox::fw::log::FieldValue::makeString("tsp")},
            {"route_id_hash", tbox::fw::log::FieldValue::makeString(route_id_hash("fota.uplink"))},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
#else
        log.info("tsp.fota.uplink.published", "快照已提交 MQTT daemon（accepted≠PUBACK）", {
            {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
#endif
    } else {
        status.state = RelayState::FAILED;
        status.last_error = "mqtt publish failed";
#if TSP_MQTT_ROUTE_API
        // CR-006 §9: daemon 显式拒绝 route publish -> TBOX-TSP-1007
        //   (route 不存在/未实例化/identity stale/模板错误)；
        //   outcome=UNKNOWN (传输失败/响应丢失) 仍为 TBOX-TSP-1001
        if (pr.outcome == PublishOutcome::UNKNOWN) {
            result.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
            {
                std::lock_guard<std::mutex> lock(route_status_mutex_);
                route_api_status_.uplink_route_state = "FAILED";
            }
        } else {
            result.error_code = static_cast<int32_t>(TspErrorCode::ROUTE_API_INCOMPATIBLE);
            route_metrics_.route_api_incompatible++;
            {
                std::lock_guard<std::mutex> lock(route_status_mutex_);
                route_api_status_.uplink_route_state = "DEGRADED";
            }
        }
        log.error("tsp.fota.uplink.publish_failed", "MQTT route 发布失败或超时", {
            {"owner", tbox::fw::log::FieldValue::makeString("tsp")},
            {"route_id_hash", tbox::fw::log::FieldValue::makeString(route_id_hash("fota.uplink"))},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)},
            {"error_code", tbox::fw::log::FieldValue::makeString(
                error_code_to_string(static_cast<TspErrorCode>(result.error_code)))}
        });
#else
        result.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        log.error("tsp.fota.uplink.publish_failed", "MQTT 发布失败或超时", {
            {"topic", tbox::fw::log::FieldValue::makeString(up_topic)},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
        });
#endif
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

#if TSP_MQTT_ROUTE_API
RouteApiStatus FotaHandler::getRouteApiStatus() const {
    std::lock_guard<std::mutex> lock(route_status_mutex_);
    return route_api_status_;
}

RouteMetricsSnapshot FotaHandler::getRouteMetrics() const {
    return route_metrics_.snapshot();
}
#endif

void FotaHandler::handle_downstream(const std::vector<uint8_t>& payload,
                                     const std::string& request_id,
                                     const std::string& trace_id) {
    tbox::fw::log::LogContext ctx;
    ctx.request_id = request_id.empty()
        ? ("req-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()))
        : request_id;
    if (!trace_id.empty()) ctx.trace_id = trace_id;
    tbox::fw::log::ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.debug("tsp.fota.downlink.received", "收到 FOTA 下行", {
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

    log.info("tsp.fota.downlink.forwarded", "下行命令已投递事件推送器");
}

bool FotaHandler::is_throttled() {
    std::lock_guard<std::mutex> lock(throttle_mutex_);
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (static_cast<uint64_t>(now) - last_publish_time_ms_) < THROTTLE_INTERVAL_MS;
}

} // namespace tsp
} // namespace tbox
