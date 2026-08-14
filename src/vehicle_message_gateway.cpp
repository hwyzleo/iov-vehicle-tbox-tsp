// TBOX-TSP-DSN-CR-009 §16: VehicleMessageGateway 实现。

#include "vehicle_message_gateway.h"

#include "downlink_route_dispatcher.h"
#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "log_adapter.h"
#include "hash.h"
#include "constants.h"

#include "vehicle/common/v1/envelope.pb.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <regex>

namespace tbox {
namespace tsp {

namespace {

// route_id 不可逆摘要（日志脱敏，CR-006 §13.9）
std::string route_id_hash(const std::string& route_id) {
    return tbox::fw::hash::sha256_hex(std::string_view(route_id));
}

// 从 Envelope bytes（uint8_t 视图）构造 protobuf 输入
std::string bytes_to_string(const std::vector<std::byte>& bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (auto b : bytes) {
        out.push_back(static_cast<char>(static_cast<uint8_t>(b)));
    }
    return out;
}

std::vector<std::byte> string_to_bytes(const std::string& s) {
    std::vector<std::byte> out(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(static_cast<uint8_t>(s[i]));
    }
    return out;
}

// 从 protocol_version 字符串提取 major（允许 "1" / "1.0" / "fota-v1" 等；
// 取首个十进制前缀）。空或无法解析视为 major 缺失。
bool parse_protocol_major(const std::string& version, uint32_t& major) {
    if (version.empty()) return false;
    size_t i = 0;
    while (i < version.size() && std::isdigit(static_cast<unsigned char>(version[i]))) {
        ++i;
    }
    if (i == 0) return false;
    try {
        major = static_cast<uint32_t>(std::stoul(version.substr(0, i)));
        return true;
    } catch (...) {
        return false;
    }
}

// payload_type 能力目录：vehicle.fota.v1.<MessageName> fully-qualified name。
// TSP 只做 FQN 格式/能力门槛校验，不解释具体 FOTA 消息（US-012）。
bool payload_type_in_capability(const std::string& service,
                                const std::string& payload_type) {
    const std::string prefix = service + ".v1.";
    if (payload_type.size() <= prefix.size()) return false;
    if (payload_type.compare(0, prefix.size(), prefix) != 0) return false;
    const std::string name = payload_type.substr(prefix.size());
    static const std::regex kName("^[A-Za-z_][A-Za-z0-9_]*$");
    return std::regex_match(name, kName);
}

} // anonymous namespace

// ============================================================
// 校验结果
// ============================================================
struct VehicleMessageGateway::EnvelopeValidation {
    bool ok = false;
    TransportOutcome outcome = TransportOutcome::ProtocolError;
    std::string reason;
    std::string service;
    std::string payload_type;
    vehicle::common::v1::MessageKind message_kind =
        vehicle::common::v1::MESSAGE_KIND_UNSPECIFIED;
    std::string message_id;
    std::string correlation_id;
    uint32_t protocol_major = 0;
    uint32_t payload_size = 0;
    bool expired = false;
};

// ============================================================
// Correlation entry（引用计数，exchange 线程与 sweeper/downlink 安全共享）
// ============================================================
struct VehicleMessageGateway::CorrelationEntry {
    std::string message_id;
    std::string service;
    std::chrono::steady_clock::time_point deadline;
    std::size_t max_response_bytes = 16384;
    bool mqtt_accepted = false;

    TransportOutcome outcome = TransportOutcome::Unknown;
    std::vector<std::byte> response_bytes;
    bool terminal = false;
    std::chrono::steady_clock::time_point completed_at;

    std::mutex mutex;
    std::condition_variable cv;
};

VehicleMessageGateway::VehicleMessageGateway(std::shared_ptr<MqttFacade> mqtt)
    : mqtt_(std::move(mqtt)) {}

VehicleMessageGateway::~VehicleMessageGateway() {
    stop();
}

bool VehicleMessageGateway::initialize(const VehicleMessageGatewayConfig& config) {
    if (!mqtt_) {
        LogAdapter::relay().error(
            "tsp.vehicle_message.init_failed", "MqttFacade 未注入");
        return false;
    }
    config_ = config;
    if (config_.limits.allowed_services.empty() ||
        config_.default_exchange_timeout_ms == 0) {
        LogAdapter::relay().error(
            "tsp.vehicle_message.init_failed", "vehicle_message 配置非法");
        return false;
    }
    return true;
}

bool VehicleMessageGateway::start() {
    if (running_.exchange(true)) {
        return true;
    }
    stopping_.store(false, std::memory_order_release);

    // CR-006 §6.2: 只接受 owner=tsp + route_id=fota.downlink + target=tsp.fota
    route_dispatcher_ = std::make_unique<DownlinkRouteDispatcher>();
    route_dispatcher_->register_handler(
        "tsp", "fota.downlink", "tsp.fota",
        [this](const RoutedDownlinkEvent& event) {
            handle_routed_downlink(event);
        });

    if (!mqtt_->subscribeRoutedDownlink("tsp",
            [this](const RoutedDownlinkEvent& event) {
                if (route_dispatcher_) {
                    route_dispatcher_->dispatch(event);
                }
            })) {
        LogAdapter::relay().warn(
            "tsp.vehicle_message.route_incompatible",
            "MQTT route 下行能力不可用，进入 DEGRADED", {
                {"route_id_hash",
                 tbox::fw::log::FieldValue::makeString(route_id_hash("fota.downlink"))}
            });
    }

    // correlation 超时收敛 worker（worker_count 个 shard）
    const uint32_t workers = std::max<uint32_t>(1, config_.worker_count);
    for (uint32_t i = 0; i < workers; ++i) {
        workers_.emplace_back([this, i, workers] { sweeper_loop(i, workers); });
    }

    LogAdapter::relay().info(
        "tsp.vehicle_message.started", "VehicleMessageGateway 启动", {
            {"worker_count", tbox::fw::log::FieldValue::makeInt(
                static_cast<int64_t>(workers))}
        });
    return true;
}

void VehicleMessageGateway::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    stopping_.store(true, std::memory_order_release);

    // 将 in-flight 收敛为 Stopping（设计 §生命周期停止）
    {
        std::lock_guard<std::mutex> lock(table_mutex_);
        for (auto& kv : table_) {
            auto& e = kv.second;
            std::lock_guard<std::mutex> elock(e->mutex);
            if (!e->terminal) {
                e->outcome = TransportOutcome::Stopping;
                e->terminal = true;
                e->completed_at = std::chrono::steady_clock::now();
                e->cv.notify_all();
            }
        }
    }

    // join worker
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();

    route_dispatcher_.reset();
    {
        std::lock_guard<std::mutex> lock(table_mutex_);
        table_.clear();
        recent_terminal_.clear();
    }
    LogAdapter::relay().info(
        "tsp.vehicle_message.stopped", "VehicleMessageGateway 停止");
}

// ============================================================
// Envelope 校验管线（CR-009 §Envelope）
// ============================================================
VehicleMessageGateway::EnvelopeValidation
VehicleMessageGateway::validate_envelope(const std::vector<std::byte>& bytes,
                                         bool expect_request) const {
    EnvelopeValidation v;
    const size_t total_len = bytes.size();

    if (total_len == 0) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "empty_envelope";
        return v;
    }
    if (total_len > config_.limits.max_envelope_bytes) {
        v.outcome = TransportOutcome::PayloadTooLarge;
        v.reason = "envelope_exceeds_max_bytes";
        return v;
    }

    vehicle::common::v1::VehicleMessageEnvelope env;
    const std::string raw = bytes_to_string(bytes);
    if (!env.ParseFromString(raw)) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "envelope_parse_failed";
        return v;
    }

    // protocol major
    if (!parse_protocol_major(env.protocol_version(), v.protocol_major)) {
        v.outcome = TransportOutcome::VersionMismatch;
        v.reason = "protocol_major_missing";
        return v;
    }
    const auto& majors = config_.limits.allowed_protocol_majors;
    if (std::find(majors.begin(), majors.end(), v.protocol_major) == majors.end()) {
        v.outcome = TransportOutcome::VersionMismatch;
        v.reason = "protocol_major_unsupported";
        return v;
    }

    // message kind / 方向
    v.message_kind = env.message_kind();
    if (v.message_kind == vehicle::common::v1::MESSAGE_KIND_UNSPECIFIED) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "message_kind_unspecified";
        return v;
    }
    if (expect_request && v.message_kind != vehicle::common::v1::MESSAGE_KIND_REQUEST) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "expected_request";
        return v;
    }
    if (!expect_request && v.message_kind == vehicle::common::v1::MESSAGE_KIND_REQUEST) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "illegal_downlink_request";
        return v;
    }

    // service allowlist
    v.service = env.service();
    const auto& services = config_.limits.allowed_services;
    if (std::find(services.begin(), services.end(), v.service) == services.end()) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "service_not_allowed";
        return v;
    }

    // payload_type 能力目录（FQN 格式门槛）
    v.payload_type = env.payload_type();
    if (!payload_type_in_capability(v.service, v.payload_type)) {
        v.outcome = TransportOutcome::VersionMismatch;
        v.reason = "payload_type_not_supported";
        return v;
    }

    // payload 大小
    v.payload_size = static_cast<uint32_t>(env.payload().size());
    if (v.payload_size > config_.limits.max_payload_bytes) {
        v.outcome = TransportOutcome::PayloadTooLarge;
        v.reason = "payload_exceeds_max_bytes";
        return v;
    }

    // TTL
    if (env.has_expire_at_ms() && env.expire_at_ms() > 0) {
        const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now_ms >= env.expire_at_ms()) {
            v.expired = true;
            v.outcome = TransportOutcome::Rejected;
            v.reason = "ttl_expired";
            return v;
        }
    }

    // message_id（REQUEST/RESPONSE 关联必需；EVENT 也应携带）
    v.message_id = env.message_id();
    if (v.message_id.empty()) {
        v.outcome = TransportOutcome::ProtocolError;
        v.reason = "message_id_missing";
        return v;
    }
    if (v.message_kind == vehicle::common::v1::MESSAGE_KIND_RESPONSE) {
        v.correlation_id = env.correlation_id().empty()
            ? "" : env.correlation_id();
        if (v.correlation_id.empty()) {
            v.outcome = TransportOutcome::ProtocolError;
            v.reason = "correlation_id_missing";
            return v;
        }
    }

    v.ok = true;
    return v;
}

// ============================================================
// 上行：通用交换（阻塞至业务 RESPONSE/deadline）
// ============================================================
TransportResult<VehicleMessage> VehicleMessageGateway::exchange(
    const VehicleMessage& request,
    const ExchangeOptions& options,
    const CallContext& ctx) {
    if (stopping_.load(std::memory_order_acquire)) {
        TransportResult<VehicleMessage> r;
        r.outcome = TransportOutcome::Stopping;
        r.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        r.error = "stopping";
        return r;
    }

    const auto v = validate_envelope(request.envelope_bytes, /*expect_request=*/true);
    if (!v.ok) {
        counters_.envelope_invalid++;
        LogAdapter::relay().warn(
            "tsp.vehicle_message.envelope.invalid", "上行 Envelope 校验失败", {
                {"service", tbox::fw::log::FieldValue::makeString(v.service)},
                {"reason", tbox::fw::log::FieldValue::makeString(v.reason)}
            });
        TransportResult<VehicleMessage> r;
        r.outcome = v.outcome;
        r.error = v.reason;
        return r;
    }

    counters_.request_total++;

    // 计算 deadline：取调用方 timeout 与默认上限的最小值
    auto timeout = options.timeout.count() > 0 ? options.timeout
        : std::chrono::milliseconds(config_.default_exchange_timeout_ms);
    auto bounded = std::min(timeout,
        std::chrono::milliseconds(config_.default_exchange_timeout_ms));
    auto deadline = std::chrono::steady_clock::now() + bounded;

    auto entry = std::make_shared<CorrelationEntry>();
    entry->message_id = v.message_id;
    entry->service = v.service;
    entry->deadline = deadline;
    entry->max_response_bytes = options.max_response_bytes > 0
        ? options.max_response_bytes : config_.limits.max_envelope_bytes;

    // 在 publish 前建立有界 correlation（US-014）
    {
        std::lock_guard<std::mutex> lock(table_mutex_);
        if (table_.size() >= config_.max_in_flight) {
            TransportResult<VehicleMessage> r;
            r.outcome = TransportOutcome::Rejected;
            r.error_code = static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
            r.error = "max_in_flight";
            return r;
        }
        // 身份冲突：同 message_id 仍在活跃或终止保护窗口内，拒绝复用（迟到响应保护）
        if (table_.count(v.message_id) ||
            recent_terminal_.count(v.message_id)) {
            counters_.response_rejected++;
            LogAdapter::relay().warn(
                "tsp.vehicle_message.message_identity_conflict",
                "message_id 身份冲突，拒绝复用", {
                    {"message_id_hash", tbox::fw::log::FieldValue::makeString(
                        tbox::fw::hash::sha256_hex(v.message_id))}
                });
            TransportResult<VehicleMessage> r;
            r.outcome = TransportOutcome::ProtocolError;
            r.error_code = static_cast<int32_t>(TspErrorCode::RESPONSE_CONFLICT);
            r.error = "message_identity_conflict";
            return r;
        }
        table_[v.message_id] = entry;
    }

    // 发布：local accepted 仅更新投递阶段，不完成业务 exchange (US-014)
    auto serialized = bytes_to_string(request.envelope_bytes);
    std::vector<uint8_t> payload(serialized.begin(), serialized.end());
    MqttPublishResult pr = mqtt_->publishRoute(
        "tsp", "fota.uplink", v.message_id, payload, FOTA_QOS,
        "application/x-protobuf", ctx.trace_id, ctx.request_id);
    counters_.request_published++;

    if (!pr.accepted) {
        bool unknown = (pr.outcome == MqttDeliveryOutcome::Unknown);
        {
            std::lock_guard<std::mutex> lock(table_mutex_);
            table_.erase(v.message_id);
        }
        TransportResult<VehicleMessage> r;
        r.outcome = unknown ? TransportOutcome::Unknown
                            : TransportOutcome::Rejected;
        r.error_code = static_cast<int32_t>(
            unknown ? TspErrorCode::UNKNOWN_OUTCOME : TspErrorCode::PUBLISH_FAILED);
        r.error = unknown ? "publish_outcome_unknown" : "mqtt_local_rejected";
        LogAdapter::relay().error(
            "tsp.vehicle_message.uplink.publish_failed", "MQTT route 发布失败", {
                {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                    route_id_hash("fota.uplink"))},
                {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
                {"outcome", tbox::fw::log::FieldValue::makeString(
                    unknown ? "unknown" : "rejected")}
            });
        return r;
    }
    {
        std::lock_guard<std::mutex> lock(entry->mutex);
        entry->mqtt_accepted = true;
    }

    LogAdapter::relay().debug(
        "tsp.vehicle_message.uplink.published",
        "Envelope 已提交 MQTT daemon（accepted≠PUBACK），等待业务 RESPONSE", {
            {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                route_id_hash("fota.uplink"))},
            {"qos", tbox::fw::log::FieldValue::makeInt(FOTA_QOS)},
            {"service", tbox::fw::log::FieldValue::makeString(v.service)},
            {"payload_type", tbox::fw::log::FieldValue::makeString(v.payload_type)}
        });

    // 阻塞等待业务 RESPONSE 或 deadline（异步 RESPONSE correlation 完成同步 exchange）
    TransportOutcome outcome;
    std::vector<std::byte> response_bytes;
    bool mqtt_accepted;
    {
        std::unique_lock<std::mutex> lk(entry->mutex);
        entry->cv.wait_until(lk, deadline, [&] { return entry->terminal; });
        if (!entry->terminal) {
            // 超时：按是否已被 MQTT 接受分类（CR-009 §错误与重试）
            entry->outcome = entry->mqtt_accepted
                ? TransportOutcome::Timeout : TransportOutcome::Unknown;
            entry->terminal = true;
            entry->completed_at = std::chrono::steady_clock::now();
            counters_.exchange_timeout++;
            entry->cv.notify_all();
        }
        outcome = entry->outcome;
        response_bytes = entry->response_bytes;
        mqtt_accepted = entry->mqtt_accepted;
    }

    // 移除 active 项并进入终止保护窗口（迟到响应不完成复用 message_id 的新请求）
    {
        std::lock_guard<std::mutex> lock(table_mutex_);
        table_.erase(v.message_id);
        auto window = std::max(
            std::chrono::milliseconds(2 * config_.default_exchange_timeout_ms),
            std::chrono::milliseconds(5000));
        recent_terminal_[v.message_id] = std::chrono::steady_clock::now() + window;
    }

    if (outcome == TransportOutcome::Accepted) {
        counters_.response_completed++;
        LogAdapter::relay().info(
            "tsp.vehicle_message.response.completed",
            "业务 RESPONSE 已关联并完成 exchange", {
                {"service", tbox::fw::log::FieldValue::makeString(v.service)},
                {"payload_size", tbox::fw::log::FieldValue::makeInt(
                    static_cast<int64_t>(response_bytes.size()))}
            });
    }

    TransportResult<VehicleMessage> r;
    r.outcome = outcome;
    if (outcome == TransportOutcome::Accepted && !response_bytes.empty()) {
        VehicleMessage resp;
        resp.envelope_bytes = std::move(response_bytes);
        r.value = std::move(resp);
    } else {
        r.error_code = (outcome == TransportOutcome::Unknown)
            ? static_cast<int32_t>(TspErrorCode::UNKNOWN_OUTCOME)
            : (outcome == TransportOutcome::Timeout)
                ? static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED)
                : (outcome == TransportOutcome::PayloadTooLarge)
                    ? static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE)
                    : 0;
        r.error = (outcome == TransportOutcome::Timeout) ? "business_response_timeout"
                 : (outcome == TransportOutcome::Unknown) ? "business_response_unknown"
                 : (outcome == TransportOutcome::PayloadTooLarge) ? "response_too_large"
                 : (outcome == TransportOutcome::Stopping) ? "stopping" : "";
        (void)mqtt_accepted;
    }
    return r;
}

// ============================================================
// 下行：RESPONSE -> correlation；EVENT -> 订阅队列（CR-009 §EVENT 下行）
// ============================================================
void VehicleMessageGateway::handle_routed_downlink(const RoutedDownlinkEvent& event) {
    if (stopping_.load(std::memory_order_acquire)) {
        return;
    }

    // 路由校验（DownlinkRouteDispatcher 已按 owner/route_id/target 匹配；防御式复核）
    if (event.owner != "tsp" || event.route_id != "fota.downlink" ||
        event.target != "tsp.fota") {
        LogAdapter::relay().warn(
            "tsp.vehicle_message.downlink.invalid", "未知 route/target，拒绝下行", {
                {"owner", tbox::fw::log::FieldValue::makeString(event.owner)},
                {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                    route_id_hash(event.route_id))},
                {"target", tbox::fw::log::FieldValue::makeString(event.target)}
            });
        counters_.envelope_invalid++;
        return;
    }

    // 解码 Envelope（payload 不透明）
    std::vector<std::byte> env_bytes(event.payload.size());
    for (size_t i = 0; i < event.payload.size(); ++i) {
        env_bytes[i] = static_cast<std::byte>(event.payload[i]);
    }
    const auto v = validate_envelope(env_bytes, /*expect_request=*/false);
    if (!v.ok) {
        counters_.envelope_invalid++;
        LogAdapter::relay().warn(
            "tsp.vehicle_message.envelope.invalid", "下行 Envelope 校验失败", {
                {"route_id_hash", tbox::fw::log::FieldValue::makeString(
                    route_id_hash(event.route_id))},
                {"service", tbox::fw::log::FieldValue::makeString(v.service)},
                {"reason", tbox::fw::log::FieldValue::makeString(v.reason)}
            });
        return;
    }

    switch (v.message_kind) {
        case vehicle::common::v1::MESSAGE_KIND_RESPONSE: {
            // RESPONSE 必须以 correlation_id 唯一匹配请求（US-014）
            std::shared_ptr<CorrelationEntry> entry;
            {
                std::lock_guard<std::mutex> lock(table_mutex_);
                auto it = table_.find(v.correlation_id);
                if (it != table_.end()) {
                    entry = it->second;
                }
            }

            if (!entry) {
                // 未知/迟到/终止后的响应：只记录摘要，不完成复用 message_id 的新请求
                counters_.response_rejected++;
                LogAdapter::relay().info(
                    "tsp.vehicle_message.response.duplicate",
                    "未知/迟到/重复 RESPONSE，拒绝完成", {
                        {"correlation_id_hash", tbox::fw::log::FieldValue::makeString(
                            tbox::fw::hash::sha256_hex(v.correlation_id))},
                        {"error_code", tbox::fw::log::FieldValue::makeString(
                            error_code_to_string(TspErrorCode::RESPONSE_CONFLICT))}
                    });
                return;
            }

            std::lock_guard<std::mutex> elock(entry->mutex);
            if (entry->terminal) {
                // 同一请求重复 RESPONSE：仅第一次完成
                counters_.response_rejected++;
                LogAdapter::relay().info(
                    "tsp.vehicle_message.response.duplicate",
                    "重复 RESPONSE，仅首次完成", {
                        {"message_id_hash", tbox::fw::log::FieldValue::makeString(
                            tbox::fw::hash::sha256_hex(entry->message_id))}
                    });
                return;
            }
            if (entry->service != v.service) {
                counters_.response_rejected++;
                LogAdapter::relay().warn(
                    "tsp.vehicle_message.response.mismatch",
                    "RESPONSE service 与请求不匹配，拒绝", {
                        {"expected", tbox::fw::log::FieldValue::makeString(entry->service)},
                        {"actual", tbox::fw::log::FieldValue::makeString(v.service)}
                    });
                return;
            }
            if (v.expired) {
                counters_.response_rejected++;
                LogAdapter::relay().warn(
                    "tsp.vehicle_message.response.expired",
                    "RESPONSE 已过期，拒绝", {
                        {"message_id_hash", tbox::fw::log::FieldValue::makeString(
                            tbox::fw::hash::sha256_hex(entry->message_id))}
                    });
                return;
            }
            if (env_bytes.size() > entry->max_response_bytes) {
                // 业务 RESPONSE 超出调用方上限：以 PayloadTooLarge 完成，不截断/不落盘
                counters_.response_rejected++;
                LogAdapter::relay().warn(
                    "tsp.vehicle_message.response.oversize",
                    "RESPONSE 超出 max_response_bytes，以 PayloadTooLarge 完成", {
                        {"message_id_hash", tbox::fw::log::FieldValue::makeString(
                            tbox::fw::hash::sha256_hex(entry->message_id))},
                        {"response_size", tbox::fw::log::FieldValue::makeInt(
                            static_cast<int64_t>(env_bytes.size()))},
                        {"max_response_bytes", tbox::fw::log::FieldValue::makeInt(
                            static_cast<int64_t>(entry->max_response_bytes))}
                    });
                entry->outcome = TransportOutcome::PayloadTooLarge;
                entry->terminal = true;
                entry->completed_at = std::chrono::steady_clock::now();
                entry->cv.notify_all();
                return;
            }

            entry->outcome = TransportOutcome::Accepted;
            entry->response_bytes = std::move(env_bytes);
            entry->terminal = true;
            entry->completed_at = std::chrono::steady_clock::now();
            entry->cv.notify_all();
            return;
        }

        case vehicle::common::v1::MESSAGE_KIND_EVENT: {
            // EVENT 进入对应 service 的下行订阅队列，不误完成请求 (US-014)
            if (!event_publisher_) {
                counters_.event_dropped++;
                LogAdapter::relay().warn(
                    "tsp.vehicle_message.event.no_publisher",
                    "EVENT 下行推送器未设置");
                return;
            }
            if (!event_publisher_->publish_vehicle_message(
                    v.service, env_bytes, event.trace_id, event.request_id)) {
                counters_.event_dropped++;
                LogAdapter::relay().warn(
                    "tsp.vehicle_message.event.dropped",
                    "EVENT 下行队列满，有界丢弃", {
                        {"service", tbox::fw::log::FieldValue::makeString(v.service)},
                        {"payload_size", tbox::fw::log::FieldValue::makeInt(
                            static_cast<int64_t>(env_bytes.size()))}
                    });
                return;
            }
            counters_.event_forwarded++;
            return;
        }

        default:
            // UNSPECIFIED / 非法 REQUEST 下行：拒绝，不落入 EVENT 默认路径
            counters_.envelope_invalid++;
            LogAdapter::relay().warn(
                "tsp.vehicle_message.downlink.invalid",
                "非法 message_kind 下行，拒绝", {
                    {"kind", tbox::fw::log::FieldValue::makeInt(
                        static_cast<int64_t>(v.message_kind))}
                });
            return;
    }
}

void VehicleMessageGateway::set_event_publisher(TspEventPublisher* publisher) {
    event_publisher_ = publisher;
}

VehicleMessageGateway::TransportCountersSnapshot VehicleMessageGateway::counters() const {
    TransportCountersSnapshot s;
    s.request_total = counters_.request_total.load();
    s.request_published = counters_.request_published.load();
    s.response_completed = counters_.response_completed.load();
    s.response_rejected = counters_.response_rejected.load();
    s.event_forwarded = counters_.event_forwarded.load();
    s.event_dropped = counters_.event_dropped.load();
    s.exchange_timeout = counters_.exchange_timeout.load();
    s.envelope_invalid = counters_.envelope_invalid.load();
    return s;
}

// ============================================================
// 超时收敛 worker（按 shard 扫描 correlation table）
// ============================================================
void VehicleMessageGateway::sweeper_loop(int shard, int shard_count) {
    const auto sweep_interval = std::chrono::milliseconds(100);
    while (running_.load()) {
        std::this_thread::sleep_for(sweep_interval);

        const auto now = std::chrono::steady_clock::now();
        // 终止保护窗口（迟到响应 tombstone 保留时长）
        const auto tombstone_window = std::max(
            std::chrono::milliseconds(2 * config_.default_exchange_timeout_ms),
            std::chrono::milliseconds(5000));
        const auto terminal_grace = std::chrono::milliseconds(1000);

        std::vector<std::shared_ptr<CorrelationEntry>> to_complete;
        {
            std::lock_guard<std::mutex> lock(table_mutex_);
            for (auto it = table_.begin(); it != table_.end();) {
                auto& e = it->second;
                // shard 分片：按 message_id 哈希归一到 worker_count 个 shard
                size_t h = std::hash<std::string>{}(e->message_id);
                if (static_cast<int>(h % shard_count) != shard) {
                    ++it;
                    continue;
                }
                std::lock_guard<std::mutex> elock(e->mutex);
                if (!e->terminal && e->deadline <= now) {
                    e->outcome = e->mqtt_accepted
                        ? TransportOutcome::Timeout : TransportOutcome::Unknown;
                    e->terminal = true;
                    e->completed_at = now;
                    counters_.exchange_timeout++;
                    to_complete.push_back(e);
                } else if (e->terminal &&
                           (now - e->completed_at) > terminal_grace) {
                    // 已终止且 exchange 线程已返回：从表移除并登记 tombstone
                    recent_terminal_[e->message_id] = now + tombstone_window;
                    it = table_.erase(it);
                    continue;
                }
                ++it;
            }

            // 惰性清理过期 tombstone
            for (auto it = recent_terminal_.begin();
                 it != recent_terminal_.end();) {
                if (it->second <= now) {
                    it = recent_terminal_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& e : to_complete) {
            std::lock_guard<std::mutex> elock(e->mutex);
            e->cv.notify_all();
        }
    }
}

} // namespace tsp
} // namespace tbox
