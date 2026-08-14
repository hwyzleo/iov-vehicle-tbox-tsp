// TBOX-TSP IPC 请求分发适配器实现 (CR-003 §2; CR-009 §Client 与 IPC 契约)

#include "tsp_ipc_dispatcher.h"
#include "vehicle_message_gateway.h"
#include "net_status_provider.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "log_adapter.h"

#include "utils.h"
#include <nlohmann/json.hpp>
#include <chrono>

namespace tbox {
namespace tsp {

namespace {

// FW-0305: JSON/base64 serialization failed
constexpr int32_t FW_SERIALIZATION_FAILED = 305;
// FW-0306: unknown method or request handler failed
constexpr int32_t FW_HANDLER_FAILED = 306;

std::string make_json_response(int32_t status, const nlohmann::json& payload) {
    nlohmann::json j = payload;
    j[ipc::field::STATUS] = status;
    return j.dump();
}

std::string b64_encode_bytes(const std::vector<std::byte>& data) {
    std::string raw;
    raw.reserve(data.size());
    for (auto b : data) {
        raw.push_back(static_cast<char>(static_cast<uint8_t>(b)));
    }
    return ::hwyz::Utils::base64_encode(raw);
}

std::vector<std::byte> b64_decode_bytes(const std::string& encoded) {
    std::string decoded = ::hwyz::Utils::base64_decode(encoded);
    std::vector<std::byte> out(decoded.size());
    for (size_t i = 0; i < decoded.size(); ++i) {
        out[i] = static_cast<std::byte>(static_cast<uint8_t>(decoded[i]));
    }
    return out;
}

// TransportOutcome -> TBOX-TSP-10xx/2xxx 业务状态码（SPEC §7, CR-009 §错误与重试）
int32_t tsp_error_for_outcome(TransportOutcome o) {
    switch (o) {
        case TransportOutcome::Accepted:        return static_cast<int32_t>(TspErrorCode::SUCCESS);
        case TransportOutcome::Rejected:        return static_cast<int32_t>(TspErrorCode::PAYLOAD_PARSE_FAILED);
        case TransportOutcome::Timeout:         return static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        case TransportOutcome::Unknown:         return static_cast<int32_t>(TspErrorCode::UNKNOWN_OUTCOME);
        case TransportOutcome::Unavailable:     return static_cast<int32_t>(TspErrorCode::ROUTE_API_INCOMPATIBLE);
        case TransportOutcome::VersionMismatch: return static_cast<int32_t>(TspErrorCode::ROUTE_API_INCOMPATIBLE);
        case TransportOutcome::PayloadTooLarge: return static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE);
        case TransportOutcome::ProtocolError:   return static_cast<int32_t>(TspErrorCode::PAYLOAD_PARSE_FAILED);
        case TransportOutcome::Stopping:        return static_cast<int32_t>(TspErrorCode::PUBLISH_FAILED);
        default: return static_cast<int32_t>(TspErrorCode::INTERNAL_ERROR);
    }
}

} // anonymous namespace

TspIpcDispatcher::TspIpcDispatcher(VehicleMessageRelayInterface* relay,
                                   NetStatusProvider* net_provider,
                                   uint32_t max_payload_bytes)
    : relay_(relay)
    , net_provider_(net_provider)
    , max_payload_bytes_(max_payload_bytes) {
}

std::string TspIpcDispatcher::dispatch(uint32_t method_id,
                                       std::string_view params_json,
                                       int client_fd) {
    (void)client_fd;

    auto start = std::chrono::steady_clock::now();

    LogAdapter::ipc_server().debug(
        "tsp.ipc.dispatch",
        "Dispatching request",
        {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id))),
         tbox::fw::log::Field("payload_bytes", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(params_json.size())))}
    );

    std::pair<int32_t, std::string> result{FW_HANDLER_FAILED,
        nlohmann::json({{ipc::field::ERROR, "Unknown method"}}).dump()};

    try {
        switch (static_cast<ipc::MethodId>(method_id)) {
            case ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE:
                result = handle_exchange_vehicle_message(params_json);
                break;
            case ipc::MethodId::GET_NET_STATUS:
                result = handle_get_net_status();
                break;
            case ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE:
            case ipc::MethodId::SUBSCRIBE_NET_STATUS:
                result = handle_subscribe();
                break;
            default:
                LogAdapter::ipc_server().warn(
                    "tsp.ipc.unknown_method",
                    "Unknown method ID",
                    {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id)))}
                );
                break;
        }
    } catch (const nlohmann::json::exception& e) {
        LogAdapter::ipc_server().error(
            "tsp.ipc.json_error",
            "JSON serialization error in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id))),
             tbox::fw::log::Field("what", tbox::fw::log::FieldValue::makeString(e.what()))}
        );
        result = {FW_SERIALIZATION_FAILED, nlohmann::json({{ipc::field::ERROR, "JSON error"}}).dump()};
    } catch (const std::exception& e) {
        LogAdapter::ipc_server().error(
            "tsp.ipc.dispatch_exception",
            "Exception in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id))),
             tbox::fw::log::Field("what", tbox::fw::log::FieldValue::makeString(e.what()))}
        );
        result = {FW_HANDLER_FAILED, nlohmann::json({{ipc::field::ERROR, "Internal error"}}).dump()};
    } catch (...) {
        LogAdapter::ipc_server().error(
            "tsp.ipc.dispatch_exception",
            "Unknown exception in dispatch",
            {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id)))}
        );
        result = {FW_HANDLER_FAILED, nlohmann::json({{ipc::field::ERROR, "Unknown exception"}}).dump()};
    }

    auto end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    LogAdapter::ipc_server().debug(
        "tsp.ipc.dispatched",
        "Request dispatched",
        {tbox::fw::log::Field("method_id", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(method_id))),
         tbox::fw::log::Field("status", tbox::fw::log::FieldValue::makeInt(result.first)),
         tbox::fw::log::Field("duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms))}
    );

    try {
        auto payload = nlohmann::json::parse(result.second);
        return make_json_response(result.first, payload);
    } catch (...) {
        return make_json_response(result.first, nlohmann::json({{ipc::field::ERROR, "Invalid response"}}));
    }
}

// ============================================================
// Method handlers
// ============================================================

std::pair<int32_t, std::string>
TspIpcDispatcher::handle_exchange_vehicle_message(std::string_view params) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(params);
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED,
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Invalid JSON"}}).dump()};
    }

    std::string envelope_b64 = j.value(ipc::field::ENVELOPE_B64, "");
    if (envelope_b64.empty()) {
        return {static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Missing envelope_base64"}}).dump()};
    }

    // 超限帧在分配前拒绝（CR-003 §6）
    if (envelope_b64.size() > max_payload_bytes_) {
        LogAdapter::ipc_server().warn(
            "tsp.ipc.frame_too_large",
            "Envelope exceeds frame limit",
            {tbox::fw::log::Field("payload_bytes", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(envelope_b64.size()))),
             tbox::fw::log::Field("limit", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(max_payload_bytes_)))}
        );
        return {static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Frame too large"}}).dump()};
    }

    VehicleMessage request;
    try {
        request.envelope_bytes = b64_decode_bytes(envelope_b64);
    } catch (const std::exception&) {
        return {FW_SERIALIZATION_FAILED,
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "base64 decode failed"}}).dump()};
    }

    ExchangeOptions options;
    options.timeout = std::chrono::milliseconds(
        j.value(ipc::field::TIMEOUT_MS, 0));
    options.max_response_bytes = j.value(ipc::field::MAX_RESPONSE_BYTES, 16384u);

    CallContext ctx;
    ctx.trace_id   = j.value(ipc::field::TRACE_ID, "");
    ctx.request_id = j.value(ipc::field::REQUEST_ID, "");

    if (!relay_) {
        return {static_cast<int32_t>(TspErrorCode::NOT_INITIALIZED),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Relay not ready"}}).dump()};
    }

    TransportResult<VehicleMessage> r = relay_->exchange(request, options, ctx);

    nlohmann::json resp;
    resp[ipc::field::SUCCESS]  = (r.outcome == TransportOutcome::Accepted);
    resp[ipc::field::OUTCOME]  = transport_outcome_to_string(r.outcome);
    if (r.value.has_value() && !r.value->envelope_bytes.empty()) {
        resp[ipc::field::ENVELOPE_B64] = b64_encode_bytes(r.value->envelope_bytes);
    }
    if (!r.error.empty()) {
        resp[ipc::field::ERROR] = r.error;
    }
    return {tsp_error_for_outcome(r.outcome), resp.dump()};
}

std::pair<int32_t, std::string>
TspIpcDispatcher::handle_get_net_status() {
    if (!net_provider_ || !net_provider_->is_available()) {
        return {static_cast<int32_t>(TspErrorCode::NOT_INITIALIZED),
            nlohmann::json({{ipc::field::ERROR, "Net status provider not available"}}).dump()};
    }
    auto status = net_provider_->get_net_status();
    nlohmann::json resp;
    resp["is_connected"]    = status.is_connected;
    resp["signal_strength"] = status.signal_strength;
    resp["network_type"]    = status.network_type;
    resp["operator"]        = status.operator_name;
    return {0, resp.dump()};
}

std::pair<int32_t, std::string>
TspIpcDispatcher::handle_subscribe() {
    // 订阅注册（add_subscription）由 TspFrameworkServer 的 request_handler 完成
    nlohmann::json resp;
    resp[ipc::field::SUCCESS] = true;
    return {0, resp.dump()};
}

} // namespace tsp
} // namespace tbox
