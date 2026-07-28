// TBOX-TSP IPC 请求分发适配器实现 (CR-003 §2)

#include "tsp_ipc_dispatcher.h"
#include "fota_relay_interface.h"
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

std::vector<uint8_t> b64_decode(const std::string& encoded) {
    std::string decoded = ::hwyz::Utils::base64_decode(encoded);
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

const char* outcome_str(PublishOutcome o) {
    return (o == PublishOutcome::UNKNOWN) ? "UNKNOWN" : "ACCEPTED";
}

} // anonymous namespace

TspIpcDispatcher::TspIpcDispatcher(FotaRelayInterface* relay,
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
            case ipc::MethodId::REPORT_SOFTWARE_INVENTORY:
                result = handle_report_software_inventory(params_json);
                break;
            case ipc::MethodId::GET_RELAY_STATUS:
                result = handle_get_relay_status(params_json);
                break;
            case ipc::MethodId::GET_NET_STATUS:
                result = handle_get_net_status();
                break;
            case ipc::MethodId::SUBSCRIBE_FOTA_COMMAND:
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
TspIpcDispatcher::handle_report_software_inventory(std::string_view params) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(params);
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED,
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Invalid JSON"}}).dump()};
    }

    std::string payload_b64 = j.value(ipc::field::PAYLOAD_B64, "");
    if (payload_b64.empty()) {
        return {static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Missing payload_base64"}}).dump()};
    }

    // 超限帧在分配前拒绝 (CR-003 §6)
    if (payload_b64.size() > max_payload_bytes_) {
        LogAdapter::ipc_server().warn(
            "tsp.ipc.frame_too_large",
            "Payload exceeds frame limit",
            {tbox::fw::log::Field("payload_bytes", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(payload_b64.size()))),
             tbox::fw::log::Field("limit", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(max_payload_bytes_)))}
        );
        return {static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Frame too large"}}).dump()};
    }

    FotaSnapshot snapshot;
    snapshot.snapshot_seq = j.value(ipc::field::SNAPSHOT_SEQ, 0u);
    snapshot.msg_id       = j.value(ipc::field::MSG_ID, "");
    snapshot.content_type = j.value(ipc::field::CONTENT_TYPE, "application/x-protobuf");
    snapshot.trace_id     = j.value(ipc::field::TRACE_ID, "");
    snapshot.request_id   = j.value(ipc::field::REQUEST_ID, "");
    try {
        snapshot.payload = b64_decode(payload_b64);
    } catch (const std::exception&) {
        return {FW_SERIALIZATION_FAILED,
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "base64 decode failed"}}).dump()};
    }

    if (snapshot.msg_id.empty()) {
        return {static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Missing msg_id"}}).dump()};
    }

    if (!relay_) {
        return {static_cast<int32_t>(TspErrorCode::NOT_INITIALIZED),
            nlohmann::json({{ipc::field::SUCCESS, false}, {ipc::field::ERROR, "Relay not ready"}}).dump()};
    }

    ReportResult r = relay_->handle_uplink(snapshot);

    nlohmann::json resp;
    resp[ipc::field::SUCCESS]  = r.accepted;
    resp[ipc::field::ACCEPTED] = r.accepted;
    resp[ipc::field::OUTCOME]  = outcome_str(r.outcome);
    resp[ipc::field::MSG_ID]   = r.msg_id;
    return {r.error_code, resp.dump()};
}

std::pair<int32_t, std::string>
TspIpcDispatcher::handle_get_relay_status(std::string_view params) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(params);
    } catch (const nlohmann::json::exception&) {
        return {FW_SERIALIZATION_FAILED,
            nlohmann::json({{ipc::field::ERROR, "Invalid JSON"}}).dump()};
    }

    std::string msg_id = j.value(ipc::field::MSG_ID, "");
    if (msg_id.empty()) {
        return {static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER),
            nlohmann::json({{ipc::field::ERROR, "Missing msg_id"}}).dump()};
    }

    if (!relay_) {
        return {static_cast<int32_t>(TspErrorCode::NOT_INITIALIZED),
            nlohmann::json({{ipc::field::ERROR, "Relay not ready"}}).dump()};
    }

    RelayStatus s = relay_->get_relay_status(msg_id);

    nlohmann::json resp;
    resp[ipc::field::STATE]        = relay_state_to_string(s.state);
    resp[ipc::field::MSG_ID]       = s.msg_id;
    resp[ipc::field::SNAPSHOT_SEQ] = s.snapshot_seq;
    resp[ipc::field::LAST_ERROR]   = s.last_error;
    return {s.error_code, resp.dump()};
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
