// TBOX-TSP 客户端 facade 实现 (CR-003 §7; CR-009 §Client 与 IPC 契约)
//
// 内部使用 framework-ipc Client。
// CR-009：只暴露通用 exchange/subscribe；wire 只承载单一 Envelope bytes。
// EXCHANGE_VEHICLE_MESSAGE 使用 callOnce（禁止不可见自动重试；重试由 CGW-FOTA
// 以原 request/idempotency 身份发起）。不向业务调用方泄露 framework 异常类型。

#include "tbox/tsp/client.h"
#include "tsp_retry_policy.h"
#include "tsp_ipc_protocol.h"
#include "utils.h"

#include "ipc.h"

#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

namespace {

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

TransportOutcome parse_outcome(const std::string& s) {
    if (s == "Accepted")        return TransportOutcome::Accepted;
    if (s == "Rejected")        return TransportOutcome::Rejected;
    if (s == "Timeout")         return TransportOutcome::Timeout;
    if (s == "Unknown")         return TransportOutcome::Unknown;
    if (s == "Unavailable")     return TransportOutcome::Unavailable;
    if (s == "VersionMismatch") return TransportOutcome::VersionMismatch;
    if (s == "PayloadTooLarge") return TransportOutcome::PayloadTooLarge;
    if (s == "ProtocolError")   return TransportOutcome::ProtocolError;
    if (s == "Stopping")        return TransportOutcome::Stopping;
    return TransportOutcome::Unknown;
}

} // anonymous namespace

// ============================================================
// TspClient::Impl
// ============================================================
class TspClient::Impl {
public:
    explicit Impl(const std::string& socket_path)
        : socket_path_(socket_path),
          fw_client_(std::make_unique<::tbox::fw::ipc::Client>(socket_path_)) {
    }

    ~Impl() {
        disconnect();
    }

    bool connect() { return fw_client_->connect(); }
    void disconnect() { fw_client_->disconnect(); }
    bool is_connected() const { return fw_client_->is_connected(); }

    /// 发送请求-响应，返回 (transport_ok, fw_status, response_json)
    std::tuple<bool, int32_t, std::string>
    send_request(uint32_t method_id, const std::string& params_json) {
        std::pair<int32_t, std::string> result;
        if (TspRetryPolicy::should_retry(method_id)) {
            result = fw_client_->call(method_id, params_json);
        } else {
            result = fw_client_->callOnce(method_id, params_json);
        }
        auto [fw_status, response_json] = result;
        bool transport_ok = (fw_status == 0);
        return {transport_ok, fw_status, response_json};
    }

    TransportResult<VehicleMessage> exchange_vehicle_message(
        const VehicleMessage& request,
        const ExchangeOptions& options,
        const CallContext& ctx) {
        const uint32_t method = static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE);

        nlohmann::json params;
        params[ipc::field::ENVELOPE_B64] = b64_encode_bytes(request.envelope_bytes);
        params[ipc::field::TIMEOUT_MS] = static_cast<uint32_t>(options.timeout.count());
        params[ipc::field::MAX_RESPONSE_BYTES] = static_cast<uint32_t>(options.max_response_bytes);
        if (!ctx.trace_id.empty())   params[ipc::field::TRACE_ID]   = ctx.trace_id;
        if (!ctx.request_id.empty()) params[ipc::field::REQUEST_ID] = ctx.request_id;

        auto [transport_ok, fw_status, response_json] = send_request(method, params.dump());

        TransportResult<VehicleMessage> r;

        if (!transport_ok) {
            // 传输失败：TSP client 不可达 -> Unavailable（不生成新业务身份重试）
            r.outcome = TransportOutcome::Unavailable;
            r.error_code = static_cast<int32_t>(map_fw_status(fw_status));
            r.error = "transport_failed";
            return r;
        }

        // 解析业务状态
        try {
            auto j = nlohmann::json::parse(response_json);
            r.outcome = parse_outcome(j.value(ipc::field::OUTCOME, "Unknown"));
            r.error_code = j.value(ipc::field::STATUS, 0);
            r.error = j.value(ipc::field::ERROR, "");
            std::string resp_b64 = j.value(ipc::field::ENVELOPE_B64, "");
            if (!resp_b64.empty()) {
                VehicleMessage resp;
                resp.envelope_bytes = b64_decode_bytes(resp_b64);
                r.value = std::move(resp);
            }
        } catch (...) {
            r.outcome = TransportOutcome::ProtocolError;
            r.error_code = static_cast<int32_t>(TspErrorCode::INTERNAL_ERROR);
            r.error = "invalid_response";
        }
        return r;
    }

    ::tbox::fw::ipc::Subscription subscribe_vehicle_message(
        std::string_view service, VehicleMessageHandler handler) {
        const uint32_t method = static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE);
        const uint32_t event  = static_cast<uint32_t>(ipc::EventType::VEHICLE_MESSAGE);

        nlohmann::json params;
        params[ipc::field::SERVICE] = std::string(service);

        auto wrapped = [svc = std::string(service), cb = std::move(handler)](
                           uint32_t /*event_type*/, std::string_view payload_json) {
            // 解析失败不回调，避免向业务投递坏帧
            try {
                auto j = nlohmann::json::parse(payload_json);
                // 分类键不一致（理论上按订阅事件推送，防御式忽略）
                if (!j.value(ipc::field::SERVICE, "").empty() &&
                    j.value(ipc::field::SERVICE, "") != svc) {
                    return;
                }
                std::string b64 = j.value(ipc::field::ENVELOPE_B64, "");
                if (b64.empty()) return;
                VehicleMessage msg;
                msg.envelope_bytes = b64_decode_bytes(b64);
                if (cb) cb(msg);
            } catch (...) {
                return;
            }
        };

        return fw_client_->subscribe(method, event, params.dump(), std::move(wrapped));
    }

private:
    std::string socket_path_;
    std::unique_ptr<::tbox::fw::ipc::Client> fw_client_;
};

// ============================================================
// TspClient facade
// ============================================================

TspClient::TspClient(const std::string& socket_path)
    : impl_(std::make_unique<Impl>(socket_path)) {
}

TspClient::~TspClient() = default;

bool TspClient::connect() { return impl_->connect(); }
void TspClient::disconnect() { impl_->disconnect(); }
bool TspClient::is_connected() const { return impl_->is_connected(); }

TransportResult<VehicleMessage> TspClient::exchangeVehicleMessage(
    const VehicleMessage& request,
    const ExchangeOptions& options,
    const CallContext& ctx) {
    return impl_->exchange_vehicle_message(request, options, ctx);
}

::tbox::fw::ipc::Subscription TspClient::subscribeVehicleMessage(
    std::string_view service, VehicleMessageHandler handler) {
    return impl_->subscribe_vehicle_message(service, std::move(handler));
}

} // namespace tsp
} // namespace tbox
