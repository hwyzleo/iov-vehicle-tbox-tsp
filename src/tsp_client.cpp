// TBOX-TSP 客户端 facade 实现 (CR-003 §7)
//
// 内部使用 framework-ipc Client + TspRetryPolicy。
// 不向业务调用方泄露 framework 异常类型：FW-03xx 统一映射为公开 client 错误。

#include "tbox/tsp/client.h"
#include "tsp_retry_policy.h"
#include "tsp_ipc_protocol.h"
#include "utils.h"

#include "ipc.h"

#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

namespace {

std::string b64_encode(const std::vector<uint8_t>& data) {
    return ::hwyz::Utils::base64_encode(
        std::string(reinterpret_cast<const char*>(data.data()), data.size()));
}

std::vector<uint8_t> b64_decode(const std::string& encoded) {
    std::string decoded = ::hwyz::Utils::base64_decode(encoded);
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

PublishOutcome parse_outcome(const std::string& s) {
    return (s == "UNKNOWN") ? PublishOutcome::UNKNOWN : PublishOutcome::ACCEPTED;
}

RelayState parse_state(const std::string& s) {
    if (s == "ACCEPTED")  return RelayState::ACCEPTED;
    if (s == "PUBLISHED") return RelayState::PUBLISHED;
    if (s == "ACKED")     return RelayState::ACKED;
    if (s == "FAILED")    return RelayState::FAILED;
    return RelayState::UNKNOWN;
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

    ReportResult report_software_inventory(const FotaSnapshot& snapshot) {
        const uint32_t method = static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY);

        nlohmann::json params;
        params[ipc::field::SNAPSHOT_SEQ] = snapshot.snapshot_seq;
        params[ipc::field::MSG_ID]       = snapshot.msg_id;
        params[ipc::field::CONTENT_TYPE] = snapshot.content_type;
        params[ipc::field::PAYLOAD_B64]  = b64_encode(snapshot.payload);
        if (!snapshot.trace_id.empty())   params[ipc::field::TRACE_ID]   = snapshot.trace_id;
        if (!snapshot.request_id.empty()) params[ipc::field::REQUEST_ID] = snapshot.request_id;

        auto [transport_ok, fw_status, response_json] = send_request(method, params.dump());

        ReportResult r;
        r.msg_id = snapshot.msg_id;

        if (!transport_ok) {
            // 传输失败：unknown outcome，仅可复用相同 msg_id 查询/单次重试
            r.accepted = false;
            r.outcome = PublishOutcome::UNKNOWN;
            r.error_code = static_cast<int32_t>(TspErrorCode::UNKNOWN_OUTCOME);
            return r;
        }

        // 解析业务状态
        try {
            auto j = nlohmann::json::parse(response_json);
            r.error_code = j.value(ipc::field::STATUS, 0);
            r.accepted = j.value(ipc::field::ACCEPTED, false);
            r.outcome = parse_outcome(j.value(ipc::field::OUTCOME, "ACCEPTED"));
            if (j.contains(ipc::field::MSG_ID)) {
                r.msg_id = j.value(ipc::field::MSG_ID, snapshot.msg_id);
            }
        } catch (...) {
            r.accepted = false;
            r.error_code = static_cast<int32_t>(TspErrorCode::INTERNAL_ERROR);
        }
        return r;
    }

    ::tbox::fw::ipc::Subscription subscribe_fota_command(FotaCommandCallback callback) {
        const uint32_t method = static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_FOTA_COMMAND);
        const uint32_t event  = static_cast<uint32_t>(ipc::EventType::FOTA_COMMAND);

        auto wrapped = [cb = std::move(callback)](uint32_t /*event_type*/,
                                                   std::string_view payload_json) {
            FotaCommand cmd;
            try {
                auto j = nlohmann::json::parse(payload_json);
                cmd.command_id     = j.value(ipc::field::COMMAND_ID, "");
                cmd.delivery_id    = j.value(ipc::field::DELIVERY_ID, "");
                cmd.schema_version = j.value(ipc::field::SCHEMA_VERSION, "");
                cmd.content_type   = j.value(ipc::field::CONTENT_TYPE, "application/x-protobuf");
                cmd.trace_id       = j.value(ipc::field::TRACE_ID, "");
                cmd.request_id     = j.value(ipc::field::REQUEST_ID, "");
                std::string b64 = j.value(ipc::field::PAYLOAD_B64, "");
                if (!b64.empty()) cmd.payload = b64_decode(b64);
            } catch (...) {
                // 解析失败：不回调，避免向业务投递坏帧
                return;
            }
            if (cb) cb(cmd);
        };

        return fw_client_->subscribe(method, event, wrapped);
    }

    RelayStatus get_relay_status(const std::string& msg_id) {
        const uint32_t method = static_cast<uint32_t>(ipc::MethodId::GET_RELAY_STATUS);

        nlohmann::json params;
        params[ipc::field::MSG_ID] = msg_id;

        auto [transport_ok, fw_status, response_json] = send_request(method, params.dump());

        RelayStatus s;
        s.msg_id = msg_id;
        if (!transport_ok) {
            s.state = RelayState::UNKNOWN;
            s.error_code = static_cast<int32_t>(map_fw_status(fw_status));
            s.last_error = "transport failed";
            return s;
        }
        try {
            auto j = nlohmann::json::parse(response_json);
            s.error_code = j.value(ipc::field::STATUS, 0);
            s.state = parse_state(j.value(ipc::field::STATE, "UNKNOWN"));
            s.msg_id = j.value(ipc::field::MSG_ID, msg_id);
            s.snapshot_seq = j.value(ipc::field::SNAPSHOT_SEQ, 0u);
            s.last_error = j.value(ipc::field::LAST_ERROR, "");
        } catch (...) {
            s.state = RelayState::UNKNOWN;
            s.error_code = static_cast<int32_t>(TspErrorCode::INTERNAL_ERROR);
        }
        return s;
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

ReportResult TspClient::reportSoftwareInventory(const FotaSnapshot& snapshot) {
    return impl_->report_software_inventory(snapshot);
}

::tbox::fw::ipc::Subscription TspClient::subscribeFotaCommand(FotaCommandCallback callback) {
    return impl_->subscribe_fota_command(std::move(callback));
}

RelayStatus TspClient::getRelayStatus(const std::string& msg_id) {
    return impl_->get_relay_status(msg_id);
}

} // namespace tsp
} // namespace tbox
