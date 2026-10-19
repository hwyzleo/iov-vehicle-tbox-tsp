// TBOX-TSP-DSN-CR-010 §3.2: SEC 业务密钥适配器实现。
#include "sec_business_key_facade.h"

#include <tbox/sec/client.h>

#include "log_adapter.h"

namespace tbox {
namespace tsp {

SecClientBusinessKeyAdapter::SecClientBusinessKeyAdapter(
    const std::string& socket_path)
    : socket_path_(socket_path),
      client_(std::make_unique<tbox::sec::SecClient>(socket_path_)) {
}

SecClientBusinessKeyAdapter::~SecClientBusinessKeyAdapter() {
    disconnect();
}

bool SecClientBusinessKeyAdapter::connect() {
    if (!client_) return false;
    if (client_->is_connected()) return true;
    bool ok = client_->connect();
    if (!ok) {
        LogAdapter::keyprov().warn(
            "tsp.keyprov.sec.connect_failed",
            "SEC client 连接失败，keyprov 保持 NOT_READY", {});
    }
    return ok;
}

void SecClientBusinessKeyAdapter::disconnect() {
    if (client_) {
        client_->disconnect();
    }
}

bool SecClientBusinessKeyAdapter::is_connected() const {
    return client_ && client_->is_connected();
}

tbox::sec::ErrorCode SecClientBusinessKeyAdapter::get_business_key_status(
    const std::string& business_domain,
    const std::vector<std::string>& purposes,
    tbox::sec::BusinessKeyStatusSet& out) {
    if (!client_) return tbox::sec::ErrorCode::NOT_INITIALIZED;
    connect();
    return client_->get_business_key_status(business_domain, purposes, out);
}

tbox::sec::ErrorCode SecClientBusinessKeyAdapter::import_wrapped_business_keys(
    const std::string& request_id,
    const std::string& business_domain,
    const std::vector<tbox::sec::WrappedKeyItem>& items,
    tbox::sec::ImportResult& out) {
    if (!client_) return tbox::sec::ErrorCode::NOT_INITIALIZED;
    connect();
    return client_->import_wrapped_business_keys(
        request_id, business_domain, items, out);
}

tbox::sec::ErrorCode SecClientBusinessKeyAdapter::get_business_key_import_result(
    const std::string& request_id,
    tbox::sec::ImportResult& out) {
    if (!client_) return tbox::sec::ErrorCode::NOT_INITIALIZED;
    connect();
    return client_->get_business_key_import_result(request_id, out);
}

tbox::sec::ErrorCode SecClientBusinessKeyAdapter::get_v2c_key_provisioning_capability(
    tbox::sec::V2cKeyProvisioningCapability& out) {
    if (!client_) return tbox::sec::ErrorCode::NOT_INITIALIZED;
    connect();
    return client_->get_v2c_key_provisioning_capability(out);
}

} // namespace tsp
} // namespace tbox
