// TBOX-TSP-DSN-CR-010 §3.2 / CR-014 §3/§21.1: SEC 业务密钥适配器实现。
#include "sec_business_key_facade.h"

#include <tbox/sec/client.h>

#include "log_adapter.h"

namespace tbox {
namespace tsp {

namespace {

// 已知的 BusinessKeyImportState 数值（诊断保留；未知数值在 wire 层已被 SEC
// client 归一化为 UNKNOWN，此处仅识别显式枚举）。
int raw_state_code(const tbox::sec::ImportResult& result) {
    switch (result.state) {
        case tbox::sec::BusinessKeyImportState::REQUESTED: return 0;
        case tbox::sec::BusinessKeyImportState::STAGED: return 1;
        case tbox::sec::BusinessKeyImportState::COMMITTED: return 2;
        case tbox::sec::BusinessKeyImportState::FAILED: return 3;
        case tbox::sec::BusinessKeyImportState::UNKNOWN: return 4;
        case tbox::sec::BusinessKeyImportState::NOT_FOUND: return 5;
        default: return -1;
    }
}

} // namespace

// TBOX-TSP-DSN-CR-014 §3/§21.1：exhaustive switch 分类。
// 除明确 NotFound 外，所有新增、未知和失败路径均保持 fail-closed；
// 旧 SEC 的 UNKNOWN 不得升级为 NotFound。
SecImportEvidence sec_classify_import_result(
    tbox::sec::ErrorCode ec, const tbox::sec::ImportResult& result,
    uint32_t sec_import_result_contract_version) {
    SecImportEvidence ev;
    ev.raw_import_state = raw_state_code(result);
    if (ec != tbox::sec::ErrorCode::SUCCESS) {
        // 传输/解析/timeout：契约版本无法确认记 0。
        ev.kind = SecImportEvidenceKind::QueryError;
        ev.sec_import_result_contract_version = 0;
        return ev;
    }
    ev.sec_import_result_contract_version = sec_import_result_contract_version;
    switch (result.state) {
        case tbox::sec::BusinessKeyImportState::COMMITTED:
            ev.kind = SecImportEvidenceKind::Committed;
            break;
        case tbox::sec::BusinessKeyImportState::FAILED:
            // journal 存在且失败：不得等同 NotFound，保持阻断。
            ev.kind = SecImportEvidenceKind::Failed;
            break;
        case tbox::sec::BusinessKeyImportState::NOT_FOUND:
            ev.kind = SecImportEvidenceKind::NotFound;
            break;
        case tbox::sec::BusinessKeyImportState::REQUESTED:
        case tbox::sec::BusinessKeyImportState::STAGED:
            // 事务痕迹已存在（受理/ staging 中）：fail-closed，raw 数值保留诊断。
            ev.kind = SecImportEvidenceKind::OutcomeUnknown;
            break;
        case tbox::sec::BusinessKeyImportState::UNKNOWN:
            ev.kind = SecImportEvidenceKind::OutcomeUnknown;
            break;
        default:
            // 未知数值/字符串（防御；wire 层归一化后通常不可达）。
            ev.kind = SecImportEvidenceKind::ContractUnknown;
            break;
    }
    return ev;
}

const char* sec_import_evidence_kind_to_string(SecImportEvidenceKind k) {
    switch (k) {
        case SecImportEvidenceKind::Committed: return "COMMITTED";
        case SecImportEvidenceKind::Failed: return "FAILED";
        case SecImportEvidenceKind::NotFound: return "NOT_FOUND";
        case SecImportEvidenceKind::OutcomeUnknown: return "OUTCOME_UNKNOWN";
        case SecImportEvidenceKind::QueryError: return "QUERY_ERROR";
        case SecImportEvidenceKind::ContractUnknown: return "CONTRACT_UNKNOWN";
        default: return "?";
    }
}

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
