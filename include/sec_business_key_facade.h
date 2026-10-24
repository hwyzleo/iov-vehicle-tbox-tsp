// TBOX-TSP-DSN-CR-010 §3.2: TBOX-SEC 业务密钥窄接口。
//
// TSP 只依赖以下语义（由 TBOX-SEC-DSN-CR-019 冻结）：
//   - getBusinessKeyStatus：查询 V2C_COMM 两个 purpose 的件内状态；
//   - importWrappedBusinessKeys：把完整 Wrapped Key bundle 一次性交给 SEC 原子导入；
//   - getBusinessKeyImportResult：Unknown 时按 requestId 查询，不盲目重放。
//
// 安全不变量：SEC 不返回明文密钥；wrapped_key/parameters 使用不可复制、可清零的
// tbox::sec::SecureBuffer；TSP 不解析其密码学内容、不落盘、不打印。
//
// 以窄接口抽象便于契约测试注入 FakeSecClient（CR-010 §10 测试矩阵第 7 条）。

#pragma once

#include <tbox/sec/business_key.h>
#include <tbox/sec/errors.h>

#include <memory>
#include <string>
#include <vector>

namespace tbox {
namespace sec {
class SecClient;
}  // namespace sec

namespace tsp {

// ============================================================
// TBOX-TSP-DSN-CR-014 §2/§3/§21.1：SEC import result 强类型分类。
// ============================================================
// 分类语义（adapter exhaustive switch）：
//   COMMITTED              -> Committed      （journal 已原子提交）
//   FAILED                 -> Failed         （journal 存在且失败；不得等同 NotFound）
//   NOT_FOUND              -> NotFound       （结构化 journal 证明无记录/无副作用）
//   UNKNOWN/OUTCOME_UNKNOWN -> OutcomeUnknown（可能有副作用，fail-closed）
//   REQUESTED/STAGED       -> OutcomeUnknown（事务痕迹已存在，fail-closed；
//                             raw_import_state 保留原始数值用于诊断区分）
//   未知数值/字符串         -> ContractUnknown（防御兜底；Store 旧记录缺字段默认值）
//   传输/解析/timeout       -> QueryError     （sec_import_result_contract_version=0）
//
// 除明确 NotFound 外，所有新增、未知和失败路径均保持 sec_outcome_unknown_=true；
// 旧 SEC 的 UNKNOWN 不得升级为 NotFound。
enum class SecImportEvidenceKind : uint8_t {
    Committed = 0,
    Failed = 1,
    NotFound = 2,
    OutcomeUnknown = 3,
    QueryError = 4,
    ContractUnknown = 5
};

const char* sec_import_evidence_kind_to_string(SecImportEvidenceKind k);

// TBOX-TSP-DSN-CR-015 §6.1：支持 CR-021 精确 NOT_FOUND 语义所需的最低
// SEC capability 契约版本（TBOX-SEC-DSN-CR-021 在 kContractVersion=2 中引入
// NOT_FOUND additive 值 5 与“无残留检查”语义）。旧 SEC 的 UNKNOWN/低版本
// NOT_FOUND 不得派生 no_residue_proven。
constexpr uint32_t kSecCr021NotFoundContractVersion = 2;

struct SecImportEvidence {
    SecImportEvidenceKind kind = SecImportEvidenceKind::ContractUnknown;
    // 观测时 capability 快照的契约版本；查询失败/无法确认记 0=UNKNOWN。
    // 仅用于兼容诊断，不得作为 NOT_FOUND 或释放旧 attempt 的证明。
    uint32_t sec_import_result_contract_version = 0;
    std::vector<uint8_t> request_id_digest;  // 32B raw（受控摘要，无完整 requestId）
    uint64_t observed_store_generation = 0;
    bool import_invocation_recorded = false;  // 已调用 SEC import API
    bool pending_callback = false;            // import 结果待定（回调待收敛）
    int raw_import_state = -1;                // 原始 SEC state 数值（诊断保留，-1=无）
    // CR-015：仅“新 SEC + 强类型 NOT_FOUND + capability/contract 匹配”时由
    // adapter 派生（不新增 wire 字段）；旧 SEC 的 UNKNOWN 不得派生该值。
    bool no_residue_proven = false;
};

// SEC import result 分类（实现位于 sec_business_key_adapter.cpp）。
// ec!=SUCCESS 时按 QueryError 处理且契约版本记 0；结果有效时 contract_version
// 取调用方提供的 capability 快照契约版本。
SecImportEvidence sec_classify_import_result(
    tbox::sec::ErrorCode ec, const tbox::sec::ImportResult& result,
    uint32_t sec_import_result_contract_version);

class SecBusinessKeyFacade {
public:
    virtual ~SecBusinessKeyFacade() = default;

    virtual tbox::sec::ErrorCode get_business_key_status(
        const std::string& business_domain,
        const std::vector<std::string>& purposes,
        tbox::sec::BusinessKeyStatusSet& out) = 0;

    virtual tbox::sec::ErrorCode import_wrapped_business_keys(
        const std::string& request_id,
        const std::string& business_domain,
        const std::vector<tbox::sec::WrappedKeyItem>& items,
        tbox::sec::ImportResult& out) = 0;

    virtual tbox::sec::ErrorCode get_business_key_import_result(
        const std::string& request_id,
        tbox::sec::ImportResult& out) = 0;

    // TBOX-TSP-DSN-CR-012 §8 / Q1：只读 keyprov capability 查询。
    // 默认 NOT_IMPLEMENTED（fail-closed），由真实适配器/Fake 覆盖。
    virtual tbox::sec::ErrorCode get_v2c_key_provisioning_capability(
        tbox::sec::V2cKeyProvisioningCapability& out) {
        (void)out;
        return tbox::sec::ErrorCode::NOT_IMPLEMENTED;
    }
};

// MqttFacade 的 SEC 对应实现：包装 tbox::sec::SecClient。
class SecClientBusinessKeyAdapter : public SecBusinessKeyFacade {
public:
    explicit SecClientBusinessKeyAdapter(
        const std::string& socket_path = "/tmp/tbox-sec.sock");
    ~SecClientBusinessKeyAdapter() override;

    SecClientBusinessKeyAdapter(const SecClientBusinessKeyAdapter&) = delete;
    SecClientBusinessKeyAdapter& operator=(const SecClientBusinessKeyAdapter&) = delete;

    // 建立与 TBOX-SEC 的 IPC 连接（惰性；失败返回 false）
    bool connect();
    void disconnect();
    bool is_connected() const;

    tbox::sec::ErrorCode get_business_key_status(
        const std::string& business_domain,
        const std::vector<std::string>& purposes,
        tbox::sec::BusinessKeyStatusSet& out) override;
    tbox::sec::ErrorCode import_wrapped_business_keys(
        const std::string& request_id,
        const std::string& business_domain,
        const std::vector<tbox::sec::WrappedKeyItem>& items,
        tbox::sec::ImportResult& out) override;
    tbox::sec::ErrorCode get_business_key_import_result(
        const std::string& request_id,
        tbox::sec::ImportResult& out) override;

    tbox::sec::ErrorCode get_v2c_key_provisioning_capability(
        tbox::sec::V2cKeyProvisioningCapability& out) override;

private:
    std::string socket_path_;
    std::unique_ptr<tbox::sec::SecClient> client_;
};

} // namespace tsp
} // namespace tbox
