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
