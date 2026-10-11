// TBOX-TSP-DSN-CR-010 §5: V2C keyprov 非敏感流程状态持久化。
//
// Store namespace: tsp/keyprov/v2c（framework-store 逻辑 namespace "tsp" + 键前缀）。
// 只保存非敏感状态机字段，绝不保存 Wrapped Key、parameters 原文、证书、VIN/HSM UID
// 或任何可恢复密钥的材料。SEC/HSM 件内状态永远是事实来源，Store 不覆盖其结论。

#pragma once

#include "store.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tbox {
namespace tsp {

struct V2cKeyProvisioningRecord {
    bool valid = false;                    // Store 中是否存在记录
    std::string request_id;                // 稳定业务流程身份
    std::string idempotency_digest;        // requestId 规范化摘要（非秘密）
    std::string state;                     // 状态机名（非敏感）
    std::vector<std::string> purposes;     // 用途集合
    std::vector<std::pair<std::string, uint64_t>> business_key_versions;  // purpose -> version
    uint32_t attempt_count = 0;
    int64_t deadline_ms = 0;
    std::string last_error;                // 受控原因码，不含密钥/身份原文
    int64_t updated_at_ms = 0;
    uint64_t cloud_session_generation = 0;
};

class V2cKeyProvisioningStore {
public:
    // store_root 默认 "/var/lib/tbox"；测试可注入临时目录。
    explicit V2cKeyProvisioningStore(const std::string& store_root = "/var/lib/tbox");

    // 读取持久化记录；无记录时 valid=false。
    V2cKeyProvisioningRecord load() const;

    // 原子持久化非敏感记录。
    void save(const V2cKeyProvisioningRecord& record);

    // 清除记录（仅当云端明确终结旧请求且策略允许时）。
    void clear();

    bool is_ready() const;

private:
    hwyz::store::Store store_;
};

} // namespace tsp
} // namespace tbox
