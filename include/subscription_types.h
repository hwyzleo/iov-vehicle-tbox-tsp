// TBOX-TSP 业务订阅快照 DTO (CR-004 §3, §5, §9, §11)
//
// 本头为 TSP daemon 内部类型，描述 TSP 向 tbox::mqtt_client 提交的完整、版本化
// 业务订阅快照。不属于 client SDK 对外契约（SDK 仅含 FOTA 上下行 DTO）。
//
// 边界（CR-004 §1, §11.1）：
// - TSP 是业务 Topic / QoS / target / mandatory 的唯一事实来源。
// - 快照保存 Topic 模板，不固化设备实例值；owner 固定为 tsp。
// - 本地 REGISTERED 仅表示 MQTT daemon 接受快照，不表示 Broker SUBACK 或 Cloud Ready。

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "tsp_build_config.h"

namespace tbox {
namespace tsp {

// ============================================================
// 订阅方向 (CR-004 §3, §11.1)
// ============================================================
enum class Direction : uint8_t {
    UP = 0,
    DOWN = 1,
    BIDIRECTIONAL = 2
};

inline const char* direction_to_string(Direction d) {
    switch (d) {
        case Direction::UP:            return "UP";
        case Direction::DOWN:          return "DOWN";
        case Direction::BIDIRECTIONAL: return "BIDIRECTIONAL";
        default: return "?";
    }
}

// 方向字符串解析（配置 direction 字段，大小写不敏感）。
// 解析成功返回 true 并写入 out；失败返回 false。
inline bool direction_from_string(const std::string& s, Direction& out) {
    std::string upper;
    upper.reserve(s.size());
    for (char c : s) {
        upper.push_back(static_cast<char>(
            std::toupper(static_cast<unsigned char>(c))));
    }
    if (upper == "UP")            { out = Direction::UP;            return true; }
    if (upper == "DOWN")          { out = Direction::DOWN;          return true; }
    if (upper == "BIDIRECTIONAL" || upper == "BIDI") {
        out = Direction::BIDIRECTIONAL; return true;
    }
    return false;
}

// ============================================================
// 单条业务订阅项 (CR-004 §3, §11.1)
// ============================================================
struct SubscriptionItem {
    std::string route_id;        // owner 内稳定唯一
    std::string topic_template;  // 保存模板，不固化设备实例值
    Direction direction = Direction::UP;
    uint8_t qos = 1;             // 0/1/2
    std::string target;          // 目标处理器，如 tsp.fota
    bool mandatory = false;
};

// ============================================================
// 完整版本化订阅快照 (CR-004 §3, §11.2)
// ============================================================
struct SubscriptionSnapshot {
    std::string owner;                       // 固定 "tsp"
    uint64_t generation = 0;                 // 集合语义变化时单调递增
    std::string content_digest;              // 规范化集合摘要 (SHA-256 hex)
    bool registration_complete = false;      // 是否包含全部 Mandatory 项
    std::vector<SubscriptionItem> items;
};

// ============================================================
// 快照提交结果状态 (CR-004 §5)
// ============================================================
enum class SnapshotStatus : uint8_t {
    ACCEPTED = 0,  // MQTT 已原子接受完整集合（≠ Broker SUBACK）
    REJECTED = 1,  // 快照整体未生效，无部分替换
    UNKNOWN = 2    // 结果未知，使用相同 owner/generation 查询或幂等重试
};

inline const char* snapshot_status_to_string(SnapshotStatus s) {
    switch (s) {
        case SnapshotStatus::ACCEPTED:  return "ACCEPTED";
        case SnapshotStatus::REJECTED:  return "REJECTED";
        case SnapshotStatus::UNKNOWN:   return "UNKNOWN";
        default: return "?";
    }
}

// replaceSubscriptionSnapshot 返回 (CR-004 §5)
struct ReplaceSnapshotResult {
    SnapshotStatus status = SnapshotStatus::UNKNOWN;
    uint64_t accepted_generation = 0;
    std::vector<std::string> rejected_route_ids;
    std::string reason_code;
};

// getSubscriptionSnapshotStatus 返回 (CR-004 §5)
struct SnapshotStatusResult {
    SnapshotStatus status = SnapshotStatus::UNKNOWN;
    uint64_t generation = 0;
    std::string content_digest;
    bool registration_complete = false;
};

// ============================================================
// 注册状态机 (CR-004 §9, §11.4)
// ============================================================
enum class RegistrationState : uint8_t {
    NOT_REGISTERED = 0,
    REGISTERING = 1,
    REGISTERED = 2,
    DEGRADED = 3
};

inline const char* registration_state_to_string(RegistrationState s) {
    switch (s) {
        case RegistrationState::NOT_REGISTERED: return "NOT_REGISTERED";
        case RegistrationState::REGISTERING:    return "REGISTERING";
        case RegistrationState::REGISTERED:     return "REGISTERED";
        case RegistrationState::DEGRADED:       return "DEGRADED";
        default: return "?";
    }
}

// 公开注册状态 (CR-004 §9)
struct RegistrationStatus {
    RegistrationState state = RegistrationState::NOT_REGISTERED;
    uint64_t generation = 0;
    std::string content_digest_hash;  // SHA-256 hex（已是哈希，可安全记录）
    uint32_t mandatory_count = 0;
    uint32_t item_count = 0;
    SnapshotStatus last_result = SnapshotStatus::UNKNOWN;
    std::string last_error;
    uint32_t retry_count = 0;
    uint64_t updated_at_ms = 0;
};

#if !TSP_MQTT_ROUTE_API
// 展开 Topic 模板：将 {ecu_uid} 替换为当前设备身份 (CR-004 §4, §11.1)。
// 禁止 device_sn 兜底；模板中 {device_sn} 由 SubscriptionCatalog 校验拦截。
// route 模式 (CR-006): TSP 不展开模板，由 MQTT 按 PROV 身份展开（本函数仅 legacy 使用）。
inline std::string expand_topic_template(const std::string& tmpl,
                                         const std::string& ecu_uid) {
    std::string out = tmpl;
    const std::string placeholder = "{ecu_uid}";
    size_t pos = 0;
    while ((pos = out.find(placeholder, pos)) != std::string::npos) {
        out.replace(pos, placeholder.size(), ecu_uid);
        pos += ecu_uid.size();
    }
    return out;
}
#endif  // !TSP_MQTT_ROUTE_API

} // namespace tsp
} // namespace tbox
