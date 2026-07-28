// TBOX-TSP 公共 DTO (CR-003 §4, §5, SPEC §5.2)
//
// 本头由 daemon (TspIpcDispatcher/TspEventPublisher) 与 client SDK
// (tbox::tsp::TspClient) 共享，构成双方的 protocol contract。
// 调用方不接触 method_id、JSON/base64、socket。

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

// ============================================================
// 上行：FOTA 版本清单快照 (CR-003 §4)
// ============================================================
struct FotaSnapshot {
    uint32_t snapshot_seq = 0;       // 幂等键之一
    std::string msg_id;              // 幂等键之二 / IPC 重试与查询关联键
    std::string content_type = "application/x-protobuf";
    std::vector<uint8_t> payload;    // 原始二进制（wire 层 base64，不进日志）
    std::string trace_id;            // 合法且长度受限的上行关联标识
    std::string request_id;
};

// ============================================================
// 下行：FOTA 云端命令 (CR-003 §5)
// ============================================================
struct FotaCommand {
    std::string command_id;          // 业务幂等键
    std::string delivery_id;         // 投递幂等键（断线重放判定）
    std::string schema_version;
    std::string content_type = "application/x-protobuf";
    std::vector<uint8_t> payload;    // 原始二进制（wire 层 base64）
    std::string trace_id;
    std::string request_id;
};

// ============================================================
// 中继状态 (CR-003 §2, SPEC §5.2)
// ============================================================
enum class RelayState : uint8_t {
    UNKNOWN = 0,
    ACCEPTED,    // TSP 已校验并由 MQTT daemon 接管（≠ Broker PUBACK）
    PUBLISHED,   // MQTT daemon 已发送
    ACKED,       // Broker 已 PUBACK
    FAILED       // 失败
};

inline const char* relay_state_to_string(RelayState s) {
    switch (s) {
        case RelayState::UNKNOWN:   return "UNKNOWN";
        case RelayState::ACCEPTED:  return "ACCEPTED";
        case RelayState::PUBLISHED: return "PUBLISHED";
        case RelayState::ACKED:     return "ACKED";
        case RelayState::FAILED:    return "FAILED";
        default: return "?";
    }
}

struct RelayStatus {
    RelayState state = RelayState::UNKNOWN;
    std::string msg_id;
    uint32_t snapshot_seq = 0;
    int32_t error_code = 0;          // TBOX-TSP-10xx 业务状态码
    std::string last_error;
};

// ============================================================
// 上行发布结果语义 (CR-003 §4)
// ============================================================
enum class PublishOutcome : uint8_t {
    ACCEPTED,   // TSP 已校验并经 mqtt_client 接管
    UNKNOWN     // 响应丢失，仅可复用相同 msg_id 查询/单次重试
};

struct ReportResult {
    bool accepted = false;                       // TSP 已校验并由 MQTT daemon 接管
    PublishOutcome outcome = PublishOutcome::ACCEPTED;
    int32_t error_code = 0;                      // TBOX-TSP-10xx
    std::string msg_id;                          // 回显，用于 unknown 时查询/重试
};

} // namespace tsp
} // namespace tbox
