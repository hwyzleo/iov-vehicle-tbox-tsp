// TBOX-TSP-DSN-CR-010 §4.2 / VEH-PROTO §7: keyprov wire codec。
//
// 权威契约：PAR-PROTO security/keyprov/v1/key_provisioning.proto（VEH-PROTO §7 锁版）。
// TSP 侧锁版副本：proto/security/keyprov/v1/key_provisioning.proto。
// 所有 payload 统一放入 vehicle.common.v1.VehicleMessageEnvelope.payload，
// service=security.keyprov，protocol_version=keyprov-v1（整串 allowlist 精确匹配）。
//
// 安全边界：
//   - Wrapped Key / parameters 仅作为有界不透明密文 bytes 透传，不解析密码学内容；
//   - 解码后 wrapped_key/parameters 立即转为不可复制、可清零的 tbox::sec::SecureBuffer；
//   - 不提供任何把 keyprov payload 序列化为可读文本/JSON 的接口，日志禁止 dump payload。
//
// 资源上限（PAR-PROTO-DSN-CR-006 §4.3 / VEH-PROTO §7.5）：
//   payload<=16KiB, wrapped_key<=4KiB/item, parameters<=2KiB/item,
//   import_proof<=1KiB/item, 字符串<=128B（domain/算法<=64B）, 摘要<=64B, items<=8。
// 超限整体拒绝，不截断、不落盘、不回显内容。

#pragma once

#include <tbox/sec/business_key.h>

#include "mqtt_session_context.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace tsp {

// ============================================================
// 协议常量（VEH-PROTO §7）
// ============================================================
constexpr const char* kKeyprovService = "security.keyprov";
constexpr const char* kKeyprovProtocolVersion = "keyprov-v1";

constexpr const char* kKeyprovPayloadRequest =
    "security.keyprov.v1.KeyProvisioningRequest";
constexpr const char* kKeyprovPayloadResponse =
    "security.keyprov.v1.KeyProvisioningResponse";
constexpr const char* kKeyprovPayloadAck =
    "security.keyprov.v1.KeyProvisioningAck";
constexpr const char* kKeyprovPayloadAckResult =
    "security.keyprov.v1.KeyProvisioningAckResult";
constexpr const char* kKeyprovPayloadStatusRequest =
    "security.keyprov.v1.KeyProvisioningStatusRequest";
constexpr const char* kKeyprovPayloadStatusResponse =
    "security.keyprov.v1.KeyProvisioningStatusResponse";

// Normative 大小上限
constexpr std::size_t kKeyprovMaxPayloadBytes = 16 * 1024;
constexpr std::size_t kKeyprovMaxWrappedKeyBytes = 4 * 1024;
constexpr std::size_t kKeyprovMaxParametersBytes = 2 * 1024;
constexpr std::size_t kKeyprovMaxImportProofBytes = 1024;
constexpr std::size_t kKeyprovMaxItems = 8;
constexpr std::size_t kKeyprovMaxStringBytes = 128;
constexpr std::size_t kKeyprovMaxShortStringBytes = 64;
constexpr std::size_t kKeyprovMaxDigestBytes = 64;
constexpr std::size_t kKeyprovMaxMessageBytes = 256;

// 首期固定业务域 / 用途（V2C_COMM）
constexpr const char* kKeyprovBusinessDomainV2c = "V2C_COMM";
constexpr const char* kKeyprovPurposeUplink = "UPLINK_AEAD";
constexpr const char* kKeyprovPurposeDownlink = "DOWNLINK_AEAD";

// proto 关键枚举值（VEH-PROTO §7.2 固定，v1 永久保留；此处以命名常量引用，
// 避免 coordinator 直接依赖生成类型）
constexpr int kKeyProvPurposeUplinkValue = 1;      // KEY_PURPOSE_UPLINK_AEAD
constexpr int kKeyProvPurposeDownlinkValue = 2;    // KEY_PURPOSE_DOWNLINK_AEAD
constexpr int kKeyProvResultSucceeded = 1;         // KEY_PROVISIONING_RESULT_SUCCEEDED
constexpr int kKeyProvResultRetryableFailure = 2;  // KEY_PROVISIONING_RESULT_RETRYABLE_FAILURE
constexpr int kKeyProvStatusActive = 4;            // KEY_PROVISIONING_STATUS_ACTIVE
constexpr int kKeyProvImportImported = 1;          // KEY_IMPORT_RESULT_IMPORTED

// 支持的封装套件（proto enum 名，VEH-PROTO §7.2 allowlist）
constexpr const char* kKeyprovSuiteHpkeBaseX25519 =
    "WRAPPING_SUITE_HPKE_BASE_X25519_SHA256_AES128GCM";
constexpr const char* kKeyprovSuiteEcdhEsP256 =
    "WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM";

// ============================================================
// 会话身份（CR-011 §4）：三种上行身份必填，同源不可拼接
// ============================================================
//
// 结构完整性由 keyprov_validate_identity 判定；完整性不等于“可发布”，
// 也不代表证书已被云端认证。最终是否可发送由 MQTT daemon guard 判定。
struct KeyprovSessionIdentity {
    std::string ecu_uid;                   // MQTT leaf CN 规范值 ^[A-Z0-9-]{1,64}$
    std::string device_identity_digest;    // 与 UID 同源（sha256 等，可为 sha256:<hex>）
    std::string certificate_ref;           // 与 UID 同源（sha256:<hex>）
    MqttSessionContext session;            // daemon epoch + connection/cert 代际
};

// UID 规范校验：ASCII 大写字母/数字/连字符，长度 1..64。
// TSP 只验证规范值，不提供宽松修复（CR-011 §4）。
bool keyprov_is_canonical_uid(const std::string& uid);

// 摘要归一化：兼容 "sha256:<hex>" 与裸 hex（<= kKeyprovMaxDigestBytes），
// 其它 <= 上限的字符串按原 bytes 接受。失败时 out 为空。
bool keyprov_normalize_digest(const std::string& in, std::vector<uint8_t>& out);

// 结构性完整性校验（身份必填，无默认值、无兜底）：
//   - ecu_uid 非空且规范；
//   - device_identity_digest / certificate_ref 非空；
//   - session 完整（daemon_epoch 非空且两代际 > 0）。
// 失败返回 false 并写入脱敏 reason（不含完整 UID/身份值）。
bool keyprov_validate_identity(const KeyprovSessionIdentity& identity,
                               std::string& reason);

// ============================================================
// 编解码状态
// ============================================================
enum class KeyProvCodecStatus : uint8_t {
    Ok = 0,
    EnvelopeInvalid,            // Envelope 反序列化/字段缺失/方向错误
    UnsupportedPayloadType,     // payload_type 不在 allowlist
    ProtocolVersionMismatch,    // protocol_version != keyprov-v1
    ServiceMismatch,            // service != security.keyprov
    SizeExceeded,               // 超限（payload/字段/items）
    FieldInvalid,               // 关键字段非法/未知关键枚举/身份不一致
    Internal                    // 序列化失败
};

const char* keyprov_codec_status_to_string(KeyProvCodecStatus s);

// ============================================================
// 上行请求（KeyProvisioningRequest）
// ============================================================
struct KeyProvCertificateRef {
    std::string certificate_profile;              // <=64
    std::string key_encipherment_key_id;          // <=128
};

struct KeyProvCurrentVersion {
    int purpose = 0;                 // security.keyprov.v1.KeyPurpose
    uint64_t business_key_version = 0;
};

struct KeyProvRequestData {
    std::string request_id;                       // <=128
    std::string idempotency_key;                  // <=128
    std::string business_domain;                  // <=64
    std::vector<int> purposes;                    // {UPLINK, DOWNLINK}
    // CR-011 §4: device_identity_digest / certificate_ref.certificate_digest
    // 不再由调用方填写，统一由 builder 从必填的 KeyprovSessionIdentity 派生。
    KeyProvCertificateRef certificate_ref;
    std::vector<int> supported_wrapping_suites;   // <=8
    std::vector<KeyProvCurrentVersion> current_versions;  // <=8
    int64_t timestamp_ms = 0;
    int64_t expire_at_ms = 0;
};

// ============================================================
// 下行解码结果
// ============================================================
struct KeyProvProtocolError {
    std::string code;      // <=128
    bool retryable = false;
    std::string action;    // <=128
    std::string message;   // <=256
};

struct KeyProvResponseData {
    std::string request_id;
    int result = 0;       // security.keyprov.v1.KeyProvisioningResult
    int64_t expire_at_ms = 0;
    KeyProvProtocolError error;
    // Wrapped Key bundle（move-only SecureBuffer；调用后清零）
    std::vector<tbox::sec::WrappedKeyItem> items;
};

struct KeyProvAckResultData {
    std::string request_id;
    int result = 0;
    int64_t occurred_at_ms = 0;
    KeyProvProtocolError error;
};

struct KeyProvStatusItem {
    int purpose = 0;
    std::string key_id;
    uint64_t business_key_version = 0;
    int import_result = 0;  // security.keyprov.v1.KeyImportResult
};

struct KeyProvStatusResponseData {
    std::string request_id;
    int status = 0;  // security.keyprov.v1.KeyProvisioningStatus
    int64_t occurred_at_ms = 0;
    KeyProvProtocolError error;
    std::vector<KeyProvStatusItem> items;
};

enum class KeyProvMessageKind : uint8_t {
    Unknown = 0,
    Response,
    AckResult,
    StatusResponse
};

struct KeyProvDecoded {
    KeyProvMessageKind kind = KeyProvMessageKind::Unknown;
    std::string request_id;  // 公共关联标识（首个可用来源）
    std::string message_id;  // Envelope.message_id（用于 ACK correlation）
    KeyProvResponseData response;
    KeyProvAckResultData ack_result;
    KeyProvStatusResponseData status_response;
};

struct KeyProvDecodeOutcome {
    KeyProvCodecStatus status = KeyProvCodecStatus::Internal;
    KeyProvDecoded decoded;
    std::string reason;
};

// 上行 ACK 单项结果（来自 SEC ImportResult）
struct KeyProvImportItemResult {
    int purpose = 0;
    std::string key_id;      // <=128
    uint64_t business_key_version = 0;
    int result = 0;          // security.keyprov.v1.KeyImportResult
    std::vector<uint8_t> import_proof;   // <=1024
    std::string proof_algorithm;         // <=128
};

struct KeyProvEncodeOutcome {
    KeyProvCodecStatus status = KeyProvCodecStatus::Internal;
    std::vector<uint8_t> envelope_bytes;  // 完整序列化 VehicleMessageEnvelope
    std::string reason;
};

// ============================================================
// 编码（只产出完整 Envelope bytes；不产生可读 JSON）
// ============================================================
// identity 为必填参数：缺失/非法时返回 FieldInvalid，不产生可发送 Envelope。
// device_id 统一由公共 helper 从同一 identity 填写；Request 的身份摘要/引用
// 也从该 identity 派生，保证同源。
// message_id 为本次传输唯一标识；trace_id 可空。
KeyProvEncodeOutcome build_keyprov_request_envelope(
    const KeyprovSessionIdentity& identity,
    const KeyProvRequestData& in,
    const std::string& message_id,
    const std::string& trace_id);

// ACK：correlation_id 指向响应 message_id（可空）。
KeyProvEncodeOutcome build_keyprov_ack_envelope(
    const KeyprovSessionIdentity& identity,
    const std::string& request_id,
    const std::vector<KeyProvImportItemResult>& items,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& correlation_id);

// 状态对账请求：使用新 message_id，payload 保留原 request_id。
KeyProvEncodeOutcome build_keyprov_status_request_envelope(
    const KeyprovSessionIdentity& identity,
    const std::string& request_id,
    int64_t timestamp_ms,
    const std::string& message_id,
    const std::string& trace_id);

// ============================================================
// 解码（严格校验 service/protocol_version/payload_type/方向/大小）
// ============================================================
KeyProvDecodeOutcome decode_keyprov_envelope(
    const std::vector<uint8_t>& envelope_bytes);

// ============================================================
// 枚举/字符串映射
// ============================================================
int keyprov_purpose_from_string(const std::string& name);
std::string keyprov_purpose_to_string(int purpose);
int keyprov_wrapping_suite_from_string(const std::string& name);
std::string keyprov_wrapping_suite_to_string(int suite);
const char* keyprov_import_result_to_string(int result);

} // namespace tsp
} // namespace tbox
