// TBOX-TSP-DSN-CR-010 §3.1: V2cKeyProvisioningCoordinator。
//
// 在 TspRelayService 内聚：消费 MQTT Cloud/Capability Readiness，查询 SEC 件内状态，
// 创建/恢复稳定 requestId，经 keyprov.uplink 发起申请，接收 Wrapped Key bundle，
// 调用 SEC 原子导入并幂等回传 ACK，持久化非敏感状态。
//
// 安全边界（CR §7 / SEC CR-019）：TSP 不解析/打印/持久化 Wrapped Key 内容；
// wrapped_key/parameters 只在有界 SecureBuffer 中短暂存在并立即交给 SEC。
//
// 门禁（CR §8，采用 (c)：MQTT capability ready 已足够，不设独立云端能力条件）：
//   KEYPROV_READY = enabled
//     AND codec/SEC API 可用（编译期）
//     AND SEC 业务密钥能力可用（运行时由 SEC 返回码判定）
//     AND MQTT capability ready（含 contract/snapshot/uplink/downlink SUBACK/cloud session）
//     AND 当前证书身份摘要可见
// 任一不满足不得发送 Request、不得置 ACTIVE，且不阻塞共享 Cloud Ready。

#pragma once

#include "keyprov_protocol.h"
#include "mqtt_facade.h"
#include "sec_business_key_facade.h"
#include "v2c_key_provisioning_store.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tbox {
namespace tsp {

struct V2cKeyProvisioningConfig {
    bool enabled = false;                 // production default false（release-set 显式开启）
    std::string business_domain = "V2C_COMM";
    std::vector<std::string> purposes = {"UPLINK_AEAD", "DOWNLINK_AEAD"};
    std::string route_up = "keyprov.uplink";
    std::string route_down = "keyprov.downlink";
    std::string certificate_profile = "mqtt";
    uint32_t request_timeout_ms = 10000;
    uint32_t ack_timeout_ms = 10000;
    uint32_t max_attempts_before_alert = 8;
    uint32_t retry_initial_ms = 500;
    uint32_t retry_max_ms = 30000;
    double retry_multiplier = 2.0;
    bool retry_jitter = true;
    uint32_t poll_interval_ms = 200;      // worker tick
};

enum class V2cKeyProvState : uint8_t {
    DISABLED = 0,
    WAIT_CLOUD,
    CHECKING,
    REQUESTING,
    WAIT_RESPONSE,
    IMPORTING,
    ACK_PENDING,
    ACTIVE,
    RETRY_WAIT,
    BLOCKED
};

const char* v2c_key_prov_state_to_string(V2cKeyProvState s);
bool v2c_key_prov_state_from_string(const std::string& s, V2cKeyProvState& out);

struct V2cKeyProvisioningSnapshot {
    V2cKeyProvState state = V2cKeyProvState::DISABLED;
    std::string request_id;
    bool capability_ready = false;
    bool identity_valid = false;            // CR-011 §18.3: 当前是否有有效会话身份
    bool publish_session_supported = false; // CR-011 §18.3: MQTT 支持 session-bound publish
    std::string reason_code;
    uint32_t attempt_count = 0;
    std::string last_error;
    uint64_t cloud_session_generation = 0;
    bool sec_api_available = false;
    bool clock_synced = false;               // 系统时钟是否已同步（时间敏感请求门禁）
    // 脱敏计数器
    uint64_t cloud_ready_events = 0;
    uint64_t requests_published = 0;
    uint64_t responses_received = 0;
    uint64_t responses_rejected = 0;
    uint64_t imports_committed = 0;
    uint64_t imports_failed = 0;
    uint64_t imports_unknown = 0;
    uint64_t acks_sent = 0;
    uint64_t ack_results_received = 0;
    uint64_t active_transitions = 0;
    uint64_t status_requests_sent = 0;
};

class V2cKeyProvisioningCoordinator {
public:
    V2cKeyProvisioningCoordinator(std::shared_ptr<MqttFacade> mqtt,
                                  std::shared_ptr<SecBusinessKeyFacade> sec,
                                  std::shared_ptr<V2cKeyProvisioningStore> store);
    ~V2cKeyProvisioningCoordinator();

    V2cKeyProvisioningCoordinator(const V2cKeyProvisioningCoordinator&) = delete;
    V2cKeyProvisioningCoordinator& operator=(const V2cKeyProvisioningCoordinator&) = delete;

    // 恢复 Store 非敏感状态、订阅 readiness 事件（start 时）。
    bool initialize(const V2cKeyProvisioningConfig& config);

    // 订阅 Cloud/Capability readiness 事件并启动 worker（stop 前一直有效）。
    // start_monitor=false 时不启后台线程，供测试通过 tick() 驱动。
    bool start(bool start_monitor = true);

    // 进入 STOPPING：拒绝新申请与 callback。
    void beginShutdown();

    // 停止：join worker、清零临时 Wrapped Key 缓冲（内存态）。
    void stop();

    // 下行入口（TspRelayService 在 DownlinkRouteDispatcher 注册 owner=tsp +
    // route_id=keyprov.downlink + target=tsp.keyprov）。
    void handle_routed_downlink(const RoutedDownlinkEvent& event);

    // 单次状态推进（生产由 worker 调用；测试直接调用）。
    void tick();

    V2cKeyProvisioningSnapshot snapshot() const;

    // 注入时钟同步判定（默认读 systemd-timesyncd 同步标记；测试可覆盖）。
    // keyprov Request 携带绝对 expire_at_ms，冷启动早期时钟未同步时必须等待，
    // 否则发送即被云端按过期拒绝（见 /run/systemd/timesync/synchronized）。
    void set_clock_sync_check(std::function<bool()> check);

private:
    // ---- readiness 回调（MQTT SDK 执行器线程） ----
    void on_cloud_readiness(const CloudReadiness& readiness);
    void on_capability_readiness(const CapabilityReadiness& readiness);

    // 需持有 mutex_ 的状态推进
    void tick_locked();
    void do_check_locked();
    void do_request_locked();
    void do_import_locked();
    void handle_import_result_locked(tbox::sec::ErrorCode ec,
                                     const tbox::sec::ImportResult& result);
    void do_ack_locked();
    void on_response_timeout_locked();
    void schedule_retry_locked();
    void persist_locked();
    void worker_loop();
    void reset_to_checking_locked();

    bool capability_gate_locked(std::string& reason);
    // 系统时钟是否已同步（未注入时读 systemd-timesyncd 标记）。
    bool clock_check_ok() const;
    // CR-011 §5.1/§18.3: 失效缓存身份与未发送传输任务（保留业务 requestId）。
    void invalidate_identity_locked(const char* reason);
    // CR-011 §5.1: 对账并接受 readhip 快照（epoch/sequence/generation 变化处理）。
    void apply_cloud_readiness_locked(const CloudReadiness& readiness);
    void apply_capability_readiness_locked(const CapabilityReadiness& readiness);
    // 主动重查 MQTT 当前快照（构造后切换/STALE 后对账）。
    void refresh_readiness_locked();
    // CR-011 §5.2: 携 expected_session 发布；按 reason 分流，成功返回 true。
    bool publish_keyprov_locked(const std::string& message_id,
                                const std::vector<uint8_t>& envelope_bytes,
                                const std::string& request_id);
    bool keyprov_response_valid_locked(const KeyProvResponseData& resp,
                                       std::string& err) const;
    uint32_t current_backoff_ms_locked() const;
    bool purposes_complete_locked(const std::vector<tbox::sec::BusinessKeyStatus>& items) const;

    static int64_t now_ms();
    static std::string generate_id(const char* prefix);

    std::shared_ptr<MqttFacade> mqtt_;
    std::shared_ptr<SecBusinessKeyFacade> sec_;
    std::shared_ptr<V2cKeyProvisioningStore> store_;
    V2cKeyProvisioningConfig config_;

    mutable std::mutex mutex_;
    V2cKeyProvState state_ = V2cKeyProvState::DISABLED;
    V2cKeyProvisioningRecord record_;

    // readiness 缓存
    CloudReadiness cloud_;
    CapabilityReadiness capability_;
    KeyprovSessionIdentity identity_;   // 门禁通过后由同一快照生成的不可变身份
    bool identity_valid_ = false;
    bool publish_session_supported_ = false;
    uint64_t last_cloud_sequence_ = 0;  // 同一 daemon epoch 内事件序列对账
    bool capability_ready_ = false;
    bool clock_synced_ = false;
    std::function<bool()> clock_sync_check_;
    std::string gate_reason_;

    // in-flight（内存态；pending_items_ 持有 move-only SecureBuffer）
    std::vector<tbox::sec::WrappedKeyItem> pending_items_;
    bool import_attempted_ = false;
    std::vector<KeyProvImportItemResult> ack_items_;
    bool ack_sent_ = false;
    bool status_sent_ = false;
    bool recovering_ack_ = false;
    std::string last_response_message_id_;
    int64_t deadline_ms_ = 0;
    int64_t next_retry_ms_ = 0;
    uint32_t backoff_ms_ = 0;
    bool capability_event_seen_ = false;

    // worker
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::thread worker_;
    std::condition_variable cv_;
    bool start_monitor_ = true;

    mutable V2cKeyProvisioningSnapshot counters_;
};

} // namespace tsp
} // namespace tbox
