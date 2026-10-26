// TBOX-TSP-DSN-CR-017 §6：KL1 coordinator 集成测试（fake UTC/monotonic 固定）。
//
// 覆盖：根因修复（过期响应不再无限重发）、KL1 租约准入导入携带 admission、
// E-U 余量等号、freshen 一次、Request 预算耗尽、D 后禁新 ACK、fail-closed。
// 共享向量 case 归属见 tests/fixtures/keyprov-kl1-v1/tsp_case_ownership.json。
#include <gtest/gtest.h>

#include "v2c_key_provisioning_coordinator.h"
#include "mocks.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

#include <chrono>
#include <string>

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using namespace security::keyprov::v1;
using vehicle::common::v1::MESSAGE_KIND_RESPONSE;
using vehicle::common::v1::VehicleMessageEnvelope;

namespace {

constexpr int64_t kT0 = 1800000000000LL;  // 共享向量固定 T0（绝非执行机器时间）

std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_kl1_coord_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}

std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// 带交付租约 E（field4=expire_at_ms）的 SUCCEEDED Response。
std::vector<uint8_t> make_response_envelope(const std::string& request_id,
                                            int64_t expire_at_ms) {
    KeyProvisioningResponse resp;
    resp.set_request_id(request_id);
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    resp.set_expire_at_ms(expire_at_ms);
    for (int i = 0; i < 2; ++i) {
        auto* it = resp.add_items();
        it->set_purpose(i == 0 ? KEY_PURPOSE_UPLINK_AEAD
                               : KEY_PURPOSE_DOWNLINK_AEAD);
        it->set_key_id(i == 0 ? "kid-up" : "kid-down");
        it->set_business_key_version(3);
        it->set_key_algorithm("AES-256");
        it->set_wrapping_suite(WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        it->set_wrapped_key(std::string(32, 'W'));
        it->set_parameters(std::string(8, 'P'));
        it->set_envelope_format(KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
        it->set_envelope_digest(std::string(32, '\xD1'));
        it->set_key_check_value(std::string(3, '\xC1'));
    }
    std::string payload;
    resp.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_request_id(request_id);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadResponse);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("msg-resp");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

std::vector<uint8_t> make_status_response_envelope(const std::string& request_id,
                                                   int status) {
    KeyProvisioningStatusResponse msg;
    msg.set_request_id(request_id);
    msg.set_status(static_cast<KeyProvisioningStatus>(status));
    msg.set_occurred_at_ms(1);
    std::string payload;
    msg.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_request_id(request_id);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadStatusResponse);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("msg-status");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

FakeSecClient::StatusItem status_item(const std::string& purpose, int state,
                                      uint64_t version) {
    FakeSecClient::StatusItem s;
    s.purpose = purpose;
    s.state = state;
    s.business_key_version = version;
    s.key_id = (purpose == kKeyprovPurposeUplink) ? "kid-up" : "kid-down";
    s.envelope_format =
        static_cast<int>(tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1);
    s.envelope_digest = std::vector<uint8_t>(32, 0xD1);
    s.key_check_value = std::vector<uint8_t>(3, 0xC1);
    s.import_proof = std::vector<uint8_t>(64, 0xE1);
    s.proof_algorithm = tbox::sec::kImportProofAlgorithmP1363;
    s.recipient_certificate_digest = std::vector<uint8_t>(32, 0xB1);
    return s;
}

RoutedDownlinkEvent downlink(const std::vector<uint8_t>& payload) {
    RoutedDownlinkEvent e;
    e.owner = "tsp";
    e.route_id = "keyprov.downlink";
    e.target = "tsp.keyprov";
    e.payload = payload;
    return e;
}

constexpr int kActive = 2;
constexpr int kCommitted = 2;
constexpr int kNotFound = 5;
constexpr int kStatusAckPending = 3;
constexpr int kStatusFailed = 5;

} // namespace

class V2cKl1CoordinatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        sec_ = std::make_shared<FakeSecClient>();
        store_root_ = temp_root();
        store_ = std::make_shared<V2cKeyProvisioningStore>(store_root_);
        cfg_.enabled = true;
        cfg_.request_timeout_ms = 500;
        cfg_.ack_timeout_ms = 500;
        cfg_.retry_initial_ms = 10;
        cfg_.retry_max_ms = 40;
        cfg_.poll_interval_ms = 5;
        cfg_.status_request_initial_interval_ms = 10;
        cfg_.status_request_max_interval_ms = 40;
        cfg_.not_found_stabilization_count = 3;
        cfg_.not_found_stabilization_window_ms = 10;
        cfg_.sec_import_timeout_ms = 5;
        cfg_.sec_callback_grace_ms = 5;
        coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_,
                                                                 store_);
        coord_->set_clock_sync_check([this] { return clock_synced_; });
        // fake UTC/monotonic：固定 T0，绝不使用执行机器时间（CR-017 §6）。
        coord_->set_clock_source(
            [this] { return clk_.utc_ms; },
            [this] { return clk_.mono_ms; },
            [this] {
                KeyprovClockSource c;
                c.utc_now_ms = clk_.utc_ms;
                c.monotonic_ms = clk_.mono_ms;
                c.uncertainty_ms = clk_.uncertainty;
                c.trusted = clk_.trusted;
                return c;
            });
        ASSERT_TRUE(coord_->initialize(cfg_));
        ASSERT_TRUE(coord_->start(false));
    }

    void TearDown() override {
        if (coord_) coord_->stop();
    }

    void make_ready(bool ready = true) {
        CloudReadiness cr;
        cr.cloud_ready = ready;
        cr.cert_session_generation = 1;
        cr.connection_generation = 1;
        cr.device_identity_digest = std::string(64, 'a');
        cr.certificate_ref = "sha256:" + std::string(64, 'a');
        cr.contract_supported = true;
        cr.contract_version = 3;
        cr.publish_contract_version = 1;
        cr.ecu_uid = "ECU-1";
        cr.session.daemon_epoch = "epoch-1";
        cr.session.connection_generation = 1;
        cr.session.cert_session_generation = 1;
        cr.event_sequence = ++cloud_seq_;
        mqtt_->deliver_cloud_readiness(cr);

        CapabilityReadiness cap;
        cap.capability = "security.keyprov";
        cap.ready = ready;
        cap.enabled = ready;
        cap.contract_supported = true;
        cap.snapshot_accepted = true;
        cap.uplink_ready = true;
        cap.downlink_suback_ready = true;
        cap.connection_generation = 1;
        cap.cert_session_generation = 1;
        mqtt_->deliver_capability_readiness(cap);
    }

    std::string make_first_request() {
        sec_->status_items.clear();
        make_ready();
        coord_->tick();
        return coord_->snapshot().request_id;
    }

    int publish_count_for(const std::string& route_id) const {
        int n = 0;
        for (const auto& c : mqtt_->publish_route_calls()) {
            if (c.route_id == route_id) ++n;
        }
        return n;
    }

    bool saw_ack() const {
        for (const auto& c : mqtt_->publish_route_calls()) {
            if (c.route_id != "keyprov.uplink") continue;
            VehicleMessageEnvelope env;
            if (!env.ParseFromArray(c.payload.data(),
                                    static_cast<int>(c.payload.size()))) {
                continue;
            }
            if (env.payload_type() == kKeyprovPayloadAck) return true;
        }
        return false;
    }

    // 仅统计应用层 Request（不含 StatusRequest，二者同走 keyprov.uplink）。
    int count_requests() const {
        int n = 0;
        for (const auto& c : mqtt_->publish_route_calls()) {
            if (c.route_id != "keyprov.uplink") continue;
            VehicleMessageEnvelope env;
            if (!env.ParseFromArray(c.payload.data(),
                                    static_cast<int>(c.payload.size()))) {
                continue;
            }
            if (env.payload_type() == kKeyprovPayloadRequest) ++n;
        }
        return n;
    }

    struct FakeClock {
        int64_t utc_ms = kT0;
        int64_t mono_ms = 0;
        uint32_t uncertainty = 0;
        bool trusted = true;
    } clk_;

    std::shared_ptr<MockMqttFacade> mqtt_;
    std::shared_ptr<FakeSecClient> sec_;
    std::shared_ptr<V2cKeyProvisioningStore> store_;
    std::string store_root_;
    V2cKeyProvisioningConfig cfg_;
    std::unique_ptr<V2cKeyProvisioningCoordinator> coord_;
    uint64_t cloud_seq_ = 0;
    bool clock_synced_ = true;
};

// ============================================================
// 根因修复：response_expired 不再回 RETRY_WAIT 无限重发（现场 attempt_count=22）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, ExpiredResponseBoundedNoInfiniteRetry) {
    std::string rid = make_first_request();
    const int requests_before = publish_count_for("keyprov.uplink");

    // VMD 永久返回已过期 bundle（E 已过）。
    coord_->handle_routed_downlink(downlink(
        make_response_envelope(rid, clk_.utc_ms - 1000)));
    EXPECT_EQ(coord_->snapshot().state,
              V2cKeyProvState::RECONCILE_OLD_ATTEMPT)
        << "过期响应必须进入只读对账，而不是 RETRY_WAIT";
    EXPECT_EQ(coord_->snapshot().last_error, "response_expired");

    // 推进时间多次 tick：不得产生新的应用层 Request（无 freshen 前提）。
    for (int i = 0; i < 20; ++i) {
        clk_.utc_ms += 100;
        clk_.mono_ms += 100;
        coord_->tick();
    }
    EXPECT_EQ(publish_count_for("keyprov.uplink"), requests_before)
        << "过期响应后不得无限重发 Request（KL-REQ-003）";
}

// ============================================================
// KL1 租约准入导入：携带 E/epoch/profile（TBOX-SEC-DSN-CR-023）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1ImportCarriesAdmissionAndAck) {
    sec_->kl1_supported = true;
    std::string rid = make_first_request();

    // 新鲜响应：E = U + 60000（LC02.fresh 语义）。
    const int64_t E = clk_.utc_ms + 60000;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    coord_->tick();

    ASSERT_EQ(sec_->kl1_import_calls.size(), 1u)
        << "KL1 模式必须走租约准入导入接口";
    EXPECT_EQ(sec_->kl1_import_calls[0].admission_expire_at_ms, E);
    EXPECT_EQ(sec_->kl1_import_calls[0].capability_epoch, 7u);   // SEC 权威 epoch
    EXPECT_EQ(sec_->kl1_import_calls[0].kl1_profile_version, 1u);
    EXPECT_TRUE(saw_ack()) << "双用途 COMMITTED 后必须恢复原 proof 发送 ACK";
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);
}

// ============================================================
// E-U < import_min（15000）：只读对账，不 import（LC02.-1）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1LeaseTooShortReadonly) {
    std::string rid = make_first_request();
    const int64_t E = clk_.utc_ms + 10000;  // E-U=10000 < 15000
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    EXPECT_EQ(coord_->snapshot().state,
              V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(coord_->snapshot().last_error, "lease_too_short");
    EXPECT_EQ(sec_->import_calls, 0);
}

// ============================================================
// U == E 等号即过期（LC02.0）：只读对账，不 import
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1LeaseExpiredEqualsGate) {
    std::string rid = make_first_request();
    const int64_t E = clk_.utc_ms;  // U==E：等号即过期
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    EXPECT_EQ(coord_->snapshot().state,
              V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(coord_->snapshot().last_error, "response_expired");
    EXPECT_EQ(sec_->import_calls, 0);
}

// ============================================================
// 过期 + ACK_PENDING + proven：至多一次同 rid freshen（LC16.first/LC16）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1FreshenOnceThenReadonly) {
    sec_->kl1_supported = true;
    std::string rid = make_first_request();

    // 先收到新鲜响应（记录 E），import 返回 NOT_FOUND -> 对账稳定化。
    sec_->import_state = kNotFound;
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(
        downlink(make_response_envelope(rid, clk_.utc_ms + 60000)));
    coord_->tick();  // import -> NOT_FOUND -> RECONCILE_EVIDENCE
    // 推进退避时间，完成 3 次强 NOT_FOUND + 稳定窗（fake monotonic 固定）。
    for (int i = 0; i < 8; ++i) {
        clk_.utc_ms += 50;
        clk_.mono_ms += 50;
        coord_->tick();
    }
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_REMOTE)
        << "3NF 稳定化后应 proven 并进入云端矩阵";

    // 云端 ACK_PENDING：缓存为待交付（freshen 前提）。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusAckPending)));

    // 推进时间使 E 过期 -> 设备主动 freshen（一次同 rid 新 Request）。
    clk_.utc_ms += 60000 + 1;  // U >= E
    clk_.mono_ms += 60000 + 1;
    const int requests_before = count_requests();
    coord_->tick();  // RECONCILE_REMOTE -> do_reconcile -> freshen
    EXPECT_EQ(count_requests(), requests_before + 1)
        << "过期 + proven + ACK_PENDING：应发送一次同 rid freshen";

    // 再次推进/对账：第二次 freshen 不得发生（仅 Status）。
    clk_.utc_ms += 1000;
    coord_->tick();
    coord_->tick();
    EXPECT_EQ(count_requests(), requests_before + 1)
        << "第二次过期不得再次 freshen（仅 Status）";
}

// ============================================================
// Request 持久预算：耗尽后只读，重启不重置（LC09.*）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1RequestBudgetExhaustedAfterLimit) {
    // 连续发送直到 Request 预算耗尽（现场 attempt_count=22 场景的边界）。
    std::string rid = make_first_request();  // Request #1
    const int limit = static_cast<int>(cfg_.kl1_request_limit);
    // 每 cycle：WAIT_RESPONSE 超时 -> RETRY_WAIT -> CHECKING -> REQUESTING -> 发送。
    // 推进量覆盖 retry jitter（max 50ms）保证退避必然越过。
    for (int i = 0; i < limit - 1; ++i) {
        clk_.utc_ms += cfg_.request_timeout_ms + 500;  // 越过 WAIT_RESPONSE deadline + jitter
        clk_.mono_ms += cfg_.request_timeout_ms + 500;
        coord_->tick();  // WAIT_RESPONSE -> on_response_timeout -> RETRY_WAIT
        clk_.utc_ms += 500;                             // 越过 retry backoff（含 jitter）
        clk_.mono_ms += 500;
        coord_->tick();  // RETRY_WAIT -> CHECKING -> REQUESTING
        coord_->tick();  // REQUESTING -> do_request（发送）
    }
    EXPECT_EQ(count_requests(), limit) << "预算内应发送满 limit 次";

    // 第 limit+1 次尝试：预算耗尽 -> 只读对账，不得再发。
    clk_.utc_ms += cfg_.request_timeout_ms + 500;
    clk_.mono_ms += cfg_.request_timeout_ms + 500;
    coord_->tick();
    clk_.utc_ms += 500;
    clk_.mono_ms += 500;
    coord_->tick();
    coord_->tick();
    EXPECT_EQ(count_requests(), limit)
        << "Request 预算耗尽后不得重发旧 ID（现场 count=22 场景）";
    EXPECT_EQ(coord_->snapshot().last_error, "request_budget_exhausted");
}

// ============================================================
// D 后禁新 ACK：只读 Status 确认（LC09.ack-D / LC14.after-D）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1AckDeadlineGate) {
    sec_->kl1_supported = true;
    std::string rid = make_first_request();
    const int64_t E = clk_.utc_ms + 60000;
    const int64_t D = E + 30000 - 2000;  // kl1_ack_grace - skew
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    coord_->tick();  // import -> ACK_PENDING（D 内首次 ACK）

    // 推进超过 D：重试 ACK 不得再发（仅 Status）。
    clk_.utc_ms = D + 1;
    const int acks_before = saw_ack() ? 1 : 0;
    coord_->tick();
    // do_ack_locked：D 已过 -> 不重发 ACK；仅 Status 确认。
    int acks_after = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(),
                                static_cast<int>(c.payload.size()))) {
            continue;
        }
        if (env.payload_type() == kKeyprovPayloadAck) ++acks_after;
    }
    EXPECT_EQ(acks_after, acks_before) << "D 后不得新增 ACK 投递";
}

// ============================================================
// KL1 完整 E2E（mock-VMD + FakeSec）：request -> fresh bundle -> 双用途 COMMITTED
// -> 原 proof ACK -> AckResult -> ACTIVE（共享向量 LC05/LC19 语义的 TSP 侧）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1FullFlowToActive) {
    sec_->kl1_supported = true;
    std::string rid = make_first_request();
    const int64_t E = clk_.utc_ms + 60000;

    // fresh bundle -> import（KL1 准入）-> COMMITTED -> ACK。
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    coord_->tick();
    ASSERT_TRUE(saw_ack());

    // 云端 AckResult SUCCEEDED -> ACTIVE（幂等；两用途 ACTIVE）。
    auto make_ack_result = [](const std::string& req_id, int result) {
        KeyProvisioningAckResult msg;
        msg.set_request_id(req_id);
        msg.set_result(static_cast<KeyProvisioningResult>(result));
        msg.set_occurred_at_ms(1);
        std::string payload;
        msg.SerializeToString(&payload);
        VehicleMessageEnvelope env;
        env.set_request_id(req_id);
        env.set_protocol_version("keyprov-v1");
        env.set_service("security.keyprov");
        env.set_payload_type(kKeyprovPayloadAckResult);
        env.set_message_kind(MESSAGE_KIND_RESPONSE);
        env.set_message_id("msg-ackres");
        env.set_payload(payload);
        std::string s;
        env.SerializeToString(&s);
        return to_bytes(s);
    };
    coord_->handle_routed_downlink(downlink(
        make_ack_result(rid, KEY_PROVISIONING_RESULT_SUCCEEDED)));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACTIVE);
    EXPECT_EQ(coord_->snapshot().active_transitions, 1u);
}

// ============================================================
// 预算观察指标：snapshot 输出剩余预算/截止（KL-REQ-003）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1BudgetObservability) {
    std::string rid = make_first_request();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.kl1_request_remaining, cfg_.kl1_request_limit - 1);
    EXPECT_EQ(snap.kl1_status_remaining, cfg_.kl1_readonly_limit);
    EXPECT_EQ(snap.kl1_sec_query_remaining, cfg_.kl1_readonly_limit);
    EXPECT_EQ(snap.kl1_ack_remaining, cfg_.kl1_ack_limit);
    EXPECT_EQ(snap.kl1_chain_remaining, cfg_.kl1_chain_ids);
}

// ============================================================
// fail-closed：新 SEC 快照存在但声明不支持租约准入 -> 阻断 import
// （TBOX-SEC-DSN-CR-023 §4：不走旧接口降级导入）
// ============================================================
TEST_F(V2cKl1CoordinatorTest, Kl1LeaseAdmissionUnsupportedFailClosed) {
    sec_->kl1_supported = true;
    sec_->kl1_lease_admission_supported = false;  // 快照成功但能力 false
    std::string rid = make_first_request();
    const int64_t E = clk_.utc_ms + 60000;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid, E)));
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    coord_->tick();
    EXPECT_EQ(sec_->import_calls, 0) << "能力不足不得走旧接口降级导入";
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::BLOCKED);
    EXPECT_EQ(coord_->snapshot().last_error, "sec_lease_admission_unsupported");
}
