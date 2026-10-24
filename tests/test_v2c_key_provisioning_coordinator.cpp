// TBOX-TSP-DSN-CR-010 §10: V2cKeyProvisioningCoordinator 单元测试。
#include <gtest/gtest.h>

#include "v2c_key_provisioning_coordinator.h"
#include "mocks.h"

#include "store.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <thread>

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using namespace security::keyprov::v1;
using vehicle::common::v1::MESSAGE_KIND_RESPONSE;
using vehicle::common::v1::VehicleMessageEnvelope;

namespace {

std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_keyprov_coord_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}

std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> make_response_envelope(const std::string& request_id,
                                            uint64_t version = 3) {
    KeyProvisioningResponse resp;
    resp.set_request_id(request_id);
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    for (int i = 0; i < 2; ++i) {
        auto* it = resp.add_items();
        it->set_purpose(i == 0 ? KEY_PURPOSE_UPLINK_AEAD
                               : KEY_PURPOSE_DOWNLINK_AEAD);
        it->set_key_id(i == 0 ? "kid-up" : "kid-down");
        it->set_business_key_version(version);
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

std::vector<uint8_t> make_ack_result_envelope(const std::string& request_id,
                                              int result) {
    KeyProvisioningAckResult msg;
    msg.set_request_id(request_id);
    msg.set_result(static_cast<KeyProvisioningResult>(result));
    msg.set_occurred_at_ms(1);
    std::string payload;
    msg.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_request_id(request_id);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadAckResult);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("msg-ackres");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

// CR-013：带 error（幂等冲突等）的 Response 下行。
std::vector<uint8_t> make_response_error_envelope(
    const std::string& request_id, int result, const std::string& code,
    const std::string& action = "", bool retryable = false) {
    KeyProvisioningResponse resp;
    resp.set_request_id(request_id);
    resp.set_result(static_cast<KeyProvisioningResult>(result));
    auto* e = resp.mutable_error();
    e->set_code(code);
    e->set_retryable(retryable);
    e->set_action(action);
    std::string payload;
    resp.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_request_id(request_id);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadResponse);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("msg-resp-err");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

// CR-013：StatusResponse 下行（状态对账）。
// retryable：CR-016 判定 806099 四元组需要显式 retryable=false。
std::vector<uint8_t> make_status_response_envelope(
    const std::string& request_id, int status, const std::string& code = "",
    const std::string& action = "", bool retryable = false) {
    KeyProvisioningStatusResponse msg;
    msg.set_request_id(request_id);
    msg.set_status(static_cast<KeyProvisioningStatus>(status));
    msg.set_occurred_at_ms(1);
    if (!code.empty()) {
        auto* e = msg.mutable_error();
        e->set_code(code);
        e->set_action(action);
        e->set_retryable(retryable);
    }
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
    s.key_id_digest = "digest-" + purpose;
    // CR-012 Q3 / CR-008：journal 返回原 ACK 绑定材料（与原 Response 一致）。
    s.key_id = (purpose == kKeyprovPurposeUplink) ? "kid-up" : "kid-down";
    s.envelope_format = static_cast<int>(tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1);
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

void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

constexpr int kActive = 2;
constexpr int kMissing = 0;
constexpr int kCommitted = 2;
constexpr int kImportUnknown = 4;
constexpr int kNotFound = 5;  // BusinessKeyImportState::NOT_FOUND（CR-014 唯一“无副作用”证明）
constexpr int kFailed = 3;    // BusinessKeyImportState::FAILED（有 journal 但失败，阻断）
constexpr int kUnknownErr = 1024;  // ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN

constexpr int kStatusActive = 4;
constexpr int kStatusFailed = 5;
constexpr int kStatusUnspecified = 0;
constexpr int kStatusRequested = 1;  // KEY_PROVISIONING_STATUS_REQUESTED

} // namespace

class V2cKeyProvisioningCoordinatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        sec_ = std::make_shared<FakeSecClient>();
        store_root_ = temp_root();
        store_ = std::make_shared<V2cKeyProvisioningStore>(store_root_);
        cfg_.enabled = true;
        cfg_.request_timeout_ms = 200;
        cfg_.ack_timeout_ms = 200;
        cfg_.retry_initial_ms = 10;
        cfg_.retry_max_ms = 40;
        cfg_.poll_interval_ms = 5;
        // CR-015：稳定化/StatusRequest 测试用小值配置（有界、可配）。
        cfg_.status_request_initial_interval_ms = 10;
        cfg_.status_request_max_interval_ms = 40;
        cfg_.not_found_stabilization_count = 3;
        cfg_.not_found_stabilization_window_ms = 10;
        cfg_.sec_import_timeout_ms = 5;
        cfg_.sec_callback_grace_ms = 5;
        coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
        coord_->set_clock_sync_check([this] { return clock_synced_; });
        ASSERT_TRUE(coord_->initialize(cfg_));
        ASSERT_TRUE(coord_->start(false));
    }

    void TearDown() override {
        if (coord_) coord_->stop();
    }

    void make_ready(bool ready = true, uint32_t contract_version = 3,
                    uint32_t publish_contract_version = 1,
                    const std::string& uid = "ECU-1",
                    uint64_t connection_generation = 1) {
        CloudReadiness cr;
        cr.cloud_ready = ready;
        cr.cert_session_generation = 1;
        cr.connection_generation = connection_generation;
        cr.device_identity_digest = std::string(64, 'a');
        cr.certificate_ref = "sha256:" + std::string(64, 'a');
        cr.contract_supported = true;
        cr.contract_version = contract_version;
        cr.publish_contract_version = publish_contract_version;
        // CR-011 §3: v3 会话身份投影（同一快照）。
        cr.ecu_uid = uid;
        cr.session.daemon_epoch = "epoch-1";
        cr.session.connection_generation = connection_generation;
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
        cap.connection_generation = connection_generation;
        cap.cert_session_generation = 1;
        mqtt_->deliver_capability_readiness(cap);
    }

    std::string make_first_request(bool ready = true) {
        sec_->status_items.clear();
        make_ready(ready);
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

    std::shared_ptr<MockMqttFacade> mqtt_;
    std::shared_ptr<FakeSecClient> sec_;
    std::shared_ptr<V2cKeyProvisioningStore> store_;
    std::string store_root_;
    V2cKeyProvisioningConfig cfg_;
    std::unique_ptr<V2cKeyProvisioningCoordinator> coord_;
    uint64_t cloud_seq_ = 0;
    bool clock_synced_ = true;

    // CR-013：同 UID 换证（接收证书摘要变化），同步更新 capability 代际以通过 gate。
    void deliver_cert_change(const std::string& cert_hex, uint64_t session_gen) {
        CloudReadiness cr = mqtt_->cloud_readiness;
        cr.certificate_ref = "sha256:" + cert_hex;
        cr.device_identity_digest = cert_hex;
        cr.cert_session_generation = session_gen;
        cr.session.cert_session_generation = session_gen;
        cr.event_sequence = ++cloud_seq_;
        mqtt_->deliver_cloud_readiness(cr);
        CapabilityReadiness cap = mqtt_->capability_readiness;
        cap.cert_session_generation = session_gen;
        mqtt_->deliver_capability_readiness(cap);
    }
};

TEST_F(V2cKeyProvisioningCoordinatorTest, DisabledWhenConfigOff) {
    cfg_.enabled = false;
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    make_ready();
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::DISABLED);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, WaitsForCapabilityBeforeRequest) {
    sec_->status_items.clear();
    // 不投递 readiness
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, ExistingActiveKeysSkipRequest) {
    sec_->status_items = {status_item(kKeyprovPurposeUplink, kActive, 5),
                          status_item(kKeyprovPurposeDownlink, kActive, 5)};
    make_ready();
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACTIVE);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, ClockNotSyncedHoldsRequestUntilSynced) {
    sec_->status_items.clear();  // 缺少业务密钥 -> 需要申请
    make_ready();
    clock_synced_ = false;       // 模拟冷启动早期 NTP 尚未校正
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_FALSE(snap.clock_synced);
    EXPECT_TRUE(snap.request_id.empty());
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);

    clock_synced_ = true;        // NTP 校正完成
    coord_->tick();
    snap = coord_->snapshot();
    EXPECT_TRUE(snap.clock_synced);
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 1);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, FirstProvisioningFullFlow) {
    sec_->status_items.clear();  // missing
    make_ready();
    coord_->tick();  // -> CHECKING -> REQUESTING -> publish
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    ASSERT_FALSE(snap.request_id.empty());
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 1);

    // 下行 RESPONSE
    coord_->handle_routed_downlink(downlink(make_response_envelope(snap.request_id)));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::IMPORTING);

    // SEC 原子导入成功
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_proof = {0x01, 0x02, 0x03};
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);
    EXPECT_EQ(sec_->import_calls, 1);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 2);  // Request + ACK

    // 云端确认 ACK
    coord_->handle_routed_downlink(downlink(make_ack_result_envelope(
        snap.request_id, KEY_PROVISIONING_RESULT_SUCCEEDED)));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACTIVE);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, MismatchedResponseRejected) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    auto snap = coord_->snapshot();
    ASSERT_FALSE(snap.request_id.empty());

    coord_->handle_routed_downlink(downlink(make_response_envelope("other-req")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_GE(coord_->snapshot().responses_rejected, 1u);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, ResponseTimeoutRetriesSameRequestId) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string r1 = coord_->snapshot().request_id;
    ASSERT_FALSE(r1.empty());

    sleep_ms(230);  // 超过 request_timeout
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RETRY_WAIT);

    sleep_ms(60);  // 超过 backoff
    coord_->tick();
    auto calls = mqtt_->publish_route_calls();
    ASSERT_GE(calls.size(), 2u);
    for (const auto& c : calls) {
        if (c.route_id == "keyprov.uplink") {
            EXPECT_EQ(c.request_id, r1);  // requestId 稳定
        }
    }
}

TEST_F(V2cKeyProvisioningCoordinatorTest, ImportUnknownConvergesToAck) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));

    // 导入结果未知
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    EXPECT_EQ(sec_->import_calls, 1);
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RETRY_WAIT);

    // SEC 件内已提交；后续查询返回 COMMITTED
    sec_->status_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->query_state = kCommitted;
    sec_->query_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                         status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_proof = {0x0A};
    sleep_ms(60);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);
    // 不得重复导入
    EXPECT_EQ(sec_->import_calls, 1);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, RestartRecoversAckPending) {
    // CR-013：走完整流程到 ACK_PENDING（冻结 snapshot/fingerprint 已持久化），
    // 再重启验证 ACK 恢复（不重复导入）。
    sec_->status_items.clear();  // missing
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kCommitted;
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_proof = {0x0B};
    coord_->tick();
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);
    const int import_before_restart = sec_->import_calls;  // 共享 FakeSecClient 累计

    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));

    sec_->status_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->query_state = kCommitted;
    sec_->query_items = sec_->status_items;
    sec_->import_proof = {0x0B};
    make_ready();
    coord_->tick();

    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);
    EXPECT_EQ(sec_->import_calls, import_before_restart);  // 不重复导入
    EXPECT_GE(publish_count_for("keyprov.uplink"), 1);  // 发送 ACK
    // 重启后非 legacy：fingerprint 已冻结。
    EXPECT_FALSE(coord_->snapshot().legacy_snapshot_unknown);
    EXPECT_EQ(coord_->snapshot().fingerprint_version, 1u);
}

// ============================================================
// CR-011 §5/§6: 身份门禁、expected_session 与按 reason 恢复
// ============================================================
TEST_F(V2cKeyProvisioningCoordinatorTest, GateRequiresReadinessV3) {
    sec_->status_items.clear();
    make_ready(true, /*contract_version=*/2, /*publish_contract=*/1);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, GateRequiresSessionBoundPublish) {
    sec_->status_items.clear();
    make_ready(true, 3, /*publish_contract=*/0);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().publish_session_supported);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, GateRequiresCanonicalUid) {
    sec_->status_items.clear();
    make_ready(true, 3, 1, "lower-uid");
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, GateRequiresNonzeroConnectionGeneration) {
    // CR-011 §5.1 / MQTT CR-017: daemon 未提交有效连接上下文（generation==0）时，
    // 会话上下文不完整，必须判定身份不可用，不得发 keyprov。
    sec_->status_items.clear();
    make_ready(true, /*contract_version=*/3, /*publish_contract=*/1, "ECU-1",
               /*connection_generation=*/0);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, RequestCarriesDeviceIdAndExpectedSession) {
    std::string rid = make_first_request();
    ASSERT_FALSE(rid.empty());
    auto calls = mqtt_->publish_route_calls();
    ASSERT_EQ(calls.size(), 1u);
    ASSERT_TRUE(calls[0].expected_session.has_value());
    EXPECT_EQ(calls[0].expected_session->daemon_epoch, "epoch-1");
    EXPECT_EQ(calls[0].expected_session->connection_generation, 1u);
    EXPECT_EQ(calls[0].expected_session->cert_session_generation, 1u);
    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(calls[0].payload.data(),
                                   (int)calls[0].payload.size()));
    EXPECT_EQ(env.device_id(), "ECU-1");
}

TEST_F(V2cKeyProvisioningCoordinatorTest, PublishStaleInvalidatesAndRetriesSameRequestId) {
    sec_->status_items.clear();
    make_ready();
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted,
                                   session_reason::kPublishContextStale, true};
    coord_->tick();  // 构造并发布 -> STALE
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());

    // 刷新后就绪：重新构造发送，业务 requestId 不变
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted, "", true};
    coord_->tick();
    auto calls = mqtt_->publish_route_calls();
    ASSERT_GE(calls.size(), 2u);
    EXPECT_EQ(calls.back().request_id, rid);
    ASSERT_TRUE(calls.back().expected_session.has_value());
}

TEST_F(V2cKeyProvisioningCoordinatorTest, PublishContextRequiredBlocks) {
    sec_->status_items.clear();
    make_ready();
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted,
                                   session_reason::kPublishContextRequired, false};
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::BLOCKED);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, PublishContextUnsupportedNotReady) {
    sec_->status_items.clear();
    make_ready();
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted,
                                   session_reason::kPublishContextUnsupported, false};
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().publish_session_supported);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, SessionIdentityInvalidBlocks) {
    sec_->status_items.clear();
    make_ready();
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted,
                                   session_reason::kSessionIdentityInvalid, false};
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::BLOCKED);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, DaemonEpochChangeRebuildsIdentity) {
    make_first_request();
    EXPECT_TRUE(coord_->snapshot().identity_valid);

    // 同 ready 但 daemon epoch 更新：立即失效，不跨 epoch 复用身份
    CloudReadiness cr = mqtt_->cloud_readiness;
    cr.session.daemon_epoch = "epoch-2";
    cr.event_sequence = 1;  // 新 epoch 内 sequence 重置
    mqtt_->deliver_cloud_readiness(cr);
    EXPECT_FALSE(coord_->snapshot().identity_valid);

    // 重新门禁后从新快照重建身份
    coord_->tick();
    EXPECT_TRUE(coord_->snapshot().identity_valid);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, EventSequenceGapInvalidatesIdentity) {
    make_first_request();
    EXPECT_TRUE(coord_->snapshot().identity_valid);

    CloudReadiness cr = mqtt_->cloud_readiness;
    cr.event_sequence = cloud_seq_ + 5;  // 缺口
    mqtt_->deliver_cloud_readiness(cr);
    EXPECT_FALSE(coord_->snapshot().identity_valid);
}

// ============================================================
// CR-012 §8: readiness 门禁（build-lock 由生成清单保证，SEC 能力逐项可关闭）
// ============================================================
TEST_F(V2cKeyProvisioningCoordinatorTest, SecCapabilityDownBlocksRequest) {
    sec_->status_items.clear();
    sec_->capability.secure_journal_replay_ready = false;
    make_ready();
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().readiness.all());
    EXPECT_EQ(coord_->snapshot().readiness.first_missing_reason(),
              "sec_journal_replay_not_ready");
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, SecCapabilityContractMismatchBlocksRequest) {
    sec_->status_items.clear();
    sec_->capability.capability_contract_version = 999;
    make_ready();
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_FALSE(coord_->snapshot().readiness.sec_envelope_v1_import_ready);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, ReadyDownReadyResumesSameRequestId) {
    std::string rid = make_first_request();
    ASSERT_FALSE(rid.empty());
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // SEC 能力 DOWN：暂停，不重发；保留业务 requestId。
    sec_->capability.atomic_dual_purpose_commit_ready = false;
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_EQ(coord_->snapshot().request_id, rid);
    int paused = publish_count_for("keyprov.uplink");

    // 恢复：同 requestId 继续（不生成新业务版本）。
    sec_->capability.atomic_dual_purpose_commit_ready = true;
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().request_id, rid);
    EXPECT_GE(publish_count_for("keyprov.uplink"), paused);
}

// ============================================================
// CR-012 §5: Response 完整转交 SEC（format/digest/KCV/suite）
// ============================================================
TEST_F(V2cKeyProvisioningCoordinatorTest, RequestDeclaresCanonicalSuiteAndEnvelopeFormat) {
    std::string rid = make_first_request();
    ASSERT_FALSE(rid.empty());
    auto calls = mqtt_->publish_route_calls();
    ASSERT_FALSE(calls.empty());
    VehicleMessageEnvelope env;
    ASSERT_TRUE(env.ParseFromArray(calls[0].payload.data(),
                                   (int)calls[0].payload.size()));
    KeyProvisioningRequest req;
    ASSERT_TRUE(req.ParseFromString(env.payload()));
    EXPECT_EQ(req.business_domain(), "V2C_COMM");
    ASSERT_EQ(req.purposes_size(), 2);
    EXPECT_EQ(req.purposes(0), KEY_PURPOSE_UPLINK_AEAD);
    EXPECT_EQ(req.purposes(1), KEY_PURPOSE_DOWNLINK_AEAD);
    // CR-012 §4：显式 ECDH suite + envelope v1，不声明未实现套件。
    ASSERT_EQ(req.supported_wrapping_suites_size(), 1);
    EXPECT_EQ(req.supported_wrapping_suites(0),
              WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
    ASSERT_EQ(req.supported_envelope_formats_size(), 1);
    EXPECT_EQ(req.supported_envelope_formats(0),
              KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, FullHandoverPassesEnvelopeBindingToSec) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_state = kCommitted;
    coord_->tick();

    ASSERT_EQ(sec_->last_import_items.size(), 2u);
    for (const auto& it : sec_->last_import_items) {
        EXPECT_EQ(it.wrapping_suite, tbox::sec::kWrappingSuiteEcdhEsP256);
        EXPECT_EQ(it.envelope_format,
                  static_cast<int>(tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1));
        EXPECT_EQ(it.envelope_digest, std::vector<uint8_t>(32, 0xD1));
        EXPECT_TRUE(it.key_check_value_present);
        EXPECT_EQ(it.key_check_value, (std::array<uint8_t, 3>{0xC1, 0xC1, 0xC1}));
        EXPECT_EQ(it.wrapped_key_size, 32u);
        EXPECT_EQ(it.parameters_size, 8u);
    }
}

// ============================================================
// CR-012 §6: ACK 每用途 P1363 Import Attestation
// ============================================================
TEST_F(V2cKeyProvisioningCoordinatorTest, AckCarriesPerPurposeP1363Attestation) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_state = kCommitted;
    coord_->tick();
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::ACK_PENDING);

    // 取最后一条 ACK 上行 payload。
    auto calls = mqtt_->publish_route_calls();
    bool found = false;
    KeyProvisioningAck ack;
    for (auto it = calls.rbegin(); it != calls.rend(); ++it) {
        if (it->route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(it->payload.data(), (int)it->payload.size())) continue;
        if (env.payload_type() != kKeyprovPayloadAck) continue;
        ASSERT_TRUE(ack.ParseFromString(env.payload()));
        found = true;
        break;
    }
    ASSERT_TRUE(found);
    ASSERT_EQ(ack.items_size(), 2);
    for (const auto& item : ack.items()) {
        EXPECT_EQ(item.import_proof_algorithm(),
                  IMPORT_PROOF_ALGORITHM_ECDSA_P256_SHA256_P1363);
        EXPECT_EQ(item.import_proof().size(), 64u);
        EXPECT_EQ(item.recipient_certificate_digest().size(), 32u);
        EXPECT_EQ(item.envelope_digest().size(), 32u);
        EXPECT_EQ(item.key_check_value().size(), 3u);
        EXPECT_EQ(item.envelope_format(), KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
        EXPECT_TRUE(item.proof_algorithm().empty());  // 遗留字段不得形成第二事实源
    }
}

TEST_F(V2cKeyProvisioningCoordinatorTest, PartialImportNeverSendsSuccessAck) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    // 只有一个 purpose 返回 ACTIVE，不构成完整批次。
    sec_->import_items = {status_item(kKeyprovPurposeUplink, kActive, 3)};
    sec_->import_state = kCommitted;
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::BLOCKED);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 1);  // 仅 Request，无 ACK
    for (const auto& c : mqtt_->publish_route_calls()) {
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        EXPECT_NE(env.payload_type(), kKeyprovPayloadAck);
    }
}

TEST_F(V2cKeyProvisioningCoordinatorTest, AckAttestationMissingBlocksAck) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    auto up = status_item(kKeyprovPurposeUplink, kActive, 3);
    auto down = status_item(kKeyprovPurposeDownlink, kActive, 3);
    down.import_proof = std::vector<uint8_t>(63, 0xE1);  // 非 64B
    sec_->import_items = {up, down};
    sec_->import_state = kCommitted;
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::BLOCKED);
    EXPECT_EQ(publish_count_for("keyprov.uplink"), 1);
}

// ============================================================
// CR-013：不可变 attempt / fingerprint / 806095 / supersede / legacy
// ============================================================
TEST_F(V2cKeyProvisioningCoordinatorTest, AttemptFrozenOnFirstRequest) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    auto snap = coord_->snapshot();
    ASSERT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_EQ(snap.fingerprint_version, 1u);
    EXPECT_FALSE(snap.legacy_snapshot_unknown);
    EXPECT_EQ(snap.attempts_created, 1u);
    // 提交证据已记录。
    EXPECT_FALSE(coord_->snapshot().request_id.empty());
}

TEST_F(V2cKeyProvisioningCoordinatorTest, CertificateChangeTriggersReconcileNoChangedRequest) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // 同 UID 换证：接收证书摘要变化（Wrapped Key 接收者绑定变化）。
    deliver_cert_change(std::string(64, 'b'), /*session_gen=*/2);

    // 身份失效暂停 deadline -> 重读快照重新评估：candidate != frozen -> RECONCILE。
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    // 换证同时改变 deviceIdentityDigest 与 recipientCertificateDigest（同源）；
    // dimension 取首个差异项（DEVICE_IDENTITY 或 CERTIFICATE），两者都合法。
    uint64_t fp_changes = 0;
    for (const auto& kv : snap.fingerprint_changes_total) {
        if (kv.first == "DEVICE_IDENTITY" || kv.first == "CERTIFICATE") {
            fp_changes += kv.second;
        }
    }
    EXPECT_GE(fp_changes, 1u);

    // 不得以原 requestId 发送变化后的 KeyProvisioningRequest（仅最初 1 次）。
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) {
            request_payloads++;
            EXPECT_EQ(c.request_id, rid);
        }
    }
    EXPECT_EQ(request_payloads, 1);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, CertSessionChangeSameLeafReusesRequestId) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());

    // cert session 代际变化但 leaf 摘要不变：业务 fingerprint 相同 -> 复用 requestId。
    deliver_cert_change(std::string(64, 'a'), /*session_gen=*/2);

    sleep_ms(230);
    coord_->tick();  // timeout -> RETRY_WAIT
    sleep_ms(60);
    coord_->tick();  // -> CHECKING -> candidate==frozen -> 复用原 requestId 重发
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_TRUE(snap.fingerprint_changes_total.empty());  // 未进入对账
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) {
            request_payloads++;
            EXPECT_EQ(c.request_id, rid);
        }
    }
    EXPECT_GE(request_payloads, 2);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, SecVersionChangeTriggersReconcile) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());

    // SEC 当前版本变化（缺失 -> 已登记版本，但仍未 ACTIVE）：业务输入变化。
    sec_->status_items = {status_item(kKeyprovPurposeUplink, kMissing, 5),
                          status_item(kKeyprovPurposeDownlink, kMissing, 5)};
    sleep_ms(230);
    coord_->tick();
    sleep_ms(60);
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_GE(snap.fingerprint_changes_total.count("CURRENT_VERSIONS"), 1u);
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
    }
    EXPECT_EQ(request_payloads, 1);  // 不发送变化后的 Request
}

TEST_F(V2cKeyProvisioningCoordinatorTest, RequestKeepsFrozenBusinessFieldsAcrossRetries) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());

    sleep_ms(230);
    coord_->tick();  // timeout -> RETRY_WAIT
    sleep_ms(60);
    coord_->tick();  // 复用原 requestId 重发
    // 重试的 Request 冻结业务字段（suite/format/purpose/版本）保持不变。
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() != kKeyprovPayloadRequest) continue;
        KeyProvisioningRequest req;
        ASSERT_TRUE(req.ParseFromString(env.payload()));
        EXPECT_EQ(req.request_id(), rid);
        EXPECT_EQ(req.current_versions_size(), 0);  // 冻结：SEC 未登记版本
        ASSERT_EQ(req.supported_wrapping_suites_size(), 1);
        EXPECT_EQ(req.supported_wrapping_suites(0),
                  WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        ASSERT_EQ(req.supported_envelope_formats_size(), 1);
        EXPECT_EQ(req.supported_envelope_formats(0),
                  KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1);
        EXPECT_EQ(req.device_identity_digest().size(), 32u);
        request_payloads++;
    }
    EXPECT_GE(request_payloads, 2);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, Response806095StopsRetryAndReconciles) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // 首次 Request 直接被云端以 806095 拒绝（Response.error）。
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.idempotency_conflicts_total, 1u);
    EXPECT_EQ(snap.conflict_vmd_code, "806095");
    EXPECT_GE(snap.blocked_reasons_total["IDEMPOTENCY_CONFLICT"], 1u);

    // 继续对账：SEC 证明无记录（NOT_FOUND）-> 发 StatusRequest，保持 RECONCILE，不重发 Request。
    sec_->query_state = kNotFound;
    sec_->query_error_code = 0;
    sleep_ms(300);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    int request_payloads = 0;
    bool saw_status_request = false;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
        if (env.payload_type() == kKeyprovPayloadStatusRequest) saw_status_request = true;
    }
    EXPECT_EQ(request_payloads, 1);
    EXPECT_TRUE(saw_status_request);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, Status806095LeadsToAwaitCloudTermination) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;  // SEC 证明无记录
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    // 进入对账：首次 Request 被 806095 拒绝。
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // 对账 Status 返回幂等冲突 -> VMD 有未终结旧批次 -> 待云端终结。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806095")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kAwaitCloudTermination);
    EXPECT_GE(snap.blocked_reasons_total[
                  keyprov_blocked_reason::kAwaitCloudTermination], 1u);
    EXPECT_GE(snap.idempotency_conflicts_total, 2u);  // Response + Status
}

TEST_F(V2cKeyProvisioningCoordinatorTest, VmdFailedSupersedesRemoteCreatesNewAttempt) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;  // SEC 证明无记录（唯一可释放条件）
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 已终结（FAILED）+ SEC 无副作用 -> SUPERSEDED_REMOTE -> 新 attempt。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);  // 新 attempt 已发布
    EXPECT_NE(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_GE(snap.attempts_created, 2u);
}

// CR-014 用户裁决：UNSPECIFIED 无协议冻结语义证明“批次不存在/已终结释放”，
// 一律 fail-closed，不得当作可释放终态（不再从 UNSPECIFIED 触发 SUPERSEDED_LOCAL）。
TEST_F(V2cKeyProvisioningCoordinatorTest, UnspecifiedNotFoundFailsClosed) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;  // SEC 证明无记录
    // 首次 attempt：publish 被 STALE 拒绝（从未提交成功，submission=NONE）。
    mqtt_->publish_route_result = {false, MqttDeliveryOutcome::Accepted,
                                   session_reason::kPublishContextStale, true};
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_CLOUD);

    // 证书变化 -> candidate != frozen -> RECONCILE（从未提交，无提交证据）。
    deliver_cert_change(std::string(64, 'b'), /*session_gen=*/2);
    mqtt_->publish_route_result = {true, MqttDeliveryOutcome::Accepted, "", true};
    coord_->tick();  // gate + WAIT_CLOUD -> CHECKING -> RECONCILE
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 无批次（UNSPECIFIED）+ SEC NOT_FOUND：UNSPECIFIED 不可证明“不存在”，
    // fail-closed -> 等待云端终结，不得建新 attempt、不得 SUPERSEDED_LOCAL。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecImportNotFound);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_local, 0u);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);  // 未建新 attempt
}

// 回归：SEC journal outcome unknown 时，禁止新 attempt，但必须继续发 VMD
// StatusRequest（CR-013 §8 / SPEC §20.2：SEC journal 与 VMD Status 双路对账），
// 不能把 UNKNOWN 当作已消费终态导致对账卡死、无限退避。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecUnknownKeepsVmdStatusReconciliation) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // 首次 Request 被 806095 拒绝 -> 进入对账。
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // SEC 查询持续返回 outcome unknown。
    sec_->query_error_code = kUnknownErr;  // ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN
    coord_->tick();

    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);

    // 关键断言：SEC unknown 仍发出 VMD StatusRequest（修复前不会发）。
    int request_payloads = 0;
    int status_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
        if (env.payload_type() == kKeyprovPayloadStatusRequest) status_payloads++;
    }
    EXPECT_GE(status_payloads, 1);
    EXPECT_EQ(request_payloads, 1);  // 未创建新 Request

    // 等待 StatusResponse 期间再次 tick：保持 RECONCILE，不重复发 Status、不发新 Request。
    coord_->tick();
    snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
}

// 回归：SEC outcome unknown 期间 VMD 已终结（FAILED）也不得建新 attempt
// （CR-013 §9：outcome unknown 禁止新 attempt）；SEC 恢复明确无副作用后才收敛。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecUnknownBlocksNewAttemptUntilSecResolves) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 已终结（FAILED），但 SEC 仍 unknown：保持对账、不建新 attempt。
    sec_->query_error_code = kUnknownErr;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);  // 未建新 attempt

    // SEC 恢复为明确无副作用（NOT_FOUND）-> VMD FAILED 才允许 SUPERSEDED_REMOTE 建新 attempt。
    sec_->query_error_code = 0;
    sec_->query_state = kNotFound;  // SEC 证明无记录
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);  // 新 attempt 已发布
    EXPECT_NE(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_GE(snap.attempts_created, 2u);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, LegacyRecordBlocksNewRequest) {
    // 写旧版多键记录（缺 snapshot/fingerprint）。
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", store_root_);
        raw.save<std::string>("keyprov.v2c.present", "1");
        raw.save<std::string>("keyprov.v2c.request_id", "kp-legacy");
        raw.save<std::string>("keyprov.v2c.state", "WAIT_RESPONSE");
        raw.flush();
    }
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->query_state = kNotFound;  // SEC 证明无记录
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_TRUE(snap.legacy_snapshot_unknown);
    EXPECT_EQ(snap.state, V2cKeyProvState::LEGACY_SNAPSHOT_UNKNOWN);
    EXPECT_EQ(snap.legacy_store_records, 1u);
    // 不发送 KeyProvisioningRequest（默认阻断）。
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
    }
    EXPECT_EQ(request_payloads, 0);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, LegacyWithSecCommittedRecoversAck) {
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", store_root_);
        raw.save<std::string>("keyprov.v2c.present", "1");
        raw.save<std::string>("keyprov.v2c.request_id", "kp-legacy");
        raw.save<std::string>("keyprov.v2c.state", "ACK_PENDING");
        raw.flush();
    }
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->status_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                          status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->query_state = kCommitted;
    sec_->query_items = sec_->status_items;
    sec_->import_proof = {0x0C};
    make_ready();
    coord_->tick();  // LEGACY -> SEC journal COMMITTED -> 恢复 ACK
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::ACK_PENDING);
    EXPECT_EQ(sec_->import_calls, 0);  // 不重复导入
    bool saw_ack = false;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadAck) saw_ack = true;
    }
    EXPECT_TRUE(saw_ack);
}

TEST_F(V2cKeyProvisioningCoordinatorTest, LateOldRequestIdResultIsolated) {
    // 旧 requestId 的迟到结果（supersede 后）不得推进新 attempt。
    sec_->status_items.clear();
    sec_->query_state = kNotFound;  // SEC 证明无记录
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    // 终结旧批次 -> 新 attempt（新 requestId）。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    std::string new_rid = coord_->snapshot().request_id;
    ASSERT_NE(new_rid, rid);

    // 旧 requestId 的迟到 Response：requestId 不匹配 -> 隔离，不推进新 attempt。
    auto state_before = coord_->snapshot().state;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    EXPECT_EQ(coord_->snapshot().state, state_before);
    EXPECT_EQ(coord_->snapshot().request_id, new_rid);
    EXPECT_GE(coord_->snapshot().responses_rejected, 1u);
}

// ============================================================
// TBOX-TSP-DSN-CR-014：SEC import result 对账与释放
// ============================================================

// FAILED journal（有记录但失败）不得等同 NOT_FOUND：VMD FAILED 仍保持对账，
// 不得释放建新 attempt（CR-014 §3/§21.3 决策矩阵第 4 行回归）。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecFailedJournalBlocksRelease) {
    sec_->status_items.clear();
    sec_->query_state = kFailed;  // journal 存在但失败
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 已终结（FAILED）+ SEC journal FAILED：fail-closed，保持对账。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.sec_evidence_kind, "FAILED");
}

// QUERY_ERROR（传输/解析失败）：即使 VMD FAILED 也不得释放（CR-014 §3）。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecQueryErrorBlocksRelease) {
    sec_->status_items.clear();
    sec_->query_state = kCommitted;  // 结果无效（ec 非 SUCCESS 时忽略）
    sec_->query_error_code = static_cast<int>(tbox::sec::ErrorCode::CONNECTION_FAILED);
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.sec_evidence_kind, "QUERY_ERROR");
}

// 未知枚举（数值无法识别）-> ContractUnknown -> 保持阻断，不得释放（CR-014 §3）。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecContractUnknownBlocksRelease) {
    sec_->status_items.clear();
    sec_->query_state = 99;  // 未知数值（wire 层归一化前的防御路径）
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.sec_evidence_kind, "CONTRACT_UNKNOWN");
}

// REQUESTED/STAGED（事务痕迹存在）-> SEC_IMPORT_IN_PROGRESS 诊断区分，保持阻断。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecImportInProgressReasonDiagnostic) {
    sec_->status_items.clear();
    sec_->query_state = 0;  // BusinessKeyImportState::REQUESTED
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecImportInProgress);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.sec_evidence_kind, "OUTCOME_UNKNOWN");
}

// 非终态（REQUESTED）+ SEC NOT_FOUND -> BLOCKED_AWAIT_CLOUD_TERMINATION +
// SEC_IMPORT_NOT_FOUND（矩阵第 3 行：等待云端终结，不建新 attempt）。
TEST_F(V2cKeyProvisioningCoordinatorTest, NonTerminalNotFoundBlocksAwait) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusRequested)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecImportNotFound);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// CR-015：已调用 SEC import（结果待定）+ SEC NOT_FOUND -> 不再永久 EVIDENCE_CONFLICT
// 阻断；进入稳定化（RECONCILE_EVIDENCE -> STABILIZING_NOT_FOUND），
// 连续强 NOT_FOUND 达成后按云端终态释放（VMD FAILED + 缓存 -> 唯一 successor）。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       SecImportInvocationNotFoundStabilizesThenReleases) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    // 进入导入：调用 SEC import API（import invocation 被记录）。
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;  // 结果待定（pending callback）
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    ASSERT_EQ(sec_->import_calls, 1);
    EXPECT_TRUE(coord_->snapshot().import_invocation_recorded);
    EXPECT_EQ(coord_->snapshot().import_invocation_resolution, "UNRESOLVED");
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RETRY_WAIT);

    // 退避后重发 Request，收到 806095 -> 对账（import 证据仍在）。
    sleep_ms(60);
    coord_->tick();  // -> CHECKING -> REQUESTING -> WAIT_RESPONSE
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // SEC 无记录 + 本地已有 import invocation：VMD FAILED 不得立即释放，
    // 进入稳定化（STABILIZING_NOT_FOUND，count=1，不建新 attempt）。
    sec_->query_state = kNotFound;
    sec_->query_error_code = 0;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::STABILIZING_NOT_FOUND);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kStabilizingSecNotFound);
    EXPECT_EQ(snap.sec_not_found_count, 1u);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);

    // 连续强 NOT_FOUND 稳定化（同能力代际、窗口已满足）：count=2 -> count=3
    // -> NO_SIDE_EFFECT_PROVEN -> 缓存 VMD FAILED -> 唯一 successor
    // （新 attempt 重置计数，故不再断言 count=3）。
    sleep_ms(30);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().sec_not_found_count, 2u);
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::STABILIZING_NOT_FOUND);
    sleep_ms(30);
    coord_->tick();
    snap = coord_->snapshot();
    EXPECT_EQ(snap.import_invocation_resolution, "NO_SIDE_EFFECT_PROVEN");
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);  // 新 attempt 已发布
    EXPECT_NE(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_GE(snap.attempts_created, 2u);
}

// 导入中直接查询 NOT_FOUND（import 已调用但 SEC 无记录）-> 稳定化入口
// （RECONCILE_EVIDENCE），不再永久 EVIDENCE_CONFLICT 阻断。
TEST_F(V2cKeyProvisioningCoordinatorTest, ImportPendingThenNotFoundEntersStabilization) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;  // 首次导入结果待定
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    ASSERT_EQ(sec_->import_calls, 1);
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RETRY_WAIT);

    // 重发 Request -> 再次 IMPORTING -> 重新 import 返回 NOT_FOUND + 已调用记录
    // -> RECONCILE_EVIDENCE（稳定化入口，不立即释放）。
    sleep_ms(60);
    coord_->tick();  // -> WAIT_RESPONSE
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kNotFound;  // 再次导入即返回 NOT_FOUND
    sec_->import_error_code = 0;
    coord_->tick();  // do_import -> NOT_FOUND + invocation -> RECONCILE_EVIDENCE
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_EVIDENCE);
    EXPECT_EQ(snap.import_invocation_resolution, "UNRESOLVED");
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kStabilizingSecNotFound);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// 稳定化期间 SEC journal 变为 COMMITTED（新权威事实）-> 恢复原 ACK。
TEST_F(V2cKeyProvisioningCoordinatorTest, StabilizingResolvesOnCommitted) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    sleep_ms(60);
    coord_->tick();
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::STABILIZING_NOT_FOUND);
    EXPECT_EQ(coord_->snapshot().blocked_reason,
              keyprov_blocked_reason::kStabilizingSecNotFound);

    // 新权威事实：SEC journal 变为 COMMITTED（import 实际完成）-> 恢复 ACK。
    sec_->query_state = kCommitted;
    sec_->query_items = {status_item(kKeyprovPurposeUplink, kActive, 3),
                         status_item(kKeyprovPurposeDownlink, kActive, 3)};
    sec_->import_proof = {0x1F};
    sleep_ms(60);  // 退避到期后稳定化分支只读重查
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::ACK_PENDING);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 0u);  // 不得释放
    bool saw_ack = false;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadAck) saw_ack = true;
    }
    EXPECT_TRUE(saw_ack);
}

// CR-014 §21.5：RECONCILE 尊重退避，不形成约 200ms 固定 StatusRequest 风暴。
TEST_F(V2cKeyProvisioningCoordinatorTest, ReconcileBackoffPreventsStatusStorm) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    coord_->tick();  // 对账：发第一个 StatusRequest
    const uint64_t first = coord_->snapshot().status_requests_sent;
    EXPECT_GE(first, 1u);

    // 连续快速 tick（模拟 200ms 轮询）：未收到响应前不重复发 Status。
    for (int i = 0; i < 10; ++i) coord_->tick();
    EXPECT_EQ(coord_->snapshot().status_requests_sent, first);

    // deadline 超时 -> 进入退避；退避未到期前 tick 不得再发。
    sleep_ms(250);
    coord_->tick();  // 处理 deadline -> schedule_retry（退避 10ms 起）
    coord_->tick();  // 退避未到期 -> 不发
    EXPECT_EQ(coord_->snapshot().status_requests_sent, first);

    // 退避到期 -> 再发一个（受指数退避约束，非固定 200ms）。
    sleep_ms(60);
    coord_->tick();
    EXPECT_GE(coord_->snapshot().status_requests_sent, first + 1);
    EXPECT_LE(coord_->snapshot().status_requests_sent, first + 3);
}

// 重启恢复：Store 持久化 import_invocation（resolution=UNRESOLVED）-> 重启后
// SEC NOT_FOUND -> 稳定化入口（不再永久 EVIDENCE_CONFLICT 阻断；“可能已调用”
// 保守，不因重启丢失本地安全调用证据，也不因旧计数直接释放）。
TEST_F(V2cKeyProvisioningCoordinatorTest, RestartRestoresImportInvocationStabilization) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    ASSERT_TRUE(coord_->snapshot().import_invocation_recorded);
    EXPECT_EQ(coord_->snapshot().import_invocation_resolution, "UNRESOLVED");

    // 重启（import_invocation + resolution 已持久化）。
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->query_state = kNotFound;
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    EXPECT_TRUE(coord_->snapshot().import_invocation_recorded);  // Store 恢复
    EXPECT_EQ(coord_->snapshot().import_invocation_resolution, "UNRESOLVED");

    // 再次发送 -> 806095 -> 对账 -> SEC NOT_FOUND + 恢复的 import invocation
    // -> STABILIZING_NOT_FOUND（稳定化计数，不立即释放）。
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::STABILIZING_NOT_FOUND);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kStabilizingSecNotFound);
    EXPECT_EQ(snap.sec_not_found_count, 1u);
    EXPECT_EQ(snap.superseded_remote, 0u);
}

// 可观测性：snapshot 暴露脱敏 SEC 证据分类与 import invocation。
TEST_F(V2cKeyProvisioningCoordinatorTest, SecEvidenceObservability) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->tick();  // 对账：SEC 查询 -> NOT_FOUND
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.sec_evidence_kind, "NOT_FOUND");
    EXPECT_FALSE(snap.import_invocation_recorded);
}

// ============================================================
// TBOX-TSP-DSN-CR-015 §9.1：NOT_FOUND 稳定化单元测试
// ============================================================

// v3 恢复：import_invocation=true + BLOCKED(EVIDENCE_CONFLICT) -> 迁移为
// UNRESOLVED + RECONCILE_EVIDENCE，首个强 NOT_FOUND 后进入稳定化，不立即释放。
TEST_F(V2cKeyProvisioningCoordinatorTest, V3RestoreInvocationTrueEntersStabilization) {
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", store_root_);
        nlohmann::json j = nlohmann::json::object();
        j["schema_version"] = 3;
        j["fingerprint_version"] = 1;
        j["attempt_fingerprint"] = std::string(64, 'a');
        j["request_id"] = "kp-v3";
        j["idempotency_digest"] = "deadbeef";
        j["state"] = "BLOCKED";
        j["blocked_reason"] = "EVIDENCE_CONFLICT";
        j["submission"] = keyprov_submission::kSubmitted;
        j["import_invocation"] = true;
        j["sec_import_evidence_kind"] =
            static_cast<int>(SecImportEvidenceKind::NotFound);
        j["store_generation"] = 3;
        raw.save<std::string>("keyprov.v2c.attempt.v2", j.dump());
        raw.flush();
    }
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->query_state = kNotFound;
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    auto snap = coord_->snapshot();
    // v3 迁移：invocation=true -> UNRESOLVED；BLOCKED+EVIDENCE_CONFLICT -> RECONCILE_EVIDENCE。
    EXPECT_EQ(snap.import_invocation_resolution, "UNRESOLVED");
    EXPECT_EQ(snap.recovery_phase, keyprov_recovery_phase::kStabilizingSecNotFound);
    EXPECT_EQ(snap.state, V2cKeyProvState::STABILIZING_NOT_FOUND);  // 首个 NOT_FOUND 计数
    EXPECT_EQ(snap.sec_not_found_count, 1u);
    EXPECT_EQ(snap.superseded_remote, 0u);  // 不立即释放
    EXPECT_EQ(snap.attempts_created, 0u);  // 恢复记录不计数新 attempt
}

// 稳定化期间出现 UNKNOWN/QueryError：计数清零并 fail-closed，不得释放。
TEST_F(V2cKeyProvisioningCoordinatorTest, StabilizationResetOnContraryEvidence) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    sleep_ms(60);
    coord_->tick();
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    // 第一次 NOT_FOUND -> count=1。
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    EXPECT_EQ(coord_->snapshot().sec_not_found_count, 1u);
    // 第二次查询 UNKNOWN（QueryError）-> 计数清零 fail-closed，保持对账。
    sec_->query_state = kCommitted;
    sec_->query_error_code = kUnknownErr;
    sleep_ms(30);
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.sec_not_found_count, 0u);
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// SEC capability epoch 变化（重启/能力代际）-> 稳定化计数清零重新累计。
TEST_F(V2cKeyProvisioningCoordinatorTest, StabilizationResetsOnSecEpochChange) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    sleep_ms(60);
    coord_->tick();
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    EXPECT_EQ(coord_->snapshot().sec_not_found_count, 1u);
    // SEC capability 查询失败（重启边界）-> 恢复后视为新 epoch。
    sec_->capability_error_code =
        static_cast<int>(tbox::sec::ErrorCode::CONNECTION_FAILED);
    sleep_ms(30);
    coord_->tick();  // 查询失败：epoch unknown
    sec_->capability_error_code = 0;
    sleep_ms(30);
    coord_->tick();  // 恢复：新 epoch -> 稳定化清零重新累计
    auto snap = coord_->snapshot();
    EXPECT_GE(snap.sec_not_found_stabilization_total["RESET_EPOCH_CHANGED"], 1u);
    EXPECT_EQ(snap.sec_not_found_count, 1u);
    EXPECT_EQ(snap.superseded_remote, 0u);
}

// 首次强 NOT_FOUND 即更新 pending_callback=false：不再用入口快照制造冲突。
TEST_F(V2cKeyProvisioningCoordinatorTest, NotFoundUsesUpdatedPendingCallback) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;   // pending callback
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    ASSERT_TRUE(coord_->snapshot().import_invocation_recorded);
    sleep_ms(60);
    coord_->tick();
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    // SEC NOT_FOUND：进入稳定化（pending 快照不再构成永久冲突）。
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::STABILIZING_NOT_FOUND);
    EXPECT_EQ(snap.sec_not_found_count, 1u);
    EXPECT_EQ(snap.superseded_remote, 0u);
}

// VMD ACTIVE/SUCCEEDED + SEC NOT_FOUND：不得重开，进入 AWAIT_REMOTE_REPAIR
// （只读查询 + 人工/云端终结治理，绝不新建 attempt）。
TEST_F(V2cKeyProvisioningCoordinatorTest, VmdActiveLeadsToAwaitRemoteRepair) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusActive)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::AWAIT_REMOTE_REPAIR);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kAwaitRemoteRepair);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(sec_->import_calls, 0);
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
    }
    EXPECT_EQ(request_payloads, 1);  // 仅首次 Request
}

// VMD FAILED + proven：只 supersede 一次；重复/迟到 FAILED 响应不建第二 successor。
TEST_F(V2cKeyProvisioningCoordinatorTest, RepeatedFailedResponseSingleSupersede) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    std::string new_rid = coord_->snapshot().request_id;
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_NE(new_rid, rid);
    EXPECT_EQ(snap.attempts_created, 2u);
    // 旧 requestId 的重复 FAILED 响应：迟到隔离，不建第二 successor。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusFailed)));
    snap = coord_->snapshot();
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_EQ(snap.request_id, new_rid);
    EXPECT_EQ(snap.attempts_created, 2u);
}

// 稳定化达成（proven）后出现矛盾证据 -> HARD_CONFLICT / HARD_BLOCKED，人工治理。
TEST_F(V2cKeyProvisioningCoordinatorTest, ContradictionAfterProvenHardBlocks) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    sleep_ms(60);
    coord_->tick();
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    // 无 VMD 响应；连续 3 次 NOT_FOUND（同 epoch、窗口满足）-> proven -> RECONCILE_REMOTE。
    sec_->query_state = kNotFound;
    sleep_ms(30);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().sec_not_found_count, 1u);
    sleep_ms(30);
    coord_->tick();
    EXPECT_EQ(coord_->snapshot().sec_not_found_count, 2u);
    sleep_ms(30);
    coord_->tick();
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.import_invocation_resolution, "NO_SIDE_EFFECT_PROVEN");
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_REMOTE);
    EXPECT_EQ(snap.superseded_remote, 0u);
    // proven 后出现矛盾证据（UNKNOWN）-> HARD_CONFLICT，禁止自动释放。
    sec_->query_error_code = kUnknownErr;
    sleep_ms(30);
    coord_->tick();
    snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::HARD_BLOCKED);
    EXPECT_EQ(snap.import_invocation_resolution, "HARD_CONFLICT");
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kHardEvidenceConflict);
    EXPECT_GE(snap.hard_conflicts_total[
                  keyprov_blocked_reason::kHardEvidenceConflict], 1u);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// 分类函数层：no_residue_proven 仅由“新 SEC + 强类型 NOT_FOUND + contract>=CR-021”派生；
// 旧契约 NOT_FOUND 不得派生（不进入稳定化）。
TEST(KeyProvisioningClassifierTest, NoResidueProvenRequiresCr021Contract) {
    tbox::sec::ImportResult res;
    res.state = tbox::sec::BusinessKeyImportState::NOT_FOUND;
    auto ev1 = sec_classify_import_result(tbox::sec::ErrorCode::SUCCESS, res,
                                          /*contract=*/2);
    EXPECT_EQ(ev1.kind, SecImportEvidenceKind::NotFound);
    EXPECT_TRUE(ev1.no_residue_proven);
    auto ev0 = sec_classify_import_result(tbox::sec::ErrorCode::SUCCESS, res,
                                          /*contract=*/1);
    EXPECT_EQ(ev0.kind, SecImportEvidenceKind::NotFound);
    EXPECT_FALSE(ev0.no_residue_proven);  // 旧契约：不可进入稳定化
    // 查询失败：QueryError，never no_residue_proven。
    auto evq = sec_classify_import_result(
        tbox::sec::ErrorCode::CONNECTION_FAILED, res, /*contract=*/2);
    EXPECT_EQ(evq.kind, SecImportEvidenceKind::QueryError);
    EXPECT_FALSE(evq.no_residue_proven);
}

// ============================================================
// TBOX-TSP-DSN-CR-016 §9.1/§9.3：可释放 UNSPECIFIED 与唯一 successor
// ============================================================

// proven + UNSPECIFIED + 806099/false/DO_NOT_RETRY：
// 恰好一次 SUPERSEDED_REMOTE，创建唯一 successor 并发送新 Request（不再永久轮询）。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       Unspecified806099ReleasableCreatesUniqueSuccessor) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;  // SEC 证明无记录（proven）
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // 首次 Request 被 806095 拒绝 -> 对账（resolution 保持 proven）。
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    ASSERT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 无批次：status=UNSPECIFIED + 806099 + retryable=false + DO_NOT_RETRY。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);  // 新 attempt 已发布
    EXPECT_NE(snap.request_id, rid);
    EXPECT_TRUE(snap.request_id.rfind("kp-", 0) == 0);
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_GE(snap.attempts_created, 2u);
    // 唯一后继 digest 已生成（审计；与新 requestId 一致）。
    EXPECT_FALSE(snap.successor_request_id_digest.empty());
    EXPECT_EQ(snap.successor_request_id_digest,
              tbox::fw::hash::sha256_hex(snap.request_id));
    // 新 Request 已实际发布（冷启动现场链路：无人工介入自动收敛）。
    int request_payloads = 0;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        VehicleMessageEnvelope env;
        if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
        if (env.payload_type() == kKeyprovPayloadRequest) request_payloads++;
    }
    EXPECT_GE(request_payloads, 2);  // 旧 Request + successor Request
}

// 重复同一 StatusResponse / 旧 requestId 迟到响应：不产生第二个 successor。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       Unspecified806099RepeatedResponseSingleSuccessor) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    std::string new_rid = coord_->snapshot().request_id;
    ASSERT_NE(new_rid, rid);
    EXPECT_EQ(coord_->snapshot().superseded_remote, 1u);

    // 旧 requestId 的重复 806099 响应：迟到隔离，不建第二 successor。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.superseded_remote, 1u);
    EXPECT_EQ(snap.request_id, new_rid);
    EXPECT_EQ(snap.attempts_created, 2u);
    EXPECT_GE(snap.responses_rejected, 1u);
}

// 806099 但 retryable=true：协议不自洽，fail-closed，不得释放。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       Unspecified806099RetryableTrueFailsClosed) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY", /*retryable=*/true)));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecImportNotFound);
    EXPECT_EQ(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// 806099 但 action 缺失 / 未知（QUERY_STATUS_LATER）：fail-closed。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       Unspecified806099WrongActionFailsClosed) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    // 未知 action。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "QUERY_STATUS_LATER")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.request_id, rid);
    // action 缺失（空）：同样 fail-closed。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099", "")));
    snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
}

// UNSPECIFIED 但 error 缺失（无 806099）：fail-closed，不得当作可释放终态。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       UnspecifiedWithoutErrorFailsClosed) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified)));  // 无 error
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecImportNotFound);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.request_id, rid);
}

// UNSPECIFIED 但 code 非 806099：fail-closed（不做 message 文本匹配）。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       UnspecifiedNon806099CodeFailsClosed) {
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "804010",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.request_id, rid);
}

// UNRESOLVED（import invocation 未稳定化）：即使完整 806099 四元组也不释放。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       UnresolvedBlocks806099Release) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    // 调用 SEC import（结果待定）-> UNRESOLVED。
    coord_->handle_routed_downlink(downlink(make_response_envelope(rid)));
    sec_->import_state = kImportUnknown;
    sec_->import_error_code = kUnknownErr;
    coord_->tick();
    ASSERT_TRUE(coord_->snapshot().import_invocation_recorded);
    EXPECT_EQ(coord_->snapshot().import_invocation_resolution, "UNRESOLVED");

    sleep_ms(60);
    coord_->tick();  // -> WAIT_RESPONSE
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // SEC NOT_FOUND -> 稳定化计数（UNRESOLVED 未 proven）；806099 不释放。
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_GE(snap.sec_not_found_count, 1u);
    EXPECT_NE(snap.import_invocation_resolution, "NO_SIDE_EFFECT_PROVEN");
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.request_id, rid);
}

// SEC outcome unknown：即使完整 806099 四元组也不释放；SEC 恢复 proven 后才释放。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       SecUnknownBlocks806099UntilProven) {
    sec_->status_items.clear();
    make_ready();
    coord_->tick();
    std::string rid = coord_->snapshot().request_id;
    coord_->handle_routed_downlink(downlink(
        make_response_error_envelope(rid, KEY_PROVISIONING_RESULT_REJECTED, "806095")));
    EXPECT_EQ(coord_->snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // SEC outcome unknown：806099 不得释放。
    sec_->query_error_code = kUnknownErr;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kSecOutcomeUnknown);
    EXPECT_EQ(snap.superseded_remote, 0u);
    EXPECT_EQ(snap.attempts_created, 1u);
    EXPECT_EQ(snap.request_id, rid);

    // SEC 恢复 NOT_FOUND（proven）后同一 806099 响应才释放。
    sec_->query_error_code = 0;
    sec_->query_state = kNotFound;
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope(rid, kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_NE(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 1u);
}

// 崩溃点：supersede 已持久化（旧 record 终态化 + successor 已落盘）、新 record
// 未创建。重启后必须复用同一 successor，不生成第二个 requestId（CR-016 §6.2/§9.2）。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       RestartAfterSupersedePersistRestoresSameSuccessor) {
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", store_root_);
        nlohmann::json j = nlohmann::json::object();
        j["schema_version"] = 4;
        j["fingerprint_version"] = 1;
        j["attempt_fingerprint"] = std::string(64, 'a');
        j["request_id"] = "kp-old";
        j["idempotency_digest"] = "deadbeef";
        j["state"] = "SUPERSEDED_REMOTE";
        j["submission"] = keyprov_submission::kSubmitted;
        j["import_invocation"] = false;
        j["import_invocation_resolution"] =
            static_cast<int>(ImportInvocationResolution::NO_SIDE_EFFECT_PROVEN);
        j["store_generation"] = 1;
        j["successor_request_id"] = "kp-pre";
        j["successor_request_id_digest"] =
            tbox::fw::hash::sha256_hex("kp-pre");
        nlohmann::json snap = nlohmann::json::object();
        snap["business_domain"] = kKeyprovBusinessDomainV2c;
        snap["purposes"] = nlohmann::json::array({1, 2});
        snap["current_versions"] = nlohmann::json::array();
        snap["device_identity_digest"] = std::string(64, 'a');
        snap["recipient_certificate_digest"] = std::string(64, 'a');
        snap["certificate_ref_digest"] = std::string(64, 'a');
        snap["wrapping_suites"] = nlohmann::json::array({2});
        snap["envelope_formats"] = nlohmann::json::array({1});
        snap["protocol_lock_digest"] = std::string(64, 'a');
        j["snapshot"] = snap;
        raw.save<std::string>("keyprov.v2c.attempt.v2", j.dump());
        raw.flush();
    }
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->status_items.clear();
    make_ready();
    coord_->tick();  // SUPERSEDED_REMOTE -> create_new_attempt：复用 kp-pre

    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_EQ(snap.request_id, "kp-pre");  // 复用同一 successor
    EXPECT_GE(snap.attempts_created, 1u);
    EXPECT_EQ(snap.successor_request_id_digest,
              tbox::fw::hash::sha256_hex("kp-pre"));
    // 发布的新 Request 必须携带复用后的 requestId。
    bool saw_pre_request = false;
    for (const auto& c : mqtt_->publish_route_calls()) {
        if (c.route_id != "keyprov.uplink") continue;
        if (c.request_id == "kp-pre") saw_pre_request = true;
    }
    EXPECT_TRUE(saw_pre_request);
}

// 冷启动现场：proven record 恢复 + VMD 对不存在批次返回 806099
// -> 自动新 Request（无人工介入），原 requestId 停止持续轮询。
TEST_F(V2cKeyProvisioningCoordinatorTest,
       ColdStartProvenRecordWith806099CreatesNewAttempt) {
    {
        hwyz::store::Store raw = hwyz::store::Store::open("tsp", store_root_);
        nlohmann::json j = nlohmann::json::object();
        j["schema_version"] = 4;
        j["fingerprint_version"] = 1;
        j["attempt_fingerprint"] = std::string(64, 'b');
        j["request_id"] = "kp-cold";
        j["idempotency_digest"] = "cafe";
        j["state"] = "RECONCILE_REMOTE";
        j["submission"] = keyprov_submission::kSubmitted;
        j["import_invocation"] = false;
        j["import_invocation_resolution"] =
            static_cast<int>(ImportInvocationResolution::NO_SIDE_EFFECT_PROVEN);
        j["store_generation"] = 1;
        nlohmann::json snap = nlohmann::json::object();
        snap["business_domain"] = kKeyprovBusinessDomainV2c;
        snap["purposes"] = nlohmann::json::array({1, 2});
        snap["current_versions"] = nlohmann::json::array();
        snap["device_identity_digest"] = std::string(64, 'a');
        snap["recipient_certificate_digest"] = std::string(64, 'a');
        snap["certificate_ref_digest"] = std::string(64, 'a');
        snap["wrapping_suites"] = nlohmann::json::array({2});
        snap["envelope_formats"] = nlohmann::json::array({1});
        snap["protocol_lock_digest"] = std::string(64, 'a');
        j["snapshot"] = snap;
        raw.save<std::string>("keyprov.v2c.attempt.v2", j.dump());
        raw.flush();
    }
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
    coord_->set_clock_sync_check([this] { return clock_synced_; });
    ASSERT_TRUE(coord_->initialize(cfg_));
    ASSERT_TRUE(coord_->start(false));
    sec_->status_items.clear();
    sec_->query_state = kNotFound;
    make_ready();
    coord_->tick();  // RECONCILE_REMOTE -> SEC NOT_FOUND proven -> 发 StatusRequest

    // VMD 无批次：UNSPECIFIED + 806099/false/DO_NOT_RETRY -> 释放并新建 attempt。
    coord_->handle_routed_downlink(downlink(
        make_status_response_envelope("kp-cold", kStatusUnspecified, "806099",
                                      "DO_NOT_RETRY")));
    auto snap = coord_->snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_NE(snap.request_id, "kp-cold");
    EXPECT_EQ(snap.superseded_remote, 1u);
    // 原 requestId 轮询终止：无 806099 持续 StatusRequest 风暴。
    EXPECT_GE(snap.status_requests_sent, 1u);
}


int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}