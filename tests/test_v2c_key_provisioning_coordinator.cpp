// TBOX-TSP-DSN-CR-010 §10: V2cKeyProvisioningCoordinator 单元测试。
#include <gtest/gtest.h>

#include "v2c_key_provisioning_coordinator.h"
#include "mocks.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"

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
        it->set_key_algorithm("AES-256-GCM");
        it->set_wrapped_key(std::string(32, 'W'));
        it->set_parameters(std::string(8, 'P'));
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

FakeSecClient::StatusItem status_item(const std::string& purpose, int state,
                                      uint64_t version) {
    FakeSecClient::StatusItem s;
    s.purpose = purpose;
    s.state = state;
    s.business_key_version = version;
    s.key_id_digest = "digest-" + purpose;
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
constexpr int kUnknownErr = 1024;  // ErrorCode::BUSINESS_KEY_IMPORT_UNKNOWN

} // namespace

class V2cKeyProvisioningCoordinatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        mqtt_ = std::make_shared<MockMqttFacade>();
        sec_ = std::make_shared<FakeSecClient>();
        store_ = std::make_shared<V2cKeyProvisioningStore>(temp_root());
        cfg_.enabled = true;
        cfg_.request_timeout_ms = 200;
        cfg_.ack_timeout_ms = 200;
        cfg_.retry_initial_ms = 10;
        cfg_.retry_max_ms = 40;
        cfg_.poll_interval_ms = 5;
        coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
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
    V2cKeyProvisioningConfig cfg_;
    std::unique_ptr<V2cKeyProvisioningCoordinator> coord_;
    uint64_t cloud_seq_ = 0;
};

TEST_F(V2cKeyProvisioningCoordinatorTest, DisabledWhenConfigOff) {
    cfg_.enabled = false;
    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
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
    V2cKeyProvisioningRecord rec;
    rec.valid = true;
    rec.request_id = "kp-recovered";
    rec.state = "ACK_PENDING";
    rec.purposes = {"UPLINK_AEAD", "DOWNLINK_AEAD"};
    store_->save(rec);

    coord_->stop();
    coord_ = std::make_unique<V2cKeyProvisioningCoordinator>(mqtt_, sec_, store_);
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
    EXPECT_EQ(sec_->import_calls, 0);  // 不重复导入
    EXPECT_GE(publish_count_for("keyprov.uplink"), 1);  // 发送 ACK
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

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}