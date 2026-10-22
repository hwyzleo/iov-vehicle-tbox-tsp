// TBOX-TSP-DSN-CR-010 §10 集成测试：Fake MQTT route + Fake SEC client contract suite。
//
// 覆盖：keyprov subscription 快照契约（contract_version / enabled / scope /
// criticality）、首次 Cloud Ready 全流程、已有密钥不重复申请、capability 丢失暂停
// 与恢复（原 requestId 不变）、AckResult 确认、requestId 幂等。
#include <gtest/gtest.h>

#include "mocks.h"
#include "snapshot_builder.h"
#include "subscription_catalog.h"
#include "subscription_registrar.h"
#include "subscription_store.h"
#include "v2c_key_provisioning_coordinator.h"

#include "security/keyprov/v1/key_provisioning.pb.h"
#include "vehicle/common/v1/envelope.pb.h"
#include "yaml-cpp/yaml.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using namespace security::keyprov::v1;
using vehicle::common::v1::MESSAGE_KIND_RESPONSE;
using vehicle::common::v1::VehicleMessageEnvelope;

namespace {

std::string temp_root(const char* tag) {
    static int counter = 0;
    return std::string("/tmp/tbox_tsp_keyprov_int_") + tag + "_" +
           std::to_string(getpid()) + "_" + std::to_string(counter++);
}

const char* kCatalogYaml =
    "- route_id: fota.downlink\n"
    "  topic_template: vehicle/{ecu_uid}/down/fota\n"
    "  direction: DOWN\n"
    "  qos: 1\n"
    "  target: tsp.fota\n"
    "  mandatory: true\n"
    "- route_id: keyprov.uplink\n"
    "  topic_template: vehicle/{ecu_uid}/up/keyprov\n"
    "  direction: UP\n"
    "  qos: 1\n"
    "  target: tsp.keyprov\n"
    "  mandatory: false\n"
    "  enabled: true\n"
    "  readiness_scope: security.keyprov\n"
    "  criticality: CAPABILITY_MANDATORY\n"
    "- route_id: keyprov.downlink\n"
    "  topic_template: vehicle/{ecu_uid}/down/keyprov\n"
    "  direction: DOWN\n"
    "  qos: 1\n"
    "  target: tsp.keyprov\n"
    "  mandatory: false\n"
    "  enabled: true\n"
    "  readiness_scope: security.keyprov\n"
    "  criticality: CAPABILITY_MANDATORY\n";

std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> make_response(const std::string& rid) {
    KeyProvisioningResponse resp;
    resp.set_request_id(rid);
    resp.set_result(KEY_PROVISIONING_RESULT_SUCCEEDED);
    for (int i = 0; i < 2; ++i) {
        auto* it = resp.add_items();
        it->set_purpose(i == 0 ? KEY_PURPOSE_UPLINK_AEAD
                               : KEY_PURPOSE_DOWNLINK_AEAD);
        it->set_key_id(i == 0 ? "kid-up" : "kid-down");
        it->set_business_key_version(1);
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
    env.set_request_id(rid);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadResponse);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("m");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

std::vector<uint8_t> make_ack_result(const std::string& rid, int result) {
    KeyProvisioningAckResult msg;
    msg.set_request_id(rid);
    msg.set_result(static_cast<KeyProvisioningResult>(result));
    std::string payload;
    msg.SerializeToString(&payload);
    VehicleMessageEnvelope env;
    env.set_request_id(rid);
    env.set_protocol_version("keyprov-v1");
    env.set_service("security.keyprov");
    env.set_payload_type(kKeyprovPayloadAckResult);
    env.set_message_kind(MESSAGE_KIND_RESPONSE);
    env.set_message_id("m2");
    env.set_payload(payload);
    std::string s;
    env.SerializeToString(&s);
    return to_bytes(s);
}

RoutedDownlinkEvent downlink(const std::vector<uint8_t>& payload) {
    RoutedDownlinkEvent e;
    e.owner = "tsp";
    e.route_id = "keyprov.downlink";
    e.target = "tsp.keyprov";
    e.payload = payload;
    return e;
}

FakeSecClient::StatusItem active(const std::string& p) {
    FakeSecClient::StatusItem s;
    s.purpose = p;
    s.state = 2;  // ACTIVE
    s.business_key_version = 1;
    s.key_id_digest = "digest-" + p;
    s.key_id = (p == "UPLINK_AEAD") ? "kid-up" : "kid-down";
    s.envelope_format = static_cast<int>(tbox::sec::KeyEnvelopeFormat::ECDH_ES_P256_V1);
    s.envelope_digest = std::vector<uint8_t>(32, 0xD1);
    s.key_check_value = std::vector<uint8_t>(3, 0xC1);
    s.import_proof = std::vector<uint8_t>(64, 0xE1);
    s.proof_algorithm = tbox::sec::kImportProofAlgorithmP1363;
    s.recipient_certificate_digest = std::vector<uint8_t>(32, 0xB1);
    return s;
}

// CR-012 §10.11：递归扫描 store 目录，确认无 wrappedKey/parameters/proof 泄漏。
bool dir_contains_bytes(const std::string& root,
                        const std::vector<uint8_t>& needle) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(root, ec)) return false;
    for (const auto& e : fs::recursive_directory_iterator(root, ec)) {
        if (ec || !e.is_regular_file()) continue;
        std::ifstream in(e.path(), std::ios::binary);
        std::string data((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        if (std::search(data.begin(), data.end(), needle.begin(), needle.end()) !=
            data.end()) {
            return true;
        }
    }
    return false;
}

void make_ready(const std::shared_ptr<MockMqttFacade>& mqtt, bool ready = true) {
    static uint64_t seq = 0;
    CloudReadiness cr;
    cr.cloud_ready = ready;
    cr.cert_session_generation = 7;
    cr.connection_generation = 7;
    cr.device_identity_digest = std::string(64, 'b');
    cr.certificate_ref = "sha256:" + std::string(64, 'b');
    cr.contract_supported = true;
    cr.contract_version = 3;
    cr.publish_contract_version = 1;
    // CR-011 §3: v3 会话身份投影（同一快照）。
    cr.ecu_uid = "ECU-INT-1";
    cr.session.daemon_epoch = "epoch-int";
    cr.session.connection_generation = 7;
    cr.session.cert_session_generation = 7;
    cr.event_sequence = ++seq;
    mqtt->deliver_cloud_readiness(cr);
    CapabilityReadiness cap;
    cap.capability = "security.keyprov";
    cap.ready = ready;
    cap.enabled = ready;
    cap.contract_supported = true;
    cap.snapshot_accepted = true;
    cap.uplink_ready = true;
    cap.downlink_suback_ready = true;
    cap.connection_generation = 7;
    cap.cert_session_generation = 7;
    mqtt->deliver_capability_readiness(cap);
}

} // namespace

TEST(KeyProvisioningIntegrationTest, SnapshotCarriesCapabilityContract) {
    auto mqtt = std::make_shared<MockMqttFacade>();
    mqtt->snapshot_result.status = SnapshotStatus::ACCEPTED;
    auto catalog = std::make_shared<SubscriptionCatalog>();
    std::string err;
    ASSERT_TRUE(catalog->load_from_yaml(YAML::Load(kCatalogYaml), err)) << err;
    auto store = std::make_shared<SubscriptionStore>(temp_root("snap"));
    MqttSubscriptionRegistrar registrar(mqtt, catalog, store);
    ASSERT_TRUE(registrar.start(false));
    registrar.tick();

    auto calls = mqtt->snapshot_calls();
    ASSERT_GE(calls.size(), 1u);
    const auto& snap = calls.back();
    EXPECT_EQ(snap.contract_version, kSubscriptionContractVersion);
    bool found_keyprov = false;
    for (const auto& item : snap.items) {
        if (item.route_id == "keyprov.downlink") {
            found_keyprov = true;
            EXPECT_EQ(item.readiness_scope, "security.keyprov");
            EXPECT_EQ(item.criticality, SubscriptionCriticality::CAPABILITY_MANDATORY);
            ASSERT_TRUE(item.enabled.has_value());
            EXPECT_TRUE(*item.enabled);
            EXPECT_FALSE(item.mandatory);
        }
    }
    EXPECT_TRUE(found_keyprov);
    registrar.stop();
}

TEST(KeyProvisioningIntegrationTest, FullFlowAndCapabilityPauseResume) {
    auto mqtt = std::make_shared<MockMqttFacade>();
    auto sec = std::make_shared<FakeSecClient>();
    std::string store_root = temp_root("coord");
    auto store = std::make_shared<V2cKeyProvisioningStore>(store_root);

    V2cKeyProvisioningConfig cfg;
    cfg.enabled = true;
    cfg.request_timeout_ms = 500;
    cfg.ack_timeout_ms = 500;
    cfg.retry_initial_ms = 10;
    cfg.retry_max_ms = 40;

    V2cKeyProvisioningCoordinator coord(mqtt, sec, store);
    coord.set_clock_sync_check([] { return true; });
    ASSERT_TRUE(coord.initialize(cfg));
    ASSERT_TRUE(coord.start(false));

    make_ready(mqtt);
    coord.tick();
    std::string rid = coord.snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // capability 丢失：暂停，保留 requestId
    make_ready(mqtt, false);
    coord.tick();
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::WAIT_CLOUD);
    EXPECT_EQ(coord.snapshot().request_id, rid);

    // 恢复：继续原 requestId
    make_ready(mqtt, true);
    coord.tick();
    EXPECT_EQ(coord.snapshot().request_id, rid);

    // 下行响应 + 导入 + ACK + 确认
    coord.handle_routed_downlink(downlink(make_response(rid)));
    sec->import_items = {active("UPLINK_AEAD"), active("DOWNLINK_AEAD")};
    sec->import_state = 2;  // COMMITTED
    sec->import_proof = {0x01};
    coord.tick();
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::ACK_PENDING);

    // CR-011 §4/§5.2: Request 与 ACK 上行都必须携 device_id 与 expected_session。
    {
        bool saw_request = false;
        bool saw_ack = false;
        for (const auto& c : mqtt->publish_route_calls()) {
            if (c.route_id != "keyprov.uplink") continue;
            EXPECT_TRUE(c.expected_session.has_value());
            VehicleMessageEnvelope env;
            if (!env.ParseFromArray(c.payload.data(), (int)c.payload.size())) continue;
            EXPECT_EQ(env.device_id(), "ECU-INT-1");
            if (env.payload_type() == kKeyprovPayloadRequest) saw_request = true;
            if (env.payload_type() == kKeyprovPayloadAck) saw_ack = true;
        }
        EXPECT_TRUE(saw_request);
        EXPECT_TRUE(saw_ack);
    }

    coord.handle_routed_downlink(downlink(
        make_ack_result(rid, KEY_PROVISIONING_RESULT_SUCCEEDED)));
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::ACTIVE);

    // 已 ACTIVE 后重启不再申请
    coord.stop();
    V2cKeyProvisioningCoordinator coord2(mqtt, sec, store);
    coord2.set_clock_sync_check([] { return true; });
    sec->status_items = {active("UPLINK_AEAD"), active("DOWNLINK_AEAD")};
    ASSERT_TRUE(coord2.initialize(cfg));
    ASSERT_TRUE(coord2.start(false));
    int before = 0;
    for (const auto& c : mqtt->publish_route_calls()) {
        if (c.route_id == "keyprov.uplink") ++before;
    }
    make_ready(mqtt);
    coord2.tick();
    int after = 0;
    for (const auto& c : mqtt->publish_route_calls()) {
        if (c.route_id == "keyprov.uplink") ++after;
    }
    EXPECT_EQ(coord2.snapshot().state, V2cKeyProvState::ACTIVE);
    EXPECT_EQ(before, after);  // 无新申请
    coord2.stop();

    // CR-012 §10.11：Store 不得包含 wrappedKey/parameters/proof 原文。
    EXPECT_FALSE(dir_contains_bytes(store_root,
                                    std::vector<uint8_t>(32, 'W')));
    EXPECT_FALSE(dir_contains_bytes(store_root,
                                    std::vector<uint8_t>(8, 'P')));
    EXPECT_FALSE(dir_contains_bytes(store_root,
                                    std::vector<uint8_t>(64, 0xE1)));
}

// ============================================================
// CR-013：换证 fingerprint 变化 -> RECONCILE -> VMD 终结 -> 新 attempt
// ============================================================
TEST(KeyProvisioningIntegrationTest, FingerprintChangeReconcilesAndSupersedes) {
    auto mqtt = std::make_shared<MockMqttFacade>();
    auto sec = std::make_shared<FakeSecClient>();
    std::string store_root = temp_root("cr13");
    auto store = std::make_shared<V2cKeyProvisioningStore>(store_root);
    V2cKeyProvisioningConfig cfg;
    cfg.enabled = true;
    cfg.request_timeout_ms = 500;
    cfg.ack_timeout_ms = 500;
    cfg.retry_initial_ms = 10;
    cfg.retry_max_ms = 40;
    V2cKeyProvisioningCoordinator coord(mqtt, sec, store);
    coord.set_clock_sync_check([] { return true; });
    ASSERT_TRUE(coord.initialize(cfg));
    ASSERT_TRUE(coord.start(false));
    sec->status_items.clear();
    sec->query_state = 3;  // SEC clean（无已提交副作用）
    make_ready(mqtt);
    coord.tick();
    std::string rid = coord.snapshot().request_id;
    ASSERT_FALSE(rid.empty());
    ASSERT_EQ(coord.snapshot().state, V2cKeyProvState::WAIT_RESPONSE);

    // 换证：证书摘要变化 -> RECONCILE（不得复用原 requestId 发变化后 Request）。
    CloudReadiness cr = mqtt->cloud_readiness;
    cr.certificate_ref = "sha256:" + std::string(64, 'c');
    cr.device_identity_digest = std::string(64, 'c');
    cr.cert_session_generation = 8;
    cr.session.cert_session_generation = 8;
    cr.event_sequence = 100;
    mqtt->deliver_cloud_readiness(cr);
    CapabilityReadiness cap = mqtt->capability_readiness;
    cap.cert_session_generation = 8;
    mqtt->deliver_capability_readiness(cap);
    coord.tick();
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);

    // VMD 已终结（FAILED）+ SEC 无副作用 -> SUPERSEDED_REMOTE -> 新 attempt。
    KeyProvisioningStatusResponse st;
    st.set_request_id(rid);
    st.set_status(KEY_PROVISIONING_STATUS_FAILED);
    std::string spayload;
    st.SerializeToString(&spayload);
    VehicleMessageEnvelope senv;
    senv.set_request_id(rid);
    senv.set_protocol_version("keyprov-v1");
    senv.set_service("security.keyprov");
    senv.set_payload_type(kKeyprovPayloadStatusResponse);
    senv.set_message_kind(MESSAGE_KIND_RESPONSE);
    senv.set_message_id("st1");
    senv.set_payload(spayload);
    std::string ss;
    senv.SerializeToString(&ss);
    RoutedDownlinkEvent de;
    de.owner = "tsp";
    de.route_id = "keyprov.downlink";
    de.target = "tsp.keyprov";
    de.payload = std::vector<uint8_t>(ss.begin(), ss.end());
    coord.handle_routed_downlink(de);
    auto snap = coord.snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::WAIT_RESPONSE);
    EXPECT_NE(snap.request_id, rid);
    EXPECT_EQ(snap.superseded_remote, 1u);
    // supersede 关联持久化（旧 requestId 可审计）。
    auto rec = store->load();
    ASSERT_TRUE(rec.valid);
    EXPECT_EQ(rec.supersedes_request_id, rid);
    EXPECT_EQ(rec.fingerprint_version, 1u);
    ASSERT_FALSE(rec.attempt_fingerprint.empty());
    // Store 不得泄漏证书/密钥材料。
    EXPECT_FALSE(dir_contains_bytes(store_root, std::vector<uint8_t>(32, 0x0B)));
    coord.stop();
}

TEST(KeyProvisioningIntegrationTest, IdempotencyConflictEndToEnd) {
    auto mqtt = std::make_shared<MockMqttFacade>();
    auto sec = std::make_shared<FakeSecClient>();
    std::string store_root = temp_root("cr13b");
    auto store = std::make_shared<V2cKeyProvisioningStore>(store_root);
    V2cKeyProvisioningConfig cfg;
    cfg.enabled = true;
    cfg.request_timeout_ms = 500;
    cfg.ack_timeout_ms = 500;
    V2cKeyProvisioningCoordinator coord(mqtt, sec, store);
    coord.set_clock_sync_check([] { return true; });
    ASSERT_TRUE(coord.initialize(cfg));
    ASSERT_TRUE(coord.start(false));
    sec->status_items.clear();
    sec->query_state = 3;
    make_ready(mqtt);
    coord.tick();
    std::string rid = coord.snapshot().request_id;
    ASSERT_FALSE(rid.empty());

    // 首次 Request 被 806095 拒绝 -> RECONCILE。
    KeyProvisioningResponse resp;
    resp.set_request_id(rid);
    resp.set_result(KEY_PROVISIONING_RESULT_REJECTED);
    resp.mutable_error()->set_code("806095");
    std::string rpayload;
    resp.SerializeToString(&rpayload);
    VehicleMessageEnvelope renv;
    renv.set_request_id(rid);
    renv.set_protocol_version("keyprov-v1");
    renv.set_service("security.keyprov");
    renv.set_payload_type(kKeyprovPayloadResponse);
    renv.set_message_kind(MESSAGE_KIND_RESPONSE);
    renv.set_message_id("r1");
    renv.set_payload(rpayload);
    std::string rs;
    renv.SerializeToString(&rs);
    RoutedDownlinkEvent de;
    de.owner = "tsp";
    de.route_id = "keyprov.downlink";
    de.target = "tsp.keyprov";
    de.payload = std::vector<uint8_t>(rs.begin(), rs.end());
    coord.handle_routed_downlink(de);
    EXPECT_EQ(coord.snapshot().state, V2cKeyProvState::RECONCILE_OLD_ATTEMPT);
    EXPECT_EQ(coord.snapshot().idempotency_conflicts_total, 1u);

    // 对账 Status 返回幂等冲突 -> 待云端终结（VMD CR-065 受控终结前不建新 attempt）。
    KeyProvisioningStatusResponse st;
    st.set_request_id(rid);
    st.set_status(KEY_PROVISIONING_STATUS_UNSPECIFIED);
    st.mutable_error()->set_code("806095");
    std::string spayload;
    st.SerializeToString(&spayload);
    VehicleMessageEnvelope senv;
    senv.set_request_id(rid);
    senv.set_protocol_version("keyprov-v1");
    senv.set_service("security.keyprov");
    senv.set_payload_type(kKeyprovPayloadStatusResponse);
    senv.set_message_kind(MESSAGE_KIND_RESPONSE);
    senv.set_message_id("st1");
    senv.set_payload(spayload);
    std::string ss;
    senv.SerializeToString(&ss);
    RoutedDownlinkEvent de2;
    de2.owner = "tsp";
    de2.route_id = "keyprov.downlink";
    de2.target = "tsp.keyprov";
    de2.payload = std::vector<uint8_t>(ss.begin(), ss.end());
    coord.handle_routed_downlink(de2);
    auto snap = coord.snapshot();
    EXPECT_EQ(snap.state, V2cKeyProvState::BLOCKED_AWAIT_CLOUD_TERMINATION);
    EXPECT_EQ(snap.blocked_reason, keyprov_blocked_reason::kAwaitCloudTermination);
    // 请求 payload 不落 Store（敏感扫描）。
    EXPECT_FALSE(dir_contains_bytes(store_root, std::vector<uint8_t>(32, 0x0B)));
    coord.stop();
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
