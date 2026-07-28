// tests/test_tsp_ipc_dispatcher.cpp
#include <gtest/gtest.h>
#include "tsp_ipc_dispatcher.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "mocks.h"
#include "nlohmann/json.hpp"
#include "utils.h"

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using json = nlohmann::json;

namespace {
std::string b64(const std::vector<uint8_t>& d) {
    return ::hwyz::Utils::base64_encode(std::string(d.begin(), d.end()));
}
}

class TspIpcDispatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        relay_ = std::make_unique<MockFotaRelay>();
        net_ = std::make_unique<MockNetStatusProvider>();
        dispatcher_ = std::make_unique<TspIpcDispatcher>(
            relay_.get(), net_.get(), 10485760);
    }

    std::string dispatch(uint32_t method, const std::string& params) {
        return dispatcher_->dispatch(method, params, /*client_fd=*/1);
    }

    std::unique_ptr<MockFotaRelay> relay_;
    std::unique_ptr<MockNetStatusProvider> net_;
    std::unique_ptr<TspIpcDispatcher> dispatcher_;
};

// ---- REPORT_SOFTWARE_INVENTORY ----

TEST_F(TspIpcDispatcherTest, ReportInventoryAccepted) {
    relay_->uplink_result = {true, PublishOutcome::ACCEPTED, 0, ""};

    json params;
    params[ipc::field::SNAPSHOT_SEQ] = 42;
    params[ipc::field::MSG_ID] = "fota-42";
    params[ipc::field::CONTENT_TYPE] = "application/x-protobuf";
    params[ipc::field::PAYLOAD_B64] = b64({0x01, 0x02, 0x03});
    params[ipc::field::TRACE_ID] = "trace-1";

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(), 0);
    EXPECT_TRUE(j[ipc::field::ACCEPTED].get<bool>());
    EXPECT_EQ(j[ipc::field::OUTCOME].get<std::string>(), "ACCEPTED");
    EXPECT_EQ(j[ipc::field::MSG_ID].get<std::string>(), "fota-42");
    EXPECT_TRUE(relay_->uplink_called);
    EXPECT_EQ(relay_->uplink_calls.back().snapshot.snapshot_seq, 42u);
}

TEST_F(TspIpcDispatcherTest, ReportInventoryMissingMsgId) {
    json params;
    params[ipc::field::SNAPSHOT_SEQ] = 1;
    params[ipc::field::PAYLOAD_B64] = b64({0x01});

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER));
    EXPECT_FALSE(relay_->uplink_called);
}

TEST_F(TspIpcDispatcherTest, ReportInventoryMissingPayload) {
    json params;
    params[ipc::field::MSG_ID] = "m1";

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER));
}

TEST_F(TspIpcDispatcherTest, ReportInventoryFrameTooLarge) {
    // 构造一个超过 max_payload_bytes 的 payload_base64
    std::string big(2 * 1024 * 1024, 'A');
    json params;
    params[ipc::field::MSG_ID] = "m1";
    params[ipc::field::PAYLOAD_B64] = big;

    // 用小上限构造 dispatcher
    TspIpcDispatcher small_dispatcher(relay_.get(), net_.get(), 1024);
    std::string resp = small_dispatcher.dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), params.dump(), 1);

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE));
    EXPECT_FALSE(relay_->uplink_called);
}

TEST_F(TspIpcDispatcherTest, ReportInventoryInvalidJson) {
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), "{not json");
    auto j = json::parse(resp);
    EXPECT_TRUE(j.contains(ipc::field::ERROR));
}

TEST_F(TspIpcDispatcherTest, ReportInventoryDedupHit) {
    relay_->uplink_result = {true, PublishOutcome::ACCEPTED,
        static_cast<int32_t>(TspErrorCode::DEDUP_HIT), ""};

    json params;
    params[ipc::field::MSG_ID] = "dup-1";
    params[ipc::field::PAYLOAD_B64] = b64({0x01});

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::DEDUP_HIT));
}

// ---- GET_RELAY_STATUS ----

TEST_F(TspIpcDispatcherTest, GetRelayStatus) {
    relay_->status_result.state = RelayState::ACCEPTED;
    relay_->status_result.snapshot_seq = 7;
    relay_->status_result.error_code = 0;

    json params;
    params[ipc::field::MSG_ID] = "m-7";

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_RELAY_STATUS), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATE].get<std::string>(), "ACCEPTED");
    EXPECT_EQ(j[ipc::field::MSG_ID].get<std::string>(), "m-7");
    EXPECT_EQ(j[ipc::field::SNAPSHOT_SEQ].get<uint32_t>(), 7u);
}

TEST_F(TspIpcDispatcherTest, GetRelayStatusMissingMsgId) {
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_RELAY_STATUS), "{}");
    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER));
}

// ---- GET_NET_STATUS ----

TEST_F(TspIpcDispatcherTest, GetNetStatus) {
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_NET_STATUS), "{}");
    auto j = json::parse(resp);
    EXPECT_TRUE(j["is_connected"].get<bool>());
    EXPECT_EQ(j["network_type"].get<std::string>(), "4G");
}

// ---- SUBSCRIBE ----

TEST_F(TspIpcDispatcherTest, SubscribeFotaAck) {
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_FOTA_COMMAND), "{}");
    auto j = json::parse(resp);
    EXPECT_TRUE(j[ipc::field::SUCCESS].get<bool>());
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(), 0);
}

// ---- unknown method ----

TEST_F(TspIpcDispatcherTest, UnknownMethod) {
    std::string resp = dispatch(9999, "{}");
    auto j = json::parse(resp);
    EXPECT_TRUE(j.contains(ipc::field::ERROR));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
