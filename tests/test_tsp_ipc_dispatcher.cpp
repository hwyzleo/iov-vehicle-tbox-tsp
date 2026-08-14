// tests/test_tsp_ipc_dispatcher.cpp
// TspIpcDispatcher 单元测试（CR-009 wire 契约）：
//   EXCHANGE_VEHICLE_MESSAGE / SUBSCRIBE_VEHICLE_MESSAGE / GET_NET_STATUS。
#include <gtest/gtest.h>
#include "tsp_ipc_dispatcher.h"
#include "tsp_ipc_protocol.h"
#include "tbox/tsp/errors.h"
#include "mocks.h"
#include "vehicle_message_test_util.h"
#include "nlohmann/json.hpp"
#include "utils.h"

using namespace tbox::tsp;
using namespace tbox::tsp::test;
using json = nlohmann::json;

namespace {
std::string b64(const std::vector<std::byte>& d) {
    return ::hwyz::Utils::base64_encode(bytes_to_string(d));
}
}

class TspIpcDispatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        relay_ = std::make_unique<MockVehicleMessageRelay>();
        net_ = std::make_unique<MockNetStatusProvider>();
        dispatcher_ = std::make_unique<TspIpcDispatcher>(
            relay_.get(), net_.get(), 10485760);
    }

    std::string dispatch(uint32_t method, const std::string& params) {
        return dispatcher_->dispatch(method, params, /*client_fd=*/1);
    }

    std::unique_ptr<MockVehicleMessageRelay> relay_;
    std::unique_ptr<MockNetStatusProvider> net_;
    std::unique_ptr<TspIpcDispatcher> dispatcher_;
};

// ---- EXCHANGE_VEHICLE_MESSAGE ----

TEST_F(TspIpcDispatcherTest, ExchangeAcceptedWithResponse) {
    TransportResult<VehicleMessage> r;
    r.outcome = TransportOutcome::Accepted;
    r.value = to_msg(make_response_envelope("client-req-1", "resp-1"));
    relay_->default_result = r;

    json params;
    params[ipc::field::ENVELOPE_B64] = b64(make_request_envelope("client-req-1"));
    params[ipc::field::TIMEOUT_MS] = 1000;

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE), params.dump());

    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(), 0);
    EXPECT_EQ(j[ipc::field::OUTCOME].get<std::string>(), "Accepted");
    EXPECT_TRUE(j[ipc::field::SUCCESS].get<bool>());
    // RESPONSE Envelope 原样返回
    EXPECT_EQ(j[ipc::field::ENVELOPE_B64].get<std::string>(),
              b64(make_response_envelope("client-req-1", "resp-1")));
    EXPECT_EQ(relay_->call_count(), 1);
    EXPECT_EQ(bytes_to_string(relay_->last_call().request.envelope_bytes),
              bytes_to_string(make_request_envelope("client-req-1")));
}

TEST_F(TspIpcDispatcherTest, ExchangeRejected) {
    TransportResult<VehicleMessage> r;
    r.outcome = TransportOutcome::Rejected;
    r.error = "ttl_expired";
    relay_->default_result = r;

    json params;
    params[ipc::field::ENVELOPE_B64] = b64(make_request_envelope("client-req-2"));

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE), params.dump());
    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::PAYLOAD_PARSE_FAILED));
    EXPECT_EQ(j[ipc::field::OUTCOME].get<std::string>(), "Rejected");
    EXPECT_FALSE(j[ipc::field::SUCCESS].get<bool>());
}

TEST_F(TspIpcDispatcherTest, ExchangeMissingEnvelope) {
    json params;
    params["unrelated"] = 1;

    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE), params.dump());
    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::INVALID_PARAMETER));
    EXPECT_EQ(relay_->call_count(), 0);
}

TEST_F(TspIpcDispatcherTest, ExchangeFrameTooLarge) {
    // 构造超过 max_payload_bytes 的 envelope_base64
    std::string big(2 * 1024 * 1024, 'A');
    json params;
    params[ipc::field::ENVELOPE_B64] = big;

    TspIpcDispatcher small_dispatcher(relay_.get(), net_.get(), 1024);
    std::string resp = small_dispatcher.dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE), params.dump(), 1);
    auto j = json::parse(resp);
    EXPECT_EQ(j[ipc::field::STATUS].get<int32_t>(),
              static_cast<int32_t>(TspErrorCode::FRAME_TOO_LARGE));
    EXPECT_EQ(relay_->call_count(), 0);
}

TEST_F(TspIpcDispatcherTest, ExchangeInvalidJson) {
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE), "{not json");
    auto j = json::parse(resp);
    EXPECT_TRUE(j.contains(ipc::field::ERROR));
    EXPECT_EQ(relay_->call_count(), 0);
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

TEST_F(TspIpcDispatcherTest, SubscribeVehicleMessageAck) {
    json params;
    params[ipc::field::SERVICE] = "vehicle.fota";
    std::string resp = dispatch(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE), params.dump());
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
