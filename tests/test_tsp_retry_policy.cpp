// tests/test_tsp_retry_policy.cpp
#include <gtest/gtest.h>
#include "tsp_retry_policy.h"
#include "tsp_ipc_protocol.h"

using namespace tbox::tsp;

TEST(TspRetryPolicyTest, ReadOnlyMethodsAllowRetry) {
    EXPECT_TRUE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_NET_STATUS)));
}

TEST(TspRetryPolicyTest, ExchangeForbidsAutoRetry) {
    // CR-009: EXCHANGE_VEHICLE_MESSAGE 禁止不可见自动重试（重试由 CGW-FOTA
    // 以原 request/idempotency 身份发起；TSP 侧同 message_id 复用会被拒绝）。
    EXPECT_FALSE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE)));
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::EXCHANGE_VEHICLE_MESSAGE)),
        TspRetryPolicy::Category::kOneShot);
}

TEST(TspRetryPolicyTest, SubscribeMethodsForbidRetry) {
    EXPECT_FALSE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE)));
    EXPECT_FALSE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_NET_STATUS)));
}

TEST(TspRetryPolicyTest, UnknownMethodConservativeOneShot) {
    EXPECT_FALSE(TspRetryPolicy::should_retry(9999));
    EXPECT_EQ(TspRetryPolicy::categorize(9999), TspRetryPolicy::Category::kOneShot);
}

TEST(TspRetryPolicyTest, Categorize) {
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_NET_STATUS)),
        TspRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_VEHICLE_MESSAGE)),
        TspRetryPolicy::Category::kOneShot);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
