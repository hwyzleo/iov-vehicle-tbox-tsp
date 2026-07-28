// tests/test_tsp_retry_policy.cpp
#include <gtest/gtest.h>
#include "tsp_retry_policy.h"
#include "tsp_ipc_protocol.h"

using namespace tbox::tsp;

TEST(TspRetryPolicyTest, ReadOnlyMethodsAllowRetry) {
    EXPECT_TRUE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_NET_STATUS)));
    EXPECT_TRUE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_RELAY_STATUS)));
}

TEST(TspRetryPolicyTest, BusinessIdempotentMethodAllowsRetry) {
    // reportSoftwareInventory: 业务幂等（同 msg_id/snapshot_seq 由 TSP 去重）
    EXPECT_TRUE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY)));
}

TEST(TspRetryPolicyTest, SubscribeMethodsForbidRetry) {
    EXPECT_FALSE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_FOTA_COMMAND)));
    EXPECT_FALSE(TspRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_NET_STATUS)));
}

TEST(TspRetryPolicyTest, UnknownMethodConservativeOneShot) {
    EXPECT_FALSE(TspRetryPolicy::should_retry(9999));
    EXPECT_EQ(TspRetryPolicy::categorize(9999), TspRetryPolicy::Category::kOneShot);
}

TEST(TspRetryPolicyTest, Categorize) {
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_RELAY_STATUS)),
        TspRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::REPORT_SOFTWARE_INVENTORY)),
        TspRetryPolicy::Category::kBusinessIdempotent);
    EXPECT_EQ(TspRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_FOTA_COMMAND)),
        TspRetryPolicy::Category::kOneShot);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
