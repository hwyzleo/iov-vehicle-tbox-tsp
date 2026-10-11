// TBOX-TSP-DSN-CR-010 §5: V2cKeyProvisioningStore 单元测试。
#include <gtest/gtest.h>

#include "v2c_key_provisioning_store.h"

#include <cstdlib>
#include <string>

using namespace tbox::tsp;

namespace {
std::string temp_root() {
    static int counter = 0;
    return "/tmp/tbox_tsp_keyprov_store_" + std::to_string(getpid()) + "_" +
           std::to_string(counter++);
}
} // namespace

TEST(V2cKeyProvisioningStoreTest, EmptyOnFirstRun) {
    V2cKeyProvisioningStore store(temp_root());
    auto rec = store.load();
    EXPECT_FALSE(rec.valid);
}

TEST(V2cKeyProvisioningStoreTest, SaveLoadRoundTrip) {
    auto root = temp_root();
    {
        V2cKeyProvisioningStore store(root);
        V2cKeyProvisioningRecord rec;
        rec.valid = true;
        rec.request_id = "kp-abc";
        rec.idempotency_digest = "deadbeef";
        rec.state = "ACK_PENDING";
        rec.purposes = {"UPLINK_AEAD", "DOWNLINK_AEAD"};
        rec.business_key_versions = {{"UPLINK_AEAD", 5}, {"DOWNLINK_AEAD", 7}};
        rec.attempt_count = 3;
        rec.deadline_ms = 123456;
        rec.last_error = "response_timeout";
        rec.updated_at_ms = 999;
        rec.cloud_session_generation = 42;
        store.save(rec);
    }
    V2cKeyProvisioningStore store(root);
    auto rec = store.load();
    ASSERT_TRUE(rec.valid);
    EXPECT_EQ(rec.request_id, "kp-abc");
    EXPECT_EQ(rec.state, "ACK_PENDING");
    ASSERT_EQ(rec.business_key_versions.size(), 2u);
    EXPECT_EQ(rec.business_key_versions[1].second, 7u);
    EXPECT_EQ(rec.attempt_count, 3u);
    EXPECT_EQ(rec.cloud_session_generation, 42u);
}

TEST(V2cKeyProvisioningStoreTest, ClearRemovesRecord) {
    auto root = temp_root();
    V2cKeyProvisioningStore store(root);
    V2cKeyProvisioningRecord rec;
    rec.valid = true;
    rec.request_id = "kp-xyz";
    rec.state = "WAIT_CLOUD";
    store.save(rec);
    ASSERT_TRUE(store.load().valid);
    store.clear();
    EXPECT_FALSE(store.load().valid);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
