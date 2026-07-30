// CR-004 §12 单元测试：generation 持久化
#include <gtest/gtest.h>
#include "subscription_store.h"

#include <cstdlib>
#include <string>

using namespace tbox::tsp;

namespace {
std::string temp_root() {
    static int counter = 0;
    std::string p = "/tmp/tbox_tsp_store_test_" +
                    std::to_string(getpid()) + "_" +
                    std::to_string(counter++);
    return p;
}
}

TEST(SubscriptionStoreTest, FirstRunNoPersistence) {
    SubscriptionStore store(temp_root());
    uint64_t gen = 999;
    std::string digest = "should_be_cleared";
    EXPECT_FALSE(store.load(gen, digest));
    EXPECT_EQ(gen, 0u);
    EXPECT_TRUE(digest.empty());
}

TEST(SubscriptionStoreTest, SaveAndLoad) {
    std::string root = temp_root();
    {
        SubscriptionStore store(root);
        store.save(7, "deadbeef");
    }
    {
        SubscriptionStore store(root);
        uint64_t gen = 0;
        std::string digest;
        ASSERT_TRUE(store.load(gen, digest));
        EXPECT_EQ(gen, 7u);
        EXPECT_EQ(digest, "deadbeef");
    }
}

TEST(SubscriptionStoreTest, GenerationReuseAcrossInstances) {
    // 模拟进程重启：相同 digest 复用 generation（由 builder 配合 store 保证）
    std::string root = temp_root();
    SubscriptionStore store1(root);
    store1.save(3, "abc");
    SubscriptionStore store2(root);  // 重新打开（模拟重启）
    uint64_t gen = 0;
    std::string digest;
    ASSERT_TRUE(store2.load(gen, digest));
    EXPECT_EQ(gen, 3u);
    EXPECT_EQ(digest, "abc");
}

TEST(SubscriptionStoreTest, OverwriteOnSave) {
    std::string root = temp_root();
    SubscriptionStore store(root);
    store.save(1, "first");
    store.save(2, "second");
    uint64_t gen = 0;
    std::string digest;
    ASSERT_TRUE(store.load(gen, digest));
    EXPECT_EQ(gen, 2u);
    EXPECT_EQ(digest, "second");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
