// CR-004 §12 单元测试：快照构建（稳定排序、摘要、generation 复用/递增）
#include <gtest/gtest.h>
#include "snapshot_builder.h"

using namespace tbox::tsp;

namespace {
SubscriptionItem make_item(const std::string& rid, const std::string& tmpl,
                           Direction d, uint8_t qos, const std::string& target,
                           bool mandatory) {
    return {rid, tmpl, d, qos, target, mandatory};
}
}

TEST(SnapshotBuilderTest, StableSortByRouteId) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("zeta", "t/z", Direction::UP, 1, "tsp.fota", false),
        make_item("alpha", "t/a", Direction::UP, 1, "tsp.fota", false),
        make_item("mid", "t/m", Direction::UP, 1, "tsp.fota", false),
    };
    auto snap = b.build(items, "tsp", 0, "");
    ASSERT_EQ(snap.items.size(), 3u);
    EXPECT_EQ(snap.items[0].route_id, "alpha");
    EXPECT_EQ(snap.items[1].route_id, "mid");
    EXPECT_EQ(snap.items[2].route_id, "zeta");
}

TEST(SnapshotBuilderTest, DigestDeterministic) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("b", "t/b", Direction::UP, 1, "tsp.fota", false),
        make_item("a", "t/a", Direction::DOWN, 1, "tsp.fota", true),
    };
    // 乱序输入应产生相同摘要（内部稳定排序）
    auto d1 = b.compute_digest(items);
    std::reverse(items.begin(), items.end());
    auto d2 = b.compute_digest(items);
    EXPECT_EQ(d1, d2);
    EXPECT_EQ(d1.size(), 64u);  // SHA-256 hex
}

TEST(SnapshotBuilderTest, DigestChangesOnSemanticChange) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("a", "t/a", Direction::UP, 1, "tsp.fota", false),
    };
    auto d1 = b.compute_digest(items);

    items[0].qos = 2;  // 语义变化
    auto d2 = b.compute_digest(items);
    EXPECT_NE(d1, d2);

    // mandatory 变化也是语义变化
    items[0].qos = 1;
    items[0].mandatory = true;
    auto d3 = b.compute_digest(items);
    EXPECT_NE(d1, d3);
}

TEST(SnapshotBuilderTest, GenerationReuseOnSameDigest) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("a", "t/a", Direction::UP, 1, "tsp.fota", false),
    };
    std::string digest = b.compute_digest(items);
    auto snap = b.build(items, "tsp", 7, digest);
    EXPECT_EQ(snap.generation, 7u);  // 复用
    EXPECT_EQ(snap.content_digest, digest);
}

TEST(SnapshotBuilderTest, GenerationIncrementOnDigestChange) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("a", "t/a", Direction::UP, 1, "tsp.fota", false),
    };
    auto snap = b.build(items, "tsp", 5, "different_digest");
    EXPECT_EQ(snap.generation, 6u);  // 递增
    EXPECT_NE(snap.content_digest, "different_digest");
}

TEST(SnapshotBuilderTest, FirstRunGenerationIsOne) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("a", "t/a", Direction::UP, 1, "tsp.fota", false),
    };
    auto snap = b.build(items, "tsp", 0, "");
    EXPECT_EQ(snap.generation, 1u);
}

TEST(SnapshotBuilderTest, RegistrationCompleteFlag) {
    SnapshotBuilder b;
    std::vector<SubscriptionItem> items = {
        make_item("a", "t/a", Direction::UP, 1, "tsp.fota", false),
        make_item("b", "t/b", Direction::DOWN, 1, "tsp.fota", true),
    };
    auto snap = b.build(items, "tsp", 0, "");
    EXPECT_TRUE(snap.registration_complete);
    EXPECT_EQ(snap.owner, "tsp");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
