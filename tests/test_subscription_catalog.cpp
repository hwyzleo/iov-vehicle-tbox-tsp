// CR-004 §12 单元测试：业务订阅目录校验
#include <gtest/gtest.h>
#include "subscription_catalog.h"
#include "yaml-cpp/yaml.h"

using namespace tbox::tsp;

namespace {
YAML::Node yaml(const std::string& s) { return YAML::Load(s); }
}

TEST(SubscriptionCatalogTest, LoadValidTwoItems) {
    SubscriptionCatalog cat;
    std::string err;
    ASSERT_TRUE(cat.load_from_yaml(yaml(
        "- route_id: fota.uplink\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"
        "  mandatory: false\n"
        "- route_id: fota.downlink\n"
        "  topic_template: vehicle/{ecu_uid}/down/fota\n"
        "  direction: DOWN\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"
        "  mandatory: true\n"), err)) << err;

    EXPECT_EQ(cat.items().size(), 2u);
    EXPECT_EQ(cat.mandatory_count(), 1u);
    EXPECT_EQ(cat.items()[0].route_id, "fota.uplink");
    EXPECT_EQ(cat.items()[0].direction, Direction::UP);
    EXPECT_EQ(cat.items()[1].mandatory, true);
}

TEST(SubscriptionCatalogTest, DuplicateRouteIdRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: dup\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"
        "- route_id: dup\n"
        "  topic_template: vehicle/{ecu_uid}/down/fota\n"
        "  direction: DOWN\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"), err));
    EXPECT_NE(err.find("duplicate"), std::string::npos);
}

TEST(SubscriptionCatalogTest, DeviceSnTemplateRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: vehicle/{device_sn}/up/fota\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"), err));
    EXPECT_NE(err.find("device_sn"), std::string::npos);
}

TEST(SubscriptionCatalogTest, EmptyTopicTemplateRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: \"\"\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"), err));
}

TEST(SubscriptionCatalogTest, EmptyTargetRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: \"\"\n"), err));
}

TEST(SubscriptionCatalogTest, InvalidDirectionRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: SIDEWAYS\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"), err));
}

TEST(SubscriptionCatalogTest, QosOutOfRangeRejected) {
    SubscriptionCatalog cat;
    std::string err;
    EXPECT_FALSE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: UP\n"
        "  qos: 5\n"
        "  target: tsp.fota\n"), err));
}

TEST(SubscriptionCatalogTest, ShadowValidateAndReplace) {
    SubscriptionCatalog cat;
    std::string err;
    ASSERT_TRUE(cat.load_from_yaml(yaml(
        "- route_id: r1\n"
        "  topic_template: vehicle/{ecu_uid}/up/fota\n"
        "  direction: UP\n"
        "  qos: 1\n"
        "  target: tsp.fota\n"), err));

    std::vector<SubscriptionItem> candidate = cat.items();
    candidate[0].qos = 2;
    ASSERT_TRUE(cat.validate(candidate, err));
    cat.replace(candidate);
    EXPECT_EQ(cat.items()[0].qos, 2);

    // 影子校验失败不影响当前集合
    std::vector<SubscriptionItem> bad = cat.items();
    bad.push_back({"r1", "t", Direction::UP, 1, "t", false});  // 重复 route_id
    EXPECT_FALSE(cat.validate(bad, err));
    EXPECT_EQ(cat.items().size(), 1u);
}

#if !TSP_MQTT_ROUTE_API
// expand_topic_template 仅 legacy 模式可用 (CR-006: route 模式 TSP 不展开模板)
TEST(SubscriptionCatalogTest, ExpandTopicTemplate) {
    EXPECT_EQ(expand_topic_template("vehicle/{ecu_uid}/up/fota", "ECU123"),
              "vehicle/ECU123/up/fota");
    // 无占位符原样返回
    EXPECT_EQ(expand_topic_template("static/topic", "ECU123"), "static/topic");
}
#endif

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
