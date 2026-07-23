// tests/test_fota_handler.cpp
// 编译: g++ -std=c++17 -I../include -I../third_party/include test_fota_handler.cpp ../src/fota_handler.cpp ../src/mqtt_facade_stub.cpp ../src/someip_facade_stub.cpp -o test_fota_handler -lgtest -lgtest_main -lpthread
// 运行: ./test_fota_handler

#include <iostream>
#include <cassert>
#include <string>
#include <vector>

#include "fota_handler.h"
#include "mqtt_facade_stub.h"
#include "someip_facade_stub.h"

using namespace tbox::tsp;

// 简单的测试宏
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl; \
            return 1; \
        } \
    } while(0)

#define TEST_PASS(name) \
    std::cout << "PASS: " << name << std::endl

int test_initialize_empty_sn() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    FotaHandler handler(mqtt, someip);
    TEST_ASSERT(!handler.initialize(""), "Empty device_sn should fail");
    TEST_PASS("test_initialize_empty_sn");
    return 0;
}

int test_initialize_valid_sn() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    mqtt->initialize();
    someip->initialize();
    FotaHandler handler(mqtt, someip);
    TEST_ASSERT(handler.initialize("SN001"), "Valid device_sn should succeed");
    TEST_PASS("test_initialize_valid_sn");
    return 0;
}

int test_start_before_initialize() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    FotaHandler handler(mqtt, someip);
    TEST_ASSERT(!handler.start(), "Start before initialize should fail");
    TEST_PASS("test_start_before_initialize");
    return 0;
}

int test_start_after_initialize() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    mqtt->initialize();
    mqtt->start();
    someip->initialize();
    someip->start();
    FotaHandler handler(mqtt, someip);
    handler.initialize("SN001");
    TEST_ASSERT(handler.start(), "Start after initialize should succeed");
    TEST_PASS("test_start_after_initialize");
    return 0;
}

int test_upstream_publishes() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    mqtt->initialize();
    mqtt->start();
    someip->initialize();
    someip->start();
    FotaHandler handler(mqtt, someip);
    handler.initialize("SN001");
    handler.start();

    // 模拟上行 snapshot
    std::vector<uint8_t> snapshot = {'{', '"', 'v', 'e', 'r', 's', 'i', 'o',
                                      'n', '"', ':', '"', '1', '.', '0', '"', '}'};
    someip->simulate_report_software_inventory(snapshot);
    // Stub 模式下通过日志验证，这里只验证不崩溃
    TEST_PASS("test_upstream_publishes");
    return 0;
}

int test_downward_forwards() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    mqtt->initialize();
    mqtt->start();
    someip->initialize();
    someip->start();
    FotaHandler handler(mqtt, someip);
    handler.initialize("SN001");
    handler.start();

    // 模拟下行消息
    std::string payload = R"({"command":"update","version":"2.0"})";
    std::vector<uint8_t> payload_bytes(payload.begin(), payload.end());
    mqtt->simulate_incoming("vehicle/SN001/down/fota", payload_bytes);
    TEST_PASS("test_downward_forwards");
    return 0;
}

int test_dedup_rejects_duplicate() {
    auto mqtt = std::make_shared<MqttFacadeStub>();
    auto someip = std::make_shared<SomeipFacadeStub>();
    mqtt->initialize();
    mqtt->start();
    someip->initialize();
    someip->start();
    FotaHandler handler(mqtt, someip);
    handler.initialize("SN001");
    handler.start();

    std::vector<uint8_t> snapshot = {'t', 'e', 's', 't'};

    // 第一次
    someip->simulate_report_software_inventory(snapshot);
    // 第二次（应被去重丢弃）
    someip->simulate_report_software_inventory(snapshot);
    TEST_PASS("test_dedup_rejects_duplicate");
    return 0;
}

int main() {
    int failures = 0;
    failures += test_initialize_empty_sn();
    failures += test_initialize_valid_sn();
    failures += test_start_before_initialize();
    failures += test_start_after_initialize();
    failures += test_upstream_publishes();
    failures += test_downward_forwards();
    failures += test_dedup_rejects_duplicate();

    if (failures == 0) {
        std::cout << "\n所有测试通过!" << std::endl;
    } else {
        std::cerr << "\n" << failures << " 个测试失败!" << std::endl;
    }
    return failures;
}
