// tests/test_log_adapter.cpp
// 编译: g++ -std=c++17 -I../include -I../../iov-vehicle-tbox-framework/include test_log_adapter.cpp ../src/log_adapter.cpp -o test_log_adapter -L../../iov-vehicle-tbox-framework/build -lhwyz -lpthread
// 运行: ./test_log_adapter

#include <iostream>
#include <cassert>
#include <string>

#include "log_adapter.h"

using namespace tbox::tsp;
using namespace tbox::fw::log;

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

int test_log_adapter_init() {
    // 测试初始化
    LogConfig config;
    config.level = LogLevel::kInfo;
    config.console_config.enabled = true;

    auto result = LogAdapter::init("tsp", config);
    TEST_ASSERT(result.error == LogError::kOk, "LogAdapter init should succeed");
    TEST_PASS("test_log_adapter_init");
    return 0;
}

int test_log_adapter_get_modules() {
    // 测试获取各模块 Logger
    auto route_log = LogAdapter::route();
    auto fota_log = LogAdapter::fota();
    auto mqtt_log = LogAdapter::mqtt_client();
    auto someip_log = LogAdapter::someip_bridge();
    auto relay_log = LogAdapter::relay();

    // Logger 实例应该有效（不崩溃即通过）
    TEST_PASS("test_log_adapter_get_modules");
    return 0;
}

int test_log_adapter_log_output() {
    // 测试日志输出不崩溃
    auto log = LogAdapter::fota();
    log.info("tsp.test.event", "测试消息", {
        {"key1", FieldValue::makeString("value1")},
        {"key2", FieldValue::makeInt(42)}
    });
    TEST_PASS("test_log_adapter_log_output");
    return 0;
}

int test_log_adapter_context_scope() {
    // 测试上下文传播
    LogContext ctx;
    ctx.request_id = "req-123";
    ctx.trace_id = "trace-456";

    ContextScope scope(ctx);

    auto log = LogAdapter::fota();
    log.info("tsp.test.context", "带上下文的日志");

    TEST_PASS("test_log_adapter_context_scope");
    return 0;
}

int main() {
    int failures = 0;
    failures += test_log_adapter_init();
    failures += test_log_adapter_get_modules();
    failures += test_log_adapter_log_output();
    failures += test_log_adapter_context_scope();

    if (failures == 0) {
        std::cout << "\n所有测试通过!" << std::endl;
    } else {
        std::cerr << "\n" << failures << " 个测试失败!" << std::endl;
    }
    return failures;
}
