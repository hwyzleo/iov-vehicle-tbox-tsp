# tests/CMakeLists.txt

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
# miniconda GTest config 未设置 include dir，显式补充
if(NOT GTEST_INCLUDE_DIRS OR NOT EXISTS "${GTEST_INCLUDE_DIRS}/gtest/gtest.h")
    include_directories(/Users/hwyz_leo/miniconda3/include)
    link_directories(/Users/hwyz_leo/miniconda3/lib)
endif()

set(TEST_COMMON_INCLUDES
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/third_party/include
    ${FRAMEWORK_INCLUDE_DIR}
    ${GTEST_INCLUDE_DIRS}
)
set(TEST_COMMON_LIBS
    ${TBOX_FRAMEWORK_LIB}
    gtest gtest_main
    yaml-cpp
)
set(TEST_COMPILE_DEFS HAS_FRAMEWORK_LOG=1)

# 通用函数：声明一个测试可执行文件
function(tsp_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${TEST_COMMON_INCLUDES})
    target_compile_definitions(${name} PRIVATE ${TEST_COMPILE_DEFS})
    target_link_libraries(${name} PRIVATE ${TEST_COMMON_LIBS})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ============================================================
# 1. 重试策略单元测试
# ============================================================
tsp_add_test(TspRetryPolicyTest
    test_tsp_retry_policy.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_retry_policy.cpp)

# ============================================================
# 2. IPC Dispatcher 单元测试
# ============================================================
tsp_add_test(TspIpcDispatcherTest
    test_tsp_ipc_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_ipc_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# ============================================================
# 3. EventPublisher 单元测试（背压、顺序、慢消费者）
# ============================================================
tsp_add_test(TspEventPublisherTest
    test_tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# ============================================================
# 4. FotaHandler (FotaRelay) 单元测试（幂等、accepted≠PUBACK、节流、下行）
# ============================================================
tsp_add_test(FotaHandlerTest
    test_fota_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/fota_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# ============================================================
# 5. tsp_client <-> Server 集成测试（wire protocol 契约）
# ============================================================
tsp_add_test(TspClientServerTest
    test_tsp_client.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_framework_server.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_ipc_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
target_link_libraries(TspClientServerTest PRIVATE tbox_tsp_client)

# ============================================================
# 6. 端到端集成测试（client -> server -> FotaRelay -> mock mqtt / 反向）
# ============================================================
tsp_add_test(TspIntegrationTest
    test_tsp_integration.cpp
    ${PROJECT_SOURCE_DIR}/src/fota_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_framework_server.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_ipc_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
target_link_libraries(TspIntegrationTest PRIVATE tbox_tsp_client)

# ============================================================
# 7. LogAdapter 单元测试（保留）
# ============================================================
tsp_add_test(LogAdapterTest
    test_log_adapter.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
