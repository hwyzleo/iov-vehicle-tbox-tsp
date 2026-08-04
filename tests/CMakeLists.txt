# tests/CMakeLists.txt

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
# miniconda GTest config 未设置 include dir，显式补充
if(NOT GTEST_INCLUDE_DIRS OR NOT EXISTS "${GTEST_INCLUDE_DIRS}/gtest/gtest.h")
    include_directories(/Users/hwyz_leo/miniconda3/include)
    link_directories(/Users/hwyz_leo/miniconda3/lib)
endif()

# CR-007: framework 组件 target 传递公共头（config/log/ipc/store/application）与
# yaml-cpp（framework-config PUBLIC）；nlohmann_json 为 TSP 直接 TARGET 依赖。
set(TEST_COMMON_INCLUDES
    ${PROJECT_SOURCE_DIR}/include
    ${GTEST_INCLUDE_DIRS}
)
set(TEST_COMMON_LIBS
    ${TSP_FRAMEWORK_LIBS}
    nlohmann_json::nlohmann_json
    gtest gtest_main
)
set(TEST_COMPILE_DEFS HAS_FRAMEWORK_LOG=1)

# 通用函数：声明一个测试可执行文件
function(tsp_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${TEST_COMMON_INCLUDES})
    target_compile_definitions(${name} PRIVATE ${TEST_COMPILE_DEFS})
    if(TSP_USE_MQTT_ROUTE_API)
        target_compile_definitions(${name} PRIVATE TSP_USE_MQTT_ROUTE_API=1)
    else()
        target_compile_definitions(${name} PRIVATE TSP_USE_MQTT_ROUTE_API=0)
    endif()
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
    ${PROJECT_SOURCE_DIR}/src/downlink_route_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# ============================================================
# 4b. DownlinkRouteDispatcher 单元测试 (CR-006 §6.2)
# ============================================================
tsp_add_test(DownlinkRouteDispatcherTest
    test_downlink_route_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/downlink_route_dispatcher.cpp
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
#    legacy full-topic 路径；route 模式由 TspApplicationTest 覆盖 (CR-006)
# ============================================================
if(NOT TSP_USE_MQTT_ROUTE_API)
tsp_add_test(TspIntegrationTest
    test_tsp_integration.cpp
    ${PROJECT_SOURCE_DIR}/src/fota_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/downlink_route_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_framework_server.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_ipc_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
target_link_libraries(TspIntegrationTest PRIVATE tbox_tsp_client)
endif()

# ============================================================
# 7. LogAdapter 单元测试（保留）
# ============================================================
tsp_add_test(LogAdapterTest
    test_log_adapter.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# ============================================================
# CR-004: 业务订阅快照单元测试
# ============================================================
# 8. SubscriptionCatalog 单元测试（目录校验）
tsp_add_test(SubscriptionCatalogTest
    test_subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# 9. SnapshotBuilder 单元测试（稳定排序/摘要/generation）
tsp_add_test(SnapshotBuilderTest
    test_snapshot_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/snapshot_builder.cpp)

# 10. SubscriptionStore 单元测试（generation 持久化）
tsp_add_test(SubscriptionStoreTest
    test_subscription_store.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_store.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# 11. RegistrationState 单元测试（状态机）
tsp_add_test(RegistrationStateTest
    test_registration_state.cpp
    ${PROJECT_SOURCE_DIR}/src/registration_state.cpp)

# 12. MqttSubscriptionRegistrar 单元测试（提交/幂等/断连恢复/原子替换）
tsp_add_test(SubscriptionRegistrarTest
    test_subscription_registrar.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_registrar.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/snapshot_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_store.cpp
    ${PROJECT_SOURCE_DIR}/src/registration_state.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)

# 13. 业务订阅快照端到端集成测试 (CR-004 §12)
#     legacy full-topic 路径；route 模式由 TspApplicationTest 覆盖 (CR-006)
if(NOT TSP_USE_MQTT_ROUTE_API)
tsp_add_test(SubscriptionIntegrationTest
    test_subscription_integration.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_registrar.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_catalog.cpp
    ${PROJECT_SOURCE_DIR}/src/snapshot_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/subscription_store.cpp
    ${PROJECT_SOURCE_DIR}/src/registration_state.cpp
    ${PROJECT_SOURCE_DIR}/src/fota_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/downlink_route_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_event_publisher.cpp
    ${PROJECT_SOURCE_DIR}/src/tsp_error_codes.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
endif()

# ============================================================
# CR-005 §10.2: TspApplication 组合根单元测试
# 链接 tbox_tsp_lib（含 TspApplication + TspRelayService + 全部业务/传输源），
# 覆盖信号集合、initialize 各阶段成功/失败与逆序 rollback、execute 退出、cleanup 幂等。
# ============================================================
tsp_add_test(TspApplicationTest
    test_tsp_application.cpp)
target_link_libraries(TspApplicationTest PRIVATE tbox_tsp_lib)
