# tests/CMakeLists.txt

# 查找 GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(/Users/hwyz_leo/miniconda3/include)
link_directories(/Users/hwyz_leo/miniconda3/lib)

# LogAdapter 单元测试
add_executable(LogAdapterTest
    test_log_adapter.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
target_include_directories(LogAdapterTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(LogAdapterTest PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
target_include_directories(LogAdapterTest PRIVATE ${HWYZ_INCLUDE_DIR})
target_include_directories(LogAdapterTest PRIVATE ${GTEST_INCLUDE_DIRS})
if(HAS_FRAMEWORK_LOG)
    target_include_directories(LogAdapterTest PRIVATE "${TBOX_FW_DIR}/include")
    target_compile_definitions(LogAdapterTest PRIVATE HAS_FRAMEWORK_LOG=1)
endif()
target_link_libraries(LogAdapterTest PRIVATE ${TBOX_FRAMEWORK_LIB})
target_link_libraries(LogAdapterTest PRIVATE gtest gtest_main)
target_link_libraries(LogAdapterTest PRIVATE yaml-cpp)

# 集成测试
add_executable(IpcIntegrationTest
    test_ipc_integration.cpp
    ${PROJECT_SOURCE_DIR}/src/ipc_protocol.cpp
    ${PROJECT_SOURCE_DIR}/src/ipc_server.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/someip_facade_impl.cpp
    ${PROJECT_SOURCE_DIR}/src/log_adapter.cpp)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
target_include_directories(IpcIntegrationTest PRIVATE ${HWYZ_INCLUDE_DIR})
target_include_directories(IpcIntegrationTest PRIVATE ${GTEST_INCLUDE_DIRS})
target_include_directories(IpcIntegrationTest PRIVATE "${TBOX_FW_DIR}/include")
target_compile_definitions(IpcIntegrationTest PRIVATE HAS_FRAMEWORK_LOG=1)
target_link_libraries(IpcIntegrationTest PRIVATE ${TBOX_FRAMEWORK_LIB})
target_link_libraries(IpcIntegrationTest PRIVATE gtest gtest_main)
target_link_libraries(IpcIntegrationTest PRIVATE yaml-cpp)
