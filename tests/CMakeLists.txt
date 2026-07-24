# tests/CMakeLists.txt

# 查找 GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(/Users/hwyz_leo/miniconda3/include)
link_directories(/Users/hwyz_leo/miniconda3/lib)

# 集成测试
add_executable(IpcIntegrationTest
    test_ipc_integration.cpp
    ${PROJECT_SOURCE_DIR}/src/ipc_protocol.cpp
    ${PROJECT_SOURCE_DIR}/src/ipc_server.cpp
    ${PROJECT_SOURCE_DIR}/src/net_status_provider.cpp
    ${PROJECT_SOURCE_DIR}/src/someip_facade_impl.cpp)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(IpcIntegrationTest PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
target_include_directories(IpcIntegrationTest PRIVATE ${HWYZ_INCLUDE_DIR})
target_include_directories(IpcIntegrationTest PRIVATE ${GTEST_INCLUDE_DIRS})
target_link_libraries(IpcIntegrationTest PRIVATE gtest gtest_main pthread)
target_link_libraries(IpcIntegrationTest PRIVATE ${HWYZ_LIBRARIES})
target_link_libraries(IpcIntegrationTest PRIVATE yaml-cpp)
