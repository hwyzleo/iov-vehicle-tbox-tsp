cmake_minimum_required(VERSION 3.10)
project(tbox_tsp)

# 设置macOS最低版本
if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "15.2" CACHE STRING "Minimum OS X deployment version")
endif()

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-Wall -g")

include(GNUInstallDirs)

# 根据不同的环境设置不同的库文件目录
if (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/arm64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/aarch64-linux-gnu)
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-linux-gnu)
    endif ()
endif ()

# 添加库文件目录
link_directories(${LIB_DIR}/yaml-cpp)

# ============================================================
# TBOX-Framework（提供 Application 基类、framework-log、framework-ipc）
# ============================================================
set(TBOX_FW_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-framework" CACHE PATH "Path to TBOX-Framework project")

find_library(TBOX_FRAMEWORK_LIB
        NAMES tbox-framework
        PATHS "${TBOX_FW_DIR}/build"
        NO_DEFAULT_PATH)
if(NOT TBOX_FRAMEWORK_LIB)
    message(FATAL_ERROR "tbox-framework 库未找到，请先构建：cmake --build \"${TBOX_FW_DIR}/build\"")
endif()
message(STATUS "Using tbox-framework: ${TBOX_FRAMEWORK_LIB}")

set(FRAMEWORK_INCLUDE_DIR "${TBOX_FW_DIR}/include")
set(HAS_FRAMEWORK_LOG TRUE)

# ============================================================
# TBOX-MQTT 客户端库（CR-003 §1: TSP 对 MQTT 只使用 tbox::mqtt_client）
# ============================================================
set(TBOX_MQTT_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-mqtt" CACHE PATH "Path to TBOX-MQTT project")
find_library(TBOX_MQTT_CLIENT_LIB
        NAMES tbox_mqtt_client
        PATHS "${TBOX_MQTT_DIR}/build"
        NO_DEFAULT_PATH)
if(NOT TBOX_MQTT_CLIENT_LIB)
    message(FATAL_ERROR "tbox_mqtt_client 库未找到，请先构建：cmake --build \"${TBOX_MQTT_DIR}/build\"")
endif()
message(STATUS "Using tbox_mqtt_client: ${TBOX_MQTT_CLIENT_LIB}")
set(TBOX_MQTT_INCLUDE_DIR "${TBOX_MQTT_DIR}/include")

# ============================================================
# TBOX-PROV 客户端库（用于获取设备序列号）
# ============================================================
set(TBOX_PROV_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-prov" CACHE PATH "Path to TBOX-PROV project")
if(EXISTS "${TBOX_PROV_DIR}/build/libProvClient.a")
    message(STATUS "Found TBOX-PROV client library: ${TBOX_PROV_DIR}/build/libProvClient.a")
    link_directories("${TBOX_PROV_DIR}/build")
    set(HAS_TBOX_PROV TRUE)
else()
    message(WARNING "TBOX-PROV client library not found. Device SN must be configured manually.")
    set(HAS_TBOX_PROV FALSE)
endif()

# ============================================================
# Client SDK 库 (tbox_tsp_client / tbox::tsp_client, CR-003 §7)
# TSP daemon 不链接 tsp_client；双方共享 protocol contract/DTO。
# ============================================================
set(TSP_CLIENT_SOURCES
    src/tsp_client.cpp
    src/tsp_retry_policy.cpp
    src/tsp_error_codes.cpp
)

add_library(tbox_tsp_client STATIC ${TSP_CLIENT_SOURCES})
add_library(tbox::tsp_client ALIAS tbox_tsp_client)

# PUBLIC: 业务 facade/DTO 头文件（framework-ipc 头由调用方提供，与 SEC/MQTT SDK 一致）
target_include_directories(tbox_tsp_client
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# PRIVATE: framework-ipc 链接与内部头
target_link_libraries(tbox_tsp_client
    PRIVATE ${TBOX_FRAMEWORK_LIB}
)
target_include_directories(tbox_tsp_client PRIVATE
    ${FRAMEWORK_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/third_party/include
)

# 安装公共 SDK 头文件
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/tbox/tsp/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tbox/tsp
    FILES_MATCHING PATTERN "*.h"
)

# 安装 client 库
install(TARGETS tbox_tsp_client
    EXPORT TboxTspClientTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# 导出 CMake config
install(EXPORT TboxTspClientTargets
    FILE TboxTspClientTargets.cmake
    NAMESPACE tbox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TboxTspClientConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfig.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
)

# ============================================================
# Main daemon 可执行文件 (CR-003: framework-ipc Server + tbox::mqtt_client)
# ============================================================
add_executable(tbox_tsp
        src/main.cpp
        src/fota_handler.cpp
        src/mqtt_client_adapter.cpp
        src/tsp_ipc_dispatcher.cpp
        src/tsp_event_publisher.cpp
        src/tsp_framework_server.cpp
        src/tsp_error_codes.cpp
        src/net_status_provider.cpp
        src/security_manager.cpp
        src/tsp_http_client.cpp
        src/log_adapter.cpp)

target_include_directories(tbox_tsp PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(tbox_tsp PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
target_include_directories(tbox_tsp PRIVATE ${FRAMEWORK_INCLUDE_DIR})
target_include_directories(tbox_tsp PRIVATE ${TBOX_MQTT_INCLUDE_DIR})
target_link_libraries(tbox_tsp PRIVATE ${TBOX_FRAMEWORK_LIB})
target_link_libraries(tbox_tsp PRIVATE ${TBOX_MQTT_CLIENT_LIB})
find_package(CURL REQUIRED)
target_link_libraries(tbox_tsp PRIVATE ${CURL_LIBRARIES})
target_link_libraries(tbox_tsp PRIVATE yaml-cpp)

target_compile_definitions(tbox_tsp PRIVATE HAS_FRAMEWORK_LOG=1)

# 链接 TBOX-PROV 客户端库
if(HAS_TBOX_PROV)
    target_link_libraries(tbox_tsp PRIVATE ProvClient)
    target_compile_definitions(tbox_tsp PRIVATE HAS_TBOX_PROV=1)
    target_include_directories(tbox_tsp PRIVATE "${TBOX_PROV_DIR}/include")
endif()

# ============================================================
# 测试（可选）
# ============================================================
option(BUILD_TESTS "Build tests" OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
