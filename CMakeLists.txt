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

# 不再 link_directories(${LIB_DIR}/yaml-cpp)：
# yaml-cpp 的符号已随 libtbox-framework 一起导出，头文件也随 framework 安装。

# ============================================================
# TBOX-Framework（提供 Application 基类、framework-log、framework-ipc）
# ============================================================
# 统一通过 find_package 消费：framework 自包含 yaml-cpp / spdlog，
# 查找前缀来自 iov-vehicle-tbox-framework/scripts/tbox-env.sh 的 TBOX_PREFIX
# （见 scripts/build.sh），切换本地/生产环境无需改动本文件。
if(NOT TARGET TBoxFramework::tbox-framework)
    find_package(TBoxFramework REQUIRED)
endif()
set(TBOX_FRAMEWORK_LIB TBoxFramework::tbox-framework)
set(FRAMEWORK_INCLUDE_DIR ${TBoxFramework_INCLUDE_DIRS})
set(HAS_FRAMEWORK_LOG TRUE)
message(STATUS "Using TBoxFramework headers: ${FRAMEWORK_INCLUDE_DIR}")

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
# CR-006 构建开关：MQTT Route API 迁移
# ============================================================
# TSP_USE_MQTT_ROUTE_API=ON (默认, CR-006 §10.2): route 模式，TSP 不构造 prov_client、
#   不缓存 ecu_uid、不拼装完整 Topic；上行 publishRoute，下行 subscribeRoutedDownlink。
# OFF (deprecated): legacy 完整 Topic 路径，经 PROV readBinding 获取 ecu_uid。
option(TSP_USE_MQTT_ROUTE_API "Use MQTT route-based API (CR-006); legacy full-topic path is deprecated" ON)

# ============================================================
# TBOX-PROV 客户端库（legacy 模式用于获取设备序列号；route 模式不依赖 PROV）
# ============================================================
set(TBOX_PROV_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-prov" CACHE PATH "Path to TBOX-PROV project")
if(NOT TSP_USE_MQTT_ROUTE_API)
    # legacy 模式: 查找并链接 PROV 客户端库
    find_library(TBOX_PROV_CLIENT_LIB
            NAMES tbox_prov_client
            PATHS "${TBOX_PROV_DIR}/build"
            NO_DEFAULT_PATH)
    find_library(TBOX_PROV_DAEMON_LIB
            NAMES TboxProvLib
            PATHS "${TBOX_PROV_DIR}/build"
            NO_DEFAULT_PATH)
    if(TBOX_PROV_CLIENT_LIB)
        message(STATUS "Using tbox_prov_client: ${TBOX_PROV_CLIENT_LIB}")
        set(HAS_TBOX_PROV TRUE)
    else()
        message(WARNING "TBOX-PROV client library (tbox_prov_client) not found in "
                        "${TBOX_PROV_DIR}/build. Build PROV first: "
                        "cmake --build \"${TBOX_PROV_DIR}/build\". "
                        "Falling back to configured tsp.device-sn.")
        set(HAS_TBOX_PROV FALSE)
    endif()
else()
    # route 模式: 不链接 PROV (CR-006 §8, §10.2)
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
# TBOX-TSP daemon 库（CR-005 §9.1: 供 daemon 可执行文件与 Application 单测共享）
# 包含全部业务/传输源（不含 main 入口），以便 TspApplication 单测链接。
# ============================================================
set(TBOX_TSP_DAEMON_SOURCES
        src/fota_handler.cpp
        src/mqtt_client_adapter.cpp
        src/downlink_route_dispatcher.cpp
        src/subscription_catalog.cpp
        src/snapshot_builder.cpp
        src/subscription_store.cpp
        src/registration_state.cpp
        src/subscription_registrar.cpp
        src/tsp_ipc_dispatcher.cpp
        src/tsp_event_publisher.cpp
        src/tsp_framework_server.cpp
        src/tsp_error_codes.cpp
        src/net_status_provider.cpp
        src/log_adapter.cpp
        src/tsp_relay_service.cpp        # CR-005 §3: 业务聚合
        src/tsp_application.cpp)         # CR-005 §3: 进程级组合根

add_library(tbox_tsp_lib STATIC ${TBOX_TSP_DAEMON_SOURCES})
target_include_directories(tbox_tsp_lib
        PUBLIC ${PROJECT_SOURCE_DIR}/include
               ${PROJECT_SOURCE_DIR}/third_party/include
               ${FRAMEWORK_INCLUDE_DIR}
               ${TBOX_MQTT_INCLUDE_DIR})
target_link_libraries(tbox_tsp_lib
        PUBLIC ${TBOX_FRAMEWORK_LIB}
               ${TBOX_MQTT_CLIENT_LIB})
target_compile_definitions(tbox_tsp_lib PUBLIC HAS_FRAMEWORK_LOG=1)
if(TSP_USE_MQTT_ROUTE_API)
    target_compile_definitions(tbox_tsp_lib PUBLIC TSP_USE_MQTT_ROUTE_API=1)
else()
    target_compile_definitions(tbox_tsp_lib PUBLIC TSP_USE_MQTT_ROUTE_API=0)
endif()

# 链接 TBOX-PROV 客户端库
if(HAS_TBOX_PROV)
    target_link_libraries(tbox_tsp_lib PUBLIC ${TBOX_PROV_CLIENT_LIB})
    if(TBOX_PROV_DAEMON_LIB)
        # prov_client 依赖 ProvLogAdapter（定义于 daemon lib），需一并链接
        target_link_libraries(tbox_tsp_lib PUBLIC ${TBOX_PROV_DAEMON_LIB})
    endif()
    target_compile_definitions(tbox_tsp_lib PUBLIC HAS_TBOX_PROV=1)
    target_include_directories(tbox_tsp_lib PUBLIC "${TBOX_PROV_DIR}/include")
endif()

# ============================================================
# Main daemon 可执行文件 (CR-003 + CR-005: framework Application 生命周期)
# CR-005 §9.1: 构建期切换 Application 生命周期。
#   ON  -> TspApplication（hwyz::Application 编排）
#   OFF -> 旧式手写生命周期（回滚验证用，验收后删除）
# ============================================================
option(TSP_USE_FRAMEWORK_APPLICATION "Use hwyz::Application lifecycle" ON)
# CR-006: main_legacy.cpp 不支持 route API（它是 deprecated legacy 入口）。
if(NOT TSP_USE_FRAMEWORK_APPLICATION AND TSP_USE_MQTT_ROUTE_API)
    message(FATAL_ERROR "main_legacy.cpp (TSP_USE_FRAMEWORK_APPLICATION=OFF) does not "
                        "support TSP_USE_MQTT_ROUTE_API=ON; set TSP_USE_MQTT_ROUTE_API=OFF "
                        "or TSP_USE_FRAMEWORK_APPLICATION=ON")
endif()
if(TSP_USE_FRAMEWORK_APPLICATION)
    add_executable(tbox_tsp src/main.cpp)
else()
    add_executable(tbox_tsp src/main_legacy.cpp)
endif()
target_link_libraries(tbox_tsp PRIVATE tbox_tsp_lib)

# ============================================================
# 测试（可选）
# ============================================================
option(BUILD_TESTS "Build tests" OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
