# TBOX-TSP-DSN-CR-007: 接入 TBOX-BUILD 统一 Orin aarch64 构建。
#   - 不设置 CMAKE_C_COMPILER / CMAKE_CXX_COMPILER / CMAKE_SYSROOT（由 BUILD
#     toolchain/preset 注入）
#   - framework / MQTT 通过已安装 package 消费（find_package CONFIG），
#     禁止 add_subdirectory、源码私有头文件、build-tree library 或绝对库路径
#   - GNUInstallDirs + 两个显式 install component: tsp-sdk / tsp-runtime
#   - 无硬编码 RPATH / 宿主路径 / build-tree library

cmake_minimum_required(VERSION 3.16)
project(tbox_tsp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ============================================================
# CR-006 构建开关：MQTT Route API 迁移
# ============================================================
# TSP_USE_MQTT_ROUTE_API=ON (默认, CR-006 §10.2): route 模式，TSP 不构造 prov_client、
#   不缓存 ecu_uid、不拼装完整 Topic；上行 publishRoute，下行 subscribeRoutedDownlink。
# OFF (deprecated): legacy 完整 Topic 路径，经 PROV readBinding 获取 ecu_uid。
option(TSP_USE_MQTT_ROUTE_API "Use MQTT route-based API (CR-006); legacy full-topic path is deprecated" ON)

# ============================================================
# 依赖（BUILD: 受控 staging/sysroot 注入；HOST: tbox-env.sh + CMAKE_PREFIX_PATH）
# ============================================================

# --- TBox Framework（CR-007 §6.2: find_package CONFIG + 组件 target 消费） ---
# TSP 使用 framework-config / -log / -ipc / -store / -application 组件；
# yaml-cpp / spdlog 由 framework 组件传递（framework-config PUBLIC yaml-cpp）。
if(NOT TARGET TBoxFramework::config)
    find_package(TboxFramework CONFIG REQUIRED)
endif()
set(TSP_FRAMEWORK_LIBS
    TBoxFramework::config
    TBoxFramework::log
    TBoxFramework::ipc
    TBoxFramework::store
    TBoxFramework::hash
    TBoxFramework::application
)

# --- TBox MQTT client SDK（CR-003 §1 / CR-007 §6.2: 只通过 tbox::mqtt_client） ---
if(NOT TARGET tbox::mqtt_client)
    find_package(TboxMqttClient CONFIG REQUIRED)
endif()

# --- nlohmann_json（TSP 源码直接使用；CR-007 §7: 直接 TARGET dependency） ---
find_package(nlohmann_json REQUIRED)

# --- TBox PROV client SDK（仅 legacy 模式用于设备序列号；route 模式不链接） ---
# CR-007 §6.2: 目标态不为 Topic 构造 tbox::prov_client；PROV/SEC 只由 MQTT
# 构建闭包带入。legacy 分支为 deprecated 回滚验证入口，HOST 开发使用。
set(HAS_TBOX_PROV FALSE)
if(NOT TSP_USE_MQTT_ROUTE_API)
    if(NOT TARGET tbox::prov_client)
        find_package(TboxProvClient CONFIG REQUIRED)
    endif()
    set(HAS_TBOX_PROV TRUE)
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
set_target_properties(tbox_tsp_client PROPERTIES EXPORT_NAME tsp_client)

# PUBLIC: 业务 facade/DTO 头文件（framework-ipc 头由消费方经 TboxTspClientConfig
# find_dependency(TboxFramework) 解析，与 SEC/MQTT SDK 一致）
target_include_directories(tbox_tsp_client
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# PRIVATE: framework 组件与 nlohmann_json（client.h 公开头引用 framework-ipc
# Subscription RAII 句柄；静态库 PRIVATE 依赖由 Config find_dependency 声明）
target_link_libraries(tbox_tsp_client
    PRIVATE
        ${TSP_FRAMEWORK_LIBS}
        nlohmann_json::nlohmann_json
)

# ============================================================
# TBOX-TSP daemon 库（CR-005 §9.1 / CR-007 §6.3: 供 daemon 可执行文件与
# Application 单测共享；包含全部业务/传输源，不含 main 入口）
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
        PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(tbox_tsp_lib
        PUBLIC ${TSP_FRAMEWORK_LIBS}
               tbox::mqtt_client
               nlohmann_json::nlohmann_json)
target_compile_definitions(tbox_tsp_lib PUBLIC HAS_FRAMEWORK_LOG=1)
if(TSP_USE_MQTT_ROUTE_API)
    target_compile_definitions(tbox_tsp_lib PUBLIC TSP_USE_MQTT_ROUTE_API=1)
else()
    target_compile_definitions(tbox_tsp_lib PUBLIC TSP_USE_MQTT_ROUTE_API=0)
    if(HAS_TBOX_PROV)
        target_link_libraries(tbox_tsp_lib PUBLIC tbox::prov_client)
        target_compile_definitions(tbox_tsp_lib PUBLIC HAS_TBOX_PROV=1)
    endif()
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
# Install rules — 两个显式 component (CR-007 §9)
#
#   tsp-sdk     -> staging: sdk      (公开头文件 / 静态库 / CMake package)
#   tsp-runtime -> staging: rootfs   (daemon / systemd unit / 默认非秘密配置)
# ============================================================

# --- tsp-runtime: daemon binary ---
install(TARGETS tbox_tsp
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT tsp-runtime
)

# --- tsp-runtime: systemd unit ---
install(FILES packaging/systemd/tbox-tsp.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
    COMPONENT tsp-runtime
)

# --- tsp-runtime: default config（生产安全：无 VIN/SN/ECU UID 实例值、
#      完整设备 Topic、凭据或生产业务数据；只含未展开模板/route_id/QoS/target） ---
install(FILES config/tsp.default.yaml
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/tbox/conf.d
    RENAME tsp.yaml
    COMPONENT tsp-runtime
)

# --- tsp-sdk: public headers ---
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/tbox/tsp/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tbox/tsp
    COMPONENT tsp-sdk
    FILES_MATCHING PATTERN "*.h"
)

# --- tsp-sdk: client static library + export ---
install(TARGETS tbox_tsp_client
    EXPORT TboxTspClientTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT tsp-sdk
)

install(EXPORT TboxTspClientTargets
    FILE TboxTspClientTargets.cmake
    NAMESPACE tbox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
    COMPONENT tsp-sdk
)

# --- tsp-sdk: CMake package config（可重定位）+ version ---
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TboxTspClientConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/TboxTspClientConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TboxTspClient
    COMPONENT tsp-sdk
)

# ============================================================
# 测试（可选；HOST/隔离 test profile 使用，不进入量产 package）
# ============================================================
option(BUILD_TESTS "Build tests" OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
