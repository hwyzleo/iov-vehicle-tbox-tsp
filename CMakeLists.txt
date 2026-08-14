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
# TBOX-TSP-DSN-CR-009: 通用 VehicleMessage 单一依赖路径（无 legacy 双路径）
# 已删除 TSP_USE_MQTT_ROUTE_API=OFF / main_legacy.cpp / prov_client / HAS_TBOX_PROV。
# TSP 量产唯一路径为 MQTT Route API（publishRoute + subscribeRoutedDownlink +
# replaceSubscriptionSnapshot）。
# ============================================================

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

# ============================================================
# Proto / protobuf（TBOX-TSP-DSN-CR-009：VEH-PROTO 为文档 SSOT，各服务自备所需 proto）
# - HOST：protoc 仅生成构建中间文件（不进入 runtime package）；
# - TARGET：libprotobuf runtime 来自受控依赖（BUILD dep staging / Orin sysroot
#   已带 libprotobuf.so.17；头文件由 BUILD 纳入 TBOX_DEP_STAGING），
#   与 TBOX-SOMEIP 的 pkg-config 消费方式一致。
# ============================================================
find_program(PROTOC_EXECUTABLE NAMES protoc REQUIRED)
if(NOT TARGET PkgConfig::PROTOBUF)
    find_package(PkgConfig REQUIRED)
    set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
    pkg_check_modules(PROTOBUF REQUIRED IMPORTED_TARGET protobuf)
endif()

set(TSP_PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(TSP_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
file(GLOB_RECURSE TSP_PROTO_FILES CONFIGURE_DEPENDS "${TSP_PROTO_SRC_DIR}/*.proto")

set(TSP_PROTO_GEN_SOURCES "")
set(TSP_PROTO_GEN_HEADERS "")
foreach(PROTO_FILE ${TSP_PROTO_FILES})
    file(RELATIVE_PATH PROTO_REL "${TSP_PROTO_SRC_DIR}" "${PROTO_FILE}")
    string(REPLACE ".proto" ".pb.cc" PROTO_CC "${PROTO_REL}")
    string(REPLACE ".proto" ".pb.h" PROTO_H "${PROTO_REL}")
    set(PROTO_CC_ABS "${TSP_PROTO_GEN_DIR}/${PROTO_CC}")
    set(PROTO_H_ABS "${TSP_PROTO_GEN_DIR}/${PROTO_H}")
    list(APPEND TSP_PROTO_GEN_SOURCES "${PROTO_CC_ABS}")
    list(APPEND TSP_PROTO_GEN_HEADERS "${PROTO_H_ABS}")
    add_custom_command(
        OUTPUT "${PROTO_CC_ABS}" "${PROTO_H_ABS}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${TSP_PROTO_GEN_DIR}"
        COMMAND ${PROTOC_EXECUTABLE} --proto_path=${TSP_PROTO_SRC_DIR}
                --cpp_out=${TSP_PROTO_GEN_DIR}
                --experimental_allow_proto3_optional "${PROTO_FILE}"
        DEPENDS "${PROTO_FILE}"
        COMMENT "protoc: ${PROTO_REL}"
    )
endforeach()

if(TSP_PROTO_GEN_SOURCES)
    add_library(tsp_proto STATIC ${TSP_PROTO_GEN_SOURCES})
    target_include_directories(tsp_proto PUBLIC "${TSP_PROTO_GEN_DIR}")
    target_link_libraries(tsp_proto PUBLIC PkgConfig::PROTOBUF)
    set_target_properties(tsp_proto PROPERTIES POSITION_INDEPENDENT_CODE ON)
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
        src/vehicle_message_gateway.cpp   # CR-009 §16: 通用 VehicleMessage 网关
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
               tsp_proto
               nlohmann_json::nlohmann_json)
target_compile_definitions(tbox_tsp_lib PUBLIC HAS_FRAMEWORK_LOG=1)

# ============================================================
# Main daemon 可执行文件 (CR-005 + CR-009: framework Application 生命周期唯一入口)
# CR-009: main_legacy.cpp 已删除，无 legacy 生命周期/双路径。
# ============================================================
add_executable(tbox_tsp src/main.cpp)
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

# --- tsp-runtime: default config（TBOX-TSP-DSN-CR-008 §15.2: 生产安全默认模板）
#      只含未展开模板/route_id/QoS/target；无 VIN/SN/ECU UID 实例值、完整设备 Topic、
#      凭据或生产业务数据。config/dev/**、config/schema/**、config/README.md
#      不由 tsp-runtime 安装，不进入 rootfs；正式 common 由 BUILD 唯一提供。 ---
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
