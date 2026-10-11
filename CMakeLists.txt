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

# --- TBox SEC client SDK（TBOX-TSP-DSN-CR-010 §3.2 / TBOX-SEC-DSN-CR-019:
#     keyprov 件内状态查询与 Wrapped Key 原子导入，只通过 tbox::sec_client） ---
if(NOT TARGET tbox::sec_client)
    find_package(TboxSecClient CONFIG REQUIRED)
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
# 先解析 pkg-config protobuf（headers/libs），再选择与它同源目录的 protoc。
# 若不这样做，find_program 可能命中 /usr/local/bin/protoc(3.12.4) 而 pkg-config
# 提供的是 Homebrew protobuf(35.x) 头文件，导致“旧生成代码 + 新 headers”不匹配。
#
# 注意：FindPkgConfig 会缓存 __pkg_config_checked_<prefix>，旧 build/ 目录可能
# 因此保留过期的 protobuf 结果（如已损坏的 /usr/local 3.12.4）。先清除该标记
# 以便重配置时始终按当前环境重新解析 protobuf，避免旧缓存钉死错误版本。
unset(__pkg_config_checked_PROTOBUF CACHE)
if(NOT TARGET PkgConfig::PROTOBUF)
    find_package(PkgConfig REQUIRED)
    set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
    pkg_check_modules(PROTOBUF REQUIRED IMPORTED_TARGET protobuf)
endif()

# 优先在 pkg-config protobuf 前缀的 bin/ 下查找 protoc（同源）；否则回退 PATH。
# 使用独立变量（非缓存）避免旧 build/ 里过期 PROTOC_EXECUTABLE 缓存干扰。
unset(TSP_PROTOBUF_PROTOC CACHE)
if(PROTOBUF_INCLUDEDIR)
    get_filename_component(_tsp_protobuf_prefix "${PROTOBUF_INCLUDEDIR}" DIRECTORY)
    find_program(TSP_PROTOBUF_PROTOC NAMES protoc
        HINTS "${_tsp_protobuf_prefix}/bin" "${_tsp_protobuf_prefix}/../bin"
        NO_DEFAULT_PATH)
    unset(_tsp_protobuf_prefix)
endif()
if(NOT TSP_PROTOBUF_PROTOC)
    find_program(TSP_PROTOBUF_PROTOC NAMES protoc REQUIRED)
endif()
set(PROTOC_EXECUTABLE "${TSP_PROTOBUF_PROTOC}")
message(STATUS "TSP protoc: ${PROTOC_EXECUTABLE} (protobuf ${PROTOBUF_VERSION})")

set(TSP_PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(TSP_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
file(GLOB_RECURSE TSP_PROTO_FILES CONFIGURE_DEPENDS "${TSP_PROTO_SRC_DIR}/*.proto")

# protoc 路径变化时强制重新生成，避免旧生成物与当前头文件版本错配。
# configure_file(COPYONLY) 仅在内容变化时更新 stamp 的 mtime。
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/tsp_protoc_path.in"
     "${PROTOC_EXECUTABLE}\n")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/tsp_protoc_path.in"
               "${CMAKE_CURRENT_BINARY_DIR}/tsp_protoc_path.stamp" COPYONLY)

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
        DEPENDS "${PROTO_FILE}" "${CMAKE_CURRENT_BINARY_DIR}/tsp_protoc_path.stamp"
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
        src/keyprov_protocol.cpp         # CR-010 §4.2: keyprov wire codec
        src/v2c_key_provisioning_store.cpp      # CR-010 §5: 非敏感流程状态持久化
        src/v2c_key_provisioning_coordinator.cpp # CR-010 §3.1: V2C keyprov 编排
        src/sec_business_key_adapter.cpp         # CR-010 §3.2: SEC 业务密钥适配器
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
               tbox::sec_client
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
