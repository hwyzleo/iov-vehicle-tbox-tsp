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

# TBOX-Framework 项目路径（用于 framework-log）
set(TBOX_FW_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-framework" CACHE PATH "Path to TBOX-Framework project")
set(HAS_FRAMEWORK_LOG FALSE)
if(EXISTS "${TBOX_FW_DIR}/include/log.h")
    message(STATUS "Found framework-log: ${TBOX_FW_DIR}")
    # 链接 framework 的 hwyz 库（包含 framework-log）
    if(EXISTS "${TBOX_FW_DIR}/build/libhwyz.dylib")
        link_directories("${TBOX_FW_DIR}/build")
        set(HAS_FRAMEWORK_LOG TRUE)
    elseif(EXISTS "${TBOX_FW_DIR}/build/libhwyz.so")
        link_directories("${TBOX_FW_DIR}/build")
        set(HAS_FRAMEWORK_LOG TRUE)
    else()
        message(WARNING "framework-log library not built yet")
    endif()
else()
    message(WARNING "framework-log not found at ${TBOX_FW_DIR}")
endif()

# TBOX-PROV 客户端库（用于获取设备序列号）
set(TBOX_PROV_DIR "${PROJECT_SOURCE_DIR}/../iov-vehicle-tbox-prov" CACHE PATH "Path to TBOX-PROV project")
if(EXISTS "${TBOX_PROV_DIR}/build/libProvClient.a")
    message(STATUS "Found TBOX-PROV client library: ${TBOX_PROV_DIR}/build/libProvClient.a")
    link_directories("${TBOX_PROV_DIR}/build")
    set(HAS_TBOX_PROV TRUE)
else()
    message(WARNING "TBOX-PROV client library not found. Device SN must be configured manually.")
    set(HAS_TBOX_PROV FALSE)
endif()

# mosquitto 不再直接链接（TSP 不持有 MQTT 连接，SPEC §1）
# link_directories(${LIB_DIR}/mosquitto)
# link_libraries(mosquitto)
# link_libraries(mosquittopp)

# 添加可执行文件
add_executable(tbox_tsp
        src/main.cpp
        src/ipc_protocol.cpp
        src/ipc_server.cpp
        src/net_status_provider.cpp
        src/someip_facade_impl.cpp
        src/mqtt_facade_stub.cpp
        src/someip_facade_stub.cpp
        src/fota_handler.cpp
        src/security_manager.cpp
        src/tsp_http_client.cpp)

# 添加头文件目录
target_include_directories(tbox_tsp PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(tbox_tsp PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)
find_package(HWYZ REQUIRED)
target_include_directories(tbox_tsp PUBLIC ${HWYZ_INCLUDE_DIR})
target_link_libraries(tbox_tsp PRIVATE ${HWYZ_LIBRARIES})
find_package(CURL REQUIRED)
target_link_libraries(tbox_tsp PRIVATE ${CURL_LIBRARIES})
target_link_libraries(tbox_tsp PRIVATE yaml-cpp)

# framework-log 配置（在 add_executable 之后）
if(HAS_FRAMEWORK_LOG)
    target_include_directories(tbox_tsp PRIVATE "${TBOX_FW_DIR}/include")
    target_compile_definitions(tbox_tsp PRIVATE HAS_FRAMEWORK_LOG=1)
    target_link_libraries(tbox_tsp PRIVATE hwyz)
endif()

# 链接 TBOX-PROV 客户端库
if(HAS_TBOX_PROV)
    target_link_libraries(tbox_tsp PRIVATE ProvClient)
    target_compile_definitions(tbox_tsp PRIVATE HAS_TBOX_PROV=1)
    # 添加 TBOX-PROV 头文件目录
    target_include_directories(tbox_tsp PRIVATE "${TBOX_PROV_DIR}/include")
endif()

# 测试（可选）
option(BUILD_TESTS "Build tests" OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
