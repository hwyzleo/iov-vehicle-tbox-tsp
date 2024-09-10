cmake_minimum_required(VERSION 3.10)

project(TspService)

# 设置C++标准
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-std=c++11 -Wall -lpthread -g")

# 添加头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/third_party/include)

# 根据不同的环境设置不同的库文件目录
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    if(APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/arm64-apple-darwin)
    elseif(UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/aarch64-linux-gnu)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    if(APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-apple-darwin)
    elseif(UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-linux-gnu)
    endif()
endif()

# 添加库文件目录
link_directories(${LIB_DIR}/mosquitto)
link_directories(${LIB_DIR}/spdlog)
link_libraries(mosquitto)
link_libraries(mosquittopp)
link_libraries(spdlog)

# 添加可执行文件
add_executable(TspService
    src/main.cpp
    src/tsp_mqtt_client.cpp
    src/tsp_mqtt_config.cpp
    src/tbox_mqtt_client.cpp
    src/tbox_mqtt_config.cpp
)