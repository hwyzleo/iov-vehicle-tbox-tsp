cmake_minimum_required(VERSION 3.10)
project(TspService)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-Wall -lpthread -g")

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
link_libraries(mosquitto)
link_libraries(mosquittopp)

# 添加可执行文件
add_executable(TspService
    src/main.cpp
    src/tsp_mqtt_client.cpp
    src/tsp_mqtt_config.cpp
    src/tbox_mqtt_client.cpp
    src/tbox_mqtt_config.cpp
)

# 添加头文件目录
target_include_directories(TspService PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(TspService PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include)