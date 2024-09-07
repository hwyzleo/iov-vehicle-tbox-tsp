cmake_minimum_required(VERSION 3.10)

project(TspService)

# 设置C++标准
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_definitions("-std=c++11 -Wall -lpthread -g")

# 添加头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/third_party/include)

# 添加库文件目录
link_directories(${PROJECT_SOURCE_DIR}/third_party/lib/arm64-apple-darwin/mosquitto)
link_libraries(mosquitto)
link_libraries(mosquittopp)

# 添加可执行文件
add_executable(TspService
    src/main.cpp
    src/tsp_mqtt_client.cpp
    src/tsp_mqtt_config.cpp
)