# TBOX-TSP-DSN-CR-007 §13.2 / §6.3: 独立 installed-package consumer。
#
# 验证安装后的 TboxTspClient package（而非 build tree / 源码）可被外部消费方
# find_package + 链接，且 tbox::tsp_client 公开接口不泄漏 MQTT、FOTA 聚合、
# framework-ipc 或 Store 私有类型。
#
# 用法（HOST 开发验证）：
#   cmake -S tests/consumer -B build-consumer \
#       -DCMAKE_PREFIX_PATH=<tsp-sdk install prefix>;<framework/deps prefix>
#   cmake --build build-consumer
cmake_minimum_required(VERSION 3.16)
project(tbox_tsp_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(TboxTspClient CONFIG REQUIRED)
# client.h 公开头引用 framework-ipc 的 Subscription 句柄；消费方必须链接
# TBoxFramework::ipc 以解析公开头（Config find_dependency 保证 package 可发现）
find_package(TboxFramework CONFIG REQUIRED)

add_executable(tsp_consumer main.cpp)
target_link_libraries(tsp_consumer PRIVATE tbox::tsp_client TBoxFramework::ipc)
