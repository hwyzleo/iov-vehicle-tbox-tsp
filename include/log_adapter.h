#pragma once

#include "log.h"
#include "log_types.h"
#include <string>

namespace tbox {
namespace tsp {

// TBOX-TSP 日志适配器
// 封装 framework-log 的初始化和模块 Logger 获取
class LogAdapter {
public:
    // 初始化日志系统（在 main.cpp 中调用一次）
    static tbox::fw::log::InitResult init(
        const std::string& service,
        const tbox::fw::log::LogConfig& config
    );

    // 获取各模块的 Logger 实例
    static tbox::fw::log::Logger route();
    static tbox::fw::log::Logger fota();
    static tbox::fw::log::Logger mqtt_client();
    static tbox::fw::log::Logger someip_bridge();
    static tbox::fw::log::Logger relay();

private:
    static bool s_initialized;
};

} // namespace tsp
} // namespace tbox
