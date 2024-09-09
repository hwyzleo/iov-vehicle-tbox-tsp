//
// Created by 叶荣杰 on 2024/9/5.
//
#include <iostream>
#include <thread>

#include "../third_party/include/spdlog/spdlog.h"
#include "../third_party/include/spdlog/sinks/stdout_color_sinks.h"

#include "main.h"
#include "tsp_mqtt_client.h"
#include "tbox_mqtt_client.h"

// 主函数
int main() {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::debug);
    auto logger = std::make_shared<spdlog::logger>("console", console_sink);
    spdlog::set_default_logger(logger);
    spdlog::info("主函数运行");
    // 启动TSP MQTT客户端
    TspMqttClient::GetInstance().Start();
    // 启动TBOX MQTT客户端
    TboxMqttClient::GetInstance().Start();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}