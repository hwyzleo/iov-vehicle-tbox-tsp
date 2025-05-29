//
// Created by hwyz_leo on 2024/9/5.
//
#include <iostream>
#include <thread>

#include "../third_party/include/spdlog/spdlog.h"
#include "../third_party/include/spdlog/sinks/stdout_color_sinks.h"
#include "../third_party/include/spdlog/sinks/basic_file_sink.h"
#include "../third_party/include/yaml-cpp/yaml.h"

#include "common_function.h"
#include "main.h"
#include "tsp_mqtt_client.h"
#include "tbox_mqtt_client.h"
#include "tsp_mqtt_config.h"
#include "security_manager.h"
#include "tsp_http_client.h"

// 主函数
int main() {
    // 加载配置
    std::string filePath = CommonFunction::GetConfigFilePath();
    YAML::Node config = YAML::LoadFile(filePath);
    // 初始化日志
    initLogger(config);
    // 加载TSP HTTP配置
    TspHttpClient::GetInstance().LoadConfig(config);
    // TODO 从CAN服务获取车辆信息
    std::string vin = "HWYZTEST000000001";
    std::string sn = "10000000XXYY000001";
    TspHttpClient::GetInstance().LoadVehicleInfo(vin, sn);
    // 检查证书及密钥
    SecurityManager::GetInstance().LoadConfig(config);
    if (!SecurityManager::GetInstance().CheckCertification()) {
        spdlog::error("证书检查失败");
        return -1;
    }
    SecurityManager::GetInstance().CheckSecretKey();
    // 加载TSP MQTT配置
    TspMqttConfig::GetInstance().LoadConfig(config);
    // 启动TSP MQTT客户端
    TspMqttClient::GetInstance().Start();
    // 启动TBOX MQTT客户端
    TboxMqttClient::GetInstance().Start();
    spdlog::info("主函数运行");
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void initLogger(const YAML::Node &config) {
    std::string logger_type = config["logger"]["type"].as<std::string>();
    if (logger_type == "file") {
        std::string logger_path = config["logger"]["path"].as<std::string>();
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(logger_path, true);
        file_sink->set_level(spdlog::level::debug);
        auto logger = std::make_shared<spdlog::logger>("file_logger", file_sink);
        logger->set_level(spdlog::level::debug);
        spdlog::set_default_logger(logger);
        spdlog::flush_every(std::chrono::seconds(5));
    } else {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        auto logger = std::make_shared<spdlog::logger>("console", console_sink);
        logger->set_level(spdlog::level::debug);
        spdlog::set_default_logger(logger);
    }
}