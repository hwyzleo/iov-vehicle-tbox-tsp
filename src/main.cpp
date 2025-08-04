//
// Created by hwyz_leo on 2024/9/5.
//
#include <iostream>
#include <thread>
#include <signal.h>

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
    std::string file_path = CommonFunction::get_config_file_path();
    YAML::Node config = YAML::LoadFile(file_path);
    // 初始化日志
    init_logger(config);

    // 注册信号处理
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = sig_handler;
    if (sigaction(SIGTERM, &act, NULL) == -1) {
        perror("sigaction SIGTERM");
        spdlog::error("注册SIGTERM处理器失败");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        perror("sigaction SIGSEGV");
        spdlog::error("注册SIGSEGV处理器失败");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGINT, &act, NULL) == -1) {
        perror("sigaction SIGINT");
        spdlog::error("注册SIGINT处理器失败");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGILL, &act, NULL) == -1) {
        perror("sigaction SIGILL");
        spdlog::error("注册SIGILL处理器失败");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGHUP, &act, NULL) == -1) {
        perror("sigaction SIGHUP");
        spdlog::error("注册SIGHUP处理器失败");
        exit(EXIT_FAILURE);
    }

    // 加载TSP HTTP配置
    TspHttpClient::get_instance().load_config(config);
    // TODO 从CAN服务获取车辆信息
    std::string vin = "HWYZTEST000000001";
    std::string sn = "10000000XXYY000001";
    TspHttpClient::get_instance().load_vehicle_info(vin, sn);
    // 检查证书及密钥
    SecurityManager::get_instance().load_config(config);
    if (!SecurityManager::get_instance().check_certification()) {
        spdlog::error("证书检查失败");
        return -1;
    }
    if (!SecurityManager::get_instance().check_communication_secret_key()) {
        spdlog::error("通讯密钥检查失败");
        return -1;
    }
    // 加载TSP MQTT配置
    TspMqttConfig::get_instance().load_config(config);
    // 启动TSP MQTT客户端
    TspMqttClient::get_instance().start();
    // 启动TBOX MQTT客户端
    TboxMqttClient::get_instance().start();

    spdlog::info("主函数运行");
    while (!shutdown_requested) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    spdlog::info("收到关闭信号");
    TspMqttClient::get_instance().stop();
    TboxMqttClient::get_instance().stop();
    return -1;
}

static void sig_handler(int sig, siginfo_t *info, void *context) {
    shutdown_requested = 1;
}

void init_logger(const YAML::Node &config) {
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