//
// Created by 叶荣杰 on 2024/9/6.
//
#include <iostream>

#include "../third_party/include/spdlog/spdlog.h"

#include "tsp_mqtt_config.h"

TspMqttConfig::TspMqttConfig() : mqtt_config_() {
    spdlog::info("初始化TSP MQTT配置信息");
    mqtt_config_.subscribe_topics = subscribe_topics_;
    mqtt_config_.server_host = server_host_;
    mqtt_config_.server_port = server_port_;
}

TspMqttConfig::~TspMqttConfig() = default;

TspMqttConfig &TspMqttConfig::GetInstance() {
    static TspMqttConfig instance;
    return instance;
}

bool TspMqttConfig::SetInfo(const std::string &username, const std::string &client_id) {
    spdlog::info("设置TSP MQTT配置信息");
    if (username.empty() || client_id.empty()) {
        return false;
    }
    mqtt_config_.username = username;
    mqtt_config_.client_id = client_id;
    return GeneratePassword();
}

MqttConfig TspMqttConfig::get_mqtt_config() const {
    return mqtt_config_;
}

bool TspMqttConfig::GeneratePassword() {
    // 临时默认密码
    mqtt_config_.password = "111111";
    return true;
}