//
// Created by 叶荣杰 on 2024/9/6.
//
#include <iostream>

#include "../include/tsp_mqtt_config.h"

TspMqttConfig::TspMqttConfig() = default;

TspMqttConfig::~TspMqttConfig() = default;

TspMqttConfig &TspMqttConfig::GetInstance() {
    static TspMqttConfig instance;
    return instance;
}

bool TspMqttConfig::SetInfo(const std::string &server_host, const std::string &username, const std::string &client_id) {
    std::cout << "设置MQTT配置信息" << std::endl;
    if (server_host.empty() || username.empty() || client_id.empty()) {
        return false;
    }
    mqtt_config_.server_host = server_host;
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