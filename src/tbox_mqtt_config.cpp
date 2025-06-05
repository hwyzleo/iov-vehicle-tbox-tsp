//
// Created by hwyz_leo on 2024/9/7.
//
#include <iostream>

#include "../third_party/include/spdlog/spdlog.h"

#include "tbox_mqtt_config.h"

TboxMqttConfig::TboxMqttConfig() : mqtt_config_() {
    spdlog::info("初始化TBOX MQTT配置信息");
    mqtt_config_.subscribe_topics = subscribe_topics_;
    mqtt_config_.server_host = server_host_;
    mqtt_config_.server_port = server_port_;
}

TboxMqttConfig::~TboxMqttConfig() = default;

TboxMqttConfig &TboxMqttConfig::get_instance() {
    static TboxMqttConfig instance;
    return instance;
}

bool TboxMqttConfig::set_info(const std::string &username, const std::string &client_id) {
    spdlog::info("设置TBOX MQTT配置信息");
    if (username.empty() || client_id.empty()) {
        return false;
    }
    mqtt_config_.username = username;
    mqtt_config_.client_id = client_id;
    return generate_password();
}

MqttConfig TboxMqttConfig::get_mqtt_config() const {
    return mqtt_config_;
}

bool TboxMqttConfig::generate_password() {
    // 临时默认密码
    mqtt_config_.password = "111111";
    return true;
}