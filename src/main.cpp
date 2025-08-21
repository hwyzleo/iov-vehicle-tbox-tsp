//
// Created by hwyz_leo on 2024/9/5.
//

#include "application.h"
#include "spdlog/spdlog.h"

#include "tsp_mqtt_client.h"
#include "tbox_mqtt_client.h"
#include "security_manager.h"
#include "tsp_http_client.h"


class MainApplication : public hwyz::Application {
protected:
    bool initialize() override {
        if (!SecurityManager::get_instance().load_config(getConfig())) {
            return false;
        }
        if (!TboxMqttClient::get_instance().load_config(getConfig())) {
            return false;
        }
        if (!TspMqttClient::get_instance().load_config(getConfig())) {
            return false;
        }
        if (!TspHttpClient::get_instance().load_config(getConfig())) {
            return false;
        }
        return true;
    }

    void cleanup() override {
        TboxMqttClient::get_instance().stop();
        TspMqttClient::get_instance().stop();
    }

    int execute() override {
        if (!SecurityManager::get_instance().check_certification()) {
            spdlog::error("证书检查失败");
            return -1;
        }
        if (!SecurityManager::get_instance().check_communication_secret_key()) {
            spdlog::error("通讯密钥检查失败");
            return -1;
        }
        TboxMqttClient::get_instance().start();
        TspMqttClient::get_instance().start();
        spdlog::info("主函数运行");
        return 0;
    }
};

APPLICATION_ENTRY(MainApplication)