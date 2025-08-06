//
// Created by hwyz_leo on 2024/9/5.
//

#include "application.h"
#include "spdlog/spdlog.h"

#include "tsp_mqtt_client.h"
#include "tbox_mqtt_client.h"
#include "tsp_mqtt_config.h"
#include "security_manager.h"
#include "tsp_http_client.h"


class MainApplication : public hwyz::Application {
protected:
    bool initialize() override {
        return true;
    }

    void cleanup() override {
        TspMqttClient::get_instance().stop();
        TboxMqttClient::get_instance().stop();
    }

    int execute() override {
        // 加载TSP HTTP配置
        TspHttpClient::get_instance().load_config(getConfig());
        // TODO 从CAN服务获取车辆信息
        std::string vin = "HWYZTEST000000001";
        std::string sn = "10000000XXYY000001";
        TspHttpClient::get_instance().load_vehicle_info(vin, sn);
        // 检查证书及密钥
        SecurityManager::get_instance().load_config(getConfig());
        if (!SecurityManager::get_instance().check_certification()) {
            spdlog::error("证书检查失败");
            return -1;
        }
        if (!SecurityManager::get_instance().check_communication_secret_key()) {
            spdlog::error("通讯密钥检查失败");
            return -1;
        }
        // 加载TSP MQTT配置
        TspMqttConfig::get_instance().load_config(getConfig());
        // 启动TSP MQTT客户端
        TspMqttClient::get_instance().start();
        // 启动TBOX MQTT客户端
        TboxMqttClient::get_instance().start();

        spdlog::info("主函数运行");
        return 0;
    }
};

APPLICATION_ENTRY(MainApplication)