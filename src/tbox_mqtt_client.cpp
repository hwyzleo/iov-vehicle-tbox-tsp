//
// Created by 叶荣杰 on 2024/9/7.
//
#include <iostream>
#include <regex>

#include "../third_party/include/spdlog/spdlog.h"
#include "../third_party/include/nlohmann/json.hpp"

using json = nlohmann::json;

#include "tbox_mqtt_client.h"
#include "tbox_mqtt_config.h"
#include "tsp_mqtt_client.h"
#include "base64.h"

TboxMqttClient::TboxMqttClient() : mosqpp::mosquittopp() {}

TboxMqttClient::~TboxMqttClient() {
    mosqpp::lib_cleanup();
}

TboxMqttClient &TboxMqttClient::GetInstance() {
    static TboxMqttClient instance;
    return instance;
}

bool TboxMqttClient::Start() {
    if (!is_started_) {
        spdlog::info("启动TBOX MQTT客户端");
        this->ConnectManage();
        is_started_ = true;
    }
    return is_started_;
}

void TboxMqttClient::Stop() {
    if (!is_started_) {
        return;
    }
    this->disconnect();
    mosqpp::lib_cleanup();
    is_started_ = false;
}

bool TboxMqttClient::IsConnected() const {
    return is_connected_;
}

bool TboxMqttClient::Publish(int &mid, const std::string &topic, const void *payload, int payload_len, int qos) {
    if (nullptr == payload) {
        return false;
    }
    if (!is_connected_) {
        return false;
    }
    std::string base64_payload = base64_encode(std::string(static_cast<const char *>(payload), payload_len));
    int rc = mosquittopp::publish(&mid, topic.c_str(), static_cast<int>(base64_payload.length()),
                                  base64_payload.c_str(), qos, false);
    spdlog::info("转发[{}]TSP消息[{}]至主题[{}]QOS[{}]", mid, base64_payload, topic, qos);
    if (rc == MOSQ_ERR_SUCCESS) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
}

void TboxMqttClient::on_connect(int rc) {
    is_connecting_ = false;
    is_connected_ = (rc == MOSQ_ERR_SUCCESS);
    if (is_connected_) {
        spdlog::info("TBOX MQTT客户端连接成功");
        MqttConfig config = TboxMqttConfig::GetInstance().get_mqtt_config();
        std::string whole_topic = "TSP/";
        for (const auto &topic: config.subscribe_topics) {
            int mid = 0;
            Subscribe(mid, whole_topic.append(topic), 1);
        }
        is_subscribed_ = true;
    }
}

void TboxMqttClient::on_disconnect(int rc) {
    spdlog::info("TBOX MQTT客户端断开[{}]", rc);
    is_connecting_ = false;
    is_connected_ = false;
}

void TboxMqttClient::on_publish(int rc) {
    spdlog::info("转发[{}]TSP消息成功", rc);
}

void TboxMqttClient::on_message(const struct mosquitto_message *message) {
    spdlog::debug("收到消息主题[{}]内容[{}]", message->topic,
                  std::string(static_cast<char *>(message->payload), message->payloadlen));
    std::string payload = base64_decode(std::string(static_cast<char *>(message->payload), message->payloadlen));
    std::string json_string(payload.c_str(), payload.length());
    json json_object;
    try {
        json_object = json::parse(json_string);
    } catch (json::parse_error &e) {
        std::cerr << "JSON解析错误: " << e.what() << std::endl;
        return;
    }
    MqttConfig config = TboxMqttConfig::GetInstance().get_mqtt_config();
    json_object["vin"] = config.username;
    std::string params_json = json_object.dump();
    int mid = 0;
    std::string topic = message->topic;
    std::regex pattern("TSP/");
    std::string biz_topic = std::regex_replace(topic, pattern, "");
    std::string prefix_topic = "UP/";
    std::string whole_topic = prefix_topic.append(config.username).append("/").append(biz_topic);
    TspMqttClient::GetInstance().Publish(mid, whole_topic, params_json.c_str(), static_cast<int>(params_json.length()));
}

void TboxMqttClient::on_subscribe(int mid, int qos_count, const int *granted_qos) {

}

void TboxMqttClient::on_unsubscribe(int mid) {

}

void TboxMqttClient::on_log(int level, const char *str) {

}

void TboxMqttClient::on_error() {
    spdlog::info("TBOX MQTT客户端报错");
}

bool TboxMqttClient::Init() {
    if (!is_inited_) {
        spdlog::info("初始化TBOX MQTT客户端");
        int rc = mosqpp::lib_init();
        if (rc == MOSQ_ERR_SUCCESS) {
            spdlog::info("TBOX MQTT客户端初始化成功");
            is_inited_ = true;
        }
    }
    return is_inited_;
}

void TboxMqttClient::ConnectManage() {
    std::thread th([&]() {
        bool is_first_connect = true;
        while (is_started_) {
            if (!Init()) {
                spdlog::info("TBOX MQTT客户端初始化失败");
                std::this_thread::sleep_for(std::chrono::seconds(kMqttReconnectIntervalSecond));
                continue;
            }
            if (!is_connected_ && !is_connecting_) {
                if (is_first_connect) {
                    is_first_connect = false;
                } else {
                    std::this_thread::sleep_for(std::chrono::seconds(kMqttReconnectIntervalSecond));
                }
                if (Connect()) {
                    is_connecting_ = true;
                }
            } else {
                this->loop();
            }
            std::unique_lock<std::mutex> lock(mtx_loop_);
            cv_loop_.wait_for(lock, std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::milliseconds(kMqttLoopIntervalMilliSecond)));
        }
    });
    connector.swap(th);
}

bool TboxMqttClient::Connect() {
    std::string sn;
    std::string vin;
    if (!GetDeviceInfo(sn, vin)) {
        return false;
    }
    if (!TboxMqttConfig::GetInstance().SetInfo(vin, sn)) {
        return false;
    }
    MqttConfig config = TboxMqttConfig::GetInstance().get_mqtt_config();
    spdlog::info("重置客户端ID");
    int rc = this->reinitialise(config.client_id.c_str(), true);
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    spdlog::info("设置用户名密码");
    rc = this->username_pw_set(config.username.c_str(), config.password.c_str());
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    spdlog::info("连接TBOX MQTT[{}:{}]", config.server_host, config.server_port);
    rc = mosquittopp::connect(config.server_host.c_str(), config.server_port, config.keepalive);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::info("连接TBOX MQTT失败");
        return false;
    }
    return true;
}

bool TboxMqttClient::Subscribe(int &mid, const std::string &topic, int qos) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int rc = this->subscribe(&mid, topic.c_str(), qos);
    if (rc == MOSQ_ERR_SUCCESS) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
}

bool TboxMqttClient::GetDeviceInfo(std::string &sn, std::string &vin) const {
    sn.clear();
    vin.clear();
    // 当前先写死
    sn = "TSPSERVICE";
    vin = "HWYZTEST000000001";
    spdlog::info("获取SN及VIN");
    return true;
}