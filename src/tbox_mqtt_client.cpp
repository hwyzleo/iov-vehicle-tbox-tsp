//
// Created by hwyz_leo on 2024/9/7.
//
#include <iostream>
#include <regex>

#include "spdlog/spdlog.h"
#include "nlohmann/json.hpp"
#include "utils.h"

#include "tbox_mqtt_client.h"
#include "tsp_mqtt_client.h"

using json = nlohmann::json;

TboxMqttClient::TboxMqttClient() : mosqpp::mosquittopp() {}

TboxMqttClient::~TboxMqttClient() {
    mosqpp::lib_cleanup();
}

TboxMqttClient &TboxMqttClient::get_instance() {
    static TboxMqttClient instance;
    return instance;
}

bool TboxMqttClient::load_config(const YAML::Node &config) {
    spdlog::info("加载TBOX MQTT客户端配置信息");
    if (config["mqtt"]) {
        if (config["mqtt"]["server"]) {
            if (config["mqtt"]["server"]["host"]) {
                server_host_ = config["mqtt"]["server"]["host"].as<std::string>();
            }
            if (config["mqtt"]["server"]["port"]) {
                server_port_ = config["mqtt"]["server"]["port"].as<std::uint16_t>();
            }
        }
        if (config["mqtt"]["keepalive"]) {
            keepalive_ = config["mqtt"]["keepalive"].as<std::uint16_t>();
        }
        if (config["mqtt"]["use-ssl"]) {
            use_ssl_ = config["mqtt"]["use-ssl"].as<bool>();
        }
        if (config["mqtt"]["reconnect-interval-second"]) {
            reconnect_interval_second_ = config["mqtt"]["reconnect-interval-second"].as<int>();
        }
        if (config["mqtt"]["username"]) {
            username_ = config["mqtt"]["username"].as<std::string>();
        }
        if (config["mqtt"]["password"]) {
            username_ = config["mqtt"]["password"].as<std::string>();
        }
    }
    return true;
}

bool TboxMqttClient::start() {
    if (!is_started_) {
        spdlog::info("启动TBOX MQTT客户端");
        this->connect_manage();
        is_started_ = true;
    }
    return is_started_;
}

void TboxMqttClient::stop() {
    if (!is_started_) {
        return;
    }
    this->disconnect();
    mosqpp::lib_cleanup();
    is_started_ = false;
}

bool TboxMqttClient::is_connected() const {
    return is_connected_;
}

bool TboxMqttClient::publish(int &mid, const std::string &topic, const void *payload, int payload_len, int qos) {
    if (nullptr == payload) {
        return false;
    }
    if (!is_connected_) {
        return false;
    }
    std::string base64_payload = hwyz::Utils::base64_encode(std::string(static_cast<const char *>(payload), payload_len));
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
        std::string whole_topic = "TSP/";
        for (const auto &topic: subscribe_topics_) {
            int mid = 0;
            subscribe_topic(mid, whole_topic.append(topic), 1);
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
    std::string payload = hwyz::Utils::base64_decode(std::string(static_cast<char *>(message->payload), message->payloadlen));
    std::string json_string(payload.c_str(), payload.length());
    json json_object;
    try {
        json_object = json::parse(json_string);
    } catch (json::parse_error &e) {
        std::cerr << "JSON解析错误: " << e.what() << std::endl;
        return;
    }
    json_object["vin"] = username_;
    std::string params_json = json_object.dump();
    int mid = 0;
    std::string topic = message->topic;
    std::regex pattern("TSP/");
    std::string biz_topic = std::regex_replace(topic, pattern, "");
    std::string prefix_topic = "UP/";
    std::string whole_topic = prefix_topic.append(username_).append("/").append(biz_topic);
    TspMqttClient::get_instance().publish(mid, whole_topic, params_json.c_str(), static_cast<int>(params_json.length()));
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

bool TboxMqttClient::init() {
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

void TboxMqttClient::connect_manage() {
    std::thread th([&]() {
        bool is_first_connect = true;
        while (is_started_) {
            if (!init()) {
                spdlog::info("TBOX MQTT客户端初始化失败");
                std::this_thread::sleep_for(std::chrono::seconds(reconnect_interval_second_));
                continue;
            }
            if (!is_connected_ && !is_connecting_) {
                if (is_first_connect) {
                    is_first_connect = false;
                } else {
                    std::this_thread::sleep_for(std::chrono::seconds(reconnect_interval_second_));
                }
                if (connect()) {
                    is_connecting_ = true;
                }
            } else {
                this->loop();
            }
            std::unique_lock<std::mutex> lock(mtx_loop_);
            cv_loop_.wait_for(lock, std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::milliseconds(loop_interval_milli_second_)));
        }
    });
    connector.swap(th);
}

bool TboxMqttClient::connect() {
    spdlog::info("重置客户端ID");
    int rc = this->reinitialise(client_id_.c_str(), true);
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    spdlog::info("设置用户名密码");
    rc = this->username_pw_set(username_.c_str(), password_.c_str());
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    spdlog::info("连接TBOX MQTT[{}:{}]", server_host_, server_port_);
    rc = mosquittopp::connect(server_host_.c_str(), server_port_, keepalive_);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::info("连接TBOX MQTT失败");
        return false;
    }
    return true;
}

bool TboxMqttClient::subscribe_topic(int &mid, const std::string &topic, int qos) {
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