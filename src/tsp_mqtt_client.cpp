//
// Created by 叶荣杰 on 2024/9/5.
//
#include <iostream>
#include <regex>

#include "../include/tsp_mqtt_client.h"
#include "../include/tsp_mqtt_config.h"
#include "../include/tbox_mqtt_client.h"

TspMqttClient::TspMqttClient() : mosqpp::mosquittopp() {}

TspMqttClient::~TspMqttClient() {
    mosqpp::lib_cleanup();
}

TspMqttClient &TspMqttClient::GetInstance() {
    static TspMqttClient instance;
    return instance;
}

bool TspMqttClient::Start() {
    if (!is_started_) {
        std::cout << "启动TSP MQTT客户端" << std::endl;
        this->ConnectManage();
        is_started_ = true;
    }
    return is_started_;
}

void TspMqttClient::Stop() {
    if (!is_started_) {
        return;
    }
    if (is_subscribed_) {
        MqttConfig config = TspMqttConfig::GetInstance().get_mqtt_config();
        for (const auto &topic: config.subscribe_topics) {
            int mid = 0;
            std::string whole_topic = "DOWN/";
            Unsubscribe(mid, whole_topic.append(config.username).append("/").append(topic));
        }
        is_subscribed_ = false;
    }
    this->disconnect();
    mosqpp::lib_cleanup();
    is_started_ = false;
}

bool TspMqttClient::IsConnected() const {
    return is_connected_;
}

bool TspMqttClient::Publish(int &mid, const std::string &topic, const void *payload, int payload_len, int qos) {
    if (nullptr == payload) {
        return false;
    }
    if (!is_connected_) {
        return false;
    }
    int rc = mosquittopp::publish(&mid, topic.c_str(), payload_len, payload, qos, false);
    if (rc == MOSQ_ERR_SUCCESS) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
}

void TspMqttClient::on_connect(int rc) {
    is_connecting_ = false;
    is_connected_ = (rc == MOSQ_ERR_SUCCESS);
    if (is_connected_) {
        std::cout << "TSP MQTT客户端连接成功" << std::endl;
        MqttConfig config = TspMqttConfig::GetInstance().get_mqtt_config();
        for (const auto &topic: config.subscribe_topics) {
            int mid = 0;
            std::string whole_topic = "DOWN/";
            Subscribe(mid, whole_topic.append(config.username).append("/").append(topic), 1);
        }
        is_subscribed_ = true;
    }
}

void TspMqttClient::on_disconnect(int rc) {
    std::cout << "TSP MQTT客户端断开成功" << std::endl;
    is_connecting_ = false;
    is_connected_ = false;
}

void TspMqttClient::on_publish(int rc) {

}

void TspMqttClient::on_message(const struct mosquitto_message *message) {
    std::cout << "收到消息主题[" << message->topic << "]" << std::endl;
    std::cout << "  内容: " << std::string(static_cast<char *>(message->payload), message->payloadlen) << std::endl;
    int mid = 0;
    std::string topic = message->topic;
    MqttConfig config = TspMqttConfig::GetInstance().get_mqtt_config();
    std::regex pattern("DOWN/" + config.username + "/");
    std::string internal_topic = std::regex_replace(topic, pattern, "");
    TboxMqttClient::GetInstance().Publish(mid, internal_topic, message->payload, message->payloadlen);
}

void TspMqttClient::on_subscribe(int mid, int qos_count, const int *granted_qos) {
    std::cout << "订阅主题[" << mid << "]成功" << std::endl;
}

void TspMqttClient::on_unsubscribe(int mid) {
    std::cout << "取消订阅主题[" << mid << "]成功" << std::endl;
}

void TspMqttClient::on_log(int level, const char *str) {

}

void TspMqttClient::on_error() {

}

bool TspMqttClient::Init() {
    if (!is_inited_) {
        std::cout << "初始化TSP MQTT客户端" << std::endl;
        int rc = mosqpp::lib_init();
        if (rc == MOSQ_ERR_SUCCESS) {
            std::cout << "TSP MQTT客户端初始化成功" << std::endl;
            is_inited_ = true;
        }
    }
    return is_inited_;
}

void TspMqttClient::ConnectManage() {
    std::thread th([&]() {
        bool is_first_connect = true;
        while (is_started_) {
            if (!Init()) {
                std::cout << "TSP MQTT客户端初始化失败" << std::endl;
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

bool TspMqttClient::Connect() {
    std::string sn;
    std::string vin;
    if (!GetDeviceInfo(sn, vin)) {
        return false;
    }
    if (!TspMqttConfig::GetInstance().SetInfo(kMqttServerUrl, vin, sn)) {
        return false;
    }
    MqttConfig config = TspMqttConfig::GetInstance().get_mqtt_config();
    std::cout << "重置客户端ID" << std::endl;
    int rc = this->reinitialise(config.client_id.c_str(), true);
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    std::cout << "设置用户名密码" << std::endl;
    rc = this->username_pw_set(config.username.c_str(), config.password.c_str());
    if (rc != MOSQ_ERR_SUCCESS) {
        return false;
    }
    std::cout << "连接TSP MQTT[" << config.server_host << ":" << config.server_port << "]" << std::endl;
    rc = mosquittopp::connect(config.server_host.c_str(), config.server_port, config.keepalive);
    if (rc != MOSQ_ERR_SUCCESS) {
        std::cout << "连接TSP MQTT失败" << std::endl;
        return false;
    }
    return true;
}

bool TspMqttClient::Subscribe(int &mid, const std::string &topic, int qos) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int rc = this->subscribe(&mid, topic.c_str(), qos);
    std::cout << "订阅主题[" << mid << "][" << topic << "]" << std::endl;
    if (rc != MOSQ_ERR_SUCCESS) {
        std::cout << "订阅主题:" << topic << " 失败" << std::endl;
        return false;
    }
    cv_loop_.notify_all();
    return true;
}

bool TspMqttClient::Unsubscribe(int &mid, const std::string &topic) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int rc = this->unsubscribe(&mid, topic.c_str());
    std::cout << "取消订阅主题[" << mid << "][" << topic << "]" << std::endl;
    if (rc != MOSQ_ERR_SUCCESS) {
        std::cout << "取消订阅主题:" << topic << " 失败" << std::endl;
        return false;
    }
    cv_loop_.notify_all();
    return true;
}

bool TspMqttClient::GetDeviceInfo(std::string &sn, std::string &vin) const {
    sn.clear();
    vin.clear();
    // 当前先写死
    sn = "SN001";
    vin = "HWYZTEST000000001";
    std::cout << "获取SN及VIN" << std::endl;
    return true;
}