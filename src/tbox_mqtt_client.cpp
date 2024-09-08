//
// Created by 叶荣杰 on 2024/9/7.
//
#include <iostream>

#include "../include/tbox_mqtt_client.h"
#include "../include/tbox_mqtt_config.h"

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
        std::cout << "启动TBOX MQTT客户端" << std::endl;
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
    std::cout << "转发TSP消息[" << std::string(static_cast<const char*>(payload), payload_len) << "]至主题[" << topic << "]" << std::endl;
    int rc = mosquittopp::publish(&mid, topic.c_str(), payload_len, payload, qos, false);
    if (rc == MOSQ_ERR_SUCCESS) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
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

void TboxMqttClient::on_connect(int rc) {
    is_connecting_ = false;
    is_connected_ = (rc == MOSQ_ERR_SUCCESS);
    if (is_connected_) {
        std::cout << "TBOX MQTT客户端连接成功" << std::endl;
    }
}

void TboxMqttClient::on_disconnect(int rc) {
    std::cout << "TBOX MQTT客户端断开[" << rc << "]" << std::endl;
    is_connecting_ = false;
    is_connected_ = false;
}

void TboxMqttClient::on_publish(int rc) {

}

void TboxMqttClient::on_message(const struct mosquitto_message *message) {
    std::cout << "收到消息：" << std::endl;
    std::cout << "  主题: " << message->topic << std::endl;
    std::cout << "  内容: " << std::string(static_cast<char *>(message->payload), message->payloadlen) << std::endl;
}

void TboxMqttClient::on_subscribe(int mid, int qos_count, const int *granted_qos) {

}

void TboxMqttClient::on_unsubscribe(int mid) {

}

void TboxMqttClient::on_log(int level, const char *str) {

}

void TboxMqttClient::on_error() {
    std::cout << "TBOX MQTT客户端报错" << std::endl;
}

bool TboxMqttClient::Init() {
    if (!is_inited_) {
        std::cout << "初始化TBOX MQTT客户端" << std::endl;
        int rc = mosqpp::lib_init();
        if (rc == MOSQ_ERR_SUCCESS) {
            std::cout << "TBOX MQTT客户端初始化成功" << std::endl;
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
                std::cout << "TBOX MQTT客户端初始化失败" << std::endl;
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
    if (!TboxMqttConfig::GetInstance().SetInfo(kMqttServerUrl, vin, sn)) {
        return false;
    }
    MqttConfig config = TboxMqttConfig::GetInstance().get_mqtt_config();
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
    std::cout << "连接TBOX MQTT[" << config.server_host << ":" << config.server_port << "]" << std::endl;
    rc = mosquittopp::connect(config.server_host.c_str(), config.server_port, config.keepalive);
    if (rc != MOSQ_ERR_SUCCESS) {
        std::cout << "连接TBOX MQTT失败" << std::endl;
        return false;
    }
    return true;
}

bool TboxMqttClient::GetDeviceInfo(std::string &sn, std::string &vin) const {
    sn.clear();
    vin.clear();
    // 当前先写死
    sn = "TSPSERVICE";
    vin = "TSPSERVICE";
    std::cout << "获取SN及VIN" << std::endl;
    return true;
}