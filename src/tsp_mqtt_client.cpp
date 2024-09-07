//
// Created by 叶荣杰 on 2024/9/5.
//
#include <iostream>

#include "../include/tsp_mqtt_client.h"
#include "../include/tsp_mqtt_config.h"

TspMqttClient::TspMqttClient() : mosqpp::mosquittopp() {}

TspMqttClient::~TspMqttClient() {
    mosqpp::lib_cleanup();
}

TspMqttClient &TspMqttClient::GetInstance() {
    static TspMqttClient instance;
    return instance;
}

bool TspMqttClient::Init() {
    if (!is_lib_inited_) {
        int err = mosqpp::lib_init();
        if (err == mosq_err_t::MOSQ_ERR_SUCCESS) {
            std::cout << "初始化成功" << std::endl;
            is_lib_inited_ = true;
        }
    }
    return is_lib_inited_;
}

bool TspMqttClient::Start() {
    if (!is_started_) {
        this->ConnectManage();
        is_started_ = true;
    }
    return is_started_;
}

void TspMqttClient::Stop() {
    if (!is_started_) {
        return;
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
    int err = mosquittopp::publish(&mid, topic.c_str(), payload_len, payload, qos, false);
    if (mosq_err_t::MOSQ_ERR_SUCCESS == err) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
}

bool TspMqttClient::Subscribe(int &mid, const std::string &topic, int qos) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int err = this->subscribe(&mid, topic.c_str(), qos);
    if (err == mosq_err_t::MOSQ_ERR_SUCCESS) {
        cv_loop_.notify_all();
        return true;
    }
    return false;
}

void TspMqttClient::on_connect(int rc) {
    is_connecting_ = false;
    is_connected_ = (rc == mosq_err_t::MOSQ_ERR_SUCCESS);
}

void TspMqttClient::on_disconnect(int rc) {
    is_connecting_ = false;
    is_connected_ = false;
}

void TspMqttClient::on_publish(int rc) {

}

void TspMqttClient::on_message(const struct mosquitto_message *message) {
    std::cout << "收到消息：" << std::endl;
    std::cout << "  主题: " << message->topic << std::endl;
    std::cout << "  内容: " << std::string(static_cast<char*>(message->payload), message->payloadlen) << std::endl;
}

void TspMqttClient::on_subscribe(int mid, int qos_count, const int *granted_qos) {

}

void TspMqttClient::on_unsubscribe(int mid) {

}

void TspMqttClient::on_log(int level, const char *str) {

}

void TspMqttClient::on_error() {

}

void TspMqttClient::ConnectManage() {
    std::thread th([&]() {
        bool is_first_connect = true;
        while (is_started_) {
            if (!Init()) {
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
    int err = this->reinitialise(config.client_id.c_str(), true);
    if (err != mosq_err_t::MOSQ_ERR_SUCCESS) {
        return false;
    }
    std::cout << "设置用户名密码" << std::endl;
    err = this->username_pw_set(config.username.c_str(), config.password.c_str());
    if (err != mosq_err_t::MOSQ_ERR_SUCCESS) {
        return false;
    }
    std::cout << "连接MQTT" << std::endl;
    err = mosquittopp::connect(config.server_host.c_str(), config.server_port, config.keepalive);
    if (err != mosq_err_t::MOSQ_ERR_SUCCESS) {
        std::cout << "连接MQTT失败" << std::endl;
        return false;
    }
    std::cout << "连接MQTT成功" << std::endl;
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