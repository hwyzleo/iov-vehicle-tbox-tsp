//
// Created by hwyz_leo on 2024/9/5.
//
#include <regex>

#include "spdlog/spdlog.h"

#include "tsp_mqtt_client.h"
#include "tbox_mqtt_client.h"

TspMqttClient::TspMqttClient() : mosqpp::mosquittopp() {}

TspMqttClient::~TspMqttClient() {
    mosqpp::lib_cleanup();
}

TspMqttClient &TspMqttClient::get_instance() {
    static TspMqttClient instance;
    return instance;
}

bool TspMqttClient::load_config(const YAML::Node &config) {
    spdlog::info("加载TSP MQTT客户端配置信息");
    if (!config["tsp"] || !config["tsp"]["mqtt"]) {
        return false;
    }
    std::string server_host = config["tsp"]["mqtt"]["host"].as<std::string>();
    if (server_host.empty()) {
        return false;
    }
    server_host_ = server_host;
    if (!config["tsp"]["mqtt"]["port"]) {
        server_port_ = config["tsp"]["mqtt"]["port"].as<std::uint16_t>();
    }
    if (!config["tsp"]["mqtt"]["keepalive"]) {
        keepalive_ = config["tsp"]["mqtt"]["keepalive"].as<std::uint16_t>();
    }
    if (!config["tsp"]["mqtt"]["use-ssl"]) {
        use_ssl_ = config["tsp"]["mqtt"]["use-ssl"].as<bool>();
    }
    if (!config["tsp"]["mqtt"]["reconnect-interval-second"]) {
        reconnect_interval_second_ = config["tsp"]["mqtt"]["reconnect-interval-second"].as<int>();
    }
    if (!config["tsp"]["mqtt"]["username"]) {
        username_ = config["tsp"]["mqtt"]["username"].as<std::string>();
    }
    if (!config["tsp"]["mqtt"]["password"]) {
        username_ = config["tsp"]["mqtt"]["password"].as<std::string>();
    }
    return true;
}

bool TspMqttClient::start() {
    if (!is_started_) {
        spdlog::info("启动TSP MQTT客户端");
        this->connect_manage();
        is_started_ = true;
    }
    return is_started_;
}

void TspMqttClient::stop() {
    if (!is_started_) {
        return;
    }
    if (is_subscribed_) {
        for (const auto &topic: subscribe_topics_) {
            int mid = 0;
            std::string whole_topic = "DOWN/";
            unsubscribe_topic(mid, whole_topic.append(username_).append("/").append(topic));
        }
        is_subscribed_ = false;
    }
    this->disconnect();
    mosqpp::lib_cleanup();
    is_started_ = false;
}

bool TspMqttClient::is_connected() const {
    return is_connected_;
}

bool TspMqttClient::publish(int &mid, const std::string &topic, const void *payload, int payload_len, int qos) {
    if (nullptr == payload) {
        return false;
    }
    if (!is_connected_) {
        return false;
    }
    int rc = mosquittopp::publish(&mid, topic.c_str(), payload_len, payload, qos, false);
    spdlog::info("转发[{}]APP消息[{}]至主题[{}]QOS[{}]", mid,
                 std::string(static_cast<const char *>(payload), payload_len), topic, qos);
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
        spdlog::info("TSP MQTT客户端连接成功");
        for (const auto &topic: subscribe_topics_) {
            int mid = 0;
            std::string whole_topic = "DOWN/";
            subscribe_topic(mid, whole_topic.append(username_).append("/").append(topic), 1);
        }
        is_subscribed_ = true;
    }
}

void TspMqttClient::on_disconnect(int rc) {
    spdlog::info("TSP MQTT客户端断开成功");
    is_connecting_ = false;
    is_connected_ = false;
}

void TspMqttClient::on_publish(int rc) {

}

void TspMqttClient::on_message(const struct mosquitto_message *message) {
    spdlog::debug("收到消息主题[{}]内容[{}]", message->topic,
                  std::string(static_cast<char *>(message->payload), message->payloadlen));
    int mid = 0;
    std::string topic = message->topic;
    std::regex pattern("DOWN/" + username_ + "/");
    std::string biz_topic = std::regex_replace(topic, pattern, "");
    std::string prefix_topic = "APP/";
    std::string whole_topic = prefix_topic.append(biz_topic);
    TboxMqttClient::get_instance().publish(mid, whole_topic, message->payload, message->payloadlen);
}

void TspMqttClient::on_subscribe(int mid, int qos_count, const int *granted_qos) {
    spdlog::info("订阅主题[{}]成功", mid);
}

void TspMqttClient::on_unsubscribe(int mid) {
    spdlog::info("取消订阅主题[{}]成功", mid);
}

void TspMqttClient::on_log(int level, const char *str) {

}

void TspMqttClient::on_error() {

}

bool TspMqttClient::init() {
    if (!is_inited_) {
        spdlog::info("初始化TSP MQTT客户端");
        int rc = mosqpp::lib_init();
        if (rc == MOSQ_ERR_SUCCESS) {
            spdlog::info("TSP MQTT客户端初始化成功");
            is_inited_ = true;
        }
    }
    return is_inited_;
}

void TspMqttClient::connect_manage() {
    std::thread th([&]() {
        bool is_first_connect = true;
        while (is_started_) {
            if (!init()) {
                spdlog::info("TSP MQTT客户端初始化失败");
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

bool TspMqttClient::connect() {
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
    spdlog::info("连接TSP MQTT[{}:{}]", server_host_, server_port_);
    rc = mosquittopp::connect(server_host_.c_str(), server_port_, keepalive_);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::info("连接TSP MQTT失败");
        return false;
    }
    return true;
}

bool TspMqttClient::subscribe_topic(int &mid, const std::string &topic, int qos) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int rc = this->subscribe(&mid, topic.c_str(), qos);
    spdlog::info("订阅主题[{}][{}]", mid, topic);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::warn("订阅主题[{}]失败[{}]", topic, rc);
        return false;
    }
    cv_loop_.notify_all();
    return true;
}

bool TspMqttClient::unsubscribe_topic(int &mid, const std::string &topic) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    int rc = this->unsubscribe(&mid, topic.c_str());
    spdlog::info("取消订阅主题[{}][{}]", mid, topic);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::warn("取消订阅主题[{}]失败[{}]", topic, rc);
        return false;
    }
    cv_loop_.notify_all();
    return true;
}