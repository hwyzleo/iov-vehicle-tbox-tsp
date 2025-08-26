//
// Created by hwyz_leo on 2024/9/5.
//
#include <regex>

#include "spdlog/spdlog.h"
#include "utils.h"

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
        spdlog::error("未找到TSP MQTT配置");
        return false;
    }
    std::string server_host = config["tsp"]["mqtt"]["host"].as<std::string>();
    if (server_host.empty()) {
        spdlog::error("TSP MQTT服务器地址未配置");
        return false;
    }
    server_host_ = server_host;
    if (config["tsp"]["mqtt"]["port"]) {
        server_port_ = config["tsp"]["mqtt"]["port"].as<std::uint16_t>();
    }
    if (config["tsp"]["mqtt"]["keepalive"]) {
        keepalive_ = config["tsp"]["mqtt"]["keepalive"].as<std::uint16_t>();
    }
    if (config["tsp"]["mqtt"]["use-ssl"]) {
        use_ssl_ = config["tsp"]["mqtt"]["use-ssl"].as<bool>();
    }
    if (config["tsp"]["mqtt"]["reconnect-interval-second"]) {
        reconnect_interval_second_ = config["tsp"]["mqtt"]["reconnect-interval-second"].as<int>();
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
    std::string whole_topic = "UP/" + username_ + "/" + topic;
    int rc = mosquittopp::publish(&mid, whole_topic.c_str(), payload_len, payload, qos, false);
    std::vector<uint8_t> payload_vector(
            static_cast<const uint8_t *>(payload),
            static_cast<const uint8_t *>(payload) + payload_len
    );
    std::string hex_payload = hwyz::Utils::bytes_to_hex(payload_vector, true);
    spdlog::info("发送[{}]TSP消息至主题[{}]QOS[{}]", mid, whole_topic, qos);
    std::cout << hex_payload << std::endl;
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
        int mid = 0;
        is_subscribed_ = true;
        // 全局通知TSP连接
        std::string timestamp = std::to_string(hwyz::Utils::get_current_timestamp_ms());
        TboxMqttClient::get_instance().publish(mid, "GLOBAL/TSP_CONNECT", timestamp.c_str(),
                                               timestamp.length());
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
        if (init_user_info()) {
            int rc = mosqpp::lib_init();
            if (rc == MOSQ_ERR_SUCCESS) {
                spdlog::info("TSP MQTT客户端初始化成功");
                is_inited_ = true;
            }
        }
    }
    return is_inited_;
}

bool TspMqttClient::init_user_info() {
    spdlog::info("初始化TSP MQTT用户信息");
    username_ = hwyz::Utils::global_read_string(hwyz::global_key_t::VIN);
    if (username_.empty()) {
        spdlog::warn("未获取到用户名");
        return false;
    }
    client_id_ = hwyz::Utils::global_read_string(hwyz::global_key_t::TBOX_SN);
    if (client_id_.empty()) {
        spdlog::warn("未获取到客户端ID");
        return false;
    }
    password_ = generate_password(username_, client_id_);
    return true;
}

std::string TspMqttClient::generate_password(std::string username, std::string client_id) {
    // TODO 生成特殊的密码
    // 这里先简单的拼接用户名及客户端ID
    return username + client_id;
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
    spdlog::info("重置TSP客户端ID");
    int rc = this->reinitialise(client_id_.c_str(), true);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::warn("重置TSP客户端ID失败");
        return false;
    }
    spdlog::info("设置TSP用户名密码");
    rc = this->username_pw_set(username_.c_str(), password_.c_str());
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::warn("设置TSP用户名密码失败");
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

bool TspMqttClient::subscribe_topic(int &mid, const std::string &topic, TspMqttMessageHandler &handler, int qos) {
    if (!is_connected_) {
        return false;
    }
    if (topic.empty()) {
        return false;
    }
    std::string whole_topic = "DOWN/" + username_ + "/" + topic;
    int rc = this->subscribe(&mid, whole_topic.c_str(), qos);
    spdlog::info("订阅[{}]主题[{}]QOS[{}]", mid, topic, qos);
    if (rc != MOSQ_ERR_SUCCESS) {
        spdlog::warn("订阅[{}]主题[{}]失败[{}]", mid, topic, rc);
        return false;
    }
    message_handler_[topic] = &handler;
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