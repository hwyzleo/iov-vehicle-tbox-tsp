//
// Created by 叶荣杰 on 2024/9/5.
//
#include <string>
#include <set>

#ifndef TSPSERVICE_CONSTANTS_H
#define TSPSERVICE_CONSTANTS_H
// MQTT重连间隔秒数
constexpr int kMqttReconnectIntervalSecond = 15;
// MQTT消息处理间隔毫秒
constexpr int kMqttLoopIntervalMilliSecond = 100;

// MQTT配置
struct MqttConfig {
    // 服务器地址
    std::string server_host;
    std::uint16_t server_port = 1883;
    int keepalive = 60;
    // 客户端ID
    std::string client_id;
    // 用户名
    std::string username;
    // 密码
    std::string password;
    // 使用SSL
    bool use_ssl = false;
    // 订阅主题
    std::set<std::string> subscribe_topics;
};

constexpr char kMqttServerUrl[] = "127.0.0.1";
#endif //TSPSERVICE_CONSTANTS_H
