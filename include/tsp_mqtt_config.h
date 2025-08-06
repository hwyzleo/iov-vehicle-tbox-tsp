//
// Created by hwyz_leo on 2024/9/6.
//

#ifndef TSPSERVICE_TSP_MQTT_CONFIG_H
#define TSPSERVICE_TSP_MQTT_CONFIG_H
#include <set>

#include "yaml-cpp/yaml.h"

#include "constants.h"

class TspMqttConfig {
public:
    /**
     * 析构虚函数
     */
    virtual ~TspMqttConfig();

    /**
     * 获取单例
     * @return 单例
     */
    static TspMqttConfig &get_instance();

    /**
     * 防止对象被复制
     */
    TspMqttConfig(const TspMqttConfig &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TspMqttConfig &operator=(const TspMqttConfig &) = delete;

public:
    /**
     * 加载配置
     * @param config 配置信息
     * @return 是否加载成功
     */
    bool load_config(const YAML::Node &config);

    /**
     * 设置信息
     * @param username 用户名
     * @param client_id 客户端ID
     * @return 是否设置成功
     */
    bool set_info(const std::string &username, const std::string &client_id);

    /**
     * 获取MQTT配置
     * @return MQTT配置
     */
    MqttConfig get_mqtt_config() const;

private:
    TspMqttConfig();

    /**
     * 生成密码
     * @return 是否生成成功
     */
    bool generate_password();

private:
    // MQTT配置
    MqttConfig mqtt_config_;
    // 订阅主题
    std::set<std::string> subscribe_topics_ = {
            "FIND_VEHICLE"
    };

};

#endif //TSPSERVICE_TSP_MQTT_CONFIG_H