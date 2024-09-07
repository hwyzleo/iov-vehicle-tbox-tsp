//
// Created by 叶荣杰 on 2024/9/6.
//

#ifndef TSPSERVICE_TSP_MQTT_CONFIG_H
#define TSPSERVICE_TSP_MQTT_CONFIG_H
#include "constants.h"
#endif //TSPSERVICE_TSP_MQTT_CONFIG_H

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
    static TspMqttConfig &GetInstance();

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
     * 设置信息
     * @param server_host 服务器地址
     * @param username 用户名
     * @param client_id 客户端ID
     * @return 是否设置成功
     */
    bool SetInfo(const std::string &server_host, const std::string &username, const std::string &client_id);

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
    bool GeneratePassword();

private:
    // MQTT配置
    MqttConfig mqtt_config_;
};