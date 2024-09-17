//
// Created by 叶荣杰 on 2024/9/7.
//

#ifndef TSPSERVICE_TBOX_MQTT_CONFIG_H
#define TSPSERVICE_TBOX_MQTT_CONFIG_H
#include "constants.h"
#endif //TSPSERVICE_TBOX_MQTT_CONFIG_H

class TboxMqttConfig {
public:
    /**
     * 析构虚函数
     */
    virtual ~TboxMqttConfig();

    /**
     * 获取单例
     * @return 单例
     */
    static TboxMqttConfig &GetInstance();

    /**
     * 防止对象被复制
     */
    TboxMqttConfig(const TboxMqttConfig &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TboxMqttConfig &operator=(const TboxMqttConfig &) = delete;

public:
    /**
     * 设置信息
     * @param username 用户名
     * @param client_id 客户端ID
     * @return 是否设置成功
     */
    bool SetInfo(const std::string &username, const std::string &client_id);

    /**
     * 获取MQTT配置
     * @return MQTT配置
     */
    MqttConfig get_mqtt_config() const;

private:
    TboxMqttConfig();

    /**
     * 生成密码
     * @return 是否生成成功
     */
    bool GeneratePassword();

private:
    // MQTT配置
    MqttConfig mqtt_config_;
    // 订阅主题
    std::set<std::string> subscribe_topics_ = {
            "FIND_VEHICLE"
    };
    // 服务器地址
    std::string server_host_ = "127.0.0.1";
    // 服务器端口
    int server_port_ = 1883;
};