//
// Created by hwyz_leo on 2025/8/13.
//

#ifndef TSPSERVICE_TBOX_MQTT_RSMS_HANDLER_H
#define TSPSERVICE_TBOX_MQTT_RSMS_HANDLER_H
#include "tbox_mqtt_message_handler.h"

/**
 * 处理RSMS来的TBox MQTT消息
 */
class TboxMqttRsmsHandler : public TboxMqttMessageHandler {
public:
    /**
     * 析构虚函数
     */
    ~TboxMqttRsmsHandler() override = default;

    /**
     * 防止对象被复制
     */
    TboxMqttRsmsHandler(const TboxMqttRsmsHandler &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TboxMqttRsmsHandler &operator=(const TboxMqttRsmsHandler &) = delete;

    /**
     * 获取单例
     * @return 单例
     */
    static TboxMqttRsmsHandler &get_instance();
public:
    /**
     * 处理RSMS消息
     * @param payload 数据
     */
    void handle(std::string payload) override;
private:
    TboxMqttRsmsHandler() = default;
};
#endif //TSPSERVICE_TBOX_MQTT_RSMS_HANDLER_H
