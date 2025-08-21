//
// Created by hwyz_leo on 2025/8/20.
//

#ifndef TSPSERVICE_TBOX_MQTT_MESSAGE_HANDLER_H
#define TSPSERVICE_TBOX_MQTT_MESSAGE_HANDLER_H
#include <string>

class TboxMqttMessageHandler {
public:
    /**
     * 处理TBox MQTT消息
     * @param payload 数据
     */
    virtual void handle(std::string payload) = 0;

    virtual ~TboxMqttMessageHandler() = default;
};

#endif //TSPSERVICE_TBOX_MQTT_MESSAGE_HANDLER_H
