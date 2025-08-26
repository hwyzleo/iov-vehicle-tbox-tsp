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
     * @param payload_len 数据长度
     */
    virtual void handle(const void *payload=nullptr, int payload_len=0) = 0;

    virtual ~TboxMqttMessageHandler() = default;
};

#endif //TSPSERVICE_TBOX_MQTT_MESSAGE_HANDLER_H
