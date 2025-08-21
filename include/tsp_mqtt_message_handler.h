//
// Created by hwyz_leo on 2025/8/20.
//

#ifndef TSPSERVICE_TSP_MQTT_MESSAGE_HANDLER_H
#define TSPSERVICE_TSP_MQTT_MESSAGE_HANDLER_H
#include <string>

class TspMqttMessageHandler {
public:
    /**
     * 处理TSP MQTT消息
     * @param payload 数据
     */
    virtual void handle(std::string payload) = 0;

    virtual ~TspMqttMessageHandler() = default;
};

#endif //TSPSERVICE_TSP_MQTT_MESSAGE_HANDLER_H
