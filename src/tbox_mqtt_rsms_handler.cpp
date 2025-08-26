//
// Created by hwyz_leo on 2025/8/20.
//
#include "spdlog/spdlog.h"

#include "tbox_mqtt_rsms_handler.h"
#include "tsp_mqtt_client.h"

TboxMqttRsmsHandler &TboxMqttRsmsHandler::get_instance() {
    static TboxMqttRsmsHandler instance;
    return instance;
}

void TboxMqttRsmsHandler::handle(const void *payload, int payload_len) {
    spdlog::debug("转发国标信号至TSP");
    int mid = 0;
    TspMqttClient::get_instance().publish(mid, "RSMS", payload, payload_len);
}