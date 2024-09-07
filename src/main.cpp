//
// Created by 叶荣杰 on 2024/9/5.
//
#include <iostream>
#include <thread>

#include "../include/main.h"
#include "../include/tsp_mqtt_client.h"
#include "../include/tbox_mqtt_client.h"

// 主函数
int main() {
    // 启动TSP MQTT客户端
    TspMqttClient::GetInstance().Start();
    // 启动TBOX MQTT客户端
    TboxMqttClient::GetInstance().Start();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}