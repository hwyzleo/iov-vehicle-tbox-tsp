//
// Created by 叶荣杰 on 2024/9/5.
//
#include <iostream>

#include "../include/main.h"
#include "../include/tsp_mqtt_client.h"

// 主函数
int main() {
    TspMqttClient::GetInstance().Init();
    TspMqttClient::GetInstance().Start();
    std::cout << "开始" << std::endl;
    while(true) {
        std::cout << "检查是否连接" << std::endl;
        if(TspMqttClient::GetInstance().IsConnected()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    int mid = 0;
    std::cout << "订阅" << std::endl;
    TspMqttClient::GetInstance().Subscribe(mid, "DOWN/HWYZTEST000000001/FIND_VEHICLE");

    while(true) {
        std::cout << "程序正在运行..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(60)); // 每60秒打印一次
    }

    return 0;
}