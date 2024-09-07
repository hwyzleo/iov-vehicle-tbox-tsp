//
// Created by 叶荣杰 on 2024/9/7.
//

#ifndef TSPSERVICE_TBOX_MQTT_CLIENT_H
#define TSPSERVICE_TBOX_MQTT_CLIENT_H

#endif //TSPSERVICE_TBOX_MQTT_CLIENT_H

#include <thread>

#include "../third_party/include/mosquitto/mosquitto.h"
#include "../third_party/include/mosquitto/mosquittopp.h"
#include "constants.h"

/**
 * TSP的MQTT客户端
 */
class TboxMqttClient : public mosqpp::mosquittopp {
public:
    /**
     * 析构虚函数
     */
    ~TboxMqttClient() override;

    /**
     * 获取单例
     * @return 单例
     */
    static TboxMqttClient &GetInstance();

    /**
     * 防止对象被复制
     */
    TboxMqttClient(const TboxMqttClient &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TboxMqttClient &operator=(const TboxMqttClient &) = delete;

public:

    /**
     * 启动
     * @return 启动是否成功
     */
    bool Start();

    /**
     * 停止
     */
    void Stop();

    /**
     * 是否连接
     * @return 是否连接成功
     */
    bool IsConnected() const;

    /**
     * 发布
     * @param mid 消息ID
     * @param topic 主题
     * @param payload 数据
     * @param payload_len 数据长度
     * @param qos 消息质量
     * @return 是否发布成功
     */
    bool Publish(int &mid, const std::string &topic, const void *payload = nullptr, int payload_len = 0, int qos = 1);

    /**
     * 订阅
     * @param mid 消息ID
     * @param topic 主题
     * @param qos 消息质量
     * @return 是否订阅成功
     */
    bool Subscribe(int &mid, const std::string &topic, int qos = 1);

    void on_connect(int rc) override;

    void on_disconnect(int rc) override;

    void on_publish(int mid) override;

    void on_message(const struct mosquitto_message *message) override;

    void on_subscribe(int mid, int qos_count, const int *granted_qos) override;

    void on_unsubscribe(int mid) override;

    void on_log(int level, const char *str) override;

    void on_error() override;

private:

    TboxMqttClient();

    /**
     * 初始化
     * @return 初始化是否成功
     */
    bool Init();

    /**
     * 连接管理
     */
    void ConnectManage();

    /**
     * 连接
     * @return 是否连接成功
     */
    bool Connect();

    /**
     * 获取设备信息
     * @param sn 设备序列号
     * @param vin 车架号
     * @return 是否获取成功
     */
    bool GetDeviceInfo(std::string &sn, std::string &vin) const;

private:
    // 是否初始化
    std::atomic_bool is_inited_{false};
    // 是否启动
    std::atomic_bool is_started_{false};
    // 是否连接
    std::atomic_bool is_connected_{false};
    // 是否连接中
    std::atomic_bool is_connecting_{false};
    // 连接器
    std::thread connector;
    // 轮询锁
    std::mutex mtx_loop_;
    // 轮询条件
    std::condition_variable cv_loop_;
};