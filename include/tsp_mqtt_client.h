//
// Created by hwyz_leo on 2024/9/5.
//

#ifndef TSPSERVICE_TSP_MQTT_CLIENT_H
#define TSPSERVICE_TSP_MQTT_CLIENT_H
#include <thread>

#include "mosquitto/mosquitto.h"
#include "mosquitto/mosquittopp.h"

#include "constants.h"

/**
 * TSP的MQTT客户端
 */
class TspMqttClient : public mosqpp::mosquittopp {
public:
    /**
     * 析构虚函数
     */
    ~TspMqttClient() override;

    /**
     * 获取单例
     * @return 单例
     */
    static TspMqttClient &get_instance();

    /**
     * 防止对象被复制
     */
    TspMqttClient(const TspMqttClient &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TspMqttClient &operator=(const TspMqttClient &) = delete;

public:

    /**
     * 启动
     * @return 启动是否成功
     */
    bool start();

    /**
     * 停止
     */
    void stop();

    /**
     * 是否连接
     * @return 是否连接成功
     */
    bool is_connected() const;

    /**
     * 发布
     * @param mid 消息ID
     * @param topic 主题
     * @param payload 数据
     * @param payload_len 数据长度
     * @param qos 消息质量
     * @return 是否发布成功
     */
    bool publish(int &mid, const std::string &topic, const void *payload = nullptr, int payload_len = 0, int qos = 1);

    void on_connect(int rc) override;

    void on_disconnect(int rc) override;

    void on_publish(int mid) override;

    void on_message(const struct mosquitto_message *message) override;

    void on_subscribe(int mid, int qos_count, const int *granted_qos) override;

    void on_unsubscribe(int mid) override;

    void on_log(int level, const char *str) override;

    void on_error() override;

private:

    TspMqttClient();

    /**
     * 初始化
     * @return 初始化是否成功
     */
    bool init();

    /**
     * 连接管理
     */
    void connect_manage();

    /**
     * 连接
     * @return 是否连接成功
     */
    bool connect();

    /**
     * 订阅TSP主题
     * @param mid 消息ID
     * @param topic 主题
     * @param qos 消息质量
     * @return 是否订阅成功
     */
    bool subscribe_tsp(int &mid, const std::string &topic, int qos = 1);

    /**
     * 取消订阅TSP主题
     * @param mid 消息ID
     * @param topic 主题
     * @return 是否取消订阅成功
     */
    bool unsubscribe_tsp(int &mid, const std::string &topic);

    /**
     * 获取设备信息
     * @param sn 设备序列号
     * @param vin 车架号
     * @return 是否获取成功
     */
    bool get_device_info(std::string &sn, std::string &vin) const;

private:
    // 是否初始化
    std::atomic_bool is_inited_{false};
    // 是否启动
    std::atomic_bool is_started_{false};
    // 是否连接
    std::atomic_bool is_connected_{false};
    // 是否连接中
    std::atomic_bool is_connecting_{false};
    // 是否订阅
    std::atomic_bool is_subscribed_{false};
    // 连接器
    std::thread connector;
    // 轮询锁
    std::mutex mtx_loop_;
    // 轮询条件
    std::condition_variable cv_loop_;
};

#endif //TSPSERVICE_TSP_MQTT_CLIENT_H