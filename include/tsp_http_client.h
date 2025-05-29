//
// Created by hwyz_leo on 2025/5/22.
//

#ifndef TSPSERVICE_TSP_HTTP_CLIENT_H
#define TSPSERVICE_TSP_HTTP_CLIENT_H

#include <iostream>
#include <curl/curl.h>
#include "../third_party/include/yaml-cpp/yaml.h"

#endif //TSPSERVICE_TSP_HTTP_CLIENT_H

class TspHttpClient {
public:
    /**
     * 析构虚函数
     */
    ~TspHttpClient() = default;

    /**
     * 获取单例
     * @return 单例
     */
    static TspHttpClient &GetInstance();

    /**
     * 防止对象被复制
     */
    TspHttpClient(const TspHttpClient &) = delete;

    /**
     * 防止对象被赋值
     * @return
     */
    TspHttpClient &operator=(const TspHttpClient &) = delete;

public:
    /**
     * 加载配置
     * @param config 配置信息
     * @return 是否加载成功
     */
    bool LoadConfig(const YAML::Node &config);

    /**
     * 加载车辆信息
     * @param vin 车架号
     * @param sn TBox序列号
     * @return 是否加载成功
     */
    bool LoadVehicleInfo(const std::string vin, const std::string sn);

    /**
     * GET请求
     * @param path 请求路径
     * @return    请求结果
     */
    std::string Get(const std::string &path);

    /**
     * POST请求
     * @param path  请求路径
     * @param data 请求数据
     * @return     请求结果
     */
    std::string Post(const std::string &path, const std::string &data);

private:
    /**
     * 构造函数
     */
    TspHttpClient();

    /**
     * 回调函数：处理响应数据
     * @param contents
     * @param size
     * @param nmemb
     * @param s
     * @return
     */
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *s);

    /**
     * 构造请求头
     * @param headers 请求头
     * @return 请求头
     */
    void PackageHeaders(struct curl_slist *&headers);

private:
    // 服务器域名
    std::string server_domain_;
    // 车架号
    std::string vin_;
    // TBox序列号
    std::string sn_;
};