//
// Created by hwyz_leo on 2025/5/21.
//

#ifndef TSPSERVICE_SECURITY_MANAGER_H
#define TSPSERVICE_SECURITY_MANAGER_H

#include "../third_party/include/yaml-cpp/yaml.h"

#endif //TSPSERVICE_SECURITY_MANAGER_H

/**
 * 安全管理器
 */
class SecurityManager {
public:
    /**
     * 构造函数
     */
    SecurityManager() = default;

    /**
     * 析构函数
     */
    ~SecurityManager() = default;

public:
    /**
     * 获取单例
     * @return 单例
     */
    static SecurityManager &get_instance();

    /**
     * 加载配置
     * @param config 配置信息
     * @return 是否加载成功
     */
    bool load_config(const YAML::Node &config);

    /**
     * 检查证书
     */
    bool check_certification();

    /**
     * 检查通讯密钥
     */
    bool check_communication_secret_key();

private:
    // 证书路径
    std::string certification_path_;
    // 密钥文件路径
    std::string secret_key_path_;
    // 默认密钥Hex
    std::string default_sk_hex_;
    // HTTP证书申请路径
    std::string http_cert_apply_path_;
    // HTTP证书续期路径
    std::string http_cert_renew_path_;
    // HTTP通讯密钥申请路径
    std::string http_comm_sk_apply_path_;

private:
    /**
     * 检查证书文件是否存在
     * @return 证书是否存在
     */
    bool check_certification_exist();

    /**
     * 检查证书文件是否有效
     * @return 证书是否有效
     */
    bool check_certification_valid();

    /**
     * 申请证书
     * @return 是否成功
     */
    bool apply_certification();

    /**
     * 续期证书
     * @return 是否成功
     */
    bool renew_certification();

    /**
     * 检查通讯密钥是否存在
     * @return 通讯密钥是否存在
     */
    bool check_communication_secret_key_exist();

    /**
     * 检查通讯密钥是否有效
     * @return 通讯密钥是否有效
     */
    bool check_communication_secret_key_valid();

    /**
     * 申请通信密钥
     * @return 是否成功
     */
    bool apply_communication_secret_key();

};