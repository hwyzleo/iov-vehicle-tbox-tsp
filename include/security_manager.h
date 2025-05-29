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
    static SecurityManager &GetInstance();

    /**
     * 加载配置
     * @param config 配置信息
     * @return 是否加载成功
     */
    bool LoadConfig(const YAML::Node &config);

    /**
     * 检查证书
     */
    bool CheckCertification();

    /**
     * 检查密钥
     */
    void CheckSecretKey();

private:
    // 证书路径
    std::string certification_path_;
    // 密钥文件路径
    std::string secret_key_path_;
    // HTTP证书申请路径
    std::string http_cert_apply_path_;
    // HTTP证书续期路径
    std::string http_cert_renew_path_;

private:
    /**
     * 检查证书文件是否存在
     * @return 文件是否存在
     */
    bool CheckCertificationExist();

    /**
     * 检查证书文件是否有效
     * @return 文件是否有效
     */
    bool CheckCertificationValid();

    /**
     * 申请证书
     * @return 是否成功
     */
    bool ApplyCertification();

    /**
     * 续期证书
     * @return
     */
    bool RenewCertification();

};