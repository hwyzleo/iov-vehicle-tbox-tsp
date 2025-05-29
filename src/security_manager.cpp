//
// Created by hwyz_leo on 2025/5/21.
//

#include "security_manager.h"
#include "spdlog/spdlog.h"
#include "common_function.h"
#include "tsp_http_client.h"
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

SecurityManager &SecurityManager::GetInstance() {
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::LoadConfig(const YAML::Node &config) {
    spdlog::info("加载证书及密钥配置信息");
    std::string sec_cert_path = config["sec"]["cert"]["path"].as<std::string>();
    std::string sec_sk_path = config["sec"]["sk"]["path"].as<std::string>();
    std::string http_cert_apply_path = config["tsp"]["http"]["path"]["cert-apply"].as<std::string>();
    std::string http_cert_renew_path = config["tsp"]["http"]["path"]["cert-renew"].as<std::string>();
    if (sec_cert_path.empty() || sec_sk_path.empty() || http_cert_apply_path.empty()) {
        return false;
    }
    certification_path_ = sec_cert_path;
    secret_key_path_ = sec_sk_path;
    http_cert_apply_path_ = http_cert_apply_path;
    return true;
}

bool SecurityManager::CheckCertification() {
    if (!CheckCertificationExist()) {
        ApplyCertification();
    }
    bool certValid = CheckCertificationValid();
    if (!certValid) {
        RenewCertification();
        certValid = CheckCertificationValid();
    }
    return certValid;
}

bool SecurityManager::CheckCertificationExist() {
    return CommonFunction::FileExists(certification_path_);
}

bool SecurityManager::CheckCertificationValid() {
    // TODO 检查证书是否有效
    return true;
}

bool SecurityManager::ApplyCertification() {
    json request;
    request["csr"] = "";
    std::string response = TspHttpClient::GetInstance().Post(http_cert_apply_path_, request.dump());
    spdlog::info("从服务器下载证书: {}", response);
    json response_json = json::parse(response);
    if (response_json["code"] == 0) {
        spdlog::info("保存证书: {}", certification_path_);
        std::string cert_data;
        if (!response_json["data"]["p7b"].is_null()) {
            cert_data = response_json["data"]["p7b"];
        }
        return CommonFunction::WriteFile(certification_path_, cert_data);
    }
    spdlog::error("从服务器下载证书失败: {}", response_json["message"]);
    return false;
}

bool SecurityManager::RenewCertification() {
    json request;
    request["csr"] = "";
    std::string response = TspHttpClient::GetInstance().Post(http_cert_renew_path_, request.dump());
    spdlog::info("从服务器续期证书: {}", response);
    json response_json = json::parse(response);
    if (response_json["code"] == 0) {
        spdlog::info("备份证书: {}", certification_path_ + CommonFunction::GetCurrentDate());
        CommonFunction::RenameFile(certification_path_, certification_path_ + CommonFunction::GetCurrentDate());
        std::string cert_data;
        if (!response_json["data"]["p7b"].is_null()) {
            cert_data = response_json["data"]["p7b"];
        }
        return CommonFunction::WriteFile(certification_path_, cert_data);
    }
    spdlog::error("从服务器续期证书失败: {}", response_json["message"]);
    return false;
}

void SecurityManager::CheckSecretKey() {

}