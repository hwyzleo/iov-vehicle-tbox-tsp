//
// Created by hwyz_leo on 2025/5/21.
//
#include <iostream>

#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>
#include "utils.h"

#include "security_manager.h"
#include "tsp_http_client.h"

using json = nlohmann::json;

SecurityManager &SecurityManager::get_instance() {
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::load_config(const YAML::Node &config) {
    spdlog::info("加载证书及密钥配置信息");
    std::string sec_cert_path = config["sec"]["cert"]["path"].as<std::string>();
    std::string sec_sk_path = config["sec"]["sk"]["path"].as<std::string>();
    std::string default_sk_hex = config["sec"]["sk"]["default-hex"].as<std::string>();
    std::string http_cert_apply_path = config["tsp"]["http"]["path"]["cert-apply"].as<std::string>();
    std::string http_cert_renew_path = config["tsp"]["http"]["path"]["cert-renew"].as<std::string>();
    std::string http_comm_sk_apply_path = config["tsp"]["http"]["path"]["comm-sk-apply"].as<std::string>();
    if (sec_cert_path.empty() || sec_sk_path.empty() || http_cert_apply_path.empty()) {
        return false;
    }
    certification_path_ = sec_cert_path;
    secret_key_path_ = sec_sk_path;
    default_sk_hex_ = default_sk_hex;
    http_cert_apply_path_ = http_cert_apply_path;
    http_comm_sk_apply_path_ = http_comm_sk_apply_path;
    return true;
}

bool SecurityManager::check_certification() {
    if (!check_certification_exist()) {
        apply_certification();
    }
    bool cert_valid = check_certification_valid();
    if (!cert_valid) {
        renew_certification();
        cert_valid = check_certification_valid();
    }
    return cert_valid;
}

bool SecurityManager::check_certification_exist() {
    return hwyz::Utils::file_exists(certification_path_);
}

bool SecurityManager::check_certification_valid() {
    // TODO 检查证书是否有效
    return true;
}

bool SecurityManager::apply_certification() {
    json request;
    request["csr"] = "";
    std::string response = TspHttpClient::get_instance().post(http_cert_apply_path_, request.dump());
    spdlog::info("从服务器下载证书: {}", response);
    json response_json = json::parse(response);
    if (response_json["code"] == 0) {
        spdlog::info("保存证书: {}", certification_path_);
        std::string cert_data;
        if (!response_json["data"]["p7b"].is_null()) {
            cert_data = response_json["data"]["p7b"];
        }
        return hwyz::Utils::write_file(certification_path_, cert_data);
    }
    spdlog::error("从服务器下载证书失败: {}", response_json["message"]);
    return false;
}

bool SecurityManager::renew_certification() {
    json request;
    request["csr"] = "";
    std::string response = TspHttpClient::get_instance().post(http_cert_renew_path_, request.dump());
    spdlog::info("从服务器续期证书: {}", response);
    json response_json = json::parse(response);
    if (response_json["code"] == 0) {
        spdlog::info("备份证书: {}", certification_path_ + hwyz::Utils::get_current_date());
        hwyz::Utils::rename_file(certification_path_, certification_path_ + hwyz::Utils::get_current_date());
        std::string cert_data;
        if (!response_json["data"]["p7b"].is_null()) {
            cert_data = response_json["data"]["p7b"];
        }
        return hwyz::Utils::write_file(certification_path_, cert_data);
    }
    spdlog::error("从服务器续期证书失败: {}", response_json["message"]);
    return false;
}

bool SecurityManager::check_communication_secret_key() {
    if (!check_communication_secret_key_exist()) {
        apply_communication_secret_key();
    }
    bool comm_sk_valid = check_communication_secret_key_valid();
    if (!comm_sk_valid) {
        comm_sk_valid = apply_communication_secret_key();
    }
    return comm_sk_valid;
}

bool SecurityManager::check_communication_secret_key_exist() {
    // TODO 检查本地安全芯片是否存在通讯密钥
    // 此处先以检查文件跑通流程
    return hwyz::Utils::file_exists(secret_key_path_);
}

bool SecurityManager::check_communication_secret_key_valid() {
    // TODO 检查本地通讯密钥是否有效
    return true;
}

bool SecurityManager::apply_communication_secret_key() {
    json request;
    request["plaintext"] = "";
    request["signature"] = "";
    std::string response = TspHttpClient::get_instance().post(http_comm_sk_apply_path_, request.dump());
    spdlog::info("从服务器申请通讯密钥: {}", response);
    json response_json = json::parse(response);
    if (response_json["code"] == 0 && !response_json["data"]["encryptedSk"].is_null()) {
        std::string encrypted_comm_sk_with_iv = response_json["data"]["encryptedSk"];
        spdlog::info("加密通讯密钥 + IV: {}", encrypted_comm_sk_with_iv);
        std::string comm_sk_iv = encrypted_comm_sk_with_iv.substr(0, 32);
        std::string encrypted_comm_sk = encrypted_comm_sk_with_iv.substr(32);
        std::vector<unsigned char> encrypted_bytes = hwyz::Utils::hex_to_bytes(encrypted_comm_sk);
        std::vector<unsigned char> default_sk_bytes = hwyz::Utils::hex_to_bytes(default_sk_hex_);
        std::vector<unsigned char> comm_sk_iv_bytes = hwyz::Utils::hex_to_bytes(comm_sk_iv);
        std::vector<unsigned char> comm_sk_bytes = hwyz::Utils::aes_decrypt(encrypted_bytes, default_sk_bytes,
                                                                               comm_sk_iv_bytes);
        std::string comm_sk = std::string(reinterpret_cast<const char *>(comm_sk_bytes.data()), comm_sk_bytes.size());
        spdlog::info("保存通讯密钥: {}", secret_key_path_);
        // TODO 将通讯密钥写入安全芯片，这里先写本地文件
        return hwyz::Utils::write_file(secret_key_path_, comm_sk);
    }
    spdlog::error("从服务器申请通讯密钥失败: {}", response_json["message"]);
    return false;
}