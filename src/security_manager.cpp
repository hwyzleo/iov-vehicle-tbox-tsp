//
// Created by hwyz_leo on 2025/5/21.
//
#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>
#include "utils.h"

#include "security_manager.h"
#include "tsp_http_client.h"
#include "log_adapter.h"

using tbox::tsp::LogAdapter;

using json = nlohmann::json;

SecurityManager &SecurityManager::get_instance() {
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::load_config(const YAML::Node &config) {
    LogAdapter::security().info("tsp.security.config_loading", "加载证书及密钥配置信息");
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
    LogAdapter::security().info("tsp.security.cert_downloading", "从服务器下载证书", {
        {"response_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(response.size()))}
    });
    if (response.empty()) {
        LogAdapter::security().error("tsp.cert.download_failed", "从服务器下载证书失败：空响应");
        return false;
    }
    try {
        json response_json = json::parse(response);
        if (response_json["code"] == 0) {
            LogAdapter::security().info("tsp.security.cert_saving", "保存证书", {
                {"path", tbox::fw::log::FieldValue::makeString(certification_path_)}
            });
            std::string cert_data;
            if (!response_json["data"]["p7b"].is_null()) {
                cert_data = response_json["data"]["p7b"];
            }
            return hwyz::Utils::write_file(certification_path_, cert_data);
        }
        LogAdapter::security().error("tsp.cert.download_failed", "从服务器下载证书失败", {
            {"message", tbox::fw::log::FieldValue::makeString(response_json["message"].get<std::string>())}
        });
        return false;
    } catch (const json::parse_error& e) {
        LogAdapter::security().error("tsp.cert.download_failed", "从服务器下载证书失败：JSON解析错误", {
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
        return false;
    }
}

bool SecurityManager::renew_certification() {
    json request;
    request["csr"] = "";
    std::string response = TspHttpClient::get_instance().post(http_cert_renew_path_, request.dump());
    LogAdapter::security().info("tsp.security.cert_renewing", "从服务器续期证书", {
        {"response_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(response.size()))}
    });
    if (response.empty()) {
        LogAdapter::security().error("tsp.cert.renew_failed", "从服务器续期证书失败：空响应");
        return false;
    }
    try {
        json response_json = json::parse(response);
        if (response_json["code"] == 0) {
            std::string backup_path = certification_path_ + hwyz::Utils::get_current_date();
            LogAdapter::security().info("tsp.security.cert_backing_up", "备份证书", {
                {"path", tbox::fw::log::FieldValue::makeString(backup_path)}
            });
            hwyz::Utils::rename_file(certification_path_, backup_path);
            std::string cert_data;
            if (!response_json["data"]["p7b"].is_null()) {
                cert_data = response_json["data"]["p7b"];
            }
            return hwyz::Utils::write_file(certification_path_, cert_data);
        }
        LogAdapter::security().error("tsp.cert.renew_failed", "从服务器续期证书失败", {
            {"message", tbox::fw::log::FieldValue::makeString(response_json["message"].get<std::string>())}
        });
        return false;
    } catch (const json::parse_error& e) {
        LogAdapter::security().error("tsp.cert.renew_failed", "从服务器续期证书失败：JSON解析错误", {
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
        return false;
    }
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
    LogAdapter::security().info("tsp.security.comm_sk_applying", "从服务器申请通讯密钥", {
        {"response_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(response.size()))}
    });
    if (response.empty()) {
        LogAdapter::security().error("tsp.comm_sk.apply_failed", "从服务器申请通讯密钥失败：空响应");
        return false;
    }
    try {
        json response_json = json::parse(response);
        if (response_json["code"] == 0 && !response_json["data"]["encryptedSk"].is_null()) {
            std::string encrypted_comm_sk_with_iv = response_json["data"]["encryptedSk"];
            LogAdapter::security().info("tsp.security.comm_sk_decrypting", "解密通讯密钥", {
                {"encrypted_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(encrypted_comm_sk_with_iv.size()))}
            });
            std::string comm_sk_iv = encrypted_comm_sk_with_iv.substr(0, 32);
            std::string encrypted_comm_sk = encrypted_comm_sk_with_iv.substr(32);
            std::vector<unsigned char> encrypted_bytes = hwyz::Utils::hex_to_bytes(encrypted_comm_sk);
            std::vector<unsigned char> default_sk_bytes = hwyz::Utils::hex_to_bytes(default_sk_hex_);
            std::vector<unsigned char> comm_sk_iv_bytes = hwyz::Utils::hex_to_bytes(comm_sk_iv);
            std::vector<unsigned char> comm_sk_bytes = hwyz::Utils::aes_decrypt(encrypted_bytes, default_sk_bytes,
                                                                                   comm_sk_iv_bytes);
            std::string comm_sk = std::string(reinterpret_cast<const char *>(comm_sk_bytes.data()), comm_sk_bytes.size());
            LogAdapter::security().info("tsp.security.comm_sk_saving", "保存通讯密钥", {
                {"path", tbox::fw::log::FieldValue::makeString(secret_key_path_)}
            });
            // TODO 将通讯密钥写入安全芯片，这里先写本地文件
            return hwyz::Utils::write_file(secret_key_path_, comm_sk);
        }
        LogAdapter::security().error("tsp.comm_sk.apply_failed", "从服务器申请通讯密钥失败", {
            {"message", tbox::fw::log::FieldValue::makeString(response_json["message"].get<std::string>())}
        });
        return false;
    } catch (const json::parse_error& e) {
        LogAdapter::security().error("tsp.comm_sk.apply_failed", "从服务器申请通讯密钥失败：JSON解析错误", {
            {"error", tbox::fw::log::FieldValue::makeString(e.what())}
        });
        return false;
    }
}