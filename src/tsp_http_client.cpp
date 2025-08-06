//
// Created by hwyz_leo on 2025/5/22.
//
#include <string>

#include "spdlog/spdlog.h"
#include <curl/curl.h>

#include "tsp_http_client.h"

TspHttpClient::TspHttpClient() {}

TspHttpClient &TspHttpClient::get_instance() {
    static TspHttpClient instance;
    return instance;
}

bool TspHttpClient::load_config(const YAML::Node &config) {
    spdlog::info("加载TSP HTTP配置信息");
    std::string domain = config["tsp"]["http"]["domain"].as<std::string>();
    if (domain.empty()) {
        return false;
    }
    server_domain_ = domain;
    return true;
}

bool TspHttpClient::load_vehicle_info(const std::string vin, const std::string sn) {
    spdlog::info("加载车辆信息");
    if (vin.empty() || sn.empty()) {
        return false;
    }
    vin_ = vin;
    sn_ = sn;
    return true;
}

std::string TspHttpClient::get(const std::string &path) {
    std::string url = "https://" + server_domain_ + path;
    CURL *curl = curl_easy_init();
    std::string response;
    if (curl) {
        // 设置URL
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        // 启用SSL验证
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        // 设置Header
        struct curl_slist *headers = nullptr;
        package_headers(headers);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        // 设置回调函数处理响应
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        // 执行请求
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            spdlog::error("TSP HTTP GET请求失败：%s", curl_easy_strerror(res));
        }
        // 清理资源
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return response;
    }
}

std::string TspHttpClient::post(const std::string &path, const std::string &data) {
    std::string url = "https://" + server_domain_ + path;
    CURL *curl = curl_easy_init();
    std::string response;
    if (curl) {
        // 设置URL和POST标志
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        // 设置回调函数处理响应
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        // 启用SSL验证
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        // 设置POST数据
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
        // 设置Header
        struct curl_slist *headers = nullptr;
        package_headers(headers);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
        curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
        // 调试日志
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        // 执行请求
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            spdlog::error("TSP HTTP POST请求[{}]失败：{}", url, curl_easy_strerror(res));
        }
        // 清理资源
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return response;
    }
}

size_t TspHttpClient::write_callback(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size * nmemb;
    std::string data((char*)contents, newLength);
    std::string chunk_buffer_;
    chunk_buffer_ += data;
    while (true) {
        // 查找块长度行
        size_t crlf_pos = chunk_buffer_.find("\r\n");
        if (crlf_pos == std::string::npos) break;
        // 解析块长度（十六进制转十进制）
        std::string length_str = chunk_buffer_.substr(0, crlf_pos);
        size_t chunk_length = std::stoul(length_str, nullptr, 16);
        // 检查是否有完整的块数据
        size_t data_start = crlf_pos + 2;  // 跳过 "\r\n"
        if (chunk_buffer_.size() >= data_start + chunk_length + 2) {  // +2 是块结束的 "\r\n"
            // 提取数据块
            std::string chunk_data = chunk_buffer_.substr(data_start, chunk_length);
            s->append(chunk_data);
            // 移除已处理的数据（包括长度行、数据和结束符）
            size_t next_pos = data_start + chunk_length + 2;
            chunk_buffer_ = chunk_buffer_.substr(next_pos);
            // 如果块长度为0，表示结束
            if (chunk_length == 0) break;
        } else {
            // 数据不完整，等待下一次回调
            break;
        }
    }
    return newLength;
}

void TspHttpClient::package_headers(struct curl_slist *&headers) {
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, ("vin: " + vin_).c_str());
    headers = curl_slist_append(headers, ("clientId: " + sn_).c_str());
    headers = curl_slist_append(headers, "clientType: TBOX");
}