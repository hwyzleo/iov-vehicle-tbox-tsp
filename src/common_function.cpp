//
// Created by hwyz_leo on 2025/5/21.
//

#include "common_function.h"
#include <iostream>
#include <cstdlib>
#include <fstream>
#include "spdlog/spdlog.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <io.h>
#define access _access
#else

#include <unistd.h>

#endif

std::string CommonFunction::get_config_file_path() {
    const char *env = std::getenv("ENV");
    std::string env_str = env ? env : "dev";
    return "../config/config." + env_str + ".yaml";
}

bool CommonFunction::file_exists(const std::string &file_path) {
    return (access(file_path.c_str(), F_OK) == 0);
}

bool CommonFunction::write_file(const std::string &file_path, const std::string &data) {
    std::ofstream file(file_path);
    if (file.is_open()) {
        file << data;
        file.close();
        return true;
    }
    spdlog::warn("写入文件[{}]失败", file_path);
    return false;
}

bool CommonFunction::rename_file(const std::string &old_path, const std::string &new_path) {
    int result = std::rename(old_path.c_str(), new_path.c_str());
    if (result != 0) {
        spdlog::warn("重命名文件[{} -> {}]失败", old_path, new_path);
    }
}

std::string CommonFunction::get_current_date() {
    auto now = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);
    struct std::tm *local_time = std::localtime(&current_time);
    std::string date;
    int year = local_time->tm_year + 1900;
    date = std::to_string(year);
    int month = local_time->tm_mon + 1;
    if (month < 10) {
        date += "0";
    }
    date += std::to_string(month);
    int day = local_time->tm_mday;
    if (day < 10) {
        date += "0";
    }
    date += std::to_string(day);
    return date;
}

std::vector<unsigned char> CommonFunction::hex_to_bytes(const std::string &hex_str) {
    if (hex_str.length() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hex_str.length() / 2);

    for (size_t i = 0; i < hex_str.length(); i += 2) {
        if (!std::isxdigit(hex_str[i]) || !std::isxdigit(hex_str[i + 1])) {
            throw std::invalid_argument("Invalid hex character");
        }

        try {
            std::string byte_string = hex_str.substr(i, 2);
            unsigned char byte = (unsigned char) std::stoi(byte_string, nullptr, 16);
            bytes.push_back(byte);
        } catch (const std::exception &e) {
            throw std::runtime_error("Failed to convert hex to bytes: " + std::string(e.what()));
        }
    }

    return bytes;
}

std::string CommonFunction::bytes_to_hex(const std::vector<unsigned char> &bytes, bool uppercase = true) {
    static const char hex_chars_upper[] = "0123456789ABCDEF";
    static const char hex_chars_lower[] = "0123456789abcdef";
    const char *hex_chars = uppercase ? hex_chars_upper : hex_chars_lower;

    std::string hex_str;
    hex_str.reserve(bytes.size() * 2);

    for (unsigned char byte: bytes) {
        hex_str.push_back(hex_chars[byte >> 4]);
        hex_str.push_back(hex_chars[byte & 0xF]);
    }

    return hex_str;
}

std::string CommonFunction::base64_encode(const std::string &input) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (char c: input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::string CommonFunction::base64_decode(const std::string &input) {
    int in_len = input.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (input[in_] != '=') && (isalnum(input[in_]) || (input[in_] == '+') || (input[in_] == '/'))) {
        char_array_4[i++] = input[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::vector<unsigned char> CommonFunction::aes_decrypt(const std::vector<unsigned char> &encrypted_bytes,
                                                       const std::vector<unsigned char> &key,
                                                       const std::vector<unsigned char> &iv) {
    if (key.size() != 16) {
        throw std::runtime_error("密钥长度无效");
    }
    if (iv.size() != AES_BLOCK_SIZE) {
        throw std::runtime_error("IV长度无效");
    }
    if (encrypted_bytes.empty() || encrypted_bytes.size() % AES_BLOCK_SIZE != 0) {
        throw std::runtime_error("加密数据长度无效");
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("创建密钥环境失败");
    }
    std::vector<unsigned char> plaintext(encrypted_bytes.size());
    int len;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr,
                           key.data(), iv.data()) != 1) {
        throw std::runtime_error("解密初始化失败");
    }
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                          encrypted_bytes.data(), encrypted_bytes.size()) != 1) {
        throw std::runtime_error("解密数据失败");
    }
    plaintext_len += len;
    if (EVP_DecryptFinal_ex(ctx.get(),
                            plaintext.data() + plaintext_len, &len) != 1) {
        throw std::runtime_error("解密最后步骤失败");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
}