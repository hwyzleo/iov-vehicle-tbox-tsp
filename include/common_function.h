//
// Created by hwyz_leo on 2025/5/21.
//

#ifndef TSPSERVICE_COMMON_FUNCTION_H
#define TSPSERVICE_COMMON_FUNCTION_H

#include <iostream>

#endif //TSPSERVICE_COMMON_FUNCTION_H

static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

class CommonFunction {
public:
    /**
     * 构造函数
     */
    CommonFunction() {};

    /**
     * 析构函数
     */
    ~CommonFunction() {};

public:
    /**
     * 获取配置文件路径
     * @return 配置文件路径
     */
    static std::string get_config_file_path();

    /**
     * 判断文件是否存在
     * @param file_path 文件路径
     * @return 文件是否存在
     */
    static bool file_exists(const std::string &file_path);

    /**
     * 写入文件
     * @param file_path 文件路径
     * @param data 写入数据
     * @return 是否成功
     */
    static bool write_file(const std::string &file_path, const std::string &data);

    /**
     * 重命名文件
     * @param old_path 原文件路径
     * @param new_path 新文件路径
     * @return 是否成功
     */
    static bool rename_file(const std::string &old_path, const std::string &new_path);

    /**
     * 获取当前日期(yyyymmdd)
     * @return 当前日期
     */
    static std::string get_current_date();

    /**
     * 十六进制字符串转字节数组
     * @param hex_str 十六进制字符串
     * @return 字节数组
     */
    static std::vector<unsigned char> hex_to_bytes(const std::string &hex_str);

    /**
     * 字节数组转十六进制字符串
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    static std::string bytes_to_hex(const std::vector<unsigned char> &bytes, bool uppercase);

    /**
     * Base64编码
     * @param input 输入字符串
     * @return Base64编码后的字符串
     */
    static std::string base64_encode(const std::string &input);

    /**
     * Base64解码
     * @param input 输入字符串
     * @return Base64解码后的字符串
     */
    static std::string base64_decode(const std::string &input);

    /**
     * AES解密
     * @param encrypted_bytes 加密字节数组
     * @param key 密钥
     * @param iv IV
     * @return 解密后字节数组
     */
    static std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &encrypted_bytes,
                                                  const std::vector<unsigned char> &key,
                                                  const std::vector<unsigned char> &iv);
};