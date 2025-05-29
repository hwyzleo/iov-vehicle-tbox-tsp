//
// Created by hwyz_leo on 2025/5/21.
//

#ifndef TSPSERVICE_COMMON_FUNCTION_H
#define TSPSERVICE_COMMON_FUNCTION_H

#include <iostream>

#endif //TSPSERVICE_COMMON_FUNCTION_H

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
    static std::string GetConfigFilePath();

    /**
     * 判断文件是否存在
     * @param filePath 文件路径
     * @return 文件是否存在
     */
    static bool FileExists(const std::string &filePath);

    /**
     * 写入文件
     * @param filePath 文件路径
     * @param data 写入数据
     * @return 是否成功
     */
    static bool WriteFile(const std::string &filePath, const std::string &data);

    /**
     * 重命名文件
     * @param oldPath 原文件路径
     * @param newPath 新文件路径
     * @return 是否成功
     */
    static bool RenameFile(const std::string &oldPath, const std::string &newPath);

    /**
     * 获取当前日期(yyyymmdd)
     * @return 当前日期
     */
    static std::string GetCurrentDate();
};