//
// Created by hwyz_leo on 2025/5/21.
//

#include "common_function.h"
#include <iostream>
#include <cstdlib>
#include <fstream>
#include "spdlog/spdlog.h"

#ifdef _WIN32
#include <io.h>
#define access _access
#else

#include <unistd.h>

#endif

std::string CommonFunction::GetConfigFilePath() {
    const char *env = std::getenv("ENV");
    std::string envStr = env ? env : "dev";
    return "../config/config." + envStr + ".yaml";
}

bool CommonFunction::FileExists(const std::string &filePath) {
    return (access(filePath.c_str(), F_OK) == 0);
}

bool CommonFunction::WriteFile(const std::string &filePath, const std::string &data) {
    std::ofstream file(filePath);
    if (file.is_open()) {
        file << data;
        file.close();
        return true;
    }
    spdlog::warn("写入文件[{}]失败", filePath);
    return false;
}

bool CommonFunction::RenameFile(const std::string &oldPath, const std::string &newPath) {
    int result = std::rename(oldPath.c_str(), newPath.c_str());
    if (result != 0) {
        spdlog::warn("重命名文件[{} -> {}]失败", oldPath, newPath);
    }
}

std::string CommonFunction::GetCurrentDate() {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    struct std::tm *localTime = std::localtime(&currentTime);
    std::string date;
    int year = localTime->tm_year + 1900;
    date = std::to_string(year);
    int month = localTime->tm_mon + 1;
    if (month < 10) {
        date += "0";
    }
    date += std::to_string(month);
    int day = localTime->tm_mday;
    if (day < 10) {
        date += "0";
    }
    date += std::to_string(day);
    return date;
}