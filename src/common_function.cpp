//
// Created by 叶荣杰 on 2025/5/21.
//

#include "common_function.h"

std::string CommonFunction::getConfigFilePath() {
    const char* env = std::getenv("ENV");
    std::string envStr = env ? env : "dev";
    return "../config/config." + envStr + ".yaml";
}