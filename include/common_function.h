//
// Created by 叶荣杰 on 2025/5/21.
//

#ifndef TSPSERVICE_COMMON_FUNCTION_H
#define TSPSERVICE_COMMON_FUNCTION_H
#include <iostream>
#endif //TSPSERVICE_COMMON_FUNCTION_H

class CommonFunction {
public:
    /**
     * 析构虚函数
     */
    ~CommonFunction() {};

public:
    /**
     * 获取配置文件路径
     * @return 配置文件路径
     */
    static std::string getConfigFilePath();
};