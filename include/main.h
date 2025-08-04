//
// Created by hwyz_leo on 2024/9/5.
//

#ifndef TSPSERVICE_MAIN_H
#define TSPSERVICE_MAIN_H

#endif //TSPSERVICE_MAIN_H

static volatile sig_atomic_t shutdown_requested = 0;

/**
 * 信号处理
 * @param sig 信号
 * @param info 信号信息
 * @param context 上下文
 */
static void sig_handler(int sig, siginfo_t *info, void *context);

/**
 * 初始化日志
 * @param config 配置
 */
void init_logger(const YAML::Node& config);