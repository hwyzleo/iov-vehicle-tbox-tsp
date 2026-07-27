// src/main.cpp
#include "application.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "utils.h"

#include "mqtt_facade_stub.h"    // 后续替换为真正的 IPC 实现
#include "someip_facade_impl.h"  // 真正的 IPC 实现
#include "fota_handler.h"
#include "security_manager.h"
#include "tsp_http_client.h"
#include "log_adapter.h"
#include "log_types.h"

#include <iostream>
#include <fstream>

using tbox::tsp::LogAdapter;

#ifdef HAS_TBOX_PROV
#include "prov_client.h"
#endif

#include <csignal>
#include <unistd.h>

class MainApplication : public hwyz::Application {
protected:
    std::string getServiceName() const override {
        return "tsp";
    }

    // 配置根目录优先级：./config/ 优先于 /etc/tbox/
    std::vector<std::string> getConfigRoots() const override {
        return {"./config/", "/etc/tbox/"};
    }

    bool initialize() override {
        // framework-log 初始化（CR-002）
        {
            tbox::fw::log::LogConfig logConfig;
            logConfig.level = tbox::fw::log::LogLevel::kInfo;
            logConfig.console_config.enabled = true;

            // 尝试从配置读取日志级别
            if (getConfig()["common"] && getConfig()["common"]["log"] && getConfig()["common"]["log"]["level"]) {
                std::string levelStr = getConfig()["common"]["log"]["level"].as<std::string>("INFO");
                logConfig.level = tbox::fw::log::logLevelFromString(levelStr);
            }

            auto logResult = tbox::tsp::LogAdapter::init("tsp", logConfig);
            if (logResult.error != tbox::fw::log::LogError::kOk) {
                // 严格模式失败，非严格模式继续（降级到 console + INFO）
                spdlog::warn("framework-log 初始化降级: {}", logResult.error_message);
            } else {
                // 覆盖 spdlog 默认 logger 为 "tsp"，使框架基类的 spdlog::info() 也使用 tsp logger
                // 注意：framework-log 和 spdlog 是两套独立系统，这里需要同步两者
                auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
                console_sink->set_level(spdlog::level::debug);
                auto tsp_logger = std::make_shared<spdlog::logger>("tsp", console_sink);
                tsp_logger->set_level(spdlog::level::debug);
                spdlog::set_default_logger(tsp_logger);
            }
        }

        // 重定向 stdout/stderr 以捕获外部库（如 Application 基类、ProvClient）的输出
        // 注意：这是一个临时方案，长期应由框架团队修复
        redirect_stdio_to_log();

        // SecurityManager 保留（证书/密钥管理属于 SEC 依赖）
        if (!SecurityManager::get_instance().load_config(getConfig())) {
            LogAdapter::security().error("tsp.security.config_failed", "安全管理器配置加载失败");
            return false;
        }

        // 创建 Facade
        mqtt_facade_ = std::make_shared<tbox::tsp::MqttFacadeStub>();
        someip_facade_ = std::make_shared<tbox::tsp::SomeipFacadeImpl>();

        // 初始化 Facade
        if (!mqtt_facade_->initialize()) {
            LogAdapter::mqtt_client().error("tsp.mqtt.init_failed", "MQTT Facade 初始化失败");
            return false;
        }
        if (!someip_facade_->initialize()) {
            LogAdapter::someip_bridge().error("tsp.someip.init_failed", "SOMEIP Facade 初始化失败");
            return false;
        }

        // 获取设备序列号（device_sn）
        // 优先级：TBOX-PROV 服务 > 配置文件 > 全局状态
        std::string device_sn;
        
#ifdef HAS_TBOX_PROV
        // 尝试从 TBOX-PROV 服务获取设备序列号
        try {
            tbox::prov::ProvClient prov_client("/tmp/tbox-prov.sock");
            if (prov_client.connect()) {
                auto binding = prov_client.read_binding();
                if (!binding.ecu_uid.empty()) {
                    device_sn = binding.ecu_uid;
                    LogAdapter::application().info("tsp.prov.sn_obtained", "从 TBOX-PROV 获取设备序列号", {
                        {"device_sn", tbox::fw::log::FieldValue::makeString(device_sn),
                                      tbox::fw::log::Sensitivity::Identifier}
                    });
                } else {
                    LogAdapter::application().warn("tsp.prov.empty_uid", "TBOX-PROV 返回空的 ECU UID");
                }
                prov_client.disconnect();
            } else {
                LogAdapter::application().warn("tsp.prov.connect_failed", "无法连接到 TBOX-PROV 服务");
            }
        } catch (const std::exception& e) {
            LogAdapter::application().error("tsp.prov.exception", "从 TBOX-PROV 获取设备序列号异常", {
                {"error", tbox::fw::log::FieldValue::makeString(e.what())}
            });
        }
#endif
        
        // 如果从 TBOX-PROV 获取失败，尝试从配置文件读取
        if (device_sn.empty() && getConfig()["tsp"]["device-sn"]) {
            device_sn = getConfig()["tsp"]["device-sn"].as<std::string>();
        }
        
        // 最后尝试从全局状态读取
        if (device_sn.empty()) {
            device_sn = hwyz::Utils::global_read_string(hwyz::global_key_t::TBOX_SN);
        }
        
        if (device_sn.empty()) {
            LogAdapter::application().error("tsp.device_sn.missing", "device_sn 未配置");
            return false;
        }

        // 创建并初始化 FOTA 业务处理器
        fota_handler_ = std::make_unique<tbox::tsp::FotaHandler>(mqtt_facade_, someip_facade_);
        if (!fota_handler_->initialize(device_sn)) {
            LogAdapter::fota().error("tsp.fota.init_failed", "FOTA 处理器初始化失败");
            return false;
        }

        // TspHttpClient 保留用于 SEC（证书/密钥申请）
        if (!TspHttpClient::get_instance().load_config(getConfig())) {
            LogAdapter::http_client().warn("tsp.http.config_failed", "TSP HTTP 客户端配置加载失败（非致命）");
        }

        return true;
    }

    void cleanup() override {
        if (fota_handler_) fota_handler_->stop();
        if (mqtt_facade_) mqtt_facade_->stop();
        if (someip_facade_) someip_facade_->stop();
    }

    int execute() override {
        // 证书/密钥检查（SEC 依赖）
        if (!SecurityManager::get_instance().check_certification()) {
            LogAdapter::security().error("tsp.cert.check_failed", "证书检查失败");
            return -1;
        }
        if (!SecurityManager::get_instance().check_communication_secret_key()) {
            LogAdapter::security().error("tsp.comm_sk.check_failed", "通讯密钥检查失败");
            return -1;
        }

        // 启动 Facade
        if (!mqtt_facade_->start()) {
            LogAdapter::mqtt_client().error("tsp.mqtt.start_failed", "MQTT Facade 启动失败");
            return -1;
        }
        if (!someip_facade_->start()) {
            LogAdapter::someip_bridge().error("tsp.someip.start_failed", "SOMEIP Facade 启动失败");
            return -1;
        }

        // 启动 FOTA 业务处理
        if (!fota_handler_->start()) {
            LogAdapter::fota().error("tsp.fota.start_failed", "FOTA 处理器启动失败");
            return -1;
        }

        LogAdapter::application().info("tsp.application.started", "TBOX-TSP 服务启动完成");
        return 0;
    }

private:
    std::shared_ptr<tbox::tsp::MqttFacade> mqtt_facade_;
    std::shared_ptr<tbox::tsp::SomeipFacade> someip_facade_;
    std::unique_ptr<tbox::tsp::FotaHandler> fota_handler_;

    // 重定向 stdout/stderr 到日志系统
    void redirect_stdio_to_log() {
        // 保存原始的 cout/cerr 缓冲区
        static std::streambuf* orig_cout = std::cout.rdbuf();
        static std::streambuf* orig_cerr = std::cerr.rdbuf();

        // 创建自定义缓冲区，将输出重定向到日志
        class LogBuf : public std::streambuf {
        public:
            LogBuf(std::streambuf* orig, bool is_err) : orig_(orig), is_err_(is_err) {}
        protected:
            int overflow(int c) override {
                if (c == '\n') {
                    flush_line();
                } else {
                    line_ += static_cast<char>(c);
                }
                return c;
            }
            int sync() override {
                flush_line();
                return 0;
            }
        private:
            void flush_line() {
                if (!line_.empty()) {
                    if (is_err_) {
                        LogAdapter::application().error("tsp.external.stderr", "外部库输出", {
                            {"message", tbox::fw::log::FieldValue::makeString(line_)}
                        });
                    } else {
                        LogAdapter::application().info("tsp.external.stdout", "外部库输出", {
                            {"message", tbox::fw::log::FieldValue::makeString(line_)}
                        });
                    }
                    line_.clear();
                }
            }
            std::streambuf* orig_;
            bool is_err_;
            std::string line_;
        };

        static LogBuf cout_log_buf(orig_cout, false);
        static LogBuf cerr_log_buf(orig_cerr, true);

        std::cout.rdbuf(&cout_log_buf);
        std::cerr.rdbuf(&cerr_log_buf);
    }
};

// 自定义信号处理函数，避免死循环
static void custom_signal_handler(int signal) {
    // 只处理一次，避免递归
    static std::atomic<bool> handling{false};
    if (handling.exchange(true)) {
        // 已经在处理中，直接退出
        _exit(1);
    }
    
    // 只处理 SIGSEGV，其他信号交给默认处理
    if (signal == SIGSEGV) {
        // 不打印任何日志，直接退出
        _exit(1);
    }
    
    // 其他信号，设置退出标志
    // 注意：这里不能访问 Application 实例，因为是静态函数
    // 所以直接退出
    _exit(0);
}

extern "C" int main(int argc, char* argv[]) {
    // 设置自定义信号处理函数，覆盖 Application 类的设置
    struct sigaction sa{};
    sa.sa_handler = custom_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // 只处理 SIGSEGV
    sigaction(SIGSEGV, &sa, nullptr);
    
    try {
        MainApplication app;
        return app.run(argc, argv);
    } catch (const std::exception& e) {
        fprintf(stderr, "Application terminated with exception: %s\n", e.what());
        return -1;
    } catch (...) {
        fprintf(stderr, "Application terminated with unknown exception\n");
        return -1;
    }
}
