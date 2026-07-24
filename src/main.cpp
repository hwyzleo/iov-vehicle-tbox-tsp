// src/main.cpp
#include "application.h"
#include "spdlog/spdlog.h"
#include "utils.h"

#include "mqtt_facade_stub.h"    // 后续替换为真正的 IPC 实现
#include "someip_facade_impl.h"  // 真正的 IPC 实现
#include "fota_handler.h"
#include "security_manager.h"
#include "tsp_http_client.h"

#ifdef HAS_FRAMEWORK_LOG
#include "log_adapter.h"
#include "log_types.h"
#endif

#ifdef HAS_TBOX_PROV
#include "prov_client.h"
#endif

#include <csignal>
#include <unistd.h>

class MainApplication : public hwyz::Application {
protected:
    bool initialize() override {
        // framework-log 初始化（CR-002）
#ifdef HAS_FRAMEWORK_LOG
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
            }
        }
#endif

        // SecurityManager 保留（证书/密钥管理属于 SEC 依赖）
        if (!SecurityManager::get_instance().load_config(getConfig())) {
            spdlog::error("安全管理器配置加载失败");
            return false;
        }

        // 创建 Facade
        mqtt_facade_ = std::make_shared<tbox::tsp::MqttFacadeStub>();
        someip_facade_ = std::make_shared<tbox::tsp::SomeipFacadeImpl>();

        // 初始化 Facade
        if (!mqtt_facade_->initialize()) {
            spdlog::error("MQTT Facade 初始化失败");
            return false;
        }
        if (!someip_facade_->initialize()) {
            spdlog::error("SOMEIP Facade 初始化失败");
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
                    spdlog::info("从 TBOX-PROV 获取设备序列号: {}", device_sn);
                } else {
                    spdlog::warn("TBOX-PROV 返回空的 ECU UID");
                }
                prov_client.disconnect();
            } else {
                spdlog::warn("无法连接到 TBOX-PROV 服务");
            }
        } catch (const std::exception& e) {
            spdlog::error("从 TBOX-PROV 获取设备序列号异常: {}", e.what());
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
            spdlog::error("device_sn 未配置");
            return false;
        }

        // 创建并初始化 FOTA 业务处理器
        fota_handler_ = std::make_unique<tbox::tsp::FotaHandler>(mqtt_facade_, someip_facade_);
        if (!fota_handler_->initialize(device_sn)) {
            spdlog::error("FOTA 处理器初始化失败");
            return false;
        }

        // TspHttpClient 保留用于 SEC（证书/密钥申请）
        if (!TspHttpClient::get_instance().load_config(getConfig())) {
            spdlog::warn("TSP HTTP 客户端配置加载失败（非致命）");
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
            spdlog::error("证书检查失败");
            return -1;
        }
        if (!SecurityManager::get_instance().check_communication_secret_key()) {
            spdlog::error("通讯密钥检查失败");
            return -1;
        }

        // 启动 Facade
        if (!mqtt_facade_->start()) {
            spdlog::error("MQTT Facade 启动失败");
            return -1;
        }
        if (!someip_facade_->start()) {
            spdlog::error("SOMEIP Facade 启动失败");
            return -1;
        }

        // 启动 FOTA 业务处理
        if (!fota_handler_->start()) {
            spdlog::error("FOTA 处理器启动失败");
            return -1;
        }

        spdlog::info("TBOX-TSP 服务启动完成");
        return 0;
    }

private:
    std::shared_ptr<tbox::tsp::MqttFacade> mqtt_facade_;
    std::shared_ptr<tbox::tsp::SomeipFacade> someip_facade_;
    std::unique_ptr<tbox::tsp::FotaHandler> fota_handler_;
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
