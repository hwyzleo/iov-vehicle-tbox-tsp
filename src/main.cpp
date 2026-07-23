// src/main.cpp
#include "application.h"
#include "spdlog/spdlog.h"
#include "utils.h"

#include "mqtt_facade_stub.h"    // 后续替换为真正的 IPC 实现
#include "someip_facade_stub.h"  // 后续替换为真正的 IPC 实现
#include "fota_handler.h"
#include "security_manager.h"
#include "tsp_http_client.h"

class MainApplication : public hwyz::Application {
protected:
    bool initialize() override {
        // SecurityManager 保留（证书/密钥管理属于 SEC 依赖）
        if (!SecurityManager::get_instance().load_config(getConfig())) {
            spdlog::error("安全管理器配置加载失败");
            return false;
        }

        // 创建 Facade（Stub 模式，后续替换为 IPC 实现）
        mqtt_facade_ = std::make_shared<tbox::tsp::MqttFacadeStub>();
        someip_facade_ = std::make_shared<tbox::tsp::SomeipFacadeStub>();

        // 初始化 Facade
        if (!mqtt_facade_->initialize()) {
            spdlog::error("MQTT Facade 初始化失败");
            return false;
        }
        if (!someip_facade_->initialize()) {
            spdlog::error("SOMEIP Facade 初始化失败");
            return false;
        }

        // 从配置获取 device_sn（或从全局状态读取）
        std::string device_sn;
        if (getConfig()["device-sn"]) {
            device_sn = getConfig()["device-sn"].as<std::string>();
        }
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

APPLICATION_ENTRY(MainApplication)
