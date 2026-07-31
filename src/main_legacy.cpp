// TBOX-TSP-DSN-CR-005 §9.1: 回滚验证用的旧式生命周期入口。
// 当 TSP_USE_FRAMEWORK_APPLICATION=OFF 时编译。保留 CR-005 前的 MainApplication：
// 自行初始化 framework-log、覆盖 spdlog 默认 logger、自装 SIGSEGV handler、
// 在 execute() 中启动各组件。验收后删除本文件与开关（CR-005 阶段 3）。
//
// 注意：本入口保留重复日志初始化与私有信号处理，仅用于迁移期回滚对照，
// 不应与新 TspApplication 路径在同一二进制中混装。

#include "application.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "utils.h"

#include "mqtt_client_adapter.h"   // tbox::mqtt::Client 适配 (CR-003 §1)
#include "fota_handler.h"          // FotaRelay 业务 (CR-003 §2)
#include "subscription_catalog.h"   // 业务订阅目录 (CR-004 §11.1)
#include "subscription_store.h"     // generation 持久化 (CR-004 §11.2)
#include "subscription_registrar.h" // 订阅快照注册器 (CR-004 §11.3)
#include "tsp_framework_server.h"  // framework-ipc Server 接线 (CR-003 §1)
#include "tsp_ipc_protocol.h"      // DEFAULT_SOCKET_PATH
#include "net_status_provider.h"
#include "log_adapter.h"
#include "log_types.h"

#include <iostream>
#include <fstream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

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

            auto snap = getConfigSnapshot();
            if (snap) {
                std::string levelStr = snap->getString("common.log.level", "INFO");
                logConfig.level = tbox::fw::log::logLevelFromString(levelStr);
            }

            auto logResult = tbox::tsp::LogAdapter::init("tsp", logConfig);
            if (logResult.error != tbox::fw::log::LogError::kOk) {
                spdlog::warn("framework-log 初始化降级: {}", logResult.error_message);
            } else {
                auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
                console_sink->set_level(spdlog::level::debug);
                auto tsp_logger = std::make_shared<spdlog::logger>("tsp", console_sink);
                tsp_logger->set_level(spdlog::level::debug);
                spdlog::set_default_logger(tsp_logger);
            }
        }

        redirect_stdio_to_log();

        auto snap = getConfigSnapshot();
        if (!snap) {
            LogAdapter::application().error("tsp.config.snapshot_failed", "配置快照获取失败");
            return false;
        }

        // 读取 IPC 配置 (CR-003 §8: common.ipc.* + tsp.ipc.*)
        ipc_config_.max_frame_bytes = static_cast<uint32_t>(
            snap->getInt("common.ipc.max_frame_bytes", 10485760));
        ipc_config_.receive_timeout_ms = static_cast<uint32_t>(
            snap->getInt("common.ipc.receive_timeout_ms", 60000));
        ipc_config_.connect_timeout_ms = static_cast<uint32_t>(
            snap->getInt("common.ipc.connect_timeout_ms", 3000));
        ipc_config_.listen_backlog = snap->getInt("common.ipc.listen_backlog", 5);
        ipc_config_.reconnect.initial_backoff_ms = static_cast<uint32_t>(
            snap->getInt("common.ipc.reconnect.initial_backoff_ms", 100));
        ipc_config_.reconnect.max_backoff_ms = static_cast<uint32_t>(
            snap->getInt("common.ipc.reconnect.max_backoff_ms", 5000));
        ipc_config_.reconnect.multiplier =
            snap->getDouble("common.ipc.reconnect.multiplier", 2.0);

        tsp_socket_path_ = snap->getString("tsp.ipc.socket_path",
            tbox::tsp::ipc::DEFAULT_SOCKET_PATH);
        downlink_queue_size_ = static_cast<uint32_t>(
            snap->getInt("tsp.ipc.downlink_queue_size", 256));
        slow_subscriber_policy_ = tbox::tsp::parse_slow_subscriber_policy(
            snap->getString("tsp.ipc.slow_subscriber_policy", "disconnect"));

        std::string mqtt_socket_path = snap->getString("tsp.mqtt.socket_path",
            "/tmp/tbox-mqtt.sock");

        // 获取设备序列号（device_sn）
        std::string device_sn;
#ifdef HAS_TBOX_PROV
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
        if (device_sn.empty()) {
            device_sn = snap->getString("tsp.device-sn", "");
        }
        if (device_sn.empty()) {
            device_sn = hwyz::Utils::global_read_string(hwyz::global_key_t::TBOX_SN);
        }
        if (device_sn.empty()) {
            LogAdapter::application().error("tsp.device_sn.missing", "device_sn 未配置");
            return false;
        }

        // 1. 构造 mqtt_client（CR-003 §1: TSP 对 MQTT 只使用 tbox::mqtt_client）
        mqtt_adapter_ = std::make_shared<tbox::tsp::MqttClientAdapter>(mqtt_socket_path);
        if (!mqtt_adapter_->initialize()) {
            LogAdapter::mqtt_client().error("tsp.mqtt.init_failed", "MQTT 客户端初始化失败");
            return false;
        }
        mqtt_adapter_->set_device_identity(device_sn);

        // CR-004 §6, §11.1: 加载业务订阅目录（SSOT）
        catalog_ = std::make_shared<tbox::tsp::SubscriptionCatalog>();
        std::string catalog_error;
        if (!catalog_->load_from_yaml(getConfig()["tsp"]["subscriptions"], catalog_error)) {
            LogAdapter::subscription().error(
                "tsp.subscription.catalog.invalid",
                "业务订阅目录加载失败: " + catalog_error);
            return false;
        }
        // CR-004 §3.1, §11.2: generation 持久化
        std::string store_root = snap->getString("common.store.root", "/var/tbox");
        subscription_store_ = std::make_shared<tbox::tsp::SubscriptionStore>(store_root);
        // CR-004 §11.3: 订阅快照注册器
        registrar_ = std::make_unique<tbox::tsp::MqttSubscriptionRegistrar>(
            mqtt_adapter_, catalog_, subscription_store_);

        // 2. 构造 FotaRelay（业务中继）
        fota_handler_ = std::make_unique<tbox::tsp::FotaHandler>(mqtt_adapter_);
        if (!fota_handler_->initialize(device_sn)) {
            LogAdapter::fota().error("tsp.fota.init_failed", "FOTA 处理器初始化失败");
            return false;
        }
        fota_handler_->set_catalog(catalog_);

        // 3. 构造 framework-ipc Server（CR-003 §1, §3）
        net_status_provider_ = tbox::tsp::NetStatusProviderFactory::create(
            tbox::tsp::NetStatusProviderFactory::ProviderType::MOCK);
        framework_server_ = std::make_unique<tbox::tsp::TspFrameworkServer>(
            tsp_socket_path_, ipc_config_,
            fota_handler_.get(),          // FotaRelayInterface
            net_status_provider_.get(),
            downlink_queue_size_, slow_subscriber_policy_);

        // 4. 接线：FotaRelay 下行经 EventPublisher 推送
        fota_handler_->set_event_publisher(framework_server_->event_publisher());

        return true;
    }

    void cleanup() override {
        // stop 顺序：停 IPC -> 停 FOTA -> 停订阅注册器 -> 停 MQTT (CR-003 §3, CR-004 §7)
        if (framework_server_) framework_server_->stop();
        if (fota_handler_) fota_handler_->stop();
        if (registrar_) registrar_->stop();
        if (mqtt_adapter_) mqtt_adapter_->stop();
    }

    int execute() override {
        // 启动 MQTT 客户端
        if (!mqtt_adapter_->start()) {
            LogAdapter::mqtt_client().error("tsp.mqtt.start_failed", "MQTT 客户端启动失败");
            return -1;
        }

        // CR-004 §6: 提交业务订阅快照（Mandatory 完成本地提交前不宣告云路由 ready）
        if (!registrar_->start()) {
            LogAdapter::subscription().error("tsp.subscription.start_failed", "订阅注册器启动失败");
            return -1;
        }
        if (!registrar_->is_registration_ready()) {
            LogAdapter::subscription().warn("tsp.subscription.not_ready",
                "Mandatory 快照未完成本地提交");
        }

        // 启动 FOTA 业务（订阅下行）
        if (!fota_handler_->start()) {
            LogAdapter::fota().error("tsp.fota.start_failed", "FOTA 处理器启动失败");
            return -1;
        }

        // 启动 framework-ipc Server
        if (!framework_server_->start()) {
            LogAdapter::ipc_server().error("tsp.ipc.start_failed", "IPC Server 启动失败");
            return -1;
        }

        LogAdapter::application().info("tsp.application.started", "TBOX-TSP 服务启动完成");
        return 0;
    }

private:
    std::shared_ptr<tbox::tsp::MqttClientAdapter> mqtt_adapter_;
    std::shared_ptr<tbox::tsp::SubscriptionCatalog> catalog_;
    std::shared_ptr<tbox::tsp::SubscriptionStore> subscription_store_;
    std::unique_ptr<tbox::tsp::MqttSubscriptionRegistrar> registrar_;
    std::unique_ptr<tbox::tsp::FotaHandler> fota_handler_;
    std::unique_ptr<tbox::tsp::TspFrameworkServer> framework_server_;
    std::unique_ptr<tbox::tsp::NetStatusProvider> net_status_provider_;

    ::tbox::fw::ipc::IpcConfig ipc_config_{};
    std::string tsp_socket_path_;
    uint32_t downlink_queue_size_ = 256;
    tbox::tsp::SlowSubscriberPolicy slow_subscriber_policy_ = tbox::tsp::SlowSubscriberPolicy::kDisconnect;

    // 重定向 stdout/stderr 到日志系统
    void redirect_stdio_to_log() {
        static std::streambuf* orig_cout = std::cout.rdbuf();
        static std::streambuf* orig_cerr = std::cerr.rdbuf();

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
    static std::atomic<bool> handling{false};
    if (handling.exchange(true)) {
        _exit(1);
    }
    if (signal == SIGSEGV) {
        _exit(1);
    }
    _exit(0);
}

extern "C" int main(int argc, char* argv[]) {
    struct sigaction sa{};
    sa.sa_handler = custom_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
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
