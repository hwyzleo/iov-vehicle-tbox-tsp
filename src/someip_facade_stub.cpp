// src/someip_facade_stub.cpp
#include "someip_facade_stub.h"
#include "log_adapter.h"

namespace tbox {
namespace tsp {

SomeipFacadeStub::SomeipFacadeStub() = default;
SomeipFacadeStub::~SomeipFacadeStub() = default;

bool SomeipFacadeStub::initialize() {
    tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.init", "[SomeipFacadeStub] 初始化（Stub 模式）");
    initialized_ = true;
    connected_ = true;  // Stub 假设始终连接
    return true;
}

bool SomeipFacadeStub::start() {
    if (!initialized_) {
        tbox::tsp::LogAdapter::someip_bridge().error("tsp.someip.not_initialized", "[SomeipFacadeStub] 未初始化");
        return false;
    }
    tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.start", "[SomeipFacadeStub] 启动（Stub 模式）");
    started_ = true;
    return true;
}

void SomeipFacadeStub::stop() {
    tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.stop", "[SomeipFacadeStub] 停止");
    started_ = false;
    connected_ = false;
}

void SomeipFacadeStub::on_report_software_inventory(
    std::function<void(const std::vector<uint8_t>&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.register_callback", "[SomeipFacadeStub] 注册上行回调");
    inventory_callback_ = std::move(callback);
}

bool SomeipFacadeStub::push_fota_command(const std::vector<uint8_t>& payload) {
    if (!connected_) {
        tbox::tsp::LogAdapter::someip_bridge().warn("tsp.someip.push_not_connected", "[SomeipFacadeStub] 未连接，推送失败");
        return false;
    }
    tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.push_fota_command",
        std::string("[SomeipFacadeStub] push_fota_command: size=") + std::to_string(payload.size()));
    return true;
}

bool SomeipFacadeStub::is_connected() const {
    return connected_;
}

void SomeipFacadeStub::simulate_report_software_inventory(
    const std::vector<uint8_t>& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (inventory_callback_) {
        tbox::tsp::LogAdapter::someip_bridge().info("tsp.someip.simulate_snapshot",
            std::string("[SomeipFacadeStub] 模拟上行 snapshot: size=") + std::to_string(snapshot.size()));
        inventory_callback_(snapshot);
    } else {
        tbox::tsp::LogAdapter::someip_bridge().warn("tsp.someip.no_callback", "[SomeipFacadeStub] 无上行回调注册");
    }
}

} // namespace tsp
} // namespace tbox
