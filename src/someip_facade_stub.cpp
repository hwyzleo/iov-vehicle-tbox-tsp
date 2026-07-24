// src/someip_facade_stub.cpp
#include "someip_facade_stub.h"
#include "spdlog/spdlog.h"

namespace tbox {
namespace tsp {

SomeipFacadeStub::SomeipFacadeStub() = default;
SomeipFacadeStub::~SomeipFacadeStub() = default;

bool SomeipFacadeStub::initialize() {
    spdlog::info("[SomeipFacadeStub] 初始化（Stub 模式）");
    initialized_ = true;
    connected_ = true;  // Stub 假设始终连接
    return true;
}

bool SomeipFacadeStub::start() {
    if (!initialized_) {
        spdlog::error("[SomeipFacadeStub] 未初始化");
        return false;
    }
    spdlog::info("[SomeipFacadeStub] 启动（Stub 模式）");
    started_ = true;
    return true;
}

void SomeipFacadeStub::stop() {
    spdlog::info("[SomeipFacadeStub] 停止");
    started_ = false;
    connected_ = false;
}

void SomeipFacadeStub::on_report_software_inventory(
    std::function<void(const std::vector<uint8_t>&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("[SomeipFacadeStub] 注册上行回调");
    inventory_callback_ = std::move(callback);
}

bool SomeipFacadeStub::push_fota_command(const std::vector<uint8_t>& payload) {
    if (!connected_) {
        spdlog::warn("[SomeipFacadeStub] 未连接，推送失败");
        return false;
    }
    spdlog::info("[SomeipFacadeStub] push_fota_command: size={}", payload.size());
    return true;
}

bool SomeipFacadeStub::is_connected() const {
    return connected_;
}

void SomeipFacadeStub::simulate_report_software_inventory(
    const std::vector<uint8_t>& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (inventory_callback_) {
        spdlog::info("[SomeipFacadeStub] 模拟上行 snapshot: size={}", snapshot.size());
        inventory_callback_(snapshot);
    } else {
        spdlog::warn("[SomeipFacadeStub] 无上行回调注册");
    }
}

} // namespace tsp
} // namespace tbox
