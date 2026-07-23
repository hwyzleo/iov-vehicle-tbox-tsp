// include/someip_facade_stub.h
#pragma once

#include "someip_facade.h"
#include <mutex>

namespace tbox {
namespace tsp {

// SomeipFacade 的 Stub 实现
// 开发阶段使用，通过日志模拟 IPC 调用
class SomeipFacadeStub : public SomeipFacade {
public:
    SomeipFacadeStub();
    ~SomeipFacadeStub() override;

    bool initialize() override;
    bool start() override;
    void stop() override;

    void on_report_software_inventory(
        std::function<void(const std::vector<uint8_t>& snapshot)> callback) override;

    bool push_fota_command(const std::vector<uint8_t>& payload) override;

    bool is_connected() const override;

    // 测试辅助：模拟上行 snapshot 调用
    void simulate_report_software_inventory(const std::vector<uint8_t>& snapshot);

private:
    bool initialized_ = false;
    bool started_ = false;
    bool connected_ = false;

    std::function<void(const std::vector<uint8_t>&)> inventory_callback_;
    mutable std::mutex mutex_;
};

} // namespace tsp
} // namespace tbox
