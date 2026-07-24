// include/someip_facade_impl.h
#pragma once

#include "someip_facade.h"
#include "ipc_server.h"
#include "net_status_provider.h"
#include <memory>
#include <mutex>

namespace tbox {
namespace tsp {

class SomeipFacadeImpl : public SomeipFacade {
public:
    SomeipFacadeImpl();
    ~SomeipFacadeImpl() override;

    // SomeipFacade 接口实现
    bool initialize() override;
    bool start() override;
    void stop() override;
    bool is_connected() const override;

    void on_report_software_inventory(
        std::function<void(const std::vector<uint8_t>&)> callback) override;

    bool push_fota_command(const std::vector<uint8_t>& payload) override;

private:
    std::unique_ptr<ipc::IpcServer> server_;
    std::function<void(const std::vector<uint8_t>&)> inventory_callback_;
    mutable std::mutex mutex_;

    // 网络状态提供者
    std::unique_ptr<NetStatusProvider> net_status_provider_;

    // 请求处理回调
    std::string handle_request(ipc::MethodId method, const std::string& params_json, int client_fd);

    // 客户端断开回调
    void handle_client_disconnect(int client_fd);

    // 具体方法处理
    std::string handle_get_net_status(const std::string& params_json);
    std::string handle_report_software_inventory(const std::string& params_json, int client_fd);
    std::string handle_subscribe(ipc::EventType type, const std::string& params_json, int client_fd);
};

} // namespace tsp
} // namespace tbox
