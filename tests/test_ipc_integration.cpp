// tests/test_ipc_integration.cpp
#include <gtest/gtest.h>
#include "someip_facade_impl.h"
#include "ipc_protocol.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

class IpcIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        facade_ = std::make_unique<tbox::tsp::SomeipFacadeImpl>();
        ASSERT_TRUE(facade_->initialize());
        ASSERT_TRUE(facade_->start());

        // 等待服务器启动
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        if (facade_) {
            facade_->stop();
        }
    }

    std::unique_ptr<tbox::tsp::SomeipFacadeImpl> facade_;

    // 辅助函数：创建客户端连接
    int create_client() {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/tmp/tbox-tsp.sock", sizeof(addr.sun_path) - 1);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return -1;
        }

        return sock;
    }

    // 辅助函数：发送请求并接收响应
    std::string send_request(int sock, tbox::tsp::ipc::MethodId method, const std::string& params_json) {
        auto request_data = tbox::tsp::ipc::IpcSerializer::serialize_request(method, params_json);

        // 发送请求
        size_t total_sent = 0;
        while (total_sent < request_data.size()) {
            ssize_t bytes_sent = send(sock, request_data.data() + total_sent, request_data.size() - total_sent, 0);
            if (bytes_sent <= 0) {
                return "";
            }
            total_sent += bytes_sent;
        }

        // 接收响应头
        tbox::tsp::ipc::ResponseHeader header;
        memset(&header, 0, sizeof(header));
        size_t header_received = 0;
        while (header_received < sizeof(header)) {
            ssize_t bytes_read = recv(sock, reinterpret_cast<uint8_t*>(&header) + header_received, sizeof(header) - header_received, 0);
            if (bytes_read <= 0) {
                return "";
            }
            header_received += bytes_read;
        }

        // 接收响应数据
        std::vector<uint8_t> response_data(sizeof(header) + header.data_length);
        memcpy(response_data.data(), &header, sizeof(header));

        size_t data_received = 0;
        while (data_received < header.data_length) {
            ssize_t bytes_read = recv(sock, response_data.data() + sizeof(header) + data_received, header.data_length - data_received, 0);
            if (bytes_read <= 0) {
                return "";
            }
            data_received += bytes_read;
        }

        // 解析响应
        int32_t status_code;
        std::string response_json;
        if (!tbox::tsp::ipc::IpcSerializer::deserialize_response(response_data, status_code, response_json)) {
            return "";
        }

        return response_json;
    }
};

TEST_F(IpcIntegrationTest, SocketFileExists) {
    // 验证 socket 文件存在
    ASSERT_EQ(access("/tmp/tbox-tsp.sock", F_OK), 0);
}

TEST_F(IpcIntegrationTest, ClientCanConnect) {
    // 验证客户端可以连接
    int sock = create_client();
    ASSERT_GT(sock, 0);
    close(sock);
}

TEST_F(IpcIntegrationTest, GetNetStatus) {
    int sock = create_client();
    ASSERT_GT(sock, 0);

    // 发送 GET_NET_STATUS 请求
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::GET_NET_STATUS, "{}");
    ASSERT_FALSE(response.empty());

    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.contains("is_connected"));
    ASSERT_TRUE(j.contains("signal_strength"));
    ASSERT_TRUE(j.contains("network_type"));
    ASSERT_TRUE(j.contains("operator"));

    close(sock);
}

TEST_F(IpcIntegrationTest, ReportSoftwareInventory) {
    int sock = create_client();
    ASSERT_GT(sock, 0);

    // 注册上行回调
    bool callback_called = false;
    facade_->on_report_software_inventory([&callback_called](const std::vector<uint8_t>& snapshot) {
        callback_called = true;
    });

    // 发送 REPORT_SOFTWARE_INVENTORY 请求
    std::string params = "{\"snapshot_base64\":\"dGVzdA==\"}";
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::REPORT_SOFTWARE_INVENTORY, params);
    ASSERT_FALSE(response.empty());

    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.value("success", false));

    // 验证回调被调用
    ASSERT_TRUE(callback_called);

    close(sock);
}

TEST_F(IpcIntegrationTest, SubscribeAndPushEvent) {
    int sock = create_client();
    ASSERT_GT(sock, 0);

    // 订阅 FOTA_COMMAND 事件
    std::string response = send_request(sock, tbox::tsp::ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS, "{}");
    ASSERT_FALSE(response.empty());

    // 解析响应
    nlohmann::json j = nlohmann::json::parse(response);
    ASSERT_TRUE(j.value("success", false));

    // 推送事件
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    facade_->push_fota_command(payload);

    // 接收事件
    tbox::tsp::ipc::EventHeader event_header;
    memset(&event_header, 0, sizeof(event_header));
    size_t header_received = 0;
    while (header_received < sizeof(event_header)) {
        ssize_t bytes_read = recv(sock, reinterpret_cast<uint8_t*>(&event_header) + header_received, sizeof(event_header) - header_received, 0);
        if (bytes_read <= 0) {
            break;
        }
        header_received += bytes_read;
    }

    if (header_received == sizeof(event_header)) {
        ASSERT_EQ(event_header.event_type, static_cast<uint32_t>(tbox::tsp::ipc::EventType::FOTA_COMMAND));
        ASSERT_GT(event_header.payload_length, 0);
    }

    close(sock);
}

TEST_F(IpcIntegrationTest, ClientDisconnectCleanup) {
    int sock = create_client();
    ASSERT_GT(sock, 0);

    // 订阅事件
    send_request(sock, tbox::tsp::ipc::MethodId::SUBSCRIBE_FOTA_COMMANDS, "{}");

    // 断开连接
    close(sock);

    // 等待清理
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 验证服务器仍在运行
    ASSERT_TRUE(facade_->is_connected());
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
