// tests/mocks.h -- 测试用 mock 实现
#pragma once

#include "mqtt_facade.h"
#include "fota_relay_interface.h"
#include "net_status_provider.h"
#include "tbox/tsp/types.h"
#include <vector>
#include <mutex>
#include <atomic>

namespace tbox {
namespace tsp {
namespace test {

// ============================================================
// MockMqttFacade -- 记录 publish/registerRoute/subscribe 调用，
// 可配置 publish 返回结果；持有 subscribe 回调以便测试投递下行。
// ============================================================
class MockMqttFacade : public MqttFacade {
public:
    struct PublishCall {
        std::string msg_id;
        std::string topic;
        std::vector<uint8_t> payload;
        int qos = 0;
        std::string content_type;
        std::string trace_id;
        std::string request_id;
    };

    // 配置 publish 返回结果
    MqttPublishResult publish_result{true, PublishOutcome::ACCEPTED};

    bool initialize() override { return true; }
    bool start() override { return true; }
    void stop() override {}

    bool registerRoute(const std::string&, const std::string&, const std::string&, int) override {
        return true;
    }

    MqttPublishResult publish(const std::string& msg_id,
                              const std::string& topic,
                              const std::vector<uint8_t>& payload,
                              int qos,
                              const std::string& content_type = "application/x-protobuf",
                              const std::string& trace_id = "",
                              const std::string& request_id = "") override {
        std::lock_guard<std::mutex> lock(mutex_);
        publish_calls_.push_back({msg_id, topic, payload, qos, content_type, trace_id, request_id});
        return publish_result;
    }

    bool subscribe(const std::string& topic, int /*qos*/, MessageCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        sub_callback_ = std::move(callback);
        return true;
    }

    bool is_connected() const override { return true; }

    // 测试辅助：模拟收到下行消息
    void deliver_downlink(const std::string& topic, const std::vector<uint8_t>& payload) {
        MessageCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = sub_callback_;
        }
        if (cb) cb(topic, payload);
    }

    std::vector<PublishCall> publish_calls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return publish_calls_;
    }

    mutable std::mutex mutex_;
    std::vector<PublishCall> publish_calls_;
    MessageCallback sub_callback_;
};

// ============================================================
// MockFotaRelay -- 实现 FotaRelayInterface，记录 handle_uplink 调用
// ============================================================
class MockFotaRelay : public FotaRelayInterface {
public:
    struct UplinkCall {
        FotaSnapshot snapshot;
    };

    ReportResult uplink_result{true, PublishOutcome::ACCEPTED, 0, ""};
    RelayStatus status_result{};
    bool uplink_called = false;
    int uplink_count = 0;
    std::vector<UplinkCall> uplink_calls;

    ReportResult handle_uplink(const FotaSnapshot& snapshot) override {
        uplink_called = true;
        uplink_count++;
        uplink_calls.push_back({snapshot});
        ReportResult r = uplink_result;
        r.msg_id = snapshot.msg_id;
        return r;
    }

    RelayStatus get_relay_status(const std::string& msg_id) override {
        RelayStatus s = status_result;
        s.msg_id = msg_id;
        return s;
    }
};

// ============================================================
// MockNetStatusProvider -- 使用 net_status_provider.h 中的 tbox::tsp::MockNetStatusProvider
// ============================================================

} // namespace test
} // namespace tsp
} // namespace tbox
