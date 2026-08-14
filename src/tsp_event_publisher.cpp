// TBOX-TSP 下行事件推送器实现 (CR-003 §5, §6; CR-009 §EVENT 下行)

#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "log_adapter.h"

#include "utils.h"
#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

namespace {

std::string b64_encode(const std::vector<std::byte>& data) {
    std::string raw;
    raw.reserve(data.size());
    for (auto b : data) {
        raw.push_back(static_cast<char>(static_cast<uint8_t>(b)));
    }
    return ::hwyz::Utils::base64_encode(raw);
}

std::string encode_vehicle_message(const VehicleMessageEvent& ev) {
    // CR-009: wire 只承载单一 envelope_base64；service 仅作为 EVENT 推送分类键。
    nlohmann::json j;
    j[ipc::field::SERVICE]        = ev.service;
    j[ipc::field::ENVELOPE_B64]   = b64_encode(ev.envelope_bytes);
    if (!ev.trace_id.empty())   j[ipc::field::TRACE_ID]   = ev.trace_id;
    if (!ev.request_id.empty()) j[ipc::field::REQUEST_ID] = ev.request_id;
    return j.dump();
}

const char* policy_str(SlowSubscriberPolicy p) {
    switch (p) {
        case SlowSubscriberPolicy::kDisconnect: return "disconnect";
        case SlowSubscriberPolicy::kDrop:       return "drop";
        case SlowSubscriberPolicy::kReject:     return "reject";
        default: return "?";
    }
}

} // anonymous namespace

TspEventPublisher::TspEventPublisher(uint32_t downlink_queue_size,
                                     SlowSubscriberPolicy policy)
    : queue_capacity_(downlink_queue_size == 0 ? 256 : downlink_queue_size)
    , policy_(policy) {
}

TspEventPublisher::~TspEventPublisher() {
    stop();
}

void TspEventPublisher::set_push_fn(PushFn fn) {
    push_fn_ = std::move(fn);
}

void TspEventPublisher::set_has_subscriber_fn(HasSubscriberFn fn) {
    has_subscriber_fn_ = std::move(fn);
}

bool TspEventPublisher::start() {
    if (running_.exchange(true)) {
        return true;  // already started
    }
    worker_ = std::thread([this] { worker_loop(); });
    return true;
}

void TspEventPublisher::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool TspEventPublisher::publish_vehicle_message(
    const std::string& service,
    const std::vector<std::byte>& envelope_bytes,
    const std::string& trace_id,
    const std::string& request_id) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t svc_count = service_count_[service];
        if (svc_count >= queue_capacity_) {
            // 该 service 队列满：按策略处理
            switch (policy_) {
                case SlowSubscriberPolicy::kReject:
                    LogAdapter::relay().warn(
                        "tsp.vehicle_message.downlink.queue_rejected",
                        "下行队列满，拒绝入队",
                        {tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_))),
                         tbox::fw::log::Field("service", tbox::fw::log::FieldValue::makeString(service)),
                         tbox::fw::log::Field("queue_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(svc_count)))}
                    );
                    return false;
                case SlowSubscriberPolicy::kDrop:
                case SlowSubscriberPolicy::kDisconnect:
                    // 丢弃新事件
                    LogAdapter::relay().warn(
                        "tsp.vehicle_message.downlink.queue_dropped",
                        "下行队列满，丢弃新事件",
                        {tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_))),
                         tbox::fw::log::Field("service", tbox::fw::log::FieldValue::makeString(service)),
                         tbox::fw::log::Field("queue_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(svc_count)))}
                    );
                    return true;  // 不阻塞调用方，视为已接收但丢弃
            }
        }
        VehicleMessageEvent ev;
        ev.service = service;
        ev.envelope_bytes = envelope_bytes;
        ev.trace_id = trace_id;
        ev.request_id = request_id;
        queue_.push_back(std::move(ev));
        service_count_[service] = svc_count + 1;
    }
    cv_.notify_one();
    return true;
}

size_t TspEventPublisher::queue_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

void TspEventPublisher::worker_loop() {
    LogAdapter::relay().info(
        "tsp.vehicle_message.downlink.publisher_started",
        "下行事件推送 worker 启动",
        {tbox::fw::log::Field("per_service_queue_capacity", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(queue_capacity_))),
         tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_)))}
    );

    while (true) {
        VehicleMessageEvent ev;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !queue_.empty() || !running_.load(); });
            // 停机时排空剩余队列（flush），仅当队列空且已停机才退出
            if (queue_.empty() && !running_.load()) {
                break;
            }
            if (queue_.empty()) {
                continue;
            }
            ev = std::move(queue_.front());
            queue_.pop_front();
            auto it = service_count_.find(ev.service);
            if (it != service_count_.end() && it->second > 0) {
                --it->second;
            }
        }

        const uint32_t event_type = static_cast<uint32_t>(ipc::EventType::VEHICLE_MESSAGE);

        // 无订阅者：分类错误，不静默丢弃 (CR §4.3)
        if (has_subscriber_fn_ && !has_subscriber_fn_(event_type)) {
            LogAdapter::relay().warn(
                "tsp.vehicle_message.downlink.no_subscriber",
                "下行无订阅者",
                {tbox::fw::log::Field("service", tbox::fw::log::FieldValue::makeString(ev.service))}
            );
            continue;
        }

        std::string payload_json = encode_vehicle_message(ev);

        bool sent = false;
        if (push_fn_) {
            sent = push_fn_(event_type, payload_json);
        }

        if (!sent) {
            LogAdapter::relay().warn(
                "tsp.vehicle_message.downlink.push_failed",
                "下行事件推送失败",
                {tbox::fw::log::Field("service", tbox::fw::log::FieldValue::makeString(ev.service))}
            );
        }
    }

    LogAdapter::relay().info(
        "tsp.vehicle_message.downlink.publisher_stopped",
        "下行事件推送 worker 停止"
    );
}

} // namespace tsp
} // namespace tbox
