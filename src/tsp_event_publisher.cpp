// TBOX-TSP 下行事件推送器实现 (CR-003 §5, §6)

#include "tsp_event_publisher.h"
#include "tsp_ipc_protocol.h"
#include "log_adapter.h"

#include "utils.h"
#include <nlohmann/json.hpp>

namespace tbox {
namespace tsp {

namespace {

std::string b64_encode(const std::vector<uint8_t>& data) {
    return ::hwyz::Utils::base64_encode(
        std::string(reinterpret_cast<const char*>(data.data()), data.size()));
}

std::string encode_fota_command(const FotaCommand& cmd) {
    nlohmann::json j;
    j[ipc::field::COMMAND_ID]     = cmd.command_id;
    j[ipc::field::DELIVERY_ID]    = cmd.delivery_id;
    j[ipc::field::SCHEMA_VERSION] = cmd.schema_version;
    j[ipc::field::CONTENT_TYPE]   = cmd.content_type;
    j[ipc::field::PAYLOAD_B64]    = b64_encode(cmd.payload);
    if (!cmd.trace_id.empty())   j[ipc::field::TRACE_ID]   = cmd.trace_id;
    if (!cmd.request_id.empty()) j[ipc::field::REQUEST_ID] = cmd.request_id;
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

bool TspEventPublisher::publish_fota_command(const FotaCommand& cmd) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= queue_capacity_) {
            // 队列满：按策略处理
            switch (policy_) {
                case SlowSubscriberPolicy::kReject:
                    LogAdapter::relay().warn(
                        "tsp.fota.downlink.queue_rejected",
                        "下行队列满，拒绝入队",
                        {tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_))),
                         tbox::fw::log::Field("queue_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(queue_.size())))}
                    );
                    return false;
                case SlowSubscriberPolicy::kDrop:
                case SlowSubscriberPolicy::kDisconnect:
                    // 丢弃新命令
                    LogAdapter::relay().warn(
                        "tsp.fota.downlink.queue_dropped",
                        "下行队列满，丢弃新命令",
                        {tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_))),
                         tbox::fw::log::Field("queue_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(queue_.size())))}
                    );
                    return true;  // 不阻塞调用方，视为已接收但丢弃
            }
        }
        queue_.push_back(cmd);
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
        "tsp.fota.downlink.publisher_started",
        "下行事件推送 worker 启动",
        {tbox::fw::log::Field("queue_capacity", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(queue_capacity_))),
         tbox::fw::log::Field("policy", tbox::fw::log::FieldValue::makeString(policy_str(policy_)))}
    );

    while (true) {
        FotaCommand cmd;
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
            cmd = std::move(queue_.front());
            queue_.pop_front();
        }

        const uint32_t event_type = static_cast<uint32_t>(ipc::EventType::FOTA_COMMAND);

        // 无订阅者：分类错误，不静默丢弃 (CR §4.3)
        if (has_subscriber_fn_ && !has_subscriber_fn_(event_type)) {
            LogAdapter::relay().warn(
                "tsp.fota.downlink.no_subscriber",
                "下行无订阅者",
                {tbox::fw::log::Field("command_id", tbox::fw::log::FieldValue::makeString(cmd.command_id))}
            );
            continue;
        }

        std::string payload_json = encode_fota_command(cmd);

        bool sent = false;
        if (push_fn_) {
            sent = push_fn_(event_type, payload_json);
        }

        if (!sent) {
            LogAdapter::relay().warn(
                "tsp.fota.downlink.push_failed",
                "下行事件推送失败",
                {tbox::fw::log::Field("command_id", tbox::fw::log::FieldValue::makeString(cmd.command_id))}
            );
        }
    }

    LogAdapter::relay().info(
        "tsp.fota.downlink.publisher_stopped",
        "下行事件推送 worker 停止"
    );
}

} // namespace tsp
} // namespace tbox
