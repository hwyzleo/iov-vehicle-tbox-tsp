// 注册状态机实现 (CR-004 §9, §11.4)
#include "registration_state.h"

#include <chrono>

namespace tbox {
namespace tsp {

uint64_t RegistrationStateHolder::now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

RegistrationStatus RegistrationStateHolder::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_;
}

RegistrationState RegistrationStateHolder::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_.state;
}

void RegistrationStateHolder::transition_to(RegistrationState s) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.state = s;
    status_.updated_at_ms = now_ms();
}

void RegistrationStateHolder::set_generation(uint64_t generation,
                                             const std::string& digest_hash,
                                             uint32_t mandatory_count,
                                             uint32_t item_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.generation = generation;
    status_.content_digest_hash = digest_hash;
    status_.mandatory_count = mandatory_count;
    status_.item_count = item_count;
    status_.updated_at_ms = now_ms();
}

void RegistrationStateHolder::set_result(SnapshotStatus result,
                                         const std::string& last_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.last_result = result;
    status_.last_error = last_error;
    status_.updated_at_ms = now_ms();
}

void RegistrationStateHolder::increment_retry() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++status_.retry_count;
    status_.updated_at_ms = now_ms();
}

void RegistrationStateHolder::reset_retry() {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.retry_count = 0;
    status_.updated_at_ms = now_ms();
}

void RegistrationStateHolder::touch() {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.updated_at_ms = now_ms();
}

} // namespace tsp
} // namespace tbox
