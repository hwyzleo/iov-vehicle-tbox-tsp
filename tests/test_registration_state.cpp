// CR-004 §12 单元测试：注册状态机
#include <gtest/gtest.h>
#include "registration_state.h"

using namespace tbox::tsp;

TEST(RegistrationStateTest, InitialState) {
    RegistrationStateHolder h;
    auto s = h.snapshot();
    EXPECT_EQ(s.state, RegistrationState::NOT_REGISTERED);
    EXPECT_EQ(s.generation, 0u);
    EXPECT_EQ(s.retry_count, 0u);
}

TEST(RegistrationStateTest, Transitions) {
    RegistrationStateHolder h;
    h.transition_to(RegistrationState::REGISTERING);
    EXPECT_EQ(h.state(), RegistrationState::REGISTERING);
    h.transition_to(RegistrationState::REGISTERED);
    EXPECT_EQ(h.state(), RegistrationState::REGISTERED);
    // MQTT 断开 -> NOT_REGISTERED（保留 generation）
    h.set_generation(5, "hash", 1, 2);
    h.transition_to(RegistrationState::NOT_REGISTERED);
    EXPECT_EQ(h.state(), RegistrationState::NOT_REGISTERED);
    auto s = h.snapshot();
    EXPECT_EQ(s.generation, 5u);  // generation 保留
    EXPECT_EQ(s.mandatory_count, 1u);
    // 新 generation -> REGISTERING
    h.transition_to(RegistrationState::REGISTERING);
    EXPECT_EQ(h.state(), RegistrationState::REGISTERING);
}

TEST(RegistrationStateTest, DegradedAndRecover) {
    RegistrationStateHolder h;
    h.transition_to(RegistrationState::REGISTERING);
    h.transition_to(RegistrationState::DEGRADED);
    EXPECT_EQ(h.state(), RegistrationState::DEGRADED);
    // 退避到期/IPC 恢复 -> REGISTERING
    h.transition_to(RegistrationState::REGISTERING);
    EXPECT_EQ(h.state(), RegistrationState::REGISTERING);
}

TEST(RegistrationStateTest, ResultAndRetryTracking) {
    RegistrationStateHolder h;
    h.set_result(SnapshotStatus::REJECTED, "route_register_failed");
    auto s = h.snapshot();
    EXPECT_EQ(s.last_result, SnapshotStatus::REJECTED);
    EXPECT_EQ(s.last_error, "route_register_failed");

    h.increment_retry();
    h.increment_retry();
    EXPECT_EQ(h.snapshot().retry_count, 2u);

    h.reset_retry();
    EXPECT_EQ(h.snapshot().retry_count, 0u);
}

TEST(RegistrationStateTest, UpdatedAtAdvances) {
    RegistrationStateHolder h;
    auto t1 = h.snapshot().updated_at_ms;
    h.touch();
    auto t2 = h.snapshot().updated_at_ms;
    EXPECT_GE(t2, t1);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
