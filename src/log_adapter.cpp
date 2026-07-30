#include "log_adapter.h"

namespace tbox {
namespace tsp {

bool LogAdapter::s_initialized = false;

tbox::fw::log::InitResult LogAdapter::init(
    const std::string& service,
    const tbox::fw::log::LogConfig& config
) {
    auto result = tbox::fw::log::Logger::init(service, config);
    if (result.error == tbox::fw::log::LogError::kOk) {
        s_initialized = true;
    }
    return result;
}

tbox::fw::log::Logger LogAdapter::route() {
    return tbox::fw::log::Logger::get("route");
}

tbox::fw::log::Logger LogAdapter::fota() {
    return tbox::fw::log::Logger::get("fota");
}

tbox::fw::log::Logger LogAdapter::mqtt_client() {
    return tbox::fw::log::Logger::get("mqtt_client");
}

tbox::fw::log::Logger LogAdapter::someip_bridge() {
    return tbox::fw::log::Logger::get("someip_bridge");
}

tbox::fw::log::Logger LogAdapter::relay() {
    return tbox::fw::log::Logger::get("relay");
}

tbox::fw::log::Logger LogAdapter::security() {
    return tbox::fw::log::Logger::get("security");
}

tbox::fw::log::Logger LogAdapter::http_client() {
    return tbox::fw::log::Logger::get("http_client");
}

tbox::fw::log::Logger LogAdapter::ipc_server() {
    return tbox::fw::log::Logger::get("ipc_server");
}

tbox::fw::log::Logger LogAdapter::application() {
    return tbox::fw::log::Logger::get("application");
}

tbox::fw::log::Logger LogAdapter::subscription() {
    return tbox::fw::log::Logger::get("subscription");
}

} // namespace tsp
} // namespace tbox
