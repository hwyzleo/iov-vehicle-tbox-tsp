// include/tsp_build_config.h
//
// TSP 构建期配置 (CR-006 §10.2)
//
// CMake option TSP_USE_MQTT_ROUTE_API (默认 ON) 注入 compile definition
// TSP_USE_MQTT_ROUTE_API=1/0。本头将其归一化为 TSP_MQTT_ROUTE_API 宏，
// 供业务代码以 `#if TSP_MQTT_ROUTE_API` 选择 route 模式（量产默认）或 legacy
// 模式（deprecated，保留一个发布周期）。
//
// route 模式：publishRoute + subscribeRoutedDownlink，不构造 prov_client、
//   不缓存 ecu_uid、不拼装完整 Topic。
// legacy 模式：publish + subscribe 完整 Topic，经 PROV readBinding 获取 ecu_uid。
//
// 单个构建/运行实例只启用一种模式 (CR-006 §10.2)；route 模式验收后删除 legacy。
#pragma once

#if defined(TSP_USE_MQTT_ROUTE_API) && TSP_USE_MQTT_ROUTE_API
#define TSP_MQTT_ROUTE_API 1
#else
#define TSP_MQTT_ROUTE_API 0
#endif
