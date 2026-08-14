// TBOX-TSP 构建期配置
//
// TBOX-TSP-DSN-CR-009 §取代与迁移：旧 legacy 完整 Topic 双路径已删除
// （TSP_USE_MQTT_ROUTE_API=OFF / main_legacy.cpp / prov_client 已移除），
// TSP 量产唯一路径为 MQTT Route API（publishRoute + subscribeRoutedDownlink +
// replaceSubscriptionSnapshot）。本头保留为空壳以兼容历史 include。
#pragma once
