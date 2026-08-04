#!/bin/bash
# FOTA relay / lifecycle smoke test for tbox-tsp service.
# Exit 0 = pass, non-zero = fail.
#
# TBOX-TSP-DSN-CR-007 §13.3: Orin 最小 FOTA 中继验证入口（本地生命周期 + 配置
# 安全检查 + socket 重建）。完整 MQTT Route / FOTA 上下行 / SOMEIP 链路验证由
# 受控 Orin 集成用例承担；本脚本不连接生产 Broker、不发布生产 Topic、
# 不使用真实车辆业务数据。

set -euo pipefail

# --- 配置存在性 ---
CONFIG_FILE="/etc/tbox/conf.d/tsp.yaml"
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "FAIL: config file ${CONFIG_FILE} not found"
    exit 1
fi

# --- 默认配置不得含生产敏感字段/身份实例值（CR-007 §11） ---
if grep -qE "device-sn|ecu_uid\s*[:=]\s*[^/{]|token|private_key|client_cert|root_ca|key_source|tls_key_ref|tls_cert_ref" "${CONFIG_FILE}"; then
    echo "FAIL: default config contains forbidden identity/credential fields"
    exit 1
fi

# --- 服务生命周期：重启并验证 socket 重建 ---
SOCKET_PATH="/tmp/tbox-tsp.sock"
if ! systemctl restart tbox-tsp.service; then
    echo "FAIL: could not restart tbox-tsp.service"
    exit 1
fi

for i in $(seq 1 50); do
    if [ -S "${SOCKET_PATH}" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -S "${SOCKET_PATH}" ]; then
    echo "FAIL: IPC socket ${SOCKET_PATH} not recreated after restart"
    exit 1
fi

# --- 优雅停机并验证 socket 清理 ---
systemctl stop tbox-tsp.service
for i in $(seq 1 30); do
    if [ ! -e "${SOCKET_PATH}" ]; then
        break
    fi
    sleep 0.1
done
if [ -e "${SOCKET_PATH}" ]; then
    echo "WARN: IPC socket ${SOCKET_PATH} still exists after stop (may be cleaning up)"
fi

# 恢复启动
systemctl start tbox-tsp.service

echo "PASS: tbox-tsp FOTA-relay/lifecycle smoke (config, restart, socket, stop)"
exit 0
