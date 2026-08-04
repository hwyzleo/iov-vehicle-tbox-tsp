#!/bin/bash
# Health check for tbox-tsp service.
# Exit 0 = healthy, non-zero = unhealthy.
#
# TBOX-TSP-DSN-CR-007 §13.3: TSP 特有健康检查入口。
# 不连接生产 Broker、不发布生产 Topic、不读取任何凭据。

set -euo pipefail

# Check if the tbox_tsp binary exists
if [ ! -x /usr/bin/tbox_tsp ]; then
    echo "ERROR: tbox_tsp binary not found at /usr/bin/tbox_tsp"
    exit 1
fi

# Check if the systemd service is active
if ! systemctl is-active --quiet tbox-tsp.service; then
    echo "ERROR: tbox-tsp.service is not active"
    exit 1
fi

# Check if the IPC socket exists
SOCKET_PATH="/tmp/tbox-tsp.sock"
if [ ! -S "${SOCKET_PATH}" ]; then
    echo "ERROR: IPC socket ${SOCKET_PATH} not found"
    exit 1
fi

echo "OK: tbox-tsp service is healthy (binary, service, socket)"
exit 0
