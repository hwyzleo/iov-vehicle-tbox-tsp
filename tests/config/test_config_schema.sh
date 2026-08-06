#!/bin/bash
# =============================================================================
# TBOX-TSP-DSN-CR-008 §15.6: TSP 配置 schema/profile 校验测试
# =============================================================================
# 通过 tools/tsp-config-check.py 对 fixture 配置执行校验，断言退出码。
# 纯校验、无副作用；python3/PyYAML 缺失时 SKIP（exit 0）不破坏无依赖构建。
# =============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHECKER="$REPO_ROOT/tools/tsp-config-check.py"
FIXTURES="$SCRIPT_DIR/fixtures"

# --- 依赖探测 ---
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found"
    exit 0
fi
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "SKIP: PyYAML not available (pip install pyyaml)"
    exit 0
fi

PASS=0
FAIL=0

# run_case <fixture> <profile> <expected_exit> <description>
run_case() {
    local fixture="$1"
    local profile="$2"
    local expected="$3"
    local desc="$4"

    local out
    out=$(python3 "$CHECKER" --profile "$profile" --quiet "$fixture" 2>&1)
    local rc=$?

    if [ "$rc" -eq "$expected" ]; then
        echo "PASS: $desc (exit=$rc)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected exit=$expected, got exit=$rc)"
        echo "      output: $out"
        FAIL=$((FAIL + 1))
    fi
}

echo "=========================================="
echo "TSP Config Schema/Profile Tests (CR-008)"
echo "=========================================="

# --- 合规用例 ---
run_case "$FIXTURES/valid_production.yaml"        production 0 "valid production config passes"
run_case "$FIXTURES/valid_production.yaml"        test       0 "valid production config passes test profile"
run_case "$FIXTURES/valid_test_with_common.yaml"  test       0 "test profile allows top-level common and device-sn"
run_case "$FIXTURES/valid_orin_overlay.yaml"      production 0 "BUILD Orin overlay simulation passes"
run_case "$REPO_ROOT/config/tsp.default.yaml"     production 0 "real default template passes production"
run_case "$REPO_ROOT/config/tsp.default.yaml"     test       0 "real default template passes test"

# --- schema 失败用例 (exit 1) ---
run_case "$FIXTURES/invalid_missing_route_id.yaml"     production 1 "missing required route_id"
run_case "$FIXTURES/invalid_duplicate_route_id.yaml"   production 1 "duplicate route_id"
run_case "$FIXTURES/invalid_direction_enum.yaml"       production 1 "direction enum violation"
run_case "$FIXTURES/invalid_qos_range.yaml"            production 1 "qos out of range"
run_case "$FIXTURES/invalid_unknown_field.yaml"        production 1 "unknown field under tsp.ipc"
run_case "$FIXTURES/invalid_device_sn_template.yaml"   production 1 "topic_template uses deprecated {device_sn}"
run_case "$FIXTURES/invalid_forbidden_field.yaml"      production 1 "forbidden field (token) present"

# --- profile 失败用例 (exit 2) ---
run_case "$FIXTURES/invalid_top_common_production.yaml"   production 2 "production forbids top-level common"
run_case "$FIXTURES/invalid_top_common_production.yaml"   test       0 "test allows top-level common"
run_case "$FIXTURES/valid_test_with_common.yaml"        production 2 "production forbids common + device-sn (test fixture)"
run_case "$FIXTURES/invalid_device_sn_production.yaml"    production 2 "production forbids device-sn identity instance"
run_case "$FIXTURES/invalid_device_sn_production.yaml"    test       0 "test allows device-sn"
run_case "$FIXTURES/invalid_socket_path_production.yaml"  production 2 "production requires approved socket path"
run_case "$FIXTURES/invalid_socket_path_production.yaml"  test       0 "test allows non-baseline socket path"
run_case "$FIXTURES/invalid_path_traversal.yaml"          production 2 "path traversal in socket path"
run_case "$FIXTURES/invalid_pem_secret.yaml"              production 2 "PEM private key marker in value"
run_case "$FIXTURES/invalid_vin_instance.yaml"            production 2 "VIN instance value detected"
run_case "$FIXTURES/invalid_mock_production.yaml"         production 2 "mock marker not allowed in production"
run_case "$FIXTURES/invalid_mock_production.yaml"         test       0 "test allows mock marker"

# --- 用法错误 (exit 3) ---
out=$(python3 "$CHECKER" --profile production "/nonexistent/file.yaml" 2>&1)
rc=$?
if [ "$rc" -eq 3 ]; then
    echo "PASS: missing file returns usage error (exit=3)"
    PASS=$((PASS + 1))
else
    echo "FAIL: missing file should return exit=3, got exit=$rc"
    FAIL=$((FAIL + 1))
fi

echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
