# TSP 配置目录

本目录遵循 **TBOX-TSP-DSN-CR-008 §15** 的配置分层设计，分离开发调试、服务默认
模板、校验 schema 三类资产。

## 目录结构

```
config/
├── dev/                       # 开发调试（DEVELOPMENT-ONLY，不安装）
│   ├── common.yaml            #   调试用 common（framework-config layer 0）
│   └── tsp.yaml               #   调试用 tsp 覆盖（测试 socket/store/device-sn）
├── schema/
│   └── tsp.schema.yaml        # 声明式 schema（字段/类型/范围/禁止字段）
└── tsp.default.yaml           # 唯一发布默认模板（安装为 /etc/tbox/conf.d/tsp.yaml）
```

## 三层加载顺序（framework-config，保持不变）

```
/etc/tbox/common.yaml          # BUILD 唯一提供（common 所有权归 BUILD）
-> /etc/tbox/conf.d/tsp.yaml   # tsp-runtime 安装 tsp.default.yaml 生成
-> ./tsp.yaml                  # 工作目录覆盖（仅测试/研发）
```

## 各文件用途与边界

| 文件 | 安装 | 用途 |
|---|---|---|
| `tsp.default.yaml` | ✅ tsp-runtime -> `/etc/tbox/conf.d/tsp.yaml` | 唯一发布默认模板，仅含非秘密 tsp 默认值，**不含顶层 `common:`** |
| `schema/tsp.schema.yaml` | ❌（BUILD 源码引用） | 声明式 schema，供 `tools/tsp-config-check.py` 与 BUILD metadata 引用 |
| `dev/common.yaml` | ❌ | 调试用 common（store/ipc/log）；显式 `config_root=config/dev/` 启动时生效 |
| `dev/tsp.yaml` | ❌ | 调试用 tsp 覆盖（测试 socket/device-sn）；复制为 `./tsp.yaml` 或显式引用 |

## 默认模板内容边界（CR-008 §15.5 / §15.6）

`tsp.default.yaml` 只包含代码实际消费的非秘密、安全默认值：

- `tsp.ipc.socket_path`: `/tmp/tbox-tsp.sock`（framework-ipc 基线）及有界队列参数
- `tsp.mqtt.socket_path`: `/tmp/tbox-mqtt.sock`（本地 tbox::mqtt_client 连接）
- `tsp.subscriptions`: 稳定 route_id、未展开 `topic_template`、direction、QoS、target、mandatory

**不含**（production 禁止）：
- 顶层 `common:`（由 BUILD common.yaml 唯一提供）
- `device-sn` / VIN / SN / ECU UID 身份实例值
- 展开后的完整设备 Topic
- Token / 密码 / 证书 / 私钥 / 密钥材料 / 生产 Broker 凭据
- Store generation/digest、dedup/receipt 运行时状态
- mock / fixture / bypass / 模拟 peer / 测试资产
- 个人目录 / 宿主路径 / build tree / 含 `..` 的逃逸路径

> 注：去重窗口（dedup-window-ms）与节流间隔（throttle-interval-ms）当前为代码
> 常量（`include/constants.h`），不通过配置文件消费，故不进入默认模板。

## 本地开发运行

```bash
# 方式 1：显式指定调试配置根
./build/tbox_tsp config/dev/

# 方式 2：工作目录覆盖（framework-config 第三层，最高优先级）
cp config/dev/tsp.yaml ./tsp.yaml
./build/tbox_tsp
```

## 校验

```bash
# 校验默认模板（production profile）
python3 tools/tsp-config-check.py --profile production config/tsp.default.yaml

# 校验 BUILD Orin overlay 后的最终配置
python3 tools/tsp-config-check.py --profile production /etc/tbox/conf.d/tsp.yaml
```

校验命令为纯无副作用检查：无网络/DNS/MQTT/PROV/SEC/socket/store/queue
写入/身份/credential 读取，具有稳定退出码（0=pass, 1=schema fail, 2=profile fail,
3=usage），调用方可用 `timeout` 包裹。

## BUILD Orin Overlay

BUILD 在 staging 阶段检查 `configs/orin/rootfs/etc/tbox/conf.d/tsp.yaml`：
- 不存在则保留 tsp-runtime 安装的默认模板；
- 存在则**整文件覆盖**同一 staging 目标（不做 YAML 深度合并）；
- 记录 default/platform/final 来源与 SHA-256，执行 schema、production profile、
  路径/资源检查和安全扫描后打包。

TSP 仓库不维护 `tsp.orin.yaml` 或 `config/platform/orin/tsp.yaml`。
