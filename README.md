# YN076 LAN SMS Gateway

基于合宙 Air780EPM（YN076 USB Dongle）的**局域网短信网关**：USB 虚拟串口通信、**零蜂窝流量**、Web 管理面板、Bark iPhone 推送（支持自建服务器 + Basic Auth + AES 端到端加密）。服务端纯 Python 标准库（零 pip 依赖）。

> v2 串口版：彻底放弃 USB 网卡（RNDIS/NAT）方案——经实测 106 号固件的 USB netdrv 未接线，独立 IP 模式不可用。改用 **USB 虚拟串口 + JSON 行协议**，插上就用，无任何网络配置，SIM 卡流量零消耗（仅手动触发"定量消耗保号"时走 4G）。

```
手机浏览器 ──▶ WebUI(:8088) ──▶ sms_relay.py ──USB串口──▶ 780 Dongle ──▶ 蜂窝短信
                    │                                            ▲
                    └── 新短信 → Bark 推送（验证码自动提取）        └─ SIM 卡
```

## 核心特性

- 🔌 **USB 虚拟串口通信**：`uart.VUART_0` ↔ `/dev/ttyACM*`，JSON 行协议 `\n` 分帧，自动探测串口、断线重连，插上就用
- 🛡️ **零蜂窝流量**：启动即 `mobile.setDataEnable(false)` 关闭 PDP 数据上下文（短信走信令通道不受影响）；无 sntp、无任何自动公网请求；"定量消耗保号"是唯一走流量的入口（临时开 PDP → 下载 → 立即关）
- 📨 **收发短信**：收信主动推送（无需轮询）+ SQLite 落库；发信队列化（pending→sending→sent/failed 状态机）
- 🔔 **Bark 推送**：面板可视化配置，支持自建 bark-server（Basic Auth）、官方服务器、AES-128-CBC 端到端加密；验证码自动提取进推送标题、`copy` 字段一键复制
- 🌍 **SIM 卡归属地识别**：ICCID(ITU E.118)/IMSI(MCC/MNC) 离线库，面板状态卡显示旗帜+国家（如 🇵🇹 葡萄牙）；号码备注可点击编辑（如 📱 +372 xxxx）
- 📊 **流量管理**：基带级上下行计数（`mobile.dataTraffic()`）、按 KB 定量消耗（保号/激活计费）、单次上限 50MB
- 🎨 **现代化 UI**：暗色/浅色主题（🌙 切换、localStorage 持久化）、Bento 卡片布局、验证码高亮 chip 点击复制、Toast 提示
- 🐕 **设备端自愈**：硬件看门狗（9s 超时 3s 喂狗）、每小时内存回收、`mobile.setAuto` 网络自愈、短信队列断电不丢
- 🧩 **纯标准库**：服务端零 pip 依赖，Debian 12/13 开箱即用

## 仓库结构

```
dongle/
└── main.lua              # 780 端脚本 v002.000.002（串口 JSON 协议 + 流量锁 + 看门狗自愈）
server/
├── sms_relay.py          # 服务端主程序（WebUI + SQLite + Bark 推送 + SIM 归属地）
├── serial_780.py         # 串口通信层（自动探测 ttyACM0-2 / 断线重连 / 命令-响应匹配）
├── sim_info.py           # SIM 归属地离线库（ICCID/IMSI → 国家+运营商）
└── sms-relay.service     # systemd 单元
docs/
└── 烧录与部署指南.md      # 从烧录到上线的完整步骤
```

## 部署

### 1. 烧录设备端（Luatools v3）

| 项 | 值 |
|---|---|
| 内核固件 CORE | `LuatOS-SoC_V2050_Air780EPM_106.soc`（[官方下载](https://docs.openluat.com/air780epm/luatos/firmware/780epm_version/)，106 号支持电信短信） |
| 脚本文件 | 本仓库 `dongle/main.lua` |
| 添加默认 lib | ✅ **必须勾选** |

按住 Dongle BOOT 键插入 USB 进下载模式 →「下载底层和脚本」。串口日志出现 `sms_gateway_v2 002.000.002` 即成功。

### 2. 部署服务端

```bash
mkdir -p /opt/sms-relay /var/lib/sms-relay
cp server/*.py /opt/sms-relay/
cp server/sms-relay.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now sms-relay
# 浏览器打开 http://<服务器IP>:8088
```

### 3. 接入硬件

Dongle 插服务器 USB 口（或 PVE 直通进 VM），出现 `/dev/ttyACM0-2`，服务端自动探测数据口（VUART_0 实测为 ttyACM2，顺序浮动时自动 fallback），收到设备 `boot` 握手后面板显示在线。

### 4. 配置推送

面板「推送通知」区：DeviceKey 填 Bark App 内复制的 Key；服务器填自建 bark-server 地址或留空用官方。自建服务器带 Basic Auth 时在 service 里加 `Environment=BARK_AUTH_USER/PASS`。

## 串口协议（JSON 行协议）

```
服务器→780:  {"cmd":"send_sms","num":"10086","text":"hi"}   发短信
             {"cmd":"get_status"}                            查状态(CSQ/ICCID/IMSI/号码/流量)
             {"cmd":"get_traffic"}                           查流量
             {"cmd":"consume","kb":10}                       定量消耗流量(保号, 单次≤50MB)
             {"cmd":"ping"}                                  心跳
780→服务器:  {"type":"resp","req":"...","ok":true,...}        命令响应
             {"type":"sms","num":"...","text":"..."}          新短信(主动推送)
             {"type":"boot","version":"..."}                  启动握手
             {"type":"heartbeat","ts":...,"csq":...}          60s 心跳
```

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 服务+设备状态（含 `sim` 归属地、`display_number` 号码） |
| GET/POST | `/api/sim_number` | 号码备注（面板点击号码编辑） |
| GET/POST | `/api/bark` | Bark 配置 |
| POST | `/api/bark/test` | 发送测试推送 |
| GET | `/api/sms/inbox` / `/api/sms/outbox` | 收件箱 / 发件记录 |
| POST | `/api/sms/send` | 发短信 `{"num":"...","text":"..."}` |
| POST | `/api/data/consume` | 定量消耗 `{"kb":1024}` |
| POST | `/api/data/traffic/reset` | 流量统计清零 |

## 已知限制（实测结论）

- **106 号固件无 USB netdrv**：RNDIS 独立 IP / NAT 模式下 `netdrv.ipv4(socket.USB)` 均不可用（`W/netdrv 不存在或未就绪`），固件 SDK 未接线 USB 以太网适配器；109 号固件支持 USB 网卡但无 sms/httpsrv 库——官方固件矩阵无两者兼得版本，故 v2 改走串口
- Air780EPM 不支持 VoLTE/通话/eSIM；ModemManager 不识别
- 面板无鉴权，仅限内网使用；公网暴露请加反代+认证

## 致谢

- [LuatOS](https://github.com/openLuat/LuatOS)（合宙）与 Air780EPM 官方 demo
- [bark-server](https://github.com/Finb/bark-server)（自建推送）
- 本项目 v1 的 USB 网卡方案探索（HTTP over RNDIS）见 git 历史

## 许可

MIT
