# 配置与命令行参考

`idis` 使用单一 YAML 文件（默认 `~/.config/idis.yaml`，可通过 `--config` 或 `IDIS_CONFIG` 指定，传 `none` 则纯内存运行）持久化保存画质参数、预设、锁屏策略、端口空闲超时、窗口路由规则与已信任设备列表。

---

## 1. 配置文件结构示例（`~/.config/idis.yaml`）

```yaml
low_power: false
allow_input: false
client_cursor: false
max_extended_screens: 2
max_web_viewers: 0
auto_max_in_flight: true
max_in_flight: 2
lock_action_ipad: pause
lock_action_web: pause
lock_delay_secs: 10
port_idle_close_secs: 300
web_independent_screen: false
web_screen_mode: follow_ipad
web_require_approval: false
p2p_relay_enabled: true

ipad:
  width: 0
  height: 0
  fps: 30
  bitrate_mbps: 16
  hidpi: 1
  integer_scale: false
  max_pixel_edge: 0
  adaptive_quality: true
  abr_sensitivity: balanced
  half_fps_when_unfocused: false

web:
  width: 1280
  height: 720
  fps: 30
  bitrate_mbps: 16
  hidpi: 1
  max_pixel_edge: 0

polling:
  main_loop_ms: 250
  cursor_poll_ms: 8
  usb_retry_ms: 1000
  admin_poll_ms: 2000

presets: []
window_rules: []
trusted_devices: []
```

### 配置安全机制
- **损坏保护**：若磁盘 YAML 语法损坏，`idis` 自动进入只读降级模式，绝不会用默认值覆盖原文件；可在管理端 YAML 编辑器中查看并修复。
- **可逆低电量模式**：开启低电量模式（`--low-power` 或管理端开关）时，运行时会自动应用省电参数并暂停网页观看，同时完整保留你在 YAML 中的原始基线配置，退出低电量模式后自动恢复。

---

## 2. 内置配置预设

管理端内置 4 套一键预设（切换预设不会修改你的信任设备列表）：

| 预设名称 | 典型场景 | 核心参数特点 |
|---|---|---|
| **日常均衡** | 日常办公副屏 | 30 FPS / 16 Mbps、自适应码率开启、1x 缩放 |
| **高清副屏** | 代码阅读 / 设计审稿 | 60 FPS / 24 Mbps、2x HiDPI、网页观看上限 2 |
| **极简省电** | 电池续航优先 | 开启低电量模式、15 FPS / 4 Mbps、暂停网页观看与 P2P、降低轮询频率 |
| **网页共享** | 多人浏览器同屏观看 | 独立/网页优先配置、网页观看上限 6、开启局域网 P2P 中继 |

你也可以在管理端保存自定义命名预设并随时切换。

---

## 3. 常用命令行参数

### 网页扩展屏与管理端
| 参数 | 默认值 | 说明 |
|---|---|---|
| `--web` | `false` | 启用 Web 管理端（启用后才开启管理端口） |
| `--web-bind <ADDR>` | `127.0.0.1:8787` | 管理端监听地址（支持 `IP:port` 或 `网卡名:port`） |
| `--web-admin-token <TOK>` | 空 | 管理端登录口令（环境变量 `IDIS_WEB_ADMIN_TOKEN`）；监听非回环地址且未指定时自动生成随机口令 |
| `--web-view-token <TOK>` | 空 | 网页扩展屏观看口令（环境变量 `IDIS_WEB_VIEW_TOKEN`） |
| `--max-web-viewers <N>` | `0` | 最大并发网页观众数（`>0` 且配置口令后自动开启 `0.0.0.0` 随机观看端口） |
| `--web-screen-mode <MODE>` | `follow-ipad` | 网页画面来源：`independent` / `main` / `follow-ipad` |
| `--web-require-approval` | `false` | 网页观众首次连接需管理员审批 |
| `--web-width` / `--web-height` | `1280` / `720` | 独立网页扩展屏默认逻辑分辨率 |
| `--web-fps` / `--web-bitrate-mbps` | `30` / `16` | 独立网页扩展屏目标帧率与码率 |
| `--web-hidpi <1\|2>` | `1` | 独立网页扩展屏 HiDPI 倍率 |
| `--qr` | `false` | 启动时在终端打印观看链接二维码 |

### 端口空闲、待机与锁屏策略
| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port-idle-close-secs <N>` | `300` | 网页扩展屏与 iPad Wi-Fi 端口无活跃连接超时自动关闭秒数（`0` = 不自动关闭） |
| `--idle-exit-secs <N>` | `300` | 全局无连接且无认证后台访问超时自动退出进程秒数（`0` = 常驻不退出） |
| `--low-power` | `false` | 启动低电量模式 |
| `--on-lock <ACTION>` | `pause` | 主机锁屏后统一策略：`pause` / `disconnect` / `keep` |
| `--on-lock-web` / `--on-lock-ipad` | 跟随 `--on-lock` | 分别为网页端与传统客户端设置锁屏策略 |
| `--on-lock-delay-secs <N>` | `10` | 锁屏后延迟执行策略的宽限秒数 |

### 画质、采集与诊断
| 参数 | 默认值 | 说明 |
|---|---|---|
| `--mode <MODE>` | `extend` | 采集模式：`extend` / `mirror` / `main` |
| `--quality <PRESET>` | — | 画质预设：`eco` / `low` / `balanced` / `high` / `ultra` |
| `--width` / `--height` / `--fps` / `--bitrate-mbps` | `0`/`0`/`30`/`16` | 自定义逻辑宽高、帧率与码率 |
| `--hidpi <1\|2>` / `--integer-scale` | `1` / `false` | Retina HiDPI 与整数缩放 |
| `--abr-sensitivity <LVL>` | `balanced` | 自适应码率灵敏度：`conservative` / `balanced` / `aggressive` |
| `--no-adaptive-quality` | `false` | 禁用自适应码率 |
| `--debug` / `--debug-log <PATH>` | `false` | 开启结构化 JSONL 诊断日志（管理端可一键导出已脱敏诊断包） |
| `--config <PATH>` | `~/.config/idis.yaml` | 配置文件路径（`none` = 不读写磁盘） |

> 完整参数列表（含可选传统 USB/Wi-Fi 兼容选项）请运行 `idis --help` 查看，也可在 Web 管理端底部使用「CLI 启动命令生成器」实时导出当前配置对应的命令行。
