# idis

[简体中文](README.md) | [English](README.en.md) | [交互式设计方案展示页](https://mrlyc.github.io/idis/)

跨平台**网页扩展屏**、**macOS 独立虚拟屏与窗口自动路由**主机端（支持 macOS / Linux / Windows）。  
任意局域网设备打开浏览器即可作为低延迟扩展屏使用——**无需在观看端安装任何客户端**，同时附带对传统 USB / Wi-Fi 扩展屏客户端的可选兼容能力。

---

## 核心特性

- **零安装网页扩展屏（Web Extended Screen）**
  - 原生硬件 H.264 编码 + MSE fMP4 实时推流，支持 Chrome / Safari / Edge 及 iOS 17+（`ManagedMediaSource`），扫码或输入口令即可全屏观看。
  - 支持多种屏幕来源：**独立虚拟扩展屏**（macOS）、**电脑主屏幕**与**跟随模式**，并支持自定义分辨率、Retina HiDPI、画质预设与零黑屏恒定分辨率自适应码率（ABR）。
  - 内置 **局域网 WebRTC P2P 中继**：多台浏览器同时观看时自动在局域网内分摊主机带宽，异常时无缝回退至 WebSocket 推流。
- **管理端与观看端严格端口隔离 + 空闲自动关闭**
  - 管理端默认仅监听本机 `127.0.0.1:8787`（本机免密访问，完全拒绝任何观看端路由）。
  - 开启网页扩展屏并设置口令后，自动在 `0.0.0.0` 上开启**独立随机端口**对外提供观看服务；关闭观看、进入低电量模式或超过空闲时长（`--port-idle-close-secs`，默认 `300s`）后自动关闭该端口。
  - 可选的传统 Wi-Fi 接入端口同样支持在管理端动态启停与空闲自动关闭。
- **macOS 独立虚拟屏与窗口自动路由**
  - 无需外接物理显示器或观看端连接，即可在管理端一键创建最多 4 块**零编码开销**的临时虚拟屏（进程退出时自动销毁）。
  - 实时列出桌面普通窗口与**悬浮控件/置顶小窗**，支持一键移动与持久化 `window_rules` 自动路由（例如自动将会议/录音悬浮条移至虚拟屏隐藏，而不影响主窗口使用）。
- **面向笔记本的深睡友好与低功耗设计**
  - 零连接时进入事件驱动的**零唤醒待机**（不阻止系统深度睡眠）；网页切至后台或锁屏时自动暂停采集与编码。
  - 支持可逆的**低电量模式**、可自定义的**锁屏策略**（暂停 / 断开 / 保持 + 延迟秒数）、4 套内置配置预设与自定义 YAML 预设，以及 `launchd` / `systemd` Socket Activation 按需唤醒托管。
- **安全默认与轻量设备审批**
  - 默认不开启对外网络端口、默认仅观看不可远程控制、默认不走系统代理且不上传任何遥测。
  - 支持按需开启局域网设备审批：首次接入的设备需在管理后台或终端一键确认，可选择仅本次允许或加入信任列表，并支持随时撤销并立即断开。
- **可选传统客户端兼容**
  - 除网页扩展屏外，还提供对传统 USB（`usbmuxd`）与局域网 Wi-Fi 扩展屏客户端的兼容支持，详见 [传统客户端兼容说明](docs/legacy-clients.md)。

---

## 平台能力矩阵

| 能力 | macOS（Apple Silicon / Intel） | Linux（X11） | Windows（10 / 11） |
|---|---|---|---|
| 网页扩展屏（MSE H.264/fMP4 + P2P 中继） | ✅（ScreenCaptureKit + VideoToolbox） | ✅（FFmpeg x11grab + VAAPI/NVENC/x264） | ✅（FFmpeg ddagrab/gdigrab + NVENC/QSV/AMF/x264） |
| 管理端 / 观看端端口隔离与空闲自动关闭 | ✅ | ✅ | ✅ |
| 独立虚拟扩展屏 | ✅（`CGVirtualDisplay`） | 镜像 / 主屏 | 镜像 / 主屏 |
| 零编码临时虚拟屏 & 窗口自动路由 | ✅（原生 AX 窗口管理） | — | 窗口自动路由 ✅（Win32 多屏/置顶窗） |
| 锁屏自动暂停 / 断开策略 | ✅ | ✅（logind / D-Bus） | ✅（OpenInputDesktop 真暂停） |
| 后台按需唤醒（Socket Activation） | ✅（`launchd`） | ✅（`systemd --user`） | — |
| 可选传统 USB / Wi-Fi 客户端兼容 | ✅ | ✅ | ✅ |

---

## 30 秒快速开始

### 1. 安装或源码编译

- **直接下载预编译包**：前往 [GitHub Releases](https://github.com/MrLYC/idis/releases) 下载对应平台压缩包（提供 `macos-arm64`、`macos-x86_64`、`linux-x86_64`、`linux-arm64`、`windows-x86_64`）。
- **源码编译**（需 Rust stable 工具链）：
  ```bash
  cargo build --release --locked
  ```

### 2. 启动网页扩展屏

```bash
# 启动管理端（仅监听 127.0.0.1:8787，安全默认）
idis --web
```

1. 在本机浏览器打开 **`http://127.0.0.1:8787/`** 进入管理控制台。
2. 在「接入端口与连接二维码」卡片中点击**「随机生成」**（或输入自定义观看口令并保存）。
3. `idis` 会自动在 `0.0.0.0` 开启随机观看端口并生成局域网直达链接与二维码。
4. 用平板、手机或另一台电脑的浏览器扫码（或打开直达链接），按 `F` 或双击画面即可全屏作为扩展屏使用。

> 也可以通过命令行一步启动并在终端打印二维码：
> ```bash
> idis --web --max-web-viewers 2 --web-view-token "your-passcode" --qr
> ```

### 3. 平台前置依赖

- **macOS（12.3+）**：首次使用时请在 **系统设置 → 隐私与安全性** 中授予 **屏幕录制** 权限；如需使用窗口自动路由或远程输入，还需授予 **辅助功能** 权限。
- **Linux / Windows**：请确保 `ffmpeg` 位于 `PATH` 中（或通过 `--ffmpeg-path` 指定路径）。

---

## 文档导航

| 文档 | 内容说明 |
|---|---|
| [网页扩展屏指南](docs/web-extended-screen.md) | 管理端/观看端端口隔离、动态随机端口、空闲自动关闭、屏幕模式、MSE 播放与 LAN P2P 中继 |
| [macOS 虚拟屏与窗口路由](docs/virtual-displays.md) | 零编码临时虚拟屏、悬浮窗识别、一键挪窗与持久化 `window_rules` 规则 |
| [配置与命令行参考](docs/configuration.md) | `~/.config/idis.yaml`、内置预设、低电量模式、锁屏策略、轮询调优与完整 CLI 参数 |
| [后台托管与零唤醒待机](docs/background-hosting.md) | 零唤醒深睡机制及 macOS `launchd` / Linux `systemd` Socket Activation 配置 |
| [传统客户端兼容（可选）](docs/legacy-clients.md) | USB 数据线与动态 Wi-Fi 接入端口的使用说明 |
| [架构与工程不变量](docs/architecture.md) | 核心系统架构、关键不变量以及 TLA+ 形式化模型检验说明 |
| [安全策略](SECURITY.md) | 漏洞上报方式、局域网 HTTP 边界、P2P 互信与权限说明 |
| [参与贡献](CONTRIBUTING.md) | 开发环境、测试命令与代码规范 |

---

## 注意事项与免责声明

- **非公开 macOS 系统 API 提示**：macOS 上的虚拟显示器创建（`CGVirtualDisplay`）与窗口 ID 精确匹配（`_AXUIElementGetWindow`）通过运行时动态探测调用未公开系统接口，仅面向独立命令行/本机工具使用（不适用于 Mac App Store 分发），若未来 macOS 大版本接口变更会自动降级回退。
- **独立开源与商标声明**：`idis` 是一个独立的开源项目，与 Apple Inc.（macOS、iPad、Bonjour 等）、SHAPE GmbH 或任何其他商业产品与商标持有方均无隶属、赞助或背书关系。所有提及的第三方名称与商标仅用于兼容性说明，归其各自所有者所有。
- **许可证**：本项目基于 [MIT License](LICENSE) 开源；发行版二进制中静态链接的第三方 Rust 依赖声明见 [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)。
