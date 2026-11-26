# 架构与工程不变量

本文档概括 `idis` 的核心模块划分、关键工程不变量以及随仓库提供的 TLA+ 形式化模型验证方法。

---

## 1. 模块概览

```text
src/
├── main.rs                 # 启动入口、Socket Activation、零唤醒主循环与休眠唤醒检测
├── config.rs               # CLI 参数定义与安全默认值
├── user_config.rs          # ~/.config/idis.yaml 序列化、预设与窗口路由规则模型
├── netinfo.rs              # 局域网 IP 探测、网卡绑定解析与连接信息组装
├── qr.rs                   # 零依赖 QR Code 编码器（终端字符与内联 SVG）
├── debug_trace.rs          # 结构化 JSONL 诊断日志与敏感字段脱敏
├── fmp4.rs                 # H.264 Annex-B -> Fragmented MP4 实时封装器
├── abr.rs                  # 恒定分辨率自适应码率（ABR）与在途帧流控
├── trust.rs                # 设备信任列表存储与持久化管理
├── transport/
│   ├── mod.rs              # WakePipe 零轮询中断、Keepalive 与对端断开检测
│   ├── wifi.rs             # 动态可启停的 Wi-Fi 监听控制器与空闲超时关闭
│   ├── usbmux.rs           # USB usbmuxd 监听器与多路复用流
│   └── socket_activation.rs# macOS launchd / Linux systemd 预绑定套接字接管
├── platform/
│   ├── macos.rs            # macOS 桥接层（ScreenCaptureKit、VideoToolbox、虚拟屏、AX 窗口）
│   ├── linux.rs / windows.rs / ffmpeg_capture.rs
│   └── mock.rs             # 全链路端到端测试用 Mock 后端
├── session/
│   ├── mod.rs              # SessionRegistry 核心状态与并发锁协调
│   ├── config_store.rs     # 事务性配置更新、预设切换与低电量快照恢复
│   ├── web_screen.rs       # 网页扩展屏订阅、画面源切换与独立虚拟屏管理
│   ├── window_routing.rs   # 临时独立虚拟屏生命周期与窗口自动路由引擎
│   ├── lock_policy.rs      # 锁屏状态机、宽限期、零唤醒等待与唤醒恢复
│   ├── flow_control.rs     # 在途帧流控、失焦降帧与采集暂停同步
│   └── handshake.rs        # 传统兼容客户端握手、会话隔离与重连清理
└── web/
    ├── mod.rs              # 管理端与动态观看端双监听器、端口空闲看门狗
    ├── routes.rs           # 端口作用域隔离路由与管理/观看 API
    ├── ws_stream.rs        # RFC 6455 WebSocket fMP4 推流与心跳保活
    ├── p2p.rs              # 局域网 WebRTC DataChannel 中继树与共享 Muxer 缓存
    ├── http.rs             # HTTP 解析、CSRF 校验、CSP 响应头与常量时间比较
    ├── admin.html          # 单文件零依赖 Web 管理控制台
    └── viewer.html         # 单文件零依赖 Web 扩展屏观看端
```

---

## 2. 核心工程不变量

| 域 | 编号 | 核心不变量 |
|---|---|---|
| **安全与隔离** | `SEC-1` | 安全默认：无对外端口默认开启、默认只读不注入输入、默认直连不走代理、诊断导出自动脱敏敏感字段。 |
| **安全与隔离** | `SEC-2` | 管理端与观看端严格按端口作用域隔离：管理端不提供观看/推流路由，观看端不提供管理路由且永不授予管理权限。 |
| **安全与隔离** | `SEC-3` | 所有变更操作执行 `Origin` 与 `Content-Type` 校验；登录接口具备按来源分桶的失败限流；撤销信任或轮换/关闭口令立即断开相关在线观众。 |
| **安全与隔离** | `SEC-4` | 对外端口（网页观看随机端口与动态 Wi-Fi 端口）在无活跃连接超过 `port_idle_close_secs` 后自动关闭释放监听，且未认证探测请求不会重置空闲计时器。 |
| **配置一致性** | `CFG-1` | 配置变更串行化并采用原子写入；损坏的磁盘 YAML 进入只读保护模式，不覆盖用户原文件。 |
| **配置一致性** | `CFG-2` | 低电量模式与运行时端口空闲关闭不会破坏磁盘基线配置；退出低电量模式可完整恢复原设定。 |
| **视频与解码** | `VID-1` | H.264 IPPP 推流在任意画面源切换、重连、锁屏恢复或丢帧后，必须等待新源的完整 IDR 关键帧再输出后续 P 帧，避免花屏与解码器参考帧污染。 |
| **视频与解码** | `VID-2` | 恒定分辨率 ABR 仅通过帧率与码率平滑降级/恢复，不重建虚拟显示器，避免画面闪烁与窗口重排。 |
| **并发与死锁** | `CON-1` | 严格维持单向锁序（`config_tx_lock` / `web_mode_lock` → `standalone_web_capture` → `sessions` → `web_subscribers`，叶子锁 `activity_signal` 不嵌套业务锁），绝不持锁执行线程 `join()` 或阻塞 I/O。 |
| **功耗与待机** | `PWR-1` | 零连接待机与端口空闲看门狗均基于事件条件变量精确唤醒，零周期性轮询；无活跃推流时不持有系统防休眠锁。 |

---

## 3. TLA+ 形式化模型检验

仓库在 [docs/tla/](tla/) 下维护 3 份可执行 TLA+ 规约，用 TLC 穷尽检验关键并发与状态机不变量：

- [SessionLockAndIdle.tla](tla/SessionLockAndIdle.tla)：锁屏策略（Pause / Disconnect / Keep）、宽限期、休眠唤醒恢复与零唤醒空闲退出的安全性与活性。
- [VideoDpbAndPause.tla](tla/VideoDpbAndPause.tla)：多源切换、重连、丢帧与共享 Muxer 缓存下的 H.264 DPB 关键帧门控与暂停/恢复一致性。
- [ConfigAndPresets.tla](tla/ConfigAndPresets.tla)：低电量模式可逆快照、损坏 YAML 只读保护与预设切换隔离。

本地运行模型检查（需 OpenJDK 17+）：

```bash
./docs/tla/check.sh --download
```
