# 后台托管与零唤醒待机

`idis` 专为笔记本电脑长期后台使用设计，支持两级低功耗待机模式：

1. **进程内零唤醒待机**：无活跃观看端与扩展屏时，主循环与监听线程均阻塞在内核事件（`poll(2)` / 条件变量）上，零周期性轮询唤醒，不持有系统防休眠锁（`IOPMAssertion`），完全不阻止系统深睡眠。
2. **Socket Activation 按需拉起（0 进程 / 0 内存）**：交由 macOS `launchd` 或 Linux `systemd --user` 托管监听端口，平时完全不运行 `idis` 进程；访问管理后台时秒级拉起，空闲超过 `--idle-exit-secs` 后自动退出归还端口。

---

## 1. macOS `launchd` 托管

仓库已提供开箱即用的模板：[docs/hosting/com.idis.agent.plist](hosting/com.idis.agent.plist)。

```bash
# 1. 复制模板到用户 LaunchAgents 目录
cp docs/hosting/com.idis.agent.plist ~/Library/LaunchAgents/

# 2. 按需编辑 ProgramArguments 中的 idis 绝对路径与参数
#    默认监听 127.0.0.1:8787（管理端按需唤醒，观看端开启后动态分配 0.0.0.0 随机端口）

# 3. 加载启用
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.idis.agent.plist

# 4. 卸载停用
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.idis.agent.plist
```

> 提示：如需通过 `launchd` 后台采集屏幕或移动窗口，请确保对应可执行文件已获得 macOS「屏幕录制」与「辅助功能」权限。

---

## 2. Linux `systemd --user` 托管

仓库已提供用户级单元模板：[docs/hosting/idis.socket](hosting/idis.socket) 与 [docs/hosting/idis.service](hosting/idis.service)。

```bash
# 1. 复制单元文件
mkdir -p ~/.config/systemd/user
cp docs/hosting/idis.socket docs/hosting/idis.service ~/.config/systemd/user/

# 2. 按需编辑 idis.service 中的 ExecStart 路径及 DISPLAY / XAUTHORITY

# 3. 重载并启用按需唤醒
systemctl --user daemon-reload
systemctl --user enable --now idis.socket

# 查看状态
systemctl --user status idis.socket idis.service
```

---

## 3. 休眠唤醒恢复

当主机从深度睡眠中唤醒时，`idis` 会自动检测时钟跳变并授予宽限窗口：
- 不会因休眠期间的时间跨度误触发空闲退出或立即关闭已打开的外部端口。
- 自动同步系统锁屏状态并按配置的锁屏策略恢复或清理会话。
