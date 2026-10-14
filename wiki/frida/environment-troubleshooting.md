---
title: 动态/工具链环境排障（Frida / IDA / JEB / adb）
category: env
vuln_type: [reverse]
tags: [frida版本, adb互杀, APK安装失败, IDA窗口, JEB连接, 环境排障]
difficulty: easy
one_liner: 动态阶段"整段落空"、看不到 IDA/JEB 窗口、装 APK 失败、JEB 连不上 的一分钟自检+实测修复
keywords: [frida-ps, queryIntentActivities, major versions match, service check package, Broken pipe, RegisterNatives, start]
---

# 动态/工具链环境排障（Frida / IDA / JEB / adb）

> 适用：动态阶段"整段落空"、工具说"已启动"但看不到界面、装 APK 反复失败、JEB 连不上等
> **环境类故障**。这些**不是脚本/算法问题**，先把环境通了再谈解题。
> 来源：Nox 夜神 Android 9 + 本工具的实战排障，逐条实测验证。

## 0. 一分钟自检清单（按顺序，哪步失败修哪步）

```bash
# ① adb 能连上设备（统一用 nox_adb，避免双 adb 互杀）
nox_adb connect 127.0.0.1:62025
nox_adb devices            # 期望：127.0.0.1:62025  device

# ② 模拟器 package 服务就绪（装 APK 前提，刚开机时常未就绪）
nox_adb -s 127.0.0.1:62025 shell "service check package"   # 期望：Service package: found

# ③ frida 环境可用（最容易被忽视、却最致命）
frida-ps -H 127.0.0.1:27042               # 期望：列出进程列表

# ④ IDA MCP 在听
netstat -ano | findstr :13337             # 期望：有 LISTENING
```

## 1. 🔴 Frida client 与 server 版本不匹配（"动态抓取失败"最常见原因）

**症状**（看着像脚本问题，实则是版本问题）：
```
Failed to spawn: java.lang.NullPointerException:
Attempt to invoke virtual method 'java.util.List android.content.pm.PackageManager
.queryIntentActivities(android.content.Intent, int)' on a null object reference
```
或
```
Failed to spawn: unable to communicate with remote frida-server;
please ensure that major versions match ...
```
且 **`frida-ps -H ... ` 也报错**（连列进程都不行 → 不是脚本的问题，是 frida 连接/枚举层的问题）。
**看具体报错区分**：`major versions match` → 根因①（版本不一致）；`queryIntentActivities` → 根因②（枚举路径坏，换版本也没用，走 PID）。

**根因（两种，务必分辨）**：

**① 版本不一致**（次/大版本不同）→ 连 `frida-ps` 都报
`unable to communicate with remote frida-server; please ensure that major versions match`。
这种**必须**让 client 与 server 完全一致（下方步骤）。

**② 版本一致但仍枚举失败（Nox Android9 的已知 quirk）** → `frida-ps` / `-f` / `-n` / `-F` 报
`NullPointerException: queryIntentActivities on null`。
**实测：client=16.7.19 且 server=16.7.19（完全一致）时，这些"枚举类"操作依然全崩。**
根因是这条枚举路径在旧模拟器上取不到 PackageManager，**与版本是否一致无关**——所以"降到 16.7.19"**并不能**修好它。

> ⚠️ 纠错：早期文档写"client/server 一致就都能正常 frida-ps"，**该结论不准确**。准确结论是：
> 版本一致能消除 **①**；但 **②**（queryIntentActivities NPE）是**枚举路径本身**的问题，换版本无效。

**②的解法（实测有效）：绕开枚举，改用「按 PID 附加」**
`frida -p <PID>` 与 `-f/-n/-F` 走的是**完全不同的代码路径**，实测在同一环境下 **完全正常**：
```bash
# 1) 用 adb 取 PID（不经过 frida 的枚举）
nox_adb -s 127.0.0.1:62025 shell "monkey -p <包名> -c android.intent.category.LAUNCHER 1"  # 先拉起
nox_adb -s 127.0.0.1:62025 shell "pidof <包名>"        # 拿到 PID（如 3701）
# 2) 按 PID attach
frida -H 127.0.0.1:27042 -p 3701 -l hook.js            # ✅ 正常注入
```
**本工具已自动采用此策略**：`frida-ps` 枚举失败时不再中止动态阶段，而是
`adb pidof/ps -A` 取 PID → `frida -p <PID>` 附加（`electron/main.js` 的 `resolvePidByName` / `buildAttachArgs`）。

**①的修复（仅当版本确实不一致时）**：让 **client 与 server 版本完全一致**（推荐都用 16.7.19）：
```bash
# 1) PC 端对齐
python -m pip install "frida==16.7.19" "frida-tools==12.5.0"
frida --version            # 记下版本号 X

# 2) 设备端：把 server 换成同版本，并**覆盖工具实际使用的路径** /data/local/tmp/frida-server
nox_adb -s 127.0.0.1:62025 shell "su -c 'pkill -f frida-server'"
nox_adb -s 127.0.0.1:62025 push frida-server-16.7.19 /data/local/tmp/frida-server
nox_adb -s 127.0.0.1:62025 shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
nox_adb -s 127.0.0.1:62025 shell "su -c 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &'"
nox_adb -s 127.0.0.1:62025 shell "/data/local/tmp/frida-server --version"   # 必须 == X

# 3) 复检
frida-ps -H 127.0.0.1:27042               # 能列进程即成功
```
> **关键坑**：本工具/脚本启动 frida-server 用的是固定路径 **`/data/local/tmp/frida-server`**。
> 若把新版本只放到 `frida-server-16` 之类的**别名**路径，工具仍会用旧的主路径文件 → 版本照旧不匹配。
> **必须覆盖主路径** `/data/local/tmp/frida-server` 本身。

**兜底**：若 `-f spawn` 仍失败，改 **attach**——先 `adb shell monkey -p 包名 -c android.intent.category.LAUNCHER 1` 拉起，再 `frida -H ... -n 进程名 -l hook.js`。

## 2. 🔴 双 adb 互杀（装 APK 反复 `Broken pipe` / 设备掉线）

**症状**：`adb server version (36) doesn't match this client (41); killing...`；设备列表突然空；`install` 报 `Broken pipe (32)` / `Can't find service: package`。

**根因**：Nox 自带的 `nox_adb.exe`(v36) 与系统 `adb`(v41) 共用 5037 端口，**互相顶掉对方的 daemon**。

**修复**：**全程统一用 nox_adb**（本工具已改为优先 nox_adb + 检测版本不匹配时 kill-server/start-server 重建）。手动操作时别混用：
```bash
# 只用 nox_adb，不要 meanwhile 调系统 adb
nox_adb devices
```

## 3. 🔴 装 APK 报 `Can't find service: package`

**根因**：模拟器**刚开机几秒**就装包，此时 system_server 的 `package` 服务还没注册好。
**修复**：装前轮询 `service check package` 到 `found`（本工具已内置，最长等 60s）。手动装也先 `connect` 再等几秒。

## 4. 🟡 "工具说 IDA/JEB 已启动，但看不到窗口"

**症状**：进程在跑、MCP 端口在听，但屏幕上没有 IDA/JEB 界面。
**根因**：以 `spawn(detached)` 直接启动 GUI 程序时，窗口 `IsWindowVisible=False`（窗口对象存在但被隐藏）。
**修复（实测）**：用 **`cmd /c start "" "<exe>" <args>`** 启动（本工具 `gui:true` 已改为走此路径），窗口即正常显示。
**验证**：`IsWindowVisible=True` + 窗口标题非空。

## 5. 🟡 JEB MCP(16161) 连不上

- 启动 `.bat`（如 `jeb_wincon.bat`）时**参数含 `=`（如 `--script=x`）不能被 cmd 拆开**——要用 `cmd /s /c "..."` + `windowsVerbatimArguments` 手工拼引号（本工具已修）。
- 已有 JEB 进程在启动中时**别再拉第二个**（两实例抢 16161 双双失败）。
- JEB 跑在 **JDK 21** 时 dexdec 沙箱受限：在 JEB 根目录 `jvmopt.txt` 写
  `-Djava.security.manager=allow --add-opens java.base/java.lang=ALL-UNNAMED`；能用 **JDK 17** 更佳。
- 探活只判 TCP 端口（JEB 忙时 MCP 握手会超时，不能用握手判"是否在运行"）。

## 关联

- 动态 Hook 手法 → `frida/in-process-decrypt.md`、`frida/native-key-inversion.md`
- 多阶段 APK 推进 → `frida/android-multistage.md`
