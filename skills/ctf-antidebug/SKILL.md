---
name: ctf-antidebug
description: 反调试识别与绕过：Android(Java/Native) 与 Windows PE/Linux ELF 的检测点定位和 Frida 绕过脚本编写。程序闪退/检测到调试器/静态分析正常但动态异常时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 反调试识别与绕过

## 判断流程

1. 程序"跑起来就退/输入错误才退不正常" → 先怀疑反调试
2. 静态搜特征函数名/字符串（下表）
3. 找到检测点 → 选择 patch（静态改）或 Hook（Frida 动态）

## Android 检测点 → 绕过

| 检测 | 特征 | 绕过 |
|---|---|---|
| ptrace 自附加 | `ptrace(PTRACE_TRACEME)`，native 层常见 | Interceptor.replace 返回 0 |
| TracerPid | 读 `/proc/self/status` | Hook fgets/readLine 替换行内容为 `TracerPid:\t0` |
| Debuggable 标志 | `ApplicationInfo.FLAG_DEBUGGABLE` | 改 flags 值（保留其他位，只清 DEBUGGABLE 位 1<<1） |
| Frida 端口 | 连接 27042/27043、读 `/proc/net/tcp` 找端口 | Hook `Socket`/readLine 过滤 |
| Frida 文件 | 存在 `frida-server`/`re.frida.server`/`linjector` | Hook `File.exists` 按名返回 false |
| 线程名 | 枚举线程找 `gum-js-loop`/`gmain`/`pool-frida` | Hook `pthread_getname_np`/遍历过滤 |
| maps 扫描 | `/proc/self/maps` 含 frida/gadget 路径 | Hook fgets，匹配到则跳过该行 |
| System.exit | 检测后自杀 | Hook `System.exit`/`Process.killProcess` 空实现 |
| 签名校验 | `PackageManager.getPackageInfo(GET_SIGNATURES)` | Hook 返回伪造签名 |

- smali 级 patch（重打包）：检测函数直接 `return-void` 或改比较跳转（`if-eqz` ↔ `if-nez`），改完 apktool b + 签名

## Windows PE 检测点 → 绕过

| 检测 | 特征 | 绕过 |
|---|---|---|
| IsDebuggerPresent | kernel32 导出 | replace 返回 0；或清 PEB.BeingDebugged(偏移0x2) |
| CheckRemoteDebuggerPresent | kernel32 | Hook 后把输出参数写 0 |
| NtQueryInformationProcess | ProcessDebugPort(7)/DebugObject(30)/DebugFlags(31) | Hook ntdll，7/30 写 0，31 写 1 |
| NtGlobalFlag | PEB 偏移 x64:0xBC / x86:0x68 非零 | 直接写 0 |
| OutputDebugString | 调用后 GetLastError==0 判断 | replace 为空实现 |
| rdtsc/时间差 | 两次 QueryPerformanceCounter/rdtsc 差值过大 | Hook 时间函数拉平差值，或 IDA patch 跳过 |
| 窗口/进程名 | FindWindow 查 OllyDbg/x64dbg/IDA | Hook 返回 NULL |
| 硬件断点 | GetThreadContext 的 Dr0-Dr3 | 清零后返回 |

## Linux ELF

- ptrace 自附加 → fork 子进程 attach 父进程占坑：静态 patch `xor eax,eax` 或 LD_PRELOAD 假 ptrace
- 信号陷阱：`SIGTRAP/SIGSEGV` handler 当正常流程 → 必须**真调试器接住信号**而不是绕过

## 原则

- 能 Hook 不 patch：patch 破坏文件完整性校验时优先 Hook
- 绕过前先看检测点在干嘛——有时检测逻辑本身就是隐藏流程的开关（改检测结果反而走错分支）
- 一次只绕一个检测点，逐个排除，避免绕过头
