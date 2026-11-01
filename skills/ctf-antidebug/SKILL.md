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
- **信号类反调试家族**（Linux 上最常见，且与"程序逻辑"融为一体）：
  | 手法 | 表现 | 处理 |
  |---|---|---|
  | `SIGILL` 切换执行模式 | 撞到非法指令后 handler 改上下文继续 | 别 patch 掉；让信号真正抛给进程 |
  | `SIGFPE` handler 里 mprotect 改代码 | 除零后代码段被改写 | 同上，信号是流程的一部分 |
  | `fork` + pipe 死分支 | 父进程等子进程写管道，调试器只跟一个 | `set follow-fork-mode child`，或两个进程都放行 |
  | `INT3`/`0xCC` 扫描 + 代码段 hash 自校验 | 下断点即退出 | 先 patch 校验函数，再用硬件断点 |
  | `rdtsc`/`clock_gettime` 差值 | 单步导致时间异常 | Hook 时间函数返回固定值 |
  | 单步检测（`pushfq` 查 TF） | 一旦单步就走错分支 | 见下方"故障驱动 VM"——这时**不要单步** |

- **反沙箱/反 VM**（与反调试常叠加）：`CPUID` hypervisor 位、MAC 前缀、核数/内存阈值、
  `/sys/class/dmi/id/product_name` 含 VMware/VirtualBox、`systemd-detect-virt` 结果。
  绕过：改硬件指纹、patch 检查分支、换真机。CTF 里先确认它是否真的挡路——
  很多题只是"打印一行警告"然后照常跑。

### 故障驱动 VM + 反调试（强网杯 license 题实战）

这类题的"反调试"和"程序主逻辑"纠缠在一起，硬绕会走错分支。可靠做法是**先把环境做成确定性的**，
再让程序自己跑，只在关键点观测：

1. **确定性优先**：`personality(ADDR_NO_RANDOMIZE)` 关 ASLR（子进程 `preexec_fn` 里调）。
   否则同一个输入每跑一次栈地址不同，VM 的 hash 链跟着变，任何 diff 都无意义。
2. **干掉噪声源**：`sec_env_probe` 这类函数首字节改 `0xC3`（ret）最省事；
   `/proc/self/status` 里的 `TracerPid` 会进 VM 的 hash —— 把它 open 的路径重定向到假文件
   （`/tmp/fakestatus`），让值恒为 0，而不是去对抗 ptrace。
3. **别用 ptrace 观测 TF 单步的 VM**：VM 自己要收 SIGTRAP，ptrace 会先截走，VM 直接崩。
   改用 `/proc/<pid>/mem` 轮询（不需要 attach，见下）。
4. **`/proc/<pid>/mem` 差分轮询**：以 16 字节块为单位反复 `pread` 目标区域，
   只记录变化的块 → 得到"程序写了哪里、写了什么"的完整序列，完全不干扰运行。
   代价是轮询间隔（约 4ms）内的多次写会合并；要拿完整序列就缩小轮询区域。
5. **进程内 dump（无竞态）**：与其轮询，不如在目标进程里注入一小段 shellcode
   （放进已废弃函数的死代码区，注意**不要覆盖任何真实函数**——踩过一次把
   `fn_402bf5` 覆盖成 shellcode 导致 SIGILL，白查半天），在拒绝/失败瞬间把
   VM 区 + 上下文整块写文件。**这是最可靠取证方式**：无竞态、拿到的是崩溃前最终状态。
6. **区分"控制流"和"数据流"**：如果两个不同输入的执行轨迹（RIP 序列）完全一致而结果不同，
   说明分支由**数据**决定而不是控制流 —— 别再追 RIP，去比对内存/块内容。

## 原则

- 能 Hook 不 patch：patch 破坏文件完整性校验时优先 Hook
- 绕过前先看检测点在干嘛——有时检测逻辑本身就是隐藏流程的开关（改检测结果反而走错分支）
- 一次只绕一个检测点，逐个排除，避免绕过头
- **确定性比"绕过"更重要**：先把所有随机源（ASLR/TracerPid/时间/RDTSC）钉死，
  再观察。不然你分不清"这次结果不同"是逻辑差异还是环境噪声。

### 综合绕过优先级（按成本，别跳步）

1. **换执行环境**：Unicorn/Qiling 模拟天然无调试器痕迹。检测点只在"识别调试器"时最有效，
   **模拟执行根本不触发**——这是最省力的一步，却最常被忘。
2. **通用插件/脚本先行**：Linux 用 gdb 反反调试脚本；Windows 用 ScyllaHide；
   Android 用 Frida 反 anti-debug 脚本。先把标准检测点都盖住，再看是否还有残留。
3. **定位检测点**：从崩溃/退出点回溯，条件断点 + 日志。别猜。
4. **patch 语义**：改检测函数的返回值或跳转，而不是 nop 掉整段。
5. **最后才硬啃自定义检测**：只有前四步都不行（如检测嵌在 VM 内部、与哈希链耦合），
   才回到"确定性取证"路线（见下节）。

**判定"真的被挡了吗"**：先不挂调试器跑一遍。如果正常跑也失败，那不是反调试问题，
是输入/环境问题——别把时间浪费在绕过上。
