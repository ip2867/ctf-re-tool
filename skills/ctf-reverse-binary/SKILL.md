---
name: ctf-reverse-binary
description: PE/ELF 二进制逆向方法论：查壳脱壳、IDA 定位关键函数、VM 字节码题专项、算法识别入口、静态分析套路、**动态调试入场纪律与定向取证**（断点选址/窗口期/SMC/反调试/GUI）。拿到 EXE/DLL/ELF/SO 题目、或需要下断点取运行时值时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 二进制逆向方法（PE / ELF）

## 流程总览

```
EXE/ELF → DIE查壳 → (有壳:脱壳) → IDA静态取数
  → 定位main/WinMain → 搜关键字符串 → 交叉引用到比较点
  → 识别算法（含 VM 字节码型）→ 锁定候选函数 + 写调试假设
  → (需要运行时值?) → (反调试?绕过) → 定向动态取密钥 → 离线复算 → 解密
```

**关键顺序**：静态先跑完（§6.0 的四条入场条件），再决定是否启动调试器。
跳过静态直接 start 会在系统 DLL 和消息循环里漫游，几十轮下来零信息。

## 1. 查壳与脱壳

| 壳 | 识别 | 处理 |
|---|---|---|
| UPX | UPX0/UPX1 段名 | `upx -d` 直接脱 |
| VMP/Themida | 高熵段、虚拟机字节码 | 动态 dump + 修复 IAT（x64dbg/VMP 分析工具），或绕过不脱壳直接动态分析 |
| .NET | mscoree 引用 | 转 dnSpy 流程（de4dot 去混淆） |

### 1.1 UPX 脱壳（完整可落地步骤）

1. **查壳**：DIE/ExeinfoPE 确认是 UPX（段名 `UPX0`/`UPX1`/`UPX2`）
2. **脱壳**：`upx -d <完整路径>`
3. **失败时修区段名**：UPX 脱壳对区段名敏感；用 010 Editor 打开，把被改过的区段名改回 UPX 原始名（大小写以查壳工具为准），保存后重新 `upx -d`
4. **脱壳后必须重扫算法指纹**：壳里的 S 盒/常量表此时才可见，重跑 `scan_crypto`

### 1.2 手动脱壳（ESP 定律，非 UPX 壳用）

**适用**：VMP/Themida/自定义壳，或 UPX 脱壳失败。
**工具**：32 位用 x32dbg，64 位用 x64dbg（OllyDbg 只能 32 位）。

**步骤**：
1. 拖入调试器，F9 运行到第一个 `push` 指令，记下 ESP 值（如 `61FF78`）
2. F8 单步，让壳把寄存器压栈
3. 在内存窗口跟踪**原 ESP 地址**，右键设硬件断点（壳解压完会回到这里）
4. F9 跑到断点，F8 继续；遇死循环就在循环下方设断点用 F4 跳过
5. **大跳转通常就是 OEP**（跨段的长跳）
6. Scylla 插件 Dump → 保存文件
7. 修 IAT：Scylla 里 `Get Imports` 获取地址 → `Fix Dump` 修复，生成可用文件
8. 验证运行正常 → 拖入 IDA 分析

**注意**：脱壳只是手段。若只是要拿运行时的常量/密钥，**不脱壳也可以**——直接用 Frida 在壳解密完成后 Hook 取数据（见第 6 节）。

## 2. IDA 定位关键函数（命中率从高到低）

1. **Strings 窗口**搜 `flag/correct/wrong/success/key/password` → 交叉引用（X键）到使用处
2. **main / WinMain / start** 入口跟读
3. **imports** 窗口看 `strcmp/memcmp/strcmpi/strstr` → 找比较调用点
4. 常见结构：`输入 → 变换函数 → memcmp(变换结果, 常量密文)` —— 变换函数就是要还原的算法
5. `sub_XXXX` 小函数被 main 一次调用且含循环+异或/移位 → 大概率是加密核心

### 2.1 编译器符号差异（2026-09 验收实战沉淀）

- **mingw 入口是 `_main`**（不是 `main`）：`decompile('main')` 返回 Not found 时按候选序列
  `main / _main / __main / WinMain / _WinMainCRTStartup / start` 逐个尝试，命中"有代码"即用
- **C++ mangled 名把语义藏在中段**：如 `__Z9vm_operadPii` 实为 `vm_operad(int*, int)`。
  按子串（`vm_/operad/opcode/encode/decode`）匹配，别只看前缀
- 反编译返回 `{"code":null}` 或 `Not found: 'xxx'` = 函数名不对，**不是分析失败**，换名字重试

### 2.2 CRT 运行时噪声（永远不是关键函数）

mingw/gcc 运行时会带一批"长得像关键函数"的噪声，选关键函数时降权/剔除：
`__decode_pointer`（含 decode！）、`..._add_key_dtor`（含 key！）、`__get/set_invalid_parameter_handler`、
`__matherr`、`___tlregdtor`、`_my_lconv_init`、`__setargv`、`__IsNonwritableInCurrentImage`、
`_ValidateImageBase`、`_FindPESection`、`__Z4readPc`（read 的 C++ 包装）。
**教训**：噪声函数名里恰好含 `decode/key` 等关键词，硬编码关键词表会把真关键函数挤出名额——必须语义加权 + 噪声降权。

## 3. 静态分析套路

- 常量密文在 `.data`/`.rdata`：双击进去看 hex，长度暗示算法（8字节对齐→TEA/DES，16→AES，无对齐→RC4/异或/自定义）
- 变换后比较长度 ≠ 输入长度 → 有哈希/加密扩张，不能直接逆，需爆破或Hook
- 查表结构：256 字节表 → S盒（RC4/AES）；4KB 分成 16x16 → AES 完整 S 盒
- ELF 静态编译（glibc 静态）符号全无：先 `strings | grep GLIBC` 判断，用签名识别（IDA FLIRT）

## 4. VM / 字节码解释器题专项（2026-09 验收实战沉淀）

**识别特征**（命中任一即按本节处理）：
- main 里 `memcpy/qmemcpy` 把 `.data` 常量表拷进缓冲区，随后调用形如 `func(int* dst, int n)` 的函数
- 该函数内是 `while(1){ switch(dst[pc]){...} }` 大循环，case 数通常 8~15 个
- opcode 语义套路：读输入 / 算术（加减异或乘）/ 存输出缓冲 / 就地写回输入缓冲 / 校验比较 / nop

**必拿数据（缺一不可——代码与数据同等重要）**：
1. 解释器函数的**完整反编译**（所有 case 分支）
2. 常量数据表的**原始数据**：地址 + 按元素宽度小端解码（int32 数组 = get_bytes 后 4 字节小端转 int）
3. 反编译 refs 里被引用的全局（`src_`、密文表、格式串）要回头全部读出来
   ——只有解释器没有字节码表时**不可解**，不要臆测

**求解套路（写模拟器，勿纯脑推）**：
- 按反编译逐 case 复刻小型模拟器（JS/Python），严格按 pc 顺序执行
- 输出缓冲通常与输入同下标独立变换：`out[i] = f_i(in[i])` → 每个位置**可独立暴力**（可打印字符 32~126，逐位凑校验值）
- 校验比较处（`out[i] == 常量[i]`）是最终判据；拿已知输入先验证模拟器行为再反解

**已知陷阱**：
- 校验常量按**有符号 int8** 存放：`-89` 即 `0xA7`，比较两边都要 `& 0xff`
- "就地写回" opcode 会覆盖输入缓冲，改变后续读到的值——模拟器不能偷懒跳步骤
- 字节码表里 `7, x, 7, y, ...` 连续成串的"opcode 7 + 操作数"就是逐字节校验序列，直接给 AI 当靶子

### 4.1 单指令 VM（NAND-only 型）

另一种 VM 形态：**只有一种指令**（典型：`v[a] = ~(v[b] & v[c])`），靠 NAND 完备性构造所有逻辑。
d3sky 就是这种：没有结构体、没有 vm_init/vm_start，但本质一致。

**识别**：
- 解释器里没有 switch/dispatch 大循环，只有**一条** `~(x & y)` 赋值在循环里反复执行
- 输入按 4 字节一组处理（opcode[2772..] 是输入存储区）
- 有标志位：某位置 1 时输出、置 0 时读输入（opcode[2]/opcode[7]/opcode[19]）

**求解**：
- 每个输入字节的变换是**独立的 XOR 链**：`cpdata[i] = in[i] ^ in[i+1] ^ in[i+2] ^ in[i+3]`
- 直接 z3：37 个 BitVec + 34+3 条异或约束（末尾循环回开头）
- **z3 副本陷阱**（教程实测 10 小时坑）：对 flag 做 encode 时必须先 `encoded = encode(flag.copy())`，
  否则符号变量与位运算优先级会混乱，解出的值满足约束但不是真 flag

### 4.15 大数组电路型 VM（平坦数组 + 变长指令 + 恒定控制流）

和 §4.1 不同：这里**数组本身就是完整的程序**（几万到几十万项），不是几条 opcode。

**识别**（命中任一即按本节处理）：
- 附件里有一个巨大平坦数组（`m_mem = [...]`，几万项以上），旁边是 `while(1)` 取指循环
- 解释器**没有 switch**，用**操作数的符号位**区分指令类型：
  `a<=0 && b>=0 → 跳转` / `a<=0 && b<0 → 输出` / `a>0 && b<0 → 读输入` / `a>0 && b>=0 → 运算`
- 指令是**变长**的（定长切分会切出几万种"opcode"，明显不对）
- 用不同输入跑，**步数相近**（恒定控制流），输出却总是失败串

**第一步永远是 `vm_disasm`，不是手写模拟器**：

```
vm_disasm({ path: "attachment.html", array: "m_mem" })
```

它会自动判定定长/变长、切出指令、建基本块与跳转边、并生成可跑的骨架。
判断依据是否可信看两点：**覆盖率**（应接近 100%）与**类型分布**（应只有少数几种）。

**拿到骨架后**：
- 骨架里 `compute()` 与各类型分支是 TODO —— **必须**从反编译确认语义后再填。
  工具不知道 `mem[c] = ~(mem[a] & mem[b])` 还是 `+`；猜错会得到"看起来能跑但结果是假"的输出。
- 填对之后先跑**已知输入**验证行为（能打印出程序 banner / 提示串即说明管道通了），
  再决定是"复刻模拟器逐位反解"还是"z3 建模"。

**已知陷阱**：
- **mem 必须可扩容**：程序数组只是内存的一部分，指令会把结果写到程序区之外的下标。
  直接 `list(MEM_INIT)` 会 IndexError（生成骨架已内置 `ensure()` 扩容）。
- **恒定控制流 ≠ 无解**：失败串是常量输出，说明"选择"发生在数据单元上而非跳转上；
  不要因为"每次都打印 Sorry"就断定这题不可解。
- **z3 副本陷阱**（同 §4.1）：符号化 flag 时先 `encoded = encode(flag.copy())`，
  否则解出的值满足约束但不是真 flag。
- 数组若是**运行期解码**得来（不是字面量），先还原出数组再用 `vm_disasm`，
  否则工具只能看到密文。

### 4.2 VM 反调试：TLS 回调


除常规 `IsDebuggerPresent` 外，还有**线程回调**：`TlsCallback_0` 在线程创建时先于 main 执行。
典型对抗：检测调试状态 → 故意触发访问异常（读地址 0）→ 异常处理里跑真逻辑。
**绕过**：调试器停在 `IsDebuggerPresent` 返回后，把 eax 从 1 改 0；**不要改跳转指令**
（jz→jnz 会破坏后面的除零异常分支，程序依然起不来）。

### 4.3 模拟器之外的两条正路

教程里的三种解法按场景选择：

| 解法 | 适用 | 关键 |
|---|---|---|
| **手撕逆推** | opcode 操作都是可逆的（xor/加减/移位） | 从后往前反着跑 opcode，每步撤销变换 |
| **z3 约束** | 操作复杂但确定（混合运算/条件分支） | 建符号变量 + 把校验点全部转成约束；**必须先建副本再 encode** |
| **Frida 插桩爆破** | 单字节/双字节校验、程序能跑起来 | 逐字节试 32~126，看哪一位让"通过计数"增加 |

#### 4.3.1 循环分割识别法（第三篇教程）

打印出来的伪指令往往上千行，但真正有用的结构是**重复块**：
- 找一个"边界指令"（如 `jmp to fun0`、`R0=R1-->zf=0`、某个固定寄存器被赋值）
- 以它为界把整段切成 N 个块，每块结构几乎一致（只是下标 +1）
- 只分析第一块，其余照推——这是把"一千行指令"压缩成"40 个相同块"的关键

#### 4.3.2 Frida 爆破的完整框架（可直接抄）

适用：单字节/双字节校验、程序能正常跑、校验结果可通过某种"计数"区分。

```python
import subprocess, frida, time

known_flag = b''
flaglen = 40
target = r"C:\path\to\vm.exe"

jscode = open("frida/hook.js", "rb").read().decode()

def brute(F):
    def on_message(message, data):
        global result
        if message['type'] == 'send': result = message['payload']
    process = subprocess.Popen(target, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
    session = frida.attach(target.split('\\')[-1])
    script = session.create_script(jscode)
    script.on('message', on_message); script.load()
    process.stdin.write(F.decode()); output, _ = process.communicate()
    process.terminate()
    return result

count = len(known_flag)
new_number = brute(bytearray(known_flag + b' ' * (flaglen - len(known_flag))))
st = time.time()
while count < flaglen:
    flag = bytearray(known_flag + b' ' * (flaglen - len(known_flag)))
    number = brute(flag)
    if number != new_number:
        new_number = number; count += 1
    else:
        flag[count] += 1
        if flag[count] > 127: flag[count] = ord('?'); count += 1
print("耗时", time.time() - st)
print(flag.decode())
```

**关键**：`hook.js` 里 Hook 的是校验函数，把"已通过的字符数"作为 payload 发回 Python；
爆破侧逐位试，只要返回值变化就说明这一位对了。

#### 4.3.3 z3 的完整约束模板（可直接抄）

```python
from z3 import *

input = [BitVec('input_%d' % i, 8) for i in range(N)]   # N = flag 长度
cpdata = [0x0024, 0x000B, ...]                            # 校验值（从二进制读）

solver = Solver()
for i in range(N-3):
    solver.add(cpdata[i] == (input[i] ^ input[i+1] ^ input[i+2] ^ input[i+3]))
# 末尾循环回开头（如有）
solver.add(cpdata[N-3] == (input[N-3] ^ input[N-2] ^ input[N-1] ^ input[0]))
solver.add(cpdata[N-2] == (input[N-2] ^ input[N-1] ^ input[0] ^ input[1]))
solver.add(cpdata[N-1] == (input[N-1] ^ input[0] ^ input[1] ^ input[2]))
# 末位限制（题目给定，如最后一位是 ~）
solver.add(input[N-1] == 126)

if solver.check() == sat:
    m = solver.model()
    print(bytes([m[input[i]].as_long() for i in range(N)]))
```

**副本陷阱**：对 flag 做变换时必须先 `encoded = transform(flag.copy())`，否则位运算优先级混乱。

## 5. 反调试常见点（详见 ctf-antidebug skill）

- PE：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess(7)`、PEB BeingDebugged、`OutputDebugString`、rdtsc 时间差
- ELF：`ptrace(PTRACE_TRACEME)` 返回值检查、`/proc/self/status` 的 TracerPid、`sigaction` 信号陷阱

## 6. 动态取密钥（本工具环境）

### 6.0 入场条件：静态跑完再调试（**最重要的一条纪律**）

**动态调试不是探索手段，是取证手段。** 它只回答"这个值运行时是多少"，
不回答"这段代码在干什么"——后者静态反编译更便宜、更可复现。

启动调试器前，四条必须全满足：

1. **有函数清单**：`list_funcs` 拿到函数列表
2. **候选函数有职责描述**：每个候选能一句话说清（读输入 / 做变换 / 比对 / 解壳）
3. **写得出调试假设**：断点地址 + 命中后读哪个表达式 + 期望值 + 怎么判定
4. **有办法把执行流逼到那里**：入口断点 / 输入触发 / 定时触发 / 直接改 IP

写不出第 3 条 = 静态还没读够，**回反编译，不要启动调试器**。

标准流程：

```
阶段0 静态底图  list_funcs → decompile(主入口/候选) → xref(字符串/常量表)
                → scan_crypto(算法族) → globals_by_address(常量表内容)
阶段1 写假设    候选A 0x4012d0 check_input(buf,len)
                职责: XXTEA 加密后与 0x404060 比较
                要取: 入参 buf 指针、加密后缓冲区
阶段2 选模式    PE→本地 win32；ELF→Kali linux_server；Android→android_server+Frida
阶段3 窗口期    入口先下断点 / 目标有 sleep 窗口 / start 后立刻 suspend
阶段4 定向取证  一次命中批量读：寄存器 + 3 处关键内存 + 调用栈（不要来回单步几十次）
阶段5 增量收敛  运行时值 → 离线复算 → 与运行值比对，不一致先修假设
阶段6 收口      动态结论写回静态，脚本正向复现一次，产出 VERIFY
```

完整方法论见 wiki `reverse/method_static_first_dynamic.md`。

**工具侧状态语义**（`ida_dbg(action:"status")` 返回的 `state`）：
`-1` 已暂停（可单步/写内存）、`0` 无进程、`1` 运行中（单步必失败）、`2` 已退出。
`continue`/`run_to` 是异步投递，工具已自动轮询到真停下再返回。

**断点选址优先级**：
| 优先级 | 位置 | 理由 |
|---|---|---|
| 高 | 变换函数入口/出口 | 各断一次即得"输入原值→输出值"整段映射 |
| 高 | memcmp/strcmp 调用点 | 直接看到"期望 vs 实际" |
| 中 | 解密循环内部 | 只在需要轮密钥/中间态时 |
| 避免 | 消息循环、sleep、CRT 初始化 | 等于没断 |

**三个高频假故障**（别误判成工具不可用）：
- 断点"设了却不命中" → 目标在调试器下完断点之前就跑过去了（给它 sleep 窗口，或先在入口断）
- PIE 目标用静态地址下断点失效 → 必须用运行时重定位后的地址
- 运行态（`STATE=1`）单步/写内存失败 → 先 `suspend` 或等断点命中

**SMC 场景**：静态看到的是密文/乱码。正确顺序是**在解密循环结束处下断点**，
命中后 dump 解密后的真实字节，再对 dump 结果重新静态分析。

### 6.1 具体手段

- Windows PE：Frida 本地附加 `frida -n target.exe`，Hook 变换函数地址（RVA）读 RCX/RDX/R8/R9
- 找 RVA：IDA 地址 - ImageBase（PE 头的 ImageBase，ASLR 下运行时用 Module.findBaseAddress 加 RVA）
- ELF/Android SO：`frida -H 127.0.0.1:27042` 远程
- 32 位 GUI 题：跨位数窗口消息不可靠，**优先在读输入的指令下断点后直接 `dbg_write` 改缓冲区**

## 7. 输出契约

- `[FLAG]...[/FLAG]`：有把握时
- `[VERIFY]{"algo":"tea|xtea|rc4|xor|aes_ecb|base64|custom","key":"hex","ciphertext":"hex|base64","encoding":"hex|base64","expected":"..."}[/VERIFY]`
- `[HYPOTHESES][{"algo":"xtea","key":"...","ciphertext":"...","encoding":"hex","variant":"le32"},...][/HYPOTHESES]`
- custom 类型时 VERIFY 里额外给 `code`：一段完整的 Python 解密函数 `def decrypt(data: bytes, key: bytes) -> bytes`
- VM 题 custom 脚本 = 常量表 + 模拟器 + 逐位反解，三段齐全才算完整
