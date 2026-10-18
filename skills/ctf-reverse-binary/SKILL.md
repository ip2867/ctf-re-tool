---
name: ctf-reverse-binary
description: PE/ELF 二进制逆向方法论：查壳脱壳、IDA 定位关键函数、VM 字节码题专项、算法识别入口、静态分析套路。拿到 EXE/DLL/ELF/SO 题目时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 二进制逆向方法（PE / ELF）

## 流程总览

```
EXE/ELF → DIE查壳 → (有壳:脱壳) → IDA静态
  → 定位main/WinMain → 搜关键字符串 → 交叉引用到比较点
  → 识别算法（含 VM 字节码型）→ (反调试?绕过) → 动态取密钥 → 解密
```

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

- Windows PE：Frida 本地附加 `frida -n target.exe`，Hook 变换函数地址（RVA）读 RCX/RDX/R8/R9
- 找 RVA：IDA 地址 - ImageBase（PE 头的 ImageBase，ASLR 下运行时用 Module.findBaseAddress 加 RVA）
- ELF/Android SO：`frida -H 127.0.0.1:27042` 远程

## 7. 输出契约

- `[FLAG]...[/FLAG]`：有把握时
- `[VERIFY]{"algo":"tea|xtea|rc4|xor|aes_ecb|base64|custom","key":"hex","ciphertext":"hex|base64","encoding":"hex|base64","expected":"..."}[/VERIFY]`
- `[HYPOTHESES][{"algo":"xtea","key":"...","ciphertext":"...","encoding":"hex","variant":"le32"},...][/HYPOTHESES]`
- custom 类型时 VERIFY 里额外给 `code`：一段完整的 Python 解密函数 `def decrypt(data: bytes, key: bytes) -> bytes`
- VM 题 custom 脚本 = 常量表 + 模拟器 + 逐位反解，三段齐全才算完整
