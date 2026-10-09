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
