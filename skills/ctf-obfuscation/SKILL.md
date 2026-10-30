---
name: ctf-obfuscation
description: 花指令/垃圾代码/不透明谓词（junk code, opaque predicate）的识别与修复。当反编译失败、IDA 标 "sp-analysis failed"、伪代码错乱、出现 loc_XXXX: ; CODE XREF 可疑标签、代码段有红色 db、函数边界异常时使用。覆盖 x86/x64 PE 与 ELF，含 11 类特征速查与可直接执行的修复策略。
---

# 花指令识别与修复（CTF 逆向）

## 0. 一句话 + 一条纪律

花指令 = **构造永恒跳转（保证垃圾不执行） + 插入垃圾字节（破坏反汇编器的指令边界）**。
修复 ≠ 加密破解；修好后反编译即恢复可读。

> **纪律（最重要）**：IDA 里看到
> `.text:00004D8D  loc_4D8D:  ; CODE XREF: .text:00004E08↓j`
> **只表示该地址被跳转引用，不等于它是花指令**。必须再查三件事：
> ① 跳转目标是否**非对齐**（`loc_4D8D+1` / `+2`）
> ② XREF 是否指向**指令中间**
> ③ 上下文是否**错位**（红色 `db`、孤立操作码、反汇编断裂）
> 只看 XREF 就下结论 = 误判。

---

## 1. 原理：为什么 1 个垃圾字节能毁掉整段反编译

反汇编器默认**线性扫描**：从入口依次解码，不递归进分支。
x86 指令长度可变（1~15 字节），解码**顺序依赖**：
**任何一处多算/少算 1 字节 → 后面所有指令的起点全偏。**

所以最有效的花指令不是"塞无意义指令"，而是塞**"看起来像指令前缀"的单字节**，
让解码器把后续几字节当成它的操作数吃掉：

| 垃圾字节 | 被误认为 | 后果 |
|---|---|---|
| `E8` | `call rel32` | 吃掉后续 4 字节 |
| `E9` | `jmp rel32` | 吃掉后续 4 字节 |
| `EB` | `jmp rel8` | 吃掉后续 1 字节 |
| `0F` | 双字节 opcode 前缀 | 吃掉后续 1 字节 |
| `68` / `6A` | `push imm32` / `imm8` | 吃掉 4 / 1 字节 |
| `C7` | `mov r/m32, imm32` | 吃掉 ModRM + 4 字节 |
| `74` / `75` | `jz` / `jnz rel8` | 吃掉 1 字节 |

---

## 2. 11 类特征速查（按 IDA 里的样子认）

### F01 假跳转目标 / 非对齐跳转 ⭐最典型
```asm
.text:00004E08    jmp     loc_4D8D+1      ; ← 目标 +1，落在指令中间
```
- 特征：目标带 `+1`/`+2` 偏移；XREF 指进指令中间；后续出现红色 db
- 判据：**跳转目标必须是指令起点**（否则程序跑不起来）→ 目标非对齐 = 那里不是真目标
- **修复**：nop 掉这条跳转本身

### F02 永真 / 永假条件跳转
```asm
xor  eax, eax        ; ZF=1
jz   real_code       ; 恒跳
call sub_YYYY        ; ← 被当成"跳过"的垃圾，实际永不执行
```
- 特征：条件由前序赋值唯一决定（`xor/sub/test/cmp r,r`、`cmp r,imm`、`clc`）
- **修复**：① 改成无条件 `jmp`（`EB rel8` / `E9 rel32`）；或 ② nop 掉跳转本身 + nop 垃圾

### F03 call/ret 地址操纵
```asm
call sub_XXXX
...
sub_XXXX:
    add dword ptr [esp], 5    ; 改返回地址
    retn                      ; 跳到 call 之后 +5，越过垃圾
```
- 特征：被调函数极短；内部 `add/sub [esp], N`；retn 后落到 call 之后的偏移
- **修复**：⚠ **不要盲 nop**（会破坏返回地址）→ 动态单步跟一次，或直接跳过整个 call

### F04 call $+5 型（**多数是正常的，注意排除**）
```asm
call $+5
pop  eax          ; 取 EIP
```
- 本质是 PIC 取址惯用法。**只有 pop 的结果完全未被使用时**才是花指令
- 判据：看该寄存器后续是否参与运算/间接跳转
- 实测：Matr1x 有 78 处，全改后行为无变化 → 已列为**排除项**

### F05 简单 jmp / 多层跳转链
```asm
jmp short skip_junk
db  0x66, 0x90        ; 垃圾
skip_junk:
```
- 特征：`jmp +1..4` 跳过极短垃圾；或多条 jmp 串联
- **修复**：nop 掉 jmp 本身（nop 后顺序执行会落入垃圾的情况例外，见下）

### F06 操作码污染 / 字节错位
```asm
.text:...    db 0E8h        ; 孤立操作码
.text:...    call near ptr loc_XXXX+1
```
- 特征：1 字节孤立操作码；前后是 ret/jmp；IDA 显示红色 db
- **修复**：IDA 里按 `D` 转数据 → 从正确位置按 `C` 转代码 → 按 `P` 重建函数

### F07 伪造函数 / 伪调用
- 特征：`call sub_XXXX` 但 XREF 是 `↓p` 且指向指令中间；函数边界异常
- **修复**：确认后 `undefine` 该"函数"，从真实起点重建

### F08 异常交叉引用
- 与 F01 同源，但强调"XREF 指进指令中间"这个观测
- **修复**：双击跳到**来源**看跳转目标是否对齐

### F09 垃圾指令序列
```asm
nop / xchg eax,eax / push eax; pop eax / inc eax; dec eax
```
- 特征：不影响程序状态的冗余指令，栈平衡但无意义
- **修复**：可安全 nop（净效果为零）

### F10 栈指针混淆
```asm
add esp, 4
jmp loc_XXXX
...
sub esp, 4
```
- 特征：函数内 esp 增减不平衡；retn 前才恢复
- **修复**：跟踪 esp 变化，确认是跨越花指令后再处理

### F11 跳转到数据
- 特征：跳转目标落在 db 数据区；按 `C` 可转代码
- **修复**：在 IDA 里按 C 尝试转代码，转不了就是数据

---

## 3. 修复流程（可执行）

### 3.1 用工具（推荐）

```js
// 1) 先看有什么特征（不写文件）
junk_repair({ path: "chall.exe", dryRun: true })

// 2) 修补（只 nop 跳转本身，字节偏移不变）
//    写盘后工具会**自动**让 IDA 重新分析修补后的文件并等到就绪
junk_repair({ path: "chall.exe" })
// → 产出 chall_repaired.exe，且 IDA 已切到新库

// 3) 直接在新库上反编译（不需要再手动 open）
//    ida_list_functions → ida_decompile
//    若需要手动重开：ida_open_file({ path: "chall_repaired.exe" })
//    ⚠ ida_open_file 会**自动拉起 IDA**（若没在跑），并等 MCP 端口就绪。
//      所以它失败时不要推断"本机没装 IDA"——先看返回里"未监听/设置里没有路径"那几行说明，
//      按提示修环境（设置页填 ida64.exe 路径 / 确认 IDA 里 MCP 插件已启用）。
```

工具返回里每条候选都标了：
- `feature`：属于 11 类中的哪一类
- `evidence`：命中的具体证据（如"目标 0x27b0 不落在指令边界上"）
- `reason`：判定链
- `strategy`：`nop_jump`（等长 NOP）/ `to_jmp`（改无条件 jmp）/ `report_only`（需人工）

**实测效果（Matr1x，ELF32，2026-10-26 用本工具链复测）**：
```
非边界跳转目标: 301 → 70   (-76.7%)      ← 最硬的边界判据
边界图冲突点:   427 → 32   (-92.5%)      ← 交叠污染的收敛证据
不可达区间段数: 115 → 59                 ← 碎片被重新连成函数
IDA 识别函数:    54 → 90   (+36)
可反编译函数:    35 → 50   (+15)
```

⚠ **不要用"反编译成功率"判断修补是否有效**。原始文件 54 个函数里成功率 87.5%，
修补后 90 个函数里成功率 65.8% —— 这不是变差，而是**分母里多了 36 个原本根本
识别不出来的函数**，其中有 26 个是重度混淆的大函数。正确判据是：
1. `junk_repair` 返回的「非对齐跳转下降百分比」
2. **能反编译出可读伪代码的函数绝对数**（35 → 50）

实测关键函数逐个对比（原始全失败 → 修补后可读）：

| 函数 | 作用 | 原始 | 修补后 |
|---|---|---|---|
| `0x53D5` | 比对并打印 | ✗ | ✅ 197 字符 |
| `0x4EDF` | 读入 + 打包 | ✗ | ✅ 1242 字符 |
| `0x53A5` | 转调 | ✗ | ✅ 232 字符 |
| `0x4638` | 核心校验 | ✗ | ✗（最重的混淆，仍需动态） |

**多实例注意**：机器上同时开多个 IDA 时，MCP 的 `open_file` 有时拿不到新实例端口
（用"启动前后快照差集"判断，会失效）。工具的 `idaReloadAndWait` 已内置兜底：
用 `list_instances` 按**路径**匹配，再 `select_instance` 精确切换。
手工时也可以用这两个工具自己完成。


### 3.2 手工（IDA 里）

```
1. 光标移到垃圾起始 → 按 D（转数据）
2. 选中垃圾范围 → 按 U（undefine）或直接 patch 成 0x90
3. 按 C（转代码）重新反汇编
4. 光标移到函数开头 → 按 P（声明函数）
5. Tab / F5 看伪代码
```

**IDAPython 一键版**：
```python
import ida_bytes, ida_ua, idc

def nop_range(start, end):
    for ea in range(start, end):
        ida_bytes.patch_byte(ea, 0x90)

def make_code(ea, n=1):
    cur = ea
    for _ in range(n):
        if ida_bytes.is_code(ida_bytes.get_flags(cur)): break
        h = idc.get_item_head(cur)
        if h != cur:                      # 落在别的指令内部 → 先破坏
            ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, cur - h + 16)
            cur = h
        if not ida_ua.create_insn(cur): break
        cur += idc.get_item_size(cur)
```

> ⚠ `del_items` / `DELIT_SIMPLE` 在 `ida_bytes`，**不在** `ida_ua`。
> ⚠ `create_insn` 无法在"已有指令内部"创建，必须先 `del_items`。
> ⚠ 批量 `create_insn` + `auto_wait()` 会被 IDA 的 auto-analysis 反复推翻（实测：建 1054 条、被拆 1054 条，覆盖率不变）→ 要走 boundary/tracing。

### 3.3 IDC 批量模板

```c
#include <idc.idc>
static matchBytes(StartAddr, Match) {
    auto Len, i, PatSub, SrcSub;
    Len = strlen(Match);
    while (i < Len) {
        PatSub = substr(Match, i, i+1);
        SrcSub = form("%02X", Byte(StartAddr));
        SrcSub = substr(SrcSub, i % 2, (i % 2) + 1);
        if (PatSub != "?" && PatSub != SrcSub) return 0;
        if (i % 2 == 1) StartAddr++;
        i++;
    }
    return 1;
}
static main() {
    auto Addr, Start, End, Cond, i;
    Start = 0x00401000; End = 0x00405000;
    Cond = "33DB85DB7502740121????";   // xor ebx,ebx; test; jnz+2; jz+1; and
    for (Addr = Start; Addr < End; Addr++) {
        if (matchBytes(Addr, Cond)) {
            for (i = 1; Byte(Addr+i) != 0x58; i++) {   // 到 pop eax 停
                PatchByte(Addr+i, 0x90);
                MakeCode(Addr+i);
            }
        }
    }
    AnalyzeArea(Start, End);
}
```

已知字节特征（来自公开题解）：
```
33 DB 85 DB 75 02 74 01 21     xor ebx,ebx; test; jnz+2; jz+1; and
83 F8 00 72 02 73 01 E8        cmp eax,0; jb+2; jnb+1; call
74 03 C2 C7                    jz+3
E8 05 00 00 00 E8 01 00 00 00 36 8B 44    call+pop+jmp 跳板
```

---

## 4. 易错点（全部实测踩过）

| 错误做法 | 后果 | 正确做法 |
|---|---|---|
| 只看 `loc_XXXX: ; XREF` 就判花指令 | 误判一堆正常跳转 | 必须查目标对齐性 + XREF 是否指进指令中间 |
| 见到 `xor r,r` + `jnz` 就整段 nop | **SIGSEGV**（把正常清零当垃圾） | 必须证明条件恒定（目标同/短跳过/非对齐） |
| 把整段（前序 xor/test + 跳转 + 垃圾）一起 nop | 后续指令重新错位（实测不可解码 4→7） | **只 nop 跳转本身**，字节偏移不变 |
| 把 `call $+5; pop` 当花指令 | 无收益（PIC 取址） | 检查 pop 结果是否被使用；未用才算花指令 |
| 把 `jmp $`（`E9 00 00 00 00`）改成 `call` | 无任何变化 | 那是 PIC 取址，不是花指令 |
| 批量 `create_insn` 后 `auto_wait` | 被 auto-analysis 反复推翻 | 先 `enable_auto(false)` 或改走动态 |
| 修完不按 P 重建函数 | IDA 仍按旧边界显示 | 按 P；或 `del_func + add_func` |
| 32 位 ELF 在 64 位 Linux 跑 | `No such file or directory` | `dpkg --add-architecture i386 && apt install libc6:i386` |

---

## 5. 静态搞不定时：动态优先

花指令交叠污染严重（几百处短跳转互相影响）时，静态方法会陷入死循环
（实测：IDA 建 1054 条被拆 1054 条）。**执行路径是地面真值**：
程序真的跑过的地址必然是指令起点，不受任何静态解码错位影响。

### 5.0 代码被切成很多段、跳转目标是算出来的 → `emu_trace` + `ida_apply_trace`

**最优先判断**：如果 IDA 里看到大量互不相连的短小片段，中间隔着一个
`jmp rax`（或 `jmp [table+idx*8]`），而每段开头都是 `mov [rbp+var_XX], <数字>`
再 `call push_...`，那就是**分段 dispatch**（也叫 VM / 虚拟机保护）：

```
loc_401108:  mov [rbp+var_D0], 2      ← 把"段号 2"压进栈
             ...
             call push
             jmp  switch              ← 间接跳转，目标 = lookup(2)
```

跳转目标只在运行期存在，静态 CFG 因此是碎的，反编译当然读不懂。
**不要**逐段硬读、也不要手工给几百个段加 xref——那是题目作者当年手工干的活。

正确链路（两步，工具已内置）：

```js
// ① 真跑一遍，记录每次间接跳转实际去了哪里
emu_trace({ binary:"/tmp/chall", start:"<要调用的函数地址>", mode:"function" })
// → 返回脚本 + 摘要。摘要里的这行就是跳转表：
//   IND <跳转点> -> N targets: v=<段号> <段地址>(x1)  v=<段号> <段地址>(x1)
//   ↑ 左边是"段号"，右边是该段号对应的真实段地址
// → 轨迹 JSON 默认落在 cwd/emu_trace.json（含 indirect_sites / edges / exec_ranges）

// ② 把轨迹回填进 IDA，让各段连成一片
ida_apply_trace({ trace: "<上一步的轨迹对象或 JSON 路径>" })
// → 对每个目标 create_insn、每条边 add_cref、可选 add_func
// → 之后 ida_decompile 目标函数应能读出完整循环/状态机
```

回填后**每段还能单独 `ida_decompile`**（`make_funcs` 默认 true），
逐段还原语义比读一整坨 switch 快得多。

若仍有断段：`ida_apply_trace({trace, code_ranges:true})` 把执行过的整个区间都 MakeCode。

**判断 dispatch 是否已经还原成功**：反编译里出现 `while` / `for` 循环，
且循环体里只剩算术（`^ & | << >> + -`）与少量 `if`，就说明段已合并、语义已可读。
此时进入 §5.4。

**注意**：动态链接的 ELF（有 `PT_INTERP`）**不要用 `mode:"entry"`**——入口是
`ld.so`，仿真不出来。用 `mode:"function"` 直接调目标函数；工具摘要会给出这条提示。

### 5.4 校验是可逆运算时：直接逆向逐轮反解（不要上 Z3）

算法读出来后，先判断它**是不是可逆的**。如果循环体只由这些操作组成：

| 操作 | 逆运算 |
|---|---|
| `x ^= y` | `x ^= y`（自逆） |
| `x = ~x` | `x = ~x`（自逆） |
| `x = (x << 1) \| (x >> 63)` | `x = (x >> 1) \| (x << 63)` |
| `t = x; x = y; y = y + t` | `t = x; x = y - t... `（按写出顺序逆序回退） |
| `x += y` | `x -= y` |

那就**不需要**符号执行：从目标值出发，把每轮操作**逆序**执行一遍就还原出输入。
这是最省时、最可靠的路（实测：这类 1024 轮循环体往往全部可逆，倒推只需几毫秒）。

**别手写逆函数——用 `rev_solve`**。手写极易把逆向顺序写错（尤其"交换后相加"和
"交叉循环移位"），而错了以后回代会失败却不知道错在哪一步。工具会把循环体声明成
算子列表，自动生成：正向 / 逆序 / **正逆互逆自检** / 反解 / 回代验证。

```js
rev_solve({
  regs: ["X", "Y"], width: 64, rounds: 0x400,
  ops: [                                   // 按正向顺序写循环体
    { op:"xor_cond_not", dst:"Y", src:"X" },   // Y ^= (~X if X 偶 else X)
    { op:"not", reg:"X" },                     // X = ~X
    { op:"rotl_cross", hi:"X", lo:"Y" },       // (X,Y) 当整体循环左移 1
    { op:"swap_add", a:"X", b:"Y" },           // t=X; X=Y; Y=Y+t
    { op:"rotl_cross", hi:"X", lo:"Y" }
  ],
  target: ["<目标X>", "<目标Y>"]
})
// → 生成脚本；run_python 跑。必须看到两行才算真解：
//     SELFCHECK_OK   ← 正逆互逆通过（不通过=算子表写错，别信后面）
//     VERIFY = PASS  ← 回代精确命中目标
//   INPUT_TXT / INPUT_HEX 才是答案
```

可用算子：`xor` / `xor_const` / `xor_cond_not` / `not` / `rotl_single` / `rotr_single` /
`rotl_cross` / `rotr_cross` / `add` / `sub` / `swap` / `swap_add` / `mul_const`（仅奇数）。
**含 `& 掩码`、`| 或`、查表/S-box 的循环不能这样逆**，那些信息已经丢失，转 §5.2。

一个提醒：`xor_cond_not` 这类"条件依赖另一个寄存器"的算子，条件读的必须是
**该算子执行时**的值。逆序回退时若顺序写错，自检会立刻抓到——这就是自检存在的意义。

做法：
1. 把还原出的伪代码写成 `def f(X, Y)`（正向），再用真值核对：
   跑一趟 `emu_trace` 拿返回寄存器值，与 `f(0,0)` 比对（`mode=function` 时
   `regs.rax/regs.rdx` 就是返回值）。
2. 写 `def g(X, Y, rounds)`：从 `rounds-1` 到 `0` 逆序回退。
3. `g(目标X, 目标Y)` 即输入，打包成字节（注意小端/大端）验证。

**只有**在不可逆（含 `&`、`|`、`*`、查表、S-box）时才走 `angr_solve`。
先问一句"这个循环能不能倒着走"，往往能省掉几百秒的符号执行。

### 5.1 先用工具的三个运行期原语（别手工单步）

```js
// ① 反推"这段代码把数据改成了什么"——混淆 handler 的首选
ida_dbg({ action:"snapshot_diff",
          regions:[{addr:"0x13200", size:216}],   // 要观察的数据块
          mode:"until_return" })                  // 跑到当前函数返回
// → 返回逐字节变化清单（offset / before / after），置换表直接就出来了
// 之后接着调：ida_dbg({action:"snapshot_diff", mode:"once"})

// mode 选择：
//   until_return  整个 handler 做了什么（最常用）
//   single_step   单条指令的效果（看某一条具体改了什么）
//   until_addr    跑到指定地址（需 target，适合"跨函数看一段"）
//   manual / once 先拍 before，人工做点别的，再差分

// ② 让被混淆提前打断的循环跑满
ida_dbg({ action:"force_continue",
          set:[{reg:"eax", value:1}],   // 强制把退出条件改成"继续"
          then:"continue",
          repeat:6,                      // 跑 6 次（对应 6 行校验）
          bp_addr:"0x46bd" })            // 在循环判断处反复命中
// → 每个 ITER 都打印 IP 和 SET 结果

// ③ 判断"这个函数只校验了一行还是一整块"
ida_dbg({ action:"global_reads", func:"sub_4638" })
// → GLOBAL_REFS / STRIDES / ELEMENT_WIDTH
//   若引用元素数 < 一行宽度 ⇒ 该函数只处理一行，调用方在循环里喂多次
//   ⇒ 说明还有 N 组常量没抓到，回头找调用方
```

### 5.00 拿到题目目录，先 `file_digest` 把材料全看一遍（最优先）

**这是最容易被跳过、但收益最大的一步。** 题目附件往往不止一个文件：

```
DancingKeys.sys            22KB   要反汇编的目标
题面（必须给出）.docx      13KB   内容只有两行：
                                   "这是什么?"
                                   "25 40 5a 86 b5 f1 3e 58 80 9b db 0b 30 49 66 8c"
```

后面那串就是**要解的 16 字节密文**。不先读题面，你得先花大量工具调用去猜
"这个驱动在校验什么"；读了题面，一句话就知道目标。

```js
list_dir({ path: "E:\\...\\题目目录" })      // 先看有哪些文件
file_digest({ dir: "E:\\...\\题目目录" })    // 一次读全部，逐格式自动提取文本
// 也可指定多个：file_digest({ paths: ["a.sys", "题面.docx", "note.md"] })
```

`file_digest` 自动处理各种形态（**不需要按扩展名自己挑工具**）：

| 类型 | 处理 |
|---|---|
| 文本/代码 txt md json py c go rs js pem… | 给全文（超长截断保留头尾） |
| docx / xlsx / pptx | 解包抽正文（题面常在这里） |
| PDF | 解 FlateDecode 抽 Tj/TJ 文本 |
| 图片 png jpg gif bmp | 尺寸 + "读图用 OCR 或直接看图"的提示 |
| 归档 zip jar apk | 列条目名 |
| 其它二进制 | 魔数（PE/ELF/DEX/WASM/pcap）+ 熵 + strings |

它会自动跳过**工具中间产物**（`.id0/.i64/.nam/.til` 等 IDA 数据库、`.o`、Office 锁文件
`~$xxx.docx`）——实测目录里 7 个文件有 5 个是 IDA 生成的，不排除就会读到 `EBUSY` 并污染判断。

> **判断权在模型**：工具只负责"把每个文件变成人能读的样子"，
> 哪个是题面、哪个是要分析的目标，由看内容决定，不由工具替你挑。

### 5.5 格式前缀/常量字符串：用 `recover_string` 还原，不要靠"读伪代码记"

**这是最容易翻车、又最容易被忽略的一步。**

校验代码常写成逐字节比较：

```
cmp byte ptr [rbx+0], 0x62   ; 'b'
cmp byte ptr [rbx+1], 0x79   ; 'y'
cmp byte ptr [rbx+2], 0x74   ; 't'
...
```

伪代码里它会折叠成 `"bytectf{"`，但**人在读伪代码、抄进笔记、再转述时，极易少一个字符**。
实测（NaughtyBoy）：`bytectf{` 被抄成 `bytecf{`，所有输入在第一步就被拒，
而日志里只报"校验失败"——**完全看不出是前缀抄错了**，会让人往算法方向深挖，白耗几小时。

```js
recover_string({ func: "Java_..._SignTools_check" })
// 或把已有反汇编贴进来：recover_string({ disasm: "<ida_disasm 的输出>" })
// → 返回 text（真实字节）、hex、以及"与已知前缀只差 1-2 字符"的警告
```

它按偏移把 `cmp` 的立即数拼回原文，是**确定性**的。规则：
- **以工具输出为准**。如果工具说 `bytectf{` 而你笔记里是 `bytecf{`，那就是笔记错了。
- 工具会主动提示"你提取的 X 与已知前缀 Y 只差 N 个字符"——出现这种提示要立刻回头看原文。
- 识别 Intel（`cmp byte ptr [reg+disp], imm`）与 AT&T（`cmpb $imm,disp(%reg)`）两种语法。

同理适用于：**固定密钥、magic 常量、比较用的表名**——凡是从反汇编里"抄"出来的东西，
都应该让工具抽，而不是肉眼转录。

### 5.2 静态读不动算法时：符号执行（angr）

被混淆的函数"做了什么"读不出来，但**知道成功分支在哪**时，让 angr 反求输入：

```js
angr_solve({
  binary: "/tmp/chall",
  find:  ["0x5B90"],        // 打印 flag 的分支
  avoid: ["0x5BB9"],        // 失败分支
  main:  "0x4EDF",          // 主函数（call_state 入口）
  stdin_len: 32,
  hooks: [{addr:"0x39E3", kind:"opaque_jump"}]   // 间接跳转点
})
// → 生成脚本；用 run_python（本机）或 remote_exec（Kali）跑
// → 看 INPUT_HEX= 即所求输入
```

**两个必须知道的前提**（都是实测踩出来的）：

1. **绝不要用 `entry_state`**。它先进 `__libc_start_main`，该调用不返回，
   simulation manager 直接耗尽（实测 0 个 state）。必须 `call_state(主函数)`。
2. **间接跳转必须 hook**。混淆函数常经全局函数指针跳转，angr 会顺指针
   把常量表字节当代码解码，报 `IR decoding error`。把那些点写进 `hooks`。

若返回 `NO_SOLUTION` 且 `ERRORED>0`，看 `ERR0=` 的地址——那通常是**又一个**
未 hook 的间接跳转点，加进 hooks 重跑。

### 5.3 手工路线（工具不可用时）

```bash
# x64dbg: 调试 → 跟踪 → 步入（记录每条指令 + 寄存器）
# IDA:    Debugger → Trace → Instruction tracing
# gdb:    record / 单步脚本（commands + set 那套等价于 force_continue）
```

---

## 6. 30 秒判定清单

1. 反编译失败 / 伪代码错乱 / `sp-analysis failed` → 怀疑花指令
2. **拿到题目目录先 `file_digest({dir})` 通读全部材料**（见 §5.00）——题面里常有密文/要求，
   不读就动手等于盲猜
2. 看到 `loc_XXXX: ; XREF ↓j` → **先别下结论**，查三件事（对齐/XREF/上下文）
3. 目标带 `+1`/`+2` → F01 假跳转，nop 跳转本身
4. 前序 `xor/test/cmp r,r` + jcc → F02 永真永假
5. 被调函数内有 `add [esp],N` + retn → F03 跳板（动态确认）
6. 孤立 `db 0E8h` → F06 操作码污染（按 D → C → P）
7. 以上都没有但反编译仍坏 → 走 `junk_scan mode=boundary` 看不可达区间，再不行上动态
8. **大量互不相连的短片段 + `jmp rax` + `mov [rbp-X], <数字>` → 分段 dispatch，
   立刻 `emu_trace` 记录跳转目标、`ida_apply_trace` 回填**（见 §5.0）
9. 混淆 handler 读不懂 → **别读代码**，`snapshot_diff` 量它的效果（见 §5.1）
10. 循环被提前退出、常量抓不全 → `force_continue` 让它跑满（见 §5.1）
11. 只抓到一行的常量 → `global_reads` 确认是否单行校验，再找调用方（见 §5.1）
12. **算法已读出且只含 `^ ~ + - 移位` → 先判断可逆性，逐轮逆序反解**（见 §5.4），别急着上 angr；
    用 `rev_solve` 生成脚本（自带正逆自检 + 回代验证），不要手写逆函数
13. **看到逐字节 `cmp ..., imm` → 立刻 `recover_string` 还原真实前缀**（见 §5.5）。
    这类字符串靠抄必错，而错了的现象只是"校验失败"，极难反查
13. 知道成功分支但算法读不出（含 `& | *` 查表等不可逆操作）→ `angr_solve` 反求输入（见 §5.2）
