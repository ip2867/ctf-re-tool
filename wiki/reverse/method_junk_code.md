---
title: 花指令识别与修复（11 类特征速查）
tags: [花指令, junk code, opaque predicate, 反混淆, 线性扫描, 指令边界, 栈平衡, ida]
keywords: [花指令, 花指令怎么去, 反编译失败, sp-analysis failed, 垃圾代码, 永真跳转, 永假跳转, 假跳转目标, 非对齐跳转, 指令错位, 解码错位, _emit, 代码段 db, loc_XXXX, CODE XREF, 花指令识别, 花指令修复, 函数边界错误, 栈指针混淆, call ret 跳板, PIC 取址]
difficulty: 中
one_liner: 花指令靠"永恒跳转+垃圾字节"让线性扫描解码错位；修法按特征分类，最安全的是**只 nop 跳转本身**（字节偏移不变），实测非边界跳转目标可降 96.7%、IDA 识别函数 54→93。
---

# 花指令识别与修复（11 类）

## attack_chain

- 症状：反编译失败 / `sp-analysis failed` / 伪代码错乱 / 出现红色 `db` / 函数边界异常
- **先排除误判**：`loc_XXXX: ; CODE XREF: ...↓j` 只表示"该地址被跳转引用"，不等于花指令。
  必须再查三件事：① 目标是否非对齐（`+1`/`+2`）② XREF 是否指进指令中间 ③ 上下文是否错位
- 原理：线性扫描顺序解码 + x86 变长指令 → **1 字节偏差毁掉整段**
- 定位：找目标非对齐的跳转（最硬判据）→ 查前序是否有确定标志位（`xor/test/cmp r,r`、`cmp r,imm`、`clc`）
- 修复：**只 nop 出问题的跳转指令本身**（等长 NOP），或改成无条件 `jmp` 越过垃圾
- 收尾：IDA 里 `D` 转数据 → patch → `C` 重新反汇编 → `P` 重建函数 → `F5`
- 静态卡住（交叠污染：几百处短跳转互相影响）→ 动态 `Run Trace`，执行路径是地面真值

## 11 类特征

| 编号 | 名称 | IDA 里的样子 | 修复 |
|---|---|---|---|
| F01 | 假跳转目标/非对齐 | `jmp loc_4D8D+1` | nop 跳转本身 |
| F02 | 永真/永假条件跳转 | `xor eax,eax; jz L; call junk` | 改 jmp 或 nop |
| F03 | call/ret 地址操纵 | 被调函数内 `add [esp],5; retn` | ⚠ 动态确认 |
| F04 | `call $+5; pop` | 取 EIP | **多数正常，看结果是否被用** |
| F05 | 简单 jmp/多层链 | `jmp short skip; db junk` | nop 跳转本身 |
| F06 | 操作码污染 | 孤立 `db 0E8h` | `D`→`C`→`P` |
| F07 | 伪造函数 | `call sub_X` 但 XREF 指进中间 | undefine + 重建 |
| F08 | 异常交叉引用 | XREF 指向非指令开头 | 回看来源跳转 |
| F09 | 垃圾指令序列 | `nop`/`xchg eax,eax`/`push; pop` 同寄存器 | 可安全 nop |
| F10 | 栈指针混淆 | `add esp,N; jmp …; sub esp,N` | 跟踪 esp |
| F11 | 跳转到数据 | 目标落在 db 区 | `C` 试转代码 |

## reasoning_chain

- 先问"为什么反编译会坏"→ 线性扫描顺序依赖，1 字节偏差毁整段 → 花指令本质是**制造解码错位**
- 再问"垃圾怎么保证不执行"→ 必须有永恒跳转 → 构造方式决定家族（互补条件 / 确定标志位 / call+ret / 标志位技巧）
- 再问"怎么可靠识别"→ 单看跳转不够、单看 xor 也不够 → **"目标非对齐"是最硬的判据**（跳转目标必须是指令起点）
- 最后问"nop 到哪"→ **只 nop 跳转本身**，不动前后字节

## key_observations

- **只 nop 跳转本身的实测效果**（Matr1x，ELF32）：非边界跳转 239→8（-96.7%）、
  IDA 识别函数 54→93、覆盖率 25.1%→28.2%、反编译成功率 66.7%
- 修好后能直接读出真实算法（`off_13200` 指针表遍历 + 矩阵乘）
- `jnz +1` 这种极小 rel 是典型特征：跳过的 1 字节往往是下一条 `mov` 的 opcode
- `xor eax,eax` 后紧跟 `jnz` **不能**判花指令——必须看 rel 是否极小或目标是否非对齐

## failed_attempts

- **整段 nop（前序 xor/test + 跳转 + 垃圾）**：后续指令重新错位，实测不可解码 4→7、覆盖率不升反降
- **朴素匹配 `xor r,r` + 相邻 `jnz`**：批量 nop 308 处 → **SIGSEGV**
- **把 `jmp $`（`E9 00 00 00 00`）改成 `call`**：无任何变化（那是 PIC 取址）
- **把"跳转目标非边界"当成"花指令位置"**：产生 239 个假候选（那是症状不是病灶）
- **只处理"互补跳转对"（jz/jnz 成对）**：Matr1x 上 0 命中（它用的是 `xor r,r; jnz`，无配对 jz）
- **IDA 内批量 `create_insn` + `auto_wait`**：建 1054 条被拆 1054 条，覆盖率不变
  （auto-analysis 用自身模型推翻手工边界）
- **`del_items` 写在 `ida_ua`**：报 `AttributeError`，它在 `ida_bytes`
- **`create_insn` 在已有指令内部**：返回 `Failed to create instruction`，必须先 `del_items`

## key_payload

```python
# IDAPython：只 nop 跳转本身（等长 NOP，偏移不变）
import ida_bytes, idc

def nop_jump(ea, size):
    for i in range(size):
        ida_bytes.patch_byte(ea + i, 0x90)

def make_code_at(ea):
    cur = ea
    for _ in range(64):
        if ida_bytes.is_code(ida_bytes.get_flags(cur)): break
        h = idc.get_item_head(cur)
        if h != cur:
            ida_bytes.del_items(h, ida_bytes.DELIT_SIMPLE, cur - h + 16)
            cur = h
        if not ida_ua.create_insn(cur): break
        cur += idc.get_item_size(cur)
```

已知字节特征：
```
33 DB 85 DB 75 02 74 01 21     xor ebx,ebx; test; jnz+2; jz+1; and
83 F8 00 72 02 73 01 E8        cmp eax,0; jb+2; jnb+1; call
74 03 C2 C7                    jz+3
E8 05 00 00 00 E8 01 00 00 00 36 8B 44    call+pop+jmp 跳板
```

## 一句话

花指令不是加密，是**让反汇编器顺序解码错位**；识别靠"目标非对齐"这条硬判据，
修复**只 nop 跳转本身**（不碰前后字节），修完重新反编译即可。
