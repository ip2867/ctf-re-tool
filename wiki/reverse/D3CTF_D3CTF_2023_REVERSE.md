# 逆向题：D3CTF 2023 REVERSE

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：D3CTF 2023 ｜ 难度：hard

```yaml
title: D3CTF 2023 REVERSE
contest: D3CTF
year: 2023
difficulty: hard
vuln_type: reverse
tags:
- nand-vm
- rc4
- pyd
- bindiff
- syscall-hooking
- kernel-module
- fork-pipe
- z3
attack_chain:
- 'D3SKY: RC4 解密 opcode 还原 NAND VM'
- 条件断点提取 opcode 操作
- 识别 XOR 比较模式
- Z3 约束求解
- 'D3RC4: 反编译 fork+pipe 子进程'
- 模拟递归 get_key
- 还原 RC4 key
- Z3 解密
- 'D3RECOVER: Bindiff 合并 pyd 符号'
- XOR+add 还原
- 'D3SYSCALL: 内核模块劫持 syscall_table'
- 翻译 rax 调度
key_payload: RC4 加密 opcode + NAND VM + fork/pipe 子进程 + syscall hook
one_liner: D3CTF 2023 四道逆向 WP 合集，NAND-VM / fork-pipe 套娃 / pyd Bindiff / syscall 劫持 VM。
lesson: 当 IDA/Ghidra 看到 "mov byte 一坨"、自定义 syscall、fork/pipe 套娃时，要立刻反应过来这是 VM 套娃。
quality: high
full_path: D3CTF2023_REVERSE.full.md
meta_path: D3CTF2023_REVERSE.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 'D3CTF 2023 REVERSE。D3CTF 2023 四道逆向 WP 合集，NAND-VM / fork-pipe 套娃 / pyd Bindiff / syscall 劫持 VM。。关键路径：D3SKY: RC4 解密 opcode 还原 NAND VM → 条件断点提取 opcode 操作 → 识别 XOR 比较模式。经验：当 IDA/Ghidra 看到 "mov byte 一坨...'
category: reverse
subcategory: reverse
tools_used:
- Ghidra
- IDA
- Z3
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/133171.html
reasoning_chain:
- D3SKY 拿到 32 位无壳 → TLS 函数修改 RC4 密钥为 YunZhiJun → main 函数输入 37 位 → 触发点：NAND VM 题
- 动作：观察 main 函数 op[p2] = ~(op[p0] & op[p1]) → 假设：所有操作都是 NAND 构成的 VM（与门 + 取反）
- 假设：VM 操作码被 RC4 加密存放在 op 数组 → 动作：op_addr=0x5B4018 处下条件断点，在 RC4 解密前打印 op[i] 内容
- 观察：识别出 ~(&) 操作 → 假设：构造 python NAND VM 复现（37 位输入跑 op 序列）
- 假设：识别 XOR 比较模式（如 op[i]^op[j] = 0xXX）→ 动作：Z3 约束求解 → 观察：还原 flag 37 位
- D3RC4 fork+pipe 子进程递归 get_key → 模拟子进程得 RC4 key → 假设：sub_406270 是真正 RC4
- D3REVERSE Bindiff 合并 pyd 符号 + 系统调用调度 → 还原 RC4 key + XOR+add 异或加解密
- D3SYSCALL 内核模块劫持 syscall_table → 反汇编 rax → 翻译成自定义调度 → hook 真实 syscall
- 动作：把 rax 翻译表逆向 → 还原业务逻辑 → 完成
failed_attempts:
- 试图静态分析 op 数组硬解 → 失败：op 被 RC4 加密，看不出语义
- 试图不模拟 fork+pipe 直接调 get_key → 失败：子进程逻辑影响父进程 key 派生
- 试图 IDA 静态分析 NAND VM → 失败：操作码密文，IDApython 条件断点才能 print
key_observations:
- 看到 'mov byte 一坨' 或 op[p2]=~(op[p0]&op[p1]) 等模式要立刻反应是 VM 题
- NAND VM = 仅用 NAND 操作可构造所有逻辑门，复现时要还原 ~ / & / XOR / OR
- IDApython 条件断点 + op[i] print 是从加密 VM 提取 opcode 的标准手法
- fork+pipe 子进程套娃要模拟子进程调用栈，单纯调主函数拿不到 key
- Bindiff 合并 pyd 符号能快速对齐 strip 后的 Python native 模块
- syscall_table 劫持 + rax 翻译是 CTF 内核 PWN 新热点
prerequisites:
- RC4 算法实现（KSAS/PRGA）
- NAND VM 构造（~、&、XOR、OR 的 NAND 表达）
- IDApython 条件断点（idc.get_reg_value/ida_bytes.get_word）
- Z3 约束求解（Solver/Int/BitVec）
- Ghidra/IDA 反编译（sub_xxx 命名 + 函数图）
- fork/pipe/socket 子进程编程
```
