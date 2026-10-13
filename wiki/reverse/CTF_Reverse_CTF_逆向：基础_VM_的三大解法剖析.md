# 逆向题：CTF 逆向：基础 VM 的三大解法剖析

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：CTF Reverse 2024 ｜ 难度：medium

```yaml
title: CTF 逆向：基础 VM 的三大解法剖析
contest: CTF Reverse
year: 2024
difficulty: medium
vuln_type: reverse
tags:
- VM字节码
- opcode 0x01/0x04/0x05 add/sub/xor
- target+value 操作数
- IDA get_wide_byte 提取
- z3 BitVec 8位约束
- Frida hook onEnter 计数
- encode/decode 对称
- flag_enc 32字节密文
attack_chain:
- 'VM 字节码: opcode 0x01 加 / 0x04 减 / 0x05 异或'
- '操作数: (target, value) - flag[target] += value / -= value / ^= value'
- '解法 1: IDA Python idc.get_wide_byte(start+i) 提取 0x7A31D0 起 16*25 字节'
- '解法 2: deopcode 倒序遍历 (3字节一组) 还原 flag'
- '解法 3: z3 BitVec 8位 + solver 约束每字节 == flag_enc'
- '解法 4: Frida hook vm.exe + 0x197F onEnter 计数, send(number) 到 Python'
- flag_enc = [0x65, 0xE2, ..., 0xFD] 32 字节
key_payload: '''VM opcode 0x01/0x04/0x05 / (target, value) 操作 / IDA get_wide_byte / z3 BitVec 8位 / deopcode 倒序 / Frida Interceptor.attach onEnter'''
one_liner: CTF VM 基础 — VM 字节码 0x01/0x04/0x05 (add/sub/xor) + IDA get_wide_byte 提取 + z3 BitVec 8 位约束 + deopcode 倒序遍历 + Frida hook onEnter 计数。
lesson: VM 逆向 3 大解法:① IDA 提取 opcode + 解释执行 / ② 倒序遍历反推 (因为加减异或操作可逆) / ③ z3 符号执行约束求解;VM 字节码通常 3 字节一组 (op, target, value)。
quality: high
full_path: CTF_逆向：基础_VM_的三大解法剖析.full.md
meta_path: CTF_逆向：基础_VM_的三大解法剖析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 'CTF 逆向：基础 VM 的三大解法剖析。CTF VM 基础 — VM 字节码 0x01/0x04/0x05 (add/sub/xor) + IDA get_wide_byte 提取 + z3 BitVec 8 位约束 + deopcode 倒序遍历 + Frida hook onEnter 计数。。关键路径：VM 字节码: opcode 0x01 加 / 0x04 减 / 0x05 异或 ...'
category: reverse
subcategory: reverse
tools_used:
- IDA
- Python
- Z3
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/235951.html
reasoning_chain:
- 触发点：VM 字节码主循环 while(i<len) 解析 opcode → 假设：典型 switch-case VM 三类操作
- 动作：分析 opcode 0x00 nop / 0x01 add flag[target]+=value / 0x04 sub / 0x05 xor → 观察：每条指令 3 字节 (op, target, value)
- 假设：操作可逆 → 动作：解法 1 IDA get_wide_byte(0x7A31D0+i) 提取 16*25 字节 + Python 解释执行 → 观察：解出 flag
- 假设：加减异或可逆 → 动作：解法 2 deopcode 倒序遍历 opcode 应用 (sub→add, add→sub, xor→xor) 还原 flag 字节
- 假设：可以用 SAT 求解 → 动作：解法 3 z3 BitVec('flag[i]', 8) + 32 字节约束迭代 → 观察：s.check()=sat 得到 32 字符
- 假设：还能动态 hook → 动作：解法 4 Frida Interceptor.attach(vm.exe + 0x197F).onEnter 数 send(number) → Python 收集
- 观察：四种解法殊途同归 → 完成
failed_attempts:
- 试图用 IDA F5 反编译直接看逻辑 → 失败：opcode 是手工解释执行，F5 看不到 switch state machine
- 试图用 Python ctypes 模拟执行整个 VM → 失败：VM 解释器太复杂，opcode 操作更直接
- 试图猜默认 flag 长度 → 失败：flag_enc 是 32 字节硬编码
key_observations:
- VM 逆向 3 大解法：① IDA 提取 opcode + 解释执行 / ② 倒序遍历反推（可逆操作）/ ③ z3 符号执行约束
- VM 字节码通常 3 字节一组（op/target/value）
- 加减异或都是可逆操作，逆向可还原（除法不可逆）
- Frida onEnter 计数器能打印执行序列辅助理解
- 32 字节约束 + z3 BitVec 8 位单层 SAT 几分钟就能出
prerequisites:
- IDA Python 脚本（idc.get_wide_byte 提取内存）
- VM 字节码分析 + opcode 反汇编模式
- z3 BitVec + Solver 约束建模
- Frida Interceptor.attach + onEnter 回调
- Python 字节/列表/字符转换
```
