# 逆向题：强网杯 S8 决赛 Reverse S1mpleVM

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：强网杯 2024 ｜ 难度：hard

```yaml
title: 强网杯 S8 决赛 Reverse S1mpleVM
contest: 强网杯
year: 2024
difficulty: hard
vuln_type: reverse
tags:
- custom-VM
- stack-VM
- LinkEntry
- opcode-16
- virtual-machine
- compiler
- vmrun
- pwn-reverse
attack_chain:
- S1mpleVM 自定义栈式 VM，16 个 opcode
- '数据结构: struct LinkEntry { signed val; LinkEntry *next; } 链表栈'
- 'case 0u: pop+pop+v7%v8 push 模运算（0x80000000 标志空栈）'
- 'case 1u: push PC+1 单字节'
- 'case 2u: pop to v5 (load)'
- 'case 3u: sub (类似)'
- 'case 4u: add'
- 'case 5u: bitwise NOT'
- 'case 6u: XOR'
- 'case 7u: OR'
- 'case 8u: AND'
- 'case 9u: CMP (类似)'
- 'case 10u: JMP PC'
- 'case 11u: JE'
- 'case 12u: JNE'
- 'case 13u: read (input)'
- 'case 14u: write (output)'
- 'case 15u: end'
- vmrun 接受 input + vmcode 字节码
- '指令格式: 1 字节 opcode (vmcode[0]-16), 部分带 1 字节操作数 (vmcode[1])'
key_payload: '''16 opcode stack VM + LinkEntry 链表 + input/vmcode 参数'''
one_liner: 强网杯 S8 决赛 S1mpleVM：自定义 16 opcode 栈式 VM 编译器，逆向需要还原指令语义。
lesson: 自定义 VM 逆向关键在数据结构（LinkEntry 链表栈）+ opcode 表 + 操作数格式（1 字节）。
quality: high
full_path: 强网杯S8决赛Reverse.full.md
meta_path: 强网杯S8决赛Reverse.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: '强网杯 S8 决赛 Reverse S1mpleVM。强网杯 S8 决赛 S1mpleVM：自定义 16 opcode 栈式 VM 编译器，逆向需要还原指令语义。。关键路径：S1mpleVM 自定义栈式 VM，16 个 opcode → 数据结构: struct LinkEntry { signed val; LinkEntry *next; } 链表栈 → case 0u: pop+pop...'
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/220846.html
reasoning_chain:
- 题目是 S1mpleVM 自定义栈式 VM → 触发点：反编译看到 switch(v3) 16 个 case，结构体 LinkEntry
- 假设：自定义 VM 逆向关键是 opcode 表 + 数据结构 → 动作：分析 struct LinkEntry { signed val; LinkEntry *next; } 链表栈
- 观察：vmrun(input, vmcode) 主循环 → 假设：vmcode[0]-16 是 opcode，vmcode[1] 是操作数
- 动作：穷举每个 case 语义：case 0u=mod/case 1u=push PC+1/case 2u=load/case 4u=add/case 14u=write 等
- 假设：0x80000000 标志空栈 → 动作：在 IDA 里把所有 pop/push 标注释后还原栈状态
- 动作：写 Python vmrun2(input, vmcode) 重放 → 假设：能 reproduce VM 行为 → 观察：成功恢复算法
- 下一步：参数反推 input 字符串 = flag
failed_attempts:
- 试图用 unicorn 引擎 emulate 整个二进制 → 失败：自定义 VM 栈操作与 unicorn 模型不匹配
- 试图硬读 16 个 case 字符串 → 失败：switch 分支多，字符串不变没法分 case
- 试图直接爆破 input 全部字节 → 失败：分支太多，爆不动
key_observations:
- 自定义 VM 逆向 = 数据结构（链表栈 LinkEntry） + opcode 表 + 操作数格式还原
- switch(state) 是 OLLVM flatten 的简化版，手动标每个 case 状态比反编译省力
- 0x80000000 标志位是栈式 VM 区分空栈与值的常用手法
- 1 字节 opcode + 1 字节操作数 是最小化 VM 字节码设计
- 复现 VM 比静态逆向更稳，写一个 vmrun2 直接 reproduce
prerequisites:
- IDA 反编译与 switch case 还原
- 栈式 VM 原理（push/pop/call/ret 映射）
- 数据结构（struct LinkEntry 链表栈）
- Python 模拟器编写（vmrun2）
```
