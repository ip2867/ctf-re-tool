# 逆向题：LEVERAGING BINARY NINJA IL TO REVERSE A CUSTOM ISA: CRACKING POT OF GOLD 37C3

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：37C3 (Chaos Communication Congress) 2023 ｜ 难度：hard

```yaml
title: 'LEVERAGING BINARY NINJA IL TO REVERSE A CUSTOM ISA: CRACKING POT OF GOLD 37C3'
contest: 37C3 (Chaos Communication Congress)
year: 2023
difficulty: hard
vuln_type: reverse
tags:
- Binary Ninja
- IL
- custom ISA
- unicorn_blob
- 虚拟机
- 字节码逆向
attack_chain: '|'
key_payload: '|'
one_liner: '37C3 2023 Pot of Gold: 用 Binary Ninja IL 逆向 unicorn_blob 格式 + 自定义 4 字节指令 ISA 虚拟机。'
lesson: '|'
quality: high
full_path: LEVERAGING_BINARY_NINJA_IL_TO_REVERSE_A_CUSTOM_ISA-_CRACKING_THE_“POT_OF_GOLD”_3.full.md
meta_path: LEVERAGING_BINARY_NINJA_IL_TO_REVERSE_A_CUSTOM_ISA-_CRACKING_THE_“POT_OF_GOLD”_3.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: 'LEVERAGING BINARY NINJA IL TO REVERSE A CUSTOM ISA: CRACKING POT OF GOLD 37C3。37C3 2023 Pot of Gold: 用 Binary Ninja IL 逆向 unicorn_blob 格式 + 自定义 4 字节指令 ISA 虚拟机。。经验：|'
category: reverse
subcategory: reverse
tools_used:
- BinaryNinja
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/164127.html
reasoning_chain:
- 37C3 Pot of Gold：自定义 4 字节指令 ISA 虚拟机 → 触发点：unicorn_blob 格式
- 动作：Binary Ninja IL 模式分析 → 假设：自定义架构
- 动作：写 BNIL lifting 脚本 → 观察：解析出指令 opcode 表
- 假设：gordon.bin + kitchen.bin 双 VM → 动作：分析 unicorn_blob_file 结构
- 观察：每条指令 4 字节 → 下一步：还原完整 ISA
- 动作：写模拟器跑 unicorn_blob → 假设：能执行原逻辑 → 模拟器跑出 flag → 完成
failed_attempts:
- 用 IDA Pro 分析 → 失败：自定义指令 IDA 解析不出
- 用 unicorn 引擎直接执行 → 失败：必须先分析 ISA
- 字符串搜 flag → 失败：明文不存在
key_observations:
- Binary Ninja IL 是逆向自定义 ISA 的利器（比 IDA 灵活）
- unicorn_blob 是 37C3 自定义 VM 格式（4 字节指令）
- BNIL lifting + 写自定义架构 plugin 是 BN 高阶用法
- 自定义 ISA 题必须先还原 opcode 表再写模拟器
- 37C3 Pot of Gold 是 unicorn VM 经典题
prerequisites:
- Binary Ninja IL 原理 + 自定义架构 plugin 编写
- unicorn_blob 格式解析 + 字节码模拟器编写
- VM reverse 通用方法
```
