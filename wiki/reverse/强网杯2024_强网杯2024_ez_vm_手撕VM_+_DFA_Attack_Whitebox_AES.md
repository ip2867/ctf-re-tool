# 逆向题：强网杯2024 ez_vm 手撕VM + DFA Attack Whitebox AES

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：强网杯2024 2024 ｜ 难度：hard

```yaml
title: 强网杯2024 ez_vm 手撕VM + DFA Attack Whitebox AES
contest: 强网杯2024
year: 2024
difficulty: hard
vuln_type: reverse
tags:
- 手撕VM
- 自定义VM
- tzcnt指令
- push_8/16/32/64
- 白盒AES
- DFA
- Differential_Fault_Analysis
- 故障分析
- 字节码格式
- 0x08开头格式
- chal.exe
- '3766323862633565'
- 魔改TEA
- Inline_hook
- 寄存器vm
attack_chain: 静态分析chal.exe → switch+tzcnt指令调度发现自定义VM → 0x08 0x20 0x00格式字节码 → push_8/16/32/64/pop_64/pop_32/mov reg imm/mov reg [reg]等指令集还原 → 提取AES密钥用白盒+DFA差分故障分析 → 验证密钥解魔改TEA得flag
key_payload: switch+tzcnt VM调度 + 字节码0x08 0x20格式 + DFA故障分析 + 白盒AES
one_liner: 强网杯2024 ez_vm:手撕Windows自定义VM字节码(0x08+寄存器+操作)+白盒AES DFA差分故障分析。
lesson: 自定义VM逆向:switch+tzcnt指令调度;白盒AES密钥提取可用DFA差分故障分析(注入fault观察密文差分推key);字节码格式常见0x08开头+reg+操作;Windows x64程序用push_8/16/32/64/pop_64/pop_32/mov reg,[reg];魔改TEA delta非0x9E3779B9。
quality: high
full_path: 强网杯2024_ez_vm_手撕VM_+_DFA_Attack_Whitebox_AES.full.md
meta_path: 强网杯2024_ez_vm_手撕VM_+_DFA_Attack_Whitebox_AES.meta.md
images_removed: true
images_removed_count: 6
schema_version: v3.0.0-P0
summary: 强网杯2024 ez_vm 手撕VM + DFA Attack Whitebox AES。强网杯2024 ez_vm:手撕Windows自定义VM字节码(0x08+寄存器+操作)+白盒AES DFA差分故障分析。。经验：自定义VM逆向:switch+tzcnt指令调度;白盒AES密钥提取可用DFA差分故障分析(注入fault观察密文差分推...
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 6
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/221672.html
reasoning_chain:
- 强网杯 2024 ez_vm 手撕 Windows 自定义 VM + 白盒 AES DFA 差分故障分析 → 触发点：VM + 白盒 + DFA 三连环
- 静态分析 chal.exe → switch + tzcnt 指令调度 → 假设：自定义 VM 字节码调度 → 动作：识别 0x08 0x20 0x00 格式
- 指令集还原：push_8/16/32/64/pop_64/pop_32/mov reg imm/mov reg [reg] 等 → 假设：标准寄存器 VM
- 提取 AES 密钥用白盒 + DFA 差分故障分析 → 假设：白盒 AES 嵌入密钥可被 DFA 恢复 → 动作：注入 fault 观察密文差分
- 差分比较得密钥字节 → 验证密钥解魔改 TEA → flag 输入 3766323862633565...
failed_attempts:
- 试图静态提取白盒 AES key → 失败：白盒 AES 是混淆表，DFA 才是正解
- VM 直接当 ELF 解析 → 失败：Windows PE
- Magic byte 头未识别 → 失败：必须看 0x08 字节码格式
key_observations:
- 自定义 VM 逆向：switch + tzcnt 指令调度
- 白盒 AES 密钥提取可用 DFA 差分故障分析（注入 fault 观察密文差分推 key）
- 字节码格式常见 0x08 开头 + reg + 操作
- Windows x64 程序用 push_8/16/32/64/pop_64/pop_32/mov reg,[reg]
- 魔改 TEA delta 非 0x9E3779B9
prerequisites:
- Windows PE + IDA 反汇编
- 自定义 VM 字节码模式识别（tzcnt + switch）
- 白盒 AES + DFA 差分故障分析原理
- 魔改 TEA 变体识别
```
