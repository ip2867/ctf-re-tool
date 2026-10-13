# 逆向题：Square CTF 2022: Yet Another Reversing Activity

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：Square CTF 2022 ｜ 难度：medium

```yaml
title: 'Square CTF 2022: Yet Another Reversing Activity'
contest: Square CTF
year: 2022
difficulty: medium
vuln_type: reverse
tags:
- yara-rules
- yara-vm-debug
- opcode-trace
- op_bitwise_xor
- brute-char
attack_chain:
- yara-4.2.3 源码 ./bootstrap.sh + ./configure --with-debug-verbose=8 + make
- 写 flag.yarc 测试规则匹配 banker pattern
- 跑 ./yara-4.2.3/yara -C flag.yarc test.txt 触发 OP_PUSH_8
- 提取 yr_execute_code 调试日志中所有 PUSH_8 + BITWISE_XOR 对
- chr(95^57)='f' chr(51^95)='l' chr(248^153)='a' chr(83^52)='g' chr(248^131)='{' chr(154^247)='m
- 写 bruteforce.sh 自动化每次取最后 3 行
- flag{m33t_me_1n_7h3_ar3n4} 渐进输出
key_payload: yara-4.2.3/yara -C flag.yarc test.txt 2>&1 | grep -B2 OP_BITWISE_XOR
one_liner: Square CTF 2022 YARA：自编译 yara --with-debug-verbose=8 跑规则，提取 OP_PUSH_8 + BITWISE_XOR trace 还原 flag。
lesson: 给开源工具加 --with-debug-verbose 选项是 CTF 题目常用的"半源码"逆向入口。
quality: high
full_path: Square_CTF_2022-_Yet_Another_Reversing_Activity.full.md
meta_path: Square_CTF_2022-_Yet_Another_Reversing_Activity.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: 'Square CTF 2022: Yet Another Reversing Activity。Square CTF 2022 YARA：自编译 yara --with-debug-verbose=8 跑规则，提取 OP_PUSH_8 + BITWISE_XOR trace 还原 flag。。关键路径：yara-4.2.3 源码 ./bootstrap.sh + ./configure --...'
category: reverse
subcategory: reverse
tools_used:
- C
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/77789.html
wp_author: the
reasoning_chain:
- 题目给 YARA 规则 silent_banker:banker → 触发点：YARA VM 字节码执行
- 假设：YARA 自带 bytecode VM yr_execute_code → 动作：自编译 --with-debug-verbose=8
- ./bootstrap.sh + ./configure --with-debug-verbose=8 + make → 观察：debug 日志有所有 opcode
- 动作：./yara-4.2.3/yara -C flag.yarc test.txt → 观察：OP_PUSH_8 + OP_BITWISE_XOR 打印
- 假设：每次改 test.txt 触发不同 PUSH_8 → 动作：grep -B2 OP_BITWISE_XOR 提取数值
- chr(95^57)='f' chr(51^95)='l' chr(248^153)='a' → 假设：flag 字符级可还原
- 动作：bruteforce.sh 自动化每次取最后 3 行 → 观察：flag{m33t_me_1n_7h3_ar3n4} 渐进输出
failed_attempts:
- 试图不编译直接跑 → 失败：无 debug-verbose 输出
- 试图一次提取所有 flag 字符 → 失败：每次只能拿最后 XOR 的两个 operand
key_observations:
- 给开源工具加 --with-debug-verbose 是 CTF 题目常用的'半源码'逆向入口
- YARA 规则条件编译为字节码执行 (OP_PUSH_8/INT_EQ/BITWISE_XOR/AND/JFALSE/MATCH_RULE/HALT)
- 字符级爆破 = 每次改 test.txt 重跑 + tail -3 提取最后 XOR 数值对
- chr(x^y) 还原单字符是经典 trace 解读手法
prerequisites:
- YARA 规则语法与自编译
- configure --with-debug-verbose 选项
- shell grep/tail/sed/xargs 流水线
- 字节码 VM 概念 (opcode operand)
```
