# 逆向题：一道简单 Chacha20 + RC4 算法 CTF 题目

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：CTF练习 2022 ｜ 难度：medium

```yaml
title: 一道简单 Chacha20 + RC4 算法 CTF 题目
contest: CTF练习
year: 2022
difficulty: medium
vuln_type: reverse
tags:
- Chacha20
- RC4
- flower-instructions
- anti-debug
- IDA
- srand-time-pid
- time-brute-force
- newu
- 看雪
attack_chain:
- 32 位 VC++ 程序，无壳
- IDA F5 反编译 main 函数：读 flag → 3 个未识别函数 → 输出 flag.enc
- '关键: sub_401450 是 Chacha20（特征字符串 "expand 32-byte k"）'
- '花指令: 0x401468~0x40146C 红色未识别，0x40146A 强制跳转到 0x40146F'
- '去花: 0x40146E 按 D 转数据 + 0x40146F 按 C 转代码 + 0x40146A~0x40146E 改 0x90 (NOP) + 0x401450~0x401566 按 P 重定义函数'
- loc_401940 和 loc_401AA0 同样处理
- 三个函数：Chacha20 + RC4 + PRNG seed
- sub_401610 是 PRNG seed 生成器，srand(time(0) ^ pid)
- RC4 key = "Encrypted!!" (12 字节)
- Chacha20 key 由 PRNG 生成 32 字节
- '爆破: timestamp [1662909722, 1662973302] × pid [1, 9000]'
- '判定: 解密后前 3 字符 == "fla'
key_payload: '''time(0) ^ pid 爆破 + ChaCha20XOR + RC4 + hexData[0:3] == "fla"'''
one_liner: Reverse 32 位题：花指令 0x40146A 跳 0x40146F + Chacha20 + RC4 + srand(time^pid) 爆破。
lesson: 花指令去花三步走 (D 转数据 + C 转代码 + NOP 填充)；Chacha20 特征 "expand 32-byte k"；srand(time) 爆破时间窗口。
quality: high
full_path: 一道简单Chacha20_RC4算法CTF题目.full.md
meta_path: 一道简单Chacha20_RC4算法CTF题目.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: '一道简单 Chacha20 + RC4 算法 CTF 题目。Reverse 32 位题：花指令 0x40146A 跳 0x40146F + Chacha20 + RC4 + srand(time^pid) 爆破。。关键路径：32 位 VC++ 程序，无壳 → IDA F5 反编译 main 函数：读 flag → 3 个未识别函数 → 输出 flag.enc → 关键: sub_401450...'
category: reverse
subcategory: reverse
tools_used:
- C
- IDA
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/89178.html
reasoning_chain:
- '32 位 VC++ 程序 IDA F5 看 main → 3 个未识别函数 → flag.enc 输出 → 假设: 花指令'
- '观察: 0x401468~0x40146C 红未识别, 0x40146A 跳 0x40146F → 触发点: 花指令破坏栈帧'
- '动作: 0x40146E 按 D 转数据 + 0x40146F 按 C 转代码 + 0x40146A~0x40146E 改 0x90 NOP + 0x401450~0x401566 按 P 重定义函数'
- loc_401940 和 loc_401AA0 同样处理 → 3 个函数暴露
- 'sub_401450 含 ''expand 32-byte k'' 字符串 → 假设: Chacha20 → 找 github 源码'
- 其余两个是 RC4 (S-box 初始化特征) + sub_401610 PRNG seed 生成器
- '假设: srand(time(0) ^ pid) → 爆破 timestamp [1662909722, 1662973302] × pid [1, 9000]'
- '判定: 解密后前 3 字符 == ''fla'' → 输出 flag'
failed_attempts:
- '用 flag.enc 文件时间戳当 time(0) → 失败: 出题时间是 2022-09-11 23:22:02, 必须从出题时开始爆'
- '试图直接拿 flag.enc 当密文跑标准 Chacha20 → 失败: 缺密钥'
key_observations:
- '花指令去花三步走: D 转数据 + C 转代码 + NOP 填充 + P 重新定义函数'
- Chacha20 特征字符串 'expand 32-byte k', 找到即确认识别
- srand(time ^ pid) 爆破时间窗口必须从出题时间开始算
- RC4 + Chacha20 双层加密 + PRNG 种子爆破是常见中级逆向结构
prerequisites:
- IDA F5 反编译 + 花指令去除 (D/C/NOP/P 快捷键)
- Chacha20 算法细节 (init_state + 20 轮 + XOR)
- RC4 流密码 (S-box 初始化 + 加密)
- C srand(time, pid) PRNG 爆破
```
