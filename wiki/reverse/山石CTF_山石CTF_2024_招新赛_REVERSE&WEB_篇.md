# 逆向题：山石CTF 2024 招新赛/REVERSE&WEB 篇

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：山石CTF 2024 ｜ 难度：easy

```yaml
title: 山石CTF 2024 招新赛/REVERSE&WEB 篇
contest: 山石CTF
year: 2024
difficulty: easy
vuln_type:
- reverse
tags:
- C++ 字符变换
- 循环移位
- 位交换
- 保留符号未脱
- UPX 脱壳
- 字符串常量比较
- 招新赛
attack_chain:
- 'easycpp2: 程序未脱符号，直接看 main 函数'
- 读入 usr_input 字符串
- rand() % 7 + 1 得到 rotate_count
- func1 对每字符：func1_1 循环右移 rotate_count 位，func1_2 交换第 1 位和第 rotate_count 位
- 跟 24 字节 data 数组逐字节比较，全等输出 "Correct!
- 解密：swap_bits 还原 + circular_left_shift 解出 ayyctf{you_get_rand_num}
- 后续题：UPX 脱壳 (l_info corrupted) → 改用 F8 手动步过 OEP 跳板 → dump 内存
- 字符串比较：strlen 后 FUN_401830 变换后跟 "02CD290D5ACE1A83" 比较
key_payload: 'def swap_bits(byte, n): bit1 = byte & 1; bitN = (byte >> (n-1)) & 1; if bit1 != bitN: byte ^= 1; byte ^= (1 << (n-1)); return byte'
one_liner: C++ 保留符号无脱 → 看 main 还原 循环右移 + 位交换 加密
lesson: 招新赛题往往不脱符号；C++ 字符变换题常见循环移位+位操作复合；UPX l_info corrupted 时手脱 F8 步过 OEP
quality: medium
full_path: 2024年第四届山石CTF招新赛WP_REVERSE&WEB篇.full.md
meta_path: 2024年第四届山石CTF招新赛WP_REVERSE&WEB篇.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: '山石CTF 2024 招新赛/REVERSE&WEB 篇。C++ 保留符号无脱 → 看 main 还原 循环右移 + 位交换 加密。关键路径：easycpp2: 程序未脱符号，直接看 main 函数 → 读入 usr_input 字符串 → rand() % 7 + 1 得到 rotate_count。经验：招新赛题往往不脱符号；C++ 字符变换题常见循环移位+位操作复合；UPX l_inf...'
category: reverse
subcategory: reverse
tools_used:
- C
time_required: quick
difficulty_score: 2
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/199581.html
reasoning_chain:
- 触发点：easycpp2 程序未脱符号 → 假设：直接看 main 函数 → 动作：IDA 打开定位 main
- 观察：main 含 data[24] 数组 + rotate_count=rand()%7+1 → 假设：func1 func1_1 func1_2 是变换
- 动作：分析 func1_1 循环右移 rotate_count 位 + func1_2 交换 bit1 bitN → 假设：可逆变换
- 动作：写 swap_bits + circular_left_shift 还原 → 观察：得 flag ayyctf{you_get_rand_num}
- 触发点：后续题 UPX 壳 l_info corrupted → 假设：手脱 → 动作：F8 步过 OEP 跳板
- 动作：dump 内存 + import 修复 → 观察：还原未加壳 PE
- 触发点：字符串比较 → 假设：FUN_401830 变换后比 '02CD290D5ACE1A83' → 动作：静态反��编 FUN_401830
- 观察：拿到 flag
failed_attempts:
- 试图 UPX -d 自动脱壳 → 失败：l_info corrupted 必须手脱
- 试图爆破 rand()%7+1 → 失败：rotate_count 影响每一位无法独立爆破
- 试图不解 FUN_401830 直接看密文 → 失败：密文是函数输出
key_observations:
- 招新赛题往往不脱符号（C++ 编译选项保留 debug info）
- C++ 字符变换题常见循环移位+位操作复合（位 1 与位 N 交换）
- UPX l_info corrupted 时手脱 F8 步过 OEP 是必备技能
- swap_bits + circular_shift 是字符逆变换通用公式
prerequisites:
- IDA Pro 反编译 + C++ STL 容器识别
- 位运算（循环移位 + 位交换）
- UPX 脱壳（手脱 OEP 跳板）
- rand() 种子 + rotate_count 爆破
```
