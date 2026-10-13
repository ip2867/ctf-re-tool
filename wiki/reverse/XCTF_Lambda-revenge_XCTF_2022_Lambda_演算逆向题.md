# 逆向题：Lambda-revenge: XCTF 2022 Lambda 演算逆向题

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：XCTF 2022 ｜ 难度：hard

```yaml
title: 'Lambda-revenge: XCTF 2022 Lambda 演算逆向题'
contest: XCTF
year: 2022
difficulty: hard
vuln_type: reverse
tags:
- Lambda 演算
- Church 编码
- 线性代数
- 矩阵求逆
- Church 数字
- Church 布尔
- 函数式编程
attack_chain: '|'
key_payload: '|'
one_liner: 'XCTF 2022 Lambda-revenge: 把 flag 分 11 组 3 字节，编码成 Church 数字 + 矩阵 + Church 布尔值，逆向需要还原 Lambda 演算 + 线性代数。'
lesson: '|'
quality: high
full_path: Lambda-revenge：一道基于Lambda演算的CTF逆向题完整解析.full.md
meta_path: Lambda-revenge：一道基于Lambda演算的CTF逆向题完整解析.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: 'Lambda-revenge: XCTF 2022 Lambda 演算逆向题。XCTF 2022 Lambda-revenge: 把 flag 分 11 组 3 字节，编码成 Church 数字 + 矩阵 + Church 布尔值，逆向需要还原 Lambda 演算 + 线性代数。。经验：|'
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/282968.html
reasoning_chain:
- XCTF Lambda-revenge：Lambda 演算 + Church 编码 → 触发点：函数式逆向
- 动作：分析 compiler.py / decompiler.py → 假设：flag 分 11 组 3 字节编码成 Church 数字 + Church 布尔值
- 观察：矩阵 + 结果向量是 Church 编码形式 → 下一步：线性代数求解
- 动作：每个 chall[i] 还原为 M_i * X_i = R_i 方程组 → 假设：3x3 矩阵
- 动作：NumPy 矩阵求逆 X_i = M_i^(-1) * R_i → 观察：减偏移 [18,15,13] 还原 ASCII
- 观察：flag 11 组 3 字节 → 拼接 → XCTF{M4tRI1|i||l|Il|I1X_A5_YC0mb}
- 假设：编译器随机矩阵每次不同 → 动作：用官方 genMatRes 反推相同 flag 的等价矩阵
failed_attempts:
- 直接看二进制字符串 → 失败：flag 编码为 Lambda
- Z3 解 Church 数字 → 失败：必须矩阵求逆
- 试手工 Lambda 求值 → 失败：11 组计算量太大
key_observations:
- Lambda 演算 + Church 编码是 CTF Reverse 高阶考点
- Church 数字 = 应用函数 n 次（λf.λx.f^n(x)）
- Church 布尔 = True=λx.λy.x / False=λx.λy.y
- 线性代数（矩阵求逆）是解编码后的关键
- XCTF 2022 是 Lambda 演算逆向元年题目
prerequisites:
- Lambda 演算基础（α-变换 / β-归约）+ Church 编码（数字 / 布尔 / 配对）
- 线性代数（矩阵求逆）+ NumPy 数值计算
- ELF 文件结构分析
```
