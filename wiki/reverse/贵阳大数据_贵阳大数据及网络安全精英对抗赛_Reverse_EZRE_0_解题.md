# 逆向题：贵阳大数据及网络安全精英对抗赛 Reverse EZRE_0 解题

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：贵阳大数据 2023 ｜ 难度：medium

```yaml
title: 贵阳大数据及网络安全精英对抗赛 Reverse EZRE_0 解题
contest: 贵阳大数据
year: 2023
difficulty: medium
vuln_type: reverse
tags:
- TLS-callback
- RC4
- JT8U9ptt
- multi-stage
- param-control
- encrypt-decrypt-flag
- chence
- key-extraction
- debugger
attack_chain:
- 32 位 C++ 程序，无壳
- 输入 flag{77e52c5b-b141-4f3b-92ec-aa680ca38} (38 字符)
- '错位异或: x[i] ^= x[i+1]'
- 'TLS 回调函数: RC4 加密, 密码 JT8U9ptt'
- '第 3 阶段: 自定义变换函数, 第 5 个参数 0x65 = 加密, 0x64 = 解密'
- 5 次变换后比对
- '解法: 拿最终正确值, 把变换函数参数 5 改成 0x64 解密, 再 RC4 解密, 再错位 XOR 逆'
- flag = flag{068d772e155448f0ba101abb62a2a837}
key_payload: '''JT8U9ptt (RC4 key) + 第 5 参数 0x64 解密 + 错位 XOR 逆 + flag{068d772e155448f0ba101abb62a2a837}'''
one_liner: EZRE_0 Reverse：错位异或 + TLS 回调 RC4(JT8U9ptt) + 自定义变换（参数 0x65/0x64 切换加解密）+ 5 阶段。
lesson: TLS 回调函数是 RE 隐蔽执行点；自定义算法通过第 5 参数切换加解密是好出题思路。
quality: high
full_path: 贵阳大数据及网络安全精英对抗赛Reverse_EZRE_0解题.full.md
meta_path: 贵阳大数据及网络安全精英对抗赛Reverse_EZRE_0解题.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: '贵阳大数据及网络安全精英对抗赛 Reverse EZRE_0 解题。EZRE_0 Reverse：错位异或 + TLS 回调 RC4(JT8U9ptt) + 自定义变换（参数 0x65/0x64 切换加解密）+ 5 阶段。。关键路径：32 位 C++ 程序，无壳 → 输入 flag{77e52c5b-b141-4f3b-92ec-aa680ca38} (38 字符) → 错位异或: x[i]...'
category: reverse
subcategory: reverse
tools_used:
- C
time_required: medium
difficulty_score: 3
code_blocks_count: 0
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/115285.html
reasoning_chain:
- file 显示 32 位 C++ 程序无壳 → 触发点：典型 RE 题
- IDA 看到长度校验 + 错位异或 x[i]^=x[i+1] + 开启线程 → 假设：多阶段加密
- x32dbg 输入 flag{77e52c5b-b141-4f3b-92ec-aa680ca38 (38 字符) → 跟踪错位异或
- 线程函数调用 sub_f1127b 进一步变换 → 中断在 TLS 回调函数 → 触发点：隐蔽执行
- TLS 回调函数体内发现 RC4 实现 → 假设：异或后数据被 RC4 加密，密钥硬编码
- 动作：调试器抠出 RC4 密钥 = JT8U9ptt → RC4 解密
- 下一步：第 3 阶段自定义变换函数（sub_xxxxx）参数 5 = 0x65 → 假设：可逆变换
- 动作：把第 3 阶段变换后的输出当作输入重新调用，把参数 5 改成 0x64
- 观察：输出 = 原输入 → 假设：参数 5 (0x65=加密,0x64=解密) 切换加解密
- 5 次逆变换 → RC4 解密 → 错位 XOR 逆 → flag{068d772e155448f0ba101abb62a2a837}
failed_attempts:
- 试图不解 TLS 直接看 main 加密链 → 失败：TLS 在 DllMain 之前执行，是隐藏关卡
- 试图只改输入值不解密跑 5 遍 → 失败：变换函数有方向性
- 试图爆破 RC4 密钥 → 失败：密钥已在内存中可见 JT8U9ptt 字符串
key_observations:
- TLS 回调函数是 RE 题的隐蔽执行点（DllMain 前后触发）
- 自定义算法通过参数切换加解密（0x65 加密/0x64 解密）是好的出题思路
- 调试器硬件断点是跟踪数据流的金钥匙（'对数据下硬件断点 F9'）
- 错位异或 x[i]^=x[i+1] 是经典可逆变换，对解即反向迭代
prerequisites:
- PE 文件格式与 TLS 回调机制
- RC4 算法原理（KSA + PRGA）
- x32dbg / IDA 动态调试技巧（硬件断点+内存观察）
- C++ 反汇编与伪代码阅读
```
