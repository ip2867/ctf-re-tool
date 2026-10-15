---
title: 短密文秒解套路（enc.txt 类）与协议封装明文
category: reverse-method
vuln_type: short-ciphertext-triage
difficulty: easy
tags: [短密文, enc.txt, 单字节XOR, 移位, Caesar, flag前缀匹配, RC4, 协议头, 控制字符, printable, sun, sunshine]
keywords: [enc.txt, 短密文, 单字节XOR, 暴力扫描, 移位密码, Caesar, flag前缀, 30秒分诊, RC4, 协议封装, 控制字符, \x03\x11, printable, 剥头]
one_liner: 几十字节的密文文件先做 30 秒分诊——单字节 XOR/加减移位全扫 + flag 前缀匹配（flag|ctf|sun|dice|sunshine...），命中即收工；解出的明文若带 \x03\x11 类协议封装头，剥首尾控制字符再读。
attack_chain:
- 分诊：附件是几十~几百字节的文本（enc.txt/out.dat）→ 先轻量扫描再考虑复杂算法
- 单字节全扫：XOR 0..255、加减移位 ±1..32，每组结果匹配常见前缀（flag|ctf|sun|dice|sunshine|pico）+ 可打印约束；一个循环搞定
- 移位密码判定：明文片段（如 tvotijof→sunshine）确定 shift 后整段平移即得全文；题面双关（"When in Rome"→Caesar）是提示
- 有 ELF 伴生时：先看 ELF 是否定义了"密码→密钥流"关系；是 packer（读 x 写 y）则 flag 是输入不是输出——拿到密文先判方向
- RC4/密钥流变体：在二进制里找常量表（LCG 参数/置换表/XOR 链表）定 seed 关系；key 派生函数若读未初始化变量，用已知明文（协议类型字节）爆破初值 0..255
- 协议封装明文：聊天/网络类题的解密结果常是 `[类型字节][len 用户名]正文` 封装——剥首尾控制字符（0x00-0x08,0x0B,0x0C,0x0E-0x1F）后再匹配 flag，否则整段被当不可打印回退成 hex，flag 就埋没了
- 终检：明文全可读 + 前缀吻合题面声明（题面写 sunshine{...} 就别找 flag{）→ 唯一确定
failed_attempts:
- 34 字节密文先上 AES/RSA 复杂分析 → 先 30 秒单字节扫描，sunshine{kN0w...} 一发命中
- 明文带 \x03\x11 协议头时整段判"不可打印"回退 hex → flag 明明在正文里却被埋进十六进制串，expected 包含判定也随之失效
- 只认 flag{ 前缀 → 题面声明的非标准前缀（sunshine{）/平台前缀（sun{ dice{）都要进匹配表
- RC4 key 派生里"未初始化变量"直接放弃 → x86-64 上常因调用约定恰好为 0：先试 0 再爆破，别假设不可复现
- 密文与 ELF 校验器并存时只逆 ELF → 先确认 flag 到底在本地校验还是伴生密文里，方向错了全白费
