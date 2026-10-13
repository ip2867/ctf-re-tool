# 逆向题：第五届"鹏城杯"初赛 Reverse-MDriver-赛题解析

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：鹏城杯 2025 ｜ 难度：hard

```yaml
title: 第五届"鹏城杯"初赛 Reverse-MDriver-赛题解析
contest: 鹏城杯
year: 2025
difficulty: hard
vuln_type: reverse
tags:
- Windows驱动
- WFP
- FWPS_CLASSIFY
- MSR
- KiSystemCall64
- KUSER_SHARED_DATA
- ICMP
- RC4-XOR
attack_chain: '1. 识别ClassifyFn为WFP callout驱动函数→rdmsr C0000082获取MSR_LSTAR=fffff801`0c211900→KiSystemCall64前4字节0f 01 f8 65作key1(4字节循环)|2. 读取KUSER_SHARED_DATA.NtSystemRoot="C:\WINDOWS" UTF-16LE 20字节→v4[i]^=(~i)&0xFF 256次异或生成key2|3. 密文v41 20字节cipher=payload[i]=cipher[i]^key2[i]^key1[i%4]|4. 触发: Python socket SOCK_RAW IPPROTO_ICMP发包payload=go_to_find_the_flag!→驱动ICMP包匹配触发'
key_payload: msr[c0000082] = fffff801`0c211900|0f 01 f8 65(key1)|seed_str="C:\WINDOWS" seed_bytes=seed_str.encode('utf-16le')[:0x14]|v4[i] ^= (~i) & 0xFF for i in range(256)|cipher=[0xD4,0x90,0x60,0xED,...]|key2=[0xBC,0xFE,0xC7,0xFC,...]|p=c^k2^k1|socket.SOCK_RAW socket.IPPROTO_ICMP|flag{Y0r_Ar3_W1nKern3l_Mas7er!*}
one_liner: 鹏城杯2025 WFP callout驱动逆向,ClassifyFn识别WFP过滤ICMP,MSR_LSTAR读KiSystemCall64前4字节作Key1,KUSER_SHARED_DATA.NtSystemRoot="C:\WINDOWS" UTF-16LE异或(~i)生成Key2,密文双key异或解flag,Python SOCK_RAW发ICMP包触发驱动
lesson: 1) WFP驱动ClassifyFn签名识别:(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, void*, const void*, const FWPS_FILTER1*, UINT64, FWPS_CLASSIFY_OUT0*); 2) MSR C0000082(MSR_LSTAR)读KiSystemCall64前4字节作为密码key1; 3) KUSER_SHARED_DATA.NtSystemRoot(0x30偏移)固定存系统目录"C:\WINDOWS" UTF-16LE格式,加密key素材; 4) Python socket SOCK_RAW IPPROTO_ICMP直接发ICMP包触发驱动callout; 5) 驱动级逆向思路:从filter/classify函数入手定位算法,MSR+共享数据是常见数据源
quality: high
full_path: 第五届“鹏城杯”初赛_Reverse-MDriver-赛题解析.full.md
meta_path: 第五届“鹏城杯”初赛_Reverse-MDriver-赛题解析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 第五届"鹏城杯"初赛 Reverse-MDriver-赛题解析。鹏城杯2025 WFP callout驱动逆向,ClassifyFn识别WFP过滤ICMP,MSR_LSTAR读KiSystemCall64前4字节作Key1,KUSER_SHARED_DATA.NtSystemRoot="C:\WINDOWS" UTF-16LE异或(~i)生成Key2,密文双key异或解flag,P...
category: reverse
subcategory: reverse
tools_used:
- C
- Python
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/291134.html
reasoning_chain:
- WFP callout 驱动逆向 → 触发点：ClassifyFn 识别 WFP callout 函数
- 动作：识别函数签名 (FWPS_INCOMING_VALUES0*, FWPS_INCOMING_METADATA_VALUES0*, void*, const void*, FWPS_FILTER1*, UINT64, FWPS_CLASSIFY_OUT0*)
- 假设：rdmsr C0000082 读 MSR_LSTAR = fffff801'0c211900 → KiSystemCall64 前 4 字节 0f 01 f8 65 作 key1
- 假设：KUSER_SHARED_DATA.NtSystemRoot 偏移 0x30 = 'C:\WINDOWS' UTF-16LE 20 字节 → v4[i] ^= (~i) & 0xFF 256 次异或生成 key2
- 动作：cipher[i] = cipher[i] ^ key2[i] ^ key1[i%4] → 解 flag
- 假设：触发驱动 → 动作：Python socket SOCK_RAW IPPROTO_ICMP 发包 payload='go_to_find_the_flag!'
- 观察：flag{Y0r_Ar3_W1nKern3l_Mas7er!*}
failed_attempts:
- 直接 IDA 看 ClassifyFn 函数 → 失败：必须 rdmsr C0000082 才能取 KiSystemCall64
- KUSER_SHARED_DATA 偏移错误 → 失败：NtSystemRoot 在 0x30 偏移不是其他位置
key_observations:
- WFP 驱动 ClassifyFn 签名识别是驱动逆向入口
- MSR C0000082(MSR_LSTAR) 读 KiSystemCall64 前 4 字节作为密码 key1
- KUSER_SHARED_DATA.NtSystemRoot(0x30 偏移) 固定存系统目录 UTF-16LE 格式
- Python socket SOCK_RAW IPPROTO_ICMP 直接发 ICMP 包触发驱动 callout
- 驱动级逆向思路：从 filter/classify 函数入手定位算法
prerequisites:
- WFP 驱动逆向（ClassifyFn 识别）
- MSR 寄存器读取（rdmsr 指令）
- KUSER_SHARED_DATA 结构（NtSystemRoot 偏移）
- Python socket SOCK_RAW IPPROTO_ICMP 发包
```
