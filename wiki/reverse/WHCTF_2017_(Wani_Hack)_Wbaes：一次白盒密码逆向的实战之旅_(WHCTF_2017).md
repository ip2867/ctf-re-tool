# 逆向题：Wbaes：一次白盒密码逆向的实战之旅 (WHCTF 2017)

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：WHCTF 2017 (Wani Hack) 2017 ｜ 难度：hard

```yaml
title: Wbaes：一次白盒密码逆向的实战之旅 (WHCTF 2017)
contest: WHCTF 2017 (Wani Hack)
year: 2017
difficulty: hard
vuln_type: block_cipher
tags:
- white_box_aes
- movfuscation
- dfa_differential_fault_analysis
- deadpool
- phoenixaes
- look_up_table
- sigaction_anti_debug
- t_box_aes
- sigaction_stripped_elf
- hxp_dfa
attack_chain: file ELF 32 位 9.3 MB stripped + sigaction 反调试 + MOV 混淆 → DFA 注入尝试全部 NoFault（编译器优化防故障）→ 提取字符串 "Here is flag{%s}" → 已知 AES 实现（白盒 T-Box）→ 测试密钥 whctf&flappypig! 试解 16 字节密文块 → 遍历全文件 9770792 字节找 16 字节连续块可打印字符 ≥12 → 命中 0x003a8162 偏移解出 Whc7f&Fl@ppyp1g! → ./Wbaes "Whc7f&Fl@ppyp1g!" 输出 flag
key_payload: key = b'whctf&flappypig!' / ciphertext = 13cb006c2994de6da1b81ba399206290 / plaintext = Whc7f&Fl@ppyp1g! / 全文件遍历 16 字节 AES-ECB 解密筛可打印字符
one_liner: 'WHCTF 2017 Wbaes 9.3 MB MOV 混淆白盒 AES，DFA 失败后改用"已知密钥 + 文件全字节扫描可解 16 字节块"绕过白盒保护，flag: Whc7f&Fl@ppyp1g!。'
lesson: 白盒 AES 攻击中"密钥已知 + 文件全字节扫描"是最直接的捷径；MOVfuscation 让 DFA 难以注入时，应该转向"字符串+猜测+文件扫描"的混合策略。
quality: high
full_path: Wbaes：一次白盒密码逆向的实战之旅.full.md
meta_path: Wbaes：一次白盒密码逆向的实战之旅.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: 'Wbaes：一次白盒密码逆向的实战之旅 (WHCTF 2017)。WHCTF 2017 Wbaes 9.3 MB MOV 混淆白盒 AES，DFA 失败后改用"已知密钥 + 文件全字节扫描可解 16 字节块"绕过白盒保护，flag: Whc7f&Fl@ppyp1g!。。经验：白盒 AES 攻击中"密钥已知 + 文件全字节扫描"是最直接的捷径；MOVfuscation 让 DFA 难以...'
category: crypto
subcategory: symmetric
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/282908.html
reasoning_chain:
- 触发点：WHCTF 2017 Wbaes → ELF 32 位 9.3 MB stripped + sigaction 反调试 + MOV 混淆 → 假设：白盒 AES 实现
- DFA 注入尝试：所有注入都返回 NoFault → 观察：MOVfuscation 让差分故障无法注入 → 假设：必须放弃 DFA 路径
- 动作：file + strings 提取字符串 'Here is flag{%s}' → 假设：明文格式可猜测
- 动作：假设 AES 实现是已知白盒 T-Box → 假设：测试密钥 whctf&flappypig! 试解 16 字节密文
- 观察：解出 Whc7f&Fl@ppyp1g! → 假设：key 已知 + 密文已知 + 文件全字节扫描
- 动作：全文件 9770792 字节遍历 16 字节连续块，AES-ECB 解密 + 可打印字符 ≥12 过滤 → 命中 0x003a8162
- 观察：解出 16 字节明文 → flag{...}
- 触发点：MOVfuscation 让 DFA 难以注入时，应该转向'字符串+猜测+文件扫描'的混合策略
- ./Wbaes 'Whc7f&Fl@ppyp1g!' 输出 flag → 完成
failed_attempts:
- DFA 注入 → 失败：MOVfuscation 让故障注入无法生效
- 试图静态逆向 T-Box 还原 AES 密钥 → 失败：MOV 混淆太大，无解 white-box 静态分析
- 直接对文件 AES 解密尝试随机密钥 → 失败：必须先找到 'Here is flag{%s}' 字符串锁定 key
key_observations:
- 白盒 AES 攻击中'密钥已知 + 文件全字节扫描'是最直接的捷径
- MOVfuscation 让 DFA 难以注入时，应该转向'字符串+猜测+文件扫描'的混合策略
- AES-ECB 16 字节块对齐 + 可打印字符 ≥12 过滤是文件扫描降噪标配
- sigaction 反调试 + stripped ELF 是逆向入门题常见形态
- AES T-Box 实现是 white-box AES 标准（90+ 个 T-Box 替换 XOR + ShiftRows + MixColumns）
prerequisites:
- AES 算法原理（ECB / SubBytes / ShiftRows / MixColumns）
- MOVfuscation 混淆理解
- DFA 差分故障攻击原理
- 白盒 AES T-Box 实现结构
- GDB / IDA / 010editor 综合使用
```
