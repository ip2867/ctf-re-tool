# 逆向题：第三届古剑山网络安全功防大赛初赛Reverse全解wp

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：第三届古剑山网络安全功防大赛初赛 2025 ｜ 难度：hard

```yaml
title: 第三届古剑山网络安全功防大赛初赛Reverse全解wp
contest: 第三届古剑山网络安全功防大赛初赛
year: 2025
difficulty: hard
vuln_type: reverse
tags:
- 古剑山RE全解
- base64+rc4+0x22222222异或
- HelloWorld字节码
- VM opcodes 0x101-0x504
- sys_ptrace反调试
- RC4加密
- CVE-2010-2967 VxWorks固件
attack_chain: easyre(base64+rc4+0x22222222异或)→HelloWorld(字节码v3[idx]=v28[src_idx] op=3)→veryez(VM opcodes 0x101/0x102/0x103/0x201/0x202/0x203)→babyre(sys_ptrace反调试+RC4 key="is_good}")→final(VxWorks固件+CVE-2010-2967 loginDefaultEncrypt hash)
key_payload: easyre:异或0x90504956+0x22222222+RC4+base64;HelloWorld字节码(v3[idx]=v28[src_idx] op=3);VM opcodes 0x101 add, 0x102 and, 0x201 sub;RC4 key='is_good}';VxWorks PowerPC + loginDefaultEncrypt CVE-2010-2967
one_liner: 古剑山初赛Reverse全解5题：easyre RC4+异或+HelloWorld字节码+VM+RC4 key is_good}+VxWorks固件
lesson: RE题常见组合：字节码VM+字符串异或+RC4；固件逆向CVE编号对应函数
quality: high
full_path: 第三届古剑山网络安全功防大赛初赛Reverse全解wp.full.md
meta_path: 第三届古剑山网络安全功防大赛初赛Reverse全解wp.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 第三届古剑山网络安全功防大赛初赛Reverse全解wp。古剑山初赛Reverse全解5题：easyre RC4+异或+HelloWorld字节码+VM+RC4 key is_good}+VxWorks固件。经验：RE题常见组合：字节码VM+字符串异或+RC4；固件逆向CVE编号对应函数
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 0
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/284751.html
reasoning_chain:
- easyre 提示 '动静结合' + 描述 base64+rc4+异或 → 触发点：v7 决定每组密文是否再与 0x22222222 异或
- 假设：动调可直接出密钥流 → 动作：gdb 单步跟踪 → 观察：00 00 00 00 22 22 22 22 22 22 ... 密钥流
- 动作：Cyberchef 逆序解密（异或 0x90504956 → 异或密钥流 → RC4 解密 → base64 解码）→ 观察：得到 easyre flag
- HelloWorld 字节码题 → 触发点：v3[idx]=v28[src_idx] op=3 字节码 VM
- 假设：op=3 是精确赋值（其它 op 是大写转换）→ 动作：分析 v3 初始化→v28='abcdefghijklmnopqrstuvwxyz' 26 字符表
- 动作：写 generate_helloworld_payload() 用 op=3 赋值小写 + op=1 转大写 → 观察：生成 payload hex=300710ff3104... → pwntools 打远程
- veryez VM 保护题 → 触发点：VM opcodes 0x101/0x102/0x103/0x201/0x202/0x203 → 假设：标准算术 VM
- babyre sys_ptrace 反调试 → 假设：直接 patch 掉 qword_6D1D60 跳过 → 动作：观察 RC4 加密逻辑
- 假设：flag 后半段 'is_good}' 明文比较作为 RC4 密钥 → 动作：Cyberchef RC4 解密 → 观察：得到 babyre flag
- final CVE-2010-2967 + VxWorks 固件 → 触发点：binwalk -e patch.bin 提取 385 → 假设：VxWorks 2.5 + PowerPC
- 动作：hexdump -C 385 | head -20 看 0x7C 开头的 PPC 指令 → 假设：基址 0x10000 + 大端序符号表偏移 0x301E74
- 动作：写 Python 解析 symtab（每个条目 16 字节：name_off+func_off+type+reserved）→ IDA 加载 firmware → 符号恢复 → 定位 loginDefaultEncrypt
failed_attempts:
- 试图静态分析 easyre 全部 11 组异或分支 → 失败：v7 决策动态，直接动调更省事
- 试图用 op=1/op=2 直接给目标字符赋值 → 失败：op=1/2 只做大写转换，必须先 op=3 设值再 op=1 转大写
- 试图直接动调 final VxWorks 固件 → 失败：没有运行环境，必须 IDA + 符号恢复
key_observations:
- RC4 + 异或 + base64 是 CTF 入门级 RE 三件套
- 字节码 VM 题 '每 N 字节一个 op + 4-bit op + 4-bit idx' 是经典操作码设计
- sys_ptrace 反调试 = qword_6D1D60 反调试标志位，patch 掉即可绕过
- VxWorks 固件逆向必看：基址 0x10000 + 大端序 + 符号表偏移 0x301E74（vxworks_symtab 格式）
- CVE 编号对应固件函数（如 CVE-2010-2967 loginDefaultEncrypt）是 IoT RE 经典套路
prerequisites:
- IDA/Ghidra 静态分析（函数识别 + 控制流）
- 字节码 VM 反汇编（op + idx 双 4-bit 解码）
- VxWorks 固件分析（binwalk + PowerPC 架构 + 符号表恢复）
- RC4 算法结构（KSA + PRGA）
```
