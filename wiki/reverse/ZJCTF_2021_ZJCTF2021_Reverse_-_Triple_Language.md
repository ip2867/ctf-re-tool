# 逆向题：ZJCTF2021 Reverse - Triple Language

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：ZJCTF 2021 2021 ｜ 难度：hard

```yaml
title: ZJCTF2021 Reverse - Triple Language
contest: ZJCTF 2021
year: 2021
difficulty: hard
vuln_type: heap_exploit
tags:
- unicorn_engine
- mips_emulation
- arm_emulation
- x86_64_host
- multi_arch_validate
- custom_hook_callback
- ctf_crc32_table_brute
- base64_decode_xor
- character_split_3_2_1
- unicorn_capstone_disasm
attack_chain: '主程序 + unicorn.dll + uc_open(3=MIPS, 4=ARM) 双架构模拟 → MIPS 段 0x10000：输入前 6 字符 × "zjgcjy" = {0x2F2E, 0x282A, 0x2C42, 0x2A8A, 0x13E0, 0x36D4} 反推 "cann0t" → 后 16 字符 x-y=key1, x+y=key2 解方程 "be_t0o_carefu1" → ARM 段 0x200000：自定义 hook 改 r3 寄存器 → Base64-style 字符重组 3+2+1 位 split + chunk 16 字节 base64 编码 → CRC32 验证前 4 字符爆破 "when" → flag: cann0t_be_t0o_carefu1_when_faclng_ianguage'
key_payload: MIPS_CODE @0x10000 + uc_reg_read(t1..t6) == {0x2F2E,0x282A,0x2C42,0x2A8A,0x13E0,0x36D4} / ARM_CODE @0x200000 + v3 += 15, v3 ^= 0x6F 等 hook 操作 / key1={0xFC,0x1,0xF3,0xFA,0xE,0xBB,0x3E,0x0} / key2={0xC2,0xC3,0xD7,0xC4,0xDA,0xA5,0xA0,0xBE} / res[]={0x38,0x57,0x3A,0x42,...,0x31} 后 22 字节
one_liner: ZJCTF 2021 Triple Language 逆向：x86 主程序 + Unicorn 模拟 MIPS+ARM 双架构 + 自定义 hook 改寄存器 + CRC32 表爆破前 4 字符 + Base64-style 字符重组还原 flag。
lesson: Unicorn + Capstone 是跨架构逆向的黄金组合，hook 机制 + 寄存器读/写是观察嵌入式代码执行流的标配；CRC32 验证 4 字符爆破速度足够快。
quality: high
full_path: ZJCTF2021_Reverse-Triple_Language.full.md
meta_path: ZJCTF2021_Reverse-Triple_Language.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: ZJCTF2021 Reverse - Triple Language。ZJCTF 2021 Triple Language 逆向：x86 主程序 + Unicorn 模拟 MIPS+ARM 双架构 + 自定义 hook 改寄存器 + CRC32 表爆破前 4 字符 + Base64-style 字符重组还原 flag。。经验：Unicorn + Capstone 是跨架构逆向的黄金组合，h...
category: misc
subcategory: misc_other
tools_used:
- ARM
- x86/x64
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/36904.html
reasoning_chain:
- 触发点:程序带 unicorn.dll → 假设:用 Unicorn 模拟其他架构 → 动作:IDA 找 main 跟 uc_open
- 观察:uc_open 第一个参数 3=MIPS 4=ARM,说明有两段模拟代码 → 下一步:提取 MIPS_CODE @0x10000 + ARM_CODE @0x200000
- 动作:写 Python Unicorn 代码 + Capstone 反汇编 → 观察:MIPS 段把输入前 6 字符 × 'zjgcjy' 字节得 {0x2F2E,0x282A,0x2C42,0x2A8A,0x13E0,0x36D4}
- 动作:C 脚本 flag[i] = res[i] / key[i] → 观察:前 6 字符 = 'cann0t'
- 触发点:后 16 字符是 x-y=key1, x+y=key2 → 假设:解方程 → 动作:爆破 32-126
- 观察:解出 8 对 (a,b) → flag = 'cann0t_be_t0o_carefu1'
- 触发点:ARM 段 hook 回调改 r3 → 假设:hook 是为改字符比对 res[] → 动作:提取 res[] 22 字节
- 动作:字符重组 3+2+1 位 split + chunk 16 字节 base64-style 解 → 观察:得 'when_faclng_ianguage' 后 16 字符
- 动作:CRC32 表爆破前 4 字符 'when' → 观察:验证通过 → 完成
failed_attempts:
- 试图直接 IDA F5 MIPS 代码 → 失败:IDA 不识别 Unicorn 模拟的 MIPS 段
- 试图手工算 MIPS 乘 → 失败:太长易错,直接写 Unicorn 模拟
- 试图不解 hook 直接看 res[] → 失败:res[] 是 hook 改过的值
key_observations:
- Unicorn + Capstone 是跨架构逆向的黄金组合,hook 机制 + 寄存器读/写是观察嵌入式代码执行流的标配
- CRC32 验证 4 字符爆破速度足够快 (256^4 / sec)
- MIPS_CODE @0x10000 + ARM_CODE @0x200000 是跨架构混淆的常见内存布局
- hook 改 r3 是 ARM 上做字符串混淆的最简方式
- 字符重组 3+2+1 位 split 是 Base64-style 自定义编码的通用手法
prerequisites:
- Unicorn 引擎 + Capstone 反汇编
- MIPS / ARM 汇编基础
- CRC32 算法理解
- IDA 静态分析 + 跨架构 VM 调试
```
