# 逆向题：CrackMe3 逆向分析实战 – PowerPC架构双重加密挑战完全解析

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：公众号文章 2024 ｜ 难度：medium

```yaml
title: CrackMe3 逆向分析实战 – PowerPC架构双重加密挑战完全解析
contest: 公众号文章
year: 2024
difficulty: medium
vuln_type: reverse
tags:
- rev
- powerpc
- idea
- rc6
- dual-cipher
- radare2
- abiv2
- stripped
attack_chain:
- file命令识别ELF 64-bit LSB PowerPC abiv2
- radare2 r2 -q -c 'aaa; iz'列字符串
- Bingo!"在0x100024a8
- fcn.10001740(2528字节)主要加密逻辑
- fcn.10000c64(1196字节)辅助加密/密钥派生
- 16字节(128-bit)IDEA标准Key
- 24字节可能是加密输出
- 双重加密：IDEA加密→RC6加密→与硬编码比较
key_payload: 'r2 -q -c ''aaa; iz'' ./crackme3  # 找Bingo!和加密数据'
one_liner: PowerPC64 CrackMe，IDEA+RC6双重加密逆向
lesson: 非x86架构二进制逆向需用file/readelf先确认，r2跨平台支持好
quality: high
full_path: CrackMe3_逆向分析实战_–_PowerPC架构双重加密挑战完全解析.full.md
meta_path: CrackMe3_逆向分析实战_–_PowerPC架构双重加密挑战完全解析.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: CrackMe3 逆向分析实战 – PowerPC架构双重加密挑战完全解析。PowerPC64 CrackMe，IDEA+RC6双重加密逆向。关键路径：file命令识别ELF 64-bit LSB PowerPC abiv2 → radare2 r2 -q -c 'aaa; iz'列字符串 → Bingo!"在0x100024a8。经验：非x86架构二进制���向需用file/readelf先...
category: reverse
subcategory: reverse
tools_used:
- Radare2
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/282755.html
reasoning_chain:
- file ./crackme3 → ELF 64-bit LSB executable, PowerPC abiv2, stripped → 触发点：非 x86 架构二进制
- 动作：readelf -h 确认架构 + radare2 r2 -q -c 'aaa; iz' 列字符串 → 观察：Bingo! 字符串在虚拟地址 0x100024a8
- 观察 .data 段有硬编码密文 + 16 字节 key + 24 字节疑似加密输出 → 假设：双重加密对比 = 'Bingo!' 触发条件
- 动作：r2 -q -c 'pdf @ fcn.10001740'（2528 字节主函数）+ 'pdf @ fcn.10000c64'（1196 字节辅助函数）
- 假设：fcn.10001740 是第一层加密 IDEA（128-bit key 16 字节匹配硬编码） → 动作：识别 IDEA 子密钥生成 + 加解密轮
- 假设：fcn.10000c64 是第二层 RC6（24 字节可能是 RC6 输出）→ 动作：识别 RC6 r=20 轮 + mod 2^32 加减
- 动作：先 RC6 解密 → 再 IDEA 解密 → 与硬编码 24 字节比较 → 假设：解出的 24 字节就是用户输入 FLAG
- 观察：非 x86 反汇编需注意寄存器映射（r3=arg/return，r1=sp，PowerPC 函数 prologue save r0/lr）
failed_attempts:
- 试图用 IDA 直接反汇编 PowerPC → 失败：IDA ��版对 abiv2 支持不全，r2 跨平台更稳
- 试图按字符串长度硬猜算法 → 失败：必须从函数大小（2528/1196）和参数（16/24 字节）反推 IDEA+RC6
- 试图同时解 IDEA 和 RC6 → 失败：双重加密有先后顺序，顺序反了得不出明文
key_observations:
- file + readelf -h 永远是确认非 x86 架构第一步（PowerPC/ARM/MIPS/RISC-V）
- radare2 的 'aaa; iz' 一行命令跨平台列字符串 + 自动分析，比 IDA 兼容性更好
- IDEA 8.5 轮（8 轮 + 半轮 Output Transformation）+ RC6 r=20 轮是经典双重加密组合
- stripped 二进制无符号表时，函数大小 + 参数字节数是反推算法的关键线索
- PowerPC abiv2 函数 prologue 是 std r0,16(r1); std r, ... 模式，与 x86 push 不同
prerequisites:
- Linux file/readelf/objdump 命令使用
- Radare2 基本使用（aaa / pdf / iz）
- IDEA 算法（8.5 轮，128-bit 块/密钥，模 2^16 加乘）
- RC6 算法（r 轮 + mod 2^32 加减 + 旋转依赖）
- PowerPC 寄存器约定（r3 返回值，r1 栈指针，r0 LR）
```
