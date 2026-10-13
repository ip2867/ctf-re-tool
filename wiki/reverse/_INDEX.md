# 逆向题结构化条目库（_INDEX）

> 来源：Des-CTF 知识库的**逆向题** meta（含 attack_chain 解法链 / reasoning_chain 思维链 / failed_attempts 避坑）。
> 每题一个 .md（YAML meta）；AI 用 `wiki_search` 检索，命中即 `wiki_read`。共 **10** 题。

| 题名 | 大赛 | 年 | 难度 | 一句话 |
|---|---|---|---|---|
| [山石CTF 2024 招新赛/REVERSE&WEB 篇](山石CTF_山石CTF_2024_招新赛_REVERSE&WEB_篇.md) | 山石CTF | 2024 | easy | C++ 保留符号无脱 → 看 main 还原 循环右移 + 位交换 加密 |
| [CrackMe3 逆向分析实战 – PowerPC架构双重加密挑战完全解析](公众号文章_CrackMe3_逆向分析实战_–_PowerPC架构双重加密挑战完全解析.md) | 公众号文章 | 2024 | medium | PowerPC64 CrackMe，IDEA+RC6双重加密逆向 |
| [N1CTF 2024 ezapk 解题思路 (Android + JNI Frida hook)](N1CTF_N1CTF_2024_ezapk_解题思路_(Android_+_JNI_Frida_hook).md) | N1CTF | 2024 | hard | N1CTF 2024 ezapk: Android APK + native1/native |
| [Nep CTF password RC4 + 换表 base64 算法分析 (Android JNI)](Nep_CTF_Nep_CTF_password_RC4_+_换表_base64_算法分析_(Android_JNI).md) | Nep CTF | 2023 | hard | Nep CTF password: Android JNI verify + 自定义 bas |
| [NewstarCTF 2025 Week1 REVERSE 全解 WP](NewstarCTF_2025_Week1_NewstarCTF_2025_Week1_REVERSE_全解_WP.md) | NewstarCTF 2025 Week1 | 2026 | medium | NewstarCTF 2025 Week1 Reverse 全解 (5 题)：自定义 bas |
| [REVERSE - 西湖论剑 2022 中国杭州网络安全技能大赛初赛官方 Write Up](西湖论剑_2022_中国杭州网络安全技能大赛_初赛_REVERSE_-_西湖论剑_2022_中国杭州网络安全技能大赛初赛官方_Write_Up.md) | 西湖论剑 2022 中国杭州网络安全技能大赛 初赛 | 2023 | hard | 西湖论剑 2022 Reverse 官方 WP：BabyRE IAT hook + base |
| [Square CTF 2022: Yet Another Reversing Activity](Square_CTF_Square_CTF_2022_Yet_Another_Reversing_Activity.md) | Square CTF | 2022 | medium | Square CTF 2022 YARA：自编译 yara --with-debug-ver |
| [Unicorn-BinaryNinja 去除 csel-br 间接跳转混淆](技术文章_(CSDN_转载)_Unicorn-BinaryNinja_去除_csel-br_间接跳转混淆.md) | 技术文章 (CSDN 转载) | 2024 | hard | 基于 Unicorn + BinaryNinja 的 ARM64 csel-br 间接跳转混 |
| [Write Up Reverse Engineering — LINE CTF 2023— Fishing and Jumpit](LINE_CTF_2023_Write_Up_Reverse_Engineering_—_LINE_CTF_2023—_Fishing_and_Jumpit.md) | LINE CTF 2023 | 2023 | hard | LINE CTF 2023 两道 RE：Fishing (EB FF XX 反 IDA +  |
| [ZJCTF2021 Reverse - Triple Language](ZJCTF_2021_ZJCTF2021_Reverse_-_Triple_Language.md) | ZJCTF 2021 | 2021 | hard | ZJCTF 2021 Triple Language 逆向：x86 主程序 + Unicor |

## 关键词（tags）

C++ 字符变换 · 循环移位 · 位交换 · 保留符号未脱 · UPX 脱壳 · 字符串常量比较 · 招新赛 · rev · powerpc · idea · rc6 · dual-cipher · radare2 · abiv2 · stripped · Android APK · JNI native1/native2 · Frida hook · JNI 字符串转换 · 内存读写 · JNI verify · 自定义 base64 字符表 · RC4 · v28/v30 算法还原 · reverse · custom-base64 · xorshift · two-stage-xor · android · apk · aes-ecb · pwntools-flag · atexit-hook · iat-hook · base8 · sha1 · rc4 · ebpf · uprobe · uretprobe · vma-vt · tea · mode-switch-32-64 · yara-rules · yara-vm-debug · opcode-trace · op_bitwise_xor · brute-char · unicorn_engine · binaryninja · arm64_obfuscation · csel_cset · indirect_branch · smc_emulation · code_patch · b_cond_pair · reverse_advanced · anti_decompiler_ebff · nop_patch · thread_modification_debug · custom_rc4_iv · frida_hook_brute_force · unity_il2cpp · il2cppdumper · ghidra_python_script · aes_ecb_score_concat · anti_debug_int2c · mips_emulation · arm_emulation · x86_64_host · multi_arch_validate · custom_hook_callback · ctf_crc32_table_brute · base64_decode_xor · character_split_3_2_1 · unicorn_capstone_disasm
