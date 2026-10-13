# 逆向题：Write Up Reverse Engineering — LINE CTF 2023— Fishing and Jumpit

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：LINE CTF 2023 2023 ｜ 难度：hard

```yaml
title: Write Up Reverse Engineering — LINE CTF 2023— Fishing and Jumpit
contest: LINE CTF 2023
year: 2023
difficulty: hard
vuln_type: reverse
tags:
- anti_decompiler_ebff
- nop_patch
- thread_modification_debug
- custom_rc4_iv
- frida_hook_brute_force
- unity_il2cpp
- il2cppdumper
- ghidra_python_script
- aes_ecb_score_concat
- anti_debug_int2c
attack_chain: Fishing:EB FF XX 反反编译字节码 → Python 脚本扫描全文件改 0x90 NOP → 重 IDA 反编译成功 → 发现 sub_140001DDB 段选混淆 + 线程修改 (key 调试器=m4g1KaRp_ON_7H3_Hook 实际) → XOR+sub 输入加密 + 自定义 RC4 加密 + memcmp 比 encryptedFlag → Frida hook 0x3f48 fscanf + 0x2310 encrypt + 0x3ff0 memcmp → 多线程 8 池爆破 41 字节 flag / Jumpit:Unity Android libil2cpp.so + global-metadata.dat → IL2CPPDumper → Ghidra + Python ghidra_with_struct.py 恢复符号 → GameManager$$ScoreUp 拼接 11 段 score StringLiteral → "Cia!fo2MPXZQvaVA39iuiokE6cvZUkqx" 作 AES-128 ECB 密钥 → base64 解 cWGTmeDlFsYEFI9E5mH/eCnQ1SNlWJlXj+klPLbWS/c/1vI7UPrO4dp41u2tTGM2
key_payload: ebff_nop_patch = b'\xeb\xff\xXX' → b'\x90\x90\x90' / Frida hook 0x3f48 + 0x2310 + 0x3ff0 / key = 'Cia!fo2MPXZQvaVA39iuiokE6cvZUkqx' / AES.MODE_ECB / score literal concat
one_liner: LINE CTF 2023 两道 RE：Fishing (EB FF XX 反 IDA + 线程修改 + Frida hook 41 字节爆破) + Jumpit (Unity IL2CPP 还原 + GameManager 11 段 score 拼接 AES-128 ECB 密钥解密)。
lesson: '"EB FF XX" 是 IDA 反编译杀手；现代 CTF RE 必备三件套：Frida 自动化 + IL2CPPDumper Unity 反编译 + Ghidra Python 脚本恢复符号表。'
quality: high
full_path: Write_Up_Reverse_Engingeering_—_LINE_CTF_2023—_Fishing_and_Jumpit.full.md
meta_path: Write_Up_Reverse_Engingeering_—_LINE_CTF_2023—_Fishing_and_Jumpit.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: Write Up Reverse Engineering — LINE CTF 2023— Fishing and Jumpit。LINE CTF 2023 两道 RE：Fishing (EB FF XX 反 IDA + 线程修改 + Frida hook 41 字节爆破) + Jumpit (Unity IL2CPP 还原 + GameManager 11 段 score 拼接 AES-1...
category: misc
subcategory: misc_other
tools_used:
- Ghidra
- IDA
- Python
time_required: long
difficulty_score: 4
code_blocks_count: 0
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/107081.html
wp_author: some
reasoning_chain:
- Fishing 触发点：EB FF XX 反反编译字节码 → 假设：直接 IDA 反编译卡死
- 动作：Python 脚本扫描全文件改 0x90 NOP → 重 IDA 反编译成功
- 观察：sub_140001DDB 段选混淆 + 线程修改（key 调试器=m4g1KaRp_ON_7H3_Hook 实际）→ 假设：线程会改 input
- XOR+sub 输入加密 + 自定义 RC4 加密 + memcmp 比 encryptedFlag → Frida hook 0x3f48 fscanf + 0x2310 encrypt + 0x3ff0 memcmp
- 假设：多线程 8 池爆破 41 字节 flag → 假设：必须并行 hook
- Jumpit 触发点：Unity Android libil2cpp.so + global-metadata.dat → 假设：IL2CPP 编译 Unity
- 动作：IL2CPPDumper 还原 → Ghidra + Python ghidra_with_struct.py 恢复符号
- 观察：GameManager$$ScoreUp 拼接 11 段 score StringLiteral → 'Cia!fo2MPXZQvaVA39iuiokE6cvZUkqx' 作 AES-128 ECB 密钥
- 动作：base64 解 cWGTmeDlFsYEFI9E5mH/eCnQ1SNlWJlXj+klPLbWS/c/1vI7UPrO4dp41u2tTGM2 → AES.MODE_ECB 解密
- 观察：flag 解出 → 完成
failed_attempts:
- Fishing 试图静态分析 → 失败：EB FF XX 是 IDA 反编译杀手，必须 NOP patch
- Jumpit 试图 IDA 反编译 libil2cpp.so → 失败：必须用 IL2CPPDumper 还原符号
- Fishing 试图爆破 41 字节单线程 → 失败：必须 Frida hook 多线程并行
key_observations:
- '''EB FF XX'' 是 IDA 反编译杀手；现代 CTF RE 必备三件套：Frida 自动化 + IL2CPPDumper Unity 反编译 + Ghidra Python 脚本恢复符号表'
- 自定义 RC4 + 线程修改 input 是 RE 高阶题常见组合
- AES-128 ECB 密钥藏于 StringLiteral 拼接是 Unity RE 经典
- Unity Android libil2cpp.so + global-metadata.dat 是 Unity RE 标配
- Frida hook 多线程并行爆破是 Frida 高阶用法
prerequisites:
- IDA 反编译 + EB FF XX 字节码理解
- Frida hook 基础（fscanf / encrypt / memcmp）
- IL2CPPDumper + Ghidra 符号恢复
- AES-128 ECB 解密（PyCryptodome）
- 多线程 Frida 并行爆破
```
