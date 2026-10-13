# 逆向题：强网杯2024 solve2-apk 赛题解析 - TEA+Twofish+RS_MDS

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：强网杯2024 2024 ｜ 难度：hard

```yaml
title: 强网杯2024 solve2-apk 赛题解析 - TEA+Twofish+RS_MDS
contest: 强网杯2024
year: 2024
difficulty: hard
vuln_type: reverse
tags:
- Android_Apk
- JNI
- TEA解密
- Twofish
- RS_MDS_Encode
- Reed_Solomon
- GF(256)
- 字节序转换
- 异或拼接
- key_material
- AES_S-box
- Aar0n
attack_chain: C++还原:TEA 32轮 delta=0x9e3779b9 sum=0xC6EF3720 4 key → switchEndian字节序转换 → 字符串拼接part1 → Java:RS_MDS_Encode用Reed-Solomon(12,8) over GF(256)产生AES S-box → Twofish(key=000102030405060708090a0b0c0d0e0f).decrypt(data1) → 异或data2^enc1^enc2=part2 → flag{iT3N0t7H@tH@E6D0YOV7hInkS0}
key_payload: TEA+switchEndian + Twofish+RS_MDS_Encode + 异或拼接
one_liner: 强网杯2024 solve2 apk:TEA+字节序+Twofish RS_MDS_Encode(Reed-Solomon)+异或拼接三段flag。
lesson: APK逆向需结合Java层RS_MDS_Encode(GF(256) Reed-Solomon)+C++层TEA+switchEndian字节序;Twofish密钥=000102030405060708090a0b0c0d0e0f;flag分段拼接part1+part2;RS_MDS_Encode 4字节rem+4字节rem+2次循环。
quality: high
full_path: 强网杯2024_solve2-apk-赛题解析.full.md
meta_path: 强网杯2024_solve2-apk-赛题解析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 强网杯2024 solve2-apk 赛题解析 - TEA+Twofish+RS_MDS。强网杯2024 solve2 apk:TEA+字节序+Twofish RS_MDS_Encode(Reed-Solomon)+异或拼接三段flag。。经验：APK逆向需结合Java层RS_MDS_Encode(GF(256) Reed-Solomon)+C++层TEA+swi...
category: reverse
subcategory: reverse
tools_used:
- C
- C++
- Java
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/222465.html
reasoning_chain:
- 强网杯 2024 solve2 APK 解析：TEA + Twofish + RS_MDS_Encode → 触发点：APK 多层加密拼接三段 flag
- C++ 还原：TEA 32 轮 delta=0x9e3779b9 sum=0xC6EF3720 4 key → switchEndian 字节序转换 → 字符串拼接 part1
- Java 层：RS_MDS_Encode 用 Reed-Solomon(12, 8) over GF(256) 产生 AES S-box → 假设：GF(256) Reed-Solomon 代码
- Twofish(key=000102030405060708090a0b0c0d0e0f).decrypt(data1) → 假设：标准 Twofish 库
- 异或 data2 ^ enc1 ^ enc2 = part2 → 假设：enc1/dec1/enc2 已知，data2 部分已知
- 拼接 part1 + part2 → flag{iT3N0t7H@tH@E6D0YOV7hInkS0}
failed_attempts:
- 试图单层 TEA 直接拿 flag → 失败：必须三段拼接
- switchEndian 不调 → 失败：字节序错误还原字符串
- Twofish 密钥随机 → 失败：固定 0001...0f
- RS_MDS_Encode 不重建 S-box → 失败：必须重建才能用 Twofish
key_observations:
- APK 逆向需结合 Java 层 RS_MDS_Encode（GF(256) Reed-Solomon）+ C++ 层 TEA + switchEndian 字节序
- Twofish 密钥 = 000102030405060708090a0b0c0d0e0f
- flag 分段拼接 part1 + part2
- RS_MDS_Encode 4 字节 rem + 4 字节 rem + 2 次循环
prerequisites:
- Android APK 逆向（JADX / jadx-gui + IDA）
- TEA 算法 + Reed-Solomon over GF(256)
- Twofish 加密库调用
- 字节序（大小端）转换
```
