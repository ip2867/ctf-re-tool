# 逆向题：DASCTF 2024 赛题解析：Reverse - BabyAndroid

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：DASCTF 2024 ｜ 难度：medium

```yaml
title: DASCTF 2024 赛题解析：Reverse - BabyAndroid
contest: DASCTF
year: 2024
difficulty: medium
vuln_type: reverse
tags:
- android
- jni
- rc4
- custom-hash
- aes-ecb
- in-memory-dex
- dct
attack_chain:
- loadData 读 assets/Sex.jpg (RC4 key="DASCTF")
- InMemoryDexClassLoader 加载 dex
- 反射 site.qifen.note.ui.Encrypto.encrypt
- 自定义 hash 派生 AES 16 字节 key
- AES/ECB/PKCS5Padding 加密
- native JNI encrypt 走 IDCT
- DCT 浮点 29 维
- 逆 IDCT 还原
key_payload: RC4 解 dex + 自定义 hash 派生 AES + IDCT 浮点变换
one_liner: DASCTF 2024 BabyAndroid：Android JNI + RC4 + InMemoryDexClassLoader + AES/ECB + DCT 浮点加密。
lesson: Android 逆向链：assets RC4 → InMemoryDexClassLoader → 反射调用 → 自定义 hash 派生 → AES → native JNI 二次变换。
quality: high
full_path: DASCTF_2024赛题解析：Reverse-BabyAndroid.full.md
meta_path: DASCTF_2024赛题解析：Reverse-BabyAndroid.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: DASCTF 2024 赛题解析：Reverse - BabyAndroid。DASCTF 2024 BabyAndroid：Android JNI + RC4 + InMemoryDexClassLoader + AES/ECB + DCT 浮点加密。。关键路径：loadData 读 assets/Sex.jpg (RC4 key="DASCTF") → InMemoryDexClas...
category: reverse
subcategory: reverse
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/197671.html
reasoning_chain:
- 拿到 APK → jadx 反编译 → site.qifen.note.ui.Encrypt0 类 KEY='DSACTF' + SHA-1 派生 AES/ECB key → 触发点：Java AES/ECB 加密
- 假设：先看 Java Encrypt0.encrypt 流程 → MessageDigest('SHA-1').digest(KEY) → keyBytes16[16] → Cipher 'AES/ECB/PKCS5Padding'
- 资产文件 assets/Sex.jpg → 触发点：RC4 加密 + InMemoryDexClassLoader 加载 dex → 假设：loadData 走 RC4(key='DASCTF') 解密
- 动作：写 Python rc4Decrypt 还原 dex → 文件转 dex 格式 → 反编译 dex 找 Encrypto.encrypt → 自定义 hash 派生 AES key
- 假设：自定义 hash 用 input 字符循环 XOR + 位运算派生 16 字节 key → 动作：复现 customHash 函数
- 假设：native JNI encrypt 走 IDCT 二次加密 → 动作：逆向 libnative.so 找 DCT 浮点 29 维变换
- 动作：逆 IDCT 还原 → 拼 Base64 → 还原 flag
- 观察：链是 assets RC4 → InMemoryDexClassLoader → 反射调用 → 自定义 hash → AES → native JNI IDCT
failed_attempts:
- 试图不解 RC4 直接读 assets/Sex.jpg 当 dex → 失败：内容是 RC4 密文不是 dex
- 试图用 AES/CBC 解密 → 失败：题目用的是 AES/ECB/PKCS5Padding
- 试图不模拟 IDCT 直接用 native 库 → 失败：native 是 32 位 ARM 不能在本机跑
key_observations:
- Android 逆向链：assets RC4 → InMemoryDexClassLoader → 反射调用 → 自定义 hash 派生 → AES → native JNI 二次变换
- SHA-1 派生 16 字节 AES key 是 Android/Java 常见代码模式
- InMemoryDexClassLoader + 反射调用让静态分析难追，必须手动解 RC4 还原 dex
- AES/ECB 不需要 IV，比 CBC 更难检测 padding 错误
- IDCT 浮点变换在 native 层是 Android 加密常见做法（防 Java 层 hook）
prerequisites:
- APK 反编译（jadx / apktool）
- RC4 算法 + AES/ECB/PKCS5Padding
- InMemoryDexClassLoader + Java 反射机制
- DCT/IDCT 浮点变换（Python numpy 复现）
- SHA-1 hash + 自定义 hash 派生
```
