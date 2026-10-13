# 逆向题：Nep CTF password RC4 + 换表 base64 算法分析 (Android JNI)

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：Nep CTF 2023 ｜ 难度：hard

```yaml
title: Nep CTF password RC4 + 换表 base64 算法分析 (Android JNI)
contest: Nep CTF
year: 2023
difficulty: hard
vuln_type: reverse
tags:
- Android APK
- JNI verify
- 自定义 base64 字符表
- RC4
- v28/v30 算法还原
attack_chain: '|'
key_payload: '|'
one_liner: 'Nep CTF password: Android JNI verify + 自定义 base64 字符表 (小写字母+数字+大写字母+符号) + RC4 加密, v30 数组反推算法。'
lesson: '|'
quality: high
full_path: Nep_CTF_password：rc4和换表base64算法分析.full.md
meta_path: Nep_CTF_password：rc4和换表base64算法分析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 'Nep CTF password RC4 + 换表 base64 算法分析 (Android JNI)。Nep CTF password: Android JNI verify + 自定义 base64 字符表 (小写字母+数字+大写字母+符号) + RC4 加密, v30 数组反推算法。。经验：|'
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/167920.html
reasoning_chain:
- Android APK 题 → 触发点：首页 verify(String str) 与 file(byte[] bArr, String str) 两块验证
- file 函数比对硬编码 iArr2 = {139, 210, 217, 93, ...} → 假设：解密后等于该数组
- 动作：APK 解压 → IDA 打开 so → 定�� Java_com_nepnep_app_MainActivity_verify
- 观察：JNI 函数 strcmp 比较 '3g6L2PWL2PXFmR+7ise7iq==' → 假设：v28 处理后需等于该串
- v28 字符串处理循环：每 3 字符块 + 余数 → 触发点：sub_77C + sub_8A4
- 自定义 base64 表：'abcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ'
- 动作：反推 v30 数组：v30[i] = 表中 '3' 位置 = 29 → 假设：可逆算
- 观察：完整还原 v30[0..23] → 下一步：java 层 RC4 解密
- 假设：RC4 key 已知（题目给）→ 动作：RC4 解 iArr2 → 观察：得到 flag 明文
failed_attempts:
- 试图不解 base64 直接 RC4 → 失败：RC4 输入是 v28 数组非原串
- 用标准 base64 表解码 → 失败：表是字母表 + 数字 + 大写 + 符号混合
- 不解 v30 数组 → 失败：v30 是 base64 表索引必须还原
key_observations:
- 自定义 base64 字母表逆向关键看 v30[] 索引数组
- JNI 函数命名规则 Java_com_xxx_Class_method
- Android APK 反编译三件套 jadx + apktool + IDA
- RC4 流密码对称性可加解密同算法
- 硬编码 byte[] 对比是 Android 通用校验手法
prerequisites:
- Android JNI 逆向（IDA + jadx）
- 自定义 base64 算法原理
- RC4 流密码加解密
- APK 文件结构
```
