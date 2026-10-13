# 逆向题：N1CTF 2024 ezapk 解题思路 (Android + JNI Frida hook)

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：N1CTF 2024 ｜ 难度：hard

```yaml
title: N1CTF 2024 ezapk 解题思路 (Android + JNI Frida hook)
contest: N1CTF
year: 2024
difficulty: hard
vuln_type: reverse
tags:
- Android APK
- JNI native1/native2
- Frida hook
- JNI 字符串转换
- 内存读写
attack_chain: '|'
key_payload: '|'
one_liner: 'N1CTF 2024 ezapk: Android APK + native1/native2 JNI, Frida hook MainActivity.enc 观察明文/密文对比还原 flag。'
lesson: '|'
quality: medium
full_path: N1CTF-ezapk_解题思路.full.md
meta_path: N1CTF-ezapk_解题思路.meta.md
images_removed: true
images_removed_count: 9
schema_version: v3.0.0-P0
summary: 'N1CTF 2024 ezapk 解题思路 (Android + JNI Frida hook)。N1CTF 2024 ezapk: Android APK + native1/native2 JNI, Frida hook MainActivity.enc 观察明文/密文对比还原 flag。。经验：|'
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 9
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/217460.html
reasoning_chain:
- 触发点：MainActivity binding.CheckButton.onClick 读 flagText + startsWith('n1ctf{') && endsWith('}') → 假设：substring(6, length-1) 是密文原文
- 动作：enc("...").equals("iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A=") → 假设：enc 是 native 方法，密文是 base64
- 假设：native1.so + native2.so 是链式加载（loadLibrary('native1') + loadLibrary('native2')）→ 动作：Frida hook
- 动作：Java.perform(() => { const MainActivity = Java.use('com.n1ctf2024.ezapk.MainActivity'); MainActivity.enc.implementation = function(input) { ... } })
- 假设：Frida 拦截 enc 后可观察密文 / 调自定义逻辑 → 动作：遍历输入 + 比对 'iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A='
- JNI 内存模型：GetStringUTFChars(env, s, 0) 拿 C 字符串 + ReleaseStringUTFChars(env, s, str) 释放 → 假设：标准 JNI 字符串转换
- 观察：Frida hook 后明文/密文对比 → 还原 flag n1ctf{<中间部分>}
failed_attempts:
- 试图直接 jadx 反编译 native 方法 → 失败：native1/native2 是 .so，逻辑在 C 层不在 Java 层
- 试图用 apktool 反编译找硬编码 key → 失败：key 在 native 层，必须动态 hook
- 试图不 hook 直接调 MainActivity.enc 试输入 → 失败：原方法会真实加密，需要 hook 拦截才能比对
key_observations:
- Android loadLibrary('native1') + loadLibrary('native2') 链式加载是 APK + 多 .so 题的标准结构
- Frida Java.use + .implementation 拦截 native 方法是 APK 逆向的标准武器
- JNI 标准符号：Java_<package>_<class>_<method>（包名/类名/方法名替换）
- JNI GetStringUTFChars 拿 jstring, ReleaseStringUTFChars 释放 = JNI 字符串转换标准范式
- 目标密文 'iRrL63tve+H72wjr/HHiwlVu5RZU9XDcI7A=' 是 base64，可能是 AES/DES/RSA
prerequisites:
- Android APK 逆向基础（jadx + apktool + IDA/Ghidra）
- JNI native 方法 hook（Frida Java.use / .implementation）
- base64 / AES / DES / RSA 加密算法识别
- Java.perform + 拦截回调写法
```
