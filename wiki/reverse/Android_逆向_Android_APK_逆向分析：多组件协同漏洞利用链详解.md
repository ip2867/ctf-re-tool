# 逆向题：Android APK 逆向分析：多组件协同漏洞利用链详解

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：Android 逆向 2025 ｜ 难度：hard

```yaml
title: Android APK 逆向分析：多组件协同漏洞利用链详解
contest: Android 逆向
year: 2025
difficulty: hard
vuln_type: reverse
tags:
- APK反编译
- WebActivity未导出
- CoreService normal权限
- AIDL a.Stub
- MiscService透传Intent
- CLASS_NAME
- libWaWaWa.so 娜迦加固
- DT_STRTAB损坏
- JNI decode
- Serializable DTO
- DES key/iv
attack_chain:
- apktool d Load -o decompiled 反编译
- WebActivity(未导出) 需走 Intent 跳板
- CoreService (normal 权限) AIDL a.Stub 提供 Load.getUrl/getToken/getIv + decode
- MiscService (已导出) 透传 Intent CLASS_NAME + putExtras
- b implements Serializable { key, iv, status } DTO
- WebActivity 读 Serializable b 实例, 满足 c()="loading" 调 Load.decode
- libWaWaWa.so 32 位 ARM, DT_STRTAB 损坏, 娜迦加固特征
- 'JNI: Java_com_example_wawawa_Load_decode / getUrl / getToken / getIv'
- '攻击: 通过 MiscService 启动 WebActivity, 传 Serializable b 实例'
- 申请 normal 权限 com.example.wawawa.permission.CORE_SERVICE
key_payload: '''APK 多组件协同 / MiscService Intent 透传 / WebActivity 未导出但可间接启动 / CoreService AIDL a.Stub / 娜迦加固 / Serializable b DTO / JNI decode'''
one_liner: Android 多组件协同漏洞链 — APK 反编译 + MiscService (已导出) 透传 Intent CLASS_NAME 启动未导出 WebActivity + CoreService AIDL 远程调 JNI 拿 key/iv + libWaWaWa.so 娜迦加固解密。
lesson: Android normal 权限形同虚设,任何 app 可申请;MiscService 透传 Intent 是常见未导出组件攻击跳板;娜迦加固 DT_STRTAB 损坏是显著特征;Serializable DTO 跨进程传参可携带攻击 payload。
quality: high
full_path: Android_APK逆向分析：多组件协同漏洞利用链详解.full.md
meta_path: Android_APK逆向分析：多组件协同漏洞利用链详解.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: Android APK 逆向分析：多组件协同漏洞利用链详解。Android 多组件协同漏洞链 — APK 反编译 + MiscService (已导出) 透传 Intent CLASS_NAME 启动未导出 WebActivity + CoreService AIDL 远程调 JNI 拿 key/iv + libWaWaWa.so 娜迦加固解密。。关键路径：apktool d Load -o...
category: misc
subcategory: misc_other
tools_used:
- ARM
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/284169.html
reasoning_chain:
- '[触发点] APK 反编译出 AndroidManifest.xml → 假设：WebActivity 未导出 + CoreService normal 权限 + MiscService 已导出 / [动作] apktool d Load -o decompiled 看 manifest / [观察] MiscService 是跳板 / [下一步] 走 MiscService 透传 Intent 启动 WebActivity'
- '[触发点] MiscService 透传 Intent CLASS_NAME + putExtras → 假设：可启动任意未导出 Activity / [动作] 通过 MiscService 启动 WebActivity 并传 Serializable b 实例 / [观察] WebActivity 读 Serializable b 实例，满足 c() = ''loading'' 调 Load.decode / [下一步] 调 CoreService AIDL'
- '[触发点] CoreService 是 AIDL a.Stub 提供 Load.getUrl/getToken/getIv + decode → 假设：normal 权限形同虚设 / [动作] 申请 normal 权限 com.example.wawawa.permission.CORE_SERVICE / [观察] 可调 Load.decode 拿 DES key/iv / [下一步] 还原 DES key/iv'
- '[触发点] libWaWaWa.so 32 位 ARM + 娜迦加固 + DT_STRTAB 损坏 → 假设：JNI Java_com_example_wawawa_Load_decode / getUrl / getToken / getIv / [动作] IDA / Ghidra 静态分析 so / [观察] 拿到 JNI 函数还原 DES key/iv / [下一步] 解出 flag'
failed_attempts:
- 试图直接启动 WebActivity → 失败：未导出需 Intent 透传
- 试图用 Ghidra 静态跑 so → 失败：娜迦加固 DT_STRTAB 损坏
key_observations:
- Android normal 权限形同虚设，任何 app 可申请
- MiscService 透传 Intent 是常见未导出组件攻击跳板
- 娜迦加固 DT_STRTAB 损坏是显著特征
- Serializable DTO 跨进程传参可携带攻击 payload
prerequisites:
- Android 组件安全（Activity / Service / AIDL）
- apktool / jadx 反编译工具链
- IDA / Ghidra 静态分析 so
- Android 权限机制 (normal / dangerous)
```
