# 逆向题：使用Unidbg在CTF-Android题目的快速解题

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：Unidbg Android CTF 2024 ｜ 难度：medium

```yaml
title: 使用Unidbg在CTF-Android题目的快速解题
contest: Unidbg Android CTF
year: 2024
difficulty: medium
vuln_type: reverse
tags:
- Unidbg
- Android
- JNI
- libj.so
- AbstractJni
- DvmClass
- JNIEnv
- callJniMethodObject
- 模拟执行
attack_chain:
- aapt dump badging apk 看包名 + Activity
- IDA 反编译 libj.so 看 JNI 函数 Java_an_droid_j_MainActivity_j/init/p
- j() 返回 "FlagLostHelpMeGetItBack" 字符串 (内置常量, 长度 30 字节)
- init(I) 接收 1738911344 返回 flag 字符串
- p(I) 循环 99999 次混淆控制流
- 用 Unidbg AndroidEmulatorBuilder.for32Bit() 创建模拟器
- setProcessName("an.droid.j") 避免进程名校验
- memory.setLibraryResolver(new AndroidResolver(23))
- vm.createDalvikVM(File(apkFilePath)) 加载 APK
- vm.loadLibrary(File(soFilePath), true) 加载 so
- vm.setJni(this) 设置 AbstractJni
- dvmClass.newObject(null).callJniMethodObject(emulator, "init(I)Ljava/lang/String;", temp)
- System.out.println("flag{" + result + "}")
key_payload: '''lesson4 + AndroidEmulatorBuilder + callJniMethodObject init(I)'''
one_liner: Unidbg 模拟 Android JNI 调用 libj.so 绕过动态分析，无需真机直接拿到 flag。
lesson: Unidbg 是 Android RE 的金钥匙：AndroidEmulatorBuilder + setProcessName + AndroidResolver + createDalvikVM + loadLibrary 五步走，setJni(this) 必加防报错。
quality: high
full_path: 使用Unidbg在CTF-Android题目的快速解题.full.md
meta_path: 使用Unidbg在CTF-Android题目的快速解题.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 使用Unidbg在CTF-Android题目的快速解题。Unidbg 模拟 Android JNI 调用 libj.so 绕过动态分析，无需真机直接拿到 flag。。关键路径：aapt dump badging apk 看包名 + Activity → IDA 反编译 libj.so 看 JNI 函数 Java_an_droid_j_MainActivity_j/init/p → j() 返...
category: reverse
subcategory: reverse
tools_used:
- IDA
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/163430.html
reasoning_chain:
- aapt dump badging apk → 包名 an.droid.j + Activity MainActivity → 触发点：Android JNI
- 动作：IDA 反编译 libj.so → Java_an_droid_j_MainActivity_j/init/p 三个 JNI 函数
- 假设：j() 返回 'FlagLostHelpMeGetItBack' 字符串 → init(I) 接收 1738911344 返回 flag
- p(I) 循环 99999 次混淆控制流 → 静态分析困难
- 动作：用 Unidbg AndroidEmulatorBuilder.for32Bit() 创建模拟器
- setProcessName('an.droid.j') 避免进程名校验 → memory.setLibraryResolver(new AndroidResolver(23))
- vm.createDalvikVM(File(apkFilePath)) + vm.loadLibrary(File(soFilePath), true) + vm.setJni(this)
- dvmClass.newObject(null).callJniMethodObject(emulator, 'init(I)Ljava/lang/String;', temp)
- 输出 flag{...} 完成
failed_attempts:
- 试图用 frida hook init 拿返回值 → 失败：环境依赖复杂
- 试图静态逆 p() 循环 → 失败：99999 次控制流混淆
- 试图不解 APK 加密 → 失败：so 内有 process name 校验
key_observations:
- Unidbg 是 Android RE 的金钥匙：AndroidEmulatorBuilder + setProcessName + AndroidResolver + createDalvikVM + loadLibrary 五步走
- setJni(this) 必加防报错
- JNI 函数命名规则 Java_<package>_<class>_<method>
- process name 校验是 Android so 反调试基础
prerequisites:
- Android JNI 机制（Java/native 互调）
- Unidbg 模拟器使用（AndroidEmulator/DalvikVM）
- IDA 反编译 libj.so
- JNI 函数签名格式
```
