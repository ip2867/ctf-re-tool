# 逆向题：Frida 与 Android CTF

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：看雪/Tide 安全 (kanxue/pediy1) 2022 ｜ 难度：medium

```yaml
title: Frida 与 Android CTF
contest: 看雪/Tide 安全 (kanxue/pediy1)
year: 2022
difficulty: medium
vuln_type:
- reverse
- misc_unknown
tags:
- Frida
- Android
- JNI
- Java.perform
- Java.choose
- enumerateClassLoaders
- Interceptor.replace
- kill
- anti-debug
attack_chain:
- frida -U -f 目标包 spawn 注入
- Java.perform hook 关键方法 VVVV(context, str)
- Java.choose 找 MainActivity 实例注入伪 context
- Java.enumerateClassLoaders 找正确 classloader
- 枚举 0-99999 爆破正确输入拿 true 返回
- Interceptor.replace(libc.so!kill) 绕反调试
key_payload: Java.use("com.kanxue.pediy1.VVVVV").VVVV(CONTEXT2, String(x))
one_liner: Frida hook + 爆破绕过 Android JNI 校验 + kill 拦截绕反调试
lesson: Android CTF 高频工具是 Frida；自定义 classloader 需 enumerateClassLoaders 切换；JNI 反调试常见用 kill(pid, 0) 检测 tracerpid
quality: high
full_path: Frida与Android_CTF.full.md
meta_path: Frida与Android_CTF.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: Frida 与 Android CTF。Frida hook + 爆破绕过 Android JNI 校验 + kill 拦截绕反调试。关键路径：frida -U -f 目标包 spawn 注入 → Java.perform hook 关键方法 VVVV(context, str) → Java.choose 找 MainActivity 实例注入伪 context。经验：Android CT...
category: reverse
subcategory: reverse
subcategories:
- reverse
- misc_other
tools_used:
- Frida
- Java
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/31515.html
reasoning_chain:
- 触发点：frida -U -f 目标包 spawn 注入 → 假设：必须 Java.perform 注入
- 动作：Java.use('com.kanxue.pediy1.VVVVV').VVVV(CONTEXT, str) → 触发点：关键方法 hook
- 假设：VVVV 返回 bool → 假设：必须爆破正确输入 → 动作：0-99999 枚举
- 假设：MainActivity 实例获取真 context → 动作：Java.choose('com.kanxue.pediy1.MainActivity')
- 假设：自定义 classloader → 动作：Java.enumerateClassLoaders() 找正确
- 假设：JNI 反调试用 kill(pid, 0) 检测 tracerpid → 动作：Interceptor.replace(libc.so!kill)
- 假设：返回 0 绕过 → 动作：var kill_func = new NativeFunction(Module.findExportByName('libc.so','kill'),'int',['int','int']);
- Interceptor.replace(kill_func, new NativeCallback(function(pid, sig){ return 0; },'int',['int','int']));
- 观察：tracerpid 检测失效 → 反调试绕过 → 完成
failed_attempts:
- 试图直接 frida --attach 注入 → 失败：必须 spawn 早注入
- 试图用 Frida 直接改 process tracerpid → 失败：必须 hook kill 系统调用
- 试图 attach debugger 调试 → 失败：触发反调试
key_observations:
- frida -U -f 是 spawn 模式最早 hook 时机
- Java.choose 找实例 + Java.enumerateClassLoaders 找正确 loader 是自定 classloader 关键
- Interceptor.replace(NativeFunction) 是 hook native 函数核心
- kill(pid, 0) 检测 tracerpid 是 Android 反调试经典手法
- 0-99999 爆破常见于简单校验函数
prerequisites:
- Frida spawn / attach 模式区别
- Java.use / Java.choose / Java.enumerateClassLoaders
- NativeFunction / Interceptor.replace
- Android JNI 反调试原理（kill tracerpid）
```
