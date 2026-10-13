# 逆向题：破译APK口令，解锁知识宝藏：大狗Unlock活动优质经验分享

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：大狗Unlock活动 2024 ｜ 难度：easy

```yaml
title: 破译APK口令，解锁知识宝藏：大狗Unlock活动优质经验分享
contest: 大狗Unlock活动
year: 2024
difficulty: easy
vuln_type: reverse
tags:
- APK逆向
- jadx反编译
- AndroidManifest.xml
- Frida hook
- 云真机平台
- ROT偏移
- cyberchef
- Check类异或
- 静态+动态双解
attack_chain: jadx反编译APK→AndroidManifest.xml定位MainActivity→静态算法分析（ROT21偏移/异或）→云真机+Frida hook动态取随机数/修改Checker.code.value=512→提交flag
key_payload: ROT21偏移:chr(ord(char)-21)+26补偿;Dagou{Unlok_HOOK_0x1};Checker.code.value=512;frida Java.use + 复制片段
one_liner: 大狗Unlock 1-5题全解：APK静态jadx+ROT21/异或+动态Frida hook+云真机
lesson: 大狗云真机平台+Frida hook组合；APK定位用AndroidManifest.xml的LAUNCHER；ROT偏移负数补偿
quality: medium
full_path: 破译APK口令，解锁知识宝藏：大狗Unlock活动优质经验分享.full.md
meta_path: 破译APK口令，解锁知识宝藏：大狗Unlock活动优质经验分享.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 破译APK口令，解锁知识宝藏：大狗Unlock活动优质经验分享。大狗Unlock 1-5题全解：APK静态jadx+ROT21/异或+动态Frida hook+云真机。经验：大狗云真机平台+Frida hook组合；APK定位用AndroidManifest.xml的LAUNCHER；ROT偏...
category: reverse
subcategory: reverse
tools_used:
- Frida
- Java
time_required: quick
difficulty_score: 2
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/223172.html
reasoning_chain:
- APK拖入jadx → 触发点：先看AndroidManifest.xml
- 动作：定位android.intent.category.LAUNCHER → com.nosugar.dagou_challenge_01.MainActivity
- 假设：MainActivity里找flag输出函数 → 观察：transform_string() ROT21偏移
- 动作：写Python transform_string() 'Yvbjp{Pigjf_CJJF_0s1}' chr(ord(char)-21)+26补偿
- 观察：运行得Dagou{Unlok_HOOK_0x1} → 静态解题完成
- 动态解：Frida hook get_random → 启动APP加载脚本+重启 → 取随机数计算i*2+4=i2提交
- 题目二：cyberchef直接解密（找key+密文+算法） → 动态Frida修改Checker.code.value=512
- 题目三：Check.get_flag异或 → cyberchef解
failed_attempts:
- 试图不重启APP加载Frida脚本 → 失败：脚本需在类加载前注入
- 试图忽略动态解只跑静态 → 失败：部分flag依赖动态随机数
- 用错了大狗平台云真机的脚本挂载点 → 失败：脚本需挂App进程
key_observations:
- AndroidManifest.xml LAUNCHER是APK定位入口
- jadx右键复制Frida片段可加速hook开发
- ROT偏移负数补偿 chr(ord(char)-21)+26 是字母表循环
- Frida修改Java静态字段 Checker.code.value=512 是动态改值
- 大狗云真机+Frida组合 = APK动态破解省去本地环境配置
prerequisites:
- jadx APK反编译使用
- AndroidManifest.xml LAUNCHER定位
- Frida hook Java方法与字段
- ROT偏移/赛博厨子/CyberChef解码
```
