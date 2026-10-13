# 逆向题：Frida Hook Android method（一）

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：ad2001 Frida 系列 2023 ｜ 难度：easy

```yaml
title: Frida Hook Android method（一）
contest: ad2001 Frida 系列
year: 2023
difficulty: easy
vuln_type: reverse
tags:
- frida
- android
- hook
- java.perform
- caesar-cipher
- get_random
- check
attack_chain:
- get_random返回0-99随机整数
- check(i, i2) 验证 (i*2)+4==i2
- 成功返回"AMDYV{WVWT_CJJF_0s1}"的Caesar变种
- charAt-21取模26+26
- Frida hook get_random返回真实值
- Frida hook check(int, int)强制参数8, 20
key_payload: 'AMDYV{WVWT_CJJF_0s1}  # Caesar-21后flag'
one_liner: Frida Hook Android：get_random+check函数hook+Caesar-21解flag
lesson: Frida可用Java.use+"implementation"覆盖Java方法
quality: high
full_path: Frida_Hook_Android_method（一）.full.md
meta_path: Frida_Hook_Android_method（一）.meta.md
images_removed: true
images_removed_count: 7
schema_version: v3.0.0-P0
summary: Frida Hook Android method（一）。Frida Hook Android：get_random+check函数hook+Caesar-21解flag。关键路径：get_random返回0-99随机整数 → check(i, i2) 验证 (i*2)+4==i2 → 成功返回"AMDYV{WVWT_CJJF_0s1}"的Caesar变种。经验：Frida可用Java....
category: reverse
subcategory: reverse
tools_used:
- Frida
time_required: quick
difficulty_score: 2
code_blocks_count: 1
images_count: 7
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/151304.html
reasoning_chain:
- 触发点：Android 反编译 smali → MainActivity.check(i, i2) → 触发点：判断 (i*2)+4==i2
- 动作：get_random() 返回 0-99 → 假设：必须输入正确 i2
- 假设：i=random, i2 = i*2+4 → 动作：Hook get_random 真实返回 ret_val
- 动作：Java.perform + Java.use('com.ad2001.frida0x1.MainActivity')
- a.get_random.implementation = function() { var ret_val = this.get_random(); return ret_val; }
- 观察：拿到 ret_val → 假设：i2 = ret_val*2+4 → 动作：输入答案
- 观察：check 通过 → 进入 Caesar-21 解码逻辑（每个字母 charAt-21 再 +26 调整）
- 观察：AMDYV{WVWT_CJJF_0s1} 是密文 → 动作：写脚本 Caesar-21 解 → flag
- 假设：Frida 可绕过随机验证 → 动作：a.check.overload('int','int').implementation = function(a,b){ this.check(8,20); }
- 观察：强制 check 通过 → flag 显示
failed_attempts:
- 试图爆破 0-99 全部答案 → 失败：check 内部判断逻辑复杂
- 试图直接修改 smali 文件重打包 → 失败：需重新签名
- 试图 Caesar-26 → 失败：偏移量是 21 不是 26
key_observations:
- Frida Java.use + Java.perform 是 Android hook 标准入口
- implementation = function() { return ret_val; } 保留原方法调用
- Caesar-21 偏移 + 26 调整（向下溢出）= 字母表 wrap
- check 函数强类型 int/int 用 overload('int','int') 区分
- Frida hook 比 smali patch 重打包快得多
prerequisites:
- Frida 基础（Java.use/perform/implementation）
- Android smali 语法
- Caesar 密码偏移 + 取模 wrap
- Java 重载方法签名（overload）
```
