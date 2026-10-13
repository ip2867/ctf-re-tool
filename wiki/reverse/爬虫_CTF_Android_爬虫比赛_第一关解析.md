# 逆向题：Android 爬虫比赛 第一关解析

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：爬虫 CTF 2022 ｜ 难度：medium

```yaml
title: Android 爬虫比赛 第一关解析
contest: 爬虫 CTF
year: 2022
difficulty: medium
vuln_type: reverse
tags:
- yuanrenxue match2022
- frida hook
- Sign.sign
- page+timestamp
- retrofit2
- BodyObservable
- lambda$initListeners$2
- Python累加
- 看雪论坛
attack_chain:
- jadx 反编译 com.yuanrenxue.match2022
- 翻页时抓包, 发现 page + t + sign 三个参数
- frida hook ChallengeOneFragment.lambda$initListeners$2(OooOO0O) 看 this.page.value
- sb = "page=" + page + timestamp → bArr = bytearray utf8
- frida hook Sign.sign(byte[]) 拿加密结果
- Python rpc.exports.callsecretfunctionedy(bArr) 调 Java Sign.sign
- 100 页累加 value 即 flag count
key_payload: '''page + timestamp 拼接 / Sign.sign(bArr) 加密 / retrofit2 BodyObservable 返回值 / 100 页累加 / frida rpc.exports'''
one_liner: 猿人学 Android 爬虫第一关 — frida hook ChallengeOneFragment + Sign.sign + Python rpc.exports.callsecretfunctionedy + 100 页 value 累加得 flag count。
lesson: frida + rpc.exports 是 Java <-> Python 跨语言调标准做法;byte[] 参数先 bytearray('utf-8') 再传;sign 加密是 page+timestamp 拼接后单函数。
quality: high
full_path: Android爬虫比赛_第一关解析.full.md
meta_path: Android爬虫比赛_第一关解析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: Android 爬虫比赛 第一关解析。猿人学 Android 爬虫第一关 — frida hook ChallengeOneFragment + Sign.sign + Python rpc.exports.callsecretfunctionedy + 100 页 value 累加得 flag count。。关键路径：jadx 反编译 com.yuanrenxue.match2022 → ...
category: web
subcategory: web_other
tools_used:
- Frida
- Java
- Python
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/92066.html
reasoning_chain:
- '[触发点] frida hook ChallengeOneFragment.lambda$initListeners$2(OooOO0O) → 假设：翻页请求是 lambda 触发 / [动作] hook 看 this.page.value + age.OooO00o().longValue() / [观察] sb = "page=" + page + timestamp / [下一步] hook Sign.sign 加密函数'
- '[触发点] frida hook Sign.sign(byte[]) → 假设：Sign 是 page + timestamp 拼接后单函数加密 / [动作] hook Sign.sign(byte[]) 拿参数和返回值 / [观察] bArr = bytearray utf8, Sign.sign 返回加密结果 / [下一步] 用 rpc.exports Python 调用'
- '[触发点] Python 端要调 Java 函数 → 假设：frida rpc.exports 可做跨语言调用 / [动作] rpc.exports.callsecretfunctionedy(bArr) 调 Java Sign.sign / [观察] 拿到加密结果与 fiddler 对比一致 / [下一步] 循环 100 页'
- '[触发点] 拿到 sign 后可批量翻页 → 假设：100 页 value 累加即为 flag count / [动作] 写 Python 循环 1..100 页累加 value / [观察] flag count 还原 / [下一步] 提交'
failed_attempts:
- 试图纯 Python 还原 Sign 算法 → 失败：Java 加密逻辑复杂
- 试图反编译 + 复刻 Sign 类 → 失败：算法混淆复杂
key_observations:
- frida + rpc.exports 是 Java <-> Python 跨语言调标准做法
- byte[] 参数先 bytearray('utf-8') 再传
- sign 加密是 page+timestamp 拼接后单函数
- retrofit2 BodyObservable 是返回值类型识别
prerequisites:
- frida hook Java 函数
- frida rpc.exports 跨语言调用
- retrofit2 网络库
- Python/Java 互操作
```
