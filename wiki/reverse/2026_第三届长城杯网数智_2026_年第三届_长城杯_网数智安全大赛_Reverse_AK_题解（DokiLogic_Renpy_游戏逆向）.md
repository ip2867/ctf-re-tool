# 逆向题：2026 年第三届"长城杯"网数智安全大赛 Reverse AK 题解（DokiLogic Renpy 游戏逆向）

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：2026 第三届长城杯网数智 2026 ｜ 难度：medium

```yaml
title: 2026 年第三届"长城杯"网数智安全大赛 Reverse AK 题解（DokiLogic Renpy 游戏逆向）
contest: 2026 第三届长城杯网数智
year: 2026
difficulty: medium
vuln_type:
- reverse
- crypto_unknown
- web_unknown
tags:
- 长城杯 2026 第三届 网数智
- Reverse AK 三题
- DokiLogic Renpy 游戏引擎
- rpyc pickle 序列化
- 文件监控拷贝 .1.exe
- UPX 脱壳
- XOR 0x23=35 加密
- renpy script.py load_file 打印 .rpyc
attack_chain:
- Renpy 游戏 → game 目录 .rpyc 文件 → 修改 renpy/script.py Script.load_file 打印加载的 .rpyc
- 还原游戏逻辑：user_input = renpy.input().strip() → l11111l1ll1l(user_input) == ll111l11l111
- 创建 ./1.exe 子程序 → 执行 → 拿密文 → 删除 .1.exe
- Python 脚本文件监控：os.path.exists(".1.exe") → shutil.copy2 → 123.exe
- upx.exe -d 123.exe 脱壳
- 动态调试拿 Buffer 密文
- '加密: chr(ord(c) ^ 35) → 直接异或 35 还原'
key_payload: chr(ord(ll1l111ll11l) ^ llll1l111ll1=35)
one_liner: 2026 长城杯网数智 Reverse AK：DokiLogic Renpy 游戏逆向 - .rpyc 打印 + 文件监控拷贝 .1.exe + UPX 脱壳 + XOR 35。
lesson: Renpy 引擎逆向 = 修改 renpy/script.py load_file 把 .rpyc 反编译输出到日志；游戏运行时临时创建又删除的子程序要文件监控拷贝（inotify/while 轮询）才能拿到；UPX 脱壳后 XOR 35 是经典小加密。
quality: high
full_path: 2026年第三届“长城杯”网数智安全大赛Reverse_AK题解（含总决赛全部题目附件）.full.md
meta_path: 2026年第三届“长城杯”网数智安全大赛Reverse_AK题解（含总决赛全部题目附件）.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 2026 年第三届"长城杯"网数智安全大赛 Reverse AK 题解（DokiLogic Renpy 游戏逆向）。2026 长城杯网数智 Reverse AK：DokiLogic Renpy 游戏逆向 - .rpyc 打印 + 文件监控拷贝 .1.exe + UPX 脱壳 + XOR 35。。关键路径：Renpy 游戏 → game 目录 .rpyc 文件 → 修改 renpy/scr...
category: reverse
subcategory: reverse
subcategories:
- reverse
- crypto_other
- web_other
tools_used:
- Python
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/307007.html
reasoning_chain:
- DokiLogic Renpy 游戏 → 触发点：game 目录 .rpyc 文件是 pickle 序列化的游戏脚本
- 假设：修改 renpy/script.py 的 Script.load_file → 动作：插入 print() 把 .rpyc 反编译输出
- '还原游戏逻辑: user_input = renpy.input().strip() → l11111l1ll1l(user_input) == ll111l11l111 → 假设：方程求解'
- 创建 ./1.exe 子程序 → 执行 → 拿密文 → 删除 .1.exe → 触发点：临时创建又删，文件监控必要
- 'Python 脚本文件监控: os.path.exists(''./1.exe'') → shutil.copy2 → 123.exe'
- upx.exe -d 123.exe 脱壳 → 观察：拿到 Buffer 密文
- '加密: chr(ord(c) ^ 35) → 动作：异或 35 直接得 plaintext'
failed_attempts:
- 试图直接解 .rpyc → 失败：二进制 pickle，需 hook load_file 反序列化
- 用 inotifywait 监控 → 失败：删除速度太快，Python while 轮询更稳
- UPX 不脱壳直接 XOR → 失败：壳代码干扰异或结果
key_observations:
- Renpy 引擎逆向 = 修改 renpy/script.py load_file 把 .rpyc 反编译输出到日志
- 游戏运行时临时创建又删除的子程序要文件监控拷贝才能拿到
- UPX 脱壳后 XOR 35 = 经典小加密
- renpy.input().strip() + 自定义函数 l11111l1ll1l == ll111l11l111 = 方程求解
- Python while os.path.exists 轮询是跨平台文件监控方案
prerequisites:
- Renpy 游戏引擎架构（.rpyc pickle / script.py hook）
- Python 文件监控（os.path.exists while 轮询）
- UPX 脱壳
- XOR 加密还原
```
