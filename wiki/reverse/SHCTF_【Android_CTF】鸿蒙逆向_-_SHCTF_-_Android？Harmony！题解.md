# 逆向题：【Android CTF】鸿蒙逆向 - SHCTF - Android？Harmony！题解

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：SHCTF 2024 ｜ 难度：medium

```yaml
title: 【Android CTF】鸿蒙逆向 - SHCTF - Android？Harmony！题解
contest: SHCTF
year: 2024
difficulty: medium
vuln_type: reverse
tags:
- HarmonyOS
- ArkTS
- ETS-bytecode
- encode-114514
- mod-95
- ASCII-shift
- maze-create
- promptAction
attack_chain: 鸿蒙 ArkTS/ETS 字节码反编译 Index 构造函数初始化 secretKey + __userInput/validateAndCreateMaze 用 encode(arg0) 与 secretKey 比较 + 调 maze.CreateMaze 生成迷宫写 /What 文件/encode 函数 (114514 * (ord - 32) + 1919810) % 95 + 32 字符编码/逆运算 ((y - 32) * 95^(-1) - 1919810) / 114514 + 32 还原
key_payload: secretKey = "[f#fLw)??Pz?#9w)Du[ks[q[#w4D?4P4UJf,kU[f.rDkfwrDtq...)?J.#rP4[qrPDJkkJ|.9J|qffU?k|D4P4P[wkk.)k?JUJ[k#9kww[r??wUfw|PkrPUf.P#f.P#.PwJ4f4q.PU4UPDr9.[9fJ#PqP)cDDffJPDrJ.J4qPP[r[.JfJ4f|?U9#"
one_liner: SHCTF 2024 鸿蒙 ArkTS 逆向，secretKey + encode 字符编码 (114514*x + 1919810) % 95 + 32 还原 + 迷宫生成。
lesson: 鸿蒙 ArkTS 编译为 ETS 字节码，可用 HarmonyOS 反编译工具还原；简单模运算 (a*x + b) % m + offset 可通过 mod 逆元还原输入；迷宫生成函数 CreateMaze(arg0) 把 flag 转迷宫。
quality: medium
full_path: 【Android_CTF]_鸿蒙逆向_—_SHCTF_–_Android？Harmony！题解.full.md
meta_path: 【Android_CTF]_鸿蒙逆向_—_SHCTF_–_Android？Harmony！题解.meta.md
images_removed: true
images_removed_count: 4
schema_version: v3.0.0-P0
summary: 【Android CTF】鸿蒙逆向 - SHCTF - Android？Harmony！题解。SHCTF 2024 鸿蒙 ArkTS 逆向，secretKey + encode 字符编码 (114514*x + 1919810) % 95 + 32 还原 + 迷宫生成。。经验：鸿蒙 ArkTS 编译为 ETS 字节码，可用 HarmonyOS 反编译工具还原；简单模运算 (a*x + b) ...
category: reverse
subcategory: reverse
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 4
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/213606.html
reasoning_chain:
- HarmonyOS APK → HarmonyOS 反编译工具还原 ETS 字节码 → 触发点：Index 构造函数
- 假设：初始化 secretKey + __userInput/validateAndCreateMaze → 动作：看 validateAndCreateMaze 逻辑
- 观察：encode(arg0) 与 secretKey 比较 + maze.CreateMaze 生成迷宫
- encode 函数 (114514 * (ord - 32) + 1919810) % 95 + 32 → 假设：仿射密码变种 → 动作：逆运算 (y-32)*95^-1 - 1919810)/114514 + 32
- 观察：还原 secretKey → flag
failed_attempts:
- 试图用 Android 通用 jadx 工具 → 失败：HarmonyOS 字节码格式不同
- 试图不解 mod 95 逆元直接爆破 → 失败：114514 与 95 互素可解
key_observations:
- 鸿蒙 ArkTS 编译为 ETS 字节码，可用 HarmonyOS 反编译工具还原
- 简单模运算 (a*x + b) % m + offset 可通过 mod 逆元还原输入
- 迷宫生成函数 CreateMaze(arg0) 把 flag 转迷宫
- HarmonyOS 与 Android 字节码不兼容，工具栈独立
prerequisites:
- HarmonyOS ArkTS/ETS 字节码结构
- 模运算逆元求解
- 仿射密码还原
- 迷宫算法识别
```
