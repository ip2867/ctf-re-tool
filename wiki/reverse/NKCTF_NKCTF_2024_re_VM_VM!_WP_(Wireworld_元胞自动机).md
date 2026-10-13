# 逆向题：NKCTF 2024 re VM?VM! WP (Wireworld 元胞自动机)

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：NKCTF 2024 ｜ 难度：hard

```yaml
title: NKCTF 2024 re VM?VM! WP (Wireworld 元胞自动机)
contest: NKCTF
year: 2024
difficulty: hard
vuln_type: reverse
tags:
- Wireworld 元胞自动机
- 2324x2324 像素图
- IDA 数据提取
- PIL 绘图
- decode XOR bit 流
attack_chain: '|'
key_payload: '|'
one_liner: NKCTF 2024 re VM?VM! — 2324x2324 Wireworld 元胞自动机 (0x914 像素) + XOR bit 流解码还原 flag。
lesson: '|'
quality: high
full_path: NKCTF2024_re_VM？VM！WP.full.md
meta_path: NKCTF2024_re_VM？VM！WP.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: NKCTF 2024 re VM?VM! WP (Wireworld 元胞自动机)。NKCTF 2024 re VM?VM! — 2324x2324 Wireworld 元胞自动机 (0x914 像素) + XOR bit 流解码还原 flag。。经验：|
category: reverse
subcategory: reverse
tools_used:
- IDA
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/197341.html
reasoning_chain:
- 触发点：2324x2324 像素图 + Wireworld 元胞自动机 + sub_1570 加密主逻辑输出 1 → 假设：模拟元胞自动机后导出结果
- Wireworld 规则：空 → 空；电子头 → 电子尾；电子尾 → 导体；当仅有一个或两个电子头的邻居是导体时，导体 → 电子头
- 动作：数据提取 IDA api 读 0x4018-0x535D93 字节 → 假设：导出 byte 数组 → PIL 渲染
- 假设：0x914x0x914 像素图 + 5 颜色（0x01 红/0xEC 蓝/0x11 绿/0xCD 黑/0x80 黄/0xEA 青）→ 动作：PIL new('RGB', (0x914, 0x914))
- 假设：Wireworld Simulator 在线模拟 → 观察：信号消失 = 异或 (XOR) 逻辑门
- 动作：decode XOR bit 流（key0/1/2/3）还原 res 序列 → long_to_bytes 转 flag
- 观察：1 是终点，到达就返回 1 → 完成
failed_attempts:
- 试图直接 IDA 反编译 sub_1570 → 失败：函数太大加载不出，必须先提取数据 + 元胞自动机模拟
- 试图用 Ghidra 自动分析 → 失败：加密逻辑分散在 2324x2324 像素图元胞自动机模拟结果中
- 试图不渲染像素图直接 XOR bit 流 → 失败：必须先模拟元胞自动机得到原始 bit 流
key_observations:
- Wireworld 元胞自动机是 CTF Reverse 出题热门（4 种 cell 状态 + 邻居规则）
- 2324x2324 像素图 = 5 颜色编码（0x01 红/0xEC 蓝/0x11 绿/0xCD 黑/0x80 黄/0xEA 青）
- Wireworld Simulator 在线工具可直接模拟（元胞自动机信号消失 = XOR 逻辑门）
- IDA 提取 byte 数组 + PIL 渲染是 Reverse 数据还原标准武器
- decode XOR bit 流 (key0/1/2/3) + long_to_bytes 转 flag 是 bit 流 flag 标准范式
prerequisites:
- Wireworld 元胞自动机规则（4 种 cell 状态）
- IDA Python API 提取数据（idaapi.get_byte）
- PIL 像素图渲染（Image.new + putpixel）
- bit 流 XOR 解码 + long_to_bytes 转字符串
```
