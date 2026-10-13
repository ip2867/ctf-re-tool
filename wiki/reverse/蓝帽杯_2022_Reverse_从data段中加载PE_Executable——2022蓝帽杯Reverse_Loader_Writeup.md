# 逆向题：从data段中加载PE Executable——2022蓝帽杯Reverse Loader Writeup

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：蓝帽杯 2022 Reverse 2022 ｜ 难度：hard

```yaml
title: 从data段中加载PE Executable——2022蓝帽杯Reverse Loader Writeup
contest: 蓝帽杯 2022 Reverse
year: 2022
difficulty: hard
vuln_type: reverse
tags:
- PE加载器
- 无文件PE
- IAT修复
- Base Relocation
- CRC32
- GetProcAddress
- PEB
- LDR
- InMemoryOrderModuleList
- Pell方程
- big num
- nim
attack_chain:
- VirtualProtect 把 .data 段设为 RWX 加载内嵌 PE dump
- 修改栈顶 rip 跳转到 code+0x34000 主逻辑
- gs:[0x60] 拿 PEB 指针 → PEB:[0x18] 拿 LDR 指针
- LDR:[0x20] 拿 InMemoryOrderModuleList 遍历已加载模块
- 解析 kernel32.dll 的 IMAGE_NT_HEADERS + IMAGE_DATA_DIRECTORY 拿 Export table
- 用 0xEDB88320 多项式 CRC32 校验函数名查 GetProcAddress
- lodsd 取下一个 checksum 循环查 LoadLibraryA
- 处理 Import Table IMAGE_IMPORT_DESCRIPTOR FirstThunk 填绝对地址
- 处理 Base Relocation Table 遍历每个要改写地址加上 code 基址
- 跳转 OEP 后是 nim 编译逻辑：input 解析 big num
- 约束 num1*num1-11*num2*num2 == 9 + big1 < num1 < big2
- sage 算 Pell 方程 x²-11y²=1 连分数收敛子
- 复合 (x1,y1)×(x2,y2) 找 num1 = 3x, num2 = 3y
key_payload: '''flag{%018d%018d}'' % (num1, num2)'
one_liner: 手写 PE Loader 从 .data 段加载无文件 PE，IAT 用 CRC32 查表 + Base Relocation；nim 关键逻辑是 Pell 方程 x²-11y²=1 求解。
lesson: 无文件 PE 加载 = VirtualProtect RWX + 手写 IAT (CRC 查函数名) + Base Relocation; Pell 方程 x²-Dy²=1 用连分数 convergents + 复合群无限解。
quality: high
full_path: 从_data_段中加载_PE_Executable_——_2022-蓝帽杯-Reverse-Loader_Writeup.full.md
meta_path: 从_data_段中加载_PE_Executable_——_2022-蓝帽杯-Reverse-Loader_Writeup.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: 从data段中加载PE Executable——2022蓝帽杯Reverse Loader Writeup。手写 PE Loader 从 .data 段加载无文件 PE，IAT 用 CRC32 查表 + Base Relocation；nim 关键逻辑是 Pell 方程 x²-11y²=1 求解。。关键路径：VirtualProtect 把 .data 段设为 RWX 加载内嵌 PE dum...
category: reverse
subcategory: reverse
tools_used:
- Sage
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/48420.html
reasoning_chain:
- 题目 Loader 从 .data 段加载 PE → 触发点：手写 PE Loader 机制
- VirtualProtect 把 .data 段设为 RWX + 修改栈顶 rip → code+0x34000
- 动作：gs:[0x60] 拿 PEB → PEB:[0x18] 拿 LDR → LDR:[0x20] 拿 InMemoryOrderModuleList
- 假设：遍历已加载模块 → 动作：解析 kernel32.dll 的 IMAGE_NT_HEADERS + IMAGE_DATA_DIRECTORY
- 0xEDB88320 多项式 → CRC32 校验函数名查 GetProcAddress → lodsd 取下一个 checksum
- 处理 Import Table IMAGE_IMPORT_DESCRIPTOR FirstThunk 填绝对地址
- 处理 Base Relocation Table 遍历每个要改写地址 + code 基址
- 跳转 OEP 后 nim 编译逻辑 → input 解析 big num
- 约束 num1*num1-11*num2*num2 == 9 + big1 < num1 < big2
- 动作：sage 算 Pell 方程 x²-11y²=1 连分数收敛子 → 复合 (x1,y1)×(x2,y2) 找 num1 = 3x, num2 = 3y
failed_attempts:
- 试图直接看 .data 段二进制 → 失败：反汇编需要 base relocation
- 试图用 Process Hacker 跟 LoadLibrary → 失败：手写 loader 不调系统
- 试图暴力搜索 Pell 解 → 失败：解太多需组合
key_observations:
- 无文件 PE 加载 = VirtualProtect RWX + 手写 IAT (CRC 查函数名) + Base Relocation
- Pell 方程 x²-Dy²=1 用连分数 convergents + 复合群无限解
- PEB_LDR_DATA.InMemoryOrderModuleList 是无 GetModuleHandle 的标准查询姿势
- CRC32 0xEDB88320 多项式是 CTF shellcode 函数名匹配常用方法
prerequisites:
- PE 文件结构（IMAGE_DOS_HEADER/NT_HEADERS/EXPORT/IMPORT/RELOCATION）
- Pell 方程数论基础
- Sage 数学工具使用
- Windows PEB/LDR 进程内部结构
```
