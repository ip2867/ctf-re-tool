# 逆向题：【CyberDefenders】TeamSpy【Walkthrough】

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：CyberDefenders 2024 ｜ 难度：medium

```yaml
title: 【CyberDefenders】TeamSpy【Walkthrough】
contest: CyberDefenders
year: 2024
difficulty: medium
vuln_type: forensic_disk
tags:
- volatility-2
- imageinfo
- malfind
- Win7SP1x64
- vmem
- mimikatz
- lsadump
- svchost-injection
- explorer-process
attack_chain: vol.py imageinfo 识 Win7SP1x64 + malfind 找 svchost.exe 0x5c40000 PAGE_EXECUTE_READWRITE 注入 + explorer.exe 0x49f0000 注入（mov rax 0xfe2d7cf8 跳转）+ hashdump + lsadump + mimikatz
key_payload: Win7SP1x64 profile  DTB=0x187000  KDBG=0xf800029ed070
one_liner: CyberDefenders TeamSpy 内存取证 WP，Win7SP1x64 镜像 + svchost/explorer 进程注入 + mimikatz 凭据提取。
lesson: volatility 2 imageinfo 优先 Win7SP1x64 候选；malfind 找 PAGE_EXECUTE_READWRITE + VadS 进程注入点；mimikatz 配合 lsadump 提取 Windows 凭据。
quality: high
full_path: 【CyberDefenders】TeamSpy【Walkthrough】.full.md
meta_path: 【CyberDefenders】TeamSpy【Walkthrough】.meta.md
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: 【CyberDefenders】TeamSpy【Walkthrough】。CyberDefenders TeamSpy 内存取证 WP，Win7SP1x64 镜像 + svchost/explorer 进程注入 + mimikatz 凭据提取。。经验：volatility 2 imageinfo 优先 Win7SP1x64 候选；malfind 找 PAGE_EXECU...
category: forensic
subcategory: disk_forensics
tools_used:
- Python
- Volatility
time_required: medium
difficulty_score: 3
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/151190.html
wp_author: the
reasoning_chain:
- vol.py imageinfo 识 Win7SP1x64 → 触发点：vmem 内存镜像分析
- 假设：DTB=0x187000 + KDBG=0xf800029ed070 → 动作：选 Win7SP1x64 profile
- malfind 找 svchost.exe 0x5c40000 PAGE_EXECUTE_READWRITE 注入 → 触发点：可疑 RWX 内存
- explorer.exe 0x49f0000 注入（mov rax 0xfe2d7cf8 跳转）→ 假设：进程注入
- 动作：hashdump + lsadump + mimikatz → 观察：拿到 Windows 凭据
- 假设：mimikatz 提取 NTLM 凭据 → flag
failed_attempts:
- 试图用 Win7SP0x64 profile → 失败：DTB/KDBG 不匹配
- 试图用 pslist 看进程列表 → 失败：malfind 才能定位注入点
key_observations:
- volatility 2 imageinfo 优先 Win7SP1x64 候选
- malfind 找 PAGE_EXECUTE_READWRITE + VadS 进程注入点
- mimikatz 配合 lsadump 提取 Windows 凭据
- mov rax 0xfe2d7cf8 是进程注入跳转指令典型模式
prerequisites:
- Volatility 2 imageinfo + profile 选择
- malfind 注入点定位
- mimikatz / lsadump 凭据提取
- Windows 凭据体系（NTLM hash）
```
