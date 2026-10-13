# 逆向题：[CTF] ECW CTF 2022 – Reverse challenges writeup

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：ECW CTF 2022 2022 ｜ 难度：hard

```yaml
title: '[CTF] ECW CTF 2022 – Reverse challenges writeup'
contest: ECW CTF 2022
year: 2022
difficulty: hard
vuln_type: esoteric
tags:
- minifilter_driver
- flt_registration
- xor_rand_bytes_encrypt
- efi_decompress_protocol
- opengl_ld_preload_hook
- glsl_330_core
- gl_fragcoord_uniform
- glteximage2d_data_extract
- ctf_re_3chals
attack_chain: '1) Minifilter 驱动 FLT_REGISTRATION 结构 + encrypt(buf, len, value) ^ rand_bytes[i%4] + file.txt.lock → key=[\xff,\xfe,E,0] + off+value 1+2+... 累加 XOR → utf-16 输出 flag / 2) EFI Decompress Protocol + cipher utf-16 切片 + off 0x200+2*24 chr(cipher[off]+4) / 3) HotShotGL OpenGL hook.so LD_PRELOAD + glCreateShader + glTexImage2D data 提取 + #version 330 core + gl_FragCoord.x*0xF117+0xA380 % 256 + uniform AN225 / uniform int X15[63] + gl_FragCoord.x+13 + ~(a^b) 还原 flag'
key_payload: key = [data[0] ^ 1 ^ 0xff, data[1] ^ 1 ^ 0xfe, data[2] ^ 1 ^ 0x45, data[3] ^ 1 ^ 0] / cipher = "x0cV$2ekF2Q..." 切片 [0x200:0x200+2*24] / glTexImage2D width=164 height=1 data <izmlvpq...> / flag[i] = ~((i*0xF117+0xA380)%256 ^ X15[i+13])
one_liner: ECW CTF 2022 三道逆向：Minifilter 驱动文件加密 + EFI Decompress Protocol UTF-16 + OpenGL hook.so LD_PRELOAD 提取 GLSL Fragment Shader uniform 计算。
lesson: OpenGL hook LD_PRELOAD glTexImage2D 是提取 Fragment Shader 输入的经典方法；Minifilter 驱动用 FLT_REGISTRATION 结构定位 PreOperation 回调是 Win 驱动逆向起点。
quality: high
full_path: '[CTF]_ECW_CTF_2022_–_Reverse_challenges_writeup.full.md'
meta_path: '[CTF]_ECW_CTF_2022_–_Reverse_challenges_writeup.meta.md'
images_removed: true
images_removed_count: 0
schema_version: v3.0.0-P0
summary: '[CTF] ECW CTF 2022 – Reverse challenges writeup。ECW CTF 2022 三道逆向：Minifilter 驱动文件加密 + EFI Decompress Protocol UTF-16 + OpenGL hook.so LD_PRELOAD 提取 GLSL Fragment Shader uniform 计算。。经验：OpenGL hook L...'
category: misc
subcategory: misc_other
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 0
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/60146.html
reasoning_chain:
- 触发点:第一题是 Minifilter 驱动 .sys → 假设:有 FLT_REGISTRATION 结构 + PreOperation 回调 → 动作:IDA 静态分析 DriverEntry
- 观察:encrypt(buf, len, value) ^ rand_bytes[i%4] + 写入 file.txt.lock → 假设:key=[0xff,0xfe,E,0] 可爆破
- 动作:data[0] ^ 1 ^ 0xff, data[1] ^ 1 ^ 0xfe, data[2] ^ 1 ^ 0x45, data[3] ^ 1 ^ 0 → 观察:还原 key
- 动作:off+value 1+2+... 累加 XOR → utf-16 输出 flag → 完成第一题
- 触发点:第二题 EFI Decompress Protocol → 假设:cipher utf-16 切片 → 动作:off 0x200+2*24 chr(cipher[off]+4)
- 观察:还原 flag 第二题
- 触发点:第三题 HotShotGL OpenGL hook.so LD_PRELOAD → 假设:glTexImage2D data 可提取 → 动作:hook.so LD_PRELOAD
- 动作:hook glCreateShader + glTexImage2D → 观察:width=164 height=1 data=<izmlvpq...> → 假设:fragment shader 计算 flag
- 动作:flag[i] = ~((i*0xF117+0xA380)%256 ^ X15[i+13]) → 观察:还原 flag → 完成
failed_attempts:
- 试图直接 IDA F5 Minifilter → 失败:驱动代码需先看 FLT_REGISTRATION 结构
- 试图不解 EFI Decompress → 失败:off+value 累加 XOR 必走
- 试图不解 OpenGL hook → 失败:fragment shader uniform X15 必须 hook glTexImage2D 取
key_observations:
- OpenGL hook LD_PRELOAD glTexImage2D 是提取 Fragment Shader 输入的经典方法
- Minifilter 驱动用 FLT_REGISTRATION 结构定位 PreOperation 回调是 Win 驱动逆向起点
- EFI Decompress Protocol + cipher utf-16 切片是 UEFI 逆向通用思路
- fragment shader 计算公式 flag[i] = ~((i*0xF117+0xA380)%256 ^ X15[i+13]) 是固定套路
- GL_PRELOAD hook 比 Frida hook OpenGL 更轻量,适合 CTF 时限
prerequisites:
- Windows Minifilter 驱动开发基础 (FLT_REGISTRATION / PreOperation)
- UEFI / EFI Decompress Protocol 协议基础
- OpenGL hook.so LD_PRELOAD + GLSL Fragment Shader
- IDA 驱动逆向 (PDB 符号 / DriverEntry)
```
