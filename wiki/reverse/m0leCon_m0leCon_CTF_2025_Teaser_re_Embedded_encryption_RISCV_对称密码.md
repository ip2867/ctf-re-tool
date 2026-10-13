# 逆向题：m0leCon CTF 2025 Teaser re Embedded encryption RISCV 对称密码

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：m0leCon 2025 ｜ 难度：hard

```yaml
title: m0leCon CTF 2025 Teaser re Embedded encryption RISCV 对称密码
contest: m0leCon
year: 2025
difficulty: hard
vuln_type: reverse
tags:
- risc-v
- mcu
- metal-gpio
- ip-permutation
- p-box
- row-column-sum
- gpio-input-pin
- custom-block-cipher
attack_chain:
- 识别 RISC-V 32 位固件
- metal_gpio_get_input_pin 读 1 位随机种子
- srand+rand 用内置库
- 'var644[1604] 分四区: m32[32]/input[33]/m256[256]/output[256*4]'
- IP 置换表 (32 字节)
- P 盒映射 (256 字节)
- 重复 1337 轮
- output[input[j]] = 1 << (31-j)
- 行列和反推 input
- 解密
key_payload: 1 位种子 + IP/P 盒 + 行列和反推
one_liner: m0leCon 2025 Teaser 嵌入式逆向，RISC-V 自定义分组密码 + 行列和反推 output。
lesson: 当 output 矩阵每行/列只有 1 位为 1 时，行列和反推是经典线性代数问题。
quality: high
full_path: m0leCon_CTF_2025_Teaser_re_Embedded_encryption_RISCV_对称密码.full.md
meta_path: m0leCon_CTF_2025_Teaser_re_Embedded_encryption_RISCV_对称密码.meta.md
images_removed: true
images_removed_count: 7
schema_version: v3.0.0-P0
summary: m0leCon CTF 2025 Teaser re Embedded encryption RISCV 对称密码。m0leCon 2025 Teaser 嵌入式逆向，RISC-V 自定义分组密码 + 行列和反推 output。。关键路径：识别 RISC-V 32 位固件 → metal_gpio_get_input_pin 读 1 位随机种子 → srand+rand 用内置库。经验：当 ...
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 7
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/206641.html
reasoning_chain:
- 触发点：tag 'risc-v' / 'mcu' / 'metal-gpio' / 'ip-permutation' / 'p-box' / 'row-column-sum' → 假设：RISC-V 32 位固件自定义分组密码
- 动作：识别 RISC-V 32 位固件 → metal_gpio_get_input_pin 读 1 位随机种子 → 触发点：srand+rand 内置库
- 假设：var644[1604] 分四区 m32[32]/input[33]/m256[256]/output[256*4] → 动作：拆解数组结构
- 触发点：IP 置换表 (32 字节) + P 盒映射 (256 字节) → 假设：标准 SP 网络 → 动作：写脚本重排
- 下一步：重复 1337 轮 → 假设：output[input[j]] = 1 << (31-j) → 动作：行列和反推 input
- 触发点：output 矩阵每行/列只有 1 位为 1 → 假设：行列和可唯一定位 → 动作：解线性方程组
- 动作：还原 plaintext → 触发点：明文 = flag → 完成
failed_attempts:
- 试图不解密直接读 output → 失败：output 是密文，需行列和反推
- 试图不解 RISC-V 反汇编 → 失败：MCU 加密位数需逆向
- 试图忽略行列和约束 → 失败：标准反推只能给多个解
key_observations:
- 当 output 矩阵每行/列只有 1 位为 1 时，行列和反推是经典线性代数问题
- RISC-V 32 位 MCU 加密通常基于 metal_gpio + 内置 srand 种子
- SP 网络 (IP + P 盒) 是经典分组密码结构，重复 1337 轮只是加深混淆
- var644 分区 (m32/input/m256/output) 是嵌入式 MCU 加密的典型内存布局
prerequisites:
- RISC-V 反汇编与 MCU 嵌入式逆向
- 分组密码 SP 网络结构
- 线性代数行列和反推
- Ghidra/IDA 嵌入式处理器插件
```
