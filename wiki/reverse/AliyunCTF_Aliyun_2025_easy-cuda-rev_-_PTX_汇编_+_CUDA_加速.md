# 逆向题：Aliyun 2025 easy-cuda-rev - PTX 汇编 + CUDA 加速

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：AliyunCTF 2025 ｜ 难度：hard

```yaml
title: Aliyun 2025 easy-cuda-rev - PTX 汇编 + CUDA 加速
contest: AliyunCTF
year: 2025
difficulty: hard
vuln_type: reverse
tags:
- CUDA
- PTX
- sm_52
- cuobjdump
- AES T-table
- ROT循环
- mov.u64 %SPL __local_depot0
- vprintf
- encrypt_kernel
- GPU加速
- 10M轮异或
attack_chain:
- cuobjdump -ptx easy_cuda 提取 PTX 汇编
- arch=sm_52, code version=[8,0], compressed
- T[256] AES T-table (S-box + MixColumns)
- RT[256] 逆 T-table
- encrypt_kernel 入口 mov.u64 %SPL, __local_depot0 + cvta.local.u64 %SP
- '字节处理: ld.global.u8 读 input[i], XOR ((i*73 + key) & 0xFF), 4-bit swap (AND 0xF0, SHL 4, SHR 4, OR)'
- 5 段循环每段 10485760 轮查 T-table, 每轮 XOR 轮计数器
- 最后 st.global.u8 写回, vprintf("gift%d", byte)
- vprintf 调用 mov.u64 %rd42, $str; cvta.global.u64; call.uni vprintf
- GPU 加速爆破 5 段独立循环, 倒数逆向
key_payload: '''cuobjdump -ptx / sm_52 / encrypt_kernel / 5x10485760 轮 / T-table 查表 / 4-bit swap / XOR (i*73+key) / vprintf gift'''
one_liner: Aliyun 2025 easy-cuda-rev — CUDA PTX 汇编 sm_52 + 5 段 10485760 轮 T-table 查表 + 4-bit swap + XOR 索引 + GPU 加速爆破 + vprintf 逐字节输出。
lesson: CUDA reverse 用 cuobjdump -ptx 提汇编;__local_depot0 是 per-thread local memory;vprintf 调 call.uni 输出来看 gift1/gift2/gift3/gift4/gift5 分段结果。
quality: high
full_path: Aliyun2025_题解：easy-cuda-rev_PTX汇编+cuda加速.full.md
meta_path: Aliyun2025_题解：easy-cuda-rev_PTX汇编+cuda加速.meta.md
images_removed: true
images_removed_count: 8
schema_version: v3.0.0-P0
summary: Aliyun 2025 easy-cuda-rev - PTX 汇编 + CUDA 加速。Aliyun 2025 easy-cuda-rev — CUDA PTX 汇编 sm_52 + 5 段 10485760 轮 T-table 查表 + 4-bit swap + XOR 索引 + GPU 加速爆破 + vprintf 逐字节输出。。关键路径：cuobjdump -ptx easy_cud...
category: reverse
subcategory: reverse
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 8
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/232133.html
reasoning_chain:
- '[触发点] 拿到 easy_cuda 二进制 → 假设：CUDA fatbin 嵌 PTX 汇编 / [动作] cuobjdump -ptx .easy_cuda > test.txt / [观察] 看到 arch=sm_52, code version=[8,0], compressed / [下一步] 分析 encrypt_kernel 函数 PTX'
- '[触发点] encrypt_kernel 入口 mov.u64 %SPL, __local_depot0 → 假设：per-thread local memory 初始化 / [动作] 读 T[256] AES T-table + RT[256] 逆 T-table / [观察] 5 段循环每段 10485760 轮查 T-table，每轮 XOR 轮计数器 / [下一步] 还原算法'
- '[触发点] 字节处理 ld.global.u8 → XOR ((i*73 + key) & 0xFF) + 4-bit swap (AND 0xF0, SHL 4, SHR 4, OR) → 假设：可逐字节爆破 / [动作] 写 Python 单字节爆破 + 倒推 / [观察] 5 段独立 / [下一步] GPU 加速爆破'
- '[触发点] 单字节串行爆破 5 段太慢 → 假设：CUDA 加速可行 / [动作] 写 CUDA kernel 并行爆破 + vprintf(''gift%d\n'', byte) 逐字节输出 / [观察] 拿到 gift1..gift5 / [下一步] 拼接 flag'
failed_attempts:
- 试图直接反汇编 CUDA 二进制 → 失败：CUDA 是 PTX 不走标准 ISA
- 试图 CPU 串行爆破 → 失败：5 段 × 10485760 轮太慢
key_observations:
- CUDA reverse 用 cuobjdump -ptx 提汇编
- __local_depot0 是 per-thread local memory
- vprintf 调 call.uni 输出来看 gift1/gift2/gift3/gift4/gift5 分段结果
- T-table 查表 + 4-bit swap 是自定义加密常见组合
prerequisites:
- CUDA 编程基础（kernel / thread block / local memory）
- PTX 汇编阅读能力
- AES T-table 加密原理
- GPU 加速爆破思路
```
