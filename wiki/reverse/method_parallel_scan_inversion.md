---
title: 并行扫描 / 置换网络型逆向（Blelloch scan、MPI 环形搬运）
category: reverse-method
vuln_type: parallel-scan-inversion
difficulty: hard
tags: [并行, Blelloch, prefix-scan, MPI, 置换, 算子表, up-sweep, down-sweep, 反演, 单位标签, srand, dice]
keywords: [并行前缀扫描, Blelloch, work-efficient, up-sweep, down-sweep, 算子表, log2选op, MPI, Scatter, Gather, Isend, Irecv, 环形搬运, 确定性置换, 单位标签, perm_out, 逆变换, 深链vtable]
one_liner: 并行结构（前缀扫描/跨进程搬运）本质是确定性变换——不模拟真实运行时：Blelloch 按 up/down-sweep 公式精确逆序反演，MPI 环形搬运用"单位标签跑一遍"得到置换表再求逆；算子选择 round(log2(stride))%3 与数据无关可独立预生成。
attack_chain:
- 识别并行型：std::thread/信号量屏障/chrono 计时输出 + getopt(-n线程数,-i输入,-o输出) + 伴生 .out 文件 → 运行型，flag 在变换结果里
- 三个算子定位（反编译直接可读）：add=和、mul=积、xor=异或；核心函数藏在 C++ lambda 深链（vtable off_XXX → invoke 槽位 → 数层转发 → 真身），顺着 vtable 槽位一路追，标准库管道跳过
- 结构判定：`a[u]=op(a[u-i],a[u])`（u=2ik-1）为 up-sweep 归约；`a[i+u]=op(a[u],a[i+u])` 为 down-sweep；每层算子 = table[round(log2(i)) % 3] —— 与数据无关，可直接预生成
- 反演顺序（错一层全盘错）：先按 up 层级顺序逆 down-sweep，再按 down 层级顺序逆 up-sweep；add 逆=减、xor 逆=再异或、mul 逆=整除（检查除数非零）
- 未知参数（线程数/种子）：暴力小范围（1..64）+ "结果全可打印 ASCII"约束锁定唯一解
- MPI 变体：Scatter/Gather/Isend/Irecv 的固定轮次环形搬运 = 确定性置换 P → 用单位标签（0..63 编号）跑同样轮次得 perm_out，逆映射 `res[perm_out[k]]=out[k]`；memcmp 目标串是**终态**不是 flag
- 正向回验：反演结果重跑同结构扫描/置换，输出与伴生文件逐元素相等才算数
failed_attempts:
- 伴生 .out 首值 100 误读为"元素个数" → 100 是 chr('d')，是数据本身；先测 ASCII 假设
- worker 语义猜成朴素 out[i]=op(data[i-1],data[i]) → 真实是树形扫描（counter 翻倍定距离），猜错反演必错
- 预算烧进 std::thread 样板与 glibc rand 复现 → 洗牌顺序不用预测：3!=6 种排列暴力 + 可打印约束即可；rand 恒等价
- down-sweep 结束后 i 的终值边界（(n>>1)>=i）弄错 → 逆序必须精确对齐每层边界，差一层全盘错
- 模拟真实 MPI（起 8 进程/mbuffer 语义）→ 完全不必要：单位标签一遍模拟就得到置换
- 把 memcmp 目标常量当 flag（"m_ERpm..." 看着像但乱序）→ 它只是 Gather 后终态，须走两步逆变换
