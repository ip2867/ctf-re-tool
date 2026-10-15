---
title: 运行型逆向题（数据变换型）的识别与解法
category: reverse-method
vuln_type: runtime-challenge
difficulty: all
tags: [运行型, runtime, 数据变换, 伴生文件, 已知明文, flag前缀, 前缀网络, up-sweep, 反演, ASCII, dice]
keywords: [运行型题目, 数据变换, flag.out, 已知明文攻击, flag前缀, 反演脚本, ASCII, 可打印过滤, 元素0不变, 并行归并, up-sweep, down-sweep]
one_liner: 程序把 flag 当"输入数据"做确定性变换后写进伴生输出文件——解法是反演输出而不是运行程序：输出文件首元素常直接是 flag 首字符的 ASCII，用已知明文（dice{ 等）推算变换方向，再写逆向脚本把输出变回 flag。
attack_chain:
- 识别运行型特征（getopt/ifstream+ofstream/线程池/计时输出），确认无静态校验
- 关键转折：伴生 .out 文件里全是纯数字 → 先测"这些数字是不是 flag 字符的 ASCII/变换值"（首值 100=chr('d') 一秒验证），不要先猜"文件格式/数量字段"
- 利用不变量：很多并行变换中 元素0 永不被更新 → 输出[0] = flag[0] 的 ASCII（100='d' 直接实锤）
- 已知明文推算子：flag 已知前缀（dice{ / flag{ / ctf{）+ 输出相邻对 → 逐一测试 xor/add/sub/mul/div 反推每个位置用了哪个 op
- 写反演脚本：按程序的两阶段循环结构（counter 上行翻倍/下行折半，op = ops[floor(log2(counter)) % 3]）逆向走一遍，加法逆=减、乘法逆=整除、xor 逆=再 xor；ops 的 rand 洗牌顺序不用预测——3! = 6 种排列暴力枚举，取"全元素可打印 ASCII"的那组
- chr 拼接输出 flag
failed_attempts:
- 把输出文件首值 100 误读为"元素个数 n=100"，纠结"51 ≠ 100 格式不符"卡死多轮 → 先测 ASCII 假设（chr(100)='d'）再谈格式
- 猜 worker 语义为 out[i] = op(data[i-1], data[i]) + i mod 3 选 op → 真实结构是前缀网络（counter 翻倍定距离，floor(log2(counter)) 定 op），猜错则反演必错
- 预算烧进 std::thread 样板（_State_impl vtable / 六层嵌套 invoke 链）→ 正确路径是搜"调用 sem_wait/pthread_mutex 的 lambda 函数体"，标准库管道直接跳过
- 试图复现 glibc rand 预测洗牌顺序 → 不必要：6 种排列暴力 + 可打印约束即可锁定
- 以为必须"运行程序"才能解（找 WSL/Unicorn）→ 数据变换型根本不用运行：变换是确定性的，反演输出即可
lesson: 运行型题分两亚型——"真运行型"（flag 在运行行为里）与"数据变换型"（flag 是被变换的输入，变换确定可反演）。伴生输出文件里全是数字时，先花 10 秒测"首值是否可打印 ASCII + 元素0 是否不变"，这两问决定走哪条路，可省掉全部 std::thread 样板逆向。
---

# 运行型逆向题（数据变换型）的识别与解法

## 两种亚型，先分清（决定整条路线）

| | 真运行型 | 数据变换型（本题） |
|---|---|---|
| flag 位置 | 运行行为里（耗时/特定输出） | **是程序的输入**，被确定性变换后写进伴生 .out |
| 解法 | 构造输入运行程序 | **反演**伴生输出文件 |
| 判据 | 输出文件与 flag 无字符关联 | **输出全是数字 → 先测 ASCII 假设** |

## 快速分诊（10 秒，两问）

拿到伴生 `.out`（一列纯数字）时：

1. **首值是不是可打印 ASCII？** `chr(100)='d'`、`chr(102)='f'`——DiceCTF 的 flag 就是 `dice{`，`100='d'` 一秒实锤
2. **元素 0 是否永不更新？** 反编译里若变换循环从下标 1/counter 开始 → 输出[0]=flag[0]

两问都中 → 数据变换型，直接进反演，**跳过 std::thread 全部样板逆向**。

## 已知明文推算子（免预测 glibc rand）

flag 前缀是公开常识（`dice{`/`flag{`/`ctf{`），输出相邻对 + 已知明文即可逐位推算子：

```
out[0]='d'=100, out[1]=13
'd'^13 = 'i'  → 第一轮 op 是 xor
后续位同理，测 xor/add(减)/mul(除) 哪个能出可打印字符
```

**ops 顺序被 `srand(size ^ threads)` 洗牌也不用管**——3! = 6 种排列暴力枚举，
取"反演结果全元素可打印 ASCII"的那组即可，比复现 glibc rand（TYPE_3 加性反馈）便宜得多。

## 反演脚本骨架（按程序循环结构逆向走）

```python
# 程序正变换：两阶段循环，counter 上行翻倍(1,2,4..32)再下行折半，
# 每轮 values[i±counter] = op(values[i], values[i±counter])，op = ops[log2(counter)%3]
# 反演：同样两阶段，op 换逆—— xor→^, add→-, mul→//（整除）
import math
vals = [int(x) for x in open('flag.out')]
OPS = {'xor': lambda a,b: a^b, 'add': lambda a,b: a-b, 'mul': lambda a,b: a//b}
counter = 1
while counter < len(vals):      # 上行
    for i in range(counter, len(vals)):
        vals[i] = INV[op_of(counter)](vals[i], vals[i-counter])
    counter <<= 1
counter >>= 1
while counter >= 1:              # 下行
    ...
print(''.join(chr(v) for v in vals))
```

（具体方向/距离以反编译为准；骨架的意义是"反演很便宜"，别被线程吓退。）

## 实战案例

**DiceCTF 2023 not-baby-parallelism**（`pppp` + `flag.out`）：
- 程序：51 个整数（flag 的 ASCII）做两阶段并行前缀变换（xor/add/mul，ops 顺序 rand 洗牌），
  多线程 + 双信号量屏障只是**执行机制**，变换本身确定性
- 输出文件 51 个数字，首值 100 = 'd'
- 正解：元素0不变 + `dice{` 已知明文推出 ops 顺序 → 反演输出 → flag
- 工具四轮失败教训（详见 failed_attempts）：误读文件格式 / 猜错 worker 语义 /
  烧预算在 std::thread 样板 / 徒劳复现 glibc rand

## 实战案例 2（对照：真运行型）

**排序 benchmark 类**：flag = 对特定输入的排序输出、srand 种子复现随机序列——
这类才需要真的运行程序（WSL/Unicorn）。
