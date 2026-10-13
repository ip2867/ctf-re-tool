# 逆向题：羊城杯 2024/chal (Reverse)

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：羊城杯 2024 ｜ 难度：hard

```yaml
title: 羊城杯 2024/chal (Reverse)
contest: 羊城杯
year: 2024
difficulty: hard
vuln_type:
- reverse
tags:
- Cython
- IDA
- Python hook
- IDEA 魔改
- TEA 魔改
- XTEA 魔改
- random.seed 可控
- pkcs5padding
attack_chain:
- 题目给 chal.pyx 编译的二进制 + main.py
- dir(chal) 发现 _p1/_p2/_p3 函数和 _tips/_var1/_var2/_var3 属性
- IDA 打开 chal 二进制，识别 PyObject 操作和 _Pyx_CyFunction_New 系列
- 用 setattr hook chal.chal 的 _p1/_p2/_p3 拦截参数和返回值
- 分析 _p3 流程：XOR 填充 → IDEA 轮 → TEA → XTEA → TEA → XTEA → IDEA 轮
- 关键：random.seed 用 sum([2654435769-len(flag)] + flag ord 列表) 可控
- 关键：self.tips 累加 tmps[i] ^ random.getrandbits(8) 才是真校验
- 关键：self._var3 没用，是干扰项
- 还原随机数生成 → 解 IDEA/TEA/XTEA 魔改密文 → 拿 flag
key_payload: 'setattr(chal.chal, ''_p1'', hook_p1); chal.chal(''a''*48)  # 拦截函数调用'
one_liner: Cython 逆向 + Python 函数 hook + random.seed 已知还原魔改 IDEA/TEA/XTEA
lesson: Cython 编译的 Python 库仍可从 .so 中逆向出 PyObject 结构和函数指针；用 setattr hook Python 函数比纯静态逆向快 10 倍；random.seed 用 flag 长度+内容生成时可枚举
quality: high
full_path: 2024年羊城杯粤港澳大湾区网络安全大赛WP-Reverse篇.full.md
meta_path: 2024年羊城杯粤港澳大湾区网络安全大赛WP-Reverse篇.meta.md
images_removed: true
images_removed_count: 4
schema_version: v3.0.0-P0
summary: 羊城杯 2024/chal (Reverse)。Cython 逆向 + Python 函数 hook + random.seed 已知还原魔改 IDEA/TEA/XTEA。关键路径：题目给 chal.pyx 编译的二进制 + main.py → dir(chal) 发现 _p1/_p2/_p3 函数和 _tips/_var1/_var2/_var3 属性 → IDA 打开 chal 二进制，...
category: reverse
subcategory: reverse
tools_used:
- IDA
- Python
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 4
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/203459.html
reasoning_chain:
- 触发点：chal.pyx 编译的二进制 + main.py → 假设：Cython 逆向 → 动作：dir(chal) 看属性
- 观察：发现 _p1/_p2/_p3 函数和 _tips/_var1/_var2/_var3 属性 → 假设：check 在 _tips
- 动作：IDA 打开 chal 二进制 → 假设：识别 PyObject 结构和 _Pyx_CyFunction_New
- 动作：setattr(chal.chal, '_p1', hook_p1) Python 函数 hook 拦截 → 观察：拿到每轮参数
- 触发点：_p3 流程 = XOR 填充 → IDEA 轮 → TEA → XTEA → TEA → XTEA → IDEA 轮 → 假设：复合加密
- 假设：random.seed 用 sum([2654435769-len(flag)] + flag ord) 可控 → 动作：枚举 flag 长度 + 字符
- 触发点：self.tips 累加 tmps[i] ^ random.getrandbits(8) 才是真校验 → 假设：可逆
- 动作：还原随机数 → 解 IDEA/TEA/XTEA 魔改密文 → 观察：拿到 flag
failed_attempts:
- 试图纯静态 IDA 反编译 Cython 二进制 → 失败：PyObject 操作太复杂
- 试图不解 random.seed 直接逆向 → 失败：随机数影响每轮加密
- 试图只看 self._var3 → 失败：_var3 是干扰项真正密文在 _tips
key_observations:
- Cython 编译的 Python 库仍可从 .so 中逆向出 PyObject 结构和函数指针
- setattr hook Python 函数比纯静态逆向快 10 倍
- random.seed 用 flag 长度+内容生成时可枚举（已知前缀约束）
- Cython 二进制逆向核心是 _Pyx_CyFunction_New 等 PyObject API 识别
prerequisites:
- IDA Python + Cython 二进制结构识别
- Python setattr 函数 hook 技巧
- IDEA / TEA / XTEA 加密算法与变种
- random 库 PRNG seed 枚举
```
