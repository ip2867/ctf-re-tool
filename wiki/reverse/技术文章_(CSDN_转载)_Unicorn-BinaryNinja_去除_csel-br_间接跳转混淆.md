# 逆向题：Unicorn-BinaryNinja 去除 csel-br 间接跳转混淆

> 来源：Des-CTF 知识库（结构化 meta，**纯文本**，无样本代码）
> 大赛：技术文章 (CSDN 转载) 2024 ｜ 难度：hard

```yaml
title: Unicorn-BinaryNinja 去除 csel-br 间接跳转混淆
contest: 技术文章 (CSDN 转载)
year: 2024
difficulty: hard
vuln_type: misc_unknown
tags:
- unicorn_engine
- binaryninja
- arm64_obfuscation
- csel_cset
- indirect_branch
- smc_emulation
- code_patch
- b_cond_pair
- reverse_advanced
attack_chain: BN 遍历所有指令找 csel/cset+br 间接跳转对 → Unicorn 模拟执行两次 (trueReg/falseReg 各一次) 收集寄存器 → 计算 trueDest/falseDest → 验证是否在 text 段范围内 → 构造 b.cond 互补指令对 (b.eq/b.ne) → bv.write 覆盖原指令
key_payload: 'Architecture[''aarch64''].assemble("b.eq #0x123") / uc.emu_start(lastCsel[1]+4, curAddr) / ARM64_CONDS = {''eq'':''ne'',''ne'':''eq'',...}'
one_liner: 基于 Unicorn + BinaryNinja 的 ARM64 csel-br 间接跳转混淆自动化去除插件源码，逆向工程高级混淆的标配工具链。
lesson: 间接跳转混淆去除的核心是"分别模拟条件 true/false 两条路径"收集寄存器，确定 br Xn 的目标后用 b.cond 互补对替换。
quality: high
full_path: Unicorn-BinaryNinja_去除csel-br_间接跳转混淆.full.md
meta_path: Unicorn-BinaryNinja_去除csel-br_间接跳转混淆.meta.md
images_removed: true
images_removed_count: 10
schema_version: v3.0.0-P0
summary: Unicorn-BinaryNinja 去除 csel-br 间接跳转混淆。基于 Unicorn + BinaryNinja 的 ARM64 csel-br 间接跳转混淆自动化去除插件源码，逆向工程高级混淆的标配工具链。。经验：间接跳转混淆去除的核心是"分别模拟条件 true/false 两条路径"收集寄存器，确定 br Xn 的目标后用 b...
category: misc
subcategory: misc_other
tools_used:
- BinaryNinja
time_required: long
difficulty_score: 4
code_blocks_count: 1
images_count: 10
last_verified: 2026-09-20
contest_type: open
wp_url: https://www.ctfiot.com/262287.html
reasoning_chain:
- 触发点：ARM64 反汇编遇到 csel/cset + br Xn 间接跳转对 → 反 IDA/反编译器无法解析目标
- '假设：csel/cset 提供 destReg = (cond) ? trueReg : falseReg 的条件赋值 → br 跳转目标由 destReg 决定'
- 动作：用 Unicorn Engine 在两条路径分别模拟执行，初始化 regs = emuToGetRegInitState(start, lastCsel[1]) 拿进入 csel 前的寄存器快照
- recover_regisers + uc.reg_write(destReg, regs[trueReg]) → emuToGetJumpReg(lastCsel[1]+4, curAddr) → trueDest
- recover_regisers + uc.reg_write(destReg, regs[falseReg]) → emuToGetJumpReg(lastCsel[1]+4, curAddr) → falseDest
- 观察：trueDest/falseDest 在 text 段范围内 → 假设：可生成 b.eq / b.ne 互补指令对 → 动作：buildOpAndPatch(bv, cond, trueDest, falseDest, curAddr)
- 'trueJmp = ''b.{} #{}''.format(cond, hex(trueDest-(curAddr-4))) / falseJmp = ''b.{} #{}''.format(ARM64_CONDS[cond], hex(falseDest-curAddr))'
- 动作：bv.write(curAddr-4, Architecture['aarch64'].assemble(trueJmp)) → 触发点：直接 patch 当前 br 指令前一条为 b.cond 真互补对
- 异常处理：UC_ERR_READ_UNMAPPED 时回溯到 preBB start，把 preBB.start 加入跳转白名单 white → workCsel 递归
- 蓝名单处理：避免BlHook hook 时把'bl'指令强制跳过白名单外的 bl 调用 → uc.reg_write(PC, address+4)
failed_attempts:
- 试图静态分析 csel 寄存器取值 → 失败：csel 前常有 add/sub 计算 brTarget，无法静态回推
- 试图单次模拟只算 trueDest → 失败：必须两次模拟分别填 trueReg / falseReg 拿到两条路径
- 试图在 x86 上跑同样思路 → 失败：ARM64 的 xzr/wzr 0 寄存器 Unicorn 不读，需手动赋 0
key_observations:
- 间接跳转混淆去除的核心是'分别模拟条件 true/false 两条路径'收集寄存器，确定 br Xn 的目标后用 b.cond 互补对替换
- Unicorn 模拟 ARM64 必须手动写 xzr/wzr 寄存器值，因 UC 不支持读 0 寄存器
- 递归处理 unmapped R/W 时回溯到 preBB start 加入跳转白名单是常见 workaround
- bv.write + Architecture['aarch64'].assemble 是 BinaryNinja Patch 标配 API
- ARM64_CONDS = {'eq':'ne','ne':'eq', ...} 互补对是 b.cond patch 必备
prerequisites:
- ARM64 汇编基础（csel/cset/br/b.cond 指令）
- Unicorn Engine API（Uc / mem_map / emu_start / reg_read / reg_write / hook_add）
- BinaryNinja Python API（bv.instructions / get_basic_blocks_at / write / get_disassembly）
- 插件开发基础（遍历指令 + 处理异常 + 递归）
- HOOK 编程（UC_HOOK_CODE + 跳转白名单）
```
