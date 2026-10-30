#!/usr/bin/env python3
"""验证 skill §5.4 的"正向模型对拍"：用独立实现的 f() 核对 emu_trace 的返回值。

步骤意义（这是通用方法论，不是这道题的答案）：
  1. 从 trace 摘要拿到真值（regs.rdx / regs.rax）
  2. 把还原出的语义写成纯 Python 正向函数
  3. 两边对上 ⇒ 模型可信，才敢用它反解
如果对不上，说明伪代码读错了——这一步能在写逆函数之前就挡住错误。
"""
import json, sys

M = (1 << 64) - 1

# fixture 的语义（由反汇编读出，不用任何题目常量）
def f(rdi, rsi, nseg=92):
    v8 = (~rdi) & M
    v10 = (rsi + 0x1234) & M
    i = 2
    while i < nseg - 1:
        if i % 4 == 0:
            v8 = (v8 ^ v10) & M
        elif i % 4 == 1:
            v8 = (v8 + v8) & M
        elif i % 4 == 2:
            v10 = (~v10) & M
        else:
            v8 = (v8 - 0x100) & M
        i += 1
    return v8, v10


tr = json.load(open(sys.argv[1] if len(sys.argv) > 1 else 'trace.json'))
rax = int(tr['regs']['rax'], 16)
rdx = int(tr['regs']['rdx'], 16)
p8, p10 = f(0x1122334455667788, 0x99aabbccddeeff00)

print('TRACE  rax=%#x rdx=%#x' % (rax, rdx))
print('MODEL  v8 =%#x v10=%#x' % (p8, p10))
print('RAX MATCH', rax == p8)
print('RDX MATCH', rdx == p10)
if rax == p8 and rdx == p10:
    print('POSITIVE MODEL VERIFIED —— 可以放心写逆函数')
    sys.exit(0)
print('MODEL MISMATCH —— 伪代码读错了，别急着逆推')
sys.exit(1)
