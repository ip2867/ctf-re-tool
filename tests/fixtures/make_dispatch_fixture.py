#!/usr/bin/env python3
"""构造一个"分段 dispatch"结构的测试 ELF（结构同型于 Obfuscating Macros II）

刻意复刻的通用特征（不是复刻某道题的具体常量）：
  · 代码被切成 N 段，段与段之间用 `jmp rax` 间接跳转
  · 段号运行期压栈，再由 `lookup(段号)` 算出段地址（静态看不到目标）
  · 段 91 = "弹出段号并跳过去"，段 1 = 起始，段 0 = 结束

用它验证 emu_trace 能否自动量出「段号 → 段地址」映射。
"""
import struct, sys

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

BASE = 0x400000
TEXT_OFF = 0x1000
TEXT_VA = BASE + TEXT_OFF
TEXT_SIZE = 0x4000
DATA_OFF = 0x6000
DATA_VA = BASE + DATA_OFF

NSEG = 92
SEG_STRIDE = 0x40          # 每段 64 字节，段入口对齐
DISPATCH_VA = TEXT_VA + 0x800

ks = Ks(KS_ARCH_X86, KS_MODE_64)


def asm(src, addr=0):
    enc, _ = ks.asm(src, addr)
    return bytes(enc)


def seg_va(i):
    return TEXT_VA + 0x1000 + i * SEG_STRIDE


text = bytearray(b'\xcc' * TEXT_SIZE)


def put(va, blob):
    off = va - TEXT_VA
    text[off:off + len(blob)] = blob


# ── 入口：调用 check(p)，然后退出 ─────────────────────────────
entry = asm(f'''
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    mov rdi, 0x1122334455667788
    mov rsi, 0x99aabbccddeeff00
    call {seg_va(1):#x}
    mov rsp, rbp
    pop rbp
    ret
''', TEXT_VA)
put(TEXT_VA, entry)

# ── 起始段（段 1）：连续做几次算术，设置下一个段号，再进入分发 ──
start_seg = asm(f'''
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    mov [rbp-0x8], rdi
    mov [rbp-0x10], rsi
    mov rax, [rbp-0x8]
    not rax
    mov [rbp-0x8], rax
    mov rax, [rbp-0x10]
    add rax, 0x1234
    mov [rbp-0x10], rax
    mov dword ptr [rbp-0x18], 2
    jmp {DISPATCH_VA:#x}
''', seg_va(1))
put(seg_va(1), start_seg)

# ── 分发器：段号 = [rbp-0x18]; rax = table[段号]; jmp rax ──────
# 用 mov rdx, imm64 而不是 rip 相对，避免手算位移出错
disp = asm(f'''
    mov ecx, dword ptr [rbp-0x18]
    mov rdx, {DATA_VA + 0x100:#x}
    mov rax, [rdx + rcx*8]
    jmp rax
''', DISPATCH_VA)
put(DISPATCH_VA, disp + b'\xcc' * (0x40 - len(disp)))

# ── 中间段：每段做一点可逆运算（结构同型的"VM 语义"）──────────
for i in range(2, NSEG - 1):
    va = seg_va(i)
    op = i % 4
    if op == 0:
        body = 'mov rax, [rbp-0x8]\nxor rax, [rbp-0x10]\nmov [rbp-0x8], rax'
    elif op == 1:
        body = 'mov rax, [rbp-0x8]\nadd rax, rax\nmov [rbp-0x8], rax'
    elif op == 2:
        body = 'mov rax, [rbp-0x10]\nnot rax\nmov [rbp-0x10], rax'
    else:
        body = 'mov rax, [rbp-0x8]\nsub rax, 0x100\nmov [rbp-0x8], rax'
    code = asm(f'''
    {body}
    mov dword ptr [rbp-0x18], {i + 1 if i + 1 < NSEG - 1 else 0}
    jmp {DISPATCH_VA:#x}
''', va)
    put(va, code)

# ── 段 0（结束）：把两个结果放回 rax/rdx 并返回 ────────────────
endseg = asm(f'''
    mov rax, [rbp-0x8]
    mov rdx, [rbp-0x10]
    mov rsp, rbp
    pop rbp
    ret
''', seg_va(NSEG - 1))
put(seg_va(NSEG - 1), endseg)

# ── 跳转表：DATA 段里 92 个 8 字节目标 ─────────────────────────
table = b''
for i in range(NSEG):
    tgt = seg_va(1) if i == 1 else (seg_va(NSEG - 1) if i == 0 else seg_va(i))
    table += struct.pack('<Q', tgt)
DATA_SIZE = 0x800
data = bytearray(b'\x00' * DATA_SIZE)
data[0x100:0x100 + len(table)] = table

# ── ELF 头 + 程序头 ────────────────────────────────────────────
ehdr = bytearray(64)
ehdr[0:4] = b'\x7fELF'
ehdr[4] = 2      # 64
ehdr[5] = 1      # LE
ehdr[6] = 1
ehdr[16:18] = struct.pack('<H', 2)        # ET_EXEC
ehdr[18:20] = struct.pack('<H', 0x3e)     # x86-64
ehdr[20:24] = struct.pack('<I', 1)
ehdr[24:32] = struct.pack('<Q', TEXT_VA)  # e_entry
ehdr[32:40] = struct.pack('<Q', 64)       # e_phoff
ehdr[52:54] = struct.pack('<H', 64)
ehdr[54:56] = struct.pack('<H', 56)
ehdr[56:58] = struct.pack('<H', 2)
ehdr[58:60] = struct.pack('<H', 64)


def phdr(flags, off, va, filesz, memsz, align=0x1000):
    return struct.pack('<IIQQQQQQ', 1, flags, off, va, va, filesz, memsz, align)


ph_text = phdr(5, TEXT_OFF, TEXT_VA, TEXT_SIZE, TEXT_SIZE)   # R+X
ph_data = phdr(6, DATA_OFF, DATA_VA, DATA_SIZE, DATA_SIZE)   # R+W

out = bytearray()
out += bytes(ehdr) + ph_text + ph_data
out += b'\x00' * (TEXT_OFF - len(out))
out += bytes(text)
out += b'\x00' * (DATA_OFF - len(out))
out += bytes(data)

path = sys.argv[1] if len(sys.argv) > 1 else 'dispatch_fixture'
with open(path, 'wb') as f:
    f.write(out)

print('WROTE', path, len(out), 'bytes')
print('ENTRY', hex(TEXT_VA), 'CHECK', hex(TEXT_VA + 0x100), 'DISPATCH', hex(DISPATCH_VA))
print('SEG0', hex(seg_va(NSEG - 1)), 'SEG91', hex(seg_va(NSEG - 1)))
print('TABLE_PTR', hex(DATA_VA + 0x100))
