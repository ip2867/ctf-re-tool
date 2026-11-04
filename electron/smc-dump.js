'use strict';
// smc_dump —— 自修改代码（SMC）的通用还原
//
// 背景：SMC 的典型形态是「解密一小块 -> 执行 -> 重新加密」，所以任何单次内存快照
// 都只能看到被解开的那一小块。要还原全貌，必须高频采样 + 取并集。
//
// 这不是某一题的技巧：只要目标是「按需解密、用完即焚」的代码保护，都适用。
//
// 流程（全部在 Kali 上执行，宿主机只发脚本、收结果）：
//   1. 可选：patch 掉静态可定位的反调试点（sec_env_probe 之类）
//   2. 启动目标进程，喂入 stdin
//   3. 高频 /proc/<pid>/mem 采样指定区间（默认按 LOAD 段的可执行区推断）
//   4. 与文件基线逐字节比对，收集所有「曾经出现过」的字节
//   5. 并集还原 + 输出被改写的块列表 + 反汇编
//
// 关键参数：采样区间必须覆盖 SMC 区。工具会先用 ELF program headers 推断候选区间，
// 也可由调用方用 region 显式指定（如 "0x404000:0x20000"）。

const DEFAULT_SAMPLE_MS = 0;   // 0 = 不 sleep，能采多快采多快

function parseRegion(s) {
  const m = /^0x([0-9a-fA-F]+):0x([0-9a-fA-F]+)$/.exec(String(s || '').trim());
  if (!m) return null;
  return { base: parseInt(m[1], 16), len: parseInt(m[2], 16) };
}

// 从 ELF program headers 推断「可执行 + 可写」或「可执行」大段
function inferRegions(elfBuf) {
  if (!elfBuf || elfBuf.length < 64) return [];
  const magic = elfBuf.readUInt32LE(0);
  if (magic !== 0x464c457f) return [];
  const is64 = elfBuf[4] === 2;
  if (!is64) return [];
  const phoff = Number(elfBuf.readBigUInt64LE(0x20));
  const phentsize = elfBuf.readUInt16LE(0x36);
  const phnum = elfBuf.readUInt16LE(0x38);
  const out = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + 56 > elfBuf.length) break;
    const pType = elfBuf.readUInt32LE(o);
    const pFlags = elfBuf.readUInt32LE(o + 4);
    if (pType !== 1) continue;                       // PT_LOAD only
    const vaddr = Number(elfBuf.readBigUInt64LE(o + 16));
    const filesz = Number(elfBuf.readBigUInt64LE(o + 32));
    const memsz = Number(elfBuf.readBigUInt64LE(o + 40));
    if (!(pFlags & 1)) continue;                     // 必须 PF_X
    out.push({ vaddr, filesz, memsz, flags: pFlags });
  }
  // 取最大的可执行段（SMC 通常藏在大 text 段里）
  out.sort((a, b) => b.filesz - a.filesz);
  return out;
}

function buildSmcScript(opts) {
  const o = opts || {};
  const binPath = String(o.binPath || './target');
  const outDir = String(o.outDir || '/tmp/smcdump');
  const region = o.region ? parseRegion(o.region) : null;
  const base = region ? region.base : Number(o.base || 0x404000);
  const len = region ? region.len : Number(o.len || 0x20000);
  const stdinData = String(o.stdinData == null ? '' : o.stdinData);
  const maxSnap = Number(o.maxSnap || 4000);
  const maxMs = Number(o.maxMs || 8000);
  const sleepMs = Number(o.sleepMs == null ? DEFAULT_SAMPLE_MS : o.sleepMs);
  const patches = Array.isArray(o.patches) ? o.patches : [];

  const patchLines = patches.map((p) => {
    const va = String(p.va || '');
    const bytes = String(p.bytes || '');
    return `patch_bytes(d, ${JSON.stringify(va)}, ${JSON.stringify(bytes)})`;
  }).join('\n');

  return `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 由 smc_dump 生成：SMC 高频采样 + 并集还原
import os, sys, struct, time

BIN = ${JSON.stringify(binPath)}
OUTDIR = ${JSON.stringify(outDir)}
BASE = ${base}
LEN = ${len}
MAX_SNAP = ${maxSnap}
MAX_MS = ${maxMs}
SLEEP_MS = ${sleepMs}
STDIN_DATA = ${JSON.stringify(stdinData)}

os.makedirs(OUTDIR, exist_ok=True)

def parse_segs(path):
    d = open(path, 'rb').read()
    e_phoff = struct.unpack_from('<Q', d, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', d, 0x36)[0]
    e_phnum = struct.unpack_from('<H', d, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', d, o)[0] != 1:
            continue
        p_off, p_va = struct.unpack_from('<QQ', d, o + 8)
        p_fsz = struct.unpack_from('<Q', d, o + 0x20)[0]
        segs.append((p_off, p_va, p_fsz))
    return d, segs

def va2off(segs, va):
    for off, vaddr, filesz in segs:
        if vaddr <= va < vaddr + filesz:
            return off + (va - vaddr)
    return None

def patch_bytes(buf, va, hexstr):
    # 就地改写文件字节；hexstr 允许 "31c0c3" 或 "31 c0 c3"
    # va 可能是 "0x5024fc" 字符串或整数 —— 统一转 int（真实踩过：不转就 TypeError）
    # buf 必须是 bytearray（bytes 不支持切片赋值）—— 真实踩过
    va = int(va, 16) if isinstance(va, str) else int(va)
    b = bytes.fromhex(hexstr.replace(' ', '').replace('0x', ''))
    fo = va2off(SEGS, va)
    if fo is None:
        print('PATCH_SKIP 0x%x (不在文件映射内)' % va)
        return
    if not isinstance(buf, bytearray):
        raise TypeError('patch_bytes 需要 bytearray，收到 %s' % type(buf).__name__)
    buf[fo:fo + len(b)] = b
    print('PATCH 0x%x <- %s' % (va, b.hex()))

d, SEGS = parse_segs(BIN)
patched = bytearray(d)
${patchLines ? patchLines.replace('patch_bytes(d,', 'patch_bytes(patched,') : 'pass  # 未指定 patches'}
PATCHED_PATH = os.path.join(OUTDIR, os.path.basename(BIN) + '.smcpatched')
open(PATCHED_PATH, 'wb').write(bytes(patched))
os.chmod(PATCHED_PATH, 0o755)

base_off = va2off(SEGS, BASE)
if base_off is None:
    print('ERROR: 采样起点 0x%x 不在文件映射内，无法建基线' % BASE)
    sys.exit(2)
baseline = bytes(patched[base_off:base_off + LEN])

import subprocess
p = subprocess.Popen([PATCHED_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, cwd=os.path.dirname(PATCHED_PATH) or '.')
if STDIN_DATA:
    try:
        p.stdin.write(STDIN_DATA.encode() if isinstance(STDIN_DATA, str) else STDIN_DATA)
        p.stdin.flush()
    except Exception:
        pass

snaps = []
last = baseline
memfd = None
t0 = time.time()
while True:
    if p.poll() is not None:
        break
    if len(snaps) >= MAX_SNAP or (time.time() - t0) * 1000 > MAX_MS:
        break
    if memfd is None:
        try:
            memfd = os.open('/proc/%d/mem' % p.pid, os.O_RDONLY)
        except Exception:
            time.sleep(0.0005)
            continue
    try:
        chunk = os.pread(memfd, LEN, BASE)
    except Exception:
        chunk = b''
    if chunk and chunk != last:
        snaps.append(chunk)
        last = chunk
    if SLEEP_MS:
        time.sleep(SLEEP_MS / 1000.0)

try:
    p.stdin.close()
except Exception:
    pass
try:
    out, err = p.communicate(timeout=20)
except Exception:
    p.kill()
    out, err = b'', b''
if memfd is not None:
    os.close(memfd)

print('CHILD_RC %s' % p.returncode)
print('STDOUT %r' % (out[:400],))
print('STDERR %r' % (err[:200],))
print('SNAPSHOTS %d' % len(snaps))

if not snaps:
    print('NO_DIFF 目标区间在运行期间未发生改写（可能区间不对，或 SMC 不在此段）')
    sys.exit(0)

# 并集还原：任何快照里与 baseline 不同的字节都采纳
merged = bytearray(baseline)
covered = bytearray(LEN)
for s in snaps:
    for i in range(min(LEN, len(s))):
        if s[i] != baseline[i]:
            merged[i] = s[i]
            covered[i] = 1

ncov = sum(covered)
print('RESTORED_BYTES %d / %d (%.2f%%)' % (ncov, LEN, 100.0 * ncov / LEN if LEN else 0))

# 输出块列表
blocks = []
i = 0
while i < LEN:
    if covered[i]:
        j = i
        while j < LEN and covered[j]:
            j += 1
        blocks.append((BASE + i, BASE + j))
        i = j
    else:
        i += 1
print('BLOCKS %d' % len(blocks))
for a, b in blocks[:60]:
    print('  BLOCK 0x%x 0x%x len=%d' % (a, b, b - a))
if len(blocks) > 60:
    print('  ... 还有 %d 个' % (len(blocks) - 60))

plain_path = os.path.join(OUTDIR, 'smc_plain.bin')
open(plain_path, 'wb').write(bytes(merged))
print('PLAIN %s' % plain_path)

# 每块的反汇编（如果有 objdump）
try:
    import subprocess as sp
    dis = sp.run(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                  '--adjust-vma=0x%x' % BASE, plain_path],
                 capture_output=True, text=True, timeout=60)
    txt = dis.stdout or ''
    open(os.path.join(OUTDIR, 'smc_plain.dis'), 'w').write(txt)
    print('DISASM %s (%d 行)' % (os.path.join(OUTDIR, 'smc_plain.dis'), len(txt.splitlines())))
except Exception as e:
    print('DISASM_SKIP %r' % e)

# 明文里的 ASCII 串（对定位反调试串/提示串有用）
import re
strs = []
for m in re.finditer(rb'[ -~]{6,}', bytes(merged)):
    strs.append('  0x%x %s' % (BASE + m.start(), m.group()[:70].decode('ascii', 'replace')))
print('STRINGS %d' % len(strs))
for s in strs[:40]:
    print(s)
if len(strs) > 40:
    print('  ... 还有 %d 条' % (len(strs) - 40))
`;
}

module.exports = { parseRegion, inferRegions, buildSmcScript };
