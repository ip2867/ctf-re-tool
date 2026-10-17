// Phase C 验证：多骨架解密器
// 1) AES 变体合成题：自定义 key + 标准 AES 结构（含 S 盒/Rcon），验证生成的脚本解出
// 2) SM4 回归：确保多骨架重构没破坏已验证的 SM4 能力
const fs = require('fs'), os = require('os'), p = require('path');
const { spawnSync } = require('child_process');
const { scanCryptoFingerprints } = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const tmp = os.tmpdir();

// ---- Python 侧独立 AES 实现（用于构造样本，与工具生成的脚本解耦）----
const pyAES = `
import struct, sys, json
M = 0xFFFFFFFF
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
        0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36]
def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p
def _rot(x, n): return ((x << n) | (x >> (8-n))) & 0xff
def build_sbox():
    inv = [0]*256
    for a in range(1, 256):
        for b in range(1, 256):
            if _mul(a, b) == 1: inv[a] = b; break
    return [(x ^ _rot(x,1) ^ _rot(x,2) ^ _rot(x,3) ^ _rot(x,4) ^ 0x63) & 0xff for x in inv]
SBOX = build_sbox()
def expand(key, rounds):
    nk = len(key)//4
    words = [list(key[i*4:i*4+4]) for i in range(nk)]
    for i in range(nk, 4*(rounds+1)):
        t = list(words[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        words.append([words[i-nk][j] ^ t[j] for j in range(4)])
    return [b"".join(bytes(words[4*r+c]) for c in range(4)) for r in range(rounds+1)]
def xtime(a):
    a <<= 1
    if a & 0x100: a = (a ^ 0x1b) & 0xff
    return a
def mix_col(col):
    return [ xtime(col[0])^(xtime(col[1])^col[1])^col[2]^col[3],
             col[0]^xtime(col[1])^(xtime(col[2])^col[2])^col[3],
             col[0]^col[1]^xtime(col[2])^(xtime(col[3])^col[3]),
             (xtime(col[0])^col[0])^col[1]^col[2]^xtime(col[3]) ]
def enc_block(blk, rk):
    state = [[blk[r+4*c] for c in range(4)] for r in range(4)]
    k = rk[0]
    state = [[state[r][c] ^ k[r+4*c] for c in range(4)] for r in range(4)]
    for rnd in range(1, len(rk)-1):
        state = [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]
        state = [[state[r][(c+r)%4] for c in range(4)] for r in range(4)]
        for c in range(4):
            col = mix_col([state[r][c] for r in range(4)])
            for r in range(4): state[r][c] = col[r]
        k = rk[rnd]
        state = [[state[r][c] ^ k[r+4*c] for c in range(4)] for r in range(4)]
    state = [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]
    state = [[state[r][(c+r)%4] for c in range(4)] for r in range(4)]
    k = rk[-1]
    state = [[state[r][c] ^ k[r+4*c] for c in range(4)] for r in range(4)]
    return bytes(state[r][c] for c in range(4) for r in range(4))

# 构造样本：key = b'AEStestkey123456'（16B, 10 轮），flag 32 字节
KEY = b'AEStestkey123456'
FLAG = b'ae s{multi_skeleton_ok_42}'[:32].ljust(32, b'\\x00')
rk = expand(KEY, 10)
ct = b"".join(enc_block(FLAG[i:i+16], rk) for i in (0, 16))

# 布局：填充 | S盒(连续256B, 会被已知常量命中) | 填充 | Rcon | 填充 | key | 零 | 密文 | 填充
parts = []
parts.append(b'\\x11' * 0x400)
parts.append(bytes(SBOX))              # 连续字节（标准表 → 直接判 AES）
parts.append(b'\\x22' * 0x600)
parts.append(bytes(RCON[:10]))         # Rcon 形态
parts.append(b'\\x33' * 0x400)
parts.append(KEY)
parts.append(b'\\x00' * 0x20)
parts.append(ct)
parts.append(b'\\x55' * 0x800)
sys.stdout.write(json.dumps({'ct_hex': ct.hex(), 'key': KEY.decode('latin-1'), 'flag': FLAG.decode('latin-1', 'ignore')}))
`;
const py = p.join(tmp, 'ctf_aes_build.py');
fs.writeFileSync(py, pyAES, 'utf8');
const built = spawnSync('python', ['-u', py], { encoding: 'utf8' });
let sample = null;
try { sample = JSON.parse(built.stdout.trim()); } catch (e) {
  console.log('  ❌ 构造样本失败:', (built.stdout || '').slice(0, 200), (built.stderr || '').slice(0, 300));
  process.exit(1);
}

console.log('A) AES 变体合成题（标准结构 + 标准 S 盒，文件布局全新）');
console.log('  flag 注入:', JSON.stringify(sample.flag));
{
  // 样本文件
  const f = p.join(tmp, 'ctf_aes_variant.bin');
  const SBOX_STD = (() => {
    const py2 = `import struct;exec(open(${JSON.stringify(py)},encoding='utf-8').read().split("# 构造样本")[0].replace("sys.stdout.write(json.dumps","pass#").rsplit("sys.stdout.write",1)[0]);print(bytes(SBOX).hex())`;
    const r2 = spawnSync('python', ['-c', `
import struct
M=0xFFFFFFFF
def _mul(a,b):
    p=0
    for _ in range(8):
        if b&1:p^=a
        hi=a&0x80;a=(a<<1)&0xff
        if hi:a^=0x1b
        b>>=1
    return p
def _rot(x,n):return ((x<<n)|(x>>(8-n)))&0xff
inv=[0]*256
for a in range(1,256):
    for b in range(1,256):
        if _mul(a,b)==1:inv[a]=b;break
SBOX=[(x^_rot(x,1)^_rot(x,2)^_rot(x,3)^_rot(x,4)^0x63)&0xff for x in inv]
print(bytes(SBOX).hex())
`], { encoding: 'utf8' });
    return Buffer.from(r2.stdout.trim(), 'hex');
  })();
  const RCON = Buffer.from([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);
  const KEY = Buffer.from(sample.key, 'latin1');
  const CT = Buffer.from(sample.ct_hex, 'hex');
  const parts = [
    Buffer.alloc(0x400, 0x11), SBOX_STD, Buffer.alloc(0x600, 0x22),
    RCON, Buffer.alloc(0x400, 0x33),
    KEY, Buffer.alloc(0x20, 0), CT, Buffer.alloc(0x800, 0x55),
  ];
  fs.writeFileSync(f, Buffer.concat(parts));

  const r = scanCryptoFingerprints(f);
  ok((r.summary || []).some(s => /AES/.test(s.algo)), `识别为 AES（summary: ${(r.summary || []).map(s => s.algo).join(',')}）`);
  // 标准 AES 表（连续字节命中 AES-SBOX）也应挂载解密脚本（v1.7.2 补齐的链路）
  const sboxFp = (r.fingerprints || []).find(x => x.constantAnalysis && x.constantAnalysis.decryptScript);
  ok(!!sboxFp, '标准 AES 表挂载了解密脚本');
  if (sboxFp) {
    const sk = sboxFp.constantAnalysis.decryptScript;
    ok(sk.skeleton === 'AES', '骨架判定为 AES');
    const pyf = p.join(tmp, 'ctf_aes_solve.py');
    fs.writeFileSync(pyf, sk.script, 'utf8');
    const out = spawnSync('python', ['-u', pyf, f], { encoding: 'utf8', timeout: 300000 });
    const txt = (out.stdout || '') + (out.stderr || '');
    const m = txt.match(/FLAG:\s*(.+)/);
    const got = m ? m[1].trim().replace(/\s+$/, '') : '';
    ok(!!m, `AES 脚本报告命中（${m ? got.slice(0, 32) : txt.slice(-200).replace(/\n/g, ' ')}）`);
    ok(got.replace(/\x00+$/, '').startsWith('ae s{multi_skeleton_ok_42}'.slice(0, 24)),
      `解出的 flag 与注入值一致（${JSON.stringify(got.slice(0, 32))}）`);
  }
}

console.log('\nB) SM4 多骨架重构回归（Disguise 仍能解出）');
{
  const stage2 = p.resolve('cases/Disguise.exe_2c0c118b/extracted/stage_pe_a200.bin');
  if (!fs.existsSync(stage2)) {
    console.log('  ⚠️ 跳过（stage2 不存在）');
  } else {
    const r = scanCryptoFingerprints(stage2);
    const ca = (r.fingerprints || []).map(x => x.constantAnalysis).find(x => x && x.decryptScript);
    ok(!!ca && !!ca.decryptScript, '仍生成解密脚本');
    ok(!!ca && ca.decryptScript.skeleton === 'SM4', '骨架判定为 SM4');
    if (ca && ca.decryptScript) {
      const pyf = p.join(tmp, 'ctf_sm4_regress.py');
      fs.writeFileSync(pyf, ca.decryptScript.script, 'utf8');
      const out = spawnSync('python', ['-u', pyf, stage2], { encoding: 'utf8', timeout: 180000 });
      const txt = (out.stdout || '') + (out.stderr || '');
      const m = txt.match(/FLAG:\s*(.+)/);
      const got = m ? m[1].trim().replace(/\s+$/, '') : '';
      ok(got === 'xmctf{We1c0me_t0_the_w0r1d_0f_VM_And_PEL0ader!!}', `SM4 端到端仍解出（${got.slice(0, 30)}…）`);
    }
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
