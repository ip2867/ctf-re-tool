'use strict';
// 代数结构求解：Feistel/ARX 逆推、GF(2) 线性方程组、小域穷举。
//
// 为什么需要（实测 license 题）：校验逻辑是
//   ① 3 轮 Feistel，轮函数 F_i(x) = x XOR g_i(x)，g_i(x) = Q_i · S(P_i · x XOR k_i)
//      （S 是逐字节 S-box，P/Q 是 GF(2) 上的 4×4 可逆矩阵）
//   ② 之后对结果做 24×24 的 GF(2) 线性混合 M
//   ③ 比较 M·Y == target
// 人类解法的关键两步，工具原本都没有：
//   · **从一批 (输入, 输出) 对反解 GF(2) 线性映射**（高斯消元）——本模块 linearMap
//   · **利用 Feistel 的可逆性把 64 位搜索降到 32 位**——本模块 feistel3Invert
//
// 设计原则：只做**确定性代数运算**，不做语义猜测。给定矩阵/函数就精确算，
// 算不出来就明确说"条件不足"，不编造。

// ─────────────── GF(2) 线性代数 ───────────────

/** 把 bit 向量打包成 BigInt（bit i = 第 i 位） */
function vecToBigInt(arr) {
  let v = 0n;
  for (let i = arr.length - 1; i >= 0; i--) v = (v << 1n) | (arr[i] ? 1n : 0n);
  return v;
}

/** BigInt → bit 数组（MSB first，长度 n） */
function bigIntToVec(v, n) {
  const out = new Array(n);
  for (let i = 0; i < n; i++) out[n - 1 - i] = Number((v >> BigInt(i)) & 1n);
  return out;
}

/**
 * 从 (输入, 输出) 样本对反解 GF(2) 线性映射 M（约定 y = M·x，M[row][col]）。
 *
 * 原理：M 的第 j **列** = M·e_j。对每个输出位 i，把输入样本当行、out[i] 当右端项，
 * 高斯消元解出该输出位对应的**行向量** row_i。
 *   row_i[j] = 输入第 j 位对输出第 i 位的贡献
 * 所以：解出来的每个解向量就是 M 的一**行**，不需要再转置。
 * （早期实现把解向量当列又转置了一次，结果得到 Mᵀ —— 实测在 4×4 例子上错位。）
 *
 * @param {Array<{in:number[], out:number[]}>} pairs  每个样本：输入 bit 数组、输出 bit 数组
 * @param {number} nIn   输入位宽
 * @param {number} nOut  输出位宽
 * @returns {{ok:boolean, M?:Array<Array<number>>, rank?:number, reason?:string}}
 */
function linearMap(pairs, nIn, nOut) {
  if (!Array.isArray(pairs) || !pairs.length) return { ok: false, reason: '没有样本对' };
  const rows = [];
  for (let i = 0; i < nOut; i++) {
    // 构造增广矩阵 [x_0; x_1; ... | out_i]
    const A = pairs.map((p) => {
      const row = new Array(nIn + 1).fill(0);
      for (let j = 0; j < nIn; j++) row[j] = p.in[j] ? 1 : 0;
      row[nIn] = p.out[i] ? 1 : 0;
      return row;
    });
    const sol = gaussSolve(A, nIn);
    if (!sol.ok) return { ok: false, reason: `输出位 ${i}：${sol.reason}` };
    rows.push(sol.x);
  }
  return { ok: true, M: rows, rank: nIn };
}

/** GF(2) 高斯消元解 A·x = b（A 为 rows×n，最后一列是 b） */
function gaussSolve(rows, n) {
  const A = rows.map((r) => r.slice());
  const m = A.length;
  const piv = [];
  let rank = 0;
  for (let col = 0; col < n && rank < m; col++) {
    let p = -1;
    for (let i = rank; i < m; i++) if (A[i][col]) { p = i; break; }
    if (p < 0) continue;
    [A[rank], A[p]] = [A[p], A[rank]];
    for (let i = 0; i < m; i++) {
      if (i !== rank && A[i][col]) {
        for (let k = col; k <= n; k++) A[i][k] ^= A[rank][k];
      }
    }
    piv.push(col);
    rank++;
  }
  // 检查矛盾行：0 = 1
  for (let i = rank; i < m; i++) {
    let allZero = true;
    for (let k = 0; k < n; k++) if (A[i][k]) { allZero = false; break; }
    if (allZero && A[i][n]) return { ok: false, reason: '样本互相矛盾（不是线性映射）' };
  }
  if (rank < n) return { ok: false, reason: `样本不足（秩 ${rank} < ${n}），需要更多独立输入` };
  const x = new Array(n).fill(0);
  for (let i = 0; i < rank; i++) x[piv[i]] = A[i][n];
  return { ok: true, x, rank };
}

/** GF(2) 上求 n×n 方阵的逆（用于把 M·Y=target 解成 Y = M⁻¹·target） */
function invertMatrix(M, n) {
  // 增广 [M | I]
  const A = [];
  for (let i = 0; i < n; i++) {
    const row = new Array(2 * n).fill(0);
    for (let j = 0; j < n; j++) row[j] = M[i][j] ? 1 : 0;
    row[n + i] = 1;
    A.push(row);
  }
  let rank = 0;
  for (let col = 0; col < n && rank < n; col++) {
    let p = -1;
    for (let i = rank; i < n; i++) if (A[i][col]) { p = i; break; }
    if (p < 0) return { ok: false, reason: `矩阵奇异（第 ${col} 列无主元）` };
    [A[rank], A[p]] = [A[p], A[rank]];
    for (let i = 0; i < n; i++) {
      if (i !== rank && A[i][col]) for (let k = col; k < 2 * n; k++) A[i][k] ^= A[rank][k];
    }
    rank++;
  }
  const inv = [];
  for (let i = 0; i < n; i++) inv.push(A[i].slice(n));
  return { ok: true, inv };
}

/** M·x（矩阵 × 向量，GF(2)） */
function matVec(M, x) {
  const nOut = M.length;
  const out = new Array(nOut).fill(0);
  for (let i = 0; i < nOut; i++) {
    let s = 0;
    for (let j = 0; j < x.length; j++) if (M[i][j] && x[j]) s ^= 1;
    out[i] = s;
  }
  return out;
}

// ─────────────── 字节向量上的 GF(2) 矩阵（4×4 作用在 4 字节上） ───────────────
// license 题的 P_i/Q_i 是 4×4 二进制矩阵，作用在 4 字节向量上：
//   (P·x)[k] = XOR of x[j] for j where P[k][j] == 1

function apply4x4(P, x) {
  const out = new Array(4).fill(0);
  for (let k = 0; k < 4; k++) {
    let v = 0;
    for (let j = 0; j < 4; j++) if (P[k][j]) v ^= x[j];
    out[k] = v & 0xff;
  }
  return out;
}

// ─────────────── Feistel 三轮逆推（把 2^64 降到 2^32） ───────────────

/**
 * 三轮 Feistel 的逆推（license 题的形态）：
 *   正向：U=R, V=L^F1(U), W=U^F2(V)
 *         L3 = W, R3 = V ^ F3(W)
 *   已知 Y = Feistel3(X) ^ X，且 yL/yR 已知。
 *
 * 关键恒等式（题解给的那套）：
 *   t = U ^ V ^ W
 *   g1(U) = t ^ yL,  g2(V) = t,  g3(W) = t ^ yR
 *   其中 F_i(x) = x ^ g_i(x)
 * 于是三个变量都用 t 表示，只需枚举 32 位 t 并检查
 *   g1⁻¹(t^yL) ^ g2⁻¹(t) ^ g3⁻¹(t^yR) ^ t == 0
 *
 * @param {object} p  {
 *   yL: number[4], yR: number[4],      // 已知的 4 字节目标
 *   g: [fn, fn, fn],                   // g_i(x[4]) -> y[4]
 *   gInv: [fn, fn, fn],                // 逆函数
 *   maxIter?: number,                  // 枚举上限（默认 2^32 全跑太慢，默认 2^24 采样）
 *   threadHint?: boolean
 * }
 * @returns {{ok:boolean, candidates:Array<{L:number[],R:number[],t:number[]}>, tried:number, reason?:string}}
 */
function feistel3Invert(p) {
  const { yL, yR, gInv } = p || {};
  if (!Array.isArray(yL) || !Array.isArray(yR) || !Array.isArray(gInv) || gInv.length !== 3) {
    return { ok: false, candidates: [], tried: 0, reason: '需要 yL / yR / gInv[3]' };
  }
  const eq = (a, b) => a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];
  const xor4 = (a, b) => [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
  const candidates = [];
  let tried = 0;
  const LIMIT = p.maxIter || 0x1000000;   // 默认 2^24，够验证框架；全量由 Python 侧跑
  // 枚举 t 的 4 个字节
  const t = [0, 0, 0, 0];
  outer:
  for (let a = 0; a < 256; a++) {
    t[0] = a;
    for (let b = 0; b < 256; b++) {
      t[1] = b;
      for (let c = 0; c < 256; c++) {
        t[2] = c;
        for (let d = 0; d < 256; d++) {
          t[3] = d;
          if (++tried > LIMIT) break outer;
          const U = gInv[0](xor4(t, yL));
          const V = gInv[1](t);
          const W = gInv[2](xor4(t, yR));
          if (!U || !V || !W) continue;
          if (eq(xor4(xor4(U, V), xor4(W, t)), [0, 0, 0, 0])) {
            candidates.push({ L: xor4(W, yL), R: U, t: t.slice() });
            if (candidates.length >= 8) break outer;
          }
        }
      }
    }
  }
  return { ok: candidates.length > 0, candidates, tried };
}

/** 生成 **C 源码**：三轮 Feistel 逆推全量 2^32 搜索（参数内联，自包含） */
function buildFeistelC(opts) {
  const o = opts || {};
  const rounds = o.rounds || [];
  if (rounds.length !== 3) throw new Error('buildFeistelC 需要恰好 3 轮参数');
  const hex = (arr) => Array.from(arr).map((v) => '0x' + (Number(v) & 0xff).toString(16).padStart(2, '0')).join(',');
  const flat = (m) => [].concat(...m);
  const sbox = hex(o.sbox || []);
  const yL = hex(o.yL || []);
  const yR = hex(o.yR || []);

  return `// 三轮 Feistel 逆推（2^32 枚举，O3 下单核约 80s）
// 生成自 ctf-tool arx-solve；结构：g_i(x)=Q_i·S(P_i·(x^k_i))，判据见下
#include <stdio.h>
#include <stdint.h>

static const uint8_t SBOX[256] = {${sbox}};
static uint8_t SINV[256];
static const uint8_t KL[3][4] = {${rounds.map((r) => '{' + hex(r.k) + '}').join(',')}};
static const uint8_t QL[3][4][4] = {${rounds.map((r) => '{' + r.Qinv.map((row) => '{' + hex(row) + '}').join(',') + '}').join(',')}};
static const uint8_t PL[3][4][4] = {${rounds.map((r) => '{' + r.Pinv.map((row) => '{' + hex(row) + '}').join(',') + '}').join(',')}};
static const uint8_t YL[4] = {${yL}};
static const uint8_t YR[4] = {${yR}};

static inline void ginv(int r, const uint8_t *z, uint8_t *out) {
    uint8_t t[4];
    for (int b = 0; b < 4; b++) {
        uint8_t s = 0;
        for (int j = 0; j < 4; j++) if (QL[r][b][j]) s ^= z[j];
        t[b] = SINV[s];
    }
    for (int b = 0; b < 4; b++) {
        uint8_t s = 0;
        for (int j = 0; j < 4; j++) if (PL[r][b][j]) s ^= t[j];
        out[b] = s ^ KL[r][b];
    }
}

int main(void) {
    for (int i = 0; i < 256; i++) SINV[SBOX[i]] = (uint8_t)i;
    long long hits = 0;
    for (uint32_t a = 0; a < 256; a++)
    for (uint32_t b = 0; b < 256; b++)
    for (uint32_t c = 0; c < 256; c++)
    for (uint32_t d = 0; d < 256; d++) {
        uint8_t t[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d};
        uint8_t z1[4], U[4], V[4], W[4];
        for (int i = 0; i < 4; i++) z1[i] = t[i] ^ YL[i];
        ginv(0, z1, U);
        ginv(1, t, V);
        uint8_t z3[4];
        for (int i = 0; i < 4; i++) z3[i] = t[i] ^ YR[i];
        ginv(2, z3, W);
        if (!((U[0]^V[0]^W[0]^t[0]) | (U[1]^V[1]^W[1]^t[1])
            | (U[2]^V[2]^W[2]^t[2]) | (U[3]^V[3]^W[3]^t[3]))) {
            printf("HIT L=");
            for (int i = 0; i < 4; i++) printf("%02x", W[i] ^ YL[i]);
            printf(" R=");
            for (int i = 0; i < 4; i++) printf("%02x", U[i]);
            printf(" t=%02x%02x%02x%02x\\n", a, b, c, d);
            if (++hits >= 16) return 0;
        }
    }
    printf("done hits=%lld\\n", hits);
    return 0;
}
`;
}

/** 生成 Python 版三轮 Feistel 逆推脚本（numpy 向量化，全 2^32 可跑） */
function buildFeistelScript(opts) {
  const o = opts || {};
  const rounds = JSON.stringify(o.rounds || []);
  const yL = JSON.stringify(o.yL || []);
  const yR = JSON.stringify(o.yR || []);
  return `# 由 ctf-tool 生成：三轮 Feistel 逆推（numpy 向量化，2^32 可跑）
#
# 结构（license 题形态）：
#   F_i(x) = x ^ g_i(x),  g_i(x) = Q_i · S(P_i · (x ^ k_i))
#   正向：U=R, V=L^F1(U), W=U^F2(V)；L3=W, R3=V^F3(W)；最后 Y = Feistel3(X) ^ X
#
# 化简（2^64 → 2^32）：
#   t = U^V^W  ⇒  g1(U)=t^yL, g2(V)=t, g3(W)=t^yR
#   ⇒ 枚举 t（32 位）并检查  g1⁻¹(t^yL) ^ g2⁻¹(t) ^ g3⁻¹(t^yR) ^ t == 0
#   命中后 L = W ^ yL,  R = U
import sys, json
import numpy as np

ROUNDS = json.loads(r'''${rounds}''')
YL = np.frombuffer(bytes(${yL}), dtype=np.uint8)
YR = np.frombuffer(bytes(${yR}), dtype=np.uint8)

def prep(rd):
    """把一轮的逆变换预编译成"按 mask 查表"的形式。"""
    SBOX = bytes(rd['SBOX'])
    SINV = np.zeros(256, dtype=np.uint8)
    for i, v in enumerate(SBOX):
        SINV[v] = i
    return {
        'SINV': SINV,
        'Pinv': np.array(rd['Pinv'], dtype=np.uint8),
        'Qinv': np.array(rd['Qinv'], dtype=np.uint8),
        'k': np.frombuffer(bytes(rd['k']), dtype=np.uint8),
    }

def lin4(M, x):
    """4x4 GF(2) 矩阵作用在 4 字节向量上；x 形状 (...,4)"""
    out = np.zeros_like(x)
    for b in range(4):
        for j in range(4):
            if M[b][j]:
                out[..., b] ^= x[..., j]
    return out

def ginv(r, z):
    """g⁻¹(z) = Pinv · S⁻¹(Qinv · z) ^ k"""
    t = lin4(r['Qinv'], z)
    t = r['SINV'][t]
    t = lin4(r['Pinv'], t)
    return t ^ r['k']

def solve_batch(ts):
    """ts: (N,4) uint8 → 返回满足判据的 t 索引"""
    r1, r2, r3 = R1, R2, R3
    U = ginv(r1, ts ^ YL)
    V = ginv(r2, ts)
    W = ginv(r3, ts ^ YR)
    s = U ^ V ^ W ^ ts
    ok = (s[:, 0] == 0) & (s[:, 1] == 0) & (s[:, 2] == 0) & (s[:, 3] == 0)
    return np.nonzero(ok)[0], U, W

def solve(chunk=1 << 20):
    hits = []
    total = 1 << 32
    for base in range(0, total, chunk):
        n = min(chunk, total - base)
        v = np.arange(base, base + n, dtype=np.uint64)
        ts = np.stack([(v >> 24) & 0xff, (v >> 16) & 0xff,
                       (v >> 8) & 0xff, v & 0xff], axis=1).astype(np.uint8)
        idx, U, W = solve_batch(ts)
        for i in idx:
            L = W[i] ^ YL
            R = U[i]
            hits.append((bytes(L), bytes(R)))
            if len(hits) >= 16:
                return hits
        if base and base % (chunk * 64) == 0:
            print('  .. %d/%d' % (base, total), file=sys.stderr)
    return hits

R1, R2, R3 = [prep(r) for r in ROUNDS]

if __name__ == '__main__':
    print('ROUNDS 已内置；直接运行开始 2^32 搜索')
    hs = solve()
    print('hits =', len(hs))
    for L, R in hs:
        print('  L =', L.hex(), ' R =', R.hex())
`;
}

module.exports = {
  vecToBigInt, bigIntToVec, linearMap, gaussSolve, invertMatrix, matVec,
  apply4x4, feistel3Invert, buildFeistelScript, buildFeistelC,
};
