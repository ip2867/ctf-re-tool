'use strict';
// 两处"编译器产物"层面的确定性检测（rank 6）。
//
// 背景（都是实测出来的漏判，不是猜的）：
//   1) CrackMe2 的真实算法是 MD5，但扫描器只认**连续的 IV**（`01 23 45 67 89 ab cd ef`）。
//      该程序用的是 64 个 K 轮常量，而且它们**散落**在文件各处（首个 0xd76aa478 的小端
//      在偏移 0xB2F，间隔 8/36/64 字节不等），任何"连续常量"匹配必然 0 命中
//      → 报零指纹 → 旧文案再把零指纹断言成"本层是壳"，方向完全反了。
//   2) cnbragon 的真实 S 盒在偏移 0x1fb98，dword 布局是 `00 70 70 70`（lane0 恒 0，
//      lane1-3 承载同一个值）。旧的 stride=4 分支要求"高 3 字节为 0"，正好排除这种布局。
//
// 判据只依赖"常量的分布形态"，与题目内容无关；阈值由 15 份系统二进制 + 2 个真实样本校准。

// ---------- MD5 轮常量 ----------
// RFC 1321 的 64 个 K 值（floor(2^32 * |sin(i+1)|)），按小端写入时的字节序统计命中。
const MD5_K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// MD5 的 IV。连续出现 4 个是"链接了标准实现"的特征；散落的 K 表 + IV 缺失才是
// "被内联进业务代码"的典型形态（CrackMe2：K 64/64，IV 0/4）。
const MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

const K_LE = MD5_K.map((k) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(k >>> 0, 0);
  return b;
});

/**
 * 检测"内联的 MD5 K 表"。
 * 判据（15 份系统二进制 + CrackMe2 校准）：
 *   CrackMe2      K 64/64，IV 0/4  → 命中
 *   ntoskrnl/ntdll K 64/64，IV 4/4 → 不命中（是标准库实现，不是本题算法）
 *   其余 12 份系统二进制          → K 0/64
 * 即 `hits >= 48 && ivHits <= 1` 专指"K 表在、标准 IV 不在"的内联形态。
 * K 常量**允许散落**，不要求连续——这正是与旧 CRYPTO_FP 连续 8 字节匹配的区别。
 */
function detectMd5RoundConstants(buf) {
  if (!buf || buf.length < 16) return { hit: false, hits: 0, ivHits: 0, firstOffset: -1 };
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);

  let hits = 0;
  let firstOffset = -1;
  for (const le of K_LE) {
    const at = b.indexOf(le);
    if (at !== -1) {
      hits++;
      if (firstOffset < 0 || at < firstOffset) firstOffset = at;
    }
  }

  // 逐个 IV 值统计出现次数（LE / BE 都试）。用命中**个数**而不是出现次数，
  // 避免一份文件里 IV 反复出现把 ivHits 撑爆。
  let ivHits = 0;
  for (const v of MD5_IV) {
    const le = Buffer.alloc(4); le.writeUInt32LE(v >>> 0, 0);
    const be = Buffer.alloc(4); be.writeUInt32BE(v >>> 0, 0);
    if (b.indexOf(le) !== -1 || b.indexOf(be) !== -1) ivHits++;
  }

  return { hit: hits >= 48 && ivHits <= 1, hits, ivHits, firstOffset };
}

// ---------- 多 lane 存放的双射表 ----------
// 真实布局（cnbragon）：dword = `00 70 70 70`（lane0 恒 0，lane1-3 同值）
// 兼容布局（Disguise）：dword = `8e 00 00 00`（lane0 承载值，其余恒 0）
//                       dword = `82 82 82 00`（值同时落在 lane0-2）
//
// 判据：
//   · 至少一个 lane 在 256 项窗口内构成双射（0..255 各出现一次）；
//   · 所有构成双射的 lane 必须**逐项相同**（`00 v v v` 的 lane1/2/3 就是同一张表）；
//   · 其余（非双射）lane 必须在窗口内恒定；
//   · 排除恒等表与仿射表（a*i+b mod 256）——常见噪声，不是密码 S 盒。
const PERM_SUM = 32640;
// 全量 lane 扫描的成本约 16 × size；超过此大小只做 4 字节对齐相位。
const LANE_FULL_MAX = 16 * 1024 * 1024;
// 再大就不扫了：这类文件是通用程序（自带密码库），双射表多且与题目无关。
const LANE_SCAN_MAX = 64 * 1024 * 1024;

function _isAffine(vals) {
  const a = (vals[1] - vals[0] + 256) & 0xff;
  if (a === 0) return true;                       // 常数表
  for (let i = 2; i < 256; i++) {
    if ((((vals[i] - vals[i - 1]) + 256) & 0xff) !== a) return false;
  }
  return true;
}

function _isIdentity(vals) {
  for (let i = 0; i < 256; i++) if (vals[i] !== i) return false;
  return true;
}

/**
 * @param {Buffer|Uint8Array} buf
 * @param {number} maxHits 最多返回多少个命中
 * @returns {Array<{off:number, valueLane:number, constLanes:Array}>}
 *   off 是 256 项窗口的起始字节偏移；第 i 项的值 = buf[off + valueLane + i*4]。
 */
function detectLaneBijectionTables(buf, maxHits = 6) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (!b || b.length < 256 * 4 || b.length > LANE_SCAN_MAX) return [];
  const limit = Math.max(1, maxHits);
  const out = [];
  const emitted = [];

  // 常量数组在正常二进制里至少 4 字节对齐；小文件额外试 1~3 的相位，
  // 覆盖手工拼接/加壳后错位的表。大文件只试相位 0，否则 4 倍扫描不可接受。
  const phases = b.length <= LANE_FULL_MAX ? [0, 1, 2, 3] : [0];

  for (const p of phases) {
    if (out.length >= limit) break;
    const nDwords = Math.floor((b.length - p) / 4);
    if (nDwords < 256) continue;

    for (let L = 0; L < 4 && out.length < limit; L++) {
      const first = p + L;
      // 滑动窗口预筛：任何 0..255 的置换都满足 XOR=0 且 Σ=32640（必要条件）。
      let wx = 0, ws = 0;
      for (let i = 0; i < 256; i++) { const v = b[first + i * 4]; wx ^= v; ws += v; }

      for (let k = 0; k + 256 <= nDwords; k++) {
        if (k > 0) {
          const drop = b[first + (k - 1) * 4];
          const add = b[first + (k + 255) * 4];
          wx ^= drop; wx ^= add; ws -= drop; ws += add;
        }
        if (wx !== 0 || ws !== PERM_SUM) continue;

        const off = p + k * 4;
        // 同一张表会被它自己的多个值 lane 重复命中（`00 v v v`），按窗口去重。
        if (emitted.some((e) => Math.abs(e - off) < 1024)) continue;

        // 收集所有构成双射的 lane
        const bij = [];
        for (let l = 0; l < 4; l++) {
          const seen = new Uint8Array(256);
          let ok = true;
          for (let i = 0; i < 256; i++) {
            const v = b[off + i * 4 + l];
            if (seen[v]) { ok = false; break; }
            seen[v] = 1;
          }
          if (ok) bij.push(l);
        }
        if (!bij.length) continue;

        // 所有双射 lane 必须逐项相同（否则是两张不同的表叠在同一个窗口，不是本形态）
        const valueLane = bij[0];
        let identical = true;
        for (const l of bij.slice(1)) {
          for (let i = 0; i < 256; i++) {
            if (b[off + i * 4 + l] !== b[off + i * 4 + valueLane]) { identical = false; break; }
          }
          if (!identical) break;
        }
        if (!identical) continue;

        const vals = new Array(256);
        for (let i = 0; i < 256; i++) vals[i] = b[off + i * 4 + valueLane];
        if (_isIdentity(vals) || _isAffine(vals)) continue;

        // 非双射 lane 必须在窗口内恒定
        const constLanes = [];
        let othersOk = true;
        for (let l = 0; l < 4; l++) {
          if (bij.includes(l)) continue;
          const c0 = b[off + l];
          for (let i = 1; i < 256; i++) {
            if (b[off + i * 4 + l] !== c0) { othersOk = false; break; }
          }
          if (!othersOk) break;
          constLanes.push({ lane: l, value: c0 });
        }
        if (!othersOk) continue;

        emitted.push(off);
        out.push({ off, valueLane, constLanes });
        if (out.length >= limit) break;
      }
      if (out.length >= limit) break;
    }
  }
  return out;
}

module.exports = {
  MD5_K,
  MD5_IV,
  detectMd5RoundConstants,
  detectLaneBijectionTables,
};
