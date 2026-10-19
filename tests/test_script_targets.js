// rank 1 单测：去重闸的「地址目标指纹」
//
// 核心回归：只改观测地址的脚本不得被判成"同一思路"——旧实现归一化后相似度恒为 1.000，
// 第 3 次起永久拦截，实测让 CrackMe2 / CrackMe5 / not-baby-parallelism 三道题放弃静态分析。
const path = require('path');
const fs = require('fs');
const D = require(path.join(__dirname, '..', 'electron', 'script-dedup.js'));

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

// 与 main.js 的 normalizeScript 保持一致（地址/数字抹成 N）——这正是误判的来源，
// 测试里必须用同一份实现，否则测不出真实行为。
const SCRIPT_KEYWORDS = new Set(('import,from,as,def,return,for,in,while,if,elif,else,try,except,finally,'
  + 'with,class,lambda,pass,break,continue,global,nonlocal,yield,assert,del,raise,not,and,or,is,'
  + 'print,len,range,int,str,bytes,bytearray,list,dict,set,tuple,open,hex,ord,chr,abs,sum,min,max,sorted,'
  + 'enumerate,zip,map,filter,repr,format,type,isinstance,getattr,setattr,struct,ord,bin,oct,divmod,'
  + 'echo,export,then,fi,do,done,set,local,function,const,let,var,read,write,readfile,readFileSync').split(','));
function normalizeScript(s) {
  let t = String(s || '')
    .replace(/"""(?:[\s\S]*?)"""|'''(?:[\s\S]*?)'''/g, ' ')
    .replace(/#[^\n]*/g, ' ')
    .replace(/\/\/[^\n]*/g, ' ');
  t = t.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, ' S ')
    .replace(/\b0[xX][0-9a-fA-F]+\b/g, ' N ')
    .replace(/\b\d+(\.\d+)?\b/g, ' N ');
  const alias = new Map();
  let next = 0;
  t = t.replace(/(\.)?\b([A-Za-z_]\w*)\b/g, (m, dot, id) => {
    if (dot) return m;
    if (SCRIPT_KEYWORDS.has(id)) return id;
    if (!alias.has(id)) alias.set(id, 'v' + (next++));
    return alias.get(id);
  });
  return t.replace(/\s+/g, '');
}
const sim = (a, b) => {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const grams = (s) => { const set = new Set(); for (let i = 0; i + 1 < s.length; i++) set.add(s.slice(i, i + 2)); return set; };
  const A = grams(a), B = grams(b);
  if (!A.size || !B.size) return 0;
  let inter = 0; for (const g of A) if (B.has(g)) inter++;
  return inter / (A.size + B.size - inter);
};

// 造一个"模板固定、只换观测地址"的脚本（真实形态：capstone 反汇编某区间）
const disasmAt = (addr, varName) => `
from capstone import *
import pefile
pe = pefile.PE("target.exe")
data = open("target.exe","rb").read()
base = pe.OPTIONAL_HEADER.ImageBase
code = data[pe.get_offset_from_rva(${addr}):pe.get_offset_from_rva(${addr})+0x200]
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ${varName} in md.disasm(code, base+${addr}):
    print(hex(${varName}.address), ${varName}.mnemonic, ${varName}.op_str)
`;

console.log('[1] scriptTargets 抽地址并规范化');
{
  const t = D.scriptTargets(disasmAt('0x4012f0', 'insn'));
  ok(t.addrs.has('4012f0'), '含 4012f0', JSON.stringify([...t.addrs]));
  ok(t.path === 'target.exe', '取到文件路径：' + t.path);
  // 大小写 / 前导零归一
  const u = D.scriptTargets('read 0x0004012F0');
  ok(u.addrs.has('4012f0'), '前导零/大写归一', JSON.stringify([...u.addrs]));
  // 小常量不是观测目标
  const sm = D.scriptTargets('for i in range(0x10): print(i, 0xff)');
  ok(sm.addrs.size === 0, '小常量被排除', JSON.stringify([...sm.addrs]));
}

console.log('\n[2] targetsOverlap：containment 语义 + 不同文件直接为 0');
{
  const a = D.scriptTargets(disasmAt('0x4012f0', 'i'));
  const b = D.scriptTargets(disasmAt('0x42f1aa', 'j'));
  ok(D.targetsOverlap(a, b) === 0, '不同地址 → 0');
  const c = D.scriptTargets(disasmAt('0x4012f0', 'x'));
  ok(D.targetsOverlap(a, c) === 1, '同地址 → 1', String(D.targetsOverlap(a, c)));
  // 单侧多一个地址仍算覆盖（containment 而非 Jaccard）
  const d = D.scriptTargets(disasmAt('0x4012f0', 'i') + '\nprint(0x42f038)\nprint(0x43c475)');
  ok(D.targetsOverlap(a, d) === 1, '子集被覆盖 → 1', String(D.targetsOverlap(a, d)));
  // 不同文件
  const e = D.scriptTargets(disasmAt('0x4012f0', 'i').replace('target.exe', 'other.exe'));
  ok(D.targetsOverlap(a, e) === 0, '不同文件 → 0');
  // 空集合
  ok(D.targetsOverlap({ addrs: new Set(), path: '' }, a) === 0, '空集合 → 0');
}

console.log('\n[3] 关键回归：相似度 1.0 但地址不同 → 必须放行');
{
  const D2 = D;
  D2.setScriptSimilarity(sim);
  const st = D2.createDedupState();
  const script = (addr, v) => disasmAt(addr, v);
  const norm1 = normalizeScript(script('0x4012f0', 'i'));
  const norm2 = normalizeScript(script('0x42f1aa', 'j'));
  // 旧判据：相似度 = 1.000（这正是误判来源）
  ok(sim(norm1, norm2) === 1, '前提成立：归一化后相似度 = 1.000', String(sim(norm1, norm2)));

  const mk = (addr, v, n) => ({
    name: 'run_python', sig: 'sig-' + addr + '-' + n, isScriptTool: true,
    script: script(addr, v), norm: normalizeScript(script(addr, v)),
    targets: D2.scriptTargets(script(addr, v)),
  });
  const r1 = D2.checkDedup(st, mk('0x4012f0', 'i', 1));
  const r2 = D2.checkDedup(st, mk('0x42f1aa', 'j', 2));
  const r3 = D2.checkDedup(st, mk('0x42fcd9', 'k', 3));
  const r4 = D2.checkDedup(st, mk('0x401000', 'm', 4));
  ok(!r1.blocked && !r2.blocked && !r3.blocked && !r4.blocked,
    '四个不同地址全部放行', JSON.stringify([r1.blocked, r2.blocked, r3.blocked, r4.blocked]));
  ok(r2.nearMiss === true || /目标集合不同/.test(r2.reason), '并标注"目标集合不同，按新实验放行"', r2.reason);
}

console.log('\n[4] A 层：逐字节相同第 2 次拦');
{
  D.setScriptSimilarity(sim);
  const st = D.createDedupState();
  const s = disasmAt('0x4012f0', 'i');
  const mk = () => ({ name: 'run_python', sig: 'SAME', isScriptTool: true, script: s, norm: normalizeScript(s), targets: D.scriptTargets(s) });
  const a = D.checkDedup(st, mk());
  const b = D.checkDedup(st, mk());
  ok(!a.blocked, '第 1 次放行');
  ok(b.blocked && b.layer === 'A', '第 2 次被 A 层拦', JSON.stringify(b));
}

console.log('\n[5] B 层：文本不同、地址相同，第 3 次拦');
{
  D.setScriptSimilarity(sim);
  const st = D.createDedupState();
  const mk = (v, n) => {
    const s = disasmAt('0x4012f0', v);
    return { name: 'run_python', sig: 'B' + n, isScriptTool: true, script: s, norm: normalizeScript(s), targets: D.scriptTargets(s) };
  };
  const r1 = D.checkDedup(st, mk('i', 1));
  const r2 = D.checkDedup(st, mk('j', 2));
  const r3 = D.checkDedup(st, mk('k', 3));
  ok(!r1.blocked, '第 1 次放行');
  ok(!r2.blocked, '第 2 次放行（count=2）', JSON.stringify(r2));
  ok(r3.blocked && r3.layer === 'B', '第 3 次被 B 层拦', JSON.stringify(r3));
  ok(/观测地址重叠/.test(r3.reason), '拦截文案含重叠度', r3.reason);
}

console.log('\n[6] cleared：上一轮结果被清空时允许重取一次');
{
  D.setScriptSimilarity(sim);
  const st = D.createDedupState();
  const s = disasmAt('0x4012f0', 'i');
  const mk = (cleared) => ({ name: 'run_python', sig: 'C1', isScriptTool: true, script: s, norm: normalizeScript(s), targets: D.scriptTargets(s), cleared });
  D.checkDedup(st, mk(false));
  const r = D.checkDedup(st, mk(true));
  ok(!r.blocked && r.layer === 'cleared', 'cleared 命中且放行', JSON.stringify(r));
  const again = D.checkDedup(st, mk(false));
  ok(!again.blocked, '重取一次后可再执行（计数已归零）', JSON.stringify(again));
}

console.log('\n[7] 无地址指纹时不判 B 层（宁放行）');
{
  D.setScriptSimilarity(sim);
  const st = D.createDedupState();
  const s = 'print("hello")\nfor i in range(3):\n    print(i)\nprint("world")\n';
  const mk = (n) => ({ name: 'run_python', sig: 'N' + n, isScriptTool: true, script: s, norm: normalizeScript(s), targets: D.scriptTargets(s) });
  const r1 = D.checkDedup(st, mk(1));
  const r2 = D.checkDedup(st, mk(2));
  const r3 = D.checkDedup(st, mk(3));
  ok(!r1.blocked && !r2.blocked && !r3.blocked, '三次均放行');
  ok(/无地址目标指纹/.test(r3.reason), '说明未判定的原因', r3.reason);
}

console.log('\n[8] 非脚本工具只走 A 层（阈值 4）');
{
  const st = D.createDedupState();
  const mk = () => ({ name: 'read_file', sig: 'R', isScriptTool: false });
  const rs = [1, 2, 3, 4].map(() => D.checkDedup(st, mk()));
  ok(!rs[0].blocked && !rs[1].blocked && !rs[2].blocked, '前 3 次放行');
  ok(rs[3].blocked && rs[3].layer === 'A', '第 4 次拦', JSON.stringify(rs[3]));
}

console.log('\n[9] 真实脚本快照（若存在）：CrackMe5 的 115 vs 31 必须放行');
{
  const f1 = path.join(__dirname, 'fixtures', 'dedup-cm5-115.js');
  const f2 = path.join(__dirname, 'fixtures', 'dedup-cm5-31.js');
  if (fs.existsSync(f1) && fs.existsSync(f2)) {
    const s1 = fs.readFileSync(f1, 'utf8');
    const s2 = fs.readFileSync(f2, 'utf8');
    const t1 = D.scriptTargets(s1), t2 = D.scriptTargets(s2);
    ok(D.targetsOverlap(t1, t2) === 0,
      `目标重叠 0（实际 ${D.targetsOverlap(t1, t2)}）`,
      JSON.stringify({ a: [...t1.addrs].slice(0, 4), b: [...t2.addrs].slice(0, 4) }));
  } else {
    console.log('  (跳过：fixtures 快照不存在)');
  }
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
