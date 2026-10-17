// 单测：normalizeScript / scriptSimilarity 是否真能识别"同思路换写法"
// 用法：node tests/test_script_dedup.js
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = src.indexOf('// 脚本归一化');
const cut = src.slice(start, src.indexOf('// 工具调用落盘日志'));
eval(cut);

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ✅ ' + name); }
  else { fail++; console.log('  ❌ ' + name + (extra ? '  → ' + extra : '')); }
}

// 同一思路、换写法（变量改名 + 注释 + 字符串改写 + 空白重排）
const s1 = `
import pefile
# 读 stage2 常量表
pe = pefile.PE("Disguise.exe")
rva = 0x41C000
off = pe.get_offset_from_rva(rva)
data = open("Disguise.exe","rb").read()[off:off+0x100]
print(data.hex())
`;
const s2 = `
import pefile
"""读取第二阶段常量"""
p = pefile.PE("Disguise.exe")
r = 0x41C000
o = p.get_offset_from_rva(r)
buf = open("Disguise.exe","rb").read()[o:o+0x100]
print(buf.hex())
`;
const s3 = `
import pefile
# 换一种注释
pe2 = pefile.PE("Disguise.exe")
rva2 = 0x41C000
off2 = pe2.get_offset_from_rva(rva2)
d = open("Disguise.exe","rb").read()[off2:off2+0x100]
print(d.hex())
`;

// 完全不同的脚本（前 400 字符相似但整体不同）
const s4 = `
import pefile
pe = pefile.PE("Disguise.exe")
for sec in pe.sections:
    print(sec.Name, hex(sec.VirtualAddress), hex(sec.Misc_VirtualSize))
`;

// 真正换了思路（SM4 解密框架）
const s5 = `
from gmssl.sm4 import CryptSM4, SM4_DECRYPT
key = b"We1c0me_t0_xmctf"
c = CryptSM4()
c.set_key(key, SM4_DECRYPT)
ct = bytes.fromhex(open("stage2.bin","rb").read().hex())
pt = c.crypt_ecb(ct)
print(pt)
`;

console.log('归一化后相似度：');
const n1 = normalizeScript(s1);
console.log(`  s1 vs s2（同思路换写法）: ${scriptSimilarity(n1, normalizeScript(s2)).toFixed(3)}`);
console.log(`  s1 vs s3（同思路换写法）: ${scriptSimilarity(n1, normalizeScript(s3)).toFixed(3)}`);
console.log(`  s1 vs s4（不同目的）    : ${scriptSimilarity(n1, normalizeScript(s4)).toFixed(3)}`);
console.log(`  s1 vs s5（换算法思路）  : ${scriptSimilarity(n1, normalizeScript(s5)).toFixed(3)}`);

check('同思路 s1/s2 相似度 >0.88', scriptSimilarity(n1, normalizeScript(s2)) > 0.88);
check('同思路 s1/s3 相似度 >0.88', scriptSimilarity(n1, normalizeScript(s3)) > 0.88);
check('不同脚本 s1/s4 相似度 <0.88', scriptSimilarity(n1, normalizeScript(s4)) < 0.88,
  scriptSimilarity(n1, normalizeScript(s4)).toFixed(3));
check('换算法 s1/s5 相似度 <0.88', scriptSimilarity(n1, normalizeScript(s5)) < 0.88,
  scriptSimilarity(n1, normalizeScript(s5)).toFixed(3));
check('完全相同 → 1.0', scriptSimilarity(n1, n1) === 1);
check('空串 → 0', scriptSimilarity('', n1) === 0);
check('归一化去注释', !normalizeScript(s1).includes('读stage2'));
check('归一化折叠长 hex', !normalizeScript(s1).includes('0x41C000'));

// 模拟拦截时序：同一思路连续第 3 次必须被拦
console.log('\n拦截时序模拟（B 层，阈值 0.88，count>=3 拦）：');
const pool = [];
let blocked = null;
[s1, s2, s3].forEach((s, i) => {
  const norm = normalizeScript(s);
  const hit = pool.find(v => scriptSimilarity(norm, v.norm) > 0.88);
  if (hit) {
    hit.count++;
    console.log(`  第 ${i + 1} 次：命中同思路（count=${hit.count}）${hit.count >= 3 ? ' → 拦截' : ' → 放行'}`);
    if (hit.count >= 3 && blocked === null) blocked = i + 1;
  } else {
    pool.push({ norm, count: 1 });
    console.log(`  第 ${i + 1} 次：新脚本，入池`);
  }
});
check('第 3 次同思路被拦截', blocked === 3);

// 误伤风险：两脚本共享同一段 boilerplate 前置，但**真正的任务不同** → 必须不判同路
const BOILER = `import pefile, struct
from capstone import *
pe = pefile.PE("Disguise.exe")
base = pe.OPTIONAL_HEADER.ImageBase
data = open("Disguise.exe","rb").read()
def rva2off(r): return pe.get_offset_from_rva(r)
`;
const t1 = BOILER + `
# 任务A：导出所有区段信息
for s in pe.sections:
    print(s.Name.decode().strip('\\x00'), hex(s.VirtualAddress), s.SizeOfRawData)
`;
const t2 = BOILER + `
# 任务B：反汇编 VM 入口附近字节
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = data[rva2off(0x401000):rva2off(0x401000)+0x200]
for i in md.disasm(code, base+0x401000):
    print(hex(i.address), i.mnemonic, i.op_str)
`;
const simBoiler = scriptSimilarity(normalizeScript(t1), normalizeScript(t2));
console.log(`\n共享 boilerplate 但任务不同: ${simBoiler.toFixed(3)}`);
check('共享前置但任务不同 → <0.88（不误伤）', simBoiler < 0.88, simBoiler.toFixed(3));

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
