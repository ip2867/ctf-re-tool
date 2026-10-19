// rank 3 单测：PE/ELF 映像范围解析 + 地址落界 + IDA 身份决策
//
// 背景：IDA MCP 只按端口复用，实测把上一题的库当成本题证据（QuiZow 那个 12KB 文件
// 被反编译出 0x42F038，而 ImageBase=0x400000 / SizeOfImage=0x7000，压根不在映像内）。
// 这组断言钉住"地址是不是属于当前文件"这个可判定的事实。
const fs = require('fs');
const path = require('path');
const M = require(path.join(__dirname, '..', 'electron', 'binary-map.js'));

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] ELF64 解析（真实回归样本 pppp）');
{
  const f = path.join(__dirname, 'regression', 'not-baby-parallelism-elf64', 'pppp');
  if (!fs.existsSync(f)) { console.log('  (跳过：样本不存在)'); }
  else {
    const buf = fs.readFileSync(f);
    const m = M.parseImageMap(buf);
    ok(!!m && m.format === 'elf', 'format=elf', m && m.format);
    ok(m && m.bits === 64, 'bits=64');
    ok(m && m.sections.length === 4, `PT_LOAD 4 段（实际 ${m && m.sections.length}）`);
    ok(m && m.imageBase === 0, 'imageBase=0（未加基址的 PIE）', m && m.imageBase);
    const expectSize = Math.max(...m.sections.map(s => s.va + s.vsize)) - Math.min(...m.sections.map(s => s.va));
    ok(m && m.sizeOfImage === expectSize, 'sizeOfImage = max(vaddr+memsz) - min(vaddr)', m && String(m.sizeOfImage));
    ok(m && m.vaIsAbsolute === true, 'ELF 的 va 是绝对地址');
  }
}

console.log('\n[2] PE32/PE32+ 解析');
{
  // 构造最小 PE32+ 头：DOS stub + PE header + 2 节
  const size = 0x400;
  const b = Buffer.alloc(size, 0);
  b[0] = 0x4d; b[1] = 0x5a;                       // MZ
  b.writeUInt32LE(0x80, 0x3c);                    // e_lfanew
  b.writeUInt32LE(0x00004550, 0x80);              // PE\0\0
  b.writeUInt16LE(0x8664, 0x84);                  // Machine = x64
  b.writeUInt16LE(2, 0x86);                       // NumberOfSections
  b.writeUInt16LE(0xf0, 0x94);                    // SizeOfOptionalHeader
  const opt = 0x98;
  b.writeUInt16LE(0x20b, opt);                    // PE32+
  b.writeBigUInt64LE(0x140000000n, opt + 24);     // ImageBase
  b.writeUInt32LE(0x9000, opt + 56);              // SizeOfImage
  const sec = opt + 0xf0;
  // .text: RVA 0x1000, vsize 0x2000
  b.write('.text\0\0\0', sec, 'latin1');
  b.writeUInt32LE(0x2000, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x2000, sec + 16);
  b.writeUInt32LE(0x400, sec + 20);
  // .data: RVA 0x3000, vsize 0x1000
  b.write('.data\0\0\0', sec + 40, 'latin1');
  b.writeUInt32LE(0x1000, sec + 48);
  b.writeUInt32LE(0x3000, sec + 52);
  b.writeUInt32LE(0x1000, sec + 56);
  b.writeUInt32LE(0x2400, sec + 60);

  const m = M.parseImageMap(b);
  ok(!!m && m.format === 'pe', 'format=pe', m && m.format);
  ok(m && m.bits === 64, 'bits=64');
  ok(m && m.imageBase === 0x140000000, 'ImageBase=0x140000000', m && '0x' + m.imageBase.toString(16));
  ok(m && m.sizeOfImage === 0x9000, 'SizeOfImage=0x9000');
  ok(m && m.sections.length === 2 && m.sections[0].name === '.text', '节名解析正确', m && JSON.stringify(m.sections.map(s => s.name)));
}

console.log('\n[3] isAddrInImage：落界判定（这是串台的核心判据）');
{
  const maps = [];
  const elf = path.join(__dirname, 'regression', 'not-baby-parallelism-elf64', 'pppp');
  if (fs.existsSync(elf)) maps.push({ name: 'pppp(elf)', map: M.parseImageMap(fs.readFileSync(elf)) });

  const peBuf = Buffer.alloc(0x400, 0);
  peBuf[0] = 0x4d; peBuf[1] = 0x5a;                 // MZ（没有它 parseImageMap 会直接返回 null）
  peBuf.writeUInt32LE(0x80, 0x3c);
  peBuf.writeUInt32LE(0x00004550, 0x80);
  peBuf.writeUInt16LE(2, 0x86);
  peBuf.writeUInt16LE(0xf0, 0x94);
  const opt = 0x98;
  peBuf.writeUInt16LE(0x10b, opt);              // PE32
  peBuf.writeUInt32LE(0x400000, opt + 28);      // ImageBase
  peBuf.writeUInt32LE(0x7000, opt + 56);        // SizeOfImage (QuiZow 的真实形状)
  const sec = opt + 0xf0;
  peBuf.write('.text\0\0\0', sec, 'latin1');
  peBuf.writeUInt32LE(0x15c4, sec + 8);
  peBuf.writeUInt32LE(0x1000, sec + 12);
  peBuf.writeUInt32LE(0x15c4, sec + 16);
  peBuf.writeUInt32LE(0x400, sec + 20);
  maps.push({ name: 'QuizowShape(pe32)', map: M.parseImageMap(peBuf) });

  for (const { name, map } of maps) {
    ok(!!map, name + ' 解析成功');
  }
  const quizow = maps.find(x => x.name.startsWith('Quizow')).map;
  ok(M.isAddrInImage(quizow, 0x401000) === true, 'QuiZow: 0x401000 在 .text 内');
  ok(M.isAddrInImage(quizow, 0x42F038) === false, 'QuiZow: 0x42F038 在映像外（实测的串台证据）');
  ok(M.isAddrInImage(quizow, 0x407000) === false, 'QuiZow: 0x407000 正好是映像上限（不含）');
  // 该合成样本的 .text 从 RVA 0x1000 起、vsize 0x15c4，所以 0x401000..0x4025c4 在内，
  // 0x4025c4 之后到映像上限之间是空洞
  ok(M.isAddrInImage(quizow, 0x402600) === false, 'QuiZow: 0x402600 落在节后空洞');
  ok(M.isAddrInImage(quizow, 0) === false, '地址 0 不算有效');

  if (maps[0].map) {
    const elfMap = maps[0].map;
    ok(M.isAddrInImage(elfMap, 0x1000) === true, 'pppp: 0x1000 在第一个 LOAD 段');
    ok(M.isAddrInImage(elfMap, 0x3000) === true, 'pppp: 0x3000 在第二个 LOAD 段');
    ok(M.isAddrInImage(elfMap, 0x9000) === false, 'pppp: 0x9000 越界（最高段止于 33592）');
    ok(M.isAddrInImage(elfMap, 0x999999) === false, 'pppp: 越界地址被拒');
  }
}

console.log('\n[4] filterFunctionsInImage：把不属于本文件的函数剔掉');
{
  const buf = Buffer.alloc(0x400, 0);
  buf[0] = 0x4d; buf[1] = 0x5a;
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x00004550, 0x80);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  const opt = 0x98;
  buf.writeUInt16LE(0x10b, opt);
  buf.writeUInt32LE(0x400000, opt + 28);
  buf.writeUInt32LE(0x7000, opt + 56);
  const sec = opt + 0xf0;
  buf.write('.text\0\0\0', sec, 'latin1');
  buf.writeUInt32LE(0x2000, sec + 8);
  buf.writeUInt32LE(0x1000, sec + 12);
  const map = M.parseImageMap(buf);

  const funcs = [
    { address: '0x401000', name: 'sub_401000' },      // 内
    { address: '0x401500', name: 'sub_401500' },      // 内
    { address: '0x402080', name: 'sub_402080' },      // 内（< 0x400000+0x1000+0x2000）
    { address: '0x42F038', name: 'sub_42F038' },      // 外（实测串台条目）
    { addr: '0x140001000', name: 'foreign' },         // 外（另一个 PE 的基址）
    { start: '0x401800', name: 'sub_401800' },        // 内
    { name: 'no-address' },                            // 无地址 → 丢弃
  ];
  const r = M.filterFunctionsInImage(funcs, map);
  ok(r.mapOk === true, 'mapOk=true');
  ok(r.kept.length === 4, `保留 4 个（实际 ${r.kept.length}）`, JSON.stringify(r.kept.map(f => f.name)));
  ok(r.dropped.length === 3, `丢弃 3 个（实际 ${r.dropped.length}）`, JSON.stringify(r.dropped.map(f => f.name)));
  ok(r.dropped.some(f => f.name === 'sub_42F038'), 'sub_42F038 被判定为越界');
  ok(!r.kept.some(f => f.name === 'foreign'), '其他镜像基址的函数被剔除');

  // 裸地址数组
  const r2 = M.filterFunctionsInImage(['0x401000', '0x999999'], map);
  ok(r2.kept.length === 1 && r2.dropped.length === 1, '支持裸地址数组');
}

console.log('\n[5] decideIdaAction：四态决策');
{
  const target = 'E:\\ctf\\pratice\\ai\\cnbragon\\KanxueCTF2016Keygenme.exe';
  const a = M.decideIdaAction({ listening: false });
  ok(a.action === 'launch', '未监听 → launch', a.action);

  const b = M.decideIdaAction({ listening: true, identity: { success: false }, targetPath: target });
  ok(b.action === 'reload' && b.reason === 'unknown', '身份未知 → reload（安全策略）', JSON.stringify(b));
  ok(/身份未知/.test(b.log), '日志含「身份未知」', b.log);

  const c = M.decideIdaAction({
    listening: true,
    identity: { success: true, input_path: 'E:\\ctf\\other\\CrackMe.exe' },
    targetPath: target,
  });
  ok(c.action === 'reload' && c.reason === 'mismatch', '路径不一致 → reload', JSON.stringify(c));
  ok(/目标不一致/.test(c.log), '日志含「目标不一致」', c.log);
  ok(/crackme\.exe/i.test(c.log) && /kanxue/i.test(c.log), '日志含双方文件名', c.log);

  const d = M.decideIdaAction({
    listening: true,
    identity: { success: true, input_path: target.toUpperCase().replace(/\\/g, '/') },
    targetPath: target,
  });
  ok(d.action === 'reuse', '路径一致（大小写/斜杠归一）→ reuse', JSON.stringify(d));
  ok(/身份校验通过/.test(d.log), '日志含「身份校验通过」', d.log);

  // 缺 input_path 但有 module
  const e = M.decideIdaAction({
    listening: true, identity: { success: true, module: 'CrackMe.exe' }, targetPath: 'C:\\x\\CrackMe.exe',
  });
  ok(e.action === 'reload', '只有 module 名不足以判定同文件 → reload（保守）', JSON.stringify(e));
}

console.log('\n[6] planPidClose：只结束启动前后新增的 PID');
{
  const before = [100, 200];
  const after = [100, 200, 300, 400];
  const kill = M.planPidClose(before, after);
  ok(JSON.stringify(kill) === '[300,400]', '返回差集 [300,400]', JSON.stringify(kill));
  ok(!kill.includes(100) && !kill.includes(200), '不包含启动前已存在的 PID');

  const none = M.planPidClose([1, 2], [1, 2]);
  ok(none.length === 0, '无新增 → 空数组');

  const empty = M.planPidClose(null, null);
  ok(empty.length === 0, 'null 输入不崩');
}

console.log('\n[7] 非法/截断输入返回 null 而不抛');
{
  ok(M.parseImageMap(null) === null, 'null → null');
  ok(M.parseImageMap(Buffer.alloc(0)) === null, '空 buffer → null');
  ok(M.parseImageMap(Buffer.from('not a binary')) === null, '非 PE/ELF → null');
  const trunc = Buffer.alloc(0x40, 0);
  trunc[0] = 0x4d; trunc[1] = 0x5a;
  trunc.writeUInt32LE(0x1000, 0x3c);   // e_lfanew 越界
  ok(M.parseImageMap(trunc) === null, 'PE 头越界 → null');
  const badElf = Buffer.alloc(64, 0);
  badElf[0] = 0x7f; badElf[1] = 0x45; badElf[2] = 0x4c; badElf[3] = 0x46;
  badElf[4] = 2; badElf[5] = 1;
  badElf.writeBigUInt64LE(0n, 0x20);   // phoff = 0
  ok(M.parseImageMap(badElf) === null, 'ELF 无程序头 → null');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
