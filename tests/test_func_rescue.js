// 函数表落界 / 兜底补取回归
//
// 实测缺陷（ByteCTF2019 easy_rust，2026-10-30）：
//   .bss 到 0x36208 结束，IDA 把未定义的外部符号合成到 0x362a8 起
//   （pthread_getattr_np / pthread_getspecific ... 全是 PLT 桩）。
//   list_funcs 按地址排序，第一页/全量都是这些桩 → 77/77 全部"越界"被剔除
//   → funcs=[] → 前置短路"无有效数据" → 整题放弃 93 秒。
//
//   ✗ 旧行为：剔除后不管剩多少，直接继续 → 全空就中止
//   ✓ 新行为：全部被剔除 = "函数表不可用"信号 → 按可执行段补取 → 仍为空才降级
//
// 另含 Rust 入口定位：C 风格 .text 里没有 main 符号，入口是 _ZN..4main..E。
const fs = require('fs');
const path = require('path');

const { parseImageMap, isAddrInImage, filterFunctionsInImage, parseAddr } =
  require('../electron/binary-map.js');

const ROOT = path.join(__dirname, '..');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

// ── 构造一个 mini ELF64：4 个 PT_LOAD，可执行段 0x5140-0x250a5 ──
function buildMiniElf() {
  const ehsize = 64, phentsize = 56, phnum = 4;
  const phoff = ehsize;
  const loads = [
    { off: 0x0, va: 0x0, filesz: 0x44b8, memsz: 0x44b8, flags: 4 },
    { off: 0x5000, va: 0x5000, filesz: 0x200a5, memsz: 0x200a5, flags: 5 },  // R+X
    { off: 0x26000, va: 0x26000, filesz: 0xbcac, memsz: 0xbcac, flags: 4 },
    { off: 0x32b60, va: 0x33b60, filesz: 0x24d8, memsz: 0x26a8, flags: 6 },
  ];
  const total = 0x32b60 + 0x24d8;
  const buf = Buffer.alloc(total, 0);
  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
  buf[4] = 2; buf[5] = 1; buf[6] = 1;
  buf.writeUInt16LE(3, 16);            // ET_DYN
  buf.writeUInt16LE(0x3e, 18);         // x86-64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x5170n, 24);   // e_entry
  buf.writeBigUInt64LE(BigInt(phoff), 32);
  buf.writeUInt16LE(ehsize, 52);
  buf.writeUInt16LE(phentsize, 54);
  buf.writeUInt16LE(phnum, 56);
  for (let k = 0; k < loads.length; k++) {
    const l = loads[k];
    const o = phoff + k * phentsize;
    buf.writeUInt32LE(1, o);
    buf.writeUInt32LE(l.flags, o + 4);
    buf.writeBigUInt64LE(BigInt(l.off), o + 8);
    buf.writeBigUInt64LE(BigInt(l.va), o + 16);
    buf.writeBigUInt64LE(BigInt(l.va), o + 24);
    buf.writeBigUInt64LE(BigInt(l.filesz), o + 32);
    buf.writeBigUInt64LE(BigInt(l.memsz), o + 40);
  }
  // 填点可打印内容，避免被判成"空文件"
  for (let p = 0x5000; p < 0x5200; p++) buf[p] = 0x90;
  return buf;
}

const elf = buildMiniElf();
const map = parseImageMap(elf);

console.log('[1] 映像边界：ELF 用 PT_LOAD，可执行段识别正确');
{
  ok(map && map.format === 'elf', '解析为 ELF', map && map.format);
  ok(map.imageBase === 0, 'imageBase=0x0', '0x' + (map.imageBase || 0).toString(16));
  ok(map.sizeOfImage === 0x36208, 'sizeOfImage=0x36208', '0x' + (map.sizeOfImage || 0).toString(16));
  const exec = map.sections.filter(s => s.executable);
  ok(exec.length === 1, '只有一个可执行段', String(exec.length));
  ok(exec[0].va === 0x5000 && exec[0].vsize === 0x200a5, '可执行段 0x5000+0x200a5',
    `0x${exec[0].va.toString(16)}+0x${exec[0].vsize.toString(16)}`);
}

console.log('\n[2] 真实函数在内、合成桩在外（判据本身正确）');
{
  ok(isAddrInImage(map, 0x6000) === true, '.text 内 0x6000 判为在映像内');
  ok(isAddrInImage(map, 0x25000) === true, '.text 内 0x25000 判为在映像内');
  // 日志里那三个 PLT 桩确实在 .bss 末尾（0x36208）之外
  ok(isAddrInImage(map, 0x362a8) === false, '合成桩 0x362a8 判为越界（正确）');
  ok(isAddrInImage(map, 0x362b0) === false, '合成桩 0x362b0 判为越界');
  ok(isAddrInImage(map, 0x362b8) === false, '合成桩 0x362b8 判为越界');
  // 边界：0x36208 是最后一字节之后，应为 false
  ok(isAddrInImage(map, 0x36208) === false, '0x36208（末尾后一字节）判为越界');
  ok(isAddrInImage(map, 0x36207) === true, '0x36207（末尾前一字节）仍在映像内');
}

console.log('\n[3] filterFunctionsInImage：分类正确，但"全丢"必须可被上层识别');
{
  // 重现日志场景：全部是合成桩
  const allStubs = [
    { address: '0x362a8', name: 'pthread_getattr_np', size: '0x8' },
    { address: '0x362b0', name: 'pthread_getspecific', size: '0x8' },
    { address: '0x362b8', name: 'pthread_cond_destroy', size: '0x8' },
  ];
  const r1 = filterFunctionsInImage(allStubs, map);
  ok(r1.kept.length === 0 && r1.dropped.length === 3, '全部越界 → kept=0 dropped=3',
    `kept=${r1.kept.length} dropped=${r1.dropped.length}`);

  // 混合场景：真实函数应被保留
  const mixed = [
    { address: '0x5140', name: 'sub_5140', size: '0x20' },
    { address: '0x6000', name: 'sub_6000', size: '0x300' },
    { address: '0x362a8', name: 'pthread_getattr_np', size: '0x8' },
  ];
  const r2 = filterFunctionsInImage(mixed, map);
  ok(r2.kept.length === 2, '混合时保留 2 个真实函数', String(r2.kept.length));
  ok(r2.dropped.length === 1, '剔除 1 个合成桩', String(r2.dropped.length));
}

console.log('\n[4] 渲染层兜底逻辑存在（不依赖 py_eval 也能走 list_funcs）');
{
  ok(/async function rescueFunctionsFromIda/.test(appSrc), '定义了 rescueFunctionsFromIda');
  const iFn = appSrc.indexOf('async function rescueFunctionsFromIda');
  const body = appSrc.slice(iFn, iFn + 9000);
  ok(/路线 A/.test(body) && /py_eval/.test(body), '路线 A：py_eval 枚举');
  ok(/路线 B/.test(body) && /list_funcs/.test(body), '路线 B：list_funcs 兜底（py_eval 不可用也能走）');
  ok(/SEGPERM_EXEC/.test(body), '只取可执行段');
  ok(/inText/.test(body), '用可执行段范围二次过滤（防串台）');
  // 调用点：全部被剔除后才触发，而不是无条件
  ok(/if \(!funcs\.length\)/.test(appSrc), '仅在 funcs 为空时触发兜底');
  ok(/rescueFunctionsFromIda\(state\.currentFile/.test(appSrc), '兜底调用传当前文件');
  // 关键：不再把"全越界"直接当串台并放弃
  ok(!/判定为串台，已剔除/.test(appSrc), '不再把剔除一律说成"串台"');
  ok(/IDA 合成条目/.test(appSrc), '区分「IDA 合成条目」与串台');
}

console.log('\n[5] Rust 入口定位（C 风格候选表不够用）');
{
  ok(/4main\\d\*h\[0-9a-f\]\+E/.test(appSrc) || /4main/.test(appSrc), '识别 mangled main（_ZN..4main..E）');
  ok(/lang_start/.test(appSrc), '把 lang_start 加入候选');
  // selectKeyFunctions 里 Rust 入口要加权
  const iSel = appSrc.indexOf('function selectKeyFunctions');
  const selBody = appSrc.slice(iSel, iSel + 3000);
  ok(/4main/.test(selBody), '关键函数评分里 mangled main 加权');
  ok(/lang_start/.test(selBody), '关键函数评分里 lang_start 加权');
  // 反例：C 风格正则不能匹配 mangled 名（说明必须单独加规则）
  const cStyleRe = /^_*(win)?main(@\d+)?$/i;
  ok(!cStyleRe.test('_ZN4main17h1234567890abcdefE'), 'C 风格正则确实匹配不到 Rust 入口');
  ok(/^_ZN.*4main\d*h[0-9a-f]+E$/i.test('_ZN4main17h1234567890abcdefE'), 'Rust 正则可匹配');
}

console.log('\n[6] parseAddr 兼容数字/十六进制字符串');
{
  ok(parseAddr('0x362a8') === 0x362a8, "parseAddr('0x362a8')");
  ok(parseAddr(0x362a8) === 0x362a8, 'parseAddr(number)');
  ok(!Number.isFinite(parseAddr('zzz')), '非法输入 NaN');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
