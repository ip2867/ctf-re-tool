'use strict';
// PE/ELF 映像范围解析 + 地址落界校验（rank 3）。
//
// 背景：IDA MCP 只按端口复用（13337 在监听就当"已加载当前文件"），
// 实测把上一题的库当成本题的证据注入了提示词 —— QuiZow 那个 12KB 的文件被反编译出
// 0x42F038（镜像上限 0x407000 之外），cnbragon / not-baby-parallelism 拿到的是
// 另一个 PE 的 WinMain。要让"返回的地址是否属于当前文件"变成可判定的，
// 必须先能从文件字节里读出映像范围和节表 —— 这就是本模块的唯一职责。
//
// 纯函数、零 Electron 依赖，便于在无 GUI 的 Node 下测试。

function parseImageMap(buf) {
  if (!buf || buf.length < 64) return null;
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  try {
    if (b[0] === 0x4d && b[1] === 0x5a) return parsePE(b);
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return parseELF(b);
  } catch (e) {
    return null;
  }
  return null;
}

function parsePE(b) {
  const peOff = b.readUInt32LE(0x3c);
  if (peOff <= 0 || peOff + 24 > b.length) return null;
  if (b.readUInt32LE(peOff) !== 0x00004550) return null;   // "PE\0\0"

  const coffOff = peOff + 4;
  const numberOfSections = b.readUInt16LE(coffOff + 2);
  const sizeOfOptionalHeader = b.readUInt16LE(coffOff + 16);
  const optOff = coffOff + 20;
  if (optOff + 2 > b.length) return null;

  const magic = b.readUInt16LE(optOff);
  const is64 = magic === 0x20b;      // PE32+
  if (!is64 && magic !== 0x10b) return null;

  // ImageBase 在 PE32 是 +28(dword)，PE32+ 是 +24(qword)
  const imageBase = is64
    ? Number(b.readBigUInt64LE(optOff + 24))
    : b.readUInt32LE(optOff + 28);
  const sizeOfImage = b.readUInt32LE(optOff + 56);
  if (!Number.isFinite(imageBase) || !sizeOfImage) return null;

  const sections = [];
  const secOff = optOff + sizeOfOptionalHeader;
  for (let i = 0; i < numberOfSections; i++) {
    const o = secOff + i * 40;
    if (o + 40 > b.length) break;
    let name = b.toString('latin1', o, o + 8).replace(/\0+$/, '');
    const vsize = b.readUInt32LE(o + 8);
    const va = b.readUInt32LE(o + 12);
    const rawSize = b.readUInt32LE(o + 16);
    const rawPtr = b.readUInt32LE(o + 20);
    sections.push({ name, va, vsize, rawSize, rawPtr });
  }
  if (!sections.length) return null;

  return { format: 'pe', bits: is64 ? 64 : 32, imageBase, sizeOfImage, sections };
}

function parseELF(b) {
  const is64 = b[4] === 2;
  const le = b[5] !== 2;      // 2 = big endian
  if (!le) return null;       // 本工具链遇到的 ELF 都是小端；大端直接放弃（宁可不判）
  if (b.length < (is64 ? 64 : 52)) return null;

  let phoff, phentsize, phnum;
  if (is64) {
    phoff = Number(b.readBigUInt64LE(0x20));
    phentsize = b.readUInt16LE(0x36);
    phnum = b.readUInt16LE(0x38);
  } else {
    phoff = b.readUInt32LE(0x1c);
    phentsize = b.readUInt16LE(0x2a);
    phnum = b.readUInt16LE(0x2c);
  }
  if (!phoff || !phentsize || !phnum) return null;

  const sections = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + phentsize > b.length) break;
    const type = is64 ? b.readUInt32LE(o) : b.readUInt32LE(o);
    if (type !== 1) continue;   // PT_LOAD
    const vaddr = is64 ? Number(b.readBigUInt64LE(o + 16)) : b.readUInt32LE(o + 8);
    const memsz = is64 ? Number(b.readBigUInt64LE(o + 40)) : b.readUInt32LE(o + 20);
    const off = is64 ? Number(b.readBigUInt64LE(o + 8)) : b.readUInt32LE(o + 4);
    sections.push({ name: 'LOAD', va: vaddr, vsize: memsz, rawSize: memsz, rawPtr: off });
  }
  if (!sections.length) return null;

  // ELF 没有单一 ImageBase：取最小 vaddr 作为基准，sizeOfImage 覆盖到最高段末尾。
  // va 在 sections 里保存的是"绝对虚拟地址"，因此比较时用 va 直接比，不再加基准。
  const minVa = Math.min(...sections.map((s) => s.va));
  const maxEnd = Math.max(...sections.map((s) => s.va + s.vsize));
  return {
    format: 'elf',
    bits: is64 ? 64 : 32,
    imageBase: minVa,
    sizeOfImage: maxEnd - minVa,
    sections,
    // ELF 的 section.va 已是绝对地址；PE 的是 RVA。用一个标记让落界判断走同一套代码。
    vaIsAbsolute: true,
  };
}

// 某个地址是否落在映像内。PE 的 section.va 是 RVA，需要加 ImageBase；
// ELF 的 p_vaddr 已是绝对地址。用 vaIsAbsolute 区分，调用方无需关心格式。
function isAddrInImage(map, addr) {
  if (!map || !Number.isFinite(addr) || addr <= 0) return false;
  const abs = (s) => (map.vaIsAbsolute ? s.va : map.imageBase + s.va);
  // 先看是否超出整个映像范围（这是最便宜的判据，也是串台最常见表现）
  const lo = map.vaIsAbsolute ? map.imageBase : map.imageBase;
  const hi = lo + map.sizeOfImage;
  if (addr < lo || addr >= hi) return false;
  // 再看是否真的落在某个节/段内（排除节间空洞）
  for (const s of map.sections) {
    const start = abs(s);
    const size = s.vsize || s.rawSize || 0;
    if (size > 0 && addr >= start && addr < start + size) return true;
  }
  return false;
}

// 函数列表落界：把不属于当前文件地址空间的条目剔除。
// funcs 支持 [{address|addr|start|ea, name, size}] 与裸地址数组两种形态。
function filterFunctionsInImage(funcs, map) {
  const kept = [];
  const dropped = [];
  if (!Array.isArray(funcs) || !map) return { kept: funcs || [], dropped, mapOk: false };

  for (const f of funcs) {
    let raw;
    if (typeof f === 'number') raw = f;
    else if (typeof f === 'string') raw = f;
    else if (f && typeof f === 'object') raw = f.address != null ? f.address : (f.addr != null ? f.addr : (f.start != null ? f.start : f.ea));
    const addr = parseAddr(raw);
    if (!Number.isFinite(addr) || addr <= 0) { dropped.push(f); continue; }
    if (isAddrInImage(map, addr)) kept.push(f); else dropped.push(f);
  }
  return { kept, dropped, mapOk: true };
}

function parseAddr(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const s = v.trim();
    const m = s.match(/^(?:0x)?([0-9a-fA-F]+)$/);
    if (!m) return NaN;
    return parseInt(m[1], 16);
  }
  return NaN;
}

// ---------- IDA 会话身份决策（纯函数，便于单测） ----------
// 输入都是"事实"，输出是"该做什么"：
//   {listening, identity: {success, input_path, idb_path, module}, targetPath}
// 输出 {action:'launch'|'reuse'|'reload', reason, log}
function normalizePathForCompare(p) {
  return String(p || '').trim().replace(/\\/g, '/').toLowerCase();
}

function decideIdaAction(input) {
  const i = input || {};
  if (!i.listening) {
    return { action: 'launch', reason: 'not-listening', log: '[IDA] 13337 未监听，启动新实例' };
  }
  const id = i.identity || {};
  if (!id.success) {
    // "不知道端口后面是谁"是最危险的状态：宁可重载一次，也不能拿别人的库当本题证据。
    return {
      action: 'reload', reason: 'unknown',
      log: '[IDA] 身份未知（server_health 不可用），按安全策略重载目标文件',
    };
  }
  const loaded = normalizePathForCompare(id.input_path || id.module || id.idb_path);
  const target = normalizePathForCompare(i.targetPath);
  if (!loaded || !target) {
    return {
      action: 'reload', reason: 'unknown',
      log: '[IDA] 身份信息不完整（缺少 input_path/module），按安全策略重载',
    };
  }
  if (loaded === target) {
    return {
      action: 'reuse', reason: 'same',
      log: '[IDA] 身份校验通过: ' + basenameOf(id.input_path || id.module),
    };
  }
  return {
    action: 'reload', reason: 'mismatch',
    log: '[IDA] 目标不一致：已加载 ' + basenameOf(loaded) + '，当前题需要 ' + basenameOf(target) + '，重载',
  };
}

function basenameOf(p) {
  const s = String(p || '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i >= 0 ? s.slice(i + 1) : s;
}

// 按 PID 结束实例：只结束"启动前后新增"的进程，绝不动启动前就在跑的。
function planPidClose(before, after) {
  const prev = new Set((before || []).map(Number).filter(Number.isFinite));
  const now = (after || []).map(Number).filter(Number.isFinite);
  return now.filter((p) => !prev.has(p));
}

module.exports = {
  parseImageMap,
  isAddrInImage,
  filterFunctionsInImage,
  parseAddr,
  decideIdaAction,
  planPidClose,
  normalizePathForCompare,
  basenameOf,
};
