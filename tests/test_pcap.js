// pcap 解析单测：标准库实现，样本是仓库内已提交的 22 帧 / 2 条 TCP 流。
const fs = require('fs');
const os = require('os');
const path = require('path');
const pcap = require('../electron/pcap.js');
const { detectCapabilities } = require('../electron/file-capability.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preloadSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

const sample = path.join(__dirname, 'regression', 'plutochat-elf64-pcap', 'evidence.pcap');

console.log('[1] 样本：magic / packets / flows / 端口 / 载荷 / http');
{
  if (!fs.existsSync(sample)) {
    console.log('  SKIP 样本缺失');
  } else {
    const r = pcap.analyzePcap(sample);
    ok(r.success === true, '解析成功');
    ok(r.magic === 'D4C3B2A1', `magic=D4C3B2A1（${r.magic}）`);
    ok(r.packets === 22, `packets=22（${r.packets}）`);
    ok(r.flows.length === 2, `flows.length=2（${r.flows.length}）`);
    ok(r.flows.every(f => f.ports.includes(31337)), '端口含 31337');
    const bytes = r.flows.map(f => f.payloadBytes).sort((a, b) => a - b);
    ok(JSON.stringify(bytes) === '[216,220]', `载荷字节 [216,220]（${JSON.stringify(bytes)}）`);
    ok(r.http === 0, `http=0（${r.http}）`);
  }
}

console.log('\n[2] pcapng 头识别');
{
  const buf = Buffer.alloc(64);
  buf.writeUInt32LE(0x0a0d0d0a, 0);
  const m = pcap.detectMagic(buf);
  ok(m && m.kind === 'pcapng', `pcapng 识别（${JSON.stringify(m)}）`);
  const tmp = path.join(os.tmpdir(), `pcapng_${Date.now()}.pcapng`);
  // 一个 SHB + 一个 EPB（块长度 32），packets 应为 1
  const out = Buffer.alloc(28 + 32);
  out.writeUInt32LE(0x0a0d0d0a, 0); out.writeUInt32LE(28, 4); out.writeUInt32LE(28, 24);
  out.writeUInt32LE(6, 28); out.writeUInt32LE(32, 32); out.writeUInt32LE(32, 28 + 28);
  fs.writeFileSync(tmp, out);
  const r = pcap.analyzePcap(tmp);
  ok(r.pcapng === true, 'pcapng=true');
  ok(r.packets === 1, `EPB 计数 1（${r.packets}）`);
  try { fs.unlinkSync(tmp); } catch (e) {}
}

console.log('\n[3] previewHex 截断到 2048B');
{
  // 构造超过 2048B 的单流 pcap。IP 总长是 16 位，单包上限 65535，
  // 因此用多个 16000 字节载荷的包累加到同一条流（4 元组相同）。
  const payloadLen = 16000;
  const frameLen = 14 + 20 + 20 + payloadLen;
  const nPkts = 20;                                    // 320KB 总载荷
  const buf = Buffer.alloc(24 + (16 + frameLen) * nPkts);
  buf.writeUInt32LE(0xa1b2c3d4, 0);    // 小端读回 d4c3b2a1
  buf.writeUInt16LE(2, 4); buf.writeUInt16LE(4, 6);
  buf.writeUInt32LE(0, 8); buf.writeUInt32LE(0, 12);
  buf.writeUInt32LE(65535, 16);
  buf.writeUInt32LE(1, 20);            // Ethernet
  for (let p = 0; p < nPkts; p++) {
    const base = 24 + p * (16 + frameLen);
    buf.writeUInt32LE(0, base); buf.writeUInt32LE(0, base + 4);
    buf.writeUInt32LE(frameLen, base + 8); buf.writeUInt32LE(frameLen, base + 12);
    const f = base + 16;
    buf.writeUInt16BE(0x0800, f + 12);
    buf[f + 14] = 0x45;
    buf.writeUInt16BE(20 + 20 + payloadLen, f + 16);
    buf[f + 14 + 9] = 6;
    buf[f + 14 + 12] = 10; buf[f + 14 + 15] = 1;
    buf[f + 14 + 16] = 10; buf[f + 14 + 19] = 2;
    const t = f + 14 + 20;
    buf.writeUInt16BE(12345, t); buf.writeUInt16BE(80, t + 2);
    buf[t + 12] = 0x50;
    for (let i = 0; i < payloadLen; i++) buf[t + 20 + i] = (i + p) & 0xff;
  }
  const tmp = path.join(os.tmpdir(), `pcap_big_${Date.now()}.pcap`);
  fs.writeFileSync(tmp, buf);
  const r = pcap.analyzePcap(tmp, { previewBytes: 2048 });
  ok(r.success && r.flows.length === 1, `单流（${r.success}, ${r.flows && r.flows.length}）`);
  const fl = r.flows[0];
  const hexBytes = fl.previewHex.split(' ').filter(Boolean).length;
  ok(hexBytes === 2048, `previewHex 截断到 2048 字节（${hexBytes}）`);
  ok(fl.previewTruncated === true, '标记 truncated');
  ok(fl.payloadBytes === payloadLen * nPkts, `总载荷 ${payloadLen * nPkts}（${fl.payloadBytes}）`);
  try { fs.unlinkSync(tmp); } catch (e) {}
}

console.log('\n[4] detect-file-type / detectCapabilities 对样本返回 PCAP');
{
  ok(/\['D4C3B2A1', 'A1B2C3D4', '4D3CB2A1', 'A1B23C4D', '0A0D0D0A'\]/.test(mainSrc), 'detect-file-type 含 pcap 魔数表');
  ok(/fileType = 'PCAP'/.test(mainSrc), "返回 fileType='PCAP'");
  ok(/capabilities: \{ pcap: true/.test(mainSrc), '返回 capabilities.pcap=true');
  if (fs.existsSync(sample)) {
    const cap = detectCapabilities(fs.readFileSync(sample).slice(0, 4096), '.pcap');
    ok(cap.pcap === true, 'detectCapabilities pcap=true');
  }
}

console.log('\n[5] preload / 工具接线');
{
  ok(/trafficExtract: \(args\) => ipcRenderer\.invoke\('traffic-extract', args\)/.test(preloadSrc), 'preload 暴露 trafficExtract');
  ok(/ipcMain\.handle\('traffic-extract'/.test(mainSrc), '主进程有 traffic-extract');
  ok(/name: "traffic_extract"/.test(mainSrc), 'schema 含 traffic_extract');
  ok(/case 'traffic_extract':/.test(mainSrc), "dispatch 含 case 'traffic_extract'");
  ok(/function trafficExtract\(filePath, opts\)/.test(mainSrc), 'trafficExtract 实现存在');
  ok(/MAX_RET = 24000/.test(mainSrc), '总返回上限 24000 字符');
  ok(/traffic_\$\{Date\.now\(\)\}\.json/.test(mainSrc), '超限落盘路径');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
