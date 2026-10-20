// 端口探测冒烟测试（可选，默认 skip；不参与 CI 判定）。
//
// 真实链路验收需要环境就绪：IDA(13337) / Burp(9876) / Kali SSH(22)。
// 这些端口在本机通常不可用，所以本测试**只打印真实状态**，永不让 CI 变红。
//
// 运行：node tests/test_smoke_ports.js            → 打印状态后 exit 0
//      node tests/test_smoke_ports.js --strict   → 全部在线才 exit 0（人工验收用）
const net = require('net');

const TARGETS = [
  { name: 'IDA MCP', host: '127.0.0.1', port: 13337 },
  { name: 'Burp MCP', host: '127.0.0.1', port: 9876 },
  { name: 'Kali SSH', host: '192.168.230.129', port: 22 },
];

function probe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (listening) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (e) {}
      resolve(listening);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    try { socket.connect(port, host); } catch (e) { done(false); }
  });
}

(async () => {
  const strict = process.argv.includes('--strict');
  const results = [];
  for (const t of TARGETS) {
    const ok = await probe(t.host, t.port, 1500);
    results.push({ ...t, listening: ok });
    console.log(`${ok ? '✅' : '⏭'} ${t.name.padEnd(10)} ${t.host}:${t.port} ${ok ? '在线' : '不可达（跳过真实验收）'}`);
  }
  const allUp = results.every(r => r.listening);
  console.log(`\n${results.filter(r => r.listening).length}/${results.length} 个服务在线`);
  if (!strict) {
    console.log('（默认模式只打印状态，不参与 CI 判定）');
    process.exit(0);
  }
  process.exit(allUp ? 0 : 1);
})();
