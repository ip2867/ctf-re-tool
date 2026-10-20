'use strict';
// 文件能力分诊（纯函数）。
//
// 旧分派按扩展名/用户口令走：UNKNOWN 一律送 Kali 固件流程（app.js 的 case 'BIN'/UNKNOWN），
// 而 detect-file-type 永远不会产出 BIN；pcap 样本按扩展名落进 UNKNOWN → 白等 3 次 SSH 超时。
// 路由依据应该是**能力**（容器/文件系统/流量/文本/可执行），不是扩展名。
//
// 输出 capabilities 供提示词与路由共用；decideRoute 只做一次决策。

const FS_MAGICS = [
  // [name, test(buf)]
  ['squashfs', (b) => b.length >= 4 && (b.toString('latin1', 0, 4) === 'hsqs' || b.toString('latin1', 0, 4) === 'sqsh')],
  ['cramfs', (b) => b.length >= 4 && b.readUInt32LE(0) === 0x28cd3d45],
  ['ubifs', (b) => b.length >= 4 && b.toString('latin1', 0, 4) === 'UBI#'],
  ['jffs2', (b) => b.length >= 2 && b.readUInt16BE(0) === 0x1985],
  ['ext', (b) => b.length >= 1082 && b.readUInt16LE(1080) === 0xEF53],
];

function looksTextual(b, ext) {
  if (/^\.(js|mjs|html?|xml|json|txt|enc|log|md|csv|py|sh)$/i.test(ext || '')) return true;
  const n = Math.min(b.length, 4096);
  if (!n) return false;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c < 0x7f)) printable++;
  }
  return printable / n > 0.9;
}

function detectCapabilities(buf, ext) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  const e = String(ext || '').toLowerCase();
  const head = b.length >= 4 ? b.toString('hex', 0, 4).toUpperCase() : '';

  // gzip 的魔数是 2 字节 (1F 8B)，这里 head 是 4 字节 hex，用 startsWith 而不是全等——
  // 旧写法 `head === '1F8B'` 永远为 false（长度不同），导致真实 gzip 头被当成 local-probe。
  const archive = head.startsWith('504B0304')                            // PK..
    || head.startsWith('52617221')                                       // RAR
    || head.startsWith('377ABCAF')                                       // 7z
    || head.startsWith('1F8B')                                           // gzip
    || /^\.(zip|apk|jar|xlsx|xlsm|docx|pptx|rar|7z|gz|tar)$/i.test(e);

  const fsType = (() => {
    for (const [name, test] of FS_MAGICS) {
      try { if (test(b)) return name; } catch (err) { /* 短文件 */ }
    }
    return '';
  })();

  // 流量：pcap/pcapng 魔数（LE/BE/纳秒四种 + pcapng）
  const pcapMagic = ['D4C3B2A1', 'A1B2C3D4', '4D3CB2A1', 'A1B23C4D'].includes(head);
  const pcapng = head === '0A0D0D0A';
  const pcap = pcapMagic || pcapng || /^\.(pcap|pcapng|cap)$/i.test(e);

  const textual = looksTextual(b, e);

  // httpHint：文本里出现 HTTP 请求/响应起始行，或 pcap 的原始字节里能看到
  // "GET/POST/HTTP/1." 的 ASCII 片段（不解析流，只做"是否值得进 Burp"的信号）。
  let httpHint = false;
  if (textual || pcap) {
    const sample = b.length > 262144 ? b.slice(0, 262144) : b;
    const s = sample.toString('latin1');
    // 抓包里 HTTP 起始行前面是二进制帧头（不是换行），因此不能只认行首；
    // 用"方法 + 空格 + / 开头路径 + HTTP/1.x"这个足够长的特征，避免误报。
    httpHint = /(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\/\S{0,200}\s+HTTP\/1\.[01]/.test(s)
      || /HTTP\/1\.[01]\s+\d{3}/.test(s);
  }
  if (/^\.(js|mjs|html?)$/i.test(e)) httpHint = true;

  // 可执行：只认魔数/明确扩展名；.bin 不算（"随机 .bin"必须走 local-probe，而不是静态反编译）
  const executable = head.startsWith('4D5A') || head === '7F454C46'
    || /^\.(exe|dll|so|elf)$/i.test(e);

  const firmware = archive || !!fsType || /^\.(bin|img|fw|rom)$/i.test(e);

  return { archive, fs: fsType, pcap, pcapng, httpHint, textual, executable, firmware };
}

// route: traffic | zip | extract | local-probe | web | burp | static
// 规则（能力优先，扩展名只作补充）：
//   pcap 且含 HTTP → burp；pcap 纯二进制 → traffic
//   JS/HTML → web（本地文件；有 Burp 则 burp）
//   archive/fs → extract
//   unknown 且无 fs 能力 → local-probe
//   可执行 → static
function decideRoute(input) {
  const i = input || {};
  const cap = i.capabilities || {};
  const fileType = String(i.fileType || '').toUpperCase();
  const ext = String(i.ext || '').toLowerCase();

  if (cap.pcap) return cap.httpHint ? 'burp' : 'traffic';
  if (fileType === 'JS' || fileType === 'HTML' || /^\.(js|mjs|html?)$/i.test(ext)) return 'web';
  if (cap.archive || cap.fs) return 'extract';
  if (fileType === 'PE' || fileType === 'ELF' || cap.executable) return 'static';
  if (!fsTypeCapability(cap)) return 'local-probe';
  return 'static';
}

function fsTypeCapability(cap) {
  return !!(cap && (cap.archive || cap.fs || cap.pcap));
}

module.exports = { detectCapabilities, decideRoute, FS_MAGICS };
