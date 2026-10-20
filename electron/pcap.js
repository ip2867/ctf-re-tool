'use strict';
// PCAP/PCAPNG 解析（只用 Node 标准库）。
//
// 本机没有 scapy/dpkt/tshark/tcpdump/binwalk，所以流量题此前只能靠人工。
// 这里只做"够用"的解析：全局头 → 每包 → 4 元组顺序重组 TCP → 每流统计 + hex 预览。
// 不承诺 HTTP 提取：样本（plutochat）是二进制协议，http=0。只有真的看到
// HTTP 起始行才标记 http，避免把二进制流量当 Web 题送进 Burp。

const ETH_P_IPV4 = 0x0800;

function detectMagic(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0x0a && buf[1] === 0x0d && buf[2] === 0x0d && buf[3] === 0x0a) {
    return { kind: 'pcapng', magic: '0A0D0D0A' };
  }
  const hex = buf.toString('hex', 0, 4).toUpperCase();
  const map = {
    D4C3B2A1: { kind: 'pcap', endian: 'le', nano: false },
    A1B2C3D4: { kind: 'pcap', endian: 'be', nano: false, magic: 'A1B2C3D4' },
    '4D3CB2A1': { kind: 'pcap', endian: 'le', nano: true, magic: '4D3CB2A1' },
    A1B23C4D: { kind: 'pcap', endian: 'be', nano: true, magic: 'A1B23C4D' },
  };
  if (map[hex]) return Object.assign({ magic: hex }, map[hex]);
  return null;
}

function entropy(buf) {
  if (!buf || !buf.length) return 0;
  const cnt = new Array(256).fill(0);
  for (const b of buf) cnt[b]++;
  let h = 0;
  for (const c of cnt) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// 解析 TCP 段（只处理 IPv4、无 IP 选项、无分片）
function parseTcpPacket(data) {
  if (data.length < 14 + 20) return null;
  const ethType = data.readUInt16BE(12);
  if (ethType !== ETH_P_IPV4) return null;
  const ip = data.slice(14);
  const ihl = (ip[0] & 0x0f) * 4;
  if (ihl < 20 || ip.length < ihl) return null;
  if (ip[9] !== 6) return null;                        // 非 TCP
  const frag = ip.readUInt16BE(6);
  if ((frag & 0x1fff) !== 0) return null;              // 分片不重组
  const srcIp = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
  const dstIp = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const tcp = ip.slice(ihl);
  if (tcp.length < 20) return null;
  const sport = tcp.readUInt16BE(0);
  const dport = tcp.readUInt16BE(2);
  const dataOff = (tcp[12] >> 4) * 4;
  if (dataOff < 20 || tcp.length < dataOff) return null;
  const payload = tcp.slice(dataOff);
  return { srcIp, dstIp, sport, dport, payload };
}

function flowKey(a, b) {
  // 顺序无关的 4 元组：端口小的在前；端口相同用 IP 比较
  const one = `${a.ip}:${a.port}`;
  const two = `${b.ip}:${b.port}`;
  return one <= two ? `${one}|${two}` : `${two}|${one}`;
}

function toHexPreview(buf, maxBytes) {
  const n = Math.min(buf.length, maxBytes || 2048);
  return buf.slice(0, n).toString('hex').replace(/(..)/g, '$1 ').trim();
}

function looksHttp(buf) {
  const s = buf.toString('latin1');
  return /^(GET|POST|PUT|DELETE|HEAD|OPTIONS) \/[^\n]{0,200}HTTP\/1\.[01]/.test(s)
    || /^HTTP\/1\.[01] \d{3}/.test(s);
}

// 主入口。opts.previewBytes 默认 2048（输出限额）。
function analyzePcap(filePath, opts) {
  const o = opts || {};
  const fs = require('fs');
  const buf = fs.readFileSync(filePath);
  const m = detectMagic(buf);
  if (!m) return { success: false, error: '不是 pcap/pcapng 文件（魔数不匹配）' };

  const out = {
    success: true,
    magic: String(m.magic || '').toUpperCase(),
    pcapng: m.kind === 'pcapng',
    packets: 0,
    flows: [],
    http: 0,
  };
  if (m.kind === 'pcapng') {
    // pcapng 只做块计数：块类型 + 总长度（不解析接口/时间戳细节）
    let off = 0;
    while (off + 12 <= buf.length) {
      const type = buf.readUInt32LE(off);
      const len = buf.readUInt32LE(off + 4);
      if (len < 12 || off + len > buf.length) break;
      if (type === 6) out.packets++;            // Enhanced Packet Block
      off += len;
    }
    return out;
  }

  const le = m.endian === 'le';
  const u32 = (off) => (le ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  if (buf.length < 24) return { success: false, error: 'pcap 全局头不完整' };
  const linkType = u32(20);
  // 只支持 Ethernet（LINKTYPE_ETHERNET=1）；其它链路类型不猜
  const linkHdr = linkType === 1 ? 14 : 0;

  const flows = new Map();
  let off = 24;
  while (off + 16 <= buf.length) {
    const incl = u32(off + 8);
    off += 16;
    if (incl <= 0 || off + incl > buf.length) break;
    const data = buf.slice(off + 0, off + incl);
    off += incl;
    out.packets++;
    if (!linkHdr) continue;
    let tcp;
    try { tcp = parseTcpPacket(data); } catch (e) { tcp = null; }
    if (!tcp) continue;
    const key = flowKey({ ip: tcp.srcIp, port: tcp.sport }, { ip: tcp.dstIp, port: tcp.dport });
    let f = flows.get(key);
    if (!f) {
      f = {
        src: `${tcp.srcIp}:${tcp.sport}`,
        dst: `${tcp.dstIp}:${tcp.dport}`,
        ports: [...new Set([tcp.sport, tcp.dport])].sort((a, b) => a - b),
        packets: 0,
        bytes: 0,
        data: [],
      };
      flows.set(key, f);
    }
    f.packets++;
    f.bytes += tcp.payload.length;
    if (tcp.payload.length) f.data.push(tcp.payload);
  }

  const previewBytes = Number(o.previewBytes) || 2048;
  for (const f of flows.values()) {
    const all = Buffer.concat(f.data);
    const maxHttp = looksHttp(all);
    if (maxHttp) out.http++;
    out.flows.push({
      src: f.src,
      dst: f.dst,
      ports: f.ports,
      packets: f.packets,
      bytes: f.bytes,
      payloadBytes: all.length,
      http: maxHttp,
      entropy: Number(entropy(all).toFixed(2)),
      previewHex: toHexPreview(all, previewBytes),
      previewTruncated: all.length > previewBytes,
    });
  }
  return out;
}

module.exports = {
  analyzePcap, detectMagic, parseTcpPacket, entropy, toHexPreview, looksHttp,
};
