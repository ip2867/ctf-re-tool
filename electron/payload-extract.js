// 载荷提取脚本生成器（主进程与渲染层共用）
//
// 为什么单独成模块：这个函数原先只写在渲染层 src/js/app.js，
// 而 electron/main.js 的 extract_payload 分支直接调用它 →
// 主进程根本看不到这个标识符，运行时抛 ReferenceError，
// 被 executeToolCall 的 catch 吞成 "工具调用失败: buildPayloadExtractPython is not defined"。
// 也就是说 extract_payload 工具 100% 不可用，而 111 个测试全绿
// （测试只从 app.js 抽源码跑，从没执行过主进程 dispatch）。
//
// 现在只有这一份实现：main.js require 它，渲染层经 IPC 取同一份。
// 任何编码逻辑的修改都只改这里，避免两份漂移。

/**
 * 生成"按指定编码从二进制里提取载荷"的 Python 脚本。
 *
 * @param {{offset:number, length?:number, encode?:{kind:string,key?:number|number[],stride?:number}}} p
 *   p.offset  起始文件偏移
 *   p.length  提取长度（0/缺省 = 从 offset 到文件尾）
 *   p.encode  { kind, key, stride }
 *             kind: none | xor | add | periodic-xor | rolling-xor | rolling-add | base64 | hex
 *             key : xor/add 为单字节；periodic-xor 字节数组
 *             stride: 按元素步长取低字节（dword 数组取低字节用 4）
 * @returns {string|null} Python 源码；未知编码返回 null（调用方据此报"不支持的编码方式"）
 */
function buildPayloadExtractPython(p) {
  const e = (p && p.encode) || {};
  const off = p && p.offset != null ? p.offset : 0;
  const n = p && p.length != null ? p.length : 0;
  const lines = [
    'import sys, re, base64',
    'src, dst = sys.argv[1], sys.argv[2]',
    'd = open(src, "rb").read()',
    `o = ${off}`,
  ];
  if (n) lines.push(`n = ${n}`);
  else lines.push('n = len(d) - o');

  switch (e.kind) {
    case 'none':
      lines.push('blob = d[o:o+n]');
      break;
    case 'xor':
      lines.push(`s = ${e.stride || 1}`, `key = ${e.key}`);
      lines.push('blob = bytes(d[o+i*s] ^ key for i in range(n))');
      break;
    case 'add':
      lines.push(`s = ${e.stride || 1}`, `key = ${e.key}`);
      // 编码是 out = in + key，解码必须 **减** key（此前误写成加，解出乱码）
      lines.push('blob = bytes((d[o+i*s] - key) & 0xff for i in range(n))');
      break;
    case 'periodic-xor':
      lines.push(`keys = [${(e.key || []).join(', ')}]`);
      lines.push('blob = bytes(d[o+i] ^ keys[i % len(keys)] for i in range(n))');
      break;
    case 'rolling-xor':
      lines.push('blob = bytearray(); prev = 0');
      lines.push('for i in range(n):');
      lines.push('    prev = d[o+i] ^ prev');
      lines.push('    blob.append(prev)');
      lines.push('blob = bytes(blob)');
      break;
    case 'rolling-add':
      lines.push('blob = bytearray(); prev = 0');
      lines.push('for i in range(n):');
      lines.push('    prev = (d[o+i] - prev) & 0xff');
      lines.push('    blob.append(prev)');
      lines.push('blob = bytes(blob)');
      break;
    case 'base64':
      lines.push('s = re.sub(rb"[^A-Za-z0-9+/=]", b"", d[o:])');
      lines.push('s += b"=" * (-len(s) % 4)');
      lines.push('blob = base64.b64decode(s)[:n]');
      break;
    case 'hex':
      lines.push('s = re.sub(r"[^0-9a-fA-F]", "", d[o:].decode("latin-1"))');
      lines.push('blob = bytes.fromhex(s[:n*2])');
      break;
    default:
      return null;   // 未知编码：不自动提取
  }

  lines.push('open(dst, "wb").write(blob)');
  lines.push('print("OK", len(blob), blob[:4].hex())');
  return lines.join('\n');
}

// 支持的编码种类（供 schema 描述 / 错误提示复用，避免文案与实现漂移）
const PAYLOAD_ENCODINGS = [
  'none', 'xor', 'add', 'periodic-xor', 'rolling-xor', 'rolling-add', 'base64', 'hex',
];

module.exports = { buildPayloadExtractPython, PAYLOAD_ENCODINGS };
