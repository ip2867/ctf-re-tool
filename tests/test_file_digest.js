// 任意文件 → 可读摘要（file-digest）回归
//
// 用户要求：不要只读一个文件、也不要只支持 docx。
// 题目附件是混合的（驱动 + docx 题面 + 说明.md + 密文.txt + 图片 + IDA 产物），
// 正确做法是把"每个文件变成人能读的摘要"交给 AI 自己判断，
// 而不是工具替它挑一个——工具猜不准"哪个是题面"。
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const {
  digestFile, digestMany, detectMagic, shannonEntropy, extractStrings,
  extractPdfText, isToolArtifact,
} = require(path.join(__dirname, '..', 'electron', 'file-digest.js'));

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ctfdigest-'));
const w = (name, content) => {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, content);
  return p;
};

console.log('[1] 工具中间产物必须被排除（实测踩坑）');
{
  // 驱动逆向下，目录里其实是 7 个文件，其中 5 个是 IDA 生成的
  const artifacts = [
    'DancingKeys.sys.id0', 'DancingKeys.sys.id1', 'DancingKeys.sys.id2',
    'DancingKeys.sys.nam', 'DancingKeys.sys.til',
  ];
  for (const a of artifacts) {
    ok(isToolArtifact(a), `排除 ${a}`);
  }
  ok(isToolArtifact('chall.i64'), '排除 .i64');
  ok(isToolArtifact('chall.idb'), '排除 .idb');
  ok(isToolArtifact('~$题面.docx'), '排除 Office 锁文件 ~$');
  ok(isToolArtifact('a.o'), '排除 .o');
  ok(!isToolArtifact('DancingKeys.sys'), '不排除 .sys（这是题目本体）');
  ok(!isToolArtifact('题面.docx'), '不排除正常 docx');
  ok(!isToolArtifact('readme.md'), '不排除 md');
}

console.log('\n[2] 多种文本/代码类型都能读');
{
  const cases = [
    ['note.txt', '题目要求：解出 16 字节密文'],
    ['说明.md', '# 说明\nflag 格式 bytectf{...}'],
    ['data.json', '{"cipher":"25405a86"}'],
    ['chall.py', 'def check(s): return len(s)==16'],
    ['a.c', 'int main(){return 0;}'],
    ['x.enc', '254 40 5a 86'],
    ['k.pem', '-----BEGIN PUBLIC KEY-----'],
  ];
  let allOk = true;
  const bad = [];
  for (const [name, content] of cases) {
    const p = w(name, content);
    const r = digestFile(p);
    if (!r.ok || r.kind !== 'text' || !r.text.includes(content.slice(0, 10))) {
      allOk = false; bad.push(name + ':' + (r.kind || r.error));
    }
  }
  ok(allOk, `${cases.length} 种文本类型都能读并返回内容`, bad.join(', '));
}

console.log('\n[3] 文本过长会截断但保留头尾');
{
  const big = 'A'.repeat(30000) + 'MIDDLE' + 'B'.repeat(30000);
  const p = w('big.txt', big);
  const r = digestFile(p, { maxText: 2000 });
  ok(r.ok && r.truncated, '标记为已截断');
  ok(r.text.length < 5000, '输出确实变短', String(r.text.length));
  ok(r.text.startsWith('AAAA'), '保留开头');
  ok(r.text.endsWith('BBBB'), '保留结尾');
}

console.log('\n[4] 二进制：魔数 + 熵 + strings');
{
  const pe = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(200, 0)]);
  fs.writeFileSync(path.join(TMP, 'x.exe'), pe);
  const r = digestFile(path.join(TMP, 'x.exe'));
  ok(r.ok && r.kind === 'binary', 'kind=binary');
  ok(/PE/.test(r.magic), '识别为 PE', r.magic);
  ok(typeof r.entropy === 'number' && r.entropy < 2, '低熵（全零）', String(r.entropy));

  ok(detectMagic(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2, 3, 4])) === 'ELF', 'ELF 识别');
  ok(/ZIP/.test(detectMagic(Buffer.from([0x50, 0x4b, 0x03, 0x04]))), 'ZIP 识别');

  // 随机数据熵应接近 8
  const rnd = Buffer.alloc(4096);
  for (let i = 0; i < rnd.length; i++) rnd[i] = Math.floor(Math.random() * 256);
  ok(shannonEntropy(rnd) > 7, '随机数据高熵', String(shannonEntropy(rnd)));

  const withStr = Buffer.concat([Buffer.alloc(16, 0), Buffer.from('bytectf{test_ok}'), Buffer.alloc(16, 0)]);
  ok(extractStrings(withStr).some(s => s.includes('bytectf')), 'strings 能抽出可见串');
}

console.log('\n[5] 图片：给尺寸而不是丢二进制');
{
  // 最小 PNG 头：签名 + IHDR（宽高在 16/20 偏移）
  const png = Buffer.alloc(33);
  png.writeUInt32BE(0x89504e47, 0);
  png.writeUInt32BE(0x0d0a1a0a, 4);
  png.writeUInt32BE(13, 8);
  png.write('IHDR', 12, 'latin1');
  png.writeUInt32BE(640, 16);
  png.writeUInt32BE(480, 20);
  fs.writeFileSync(path.join(TMP, 'shot.png'), png);
  const r = digestFile(path.join(TMP, 'shot.png'));
  ok(r.ok && r.kind === 'image', 'kind=image');
  ok(r.width === 640 && r.height === 480, '读出尺寸 640x480', `${r.width}x${r.height}`);
  ok(/OCR|看图/.test(r.note || ''), '给出"怎么读图"的指引');
}

console.log('\n[6] PDF：解 FlateDecode 流抽文本');
{
  const content = 'BT /F1 12 Tf (What is this?) Tj ET';
  const compressed = zlib.deflateSync(Buffer.from(content, 'latin1'));
  const pdf = Buffer.concat([
    Buffer.from('%PDF-1.4\n', 'latin1'),
    Buffer.from('1 0 obj\n<< /Length ' + compressed.length + ' >>\nstream\n', 'latin1'),
    compressed,
    Buffer.from('\nendstream\nendobj\n', 'latin1'),
  ]);
  const r = extractPdfText(pdf);
  ok(/What is this/.test(r.text), '抽出 PDF 文本', JSON.stringify(r.text.slice(0, 80)));
}

console.log('\n[7] 归档：列条目而不是读二进制');
{
  // 造一个最小 zip（store 方式，一个文件）
  const name = 'inner.txt';
  const data = Buffer.from('hello');
  const crc = 0; // 简化：解析器不校验 crc
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  const localFull = Buffer.concat([local, Buffer.from(name, 'latin1'), data]);

  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(20, 4);
  cd.writeUInt16LE(20, 6);
  cd.writeUInt16LE(0, 8);
  cd.writeUInt16LE(0, 10);
  cd.writeUInt16LE(0, 12);
  cd.writeUInt16LE(0, 14);
  cd.writeUInt32LE(crc, 16);
  cd.writeUInt32LE(data.length, 20);
  cd.writeUInt32LE(data.length, 24);
  cd.writeUInt16LE(name.length, 28);
  cd.writeUInt32LE(0, 42);
  const cdFull = Buffer.concat([cd, Buffer.from(name, 'latin1')]);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdFull.length, 12);
  eocd.writeUInt32LE(localFull.length, 16);

  const zipPath = path.join(TMP, 'pack.zip');
  fs.writeFileSync(zipPath, Buffer.concat([localFull, cdFull, eocd]));
  const r = digestFile(zipPath);
  ok(r.ok && r.kind === 'archive', 'kind=archive', r.kind + '/' + r.error);
  ok((r.entries || []).includes('inner.txt'), '列出条目 inner.txt', JSON.stringify(r.entries));
}

console.log('\n[8] digestMany：批量 + 跳过产物 + 单个失败不连累');
{
  const files = [
    w('t1.txt', 'hello'),
    path.join(TMP, 'x.exe'),                       // 已存在
    path.join(TMP, 'nope_missing.file'),           // 不存在
    path.join(TMP, 'chall.id0'),                   // 产物，应被跳过
  ];
  fs.writeFileSync(path.join(TMP, 'chall.id0'), 'x');
  const r = digestMany(files);
  ok(r.items.length === 3, '3 个参与（产物被排除）', String(r.items.length));
  ok(r.skipped.length === 1, '1 个被跳过', String(r.skipped.length));
  ok(/中间产物/.test(r.skipped[0].why), '跳过原因说明清楚', r.skipped[0].why);
  ok(r.failed === 1, '缺失文件记为失败但不抛出', String(r.failed));
  ok(r.ok >= 2, '其它文件正常', String(r.ok));
}

console.log('\n[9] 接线：AI 能自己调这两个工具');
{
  const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
  ok(/name: "file_digest"/.test(mainSrc), 'file_digest 工具已定义');
  ok(/name: "list_dir"/.test(mainSrc), 'list_dir 工具已定义');
  ok(/case 'file_digest'/.test(mainSrc), 'file_digest 有 dispatch');
  ok(/case 'list_dir'/.test(mainSrc), 'list_dir 有 dispatch');
  ok(/'file_digest', 'list_dir'/.test(mainSrc), '进 KNOWN 集合');
  ok(/case 'file_digest': return '批量读文件/.test(mainSrc), 'toolLabel 有 file_digest');
  ok(/if \(name === 'file_digest'\)/.test(mainSrc), 'precheck 有 file_digest');
  ok(/require\('\.\/file-digest'\)/.test(mainSrc), '惰性 require file-digest');
  // 工具描述必须讲清"交给 AI 判断"，而不是"工具替你挑"
  ok(/不替你做选择|交给 AI|看内容一眼/.test(mainSrc), '描述里说明判断权交给 AI');
  // read_file 对 Office 也要能提取（不能只靠 file_digest）
  ok(/extractOfficeText/.test(mainSrc), 'read_file 也接入了 Office 提取');
}

console.log('\n[10] 边界');
{
  ok(!digestFile(path.join(TMP, 'definitely_missing_xyz')).ok, '不存在的文件返回 ok=false');
  ok(digestMany([]).items.length === 0, '空数组不崩');
  const d = digestFile(TMP);
  ok(d.kind === 'directory', '目录返回 kind=directory', d.kind);
}

try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (e) { }

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
