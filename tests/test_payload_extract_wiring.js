// extract_payload 接线 + 编解码正确性回归
//
// 背景（真实缺陷）：electron/main.js 的 extract_payload 分支调用
// buildPayloadExtractPython，但该函数只存在于渲染层 src/js/app.js，
// 主进程既没定义也没 require → 运行时 ReferenceError，被 catch 吞成
// "工具调用失败: buildPayloadExtractPython is not defined"，工具 100% 不可用。
//
// 为什么 111 个测试没发现：
//   tests/payload_extract_loader.js 从 app.js 抽源码跑，从未执行主进程 dispatch。
//   而 node --check 只查语法，查不出"标识符未定义"这种运行时错误。
//
// 修法：抽成 electron/payload-extract.js 作为唯一实现，main.js require 它，
// 渲染层改走 IPC。本测试同时锁"接线"与"编解码正确性"两件事。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { buildPayloadExtractPython, PAYLOAD_ENCODINGS } = require(path.join(ROOT, 'electron', 'payload-extract.js'));
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');
const preSrc = fs.readFileSync(path.join(ROOT, 'electron', 'preload.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

console.log('[1] 接线：主进程必须能解析到 buildPayloadExtractPython');
{
  ok(/require\('\.\/payload-extract'\)/.test(mainSrc), 'main.js require 了 payload-extract 模块');
  ok(/const \{ buildPayloadExtractPython/.test(mainSrc), 'main.js 从模块解构出函数');
  ok(/const py = buildPayloadExtractPython\(spec\)/.test(mainSrc), 'dispatch 里调用的是已导入的绑定');
  // 关键：确认 main.js 内不再有"只调用、无来源"的情况
  const definedInMain = /function buildPayloadExtractPython/.test(mainSrc);
  const importedInMain = /require\('\.\/payload-extract'\)/.test(mainSrc);
  ok(definedInMain || importedInMain, '函数在 main.js 作用域内可解析（定义或导入至少一个）');
  ok(typeof buildPayloadExtractPython === 'function', '模块导出的确实是函数');
}

console.log('\n[2] 唯一实现：渲染层不再自带副本');
{
  ok(!/function buildPayloadExtractPython/.test(appSrc), 'app.js 已删除重复实现');
  ok(/electronAPI\.buildPayloadExtractPython/.test(appSrc), 'app.js 改走 IPC');
  ok(/buildPayloadExtractPython:\s*\(/.test(preSrc), 'preload 暴露了 IPC 方法');
  ok(/ipcMain\.handle\('build-payload-extract-python'/.test(mainSrc), 'main.js 注册了对应 handler');
}

console.log('\n[3] 8 种编码：生成的脚本能真解码回原文（字节级）');
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-pe-'));
  const plain = Buffer.from('MZ\x90\x00hello_payload_1234567890', 'latin1');

  // 编码必须严格是解码逻辑的逆（见 payload-extract.js 各分支）
  const enc = (kind, data) => {
    const b = Buffer.alloc(data.length);
    switch (kind) {
      case 'none': return Buffer.from(data);
      case 'xor': for (let i = 0; i < data.length; i++) b[i] = data[i] ^ 0x5a; return b;
      case 'add': for (let i = 0; i < data.length; i++) b[i] = (data[i] + 0x33) & 0xff; return b;
      case 'periodic-xor': { const k = [0x11, 0x22, 0x33]; for (let i = 0; i < data.length; i++) b[i] = data[i] ^ k[i % 3]; return b; }
      case 'rolling-xor': { let p = 0; for (let i = 0; i < data.length; i++) { b[i] = data[i] ^ p; p = data[i]; } return b; }
      case 'rolling-add': { let p = 0; for (let i = 0; i < data.length; i++) { b[i] = (data[i] + p) & 0xff; p = data[i]; } return b; }
      case 'base64': return Buffer.from(data.toString('base64'), 'latin1');
      case 'hex': return Buffer.from(data.toString('hex'), 'latin1');
      default: throw new Error('bad kind ' + kind);
    }
  };

  PAYLOAD_ENCODINGS.forEach((kind, idx) => {
    const srcPath = path.join(tmp, `in${idx}.bin`);
    const dstPath = path.join(tmp, `out${idx}.bin`);
    const pyPath = path.join(tmp, `gen${idx}.py`);   // ⚠️ 不可用标准库名（base64.py 会自导入）
    fs.writeFileSync(srcPath, enc(kind, plain));

    const spec = {
      offset: 0, length: plain.length,
      encode: { kind, key: kind === 'periodic-xor' ? [0x11, 0x22, 0x33] : (kind === 'add' ? 0x33 : 0x5a), stride: 1 },
    };
    const py = buildPayloadExtractPython(spec);
    if (!py) { ok(false, `${kind}: 生成脚本`); return; }
    fs.writeFileSync(pyPath, py, 'utf8');

    let err = '';
    try { execFileSync('python', [pyPath, srcPath, dstPath], { encoding: 'utf8', timeout: 30000 }); }
    catch (e) { err = String(e.stderr || e.message).slice(0, 120); }

    const got = (!err && fs.existsSync(dstPath)) ? fs.readFileSync(dstPath) : Buffer.alloc(0);
    ok(!err && got.equals(plain), `${kind}: 解码回原文`, err || ('got=' + JSON.stringify(got.toString('latin1').slice(0, 16))));
  });

  // 未知编码必须显式返回 null（调用方据此报"不支持的编码方式"）
  ok(buildPayloadExtractPython({ offset: 0, encode: { kind: 'rot13' } }) === null, '未知编码返回 null 而不是编造脚本');

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* 清理失败无影响 */ }
}

console.log('\n[4] 负向：断言能抓错（不是假保护）');
{
  // 把 add 的解码从"减"改成"加"，必须解出不同字节。
  // 这条锁定的是：如果将来有人把 - key 写成 + key，上面的正向断言会真的红。
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-pe-neg-'));
  const plain = Buffer.from('MZ\x90\x00negative_case', 'latin1');
  const encoded = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) encoded[i] = (plain[i] + 0x33) & 0xff;

  const srcPath = path.join(tmp, 'neg.bin');
  const dstPath = path.join(tmp, 'neg.out');
  const pyPath = path.join(tmp, 'neg.py');
  fs.writeFileSync(srcPath, encoded);

  const good = buildPayloadExtractPython({ offset: 0, length: plain.length, encode: { kind: 'add', key: 0x33, stride: 1 } });
  ok(/- key/.test(good), 'add 解码用的是减号（编码是 +key）');

  const bad = good.replace('(d[o+i*s] - key)', '(d[o+i*s] + key)');
  ok(bad !== good, '篡改成功（替换确实生效）');
  fs.writeFileSync(pyPath, bad, 'utf8');
  try { execFileSync('python', [pyPath, srcPath, dstPath], { encoding: 'utf8', timeout: 30000 }); } catch (e) { /* 不管 */ }
  const got = fs.existsSync(dstPath) ? fs.readFileSync(dstPath) : Buffer.alloc(0);
  ok(!got.equals(plain), '把减改成加之后解出的字节确实不同（断言能抓错）');

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* 同上 */ }
}

console.log('\n[5] 参数正确落进脚本（offset/length/stride 不是摆设）');
{
  const py = buildPayloadExtractPython({ offset: 0x1234, length: 256, encode: { kind: 'xor', key: 0x7f, stride: 4 } });
  ok(/^o = 4660$/m.test(py), 'offset 写成十进制 4660（0x1234）', py.split('\n')[3]);
  ok(/^n = 256$/m.test(py), 'length 写入');
  ok(/^s = 4$/m.test(py), 'stride 写入（dword 数组取低字节）');
  ok(/^key = 127$/m.test(py), 'key 写入');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
