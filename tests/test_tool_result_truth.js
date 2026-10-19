// 工具结果可信性测试：失败判定、MCP 返回形态、可注入 case 体。
// 这些缺陷的共同点是"工具成功返回了一句错误文本"，主循环把它当正常结果喂给模型，
// 于是模型认为工具可用、反复重试，或把报错正文当成分析结论。
const fs = require('fs'), os = require('os'), p = require('path');
const {
  toolFailureReason, parseBytesReply, parsePyExecReply, idaGetBytes,
  toToolResult, scanCryptoCase, ToolCallError, bytesFromData, buildGetBytesAttempts,
} = require('../electron/tool-result.js');
const scanner = require('./scanner_loader.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };

(async () => {
  console.log('T1) toolFailureReason 只认真实失败证据');
  {
    ok(toolFailureReason([{ error: 'missing param' }]) === 'missing param', '错误数组非空 → 返回错误文本');
    ok(toolFailureReason([{ addr: '0x1000', data: '0x55 0x8b' }]) === null, '含 data 的数组 → null');
    ok(toolFailureReason([]) === null, '空数组 → null');
    ok(toolFailureReason('工具调用失败: boom') === '工具调用失败: boom', '字符串失败前缀 → 失败');
    ok(toolFailureReason({ success: false, error: 'no such file' }) === 'no such file', 'success=false → 失败');
    ok(toolFailureReason({ result: '', stdout: '', stderr: 'File not found' }, { pythonExec: true }) === 'File not found',
      'pythonExec 语境下 stderr 非空且无 stdout/result → 失败');
    ok(toolFailureReason({ result: '', stdout: '', stderr: '' }, { pythonExec: true }) === null,
      'stderr 为空 → 不误判');
  }

  console.log('\nT2) parseBytesReply 以数组为主形态、按序拼接多 region');
  {
    const out = parseBytesReply([
      { addr: '0x1000', data: '0x55 0x8b ec' },
      { addr: '0x1003', data: '0x83 0xec 0x10' },
    ]);
    ok(!!out && out.includes('0000  55 8b ec'), `两段返回含首段字节：${out ? out.split('\n')[0] : 'null'}`);
    ok(!!out && out.includes('83 ec 10'), '第二段按序拼接在同一行');
    ok(parseBytesReply([{ addr: '0x1000', data: null }]) === null, 'data 为 null → null');
    ok(parseBytesReply([]) === null, '空数组 → null');
  }

  console.log('\nT3) parsePyExecReply 读 stdout 再 result');
  {
    const b1 = parsePyExecReply({ stdout: 'BYTES 558bec' });
    ok(!!b1 && b1.length === 3 && b1.toString('hex') === '558bec', 'stdout 的 BYTES → 3 字节');
    const b2 = parsePyExecReply({ result: 'noise\nBYTES 4142\n', stdout: '' });
    ok(!!b2 && b2.toString('hex') === '4142', 'stdout 无标记时回退 result');
    ok(parsePyExecReply({ stdout: '', stderr: 'File not found' }) === null, 'stderr 非空且无 BYTES → null');
  }

  console.log('\nT4) idaGetBytes 注入伪 callMcp：形态试探与终兜底');
  {
    const run = (accept) => idaGetBytes({
      callMcp: async (name, args) => accept(name, args),
      writeTemp: (name) => {
        const f = p.join(os.tmpdir(), name);
        fs.writeFileSync(f, 'print(1)');
        return f;
      },
      topLevelDir: 'C:\\work',
    }, { address: '0x401000', size: 4 });

    // 只认 regions[0].addr
    let r = await run((name, args) => {
      if (name === 'get_bytes' && args.regions && args.regions[0] && args.regions[0].addr !== undefined) {
        return [{ addr: args.regions[0].addr, data: '0x55 0x8b ec 83' }];
      }
      throw new Error('unsupported args');
    });
    ok(typeof r === 'string' && r.includes('55 8b ec 83'), 'regions[0].addr 形态 → hexdump');

    // 只认 {address,count}
    r = await run((name, args) => {
      if (name === 'get_bytes' && args.address !== undefined && args.count !== undefined) {
        return [{ addr: args.address, data: '0x90 0x90' }];
      }
      throw new Error('unsupported args');
    });
    ok(typeof r === 'string' && r.includes('90 90'), '{address,count} 形态 → hexdump');

    // 只认 py_exec_file(file_path)
    r = await run((name, args) => {
      if (name === 'py_exec_file' && args.file_path) return { stdout: 'BYTES 558bec83', result: '', stderr: '' };
      throw new Error('unsupported args');
    });
    ok(typeof r === 'string' && r.includes('55 8b ec 83'), 'py_exec_file(file_path) 兜底 → hexdump');

    // 全拒绝 → 类型化异常
    let err = null;
    try { await run(() => { throw new Error('no'); }); } catch (e) { err = e; }
    ok(!!err && err.__toolError === true, '全形态失败 → 抛 __toolError===true');
    ok(!!err && err instanceof ToolCallError, '异常类型为 ToolCallError');
    ok(!!err && /C:\\work/.test(err.message), '失败信息包含顶层工作目录（非 undefined）');
  }

  console.log('\nT5) scanCryptoCase 对 CUSTOM-BLOCK 样本给出结构推理（不再 buf is not defined）');
  {
    // 合成样本：自定义双射 S 盒 + 标准 CK + FK（与 test_constant_analysis 同一布局）
    const sbox = Array.from({ length: 256 }, (_, i) => i);
    let s = 42;
    for (let i = 255; i > 0; i--) {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      const j = s % (i + 1);
      [sbox[i], sbox[j]] = [sbox[j], sbox[i]];
    }
    const sboxBuf = Buffer.alloc(256 * 4);
    for (let i = 0; i < 256; i++) sboxBuf.writeUInt32LE(sbox[i], i * 4);
    const ckBuf = Buffer.alloc(32 * 4);
    for (let i = 0; i < 32; i++) {
      const b = [0, 1, 2, 3].map(j => ((4 * i + j) * 7) & 0xff);
      ckBuf.writeUInt32LE(((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0, i * 4);
    }
    const fkBuf = Buffer.alloc(16);
    [0x12345678, 0x9abcdef0, 0xfedcba98, 0x87654321].forEach((v, i) => fkBuf.writeUInt32LE(v, i * 4));
    const sample = Buffer.concat([
      Buffer.alloc(0x200, 0xcc), sboxBuf, Buffer.alloc(0x400, 0xcc),
      ckBuf, Buffer.alloc(0x400, 0xcc), fkBuf, Buffer.alloc(0x200, 0xcc),
    ]);
    const f = p.join(os.tmpdir(), 'tool_result_truth_custom_block.bin');
    fs.writeFileSync(f, sample);

    // 先证明样本本身确实带常量分析（否则下面的断言没有意义）
    const rawScan = scanner.scanCryptoFingerprints(f);
    ok((rawScan.fingerprints || []).some(x => x.constantAnalysis), '样本指纹含 constantAnalysis');

    let out = null, err = null;
    try {
      out = scanCryptoCase({ fs, scanCrypto: scanner.scanCryptoFingerprints, inferCipherStructure: scanner.inferCipherStructure }, { path: f });
    } catch (e) { err = e; }
    ok(!err, `不抛异常${err ? '：' + err.message : ''}`);
    ok(typeof out === 'string' && out.includes('## 结构推理'), '输出含「## 结构推理」');
    ok(typeof out === 'string' && !/buf is not defined/.test(out), '输出不含 "buf is not defined"');
  }

  console.log('\nT6) toToolResult 把字符串失败与 __toolError 映射为 isError');
  {
    const a = toToolResult('工具调用失败: buf is not defined');
    ok(a.isError === true, '字符串失败前缀 → isError:true');
    const b = toToolResult({ __toolError: true });
    ok(b.isError === true, '__toolError 对象 → isError:true');
    const c = toToolResult('## 主结论\n- 【AES】置信度 high');
    ok(c.isError === false, '普通字符串 → isError:false');
    ok(c.text === '## 主结论\n- 【AES】置信度 high', '普通字符串原样返回');
  }

  console.log('\nT7) main.js 静态断言：旧字段与旧参数形态已清除');
  {
    const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
    ok((mainSrc.match(/state\.currentFile/g) || []).length === 0, 'state.currentFile 计数为 0');
    ok(!/py_exec_file'\s*,\s*\{\s*path:/.test(mainSrc), "py_exec_file 调用不再含 { path:");
  }

  // ── 以下是独立复核提出的 7 个问题的回归用例 ──

  console.log('\nT9) hexdump 的地址列不得被当成数据字节');
  {
    const a = bytesFromData('00401000  55 8b ec 83  U...');
    ok(!!a && a.toString('hex') === '558bec83', `带 ASCII 列 → 55 8b ec 83（实际 ${a ? a.toString('hex') : 'null'}）`);
    const b = bytesFromData('00401000  55 8b ec 83');
    ok(!!b && b.toString('hex') === '558bec83', `无 ASCII 列 → 55 8b ec 83（实际 ${b ? b.toString('hex') : 'null'}）`);
    const c = bytesFromData('0000  55 8b ec');
    ok(!!c && c.toString('hex') === '558bec', `行内偏移 0000 不当数据（实际 ${c ? c.toString('hex') : 'null'}）`);
    const d = bytesFromData('00401000  55 8b ec 83  U...\n00401004  90 90 cc cc  ....');
    ok(!!d && d.toString('hex') === '558bec839090cccc', `多行按序拼接（实际 ${d ? d.toString('hex') : 'null'}）`);
    const e = bytesFromData('0x55 0x8b 0xec');
    ok(!!e && e.toString('hex') === '558bec', `0xNN 形态仍正确（实际 ${e ? e.toString('hex') : 'null'}）`);
    const f = bytesFromData('558bec');
    ok(!!f && f.toString('hex') === '558bec', `连续 hex 串仍正确（实际 ${f ? f.toString('hex') : 'null'}）`);
  }

  console.log('\nT10) 失败前缀表覆盖主进程真实会返回的失败文案');
  {
    const cases = [
      '搜索失败: EPERM',
      '浏览器MCP搜索失败: timeout',
      'ADB命令失败: device offline',
      '读取失败: EACCES',
      '未在文件中找到可提取的载荷。请先用 scan_crypto 查看',
      '不支持的编码方式: foo',
      '未找到自定义分组密码结构（无 256 项双射 S 盒）',
      '无结构推理输入：该文件没有识别出 256 项双射 S 盒',
      '未找到知识页: x',
    ];
    for (const c of cases) ok(!!toolFailureReason(c), `判为失败：${c.slice(0, 24)}`);
    ok(toolFailureReason('## 主结论\n- 【AES】置信度 high') === null, '分析结论不误判');
    ok(toolFailureReason('搜索到 3 个匹配项') === null, '正常结果不误判');
  }

  console.log('\nT11) error:0 / error:false 表示成功，不得判失败');
  {
    ok(toToolResult({ success: true, error: 0, data: 'ok' }).isError === false, '{success:true,error:0} → 成功');
    ok(toolFailureReason([{ addr: '0x401000', data: '0x55 0x8b', error: 0 }]) === null, '数组项 error:0 → 不失败');
    ok(toToolResult({ success: true, error: false, data: 'ok' }).isError === false, '{error:false} → 成功');
    ok(toToolResult({ success: true, error: null }).isError === false, '{error:null} → 成功');
    ok(toolFailureReason({ error: 'boom' }) === 'boom', '非空字符串 error → 失败');
    ok(toolFailureReason({ error: 1 }) === '1', '非零数字 error → 失败');
  }

  console.log('\nT12) 多段返回中部分段为 null：取到其余段而不是整体拒绝');
  {
    let calls = 0;
    const r = await idaGetBytes({
      callMcp: async (name) => {
        calls++;
        if (name === 'get_bytes') return [{ addr: '0x401000', data: null }, { addr: '0x401004', data: '0x55 0x8b' }];
        throw new Error('no fallback expected');
      },
      writeTemp: () => { throw new Error('should not need py fallback'); },
      topLevelDir: 'C:\\work',
    }, { address: '0x401000', size: 8 });
    ok(typeof r === 'string' && /55 8b/.test(r), `返回第二段字节：${r ? r.split('\n')[0] : 'null'}`);
    ok(calls === 1, `只需 1 次调用（实际 ${calls}）`);
  }

  console.log('\nT13) 终兜底脚本用完即删');
  {
    const created = [];
    const tmpPath = p.join(os.tmpdir(), 'ctf_get_bytes_test_' + Date.now() + '.py');
    try {
      await idaGetBytes({
        callMcp: async (name) => {
          if (name === 'get_bytes') return [{ addr: '0x401000', data: null }];
          if (name === 'py_exec_file') return { stdout: 'noise', result: '', stderr: 'boom' };
          throw new Error('unexpected');
        },
        writeTemp: () => { fs.writeFileSync(tmpPath, 'print(1)'); created.push(tmpPath); return tmpPath; },
        topLevelDir: 'C:\\work',
      }, { address: '0x401000', size: 4 });
      ok(false, '应当抛错（全部形态失败）');
    } catch (e) {
      ok(!!e && e.__toolError === true, '全部失败 → ToolCallError');
    }
    ok(created.length === 1, `兜底脚本被创建 1 次（实际 ${created.length}）`);
    ok(!fs.existsSync(tmpPath), '兜底脚本已被删除');
  }

  console.log('\nT14) buildGetBytesAttempts 覆盖对象/裸串/address 三种 regions 形态');
  {
    const as = buildGetBytesAttempts('0x401000', 4);
    ok(as[0].regions && as[0].regions[0] && as[0].regions[0].addr === '0x401000', '首形态 regions[{addr,size}]');
    ok(as[1].regions && as[1].regions[0].addr === '0x401000', '第二形态 regions[{addr}]（无 size）');
    ok(as[2].regions && as[2].regions[0] === '0x401000', '第三形态 regions["0x401000"] 裸串');
    ok(as[3].address === '0x401000', '第四形态 {address,size}');
    ok(as[4].count === 4, '第五形态 {address,count}');

    let n = 0;
    const r = await idaGetBytes({
      callMcp: async (name, args) => {
        n++;
        if (name === 'get_bytes' && args.regions && args.regions[0] && typeof args.regions[0] === 'object'
          && args.regions[0].size === undefined) {
          return [{ addr: '0x401000', data: '0xcc' }];
        }
        throw new Error('unsupported');
      },
      writeTemp: () => { throw new Error('no fallback'); },
    }, { address: '0x401000', size: 1 });
    ok(/cc/.test(r), '无 size 的对象形态可用');
    ok(n === 2, `在第 2 次尝试命中（实际 ${n}）`);
  }

  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
