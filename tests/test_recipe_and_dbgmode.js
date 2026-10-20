// recipe（CyberChef 式变换链）与 IDA 调试模式（local/remote）单测。
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  runRecipe, autoDecode, OPS, printableRatio, entropy, fromBaseN, toBaseN, dictionaryOf,
} = require('../electron/recipe.js');
const {
  buildDbgCall, decideDebugMode, buildStartPrelude, translateDbgError, DBG_ACTIONS,
} = require('../electron/ida-dbg.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] recipe：基础编码链');
{
  const b64 = Buffer.from('48656c6c6f').toString('base64'); // "NDg2NTZjNmM2Zg=="
  const r = runRecipe(b64, [{ op: 'from_base64' }, { op: 'from_hex' }]);
  ok(r.ok, 'base64→hex 链执行成功', r.error);
  ok(r.output.text === 'Hello', '最终得到 Hello', r.output && r.output.text);
  ok(r.steps.length === 3, '报告包含输入 + 2 步（共 3 条）', r.steps.length);
  ok(r.steps[1].op === 'from_base64' && r.steps[2].op === 'from_hex', '步骤顺序正确');
  ok(typeof r.steps[2].printable === 'number' && typeof r.steps[2].entropy === 'number', '每步带 printable/entropy');
}

console.log('\n[2] recipe：XOR / 加减 / 反转 / 位移');
{
  const src = Buffer.from('flag{test}');
  const key = Buffer.from([0x0a, 0x0b, 0x0c]);
  const enc = Buffer.alloc(src.length);
  for (let i = 0; i < src.length; i++) enc[i] = src[i] ^ key[i % key.length];
  const r = runRecipe(enc.toString('hex'), [{ op: 'from_hex' }, { op: 'xor', key: '0a0b0c' }]);
  ok(r.ok && r.output.text === 'flag{test}', 'XOR 还原', r.output && r.output.text);

  const add = runRecipe(src.toString('utf8'), [{ op: 'add', key: 3 }, { op: 'sub', key: 3 }]);
  ok(add.ok && add.output.text === 'flag{test}', 'add→sub 往返', add.output && add.output.text);

  const rev = runRecipe('cba', [{ op: 'reverse' }]);
  ok(rev.ok && rev.output.text === 'abc', 'reverse');

  const rot = runRecipe('uryyb', [{ op: 'rot', n: 13 }]);
  ok(rot.ok && rot.output.text === 'hello', 'ROT13', rot.output && rot.output.text);
}

console.log('\n[3] recipe：压缩与自定义 Base64');
{
  const zlib = require('zlib');
  const gz = zlib.gzipSync(Buffer.from('compressed payload'));
  const r = runRecipe(gz.toString('base64'), [{ op: 'from_base64' }, { op: 'gunzip' }]);
  ok(r.ok && r.output.text === 'compressed payload', 'base64→gunzip', r.error || (r.output && r.output.text));

  const alpha = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/';
  // 用自定义表编码 "flag"，再用 custom_base64 解
  const encoded = toBaseN(Buffer.from('flag'), alpha, 6);
  const d = runRecipe(encoded, [{ op: 'custom_base64', alphabet: alpha }]);
  ok(d.ok && d.output.text === 'flag', '自定义 64 表 Base64 解码', d.error || (d.output && d.output.text));
}

console.log('\n[4] recipe：哈希单向前进 + 有界反查');
{
  const digest = crypto.createHash('md5').update('password').digest('hex');
  const h = runRecipe('password', [{ op: 'hash', algo: 'md5' }]);
  ok(h.ok && h.output.text === digest, 'md5 正向计算正确');
  const c = runRecipe(digest, [{ op: 'crack', algo: 'md5' }]);
  ok(c.ok && c.output.text === 'password', '已知弱口令命中', c.output && c.output.text);

  const miss = runRecipe('0'.repeat(32), [{ op: 'crack', algo: 'md5' }]);
  ok(miss.ok && miss.output.text === '0'.repeat(32), '未命中时原样返回（不静默变成别的）', miss.output && miss.output.text);

  ok(dictionaryOf(['customword']).includes('customword'), '自定义字典项被纳入');
  ok(dictionaryOf().length > 10000, '内置字典含数字 0..9999');
}

console.log('\n[5] recipe：错误必须显式（不静默跳过）');
{
  const bad = runRecipe('x', [{ op: 'no_such_op' }]);
  ok(bad.ok === false && /未知操作/.test(bad.error), '未知操作报错', bad.error);

  const badIx = runRecipe('x', [{ op: 'from_hex' }, { op: 'gunzip' }]);
  ok(badIx.ok === false && /第 2 步/.test(badIx.error), '失败定位到具体步号', badIx.error);

  const empty = runRecipe('x', []);
  ok(empty.ok === false && /recipe 为空/.test(empty.error), '空 recipe 报错');

  const tooMany = runRecipe('x', Array.from({ length: 30 }, () => ({ op: 'reverse' })));
  ok(tooMany.ok === false && /步骤过多/.test(tooMany.error), '超长链报错');

  const noKey = runRecipe('x', [{ op: 'xor', key: '' }]);
  ok(noKey.ok === false && /key/.test(noKey.error), 'xor 缺 key 报错');

  const bz = runRecipe('x', [{ op: 'bzip2' }]);
  ok(bz.ok === false && /未内置/.test(bz.error), '未内置的算法明确报错而不是假装成功');
}

console.log('\n[6] autoDecode：只返回可打印结果，不猜 xor key');
{
  const b64 = Buffer.from('Hello World').toString('base64');
  const hits = autoDecode(b64);
  ok(hits.length > 0, '能自动识别 base64 → 明文', JSON.stringify(hits[0]));
  ok(hits[0].chain === 'from_base64' && hits[0].preview.includes('Hello World'), '首选链正确', JSON.stringify(hits[0]));
  ok(hits.every(h => h.printable >= 0.6), '全部结果都可打印');
  ok(!hits.some(h => /xor/.test(h.chain)), '自动模式不猜 xor key');
}

console.log('\n[7] IDA 调试模式：PE→local，ELF+Kali→remote');
{
  ok(decideDebugMode({}, { targetKind: 'PE' }) === 'local', 'PE 默认 local');
  ok(decideDebugMode({}, { targetKind: 'ELF', remoteAvailable: true }) === 'remote', 'ELF + Kali 可用 → remote');
  ok(decideDebugMode({}, { targetKind: 'ELF', remoteAvailable: false }) === 'local', 'ELF 但无 Kali → local（上层给提示）');
  ok(decideDebugMode({ mode: 'remote' }, { targetKind: 'PE' }) === 'remote', '显式 mode 覆盖推断');
  ok(decideDebugMode({ mode: 'LOCAL' }, { targetKind: 'ELF', remoteAvailable: true }) === 'local', 'mode 大小写不敏感');

  const local = buildStartPrelude('local', { path: 'a.exe' }, {});
  ok(local.tool === 'py_eval', 'local 走 py_eval（需要设置模式）');
  ok(/set_remote_debugger\("", "", -1\)/.test(local.args.code), 'local 显式清远程参数（残留会让你一直 start 失败）');
  ok(/load_debugger\("win32", False\)/.test(local.args.code), 'local 加载 win32 调试器');
  // start_process 的第一个实参现在是变量 _p（无 path 时回落到 get_input_file_path），
  // 因为 start_process("", ...) 会返回 0（启动被取消）。
  ok(/_p = "a\.exe"/.test(local.args.code) && /start_process\(_p,/.test(local.args.code),
    '路径被带入 start_process（经 _p 变量）');
  const localNoPath = buildStartPrelude('local', {}, {});
  ok(/get_input_file_path\(\)/.test(localNoPath.args.code), '无 path 时回落到当前加载文件');

  const remote = buildStartPrelude('remote', { path: 'a.elf' }, { remoteHost: '1.2.3.4', remotePort: 23946 });
  // Linux 远程调试必须用 IDA 自带的 dbgsrv/linux_server，调试器名为 "linux"。
  // 用 "gdb" 会走 GDB 协议客户端，与 linux_server 的私有协议不兼容（实测能连上但不接管）。
  ok(/load_debugger\("linux", True\)/.test(remote.args.code), 'remote 加载 linux 调试器（对应 linux_server）');
  ok(!/load_debugger\("gdb"/.test(remote.args.code), 'remote 不用 gdb（与 linux_server 协议不兼容）');
  ok(/set_remote_debugger\("1\.2\.3\.4", ""/.test(remote.args.code), 'remote 设置主机');
  ok(/23946/.test(remote.args.code), 'remote 设置端口');

  const noHost = buildStartPrelude('remote', {}, {});
  ok(!!noHost.error && /remote_host/.test(noHost.error), 'remote 缺 host 明确报错');

  ok(DBG_ACTIONS.includes('clear_remote'), 'clear_remote 是合法动作');
  ok(buildDbgCall('clear_remote', {}).tool === 'py_eval', 'clear_remote 走 py_eval');
  ok(/set_remote_debugger\("", "", -1\)/.test(buildDbgCall('clear_remote', {}).args.code), 'clear_remote 清空远程参数');
}

console.log('\n[8] START_RC=-1 不能再被当成功；错误信息给出可行动作');
{
  ok(/START_RC/.test(buildStartPrelude('local', {}, {}).args.code), 'py_eval 输出 START_RC');
  ok(/START_RC/.test(mainSrc), '主进程读取 START_RC');
  // dispatch 里的 case 在文件靠后位置；toolLabel 里也有同名 case，取最后一段
  const seg = mainSrc.slice(mainSrc.lastIndexOf("case 'ida_dbg':"));
  // START_RC 只要不是 1 都算失败（-1=无法创建，0=启动被取消）
  ok(/Number\(m\[1\]\) !== 1/.test(seg), 'START_RC != 1 判为失败（含 -1 与 0）');
  ok(/STALE_OPTS/.test(seg), '识别残留进程选项并提示');
  ok(/clear_remote/.test(seg), '提示可执行 clear_remote');

  const hint = translateDbgError('Failed to start debugger');
  ok(/clear_remote/.test(hint) && /remote/.test(hint), '错误翻译给出 remote/clear_remote 两个方向');
}

console.log('\n[9] 工具注册：recipe / clear_remote 全链路');
{
  ok(/name: "recipe"/.test(mainSrc), 'recipe 在工具定义');
  ok(/case 'recipe':/.test(mainSrc), 'recipe 在 dispatch');
  const known = mainSrc.slice(mainSrc.indexOf('const KNOWN = new Set(['), mainSrc.indexOf('const KNOWN = new Set([') + 1400);
  ok(/'recipe'/.test(known), 'recipe 在 KNOWN');
  ok(/case 'recipe': return/.test(mainSrc), 'recipe 有 toolLabel');
  const pre = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'), mainSrc.indexOf('function levenshtein'));
  ok(/name === 'recipe'/.test(pre), 'recipe 有 precheck');
  const def = mainSrc.slice(mainSrc.indexOf('name: "ida_dbg"'), mainSrc.indexOf('name: "ida_dbg_mem"'));
  ok(/enum: \["local", "remote"\]/.test(def), 'ida_dbg 暴露 mode 枚举');
  ok(/remote_host/.test(def), 'ida_dbg 暴露 remote_host');
  ok(/clear_remote/.test(def), 'ida_dbg 枚举含 clear_remote');
}

console.log('\n[10] 目标类型同步：set-workdir 带 file/fileType');
{
  ok(/setWorkdir: \(dir, file, fileType\)/.test(fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8')), 'preload 透传三个参数');
  ok(/ipcMain\.handle\('set-workdir', async \(event, dir, file, fileType\)/.test(mainSrc), '主进程接收三个参数');
  ok(/function idaDbgTargetKind/.test(mainSrc), '存在目标类型推断函数');
  ok(/currentTargetKind/.test(mainSrc), '目标类型被保存');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
