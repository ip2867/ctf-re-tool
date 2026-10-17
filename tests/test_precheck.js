// 真机验证：precheck 不得误拦合法的 run_python / ida_decompile / grep(无 path)
const fs = require('fs');
const p = require('path');

// precheckToolCall 是纯函数（只依赖 fs/path），直接从源码抽取执行
const mainSrc = fs.readFileSync(p.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const start = mainSrc.indexOf('function precheckToolCall');
const end = mainSrc.indexOf('function levenshtein');
const levEnd = mainSrc.indexOf('\n}', mainSrc.indexOf('function levenshtein')) + 2;
const body = mainSrc.slice(start, end) + '\n' + mainSrc.slice(mainSrc.indexOf('function levenshtein'), levEnd);
const factory = new Function('fs', 'path', body + '\nreturn { precheckToolCall, levenshtein };');
const { precheckToolCall } = factory(fs, p);

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✅ ' + m); } else { fail++; console.log('  ❌ ' + m); } };
const allow = (tool, input, label) => ok(precheckToolCall(tool, input) === null, label);
const block = (tool, input, label) => ok(precheckToolCall(tool, input) !== null, label);

console.log('A) 合法调用不得被拦截（真实 API 调用路径）');
allow('run_python', { script: 'print(1)' }, 'run_python 传 script 放行');
allow('run_python', { script: 'import idaapi\nprint(2)' }, 'run_python 多行脚本放行');
allow('ida_decompile', { function_name: 'main' }, 'ida_decompile 传 function_name 放行');
allow('ida_get_bytes', { address: '0x41C000', size: 16 }, 'ida_get_bytes 传 address 放行');
allow('grep', { pattern: 'flag' }, 'grep 不带 path 放行（path 可选）');
allow('grep', { pattern: 'flag', path: 'C:/Windows' }, 'grep 带 path 放行');
allow('glob', { pattern: '**/*.exe' }, 'glob 放行');
allow('bash', { command: 'dir' }, 'bash 放行');

console.log('\nB) 非法调用必须被拦截且给出改法');
{
  const r = precheckToolCall('run_python', {});
  block('run_python', {}, 'run_python 缺 script 被拦');
  ok(/script/.test(r), '错误信息点名 script 字段');
  ok(/不要传文件路径/.test(r), '提示不要把路径当脚本');

  const r2 = precheckToolCall('ida_decompile', {});
  block('ida_decompile', {}, 'ida_decompile 缺 function_name 被拦');
  ok(/function_name/.test(r2), '错误信息点名 function_name（与 schema 一致）');
  ok(/ida_list_functions/.test(r2), '给出补救工具建议');

  block('read_file', {}, 'read_file 缺 path 被拦');
  block('bash', {}, 'bash 缺 command 被拦');
  block('grep', {}, 'grep 缺 pattern 被拦');
}

console.log('\nC) 路径不存在时给出相近文件');
{
  const dir = p.join(__dirname, '..', 'electron');
  const r = precheckToolCall('read_file', { path: p.join(dir, 'main.jss') });
  ok(r !== null, '不存在路径被拦截');
  ok(/main\.js/.test(r), '给出最相近的真实文件 main.js');
  ok(/文件不存在/.test(r), '明确说明文件不存在');
}

console.log('\nD) 路径存在时放行');
{
  allow('read_file', { path: p.join(__dirname, '..', 'electron', 'main.js') }, '真实文件放行');
  allow('scan_crypto', { path: p.join(__dirname, '..', 'package.json') }, 'scan_crypto 放行');
  allow('analyze_structure', { path: p.join(__dirname, '..', 'package.json') }, 'analyze_structure 放行');
}

console.log('\nE) Levenshtein 正确性');
{
  const { levenshtein } = factory(fs, p);
  ok(levenshtein('main.js', 'main.jss') === 1, '插入 1 字符距离为 1');
  ok(levenshtein('abc', 'abc') === 0, '相同串距离 0');
  ok(levenshtein('', 'abc') === 3, '空串距离 = 长度');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
