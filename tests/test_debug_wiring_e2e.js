// 端到端接线检查：确认上一轮的调试能力与知识库能力都真的接在生产路径上。
const fs = require('fs');
const path = require('path');
let pass = 0, fail = 0;
const ok = (c, n, d) => { if (c) { pass++; console.log('  OK   ' + n); } else { fail++; console.log('  FAIL ' + n + (d ? '  → ' + d : '')); } };
const root = path.join(__dirname, '..');
const main = fs.readFileSync(path.join(root, 'electron', 'main.js'), 'utf8');
const idaDbg = fs.readFileSync(path.join(root, 'electron', 'ida-dbg.js'), 'utf8');
const app = fs.readFileSync(path.join(root, 'src', 'js', 'app.js'), 'utf8');

console.log('\n[1] 调试工具接线');
ok(/name: "ida_dbg"/.test(main), 'ida_dbg 工具已注册');
const schema = (main.match(/name: "ida_dbg",[\s\S]*?required: \["action"\]/) || [''])[0];
ok(/"status"/.test(schema), 'schema 含 status');
ok(/"suspend"/.test(schema), 'schema 含 suspend');
ok(/STATE：-1=已暂停/.test(schema), 'schema 写明状态语义');
ok(/continue\/run_to 已自动轮询/.test(schema), 'schema 说明异步轮询');

console.log('\n[2] 状态语义与 gate');
ok(/function dbgStateName/.test(idaDbg), 'dbgStateName 存在');
ok(/state === -1.*suspended|suspended.*-1/s.test(idaDbg) || /if \(st === -1\) return 'suspended'/.test(idaDbg), '状态映射正确');
ok(/readDbgState/.test(main), 'readDbgState 存在');
ok(/waitDbgStop/.test(main), 'waitDbgStop 存在');
ok(/无法执行 \$\{act\}：进程正在运行/.test(main), 'step/run_to 运行态拦截');
ok(/写内存失败：进程正在运行/.test(main), 'mem_write 运行态拦截');

console.log('\n[3] start 幂等与路径回落');
ok(/ALREADY_RUNNING/.test(idaDbg), 'start 幂等分支');
ok(/get_input_file_path\(\)/.test(idaDbg), 'path 为空时回落当前文件');
ok(/set_process_options/.test(idaDbg), '本地启动清残留进程选项');
ok(/load_debugger\("linux", True\)/.test(idaDbg), '远程用 linux 调试器');
ok(/idaapi\.add_bpt/.test(idaDbg), 'bp_add 走 idaapi.add_bpt');
ok(/suspend_process/.test(main), '远程 start 后自动 suspend');
ok(/symbols/.test(main), '远程返回重定位符号');

console.log('\n[4] 提示词引导');
ok(/入场条件：静态没跑完/.test(app), '入场条件在提示词');
ok(/ida_dbg\(action:"status"\)/.test(app), '提示词提到 status');
ok(/ida_dbg\(action:"suspend"\)/.test(app), '提示词提到 suspend');
ok(/32 位目标（WOW64）：\*\*优先用内存改写法/.test(app), '32 位改内存路线');
ok(/解密循环\*\*结束后\*\*/.test(app), 'SMC 正确顺序');

console.log('\n[5] 知识库接进自动预取');
ok(/动态调试 静态先行 断点/.test(app), 'FEATURES 产出动态调试检索词');
ok(/const METHOD_PAGES/.test(app), '方法论专页显式点名');
ok(/wiki_read\("reverse\/method_static_first_dynamic\.md"\)/.test(app), '提示词直接给出 wiki_read 路径');

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
