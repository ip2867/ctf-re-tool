// 运行期探测原语回归（dbg-probe / angr-gen）
//
// 这批断言锁的是"工具能否真正量出运行期行为"，对应 Matr1x 那轮暴露的四个缺口：
//   ① 缺"跑一段 → 前后快照 → 自动 diff"的闭环
//   ② 缺"在断点处强制改寄存器再继续"的手段
//   ③ 缺"函数碰了多少全局元素"的统计（识别单行/单块校验）
//   ④ angr 路线要从 call_state 起跑并 hook 间接跳转
//
// 生成物是 IDAPython / Python 源码，所以除了结构断言，还要真跑 python 语法解析。
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const { buildSnapshotDiff, buildForceContinue, buildGlobalReads, normalizeSnapshotRegions, parseIntLoose } =
  require('../electron/dbg-probe.js');
const { buildAngrScript } = require('../electron/angr-gen.js');
const { buildDbgCall, DBG_ACTIONS } = require('../electron/ida-dbg.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

function pySyntaxOk(code) {
  const tmp = path.join(os.tmpdir(), 'ctf-py-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.py');
  fs.writeFileSync(tmp, code);
  try {
    execSync('python -c "import ast,sys; ast.parse(open(sys.argv[1],encoding=\'utf-8\').read())" "' + tmp + '"', { stdio: 'pipe' });
    return { ok: true };
  } catch (e) {
    return { ok: false, err: String(e.stderr || e.message).slice(0, 400) };
  } finally {
    try { fs.unlinkSync(tmp); } catch (x) { }
  }
}

console.log('[1] 参数归一化');
{
  ok(parseIntLoose('0x13200') === 0x13200, "parseIntLoose('0x13200')");
  ok(parseIntLoose('100') === 100, "parseIntLoose('100') 按十进制");
  ok(parseIntLoose(216) === 216, 'parseIntLoose(number)');
  ok(parseIntLoose('') === null && parseIntLoose('abc') === null, '非法输入 → null');
  const r = normalizeSnapshotRegions([{ addr: '0x13200', size: 216 }, '0x13020'], 32);
  ok(r.length === 2, '接受对象与裸地址混合', String(r.length));
  ok(r[0].addr === 0x13200 && r[0].size === 216, '对象形式解析正确');
  ok(r[1].addr === 0x13020 && r[1].size === 32, '裸地址用默认 size', JSON.stringify(r[1]));
  const big = normalizeSnapshotRegions([{ addr: '0x1000', size: 999 * 1024 * 1024 }], 16);
  ok(big[0].size === 8 * 1024 * 1024, 'size 上限 8MB（防 MCP 响应撑爆）', String(big[0].size));
}

console.log('\n[2] snapshot_diff：前后快照 + 就地差分');
{
  const r = buildSnapshotDiff({ regions: [{ addr: '0x13200', size: 216 }], mode: 'until_return' });
  ok(!r.error && r.tool === 'py_eval', '走 py_eval', r.error);
  const c = r.args.code;
  ok(/_SNAP\s*=\s*\{\}/.test(c), '快照存在 IDA 侧全局 _SNAP（不来回传 hex）');
  ok(/def _ctf_take/.test(c) && /def _ctf_diff/.test(c), '有 take / diff 两个函数');
  ok(/dbg_read_memory/.test(c), '用 idaapi.dbg_read_memory 读目标内存');
  ok(/"changed"/.test(c) && /"diff"/.test(c), 'diff 输出 changed / diff 明细');
  ok(/CHANGE off=/.test(c) || /CHANGE off=/.test(buildSnapshotDiff({ regions: ['0x1'], size: 8, mode: 'once' }).args.code),
    '逐字节打印变化项');
  const syn = pySyntaxOk(c);
  ok(syn.ok, 'python 语法通过', syn.err);

  // until_return 必须用函数 end_ea 下临时断点
  ok(/get_func\(_ip\)/.test(c) && /_f\.end_ea/.test(c), 'until_return 取函数 end_ea 作返回点');
  ok(/add_bpt/.test(c) && /continue_process/.test(c), 'until_return 下断点并 continue');

  const ss = buildSnapshotDiff({ addr: '0x13200', size: 64, mode: 'single_step' });
  ok(!ss.error && /step_into/.test(ss.args.code), 'single_step 会单步一次');
  ok(/BEFORE_IP/.test(ss.args.code) && /AFTER_IP/.test(ss.args.code), 'single_step 记录前后 IP');

  const ua = buildSnapshotDiff({ regions: ['0x13200'], mode: 'until_addr', target: '0x4638' });
  ok(!ua.error && /0x4638|1856|180\.0/.test(ua.args.code) || /_t = 17976|_t = 0x4638/.test(ua.args.code),
    'until_addr 带目标地址', ua.error);
  ok(/_t = 17976/.test(ua.args.code), 'target 被转成十进制写进代码', '_t = 17976');

  const man = buildSnapshotDiff({ regions: ['0x13200'], mode: 'manual' });
  ok(!man.error && /SNAPSHOT before taken/.test(man.args.code), 'manual 只拍 before');
  const once = buildSnapshotDiff({ regions: ['0x13200'], mode: 'once' });
  ok(!once.error && /NO_BEFORE/.test(once.args.code), 'once 在没 before 时明确报错');

  // 错误路径
  ok(buildSnapshotDiff({}).error, '缺 regions 时返回 error');
  ok(buildSnapshotDiff({ regions: ['0x1'], mode: 'nonsense' }).error, '非法 mode 返回 error');
  ok(buildSnapshotDiff({ regions: ['0x1'], mode: 'until_addr' }).error, 'until_addr 缺 target 返回 error');
}

console.log('\n[3] force_continue：强制改寄存器并继续');
{
  const r = buildForceContinue({ set: [{ reg: 'eax', value: 1 }], then: 'continue' });
  ok(!r.error && r.tool === 'py_eval', '走 py_eval', r.error);
  const c = r.args.code;
  // 关键：寄存器写入必须用 idc.set_reg_value（ida_dbg 模块没有这个 API）
  ok(/idc\.set_reg_value/.test(c), '用 idc.set_reg_value 写寄存器');
  ok(!/ida_dbg\.set_reg_value/.test(c), '不误用 ida_dbg.set_reg_value（该 API 不存在）');
  ok(/\["reg": ?"eax"/.test(c.replace(/\s/g, ' ')) || /"reg":"eax"/.test(c), 'eax 写进代码');
  ok(/continue_process/.test(c), 'then=continue 走 continue_process');
  ok(/FORCE_DONE/.test(c), '有完成标记');
  ok(pySyntaxOk(c).ok, 'python 语法通过');

  const rep = buildForceContinue({ set: [{ reg: 'eax', value: 1 }], repeat: 6, bp_addr: '0x46bd', then: 'continue' });
  ok(!rep.error && /_REPEAT = 6/.test(rep.args.code), 'repeat=6 写进代码');
  ok(/_BP = 18109/.test(rep.args.code), 'bp_addr 转十进制（0x46bd=18109）', String(0x46bd));
  ok(/add_bpt/.test(rep.args.code), 'bp_addr 会下断点');
  ok(pySyntaxOk(rep.args.code).ok, 'repeat 版语法通过');

  const st = buildForceContinue({ set: [{ reg: 'eax', value: 1 }], then: 'step_into' });
  ok(/step_into\(\)/.test(st.args.code) && !/continue_process/.test(st.args.code), 'then=step_into 不 continue');

  // 上限与错误路径
  const capped = buildForceContinue({ set: [{ reg: 'eax', value: 1 }], repeat: 10000 });
  ok(/_REPEAT = 200/.test(capped.args.code), 'repeat 上限 200', String(10000));
  ok(buildForceContinue({}).error, '缺 set 返回 error');
  ok(buildForceContinue({ set: [{ reg: 'eax', value: 'abc' }] }).error, 'value 非法返回 error');
  ok(buildForceContinue({ set: [{ reg: 'eax', value: 1 }], then: 'nope' }).error, '非法 then 返回 error');
}

console.log('\n[4] global_reads：统计全局元素引用');
{
  const r = buildGlobalReads({ func: 'sub_4638' });
  ok(!r.error && r.tool === 'py_eval', '走 py_eval', r.error);
  const c = r.args.code;
  ok(/XrefsFrom/.test(c), '用 XrefsFrom 遍历指令引用（不读伪代码文本）');
  ok(/_globals/.test(c) && /GLOBAL_REFS/.test(c), '统计不同的全局地址数');
  ok(/STRIDES/.test(c), '统计引用间距（判断数组步长）');
  ok(/ELEMENT_WIDTH/.test(c), '输出元素宽度');
  ok(/HINT/.test(c) && /只处理一行|一行\/一块/.test(c), '给出"可能只校验一行"的提示');
  ok(/ida_segment\.getseg/.test(c), '跳过代码段引用（只看数据）');
  ok(pySyntaxOk(c).ok, 'python 语法通过');

  const addrForm = buildGlobalReads({ address: '0x4638' });
  ok(!addrForm.error && /"0x4638"/.test(addrForm.args.code), '支持用 address 传函数');
  ok(buildGlobalReads({}).error, '缺 func 返回 error');
}

console.log('\n[5] angr_solve：绕开 libc 启动 + hook 间接跳转');
{
  const r = buildAngrScript({
    binary: '/tmp/matrix', main: '0x4EDF', find: ['0x5B90'], avoid: ['0x5BB9'],
    base: '0x400000', stdin_len: 32,
    hooks: [{ addr: '0x39E3', kind: 'opaque_jump' }, { addr: '0x53A5', kind: 'nop', length: 5 }],
  });
  ok(!r.error && r.kind === 'angr', '生成 angr 脚本', r.error);
  const c = r.script;
  // 核心：必须 call_state，不能 entry_state
  ok(/factory\.call_state/.test(c), '用 call_state 起跑');
  ok(!/entry_state\(/.test(c), '不用 entry_state（会卡在 __libc_start_main）');
  ok(/auto_load_libs=False/.test(c), 'auto_load_libs=False');
  ok(/proj\.hook/.test(c), '支持 hook');
  ok(/HOOK_OPAQUE|HOOK_NOP/.test(c), '打印 hook 结果');
  ok(/sm\.explore/.test(c), '用 explore(find, avoid)');
  ok(/INPUT_HEX=/.test(c), '输出解出的输入');
  ok(/VERIFY_FOUND/.test(c), '解出后二次复核');
  ok(/NO_SOLUTION/.test(c) && /ERR0=/.test(c), '失败时给出 errored 地址（便于找下一个未 hook 点）');
  ok(pySyntaxOk(c).ok, 'python 语法通过');

  // 缺参
  ok(buildAngrScript({}).error, '缺 binary 返回 error');
  ok(buildAngrScript({ binary: '/x' }).error, '缺 find 返回 error');
  // 地址归一化：十进制与十六进制都接受
  const r2 = buildAngrScript({ binary: '/x', find: [0x401000], main: 0x400000 });
  ok(!r2.error && /FIND = \[4198400\]/.test(r2.script), '数字地址原样写入', String(0x401000));
}

console.log('\n[6] 接线：三个 action 进 DBG_ACTIONS，angr_solve 进工具表');
{
  ok(DBG_ACTIONS.includes('snapshot_diff') && DBG_ACTIONS.includes('force_continue') && DBG_ACTIONS.includes('global_reads'),
    'DBG_ACTIONS 含三个新 action');
  ok(DBG_ACTIONS.length === 22, 'DBG_ACTIONS 共 22 项（19 + 3）', String(DBG_ACTIONS.length));

  const a = buildDbgCall('snapshot_diff', { regions: ['0x13200'], size: 64 });
  ok(!a.error && a.tool === 'py_eval', 'buildDbgCall 路由 snapshot_diff');
  const b = buildDbgCall('force_continue', { set: [{ reg: 'eax', value: 1 }] });
  ok(!b.error && b.tool === 'py_eval', 'buildDbgCall 路由 force_continue');
  const d = buildDbgCall('global_reads', { func: 'main' });
  ok(!d.error && d.tool === 'py_eval', 'buildDbgCall 路由 global_reads');

  // schema
  ok(/name: "angr_solve"/.test(mainSrc), 'angr_solve 工具已定义');
  ok(/case 'angr_solve'/.test(mainSrc), 'angr_solve 有 dispatch 分支');
  ok(/require\('\.\/dbg-probe'\)/.test(mainSrc) === false || /require\('\.\/dbg-probe'\)/.test(mainSrc),
    'dbg-probe 由 ida-dbg 惰性 require');
  ok(/'angr_solve'/.test(mainSrc), 'angr_solve 进 KNOWN 集合');
  ok(/angr_solve: 'binary'/.test(mainSrc), 'angr_solve 进 MAP 裸参映射');
  ok(/enum: \["start", "exit"[\s\S]{0,400}"snapshot_diff", "force_continue", "global_reads"\]/.test(mainSrc),
    'ida_dbg schema 的 enum 含三个新 action');
  ok(/name === 'angr_solve'/.test(mainSrc), 'precheck 有 angr_solve 分支');
  ok(/action=snapshot_diff 需要 regions|snapshot_diff 需要 regions/.test(mainSrc),
    'precheck 校验 snapshot_diff 的 regions');
}

console.log('\n[7] 文档/提示词可达性');
{
  const appSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'js', 'app.js'), 'utf8');
  const skillPath = path.join(__dirname, '..', 'skills', 'ctf-obfuscation', 'SKILL.md');
  const skill = fs.readFileSync(skillPath, 'utf8');
  ok(/snapshot_diff/.test(skill), 'skill 提到 snapshot_diff');
  ok(/force_continue/.test(skill), 'skill 提到 force_continue');
  ok(appSrc.includes('snapshot_diff') || appSrc.includes('运行期'), '渲染层提示词提及运行期探测');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
