// gui_input 单测：参数归一化、输出解析、脚本内容、工具注册。
//
// 真实注入在 _gui_e2e.js 里做（需要启动 GUI 程序），这里只验证纯逻辑，
// 保证 CI/无桌面环境也能跑。
const fs = require('fs');
const path = require('path');
const {
  normalizeGuiInput, parseGuiOutput, GUI_SCRIPT,
} = require('../electron/gui-input.js');

const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
const ok = (c, m, extra) => { if (c) { pass++; console.log('  OK   ' + m); } else { fail++; console.log('  FAIL ' + m + (extra ? ' -> ' + extra : '')); } };

console.log('[1] 参数校验：必须能定位目标，注入必须有文本');
{
  ok(!!normalizeGuiInput({}).error, '空参数报错');
  ok(/text/.test(normalizeGuiInput({}).error), '提示需要 text');

  const noTarget = normalizeGuiInput({ text: 'abc' });
  ok(!!noTarget.error && /pid|title/.test(noTarget.error), '缺 pid/title 报错', noTarget.error);

  const byPid = normalizeGuiInput({ pid: 1234, text: 'hello' });
  ok(!byPid.error && byPid.value.pid === 1234 && byPid.value.text === 'hello', 'pid 定位可用', JSON.stringify(byPid));

  const byTitle = normalizeGuiInput({ title_contains: 'CrackMe', text: 'x' });
  ok(!byTitle.error && byTitle.value.title_contains === 'CrackMe', '标题定位可用');

  const listOnly = normalizeGuiInput({ list_only: true });
  ok(!listOnly.error && listOnly.value.list_only === true, 'list_only 不需要 text/pid');

  const noTextInjection = normalizeGuiInput({ pid: 1, text: '' });
  ok(!!noTextInjection.error, '注入模式空文本报错');

  // 非法数字不应炸
  const bad = normalizeGuiInput({ pid: 'abc', text: 'x' });
  ok(bad.error || bad.value.pid === 0, '非法 pid 被归零或报错', JSON.stringify(bad));

  const neg = normalizeGuiInput({ pid: -5, text: 'x' });
  ok(neg.error || neg.value.pid === 0, '负数 pid 被归零');

  // submit 默认 true；显式 false 保留
  const def = normalizeGuiInput({ pid: 1, text: 'x' });
  ok(def.value.submit === true, 'submit 默认 true');
  const notSubmit = normalizeGuiInput({ pid: 1, text: 'x', submit: false });
  ok(notSubmit.value.submit === false, 'submit:false 保留');

  // send_message 默认 false（PostMessage）
  ok(def.value.send_message === false, '默认 PostMessage');
  const sync = normalizeGuiInput({ pid: 1, text: 'x', send_message: true });
  ok(sync.value.send_message === true, 'send_message:true 保留');
}

console.log('\n[2] 输出解析：容忍 Add-Type 编译告警');
{
  ok(parseGuiOutput('{"ok":true,"mode":"list"}').ok === true, '纯 JSON');
  const mixed = parseGuiOutput('warning CS0168: unused\n{"ok":true,"mode":"inject","text_set":"posted"}');
  ok(mixed.ok === true && mixed.mode === 'inject' && mixed.text_set === 'posted', '告警前缀被跳过', JSON.stringify(mixed));
  ok(parseGuiOutput('').error === 'EMPTY_OUTPUT', '空输出');
  ok(parseGuiOutput('no json here').error === 'BAD_JSON', '无 JSON');
  ok(parseGuiOutput('{"ok":true').error === 'BAD_JSON', '截断 JSON');
  // 多行输出里只有最后一行是 JSON（Add-Type 告警在前）
  const multi = parseGuiOutput('warn line 1\nwarn line 2\n{"ok":true,"mode":"list","windows":[{"a":{"b":1}}]}');
  ok(multi.ok === true && multi.mode === 'list', '多行中取最后一行 JSON（旧实现用 lastIndexOf("{") 会命中嵌套对象）', JSON.stringify(multi));

  const noWin = parseGuiOutput('{"ok":false,"error":"NO_WINDOW","windows":[]}');
  ok(noWin.ok === false && noWin.error === 'NO_WINDOW', 'NO_WINDOW 可解析');
}

console.log('\n[3] 脚本关键点：PostMessage 优先、BM_CLICK、超时上限');
{
  ok(/PostMessage/.test(GUI_SCRIPT), '使用 PostMessage');
  ok(/SendMessageTimeout/.test(GUI_SCRIPT), 'SendMessage 用带超时的变体');
  ok(/WM_SETTEXT/.test(GUI_SCRIPT), '设置文本用 WM_SETTEXT');
  ok(/BM_CLICK/.test(GUI_SCRIPT), '点击用 BM_CLICK（比手拼 WM_COMMAND 更接近真实点击）');
  ok(/EnumChildWindows/.test(GUI_SCRIPT), '用 EnumChildWindows 找控件');
  ok(/GetDlgCtrlID/.test(GUI_SCRIPT), '用 GetDlgCtrlID 支持 control_id');
  ok(/GetWindowThreadProcessId/.test(GUI_SCRIPT), '按 PID 过滤窗口');
  // 优先匹配"确认/提交"类按钮（脚本用 unicode 转义拼模式，保持纯 ASCII）
  ok(/preferPattern/.test(GUI_SCRIPT), '有按钮文本优先匹配模式');
  ok(/0x786E/.test(GUI_SCRIPT) || /confirm/.test(GUI_SCRIPT), '模式含确认类语义（unicode 转义）');
  // WM_SETTEXT 用字符串重载
  ok(/PostMessage\(IntPtr h, uint m, IntPtr w, string l\)/.test(GUI_SCRIPT), 'WM_SETTEXT 用字符串重载');
  // 写完后必须回读校验；不允许无条件声称成功
  ok(/sent-verified/.test(GUI_SCRIPT), 'WM_SETTEXT 后回读校验（sent-verified）');
  ok(/charposted-verified/.test(GUI_SCRIPT), 'WM_CHAR 后回读校验（charposted-verified）');
  ok(/unverified/.test(GUI_SCRIPT), '无法回读时如实报告 unverified（不假装成功）');
  ok(/cross-bitness/.test(GUI_SCRIPT), 'unverified 说明跨位数原因');
  // PostMessage 的数值重载必须显式 EntryPoint
  ok(/EntryPoint = "PostMessageW"/.test(GUI_SCRIPT), 'PostMessage 数值重载显式 EntryPoint（否则 EntryPointNotFoundException）');
  // 脚本必须纯 ASCII
  ok([...GUI_SCRIPT].every(c => c.charCodeAt(0) < 128), 'PowerShell 脚本纯 ASCII（5.1 按 ANSI 读无 BOM 文件）');
}

console.log('\n[4] 工具注册：定义 / dispatch / KNOWN / label / precheck');
{
  ok(/name: "gui_input"/.test(mainSrc), '工具定义存在');
  ok(/case 'gui_input':/.test(mainSrc), 'dispatch 存在');
  const known = mainSrc.slice(mainSrc.indexOf('const KNOWN = new Set(['), mainSrc.indexOf('const KNOWN = new Set([') + 1500);
  ok(/'gui_input'/.test(known), 'KNOWN 含 gui_input');
  ok(/case 'gui_input': return/.test(mainSrc), 'toolLabel 存在');
  const pre = mainSrc.slice(mainSrc.indexOf('function precheckToolCall'), mainSrc.indexOf('function levenshtein'));
  ok(/name === 'gui_input'/.test(pre), 'precheck 存在');
  ok(/list_only/.test(pre), 'precheck 提示 list_only');

  // 描述必须写明适用边界，防止 AI 对自绘 UI 反复空转
  const def = mainSrc.slice(mainSrc.indexOf('name: "gui_input"'), mainSrc.indexOf('name: "browser_search"'));
  ok(/标准控件/.test(def), '描述写明只对标准控件有效');
  ok(/自绘/.test(def), '描述警告自绘 UI 不适用');
  ok(/dbg_run_to/.test(def), '描述解释为什么需要它（run_to 等不到）');
  ok(/PostMessage/.test(def), '描述说明默认用 PostMessage 及原因');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
