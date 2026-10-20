'use strict';
// GUI 输入注入：给被调试的 GUI 程序喂文本并触发按钮。
//
// 为什么需要：CrackMe 系列是对话框程序，校验只在按钮点击（WM_COMMAND）时执行。
// 程序启动后阻塞在消息循环，dbg_run_to(校验地址) 会**永远等不到**——
// 实测 8 轮 continue，IP 全程停在系统 DLL（0x77b8123c），一次都没进用户代码。
// 所以 GUI 题的动态调试必须先把输入喂进去，让程序自己走到校验分支。
//
// 关键时序（踩过的坑）：
//   · 进程被调试器挂起时，SendMessage 会一直阻塞到超时 → 必须用 PostMessage。
//   · PostMessage 在挂起状态下只是**排队**，程序 continue 后才处理——这正是我们要的：
//     先投递，再 continue，然后断点命中。
//   · WM_SETTEXT 属于系统消息（< WM_USER），跨进程 PostMessage 会由系统封送字符串。
//
// 能力边界（必须让 AI 知道）：
//   · 只对**标准控件**有效（Edit / Button）。自绘控件、Qt 自绘窗口、游戏引擎 UI 不吃这套。
//   · 部分程序会检测输入来源或做反调试，可能拒绝。
//   · 这是"模拟用户操作"，程序逻辑一步不少跑；不是跳过 UI 的捷径。

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// PowerShell + Add-Type(P/Invoke)。写成字符串而不是独立 .ps1：
// 打包后 asar 内的文件不能被 powershell 直接执行，运行时落盘最稳。
//
// ⚠️ 脚本内容必须是**纯 ASCII**：Windows PowerShell 5.1 读取无 BOM 的 .ps1 时按系统 ANSI
// 代码页解码（中文系统是 GBK），UTF-8 的中文注释会被拆成乱码，进而让 Add-Type 编译失败
// （实测报 "source code error" 且 stderr 全是 ???）。中文说明只放在 JS 侧的 description 里。
const GUI_SCRIPT = String.raw`param([Parameter(Mandatory=$true)][string]$JsonPath)
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -Raw -Encoding UTF8 $JsonPath | ConvertFrom-Json

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class CtfGui
{
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, string l);
    [DllImport("user32.dll")] public static extern bool PostMessageNum(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, string l, uint flags, uint timeout, out IntPtr res);

    public const uint WM_SETTEXT = 0x000C;
    public const uint BM_CLICK = 0x00F5;

    public static string Txt(IntPtr h) { var sb = new StringBuilder(1024); GetWindowText(h, sb, 1024); return sb.ToString(); }
    public static string Cls(IntPtr h) { var sb = new StringBuilder(256); GetClassName(h, sb, 256); return sb.ToString(); }

    public static List<IntPtr> TopWindows(uint pid, string titleContains)
    {
        var list = new List<IntPtr>();
        EnumWindows((h, l) =>
        {
            uint p; GetWindowThreadProcessId(h, out p);
            if (pid != 0 && p != pid) return true;
            if (!IsWindowVisible(h)) return true;
            var t = Txt(h);
            if (!string.IsNullOrEmpty(titleContains) &&
                t.IndexOf(titleContains, StringComparison.OrdinalIgnoreCase) < 0) return true;
            list.Add(h);
            return true;
        }, IntPtr.Zero);
        return list;
    }

    public static List<IntPtr> Children(IntPtr parent)
    {
        var list = new List<IntPtr>();
        EnumChildWindows(parent, (h, l) => { list.Add(h); return true; }, IntPtr.Zero);
        return list;
    }

    public static string SetText(IntPtr h, string text, bool useSend, int timeoutMs)
    {
        if (useSend)
        {
            IntPtr res;
            IntPtr r = SendMessageTimeout(h, WM_SETTEXT, IntPtr.Zero, text, 0x0002, (uint)timeoutMs, out res);
            return r != IntPtr.Zero ? "sent" : "send-timeout-or-hung";
        }
        return PostMessage(h, WM_SETTEXT, IntPtr.Zero, text) ? "posted" : "post-failed";
    }

    public static string Click(IntPtr btn)
    {
        IntPtr parent = GetParent(btn);
        int id = GetDlgCtrlID(btn);
        bool ok = PostMessageNum(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
        return (ok ? "clicked" : "click-failed") + " parent=" + parent.ToInt64() + " id=" + id;
    }
}
"@

function Emit($obj) {
    # Use [Console]::Out.Write instead of the pipeline: Out-String wraps at console
    # width and truncates very long output, which makes the parser see BAD_JSON
    # (reproduced when enumerating all visible windows).
    $json = $obj | ConvertTo-Json -Depth 6 -Compress
    if ($null -eq $json) { $json = '{"ok":false,"error":"NULL_JSON"}' }
    [Console]::Out.Write($json)
    [Console]::Out.Write([Environment]::NewLine)
    [Console]::Out.Flush()
}

# Caps on window/control counts: keeps output bounded when the machine has many
# top-level windows.
$maxWins = 40
if ($cfg.max_windows) { $maxWins = [int]$cfg.max_windows }
$maxKids = 60
if ($cfg.max_controls) { $maxKids = [int]$cfg.max_controls }

# Non-ASCII button captions are matched via unicode escapes built at runtime,
# so this file stays pure ASCII.
$preferPattern = '(?i)ok|submit|check|login|confirm|go|' + [char]0x786E + [char]0x5B9A + '|' +
    [char]0x786E + [char]0x8BA4 + '|' + [char]0x63D0 + [char]0x4EA4 + '|' +
    [char]0x9A8C + [char]0x8BC1 + '|' + [char]0x6CE8 + [char]0x518C

$pidNum = 0
if ($cfg.pid) { $pidNum = [uint32]$cfg.pid }
$title = ''
if ($cfg.title_contains) { $title = [string]$cfg.title_contains }

$wins = [CtfGui]::TopWindows($pidNum, $title)
$winInfo = @()
foreach ($w in $wins) {
    if ($winInfo.Count -ge $maxWins) { break }
    $kids = @()
    foreach ($c in [CtfGui]::Children($w)) {
        $kids += [pscustomobject]@{
            hwnd  = $c.ToInt64()
            cls   = [CtfGui]::Cls($c)
            id    = [CtfGui]::GetDlgCtrlID($c)
            text  = [CtfGui]::Txt($c)
        }
        if ($kids.Count -ge $maxKids) { break }
    }
    $winInfo += [pscustomobject]@{
        hwnd     = $w.ToInt64()
        title    = [CtfGui]::Txt($w)
        cls      = [CtfGui]::Cls($w)
        controls = $kids
    }
}

if ($cfg.list_only -eq $true) {
    Emit @{ ok = $true; mode = 'list'; windows = $winInfo }
    exit 0
}

if ($wins.Count -eq 0) {
    Emit @{ ok = $false; error = 'NO_WINDOW'; windows = @() }
    exit 0
}

$targetWin = $null
foreach ($wi in $winInfo) {
    if ($wi.controls | Where-Object { $_.cls -match '^Edit$' }) { $targetWin = $wi; break }
}
if (-not $targetWin) { $targetWin = $winInfo[0] }

$edit = $null
if ($cfg.control_id) {
    $want = [int]$cfg.control_id
    $edit = $targetWin.controls | Where-Object { $_.id -eq $want } | Select-Object -First 1
}
if (-not $edit) {
    $edit = $targetWin.controls | Where-Object { $_.cls -match '^Edit$' } | Select-Object -First 1
}
if (-not $edit) {
    Emit @{ ok = $false; error = 'NO_EDIT_CONTROL'; window = $targetWin }
    exit 0
}

$useSend = ($cfg.send_message -eq $true)
$timeout = 800
if ($cfg.send_timeout_ms) { $timeout = [int]$cfg.send_timeout_ms }
$setRes = [CtfGui]::SetText([IntPtr]$edit.hwnd, [string]$cfg.text, $useSend, $timeout)

$clickRes = ''
if ($cfg.submit -ne $false) {
    $btn = $targetWin.controls | Where-Object { $_.cls -match '^Button$' -and $_.text -match $preferPattern } | Select-Object -First 1
    if (-not $btn) { $btn = $targetWin.controls | Where-Object { $_.cls -match '^Button$' } | Select-Object -First 1 }
    if ($btn) {
        $clickRes = [CtfGui]::Click([IntPtr]$btn.hwnd)
    } else {
        $clickRes = 'no-button'
    }
}

Emit @{
    ok        = $true
    mode      = 'inject'
    window    = @{ hwnd = $targetWin.hwnd; title = $targetWin.title; cls = $targetWin.cls }
    control   = @{ hwnd = $edit.hwnd; id = $edit.id; cls = $edit.cls }
    text_set  = $setRes
    submit    = $clickRes
    transport = $(if ($useSend) { 'SendMessageTimeout' } else { 'PostMessage' })
}
`;

// 参数归一化（纯函数，便于单测）
function normalizeGuiInput(input) {
  const i = input || {};
  const out = {
    pid: i.pid == null || i.pid === '' ? 0 : Number(i.pid),
    title_contains: i.title_contains == null ? '' : String(i.title_contains),
    control_id: i.control_id == null || i.control_id === '' ? 0 : Number(i.control_id),
    text: i.text == null ? '' : String(i.text),
    submit: i.submit !== false,
    list_only: i.list_only === true,
    send_message: i.send_message === true,
    max_windows: i.max_windows == null || i.max_windows === '' ? 40 : Number(i.max_windows),
    max_controls: i.max_controls == null || i.max_controls === '' ? 60 : Number(i.max_controls),
  };
  if (!Number.isFinite(out.pid) || out.pid < 0) out.pid = 0;
  if (!Number.isFinite(out.control_id) || out.control_id < 0) out.control_id = 0;
  if (out.pid && out.pid > 0xffffffff) out.pid = 0;
  if (!Number.isFinite(out.max_windows) || out.max_windows <= 0) out.max_windows = 40;
  if (!Number.isFinite(out.max_controls) || out.max_controls <= 0) out.max_controls = 60;
  // 注入模式必须有文本；list_only 不需要
  if (!out.list_only && !out.text) {
    return { error: '需要 text（要喂给输入框的内容）；只想看控件列表请用 list_only:true' };
  }
  // 定位目标：pid 或标题至少给一个，避免"随便找个 Edit 就注入"
  if (!out.list_only && !out.pid && !out.title_contains) {
    return { error: '需要 pid 或 title_contains 定位目标窗口（先用 list_only:true 查看有哪些窗口）' };
  }
  return { value: out };
}

// 解析脚本输出（纯函数）
// 脚本用 [Console]::Out.Write 写一行 JSON；Add-Type 的编译告警可能混在 stdout 前面。
// ⚠️ 不能用 lastIndexOf('{') —— 那会命中 JSON **内部**最后一个嵌套对象，
// 截出来的片段必然解析失败（实测：枚举多个窗口时必现 BAD_JSON）。
// 正确做法：从后往前按行找第一个能整体解析成对象的行。
function parseGuiOutput(stdout) {
  const s = String(stdout == null ? '' : stdout).trim();
  if (!s) return { ok: false, error: 'EMPTY_OUTPUT' };
  const lines = s.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith('{')) continue;
    try {
      const j = JSON.parse(line);
      if (j && typeof j === 'object') return j;
    } catch (e) { /* 继续往前找 */ }
  }
  // 整段就是一行但带前缀时，退化为"从第一个 { 开始"再试一次
  const first = s.indexOf('{');
  if (first >= 0) {
    try {
      const j = JSON.parse(s.slice(first));
      if (j && typeof j === 'object') return j;
    } catch (e) { }
  }
  return { ok: false, error: 'BAD_JSON', raw: s.slice(-400) };
}

/**
 * 执行注入。
 * @param {object} input 见 normalizeGuiInput
 * @param {{spawn?:Function, tempDir?:string, timeoutMs?:number}} deps
 */
function runGuiInput(input, deps) {
  const d = deps || {};
  const norm = normalizeGuiInput(input);
  if (norm.error) return { ok: false, error: norm.error, stage: 'validate' };
  const cfg = norm.value;

  const spawnFn = d.spawn || spawnSync;
  const tmpRoot = d.tempDir || os.tmpdir();
  const stamp = process.pid + '_' + Date.now();
  const scriptPath = path.join(tmpRoot, `ctf_gui_${stamp}.ps1`);
  const jsonPath = path.join(tmpRoot, `ctf_gui_${stamp}.json`);

  try {
    fs.writeFileSync(scriptPath, GUI_SCRIPT, 'utf8');
    fs.writeFileSync(jsonPath, JSON.stringify(cfg), 'utf8');
    const r = spawnFn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', scriptPath, '-JsonPath', jsonPath,
    ], {
      windowsHide: true,
      timeout: d.timeoutMs || 30000,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    const stdout = r && r.stdout ? String(r.stdout) : '';
    const stderr = r && r.stderr ? String(r.stderr) : '';
    const parsed = parseGuiOutput(stdout);
    if (!parsed.ok) {
      return {
        ok: false,
        error: parsed.error,
        stage: 'script',
        script_stderr: stderr.slice(-800),
        script_stdout_tail: stdout.slice(-800),
      };
    }
    return Object.assign({ stage: 'done' }, parsed);
  } catch (e) {
    return { ok: false, error: e.message, stage: 'spawn' };
  } finally {
    try { fs.unlinkSync(scriptPath); } catch (e) { }
    try { fs.unlinkSync(jsonPath); } catch (e) { }
  }
}

module.exports = { normalizeGuiInput, parseGuiOutput, runGuiInput, GUI_SCRIPT };
