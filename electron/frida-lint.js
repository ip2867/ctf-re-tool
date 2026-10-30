'use strict';
// Frida 脚本的结构性 lint / 修复（纯函数，零 Electron 依赖）
//
// ── 为什么需要（NaughtyBoy 实测）──────────────────────────────────
// 生成的 Frida 脚本注入了，但整轮 0 条 [DATA] 输出。事后看脚本原文，发现
// AI 在"重新生成"时把模板里的区块注释写坏了：
//
//     / ============ 1. Java 层 ============ /     ← 本该是 //
//
// 这在**语法上是合法的**：`/ ============ 1. Java 层 ============ /` 是一个
// 正则字面量表达式语句（内容是一串等号）。所以 `vm.Script` 解析通过、
// 校验器返回 ok，脚本照常注入——然后整段注释消失、后续代码语义错乱。
//
// 这类"语法合法但意图被破坏"的问题，语法校验天然抓不到，必须做结构性 lint：
//   · 以 `/` 开头、不是 `//` 也不是 `/*`、且明显是横幅/注释形态的行
//   · 模板分隔符（[FRIDA_SCRIPT] 之外的区块标记）被改写
//   · 中文注释被当代码
//
// 本模块只做**判定 + 定点修复**，不重写脚本，避免引入新风险。

// 横幅/注释形态：整行只有 `/ ... /`，里面是重复符号或中文说明
const BANNER_RE = /^(\s*)\/\s*([=~\-*#_]{3,}|[\u4e00-\u9fa5][^\n]*?)\s*\/\s*$/;
// 更宽松：行首单个 / + 空格，且行尾也是 /（AI 常把 // 写成 / ... /）
const LOOSE_BANNER_RE = /^(\s*)\/\s+([^\n]*?)\s*\/\s*$/;

/**
 * 结构性 lint。
 * @returns {{ok:boolean, issues:Array<{line:number, code:string, text:string, hint:string}>}}
 */
function lintFridaScript(src) {
  const code = String(src == null ? '' : src);
  const lines = code.split(/\r?\n/);
  const issues = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();
    if (!t) continue;

    // 已经是正常注释 / 字符串 / 正则开头 → 跳过
    if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) continue;

    // 规则 1：整行形如  / ==== 标题 ==== /
    if (BANNER_RE.test(t)) {
      issues.push({
        line: i + 1, code: 'BROKEN_BANNER_COMMENT', text: t,
        hint: '这行是想写 // 注释，但被写成了 / ... /（语法上是正则字面量，不报错但注释失效）',
      });
      continue;
    }

    // 规则 2：行首 `/` + 空格 + 中文/说明文字 + 行尾 `/`
    if (LOOSE_BANNER_RE.test(t) && !/^\/[^/\s]/.test(t)) {
      issues.push({
        line: i + 1, code: 'BROKEN_BANNER_COMMENT', text: t,
        hint: '疑似把 // 注释写成 / ... /，注释会失效',
      });
      continue;
    }

    // 规则 3：裸正则字面量当语句（`/xxx/;`）几乎总是坏注释的残留
    if (/^\/[^/*][^\n]*\/\s*;?\s*$/.test(t) && !/[(){}[\]]/.test(t) && t.length > 12) {
      issues.push({
        line: i + 1, code: 'SUSPECT_REGEX_STATEMENT', text: t,
        hint: '这一行是"只有正则字面量"的表达式语句，通常说明注释被写坏',
      });
    }
  }

  // 规则 4：模板骨架是否完整（关键 hook 段存在性）
  const has = (re) => re.test(code);
  if (!has(/Java\.perform\s*\(/) && !has(/Interceptor\.attach\s*\(/)) {
    issues.push({
      line: 0, code: 'MISSING_HOOK_BODY', text: '',
      hint: '脚本里既没有 Java.perform 也没有 Interceptor.attach —— 不像有效的 hook 脚本',
    });
  }

  return { ok: issues.length === 0, issues };
}

/**
 * 定点修复：只把"坏横幅注释"改回 `//`，其余一律不动。
 * 不做任何全局替换，避免误伤正常正则。
 * @returns {{script:string, fixed:number}}
 */
function repairFridaScript(src) {
  const code = String(src == null ? '' : src);
  const lines = code.split(/\r?\n/);
  let fixed = 0;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();
    if (!t || t.startsWith('//') || t.startsWith('/*')) continue;
    if (BANNER_RE.test(t) || (LOOSE_BANNER_RE.test(t) && !/^\/[^/\s]/.test(t))) {
      const indent = (raw.match(/^\s*/) || [''])[0];
      lines[i] = indent + '//' + t.slice(1, t.endsWith('/') ? -1 : undefined);
      fixed++;
    }
  }
  return { script: lines.join('\n'), fixed };
}

/** lint + 修复 + 复检，一步到位。 */
function lintAndRepair(src) {
  const before = lintFridaScript(src);
  if (before.ok) return { ok: true, script: String(src || ''), repairs: [], remaining: [] };
  const r = repairFridaScript(src);
  const after = lintFridaScript(r.script);
  return {
    ok: after.ok,
    script: r.script,
    repairs: before.issues.filter(x => x.code === 'BROKEN_BANNER_COMMENT'),
    remaining: after.issues,
  };
}

module.exports = { lintFridaScript, repairFridaScript, lintAndRepair, BANNER_RE, LOOSE_BANNER_RE };
