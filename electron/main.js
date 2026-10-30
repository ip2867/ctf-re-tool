const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { exec, spawn, spawnSync } = require('child_process');
const fs = require('fs');
const zlib = require('zlib');
const http = require('http');
const https = require('https');
const { Client: SshClient } = require('ssh2');
// Agent 运行时（上下文压缩/重复调用护栏/会话持久化），详见 electron/agent-runtime.js
const {
  persistToolResult, microcompact, buildToolNameMap, DoomLoopGuard, FailureLoopGuard,
  estimateTokens, SessionLog, sanitizeHistoryForResume, compactHistoryDeterministic, pruneDir,
} = require('./agent-runtime');
// 去重闸的地址目标指纹层（纯函数，无 Electron 依赖）
const { createDedupState, checkDedup, setScriptSimilarity } = require('./script-dedup');
// 工具结果的形态解析与失败判定（纯函数，测试可在无 Electron 的 Node 下直接跑）
const {
  ToolCallError, toToolResult,
  idaGetBytes, scanCryptoCase, runBash,
} = require('./tool-result');
// 编译器产物层面的确定性指纹：散落的 MD5 K 轮常量、多 lane 存放的双射表（rank 6）
const { detectMd5RoundConstants, detectLaneBijectionTables } = require('./crypto-detect');
// IDA 列表工具的分页契约（插件默认 count=100，只取一页会得到残缺函数表/全局表）
const { callPaged } = require('./ida-paging');
// IDA MCP 扩展组 URL（?ext=dbg）与会话重置判定
const { idaMcpEffectiveUrl, needsSessionReset } = require('./ida-mcp-url');
// dbg_* 真实工具名 -> 两个合并 AI 工具（ida_dbg / ida_dbg_mem）的映射
const { buildDbgCall, normalizeHex, normalizeAddrList, normalizeRegions, normalizeBpItems, dbgStateName } = require('./ida-dbg');
// tools/list 结果 -> 调试能力判定（白名单完整词，替代 'ea'/'ip' 子串匹配）
const { classifyIdaDebugTools } = require('./ida-debug-capability');
// 自修改特征（W+X 节/可写代码段/反调试导入）
const { detectSmcSignals } = require('./smc-detect');
// 花指令（junk code / opaque predicate）识别与修补：判据基于控制流而非字节匹配
const { scanJunk: junkScan, scanJunkRecursive: junkScanRecursive, patchJunk: junkPatch } = require('./junk-code');
// 指令边界重建（不修改字节，从入口沿控制流建立正确的指令起点集合）
const { buildBoundaryMap } = require('./boundary-map');
// 花指令签名式修补（只 nop 跳转本身，字节偏移不变）
const { scanJunkFeatures, scanJunkFeatures: repairJunk, applyRepair, FEATURES: JUNK_FEATURES } = require('./junk-repair');
const { decodeInsn } = require('./junk-code');
// MD5 摘要目标的"存在性"闸门（16B 对齐 + Shannon>=7.5，排除 .rsrc/.reloc）
const { assessHashTarget, buildMd5Note, extractDigestCallSites } = require('./hash-hint');
// 指纹表的 xref 闸门（32 位 PE 绝对引用回退；x64/ELF 不降级）
const { assessTableRefs, isRefutedByRefs } = require('./xref-gate');
// 表地址/节表解析（缺口计算与 xref 闸门共用）
const { parseImageMap } = require('./binary-map');
// 文件能力分诊（容器/文件系统/流量/文本/可执行）
const { detectCapabilities, decideRoute } = require('./file-capability');
// 远程执行错误分类（Kali SSH）
const { classifyRemoteError } = require('./remote-exec');
// Kali 远程预检决策（不可达时跳过远程命令，别白等 3 次 60s 超时）
const { decideKaliPreflight, decideKaliRemotePlan } = require('./kali-preflight');
// PCAP 解析（仅 Node 标准库）
const pcap = require('./pcap');
// run_python 的工作目录与产物扫描
const { pickPythonCwd, snapshotDir, scanNewArtifacts } = require('./py-artifacts');

// ============ 全局异常兜底（防闪退） ============
// 之前主进程没有任何 uncaughtException/unhandledRejection 处理：任意一个后台任务
// （AI 流、Frida、脚本、adb 回调）抛出未捕获异常，Electron 会直接退出 → 表现为"工具闪退"。
// 这里统一捕获、落盘日志、并保持进程存活，让功能继续可诊断、可恢复。
function _crashLog(tag, err) {
  try {
    const line = `[${new Date().toISOString()}] [${tag}] ` + (err && (err.stack || err.message)) + '\n';
    fs.appendFileSync(path.join(app.getPath('userData'), 'crash.log'), line);
  } catch (e) { /* 落盘失败也不能再抛 */ }
  try { console.error(`[${tag}]`, err); } catch (e) {}
}
process.on('uncaughtException', (err) => { _crashLog('uncaughtException', err); });
process.on('unhandledRejection', (reason) => { _crashLog('unhandledRejection', reason instanceof Error ? reason : new Error(String(reason))); });


// Claude API 基础配置（从 CC Switch 读取环境变量；config.claude 可覆盖 baseUrl/model/max_tokens）
// 注意：baseUrl 默认留空，必须由环境变量或设置页提供——不在源码里硬编码任何(私有)中转地址。
const CLAUDE_ENV = {
  // 兼容 CCSwitch / Claude Code 环境变量；CTF_* 仅作为显式覆盖项
  baseUrl: process.env.CTF_CLAUDE_BASE_URL || process.env.ANTHROPIC_BASE_URL || '',
  apiKey: process.env.CTF_CLAUDE_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN || process.env.ANTHROPIC_API_KEY || '',
  model: process.env.CTF_CLAUDE_MODEL || process.env.ANTHROPIC_MODEL || 'glm-5.3'
};

// 合并环境变量与用户配置，得到当前生效的 AI 配置
function getClaudeConfig() {
  const c = (config && config.claude) || {};
  return {
    baseUrl: c.baseUrl || CLAUDE_ENV.baseUrl,
    apiKey: (c.apiKey && String(c.apiKey).trim()) || CLAUDE_ENV.apiKey,
    model: c.model || CLAUDE_ENV.model,
    // 模型分级（cascade）：初步求解先用快速模型，未出 flag 再升级思考模型。
    // 留空 = 禁用分级，全部走 model。fastMaxTokens 给快速模型用（非思考模型 8192 足够）。
    fastModel: c.fastModel || '',
    fastMaxTokens: Number(c.fastMaxTokens) || 8192,
    // GLM 等带"思考模式"的模型会先消耗大量 token 推理，8192 会在思考阶段耗尽
    // （stop_reason=max_tokens，正文为空只剩思考文本），故放宽到 16384。
    max_tokens: Number(c.max_tokens) || 16384,
    stream: c.stream !== false
  };
}

// 配置文件路径
const CONFIG_PATH = path.join(app.getPath('userData'), 'config.json');

// 可写根目录：开发态用应用目录；打包后 app.getAppPath() 指向只读 asar，
// 取证/脚本等落盘必须改到 userData 下，否则写入会失败。
function writableBase() {
  return app.isPackaged ? app.getPath('userData') : app.getAppPath();
}

// 默认配置
const DEFAULT_CONFIG = {
  tools: {
    // 以下为占位示例：首次运行请在应用「设置」页改成自己机器上的实际路径。
    // 静态分析工具
    ida: '',
    ida64: '',
    die: '',
    diec: '',
    jeb: '',
    jadx: '',
    pycdc: '',
    pycdas: '',

    // 脱壳工具
    upx: '',

    // APK工具
    apktool: '',
    apkckgj: '',

    // 辅助
    vscode: '',
    jebMcpPy: '',
    // Burp 启动器：如需免 GUI 自动加载 MCP Server 扩展，可指向自定义启动脚本
    burp: '',

    // 模拟器
    nox_adb: ''
  },
  emulator: {
    adb_port: 62025,
    frida_port: 27042,
    nox_path: '',
    nox_instance: ''
  },
  web: {
    // Burp 代理端口（浏览器经此代理进 Burp）；留空则自动探测 Chrome/Edge
    proxy_port: 8080,
    browser_path: '',
    // JS 逆向动态调试：受控浏览器 CDP 端口
    debug_port: 9223
  },
  mcp: {
    ida: 'http://127.0.0.1:13337/mcp',
    // 插件把 dbg_* 标为 @ext("dbg")，未在 URL 上启用该组时 tools/list 根本看不到它们。
    // 主进程会在 idaMcpGetBaseUrl 里追加 ?ext=...（见 electron/ida-mcp-url.js）。
    idaExtensions: ['dbg'],
    jebMcp: 'http://127.0.0.1:16161/mcp',
    // Burp MCP（官方 PortSwigger 扩展为 SSE 传输，默认 9876；客户端 auto 兼容 SSE/Streamable HTTP）
    burp: 'http://127.0.0.1:9876',
    // 可选：独立 JEB MCP server.py 所在目录（留空 = 依赖 JEB 插件自带 HTTP 服务）
    jebMcpScript: '',
    // 可选：自备的浏览器 MCP（SSE 端点）；留空则用内置受控浏览器 CDP
    browser: '',
    // CTF²（DASCTF Agent Arena）开放平台 MCP：练习题/附件/提交 flag。
    // 鉴权用环境变量式 Bearer Token；Token 留空表示未配置（在设置页填写，只存 userData/config.json）。
    ctf2: 'https://ctf2.dasctf.com/api/ai/v1/mcp',
    ctf2Token: ''
  },
  kali: {
    vmxPath: '',
    sshHost: '',
    sshPort: 22,
    sshUser: '',
    // 密码不写入源码：首次使用请在设置中填写（保存到用户目录 config.json）
    sshPass: ''
  },
  claude: {
    // 留空则使用环境变量（CCSwitch）；max_tokens/stream 可在设置页调整
    baseUrl: '',
    apiKey: '',
    model: '',
    // 模型分级：初步求解先走快速模型（省 token、提速），未出 flag 自动升级 model
    fastModel: 'glm-5.3',
    fastMaxTokens: 8192,
    max_tokens: 32768,
    stream: true
  },
  cases: {
    // 取证目录修剪：保留最近 keep 个 case，超出移入 cases/_archive/，
    // 归档超过 archiveKeep 个再真正删除最旧的（rename 同卷瞬时完成，可人工找回）
    keep: 20,
    archiveKeep: 60
  },
  workspace: {
    // 脚本/WP 输出目录，空则用应用目录下的 scripts/
    scriptsDir: ''
  },
  platform: {
    // CTF² 平台拉题：附件下载目录（默认 E:\ctf\pratice）
    downloadDir: 'E:\\ctf\\pratice',
    // 批量解题跳过清单（题名数组）：人工已解出/不想自动跑的题
    skipChallenges: []
  }
};

let mainWindow;
let isQuitting = false;   // 主动退出标记（quit-app IPC / before-quit）
let config = { ...DEFAULT_CONFIG };

// 深合并配置（避免浅合并覆盖掉 mcp/kali/emulator 等嵌套默认值）
function deepMerge(base, override) {
  const out = Array.isArray(base) ? base.slice() : Object.assign({}, base);
  for (const key of Object.keys(override || {})) {
    const bv = base && base[key];
    const ov = override[key];
    if (ov && typeof ov === 'object' && !Array.isArray(ov) && bv && typeof bv === 'object' && !Array.isArray(bv)) {
      out[key] = deepMerge(bv, ov);
    } else {
      out[key] = ov;
    }
  }
  return out;
}

// 加载配置
function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const data = fs.readFileSync(CONFIG_PATH, 'utf8');
      config = deepMerge(DEFAULT_CONFIG, JSON.parse(data));
    } else {
      saveConfig();
    }
  } catch (err) {
    console.error('加载配置失败:', err);
    config = deepMerge(DEFAULT_CONFIG, {});
  }
}

// 保存配置
function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  } catch (err) {
    console.error('保存配置失败:', err);
  }
}

// 创建主窗口
function createWindow() {
  const iconPath = path.join(__dirname, '..', 'assets', 'icons', 'icon.ico');
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    },
    frame: false,
    titleBarStyle: 'hidden',
    ...(fs.existsSync(iconPath) ? { icon: iconPath } : {}),
    show: false
  });

  // 导航锁定：本应用只应停留在本地 index.html，禁止渲染层被导航到外部页面
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const target = String(url || '');
    if (!target.startsWith('file://')) {
      event.preventDefault();
      if (/^https?:\/\//i.test(target)) shell.openExternal(target).catch(() => {});
    }
  });

  // 新窗口一律交给系统浏览器，不在应用内开新窗口（防钓鱼页/权限逃逸）
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(String(url || ''))) {
      shell.openExternal(url).catch(() => {});
    }
    return { action: 'deny' };
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'src', 'index.html'));

  // 渲染进程崩溃/被 OOM 杀死时自动重载，避免窗口空白（"闪退"观感）
  mainWindow.webContents.on('render-process-gone', (event, details) => {
    _crashLog('render-process-gone', new Error(JSON.stringify(details)));
    try { if (details && details.reason !== 'clean-exit') mainWindow.reload(); } catch (e) {}
  });
  mainWindow.webContents.on('unresponsive', () => { _crashLog('unresponsive', new Error('webContents unresponsive')); });

  // 窗口准备好后显示
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // 开发模式打开开发者工具
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  // 窗口状态变化时通知渲染进程
  mainWindow.on('maximize', () => {
    mainWindow.webContents.send('window-state-changed', 'maximized');
  });

  mainWindow.on('unmaximize', () => {
    mainWindow.webContents.send('window-state-changed', 'normal');
  });
}

// 应用准备就绪
app.whenReady().then(() => {
  loadConfig();
  createWindow();

  // 主动"钉住" adb daemon 版本：用我们选定的 adb 先 start-server，
  // 让 5037 上的 daemon 与我们的客户端版本一致，减少与 nox_adb(v36) 的互杀窗口。
  // 失败不阻塞启动（用户可能还没装/没配置 adb）。
  try {
    const adb = resolveAdbPath();
    if (adb && adb !== 'adb') {
      const child = spawn(adb, ['start-server'], { shell: false, windowsHide: true, detached: true, stdio: 'ignore' });
      child.on('error', () => {});
      child.unref();
      console.log('[adb] 已用', adb, 'start-server 固定 daemon 版本');
    }
  } catch (e) { /* 忽略：无 adb 时不影响其它功能 */ }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// 所有窗口关闭
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC 通信处理

// 获取配置
ipcMain.handle('get-config', () => {
  return config;
});

// 保存配置
ipcMain.handle('save-config', (event, newConfig) => {
  config = deepMerge(config, newConfig || {});
  saveConfig();
  return { success: true };
});

// 在 zip（apk/jar）中央目录里找指定文件名，用于区分 APK/JAR/普通 ZIP
function zipContainsEntry(filePath, name) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const size = fs.fstatSync(fd).size;
    const tailLen = Math.min(size, 66000); // 中央目录最大可能在文件尾部 64KB+ 区域
    const buf = Buffer.alloc(tailLen);
    fs.readSync(fd, buf, 0, tailLen, size - tailLen);
    fs.closeSync(fd);
    return buf.includes(Buffer.from(name, 'utf8'));
  } catch (e) {
    return false;
  }
}

// 在文件头 n 字节中查找 ASCII 特征串（如 mscoree / AU3!）
function headContains(filePath, needle, n = 8192) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(n);
    const read = fs.readSync(fd, buf, 0, n, 0);
    fs.closeSync(fd);
    return buf.slice(0, read).includes(Buffer.from(needle, 'utf8'));
  } catch (e) {
    return false;
  }
}

// 纯 Node 解压 ZIP 中的部分条目（只用内置 zlib/fs）——
// 避免 shell 的 Expand-Archive / 中文路径在 exec 下按 GBK 解码导致乱码，
// 进而出现 "Can't find input file ...????????.so" 一类问题。
function extractZipEntries(zipPath, filterFn, outBaseDir) {
  const fd = fs.openSync(zipPath, 'r');
  const size = fs.fstatSync(fd).size;
  // 定位中央目录结束记录 EOCD (0x06054b50)
  const tailLen = Math.min(size, 66000);
  const tail = Buffer.alloc(tailLen);
  fs.readSync(fd, tail, 0, tailLen, size - tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) { fs.closeSync(fd); throw new Error('非 ZIP 或中央目录缺失'); }
  const cdOffset = tail.readUInt32LE(eocd + 16);
  const cdCount = tail.readUInt16LE(eocd + 10);
  // 读中央目录
  const cd = Buffer.alloc(Math.min(size - cdOffset, 1 << 20));
  fs.readSync(fd, cd, 0, cd.length, cdOffset);
  const results = [];
  let p = 0;
  for (let n = 0; n < cdCount && p + 46 <= cd.length; n++) {
    if (cd.readUInt32LE(p) !== 0x02014b50) break;
    const method = cd.readUInt16LE(p + 10);
    const compSize = cd.readUInt32LE(p + 20);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    const localOffset = cd.readUInt32LE(p + 42);
    const name = cd.slice(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;
    if (!filterFn(name)) continue;
    // 读本地头，跳过文件名/扩展区，定位数据
    const lh = Buffer.alloc(30);
    fs.readSync(fd, lh, 0, 30, localOffset);
    const lNameLen = lh.readUInt16LE(26);
    const lExtraLen = lh.readUInt16LE(28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    const raw = Buffer.alloc(compSize);
    fs.readSync(fd, raw, 0, compSize, dataStart);
    const data = method === 0 ? raw : zlib.inflateRawSync(raw);
    // 输出路径：outBase 可为目录字符串或 (entryName)=>目标完整路径 的函数
    // （用 basename / 函数返回，均防 zip-slip）
    const outPath = (typeof outBaseDir === 'function')
      ? outBaseDir(name)
      : path.join(outBaseDir, path.basename(name));
    fs.writeFileSync(outPath, data);
    results.push({ entry: name, outPath, size: data.length });
  }
  fs.closeSync(fd);
  return results;
}

// 源码类扩展名 → 语言名。
// 这些是"人写的文本"，正确入口是**读全文按语言语义分析**，不是固件采集也不是 IDA。
// 单独列出来（而不是塞进 TXT）是为了让提示词能给出对的方向：
// .py 沙箱逃逸题和 .c 算法题需要完全不同的分析套路。
const SOURCE_LANG = {
  '.py': 'Python', '.pyw': 'Python',
  '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell',
  '.c': 'C', '.h': 'C/C++ 头文件', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++', '.hpp': 'C++ 头文件',
  '.go': 'Go', '.rs': 'Rust', '.rb': 'Ruby', '.php': 'PHP',
  '.java': 'Java', '.kt': 'Kotlin', '.swift': 'Swift',
  '.lua': 'Lua', '.pl': 'Perl', '.r': 'R',
  '.jsx': 'JSX', '.tsx': 'TSX', '.ts': 'TypeScript', '.vue': 'Vue',
  '.cs': 'C#', '.m': 'Objective-C', '.sql': 'SQL',
  '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS',
  '.ini': 'INI 配置', '.conf': '配置文件', '.toml': 'TOML',
};
const SOURCE_EXTS = Object.keys(SOURCE_LANG);

// 从自然语言消息里解析"要分析哪个文件"。
//
// 为什么需要：用户最自然的交互是把路径直接写在聊天里
//   E:\ctf\...\驱动逆向\attachment_x\驱动逆向 这个有两个文件是一道ctf逆向题目，你打开后求解flag
// 旧实现只认对话框选中的文件 → 命中"求解flag"快捷命令 → autoAnalyze() → 「请先选择文件」
// → 用户看到的就是"他不理我"。
//
// 返回 { success, path, kind, candidates, expanded }
//   · 路径存在且是文件 → path 就是它
//   · 路径存在且是目录 → 自动展开，挑出"最像题目主文件"的一个（见 pickMainFile）
//   · 都不存在 → success:false，但要说明"哪几个候选试过了"，避免静默失败
ipcMain.handle('resolve-message-path', async (event, message) => {
  try {
    const { pickPathFromMessage, extractPaths } = require('./path-intent');
    const pick = pickPathFromMessage(message);
    if (!pick) return { success: false, reason: '消息里没有绝对路径' };

    const tried = [];
    const tryOne = (p) => {
      tried.push(p);
      try {
        if (!fs.existsSync(p)) return null;
        const st = fs.statSync(p);
        return { p, isDir: st.isDirectory(), size: st.size };
      } catch (e) { return null; }
    };

    // 先试挑中的那个，再试消息里的其它候选（用户常先说目录再说文件）
    let hit = tryOne(pick.path);
    if (!hit) {
      for (const p of pick.all) {
        if (p === pick.path) continue;
        hit = tryOne(p);
        if (hit) break;
      }
    }
    // 仍找不到：试着把路径尾部当作"目录 + 子名"，或用上层传入的 base 目录拼
    if (!hit) {
      return {
        success: false,
        reason: `路径不存在：${pick.path}`,
        candidates: pick.all,
        tried,
      };
    }

    if (!hit.isDir) {
      return { success: true, path: hit.p, kind: 'file', candidates: pick.all, tried };
    }

    // 目录：展开，挑主文件
    let entries = [];
    try { entries = fs.readdirSync(hit.p, { withFileTypes: true }); } catch (e) { entries = []; }
    const files = [];
    const subdirs = [];
    for (const ent of entries) {
      const full = path.join(hit.p, ent.name);
      if (ent.isDirectory()) subdirs.push(full);
      else {
        let size = 0;
        try { size = fs.statSync(full).size; } catch (e) { size = 0; }
        files.push({ path: full, name: ent.name, size });
      }
    }
    const best = pickMainFile(files);
    if (best) {
      return {
        success: true, path: best.path, kind: 'file',
        pickedFromDir: hit.p, candidates: pick.all, tried,
        dirFiles: files.map(f => ({ name: f.name, size: f.size })),
      };
    }
    // 目录里没文件（只有子目录）→ 往下钻一层
    for (const sd of subdirs.slice(0, 6)) {
      try {
        const subs = fs.readdirSync(sd)
          .map(n => {
            const full = path.join(sd, n);
            let size = 0, isDir = false;
            try { const st2 = fs.statSync(full); size = st2.size; isDir = st2.isDirectory(); } catch (e) { }
            return isDir ? null : { path: full, name: n, size };
          })
          .filter(Boolean);
        const b2 = pickMainFile(subs);
        if (b2) {
          return {
            success: true, path: b2.path, kind: 'file',
            pickedFromDir: sd, candidates: pick.all, tried,
            dirFiles: subs.map(f => ({ name: f.name, size: f.size })),
          };
        }
      } catch (e) { /* 单个子目录失败不影响其它 */ }
    }
    return {
      success: false,
      reason: `目录里没找到可分析的文件：${hit.p}`,
      candidates: pick.all, tried,
      dirFiles: files.map(f => ({ name: f.name, size: f.size })),
    };
  } catch (e) {
    return { success: false, reason: e.message };
  }
});

// 从目录的文件列表里挑"最像题目主文件"的那个。
// 规则：可执行/题意载体优先，纯文档（说明/图片）垫底。
function pickMainFile(files) {
  if (!Array.isArray(files) || !files.length) return null;
  const score = (f) => {
    const n = String(f.name || '').toLowerCase();
    let s = 0;
    // 明确的可分析载体
    if (/\.(apk|exe|dll|elf|so|out|bin|py|pyc|dex|jar|wasm|luac|class)$/.test(n)) s += 10;
    else if (/\.(c|cpp|h|hpp|go|rs|js|mjs|html?|php|rb|lua|sh|txt|enc|json|xml|pcap|pcapng)$/.test(n)) s += 6;
    // 说明/图片/压缩包：通常是材料而非主文件
    if (/\.(md|png|jpg|jpeg|gif|bmp|svg|pdf|docx?|pptx?|xlsx?)$/.test(n)) s -= 8;
    if (/\.(zip|rar|7z|tar|gz)$/.test(n)) s -= 3;
    // 名字像说明文件的
    if (/^(readme|说明|instructions?|hint|题目描述|writeup)/i.test(n)) s -= 10;
    // 体积：太小可能是碎片，太大可能是素材；中间区间给一点分
    if (f.size > 1024) s += 2;
    if (f.size > 100 * 1024) s += 1;
    return s;
  };
  const sorted = files.slice().sort((a, b) => score(b) - score(a) || b.size - a.size);
  return sorted[0] || null;
}

// 文件类型检测
ipcMain.handle('detect-file-type', async (event, filePath) => {
  try {
    console.log('detect-file-type called with:', filePath);

    const ext = path.extname(filePath).toLowerCase();
    const fileName = path.basename(filePath);

    console.log('Extension:', ext, 'FileName:', fileName);

    // 检查文件是否存在
    if (!fs.existsSync(filePath)) {
      console.log('File does not exist:', filePath);
      return { success: false, error: '文件不存在: ' + filePath };
    }

    // 读取文件头（魔数）
    const buffer = Buffer.alloc(16);
    let fd;
    try {
      fd = fs.openSync(filePath, 'r');
      fs.readSync(fd, buffer, 0, 16, 0);
    } catch (openErr) {
      // Windows Defender 等杀软会拦截对特定样本的**任何**读取，Node 报的是
      // `UNKNOWN: unknown error, open '...'`（无 errno，极易被当成路径错误）。
      // 实测（CrackMe4）：解压成功、文件在盘上，但整题 1 秒"跳过"，报告里记为工具失败。
      // 这里显式识别并给出可操作诊断，让调用方能把它归为**环境阻断**而不是解题失败。
      const msg = String(openErr && openErr.message || '');
      const blocked = /UNKNOWN|EPERM|EACCES|operation not permitted/i.test(msg) | (openErr && openErr.code === 'UNKNOWN');
      if (blocked && fs.existsSync(filePath)) {
        const st = (() => { try { return fs.statSync(filePath); } catch (e) { return null; } })();
        return {
          success: false,
          blocked: true,
          fileType: 'BLOCKED',
          error: `文件存在但无法读取（${st ? st.size + ' 字节' : '大小未知'}）——典型原因是被杀软/Defender 实时保护拦截。`
            + `请在 Windows 安全中心把该目录（${path.dirname(filePath)}）加入排除项后重试；`
            + `本工具无法绕过系统级文件访问拦截。`,
          rawError: msg,
        };
      }
      throw openErr;
    } finally {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch (e) {} }
    }

    const magic = buffer.toString('hex', 0, 4).toUpperCase();
    console.log('Magic:', magic);

    let fileType = 'UNKNOWN';
    let description = '';

    // PCAP/PCAPNG：魔数优先于扩展名。四种 pcap 魔数（LE/BE × 微秒/纳秒）+ pcapng。
    // 旧代码没有这一分支 → 样本落进 UNKNOWN → 被送进 Kali 固件流程（3 次 SSH 超时白等）。
    if (['D4C3B2A1', 'A1B2C3D4', '4D3CB2A1', 'A1B23C4D', '0A0D0D0A'].includes(magic)) {
      fileType = 'PCAP';
      description = magic === '0A0D0D0A' ? 'PCAPNG 抓包' : 'PCAP 抓包（可提取 TCP 流）';
      return {
        success: true,
        fileType,
        capabilities: { pcap: true, pcapng: magic === '0A0D0D0A' },
        description,
        extension: ext,
        fileName
      };
    }

    // DEX 检测（魔数优先于扩展名）
    if (magic === '6465780A' || ext === '.dex') {
      fileType = 'DEX';
      description = 'Dalvik Executable';
    }
    // SO/ELF 检测
    else if (magic === '7F454C46' || ext === '.so') {
      fileType = 'ELF';
      description = 'Executable and Linkable Format';
      // 检测架构
      const arch = buffer[4]; // 1=32bit, 2=64bit
      description += arch === 2 ? ' (64-bit)' : ' (32-bit)';
    }
    // WASM 检测
    else if (magic === '0061736D') {
      fileType = 'WASM';
      description = 'WebAssembly';
    }
    // Lua 字节码（"\x1bLua"）
    else if (magic.startsWith('1B4C7561') || ext === '.luac') {
      fileType = 'LUAC';
      description = 'Lua Bytecode（可用 unluac 反编译）';
    }
    // Mach-O / Java class（fat binary 与 .class 同为 CAFEBABE，按扩展名区分）
    else if (ext === '.class') {
      fileType = 'JAVA_CLASS';
      description = 'Java Class（可用 jadx 反编译）';
    }
    else if (magic === 'FEEDFACE' || magic === 'FEEDFACF' || magic === 'CEFAEDFE' || magic === 'CFFAEDFE') {
      fileType = 'MACHO';
      description = 'Mach-O Binary';
    }
    else if (magic === 'CAFEBABE') {
      // 非法 fat Mach-O 的魔数与 Java class 相同：无 .class 扩展名时倾向 fat Mach-O
      fileType = 'MACHO';
      description = 'Mach-O Fat Binary 或 Java Class（魔数相同，请确认扩展名）';
    }
    // PYC 检测：CPython 魔数为 2 字节小端 + 0D 0A，且高字节恒为 0x0D（如 55 0D 0D 0A / CB 0D 0D 0A）
    // 只凭字节 2-3 是 \r\n 会把 "ab\r\n" 开头的文本误判成 PYC，必须同时校验 buffer[1]
    else if (ext === '.pyc' || (buffer[1] === 0x0D && buffer[2] === 0x0D && buffer[3] === 0x0A && magic !== '4D5A')) {
      fileType = 'PYC';
      description = 'Python Bytecode';
    }
    // PE 检测（PE 魔数 MZ 是 2 字节，需匹配 8 位 hex 的前 4 位）
    else if (magic.startsWith('4D5A') || ext === '.exe' || ext === '.dll') {
      fileType = 'PE';
      description = 'Portable Executable';
      // .NET 程序头几 KB 内会引用 mscoree.dll
      if (headContains(filePath, 'mscoree')) {
        description += ' (.NET，建议 dnSpy/ilspycmd)';
      }
      // AutoIt 编译脚本特征
      if (headContains(filePath, 'AU3!')) {
        description += ' (内嵌 AutoIt 脚本，可用 MyAut2Exe 提取)';
      }
    }
    // APK / JAR / ZIP / OOXML 区分：同为 PK 头，看中央目录内容
    else if (magic === '504B0304' || ext === '.zip' || ext === '.apk' || ext === '.jar') {
      if (ext === '.apk' || zipContainsEntry(filePath, 'AndroidManifest.xml')) {
        fileType = 'APK';
        description = 'Android Package';
      } else if (ext === '.jar' || zipContainsEntry(filePath, 'META-INF/MANIFEST.MF')) {
        fileType = 'JAR';
        description = 'Java Archive（可用 jadx 反编译）';
      } else if (ext === '.xlsx' || ext === '.xlsm' || zipContainsEntry(filePath, 'xl/workbook.xml')) {
        fileType = 'XLSX';
        description = 'Excel Workbook（OOXML；ExceLLM 类"Excel 逆向"题载体，按 ZIP 容器解压分析）';
      } else if (ext === '.docx' || ext === '.pptx' || zipContainsEntry(filePath, 'word/document.xml') || zipContainsEntry(filePath, 'ppt/presentation.xml')) {
        fileType = 'XLSX';
        description = 'OOXML 文档（Word/PowerPoint；按 ZIP 容器解压分析）';
      } else {
        fileType = 'ZIP';
        description = 'ZIP Archive';
      }
    }
    // RAR / 7z：BUUCTF 大量附件是这两种格式。之前没有分支 → 落进 UNKNOWN，
    // 走 Kali file/binwalk/strings 白烧一轮（实测 reverse2/reverse3/相册 都是这样）。
    // 统一标记为 ZIP 类型，复用 analyzeZipHandout（ctf2-unzip 已支持 rar/7z 解压）。
    else if (ext === '.rar' || magic === '52617221' || ext === '.7z' || magic === '377ABCAF') {
      fileType = 'ZIP';
      description = (ext === '.rar' || magic === '52617221') ? 'RAR Archive' : '7z Archive';
    }

    // JS / HTML（扩展名判定，走 Web/JS 逆向流程）
    else if (ext === '.js' || ext === '.mjs') {
      fileType = 'JS';
      description = 'JavaScript（可用 AST 反混淆 + Burp 联动分析）';
    }
    else if (ext === '.html' || ext === '.htm') {
      fileType = 'HTML';
      description = 'Web Page（可提取内嵌 JS 分析）';
    }
    // XML / JSON 文本结构（OOXML 解压产物等）：走文本分析，绝不进 Kali 固件流程
    else if (ext === '.xml' || ext === '.rels' || ext === '.json' || ext === '.plist' || ext === '.yml' || ext === '.yaml') {
      fileType = 'XML';
      description = '结构化文本（XML/JSON 等；直读内容分析，公式/密钥/常量常藏其中）';
    }
    // 纯文本（.txt/.enc 等）：直读内容分析。enc.txt(34B) 曾被 UNKNOWN→Kali 白烧 60s，
    // 而它的全部信息就是那 34 个字符（RSA 密文/编码串等）。
    else if (ext === '.txt' || ext === '.enc' || ext === '.log' || ext === '.md' || ext === '.csv') {
      fileType = 'TXT';
      description = '文本文件（直读内容分析：密文/编码/提示常以纯文本给出）';
    }
    // 源码类（.py/.sh/.c/.go/.rs/...）：**直读源码**分析，绝不进固件流程。
    // 实测（homebrewEventLoop 的 server.py）：2322 字节 Python2 源码被识别成 UNKNOWN
    // → 走 analyzeBIN（Kali 固件预检 + magic/熵块采集）→ 白等 2 分钟且方向全错。
    // 源码题（协议交互/沙箱逃逸/逻辑题）的正确入口是"读全文 → 按语言语义分析"，
    // 与 TXT 同路（analyzeXMLText 直读），只是需要标出语言以便提示词给对方向。
    else if (SOURCE_EXTS.includes(ext)) {
      fileType = 'SOURCE';
      description = `源码文件（${SOURCE_LANG[ext] || '未知语言'}；直读源码按语言语义分析，不进固件/IDA 流程）`;
    }

    return {
      success: true,
      fileType,
      description,
      extension: ext,
      fileName
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ 加密算法指纹扫描器（代码层确定性识别）============
// 为什么需要：实测（Disguise/xmctf）AI 每次都往 AES 猜、啃 VM handler 烧 500+ 秒，
// 而二进制里其实有确定性证据（S 盒常量、FK/CK、轮结构）可一眼判定算法。
// 旧链路"算法识别"全靠 AI 看 + 软提示，且 S 盒/FK 能否被看到取决于"引用它的函数是否被采集"
// （PE/ELF 主路径只读被反编译函数引用的地址）→ 极易漏。
// 本扫描器**直接读文件字节**，不依赖 IDA、不受引用关系限制，给出确定性的算法候选。
const CRYPTO_FP = [
  // [名称, 字节模式（hex，空格分隔），说明]
  ['SM4-FK', 'a3 b1 ba c6 56 aa 33 50 67 7d 91 97 b2 70 22 dc', 'SM4 系统参数 FK（铁证，出现即 SM4）'],
  ['SM4-FK-BE', 'c6 ba b1 a3 50 33 aa 56 97 91 7d 67 dc 22 70 b2', 'SM4 FK（大端存放）'],
  ['SM4-SBOX', 'd6 90 e9 fe cc e1 3d b7', 'SM4 标准 S 盒首 4 字节'],
  ['SM4-CK', '00 07 0e 15', 'SM4 轮常量 CK 起始（配合 256 双射表判定）'],
  ['AES-SBOX', '63 7c 77 7b f2 6b 6f c5', 'AES S 盒首 8 字节'],
  ['AES-INV-SBOX', '52 09 6a d5 30 36 a5 38', 'AES 逆 S 盒首 8 字节（解密码表）'],
  ['SM3-IV', '73 80 16 6f 49 14 b2 b9 17 24 42 d7', 'SM3 IV（铁证，出现即 SM3）'],
  ['MD5-IV', '01 23 45 67 89 ab cd ef', 'MD5 IV（小端存放）'],
  ['SHA256-IV', '67 e6 09 6a 85 ae 67 bb', 'SHA256 IV（小端存放）'],
  ['TEA-DELTA', 'b9 79 37 9e', 'TEA/XTEA delta 0x9E3779B9（小端）'],
  ['TEA-DELTA-INV', '47 c8 86 61', 'TEA delta 取反 0x61C88647（小端）'],
  ['CRC32-POLY', '20 83 b8 ed', 'CRC32 多项式 0xEDB88320（小端）'],
  // ⚠️ 旧条目 '00 01 02 03 04 05 06 07 08 09' 已删除：这 10 个字节几乎出现在每个程序里
  // （栈/结构体/索引数组的初始化），实测 20 题里 12 题被打上"RC4（疑）"，全是误报，
  // 反而把 AI 引向错误算法族。RC4 的确定性特征是**完整 0..255 递增表**，见下方 rc4TableHit。
  ['B64-STD', '41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f', '标准 Base64 表'],
];

function hexToBytes(hex) { return Buffer.from(hex.replace(/\s+/g, ''), 'hex'); }
function findPattern(buf, pat) {
  const idxs = [];
  let from = 0, at;
  while ((at = buf.indexOf(pat, from)) !== -1) { idxs.push(at); from = at + 1; if (idxs.length >= 8) break; }
  return idxs;
}

// ============ 载荷检测流水线（可插拔）============
// 设计目标（v1.6.0 Phase 1）：把"找下一层载体"从单一窄公式升级为**按序尝试多种形态**。
// 每个检测器 = 一个 `(buf,size,limit) => items[]` 函数，统一输出：
//   { type:'pe'|'elf'|'dex'|'shellcode', offset, length, confidence,
//     encode:{kind,key,stride,period}, head }
// 新增形态只需写一个检测器并注册到 PAYLOAD_DETECTORS —— 主流程、提示词、测试都不用改。
// 失败语义：某个检测器抛错只跳过它自己（try/catch），其它检测器继续 → "优雅失败"。
const PAYLOAD_MAX = 4;

// 已知 DOS stub（0x40..0x74）：用于恢复周期 XOR 的多字节密钥（已知明文攻击）。
// 绝大多数链接器产出相同 stub；不匹配只会"漏报"，不会误报。
const DOS_STUB_KNOWN = (() => {
  const a = [];
  const code = [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21];
  for (let t = 0; t < code.length; t++) a.push([0x40 + t, code[t]]);
  const s = 'This program cannot be run in DOS mode.\r\r\n$';
  for (let t = 0; t < s.length; t++) a.push([0x4e + t, s.charCodeAt(t) & 0xff]);
  return a;
})();

// 用"逻辑字节读取器"校验 PE 头（支持任意编码/步长：decode(j) 返回第 j 个逻辑字节）
function validatePE(decode, maxItems) {
  if (maxItems < 0x100) return null;
  if (decode(0) !== 0x4d || decode(1) !== 0x5a) return null;
  const e = (decode(0x3c) | (decode(0x3d) << 8) | (decode(0x3e) << 16) | (decode(0x3f) << 24)) >>> 0;
  if (e < 0x40 || e > 0x100000 || e + 4 > maxItems) return null;
  if (!(decode(e) === 0x50 && decode(e + 1) === 0x45 && decode(e + 2) === 0 && decode(e + 3) === 0)) return null;
  let length = 0;
  if (e + 24 <= maxItems) {
    const nsec = decode(e + 6) | (decode(e + 7) << 8);
    const optSize = decode(e + 20) | (decode(e + 21) << 8);
    const secTbl = e + 24 + optSize;
    if (nsec >= 1 && nsec <= 96) {
      let end = 0, ok = true;
      for (let k = 0; k < nsec; k++) {
        const p = secTbl + k * 40;
        if (p + 24 > maxItems) { ok = false; break; }
        const rs = (decode(p + 16) | (decode(p + 17) << 8) | (decode(p + 18) << 16) | (decode(p + 19) << 24)) >>> 0;
        const rp = (decode(p + 20) | (decode(p + 21) << 8) | (decode(p + 22) << 16) | (decode(p + 23) << 24)) >>> 0;
        if (rp + rs > end) end = rp + rs;
      }
      if (ok && end >= 0x100 && end <= maxItems) length = end;
    }
  }
  return { e_lfanew: e, length };
}

// ELF 头校验 + 用节头表推算长度（支持 32/64 位、大小端）
function validateELF(decode, maxItems) {
  if (maxItems < 0x40) return null;
  const magic = [0x7f, 0x45, 0x4c, 0x46];
  for (let t = 0; t < 4; t++) if (decode(t) !== magic[t]) return null;
  const cls = decode(4), data = decode(5), ver = decode(6);
  if ((cls !== 1 && cls !== 2) || (data !== 1 && data !== 2) || ver !== 1) return null;
  const be = data === 2;
  const rd16 = (o) => (o + 2 > maxItems ? NaN : (be ? (decode(o) << 8) | decode(o + 1) : decode(o) | (decode(o + 1) << 8)));
  const rd32 = (o) => (o + 4 > maxItems ? NaN : (be
    ? ((decode(o) << 24) | (decode(o + 1) << 16) | (decode(o + 2) << 8) | decode(o + 3)) >>> 0
    : (decode(o) | (decode(o + 1) << 8) | (decode(o + 2) << 16) | (decode(o + 3) << 24)) >>> 0));
  let shoff, shentsize, shnum;
  if (cls === 1) { shoff = rd32(0x20); shentsize = rd16(0x2e); shnum = rd16(0x30); }
  else { shoff = rd32(0x28) + rd32(0x2c) * 4294967296; shentsize = rd16(0x3a); shnum = rd16(0x3c); }
  let length = 0;
  if (shentsize > 0 && shnum > 0 && shnum < 0x10000 && shoff > 0 && shoff < 2 ** 40) {
    const end = shoff + shentsize * shnum;
    if (end >= 0x40 && end <= maxItems) length = end;
  }
  return { length };
}

// DEX 头校验 + file_size 字段
function validateDEX(decode, maxItems) {
  if (maxItems < 0x24) return null;
  const magic = [0x64, 0x65, 0x78, 0x0a];
  for (let t = 0; t < 4; t++) if (decode(t) !== magic[t]) return null;
  for (let t = 4; t < 7; t++) { const c = decode(t); if (c < 0x30 || c > 0x39) return null; }
  if (decode(7) !== 0) return null;
  const fs = (decode(0x20) | (decode(0x21) << 8) | (decode(0x22) << 16) | (decode(0x23) << 24)) >>> 0;
  return { length: (fs >= 0x100 && fs <= maxItems) ? fs : 0 };
}

// 检测器 1：PE，单字节 XOR/ADD × stride 1/4/2（v1.5.3 能力，保留）
// 性能要点：热路径零分配（此前每候选 push 一个数组，实测 1.8s → 0.6s）。
function detectPESingleByte(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  const emit = (kind, key, i, s) => {
    if (i === 0 && key === 0) return;                    // 文件自身 DOS 头
    const avail = Math.floor((size - i) / s);
    if (avail < 0x40) return;
    if (hits.some(x => Math.abs(x.offset - i) < 4 && x.encode.kind === kind)) return;
    const dec = (j) => (kind === 'add' ? ((buf[i + j * s] - key) & 0xff) : (buf[i + j * s] ^ key));
    const v = validatePE(dec, avail);
    if (!v) return;
    hits.push({ type: 'pe', label: 'PE', offset: i, length: v.length, confidence: 'high', head: '4d5a',
      encode: { kind, key, stride: s, period: 1 } });
  };
  for (const s of [1, 4, 2]) {
    if (hits.length >= MAX) break;
    for (let i = 0; i + s < size; i++) {
      if (hits.length >= MAX) break;
      const a = buf[i], b = buf[i + s];
      if ((a ^ b) !== 0x17 && ((b - a) & 0xff) !== 0x0d) continue;
      // 内联核对 MZ（等价于先算 key 再解码首两字节），通过后才进入昂贵校验
      if ((a ^ b) === 0x17) {
        const key = a ^ 0x4d;
        const b0 = a ^ key, b1 = b ^ key;
        if (b0 === 0x4d && b1 === 0x5a) emit('xor', key, i, s);
      }
      if (((b - a) & 0xff) === 0x0d) {
        const key = (a - 0x4d) & 0xff;
        const b0 = (a - key) & 0xff, b1 = (b - key) & 0xff;
        if (b0 === 0x4d && b1 === 0x5a) emit('add', key, i, s);
      }
    }
  }
  return hits;
}

// 检测器 2：PE，周期 XOR（周期 2 用 MZ 直接解出；3/4/8 用 DOS stub 已知明文恢复 key）
function detectPEPeriodic(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  // --- 周期 2：MZ 两个字节恰好给出 k0/k1（in[0]=4d, in[1]=5a 是已知明文）---
  //     任何位置都能"解出"一对 key，靠 e_lfanew→PE\0\0 结构校验过滤（随机偏移通过率 ~2^-32）。
  //     注意：不能用"前 4 字节周期重复"做预筛——MZ 之后是 90 00 03 00，并不会重复。
  //     性能：大文件（>16MB）上这项**跳过**。周期 2 编码的 payload 通常出现在 CTF 题目量级文件里；
  //     通用程序的 190MB 文件里逐字节解 e_lfanew 不划算（实测把扫描从 3.8s 拖到 11.4s）。
  if (size <= 16 * 1024 * 1024) {
    for (let i = 0; i + 0x100 < size; i++) {
      if (hits.length >= MAX) break;
      const k0 = buf[i] ^ 0x4d, k1 = buf[i + 1] ^ 0x5a;
      if (k0 === 0 && k1 === 0) continue;              // 明文自身
      const e = ((buf[i + 0x3c] ^ k0) | ((buf[i + 0x3d] ^ k1) << 8)
        | ((buf[i + 0x3e] ^ k0) << 16) | ((buf[i + 0x3f] ^ k1) << 24)) >>> 0;
      // e_lfanew 实际取值几乎总是 0x80/0xE8/0x100 等小值且 4 字节对齐；用它做强预筛。
      if (e < 0x40 || e > 0x100000 || (e & 3) !== 0) continue;
      if (i + e + 4 > size) continue;
      // PE\0\0 校验（e 的奇偶决定用哪个 key）
      if ((buf[i + e] ^ (e % 2 ? k1 : k0)) !== 0x50) continue;
      if ((buf[i + e + 1] ^ ((e + 1) % 2 ? k1 : k0)) !== 0x45) continue;
      if ((buf[i + e + 2] ^ ((e + 2) % 2 ? k1 : k0)) !== 0) continue;
      if ((buf[i + e + 3] ^ ((e + 3) % 2 ? k1 : k0)) !== 0) continue;
      const avail = size - i;
      const dec = (j) => buf[i + j] ^ ((j & 1) ? k1 : k0);
      const v = validatePE(dec, avail);
      if (!v) continue;
      hits.push({ type: 'pe', label: 'PE', offset: i, length: v.length, confidence: 'high', head: '4d5a',
        encode: { kind: 'periodic-xor', key: [k0, k1], stride: 1, period: 2 } });
    }
  }
  // --- 周期 3/4/8：仅中小文件（性能）；用 DOS stub 已知明文恢复全部 key 字节 ---
  //     真实链接器产出的 PE 几乎都有标准 DOS stub；没有则跳过（宁可漏报，不误报）。
  if (size <= 16 * 1024 * 1024 && hits.length < MAX) {
    for (const p of [3, 4, 8]) {
      if (hits.length >= MAX) break;
      // 预筛：任取两个已知明文位置，其隐含 key 必须一致（先比两个同余的位置）
      const t1 = 0x40, v1 = 0x0e;
      const t2 = 0x40 + p;
      if (t2 >= size) continue;
      const known2 = DOS_STUB_KNOWN.find(x => x[0] === t2);
      if (!known2) continue;
      for (let i = 0; i + t2 < size; i++) {
        if (hits.length >= MAX) break;
        if (buf[i + t2] !== (buf[i + t1] ^ v1 ^ known2[1])) continue;
        const keyMap = new Array(p).fill(-1);
        let ok = true;
        for (const [t, v] of DOS_STUB_KNOWN) {
          if (i + t >= size) { ok = false; break; }
          const k = buf[i + t] ^ v, r = t % p;
          if (keyMap[r] < 0) keyMap[r] = k; else if (keyMap[r] !== k) { ok = false; break; }
        }
        if (!ok || keyMap.some(k => k < 0)) continue;
        // key 全 0 且偏移 0 = 文件自身就是明文 PE（不是"内嵌载荷"）→ 跳过，避免每个正常 PE 自报。
        if (i === 0 && keyMap.every(k => k === 0)) continue;
        const avail = size - i;
        const dec = (j) => buf[i + j] ^ keyMap[j % p];
        const v = validatePE(dec, avail);
        if (!v) continue;
        if (hits.some(x => Math.abs(x.offset - i) < 8)) continue;
        hits.push({ type: 'pe', label: 'PE', offset: i, length: v.length, confidence: 'high', head: '4d5a',
          encode: { kind: 'periodic-xor', key: keyMap.slice(), stride: 1, period: p } });
      }
    }
  }
  return hits;
}

// 检测器 3：PE，滚动 XOR / 滚动 ADD（out[i] = in[i] ^ in[i-1] 或 +）
// 预筛极廉价：in[0]=0x4d，故 out[0]=0x4d；out[1]=0x5a^0x4d=0x17（xor）/ 0x5a+0x4d=0xa7（add）
function detectPERolling(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  for (let i = 0; i + 0x100 < size; i++) {
    if (hits.length >= MAX) break;
    if (buf[i] !== 0x4d) continue;
    // 偏移 0 且首字节即 MZ：文件自身是明文 PE，滚动解码无意义 → 跳过
    if (i === 0) continue;
    const b1 = buf[i + 1];
    const kind = b1 === 0x17 ? 'rolling-xor' : (b1 === 0xa7 ? 'rolling-add' : null);
    if (!kind) continue;
    const avail = Math.min(size - i, 0x4000);
    const dec = Buffer.allocUnsafe(avail);
    let prev = 0;
    for (let j = 0; j < avail; j++) {
      const b = buf[i + j];
      prev = kind === 'rolling-xor' ? (b ^ prev) : ((b - prev) & 0xff);
      dec[j] = prev;
    }
    const v = validatePE((j) => dec[j], avail);
    if (!v) continue;
    hits.push({ type: 'pe', label: 'PE', offset: i, length: v.length, confidence: 'high', head: '4d5a',
      encode: { kind, key: null, stride: 1, period: 1 } });
  }
  return hits;
}

// 检测器 4：PE，以 Base64 / Hex **文本**存储（MZ 不再以二进制出现）
function detectPETextEncoded(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  const pushIf = (off, kind, decoded) => {
    if (!decoded || decoded.length < 0x100) return;
    if (decoded[0] !== 0x4d || decoded[1] !== 0x5a) return;
    const v = validatePE((j) => decoded[j], decoded.length);
    if (!v) return;
    if (hits.some(x => Math.abs(x.offset - off) < 8)) return;
    hits.push({ type: 'pe', label: 'PE', offset: off, length: v.length, confidence: 'high', head: '4d5a',
      encode: { kind, key: null, stride: 1, period: 1 } });
  };
  // Base64：PE 常见前缀 "TVqQ"（MZ\x90\x00）或 "TVo"（MZ）
  for (const marker of ['TVqQ', 'TVo']) {
    let from = 0, at;
    while ((at = buf.indexOf(marker, from)) !== -1 && hits.length < MAX) {
      from = at + 1;
      const chunk = buf.slice(at, Math.min(size, at + 65536)).toString('latin1');
      const clean = chunk.replace(/[^A-Za-z0-9+/=]/g, '');
      try { pushIf(at, 'base64', Buffer.from(clean + '='.repeat((4 - clean.length % 4) % 4), 'base64')); } catch (e) {}
    }
    if (hits.length >= MAX) break;
  }
  // Hex 文本："4d5a" 开头（大小写均试）。不假设第 3~4 字节（不同链接器 stub 不同）。
  for (const marker of ['4d5a', '4D5A']) {
    let from = 0, at;
    while ((at = buf.indexOf(marker, from)) !== -1 && hits.length < MAX) {
      from = at + 1;
      const chunk = buf.slice(at, Math.min(size, at + 131072)).toString('latin1');
      const clean = chunk.replace(/[^0-9a-fA-F]/g, '');
      try { pushIf(at, 'hex', Buffer.from(clean.slice(0, clean.length - (clean.length % 2)), 'hex')); } catch (e) {}
    }
    if (hits.length >= MAX) break;
  }
  return hits;
}

// 检测器 5：ELF / DEX（明文 + 单字节 XOR/ADD × stride 1/4/2）
// 性能要点（实测 86MB 上 7.4s → ~1.5s）：
//  · **只扫 3 遍**（stride 1/4/2），每遍同时检查 ELF 与 DEX 两种 magic
//  · 热路径不分配数组/闭包；magic 用 4 个内联字节比较
function detectOtherFormats(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  const specs = [
    { type: 'elf', label: 'ELF', m: [0x7f, 0x45, 0x4c, 0x46], validate: validateELF },
    { type: 'dex', label: 'DEX', m: [0x64, 0x65, 0x78, 0x0a], validate: validateDEX },
  ];
  // 把两种格式的判据提到标量：热路径只做整数比较。
  // ⚠️ 这里**绝不能**在逐字节循环里写 `for (const sp of specs)` —— 每次迭代都分配一个
  //    数组迭代器，86MB×3 遍 ≈ 2.5 亿次分配，实测让 GC 占 30% CPU（5s → 1.5s 的差别）。
  const E = specs[0], D = specs[1];
  const exd = E.m[0] ^ E.m[1], ead = (E.m[1] - E.m[0]) & 0xff;
  const dxd = D.m[0] ^ D.m[1], dad = (D.m[1] - D.m[0]) & 0xff;
  const emit = (sp, kind, key, i, s, avail) => {
    const m = sp.m;
    const dec = (j) => (kind === 'add' ? ((buf[i + j * s] - key) & 0xff) : (buf[i + j * s] ^ key));
    const v = sp.validate(dec, avail);
    if (!v) return;
    if (hits.some(x => x.type === sp.type && Math.abs(x.offset - i) < 8)) return;
    hits.push({ type: sp.type, label: sp.label, offset: i, length: v.length, confidence: 'high',
      head: m.map(x => x.toString(16).padStart(2, '0')).join(''),
      encode: { kind, key, stride: s, period: 1 } });
  };
  for (const s of [1, 4, 2]) {
    if (hits.length >= MAX) break;
    for (let i = 0; i + s * 4 < size; i++) {
      if (hits.length >= MAX) break;
      const a = buf[i], b = buf[i + s];
      const ab = (a ^ b), ad = ((b - a) & 0xff);
      // 两字节判据：绝大多数字节直接在这里被排除（每字节 4 次整数比较，零分配）
      const eXor = ab === exd, eAdd = ad === ead;
      const dXor = ab === dxd, dAdd = ad === dad;
      if (!eXor && !eAdd && !dXor && !dAdd) continue;
      const avail = Math.floor((size - i) / s);
      if (avail < 0x40) continue;
      // 少数候选才进入完整校验（magic 4 字节先内联比，再走头部解析）
      // ⚠️ key=0 表示"明文"：只有当偏移 i===0（文件自身就是该格式）时才允许，且这种情形
      //    **不算"内嵌载荷"**（否则每个正常 ELF/PE 都会自报一次，实测回归题集全员误报）。
      if (eXor) { const k = a ^ E.m[0]; if (!(i === 0 && k === 0)) emit(E, 'xor', k, i, s, avail); }
      if (eAdd) { const k = (a - E.m[0]) & 0xff; if (!(i === 0 && k === 0)) emit(E, 'add', k, i, s, avail); }
      if (dXor) { const k = a ^ D.m[0]; if (!(i === 0 && k === 0)) emit(D, 'xor', k, i, s, avail); }
      if (dAdd) { const k = (a - D.m[0]) & 0xff; if (!(i === 0 && k === 0)) emit(D, 'add', k, i, s, avail); }
    }
  }
  return hits;
}

// 检测器 6：裸 shellcode 常见序言（保守：只认极特征化的几条，low 置信度）
function detectShellcodePrologue(buf, size, limit) {
  const hits = [];
  const MAX = Math.min(limit, PAYLOAD_MAX);
  const prologues = [
    ['fce882000000', 'calc 类 shellcode（fc e8 82 00 00 00）'],
    ['fc4883e4f0', 'x64 shellcode 常见序言（fc 48 83 e4 f0）'],
  ];
  for (const [hex, desc] of prologues) {
    const pat = hexToBytes(hex);
    for (const off of findPattern(buf, pat)) {
      if (hits.length >= MAX) break;
      hits.push({ type: 'shellcode', label: 'shellcode', offset: off, length: 0, confidence: 'low',
        head: hex.slice(0, 8), encode: { kind: 'none', key: null, stride: 1, period: 1 }, desc });
    }
  }
  return hits;
}

// 注册表：新增形态 = 在这里加一行。顺序 = 优先级。
const PAYLOAD_DETECTORS = [
  ['pe-single-byte', detectPESingleByte],
  ['pe-periodic-xor', detectPEPeriodic],
  ['pe-rolling', detectPERolling],
  ['pe-text-encoded', detectPETextEncoded],
  ['elf-dex', detectOtherFormats],
  ['shellcode-prologue', detectShellcodePrologue],
];

// ============ 编码表检测（Base64 变表 / Base91）============
// 来源：《CTF 逆向实战：Base64 变表与 SM4 自定义 S 盒还原》
// 核心：算法逻辑与表数据分离——改表不改算法就能让所有现成库失效。
// 识别信号（文章方法论）：
//   · 数据段存在 64 个互异可见字符的连续块 → Base64 变表候选（搜不到标准表时尤其要报）
//   · 字符集去重约 91 个且含大量符号（!#$%&*...）→ Base91 表
//   · 关键区分：字符集 >64 别再当 Base64 变表硬解
const STD_B64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const STD_B91_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
const STD_B64_RE = /^[A-Za-z0-9+/]{64}$/;

function detectEncodingTables(buf, size, limit) {
  const hits = [];
  // 性能：逐偏移滑窗 × Set/TypedArray 构建在 200MB 通用二进制上要 30+ 秒（实测 electron.exe）。
  // 改为**单趟游程扫描**：先线性扫出所有"≥64 连续可见字节"的游程（O(n)，零分配），
  // 只对游程内部做 64/91 窗口互异性判定（真表只能出现在可见游程里，且游程通常极短）。
  let runStart = -1;
  for (let i = 0; i <= size; i++) {
    const vis = i < size && buf[i] >= 0x21 && buf[i] <= 0x7e;
    if (vis && runStart < 0) runStart = i;
    if (!vis && runStart >= 0) {
      const runLen = i - runStart;
      if (runLen >= 64) scanVisibleRun(buf, size, runStart, runLen, limit, hits);
      runStart = -1;
    }
    if (hits.length >= limit) break;
  }
  return hits;
}

// 在一个"连续可见字节"游程内查找 Base64/Base91 变表（游程长度 ≥64 才进来）
// 性能细节：巨型游程（实测 electron.exe 有 4.9MB 的文本资源区）内部若逐偏移做 64/91 窗口
// Set 判定仍是 O(游程长 × 64)。用"发现即跳过"（off += 窗口长）+ Set 命中提前失败，
// 真表/伪表都会在窗口前几十字节内出现重复字符而失败，实际探测深度极小。
function scanVisibleRun(buf, size, runStart, runLen, limit, hits) {
  const runEnd = runStart + runLen;
  for (let off = runStart; off + 64 <= runEnd && hits.length < limit; off++) {
    // 快速互异预筛：窗口前 16 字节内重复 ⇒ 不可能是 64/91 互异排列（零分配，8ms/MB 级）。
    // 巨型文本游程（实测 electron.exe 有 4.9MB 资源区）里几乎每个偏移都有相邻重复，
    // 全量 Set 判定（64 字节 × 490 万偏移 = 8 秒/游程）靠这一步直接跳过。
    const seen16 = new Set();
    let dup16 = false;
    for (let i = 0; i < 16; i++) { const c = buf[off + i]; if (seen16.has(c)) { dup16 = true; break; } seen16.add(c); }
    if (dup16) continue;
    if (off + 91 <= size && buf[off + 90] >= 0x21 && buf[off + 90] <= 0x7e) {
      // 先试 91 字符（Base91 表更长，优先判）
      const seg = buf.slice(off, off + 91);
      // ⚠️ 强护栏：真 Base91 表的 91 字符**全部可见**（0x21..0x7E，这是 Base91 字符集的定义域）。
      //    密码 S 盒的 91 字节窗口几乎必然含 <0x21 的字节（S 盒值域 0x00..0xFF 均匀分布）。
      //    无此护栏时 SM4/AES S 盒窗口会以极高概率凑出 91 个互异字节（回归题集实测）。
      let allVisible = true;
      for (let i = 0; i < 91; i++) { const c = seg[i]; if (c < 0x21 || c > 0x7e) { allVisible = false; break; } }
      if (!allVisible) continue;
      const uniq = new Set(seg);
      if (uniq.size === 91) {
        // 与标准 Base91 表的差异
        let same = 0;
        for (let i = 0; i < 91; i++) if (seg[i] === STD_B91_TABLE.charCodeAt(i)) same++;
        if (same === 91) continue;   // 标准表不值得报（AI 用库就行）
        hits.push({
          type: 'table', label: 'Base91变表', offset: off, length: 91, confidence: 'medium',
          head: seg.slice(0, 8).toString('latin1'),
          encode: { kind: 'b91-table', key: same, stride: 1, period: 1 },
          desc: `Base91 变表 @0x${off.toString(16)}（91 字符互异，与标准表相同位 ${same}/91）。` +
            `若程序输出混有 !#$%& 等符号且长度非 4 的倍数，优先按 Base91 变表解（解码是 13 位分组运算，换表需重写解码循环，不能只做字符映射）。`,
        });
        off += 90;
        continue;
      }
    }
    if (off + 64 > runEnd) continue;
    const seg = buf.slice(off, off + 64);
    const uniq = new Set(seg);
    if (uniq.size !== 64) continue;
    // 64 个互异可见字符。标准表不报；变表才报。
    let isStd = true;
    for (let i = 0; i < 64; i++) if (seg[i] !== STD_B64_TABLE.charCodeAt(i)) { isStd = false; break; }
    if (isStd) { off += 63; continue; }
    // ⚠️ 关键护栏（回归题集实测）：**256 字节密码 S 盒的某些 64 字节窗口也可能全是 Base64 值域
    //    字符**（AES S 盒含大量 0x4x-0x7x），仅"落在值域"不够。
    //    强判据：**完整覆盖 Base64 字符集**——真 Base64 表（含变表）64 字符互异且每个值域字符
    //    恰好出现一次；而 S 盒窗口里值域字符会重复出现/缺失。实现：64 字节去重 == 64 且
    //    全部 ∈ Base64 字符集 ⇔ 窗口是 Base64 字符集的一个排列。
    let isB64Permutation = true;
    const charset = new Set();
    for (let i = 0; i < 64; i++) {
      const c = seg[i];
      if (c === 0) { isB64Permutation = false; break; }
      const okc = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2f;
      if (!okc) { isB64Permutation = false; break; }
      if (charset.has(c)) { isB64Permutation = false; break; }
      charset.add(c);
    }
    if (isB64Permutation) {
      let same = 0;
      for (let i = 0; i < 64; i++) if (seg[i] === STD_B64_TABLE.charCodeAt(i)) same++;
      hits.push({
        type: 'table', label: 'Base64变表', offset: off, length: 64, confidence: 'medium',
        head: seg.slice(0, 8).toString('latin1'),
        encode: { kind: 'b64-table', key: same, stride: 1, period: 1 },
        desc: `Base64 变表 @0x${off.toString(16)}（64 字符为 Base64 字符集的一个排列，与标准表相同位 ${same}/64）。` +
          `还原：str.maketrans(变表, 标准表) 映射后交给标准库解码；` +
          `注意表里若无 + / 时补位规则可能变（检查 len%4）。` +
          `字符集超过 64 时应改判 Base91。`,
      });
      off += 63;
    }
  }
}

// 注册到流水线（放在 shellcode 之后：表是"线索"不是"载体"，优先级最低）
PAYLOAD_DETECTORS.push(['encoding-table', detectEncodingTables]);

// 流水线入口：逐个尝试检测器；单个失败不影响其它（优雅失败）。
function detectPayloads(buf, size) {
  const acc = [];
  for (const [name, fn] of PAYLOAD_DETECTORS) {
    if (acc.length >= PAYLOAD_MAX) break;
    let items = [];
    try { items = fn(buf, size, PAYLOAD_MAX - acc.length) || []; } catch (e) { continue; }
    for (const it of items) {
      it.detector = name;
      if (acc.some(x => x.type === it.type && Math.abs(x.offset - it.offset) < 8)) continue;
      acc.push(it);
      if (acc.length >= PAYLOAD_MAX) break;
    }
  }
  // shellcode 只是"兜底线索"：一旦发现真正的容器格式（PE/ELF/DEX）就不再报它，避免噪声抢结论
  return acc.some(x => x.type !== 'shellcode') ? acc.filter(x => x.type !== 'shellcode') : acc;
}

// 把载荷命中渲染成给 AI 的结论（含可直接运行的提取脚本）
function payloadRecipe(p) {
  const off = '0x' + p.offset.toString(16);
  const n = p.length || 'N';
  const e = p.encode || { kind: 'none' };
  const head = 'd = open(r"<当前文件>","rb").read()\n';
  const out = 'open("stage2.bin","wb").write(blob)\n';
  const verify = `# 校验：blob 头部应为 ${p.type === 'pe' ? '4d5a (MZ)' : p.type === 'elf' ? '7f454c46 (ELF)' : p.type === 'dex' ? '6465780a (dex)' : p.head}\n`;
  switch (e.kind) {
    case 'none':
      return '```python\n' + head + `blob = d[${off}:${off}+${n}]\n` + out + verify + '```';
    case 'add': {
      // 编码是 out = in + key，解码必须 **减** key。
      // （此前误写成加，会让 ADD 编码的题解出乱码——单测 test_payload_extract.js 抓到的。）
      const op = e.kind === 'add' ? '(d[o+i*s] - key) & 0xff' : 'd[o+i*s] ^ key';
      return '```python\n' + head
        + `o, s, key = ${off}, ${e.stride || 1}, 0x${e.key.toString(16)}\n`
        + `n = ${n}\n`
        + `blob = bytes(${op} for i in range(n))\n` + out + verify + '```';
    }
    case 'periodic-xor': {
      const keys = e.key.map(k => '0x' + k.toString(16)).join(', ');
      return '```python\n' + head
        + `o, n = ${off}, ${n}\nkeys = [${keys}]\n`
        + `blob = bytes(d[o+i] ^ keys[i % len(keys)] for i in range(n))\n` + out + verify + '```';
    }
    case 'rolling-xor':
      return '```python\n' + head + `o, n = ${off}, ${n}\nblob = bytearray(); prev = 0\n`
        + `for i in range(n):\n    prev = d[o+i] ^ prev\n    blob.append(prev)\n` + out + verify + '```';
    case 'rolling-add':
      return '```python\n' + head + `o, n = ${off}, ${n}\nblob = bytearray(); prev = 0\n`
        + `for i in range(n):\n    prev = (d[o+i] - prev) & 0xff\n    blob.append(prev)\n` + out + verify + '```';
    case 'base64':
      return '```python\nimport base64, re\n' + head
        + `s = d[${off}:]\n`
        + `s = re.sub(rb"[^A-Za-z0-9+/=]", b"", s)\n`
        + `s += b"=" * (-len(s) % 4)\n`
        + `blob = base64.b64decode(s)[:${n}]\n` + out + verify + '```';
    case 'hex':
      return '```python\n' + head
        + `s = d[${off}:].decode("latin-1")\n`
        + `s = re.sub(r"[^0-9a-fA-F]", "", s)\n`
        + `blob = bytes.fromhex(s[:${typeof n === 'number' ? n * 2 : 'N*2'}])\n` + out + verify + '```';
    default:
      return '```python\n' + head + `blob = d[${off}:${off}+${n}]\n` + out + '```';
  }
}

function payloadDescription(p, count) {
  const off = '0x' + p.offset.toString(16);
  const e = p.encode || { kind: 'none' };

  // 编码表（Base64/Base91 变表）不是"载荷"：它是**算法数据**，不能得出"本层是 loader"的结论。
  // 实测（cnbragon / kanxue-ctf-gxustudent）：Data 段里一张 Base91 变表被 typeName 兜底成
  // "shellcode"，summary 直接断言"本层是 loader、必须提取下一层"，而同一份扫描里 AES 已是 high
  // 置信度——AI 因此放着确定的主逻辑不逆，去 dump 一个不存在的 payload，整题烧完预算。
  if (p.type === 'table') {
    return {
      algo: p.label || '编码变表',
      confidence: p.confidence || 'medium',
      evidence: `在文件偏移 ${off} 处发现 ${p.length} 字节的**编码字符表**（${p.head}…）`
        + (typeof e.key === 'number' ? `，与标准表相同位置 ${e.key}/${p.length}` : '')
        + '。这是**算法的数据表**，不是可执行载荷。',
      note: '含义：程序很可能使用**自定义表**的 Base64/Base91 编码（改表不改算法，标准库直接解会失败）。'
        + '按反编译确认：① 该表被哪个函数引用；② 编码是 4→3（Base64）还是 13 位分组（Base91）；'
        + '③ 把标准实现里的表替换成本表。'
        + '⚠️ 这张表不是可执行载体：不要因为它的存在去 dump 内存里的所谓下一阶段代码；'
        + '若同时命中 AES/SM4 等算法常量，主逻辑就在本层。',
    };
  }

  const typeName = p.type === 'pe' ? 'PE' : p.type === 'elf' ? 'ELF' : p.type === 'dex' ? 'DEX' : 'shellcode';
  let how;
  switch (e.kind) {
    case 'none': how = '明文存放'; break;
    case 'xor': how = `头部被 XOR 0x${e.key.toString(16).padStart(2, '0')} 掩盖`; break;
    case 'add': how = `头部被 ADD 0x${e.key.toString(16).padStart(2, '0')} 掩盖`; break;
    case 'periodic-xor': how = `头部被 ${e.period} 字节循环 XOR（key=${e.key.map(k => '0x' + k.toString(16)).join(' ')}）掩盖`; break;
    case 'rolling-xor': how = '整体被滚动 XOR（out[i]=in[i]^in[i-1]）掩盖'; break;
    case 'rolling-add': how = '整体被滚动 ADD（out[i]=in[i]+in[i-1]）掩盖'; break;
    case 'base64': how = '以 Base64 文本存储'; break;
    case 'hex': how = '以十六进制文本存储'; break;
    default: how = e.kind;
  }
  const strideNote = (e.kind !== 'none' && e.stride > 1) ? `每项占 ${e.stride} 字节、只取低字节；` : '';
  const lenTxt = p.length ? `，推算长度 ${p.length} 字节` : '';
  const isContainer = p.type !== 'shellcode' && p.type !== 'table';
  const evidence = `在文件偏移 ${off} 处发现**${how}**的 ${typeName} 载荷（${strideNote}故明文搜头部搜不到）：解码后为合法可执行载荷${lenTxt}`
    + (count > 1 ? `；另有 ${count - 1} 处候选` : '');
  const note = isContainer
    ? `**本层是 loader/壳**（所以本层没有算法常量）。下一步**必须先提取下一层再分析它**，不要在本层找算法或硬逆它的逻辑：\n`
      + payloadRecipe(p)
      + `\n提取出后，对**新文件**重新做算法指纹扫描——真正的加密算法/VM 在下一层里。`
      + (p.length ? '' : '（长度用头部字段/节表推算）')
    : `疑似裸 shellcode（未包装成 PE/ELF）。可从该偏移 dump 后反汇编；若是 loader 解密出的代码块，按"提取→反汇编→识别算法"处理。`;
  return {
    algo: `内嵌 ${typeName}（${e.kind === 'none' ? '明文' : '编码存储'}，已定位）`,
    confidence: p.confidence || 'high',
    evidence, note,
  };
}


// ============ 自定义分组密码的常量差分分析 ============
// 为什么需要（实测教训，Disguise stage2）：AI 已经认出"SM4 骨架 + 自定义 S 盒"，但接下来
// 花了 300+ 秒、20+ 次脚本反复纠结：FK 是否被替换？CK 和标准表什么关系？字节序怎么摆？
// 这些问题**全部是确定性可计算的**——工具应当一次性给出，而不是让 AI 猜。
//
// 做法（只做可验证的推导，不猜解法）：
//   1) 把题目 S 盒与标准 SM4 / AES S 盒逐项比对（相同项数、是否互为逆表）
//   2) 在 S 盒附近搜索"32 项 dword 表"（SM4 轮常量 CK 的形态），与标准 CK 比差分
//   3) 在附近搜索 16 字节 FK 候选，与标准 FK 比差分
//   4) 报告字节序线索（表项是按 dword 还是 byte 存放、是否每 4 字节反序）
// 标准常量表统一来自 electron/crypto-tables.js（单一事实来源，测试可直接校验）。
// 这里保留旧变量名以兼容既有代码，全部指向同一份数据。
const {
  AES_SBOX: STD_AES_SBOX,
  AES_INV_SBOX: STD_AES_INV_SBOX,
  SM4_SBOX: STD_SM4_SBOX,
  SM4_FK: STD_SM4_FK,
  SM4_CK: STD_SM4_CK,
  AES_RCON: STD_AES_RCON,
  CIPHERS, BYTE_SBOXES,
} = require('./crypto-tables');
// 结构推理用的简写（与上方同一份数据）
const T_SM4 = { CK: STD_SM4_CK };
const T_AES = { RCON: STD_AES_RCON };
const bswap32 = (x) => (((x & 0xff) << 24) | (((x >>> 8) & 0xff) << 16) | (((x >>> 16) & 0xff) << 8) | ((x >>> 24) & 0xff)) >>> 0;

// ============ S 盒「变体判定」核心 ============
// 目标：不只回答"这是不是标准表"，而是回答"它和哪个标准算法是什么关系、能不能精确还原"。
//
// 三级判定（越来越强，也越能定位变体）：
//   ① 精确相等         → 标准算法
//   ② 逐项 XOR / ADD 常量 → 表被整体平移（可逆，能还原标准表）
//   ③ GF(2) 仿射关系    → custom[i] = A·std[i] ⊕ c（A 为 8×8 位矩阵，可逆时能精确还原）
// ③ 是重点：AES/SM4 的变体常对 S 盒做线性/仿射混淆，只有解出 A 才知道怎么还原。
function gf2AffineFit(custom, std) {
  // 求解 custom[i] = A·std[i] ⊕ c 中的 A（8 列）与 c（8 位常量）
  // 逐输出位独立：对第 b 位，custom[i] 的第 b 位 = (A_b · std[i]) ⊕ c_b
  // 用高斯消元在 GF(2) 上解 8 个未知数（A_b 的 8 位）+ 1 个常量位
  const solveBit = (bitIdx) => {
    // 构造 9 列（8 个矩阵位 + 1 个常量位）的增广矩阵，256 行
    // 行：[std[i] 的 8 位, 1] | [custom[i] 的第 bitIdx 位]
    const rows = [];
    for (let i = 0; i < 256; i++) {
      const x = std[i];
      const bits = [];
      for (let k = 0; k < 8; k++) bits.push((x >>> k) & 1);
      bits.push(1);                                   // 常量位
      const rhs = (custom[i] >>> bitIdx) & 1;
      rows.push({ coeff: bits, rhs });
    }
    // 高斯消元（GF(2)）
    const n = 9;
    let pivotRow = 0;
    const pivots = new Array(n).fill(-1);
    for (let col = 0; col < n && pivotRow < rows.length; col++) {
      let sel = -1;
      for (let r = pivotRow; r < rows.length; r++) if (rows[r].coeff[col]) { sel = r; break; }
      if (sel < 0) continue;
      [rows[pivotRow], rows[sel]] = [rows[sel], rows[pivotRow]];
      for (let r = 0; r < rows.length; r++) {
        if (r === pivotRow || !rows[r].coeff[col]) continue;
        for (let k = 0; k < n; k++) rows[r].coeff[k] ^= rows[pivotRow].coeff[k];
        rows[r].rhs ^= rows[pivotRow].rhs;
      }
      pivots[col] = pivotRow;
      pivotRow++;
    }
    // 检查一致性：全零系数但 rhs=1 → 无解
    for (const row of rows) {
      if (row.coeff.every(c => c === 0) && row.rhs === 1) return null;
    }
    // 取一组解（自由变量置 0）
    const sol = new Array(n).fill(0);
    for (let col = 0; col < n; col++) if (pivots[col] >= 0) sol[col] = rows[pivots[col]].rhs;
    return sol;
  };

  const cols = [];   // 8 个输出位的解，每个解含 8 个矩阵位 + 常量位
  for (let b = 0; b < 8; b++) {
    const s = solveBit(b);
    if (!s) return null;
    cols.push(s);
  }
  // 回代验证 256 项（防止自由变量取值导致解不唯一但恰好不满足）
  const apply = (x) => {
    let out = 0;
    for (let b = 0; b < 8; b++) {
      const s = cols[b];
      let v = s[8];                          // 常量位
      for (let k = 0; k < 8; k++) if ((x >>> k) & 1) v ^= s[k];
      out |= (v & 1) << b;
    }
    return out;
  };
  for (let i = 0; i < 256; i++) if (apply(std[i]) !== custom[i]) return null;
  // 判断矩阵是否可逆（决定"能否精确还原标准表"）
  const inv = (() => {
    // 把 A 表示为 8 个 8 位列向量，做 GF(2) 求逆
    const mat = Array.from({ length: 8 }, (_, r) => Array.from({ length: 8 }, (_, c) => cols[c][r]));
    const aug = mat.map((row, r) => row.concat(Array.from({ length: 8 }, (_, c) => (r === c ? 1 : 0))));
    let pr = 0;
    for (let col = 0; col < 8; col++) {
      let sel = -1;
      for (let r = pr; r < 8; r++) if (aug[r][col]) { sel = r; break; }
      if (sel < 0) return null;
      [aug[pr], aug[sel]] = [aug[sel], aug[pr]];
      for (let r = 0; r < 8; r++) {
        if (r === pr || !aug[r][col]) continue;
        for (let k = 0; k < 16; k++) aug[r][k] ^= aug[pr][k];
      }
      pr++;
    }
    return aug.map(row => row.slice(8));
  })();
  return { cols, invertible: !!inv, identity: cols.every((s, b) =>
    s[8] === 0 && s.every((v, k) => k === 8 ? v === 0 : v === (k === b ? 1 : 0))) };
}

// 对给定表，找出与哪个标准表最接近，并给出精确关系描述
function classifySbox(table) {
  const results = [];
  for (const { name, table: std } of BYTE_SBOXES) {
    let same = 0;
    const xorSet = new Set();
    let addConsistent = true, firstAdd = null;
    for (let i = 0; i < 256; i++) {
      if (table[i] === std[i]) same++;
      xorSet.add(table[i] ^ std[i]);
      const a = (table[i] - std[i]) & 0xff;
      if (firstAdd === null) firstAdd = a; else if (a !== firstAdd) addConsistent = false;
    }
    let relation = null;
    if (same === 256) relation = { kind: 'exact', desc: `与标准 ${name} 完全相同` };
    else if (xorSet.size === 1) {
      const x = [...xorSet][0];
      relation = { kind: 'xor', key: x, desc: `与标准 ${name} 逐项 XOR 0x${x.toString(16).padStart(2, '0')}（可精确还原）` };
    } else if (addConsistent) {
      relation = { kind: 'add', key: firstAdd, desc: `与标准 ${name} 逐项 +0x${firstAdd.toString(16).padStart(2, '0')} mod 256（可精确还原）` };
    } else {
      const aff = gf2AffineFit(table, std);
      if (aff) {
        relation = aff.identity
          ? { kind: 'affine-identity', desc: `与标准 ${name} 为恒等仿射（等价）` }
          : { kind: 'affine', invertible: aff.invertible,
              desc: `与标准 ${name} 满足 GF(2) 仿射关系（8×8 可逆矩阵${aff.invertible ? '，可精确还原' : '不可逆，只能正向计算'}）` };
      }
    }
    results.push({ name, same, relation });
  }
  // 排序：有关系 > 相同项数多
  results.sort((a, b) => (b.relation ? 1 : 0) - (a.relation ? 1 : 0) || b.same - a.same);
  return results;
}

function analyzeCustomBlockConstants(buf, size, sboxOff, sboxStride, valueLane) {
  const notes = [];
  const table = [];
  for (let i = 0; i < 256; i++) table.push(buf[sboxOff + i * sboxStride] & 0xff);

  // ---- 0) S 盒密码学指标：非线性度（区分"精心设计表"与"随机占位表"）----
  // 来源：看雪《常见对称加密算法的混淆层(S盒)及其密码学指标》
  // 定义：NL = 2^(n-1) - (1/2)·max|Walsh 谱|（n=8 → 128 - maxW/2）。
  // 实测标定（本机随机置换 ×8）：AES=112、SM4=112、随机置换 90~96。
  // 判据：≥104 → 精心设计；≤100 → 与随机置换同档，疑似占位/噪声表。
  // ⚠️ 历史缺陷（已修）：旧实现 two bugs——
  //    ① 奇偶校验写成 (v ^ (v>>4) ^ (v>>2) ^ (v>>1)) & 1（三个移位都从**原始值**算），
  //       漏掉 bit3/bit7 的高位传播，导致所有表 maxW 恒等于 256；
  //    ② 非线性度少除以 2（Walsh 定义里 max|W| 的一半），于是所有表都算出 -128。
  //       两者叠加把 AES/SM4 标准表也判成"随机占位表"，会误导 AI 放弃真 S 盒。
  const PARITY8 = (() => {
    const t = new Uint8Array(256);
    for (let i = 0; i < 256; i++) { let v = i; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1; t[i] = v & 1; }
    return t;
  })();
  const walshMax = (() => {
    // Walsh 谱：对每个输出 mask b 与输入 mask a，统计 Σ(-1)^(a·x ⊕ b·S(x))
    let maxAbs = 0;
    for (let b = 1; b < 256; b++) {   // b=0 全零掩码无信息量
      for (let a = 1; a < 256; a++) {
        let sum = 0;
        for (let x = 0; x < 256; x++) sum += PARITY8[(a & x) ^ (b & table[x])] ? -1 : 1;
        const ab = Math.abs(sum);
        if (ab > maxAbs) maxAbs = ab;
      }
    }
    return maxAbs;
  })();
  const nonlinearity = 128 - walshMax / 2;
  // ⚠️ 判据只描述"设计强度"，**绝不据此劝退**：
  //    CTF 题里的自定义 S 盒大量是随机生成的置换（只要双射就能加解密），非线性度自然接近
  //    随机置换（实测 Disguise stage2 = 98）。若按"像随机表 → 别当密码表"去建议，
  //    AI 会放弃一个真实在用、且能直接解出 flag 的表（这是比漏报更严重的误导）。
  //    正确语义：低非线性度 = "这是自定义/非标准设计的表，但仍要按 S 盒用"。
  if (nonlinearity >= 104) {
    notes.push(`S 盒非线性度 ${nonlinearity}（AES/SM4 标准表=112）→ 精心设计的密码 S 盒`);
  } else {
    notes.push(`S 盒非线性度 ${nonlinearity}（随机置换约 90~96，标准 AES/SM4=112）→ 该表**不是标准设计**，` +
      `多为题目自造（随机置换也能当 S 盒用，CTF 常见）。这不影响它作为 S 盒使用：直接用题目表，别因"设计强度低"排除它`);
  }

  // ---- 1) S 盒与标准算法表的关系（精确 / XOR / ADD / GF(2) 仿射）----
  // 这是"变体识别"的核心：不只回答"像不像"，而是回答"能不能精确还原、怎么还原"。
  const cls = classifySbox(table);
  const related = cls.filter(c => c.relation);
  for (const c of related) {
    notes.push(`S 盒关系：${c.relation.desc}`);
  }
  if (!related.length) {
    const top = cls[0];
    notes.push(`S 盒与标准 SM4/AES 表**无任何可还原关系**（最多 ${top.name} 偶然重合 ${top.same}/256 项，属随机双射的正常现象）`);
    notes.push('→ 这是全新 S 盒：无法从标准表推导，必须直接从文件读表使用（轮结构仍可能是 SM4/AES 骨架）');
  }
  const sboxRelation = related.length ? related[0] : null;

  // ---- 2) 在 S 盒附近搜 32 项 dword 表（SM4 CK 形态）----
  // 搜索范围：S 盒前后 0x4000 字节，按 4 字节对齐。
  // sboxOff 是**值读取起点**（可能 = 窗口起点 + valueLane），dword 表只能从窗口起点
  // 按 4 字节对齐开始，否则会错位扫出 unaligned 的假 CK/FK 候选。
  const windowOff = sboxOff - (valueLane || 0);
  const lo = Math.max(0, windowOff - 0x4000), hi = Math.min(size - 128, windowOff + 0x4000);
  const looksLikeCK = (off) => {
    // CK 形态判据（放宽）：32 个 dword，且**同一字节位上的增量一致**。
    // 标准 SM4 CK 每项 = 前项 + 0x07070707（四字节各 +7）；魔改题常整体加常量，
    // 于是增量变成 0x06070707 / 0x08070707 之类——只要求"四字节各自增量稳定"即可。
    const deltas = [[], [], [], []];
    for (let i = 1; i < 32; i++) {
      const a = buf.readUInt32LE(off + (i - 1) * 4), b = buf.readUInt32LE(off + i * 4);
      for (let k = 0; k < 4; k++) {
        deltas[k].push(((b >>> (k * 8)) - (a >>> (k * 8))) & 0xff);
      }
    }
    // 每个字节位的 31 个增量必须几乎全相同（允许 1~2 处进位噪声）
    let stableBytes = 0;
    for (let k = 0; k < 4; k++) {
      const freq = {};
      for (const d of deltas[k]) freq[d] = (freq[d] || 0) + 1;
      const best = Math.max(...Object.values(freq));
      if (best >= 29) stableBytes++;
    }
    return stableBytes >= 3;   // 至少 3 个字节位增量稳定
  };
  let ckOff = -1;
  {
    // 只在"与标准 CK 存在**固定差分**"的表里选（这是 CK 与普通规律表的关键区别）。
    // 标准 CK 的构造是 ck_ij=(4i+j)*7，任何"整体 + 常量 / 每字节 + 常量 / 字节反序"的魔改
    // 都保持固定差分；而普通的递增表（如某个循环计数器数组）不会与标准 CK 有任何固定关系。
    for (let off = lo; off + 128 <= hi; off += 4) {
      if (!looksLikeCK(off)) continue;
      const ck = [];
      for (let i = 0; i < 32; i++) ck.push(buf.readUInt32LE(off + i * 4));
      const d0 = (ck[0] - STD_SM4_CK[0]) >>> 0;
      const fixedWord = ck.every((v, i) => (((v - STD_SM4_CK[i]) >>> 0) === d0));
      const dr = (ck[0] - bswap32(STD_SM4_CK[0])) >>> 0;
      const fixedBswap = ck.every((v, i) => (((v - bswap32(STD_SM4_CK[i])) >>> 0) === dr));
      // 每字节固定差
      let fixedPerByte = true, pbDelta = null;
      for (let k = 0; k < 4 && fixedPerByte; k++) {
        const once = ((ck[0] >>> (k * 8)) - (STD_SM4_CK[0] >>> (k * 8))) & 0xff;
        if (pbDelta === null) pbDelta = once; else if (pbDelta !== once) fixedPerByte = false;
        if (!fixedPerByte) break;
        for (let i = 1; i < 32; i++) {
          const want = (((STD_SM4_CK[i] >>> (k * 8)) + pbDelta) & 0xff);
          if (((ck[i] >>> (k * 8)) & 0xff) !== want) { fixedPerByte = false; break; }
        }
      }
      if (fixedWord || fixedBswap || fixedPerByte) { ckOff = off; break; }
    }
  }
  if (ckOff >= 0) {
    const ck = [];
    for (let i = 0; i < 32; i++) ck.push(buf.readUInt32LE(ckOff + i * 4));
    // 与标准 CK 的差分（四种可能：原样 / 整字+常量 / 每字节+常量 / 字节反序）
    const diffWord = (ck[0] - STD_SM4_CK[0]) >>> 0;
    const allWordSame = ck.every((v, i) => (((v - STD_SM4_CK[i]) >>> 0) === diffWord));
    const diffRevWord = (ck[0] - bswap32(STD_SM4_CK[0])) >>> 0;
    const allRevSame = ck.every((v, i) => (((v - bswap32(STD_SM4_CK[i])) >>> 0) === diffRevWord));
    // 每字节固定差：先由首项四个字节位算出 delta[0..3]，再逐项校验
    const pb = [];
    let perByteSame = true;
    for (let k = 0; k < 4; k++) {
      const d = (((ck[0] >>> (k * 8)) & 0xff) - ((STD_SM4_CK[0] >>> (k * 8)) & 0xff) + 256) & 0xff;
      pb.push(d);
      for (let i = 1; i < 32; i++) {
        const want = ((((STD_SM4_CK[i] >>> (k * 8)) & 0xff) + d) & 0xff);
        if (((ck[i] >>> (k * 8)) & 0xff) !== want) { perByteSame = false; break; }
      }
      if (!perByteSame) break;
    }
    // 每个字节位内的实际步进（用于描述表的形态）
    const step = (((ck[1] - ck[0]) >>> 0)).toString(16);
    notes.push(`找到轮常量表 @文件偏移 0x${ckOff.toString(16)}（32 项，相邻步进 0x${step}，SM4 CK 形态）`);
    if (allWordSame && diffWord === 0) notes.push('该表 = **标准 SM4 CK 原样**');
    else if (allWordSame) notes.push(`该表 = 标准 SM4 CK + 0x${diffWord.toString(16)}（整字常量差）`);
    else if (allRevSame) notes.push(`该表 = bswap(标准 SM4 CK) + 0x${diffRevWord.toString(16)}——**每 dword 字节反序**`);
    else if (perByteSame) {
      const uniform = pb.every(x => x === pb[0]);
      notes.push(uniform
        ? `该表 = 标准 SM4 CK 的**每一字节都 +0x${pb[0].toString(16)}**（等价整字差 0x${(pb[0] * 0x01010101 >>> 0).toString(16)}）`
        : `该表 = 标准 SM4 CK 的四个字节位分别 +[${pb.map(x => '0x' + x.toString(16)).join(', ')}]`);
    }
    else notes.push('该表与标准 CK 的差分**不是固定值**（逐项不同）→ 轮常量被逐项替换，请直接从该表原样取用，不要试图还原标准值');
  }

  // ---- 3) 在附近搜 16 字节 FK 候选（收集**多个**候选，而不是只取第一个）----
  // 为什么：完全自定义的 FK 与标准表无任何固定差分，只能靠形态识别 → 必然有误报。
  // 与其赌一个，不如把候选都交给解密脚本逐个试（16 字节常量 + 试错成本极低）。
  const fkCands = [];
  for (let off = lo; off + 16 <= hi; off += 4) {
    const v = [0, 1, 2, 3].map(i => buf.readUInt32LE(off + i * 4));
    if (v.every((x, i) => x === STD_SM4_FK[i])) { fkCands.push({ off, kind: '标准 FK 原样' }); continue; }
    const d = (v[0] - STD_SM4_FK[0]) >>> 0;
    if (v.every((x, i) => (((x - STD_SM4_FK[i]) >>> 0) === d))) { fkCands.push({ off, kind: `标准 FK + 0x${d.toString(16)}` }); continue; }
    const dr = (v[0] - bswap32(STD_SM4_FK[0])) >>> 0;
    if (v.every((x, i) => (((x - bswap32(STD_SM4_FK[i])) >>> 0) === dr))) { fkCands.push({ off, kind: `bswap(标准 FK) + 0x${dr.toString(16)}` }); continue; }
  }
  // 兜底：形态匹配（完全自定义 FK）。**不能先到先得**——实测 0xa630 附近有大量高熵数据，
  // 会把真值（0x10a10，紧邻 key/CK）挤掉。改为全量收集后按"到 CK 的距离"排序。
  if (!fkCands.length) {
    const shapeCands = [];
    // 已知常量表的占位区间——FK 不能与它们重叠（CK 本身就是高熵表，会自我误匹配）
    const occupied = [];
    if (ckOff >= 0) occupied.push([ckOff, ckOff + 128]);
    occupied.push([sboxOff, sboxOff + 256 * (sboxStride || 1)]);
    const overlapAny = (off) => occupied.some(([a, b]) => off < b && off + 16 > a);
    for (let off = lo; off + 16 <= hi; off += 4) {
      if (overlapAny(off)) continue;
      const v = [0, 1, 2, 3].map(i => buf.readUInt32LE(off + i * 4));
      if (v.some(x => x === 0)) continue;
      if (new Set(v).size !== 4) continue;
      const nonZeroBytes = v.reduce((n, x) => n + [0, 1, 2, 3].filter(k => ((x >>> (k * 8)) & 0xff) !== 0).length, 0);
      if (nonZeroBytes < 14) continue;
      shapeCands.push({ off, dist: Math.abs(off - (ckOff >= 0 ? ckOff : sboxOff)) });
    }
    shapeCands.sort((a, b) => a.dist - b.dist);
    // 取"距 CK 最近的 24 个"，再按距离排序（真值通常紧邻 CK/key，但邻近会有大量噪声）
    for (const c of shapeCands.slice(0, 24)) {
      fkCands.push({ off: c.off, kind: '**完全自定义**（形态匹配候选）' });
    }
  }
  // ⚠️ 启发式定位 FK 本质上不可靠（完全自定义的 FK 与标准表无任何关系，周围还全是噪声）。
  // 稳妥做法：把**所有**疑似常量块都交给解密脚本枚举——每个候选只多 32 轮密钥扩展，
  // 成本可忽略；这比"赌一个位置"可靠得多。故此处在笔记里提示脚本会全量枚举。
  if (fkCands.length) {
    notes.push(`FK 定位不可靠（自定义 FK 无固定特征）→ 生成脚本时会枚举文件内**所有** 16 字节常量块，不要只信第一个候选`);
  }
  const fkOffList = fkCands.map(c => c.off);
  const fkOff = fkCands.length ? fkCands[0].off : -1;
  if (fkCands.length) {
    notes.push(`FK 候选 ${fkCands.length} 个：` + fkCands.slice(0, 5).map(c => `0x${c.off.toString(16)}（${c.kind}）`).join('、')
      + (fkCands.length > 5 ? ' …' : ''));
  }

  // ---- 4) 字节序线索 ----
  // valueLane > 0 时值不在 dword 的低字节（cnbragon 是 `00 v v v`，值在 lane 1），
  // 此时必须明确写出值 lane，否则 AI 会按"低字节"读表得到全 0/错位表。
  if (sboxStride === 4) {
    notes.push(valueLane
      ? `S 盒按 **dword 数组**存放，值在 **lane ${valueLane}**（窗口起点 0x${(sboxOff - valueLane).toString(16)}）` +
        `→ 读表用 \`d[0x${sboxOff.toString(16)} + i*4]\`，不要按低字节读`
      : 'S 盒按 **dword 数组**存放（每项 4 字节、值在低字节）→ 读表时必须按 4 字节步长取低字节，不能当连续 256 字节读');
  }
  if (ckOff >= 0) {
    const asBE = [];
    for (let i = 0; i < 4; i++) asBE.push(buf.readUInt32BE(ckOff + i * 4));
    const beMatchesStd = asBE.every((v, i) => v === STD_SM4_CK[i]);
    notes.push(beMatchesStd
      ? '轮常量按**大端**存放（可直接当 SM4 的 CK 用）'
      : '轮常量按**小端**存放（若用标准 SM4 实现需注意字节序）');
  }

  return {
    sboxFileOffset: '0x' + sboxOff.toString(16),
    sboxStride,
    // S 盒与标准算法的关系（exact/xor/add/affine/无）；AI 据此决定"还原标准表"还是"直接用题目表"
    sboxRelation: sboxRelation ? {
      relatedTo: sboxRelation.name,
      kind: sboxRelation.relation.kind,
      same: sboxRelation.same,
      desc: sboxRelation.relation.desc,
    } : { relatedTo: null, kind: 'custom', same: cls[0] ? cls[0].same : 0, desc: '全新 S 盒，无法从标准表推导' },
    sboxClassification: cls.map(c => ({ name: c.name, same: c.same, relation: c.relation ? c.relation.desc : null })),
    ckFileOffset: ckOff >= 0 ? '0x' + ckOff.toString(16) : null,
    fkFileOffset: fkOff >= 0 ? '0x' + fkOff.toString(16) : null,
    fkCandidates: fkOffList.map(x => '0x' + x.toString(16)),
    notes,
  };
}

// ============ 结构推理（Phase B 最小版）============
// 目标：从文件字节推断"这是哪个分组密码骨架"，给 AI 一个**带置信度的假设**，
// 让 AI 决定用什么路线（而不是工具替它定案）。
//
// 推理证据（全部确定性）：
//   ① 轮常量表形态：
//      · 32 项 dword 且与标准 SM4 CK 存在固定差分 → SM4 骨架（极强证据）
//      · 10 项单字节（Rcon 形态）+ 256B S 盒 → AES 骨架
//   ② S 盒身份：classifySbox 判定与标准表的关系（exact/xor/add/affine/custom）
//   ③ 密文/明文长度对齐：16 字节块（AES/SM4）vs 8 字节块（DES/Blowfish）
// 输出：候选骨架列表（按证据强度排序），每项附证据与建议。
function inferCipherStructure(buf, size, ca) {
  const out = [];
  const has = (v) => !!v;
  const sboxRel = ca && ca.sboxRelation;
  const ckOff = ca && ca.ckFileOffset ? parseInt(ca.ckFileOffset, 16) : -1;

  // --- SM4 骨架证据 ---
  if (ckOff >= 0) {
    const ck = [];
    for (let i = 0; i < 32; i++) ck.push(buf.readUInt32LE(ckOff + i * 4));
    const d0 = (ck[0] - T_SM4.CK[0]) >>> 0;
    const fixedWord = ck.every((v, i) => (((v - T_SM4.CK[i]) >>> 0) === d0));
    // 每字节固定差
    let perByte = true;
    const pb = [];
    for (let k = 0; k < 4 && perByte; k++) {
      const d = (((ck[0] >>> (k * 8)) & 0xff) - ((T_SM4.CK[0] >>> (k * 8)) & 0xff) + 256) & 0xff;
      pb.push(d);
      for (let i = 1; i < 32; i++) {
        const want = ((((T_SM4.CK[i] >>> (k * 8)) & 0xff) + d) & 0xff);
        if (((ck[i] >>> (k * 8)) & 0xff) !== want) { perByte = false; break; }
      }
    }
    if (fixedWord || perByte) {
      out.push({
        skeleton: 'SM4',
        confidence: 'high',
        evidence: `轮常量表 @0x${ckOff.toString(16)} 与标准 SM4 CK 存在固定差分（${fixedWord ? '整字 0x' + d0.toString(16) : '每字节 +[' + pb.map(x => '0x' + x.toString(16)).join(',') + ']'}）` +
          (sboxRel && sboxRel.relatedTo === 'SM4' ? '；S 盒' + sboxRel.desc : '；S 盒为自定义（无法从标准表推导）'),
        advice: '按 SM4 结构照抄：32 轮 + X^X^X^rk + 4 字节并行 S 盒。可用 gen_sm4_solver 生成全组合解密脚本。',
      });
    }
  }

  // --- AES 骨架证据 ---
  if (sboxRel && (sboxRel.relatedTo === 'AES')) {
    // 找 Rcon：10 个单字节 01 02 04 08 10 20 40 80 1b 36（可整体 XOR 偏移）
    let rconOff = -1, rconXor = 0;
    const lo = Math.max(0, (ca.sboxFileOffset ? parseInt(ca.sboxFileOffset, 16) : 0) - 0x4000);
    const hi = Math.min(size, lo + 0x8000);
    for (let off = lo; off + 10 <= hi; off++) {
      const d = buf[off] ^ T_AES.RCON[0];
      let ok = true;
      for (let i = 0; i < 10; i++) if ((buf[off + i] ^ d) !== T_AES.RCON[i]) { ok = false; break; }
      if (ok) { rconOff = off; rconXor = d; break; }
    }
    out.push({
      skeleton: 'AES',
      confidence: rconOff >= 0 ? 'high' : 'medium',
      evidence: `S 盒${sboxRel.desc}` +
        (rconOff >= 0 ? `；轮常量 Rcon @0x${rconOff.toString(16)}（${rconXor ? 'XOR 0x' + rconXor.toString(16) : '原样'}）——AES 密钥扩展铁证` : '；未找到 Rcon（可能被替换或不在扫描范围）'),
      advice: '按 AES 结构照抄：SubBytes/ShiftRows/MixColumns/AddRoundKey。轮数看 key 长度（16→10、24→12、32→14）；' +
        'S 盒' + (sboxRel.kind === 'exact' ? '为标准' : '需按关系还原或直接用题目表') + '。' +
        '可用 gen_block_cipher_solver(skeleton="aes") 生成解密脚本（仅标准轮数 10/12/14；' +
        '轮数被改的变体需按反编译手写）。',
      rconOffset: rconOff,
      rconXor: rconXor,
    });
  }

  // --- 8 字节块骨架（DES/Blowfish）---
  // 最小版只做占位提示（正确率依赖形状扫描，留待 Phase C）
  if (!out.length) {
    out.push({
      skeleton: '未知',
      confidence: 'low',
      evidence: '未找到 SM4 CK 形态表，S 盒与标准 AES/SM4 也无可还原关系',
      advice: '可能是：①全新 S 盒的 SM4/AES 变体（轮结构仍标准）②DES/Blowfish 变体 ③完全自定义算法。' +
        '建议：反编译找轮循环与 S 盒查表方式，确认骨架后再写实现。',
    });
  }
  return out;
}

// ============ SM4 变体解密脚本生成器（通用）============
// 为什么需要：实测 Disguise stage2，AI 已经拿到全部常量，但仍在"字节序/块内排列"上耗掉
// 300+ 秒。这些是**有限可枚举**的组合（每块 dword 反序 × 轮密钥逆序 × 输出 dword 反序 × 块反序
// = 16 种），工具一次性全跑完并直接给出命中结果，比让 AI 逐个试快一个数量级。
//
// 触发条件（全部满足才生成，避免误报）：
//   · 确认是自定义分组密码（有 S 盒）
//   · 找到轮常量表（CK 形态）
//   · 找到 FK 候选
//   · 在文件里找到「疑似密文」：长度是 16 的倍数（≥32 字节）、高熵、位于 FK/CK 附近
// 从 off 开始，测量"连续高熵区"的长度（按 16 字节块推进，遇到低熵/含零块即停）。
// 用途：密文长度由**数据本身**决定，而不是假设 32/48/64（那会变成针对某道题的特解）。
// 返回长度（向下取整到 16 的倍数）；不足 16 返回 0。
function entropyRun(buf, size, off, maxLen) {
  let len = 0;
  const limit = Math.min(size, off + maxLen);
  while (off + len + 16 <= limit) {
    const p = off + len;
    const seen = new Set();
    let zeros = 0;
    for (let i = 0; i < 16; i++) { const b = buf[p + i]; if (b === 0) zeros++; seen.add(b); }
    // 一块可接受为"密文块"的条件：零字节 ≤2 且不同字节数 ≥10
    if (zeros > 2 || seen.size < 10) break;
    len += 16;
  }
  return len;
}

function findCiphertextCandidate(buf, size, hints) {
  // === 策略 1（最强）：key 字符串 + 紧邻密文 ===
  // CTF 题里 "16 字节可打印密钥 + 少量填充 + 高熵密文" 是极常见的常量布局
  // （实测 Disguise：key@0xfa00 → 8 字节 0 填充 → 密文@0xfa18）。
  // 这个模式**远比"随便找个高熵块"可靠**，因为 key 的可打印性是强信号。
  const keyLike = [];
  // 密钥长度不写死 16：AES-192/256 是 24/32，SM4/分组密码常见 16。
  // 这里只处理 16 字节（SM4 变体脚本的入口），其余长度由 AI/其他算法分支处理。
  for (let off = 0; off + 16 <= size; off++) {
    let ok = true;
    for (let i = 0; i < 16; i++) {
      const b = buf[off + i];
      if (b < 0x20 || b > 0x7e) { ok = false; break; }
    }
    if (!ok) continue;
    // ⚠️ 错位切片去重（回归实测）：真 key（如 AEStestkey123456 在 0x33 可打印填充中）的
    //    每个内部错位切片（'333333333333AESt' 等）也能通过 16 字节可打印检查，且数量远超
    //    真 key，会把真 key 挤出 top6。"前后非可打印"判据在可打印填充场景失效。
    //    改为：先全量收集，后面统一做**"最长代表"去重**——被更长串完整包含的窗口视为切片。
    const s = buf.slice(off, off + 16).toString('latin1');
    if (!/[A-Za-z]/.test(s)) continue;
    if (!/[A-Za-z0-9_]{8,}/.test(s)) continue;
    // "像口令"打分：下划线/大小写混合/数字/无空格 → 高分（实测 key 往往是 We1c0me_t0_xmctf 这类）
    let score = 0;
    if (/_/.test(s)) score += 5;
    if (/\d/.test(s)) score += 3;
    if (/[a-z]/.test(s) && /[A-Z]/.test(s)) score += 3;
    if (/ /.test(s)) score -= 6;                 // 含空格多半是句子/提示文本
    if (/\.(dll|exe|dll|pdb)/i.test(s)) score -= 8;
    if (/^\d+$/.test(s)) score -= 5;
    // 结构性边界加分（通用判据，不依赖具体样本）：硬编码 key 是字符串字面量/字节数组，
    // 其**结尾**必邻接非可打印字节（NUL 终止符、二进制常量、对齐零）；而填充区里的
    // 错位切片（如 0x33 填充里的 '333333333333AESt'）首尾都是填充字符。
    // 实测：合成 AES 样本里真 key 与 16 个切片打分全同（同含大小写+数字），仅靠口令打分
    // 无法区分、切片按文件序先于真 key。"结尾边界"是字符串字面量的铁证——随机的 16 字节
    // 可打印窗口恰好终止在非可打印字节上的概率极低，而填充切片永远不满足。
    // 只做**加分**（排序），不做过滤：key 嵌在可打印填充里时（两个边界都失效）仍要保留。
    const endByte = buf[off + 16];
    if (endByte === undefined || endByte < 0x20 || endByte > 0x7e) score += 3;
    const prevByte = off > 0 ? buf[off - 1] : 0;
    if (prevByte < 0x20 || prevByte > 0x7e) score += 1;
    keyLike.push({ off, s, score });
  }
  // 按分数降序：最像口令的 key 优先（它的相邻密文才是最可能的真密文）
  keyLike.sort((a, b) => b.score - a.score);
  // ⚠️ "最长代表"去重：同一可打印区里，错位切片（子串关系）只保留得分最高的那个完整窗口。
  //    实现简化：若某窗口的串与另一更长窗口的串在文件中是同一区域的切片（偏移差 <16 且内容互为
  //    包含），视为同区。做法：按分数排序后，若某低分窗口的串是某高分窗口串的"同区域重叠"
  //    （|off差|<16），且高分窗口的串包含低分窗口独有的关键内容，则跳过低分窗口。
  //    更简单可靠的实现：**按内容去重**——串相同的合并；串不同的但偏移差 <16 的只留分数最高的。
  const keyDedup = [];
  for (const k of keyLike) {
    const dup = keyDedup.find(x => Math.abs(x.off - k.off) < 16);
    if (dup) {
      if (k.score > dup.score) { dup.off = k.off; dup.s = k.s; dup.score = k.score; }
      continue;
    }
    keyDedup.push(k);
  }
  keyDedup.sort((a, b) => b.score - a.score);
  const tailCands = [];
  for (const k of keyDedup.slice(0, 6)) {  // 只试去重后最像口令的前 6 个 key（避免全文件噪声）
    // 起点判据：**跳过 key 之后的连续零填充，第一个非零字节就是密文起点**。
    // 这比"按 4/16 字节对齐"更可靠（实测两种布局都命中）：
    //   · Disguise：key@0xfa00 → 8 字节零 → 密文@0xfa18（非 16 对齐）
    //   · 合成样本：key@0x2190 → 32 字节零 → 密文@0x21c0（16 对齐）
    // 之前两次踩坑都源于假设对齐：按 4 步进会取到零填充的最后一字节；强制 16 对齐会跳过
    // 真实的 0xfa18。二者都会让整体偏移若干字节 → 解密必然失败。
    //
    // ⚠️ 但不能只收集"一个起点"：keyLike 打分高的窗口可能是**标准表内部的错位切片**
    //    （如 AES S 盒里含 'AEStestkey' 字样的错位窗口会先于真 key 被选中），
    //    其"跳零后首高熵区"不是真密文（样本实测：真 key@0xf0a、密文@0xf3a 被挤出）。
    //    改为收集 key 后 512 字节内**所有**高熵区起点（每 16 字节一个），交给枚举兜底。
    const scanFrom = k.off + 16;
    const scanTo = Math.min(size - 32, k.off + 512);
    let start = scanFrom;
    while (start < scanTo && buf[start] === 0) start++;   // 跳过零填充
    if (start < scanTo) {
      const run = entropyRun(buf, size, start, 512);
      if (run >= 16) {
        tailCands.push({ off: start, len: run, keyOff: k.off, key: k.s, dist: start - k.off, keyScore: k.score, aligned: (start & 15) === 0 });
      }
      // 兜底：同窗口内每 16 字节边界的其余高熵起点（应对 key 定位被污染的场景）
      for (let alt = start + 16; alt + 32 <= scanTo; alt += 16) {
        if (alt >= start + run) break;
        const run2 = entropyRun(buf, size, alt, 512);
        if (run2 >= 32) {
          tailCands.push({ off: alt, len: run2, keyOff: k.off, key: k.s, dist: alt - k.off, keyScore: k.score, aligned: (alt & 15) === 0 });
        }
      }
    }
  }
  if (tailCands.length) {
    // 排序：① key 越"像口令"越优先（最强的信号）② 距 key 越近
    // 注意：**不以对齐为主排序**——实测真实的密文可能不是 16 对齐（Disguise 就是 0xfa18）。
    tailCands.sort((a, b) => (b.keyScore - a.keyScore) || (a.dist - b.dist));
    // 去重（同一密文可能被多个重叠 key 命中）
    const uniq = [];
    for (const c of tailCands) {
      if (uniq.some(u => Math.abs(u.off - c.off) < 16)) continue;
      uniq.push(c);
      if (uniq.length >= 6) break;
    }
    return { cands: uniq, keyHints: keyDedup.map(k => k.s).slice(0, 20), strategy: 'key-adjacent' };
  }

  // === 策略 2（兜底）：靠近常量表的高熵块 ===
  const tables = [
    { off: hints.sboxOff, len: 256 * (hints.sboxStride || 1) },
    { off: hints.ckOff, len: 128 },
    { off: hints.fkOff, len: 16 },
  ].filter(t => t.off >= 0);
  const overlapsTable = (off, len) => tables.some(t => off < t.off + t.len && off + len > t.off);
  const centers = [hints.sboxOff, hints.fkOff, hints.ckOff].filter(x => x >= 0);
  const ranges = centers.map(c => [Math.max(0, c - 0x8000), Math.min(size, c + 0x8000)]);
  const isHighEntropy = (off, len) => {
    if (off < 0 || off + len > size) return null;
    const seen = new Set();
    let zeros = 0;
    for (let i = 0; i < len; i++) { const b = buf[off + i]; if (b === 0) zeros++; seen.add(b); }
    const zRatio = zeros / len;
    if (zRatio > 0.1) return null;
    if (seen.size < Math.min(200, len * 0.6)) return null;
    return { zeros: zRatio, uniq: seen.size };
  };
  const cands2 = [];
  for (const [lo, hi] of ranges.concat([[0, size]])) {
    for (let off = lo; off + 32 <= hi; off += 4) {
      // 跳过已知常量表内部的起点（否则 CK 表自身会被当成"密文"）
      if (off >= 0 && tables.some(t => off >= t.off && off < t.off + t.len)) continue;
      // 分组密码的密文通常从**块边界**开始（16 字节对齐）。这不是题目特解，而是分组密码的
      // 结构约束：常量数组通常按自然对齐存放。实测踩坑：不对齐的窗口会从零填充的最后一字节
      // 起算，导致整体偏移 1~15 字节、解密必然失败。
      // 保留未对齐候选作为兜底（有些编译器把常量塞在任意位置），但排在对齐候选之后。
      const aligned = (off & 15) === 0;
      // 起点首字节不能是零填充（真实密文几乎不以 0x00 开头）
      if (buf[off] === 0) continue;
      // 长度由连续高熵区决定（不再枚举 48/64/32/128 这类固定值）
      const runLen = entropyRun(buf, size, off, 512);
      if (runLen < 32) continue;
      // 若高熵区**跨过**了某个已知表，把它截断到表边界之前（真正的密文不会包含 S 盒/CK）
      let capped = runLen;
      for (const t of tables) {
        if (off < t.off && off + capped > t.off) { capped = t.off - off; break; }
      }
      if (capped < 32) continue;
      if (overlapsTable(off, capped)) continue;
      const he = isHighEntropy(off, capped);
      if (!he) continue;
      const center = centers.length ? centers.reduce((a, b) => a + b, 0) / centers.length : off;
      cands2.push({ off, len: capped, dist: Math.abs(off - center), uniq: he.uniq, aligned });
    }
  }
  if (!cands2.length) return null;
  // 排序：**优先 16 字节对齐**，再按距常量表远近。
  cands2.sort((a, b) => (b.aligned - a.aligned) || (a.dist - b.dist) || (b.uniq - a.uniq));
  const out2 = [];
  for (const c of cands2) {
    if (out2.some(o => Math.abs(o.off - c.off) < 16)) continue;
    out2.push(c);
    if (out2.length >= 12) break;
  }
  return { cands: out2, keyHints: keyDedup.map(k => k.s).slice(0, 20), strategy: 'entropy-near-tables' };
}

function buildSM4VariantDecryptScript({ sboxOff, sboxStride, ckOff, fkOffs, ctCands, keyHints }) {
  const ctList = ctCands.map(c => `    (0x${c.off.toString(16)}, ${c.len}),`).join('\n');
  const fkList = (fkOffs || []).map(o => `    0x${o.toString(16)},`).join('\n');
  const keyList = (keyHints || []).slice(0, 40).map(k => `    ${JSON.stringify(k)},`).join('\n');
  return `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 由 ctf-tool 自动生成：SM4 变体（自定义 S 盒 / FK / CK）全组合枚举解密
#   S 盒 @文件偏移 0x${sboxOff.toString(16)}（stride=${sboxStride}）
#   CK   @文件偏移 ${ckOff >= 0 ? '0x' + ckOff.toString(16) : '（未定位）'}
#   FK/密文候选均由工具按"key 相邻布局"等确定性特征给出；无法唯一确定 → 全部枚举
import struct, itertools, sys

PATH = sys.argv[1] if len(sys.argv) > 1 else r"<目标文件>"
d = open(PATH, "rb").read()
_sz = len(d)

SBOX = [d[${sboxOff} + i * ${sboxStride}] for i in range(256)]
CK   = [struct.unpack_from("<I", d, ${ckOff >= 0 ? ckOff : 0} + i * 4)[0] for i in range(32)]
# 偏移说明：S 盒=0x${sboxOff.toString(16)}，CK=0x${(ckOff >= 0 ? ckOff : 0).toString(16)}（上面是十进制写法，等价）

CT_CANDS = [
${ctList}
]

FK_CANDS = [
${fkList}
]

# 工具从文件里找到的"像口令的 16 字节串"（强提示，优先试）
KEY_HINTS = [
${keyList}
]

# 其余 key 候选：文件里所有 16 字节可打印串（兜底）
KEY_CANDS = []
seen_k = set()
for off in range(0, _sz - 16):
    chunk = d[off:off + 16]
    try:
        s = chunk.decode("ascii")
    except Exception:
        continue
    if all(32 <= ord(c) < 127 for c in s) and chunk not in seen_k:
        seen_k.add(chunk)
        KEY_CANDS.append(chunk)
KEY_CANDS = [k.encode("latin-1") for k in KEY_HINTS] + [k for k in KEY_CANDS if k.decode("latin-1", "ignore") not in KEY_HINTS]
# 分层：工具已按"像口令"给 KEY_HINTS 排序 → 前若干个是强候选。
# 先只用前 3 个 key 跑全部 FK（覆盖绝大多数题），未命中再放开到全部（--all-keys 或自动）。
KEY_TIER1 = KEY_CANDS[:3]
KEY_TIER2 = KEY_CANDS[3:40]
KEY_CANDS = KEY_CANDS[:80]

M = 0xFFFFFFFF
def rotl(x, n): return ((x << n) | (x >> (32 - n))) & M
def tau(a):
    return ((SBOX[(a >> 24) & 0xff] << 24) | (SBOX[(a >> 16) & 0xff] << 16)
            | (SBOX[(a >> 8) & 0xff] << 8) | SBOX[a & 0xff]) & M
def L(b):  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) & M
def Lp(b): return (b ^ rotl(b, 13) ^ rotl(b, 23)) & M

def key_schedule(key_bytes, FK):
    mk = list(struct.unpack(">4I", key_bytes[:16]))
    k = [(mk[i] ^ FK[i]) & M for i in range(4)]
    rk = []
    for i in range(32):
        t = (k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]) & M
        k.append((k[i] ^ Lp(tau(t))) & M)
        rk.append(k[i + 4])
    return rk

def decrypt_block(blk, rk, *, in_bswap, rk_rev, out_bswap, out_swap):
    b = blk
    if in_bswap:
        b = b"".join(b[i:i+4][::-1] for i in range(0, 16, 4))
    x = list(struct.unpack(">4I", b))
    for i in range(32):
        kk = rk[31 - i] if rk_rev else rk[i]
        t = (x[1] ^ x[2] ^ x[3] ^ kk) & M
        x = [x[1], x[2], x[3], (x[0] ^ L(tau(t))) & M]
    # 标准 SM4 的输出是 (X35,X34,X33,X32)，即与内部状态**反序**（out_swap=True）。
    # 很多魔改实现保留原序，所以两种都要试。
    words = [x[3], x[2], x[1], x[0]] if out_swap else x
    o = struct.pack(">4I", *words)
    if out_bswap:
        o = b"".join(o[i:i+4][::-1] for i in range(0, 16, 4))
    return o

FLAG_RE = ("xmctf{", "flag{", "ctf{", "dasctf{", "nssctf{", "sctf{", "iscc{", "hgame{")
import re as _re
# ⚠️ 正则里的花括号在 JS 模板字符串中会被当成转义序列吞掉（{{ }} → { }），
#    因此这里用字符码拼出正则，避免生成出来的脚本拿到错误 pattern。
_LB = chr(123)   # {
_RB = chr(125)   # }
# 通用形态①：prefix{...}（prefix 连写，如 flag{ / synthetic{）。
_GENERIC_FLAG = _re.compile("[A-Za-z][A-Za-z0-9_]{2,24}" + _re.escape(_LB) + "[ -~]{3,120}" + _re.escape(_RB))
# 通用形态②：花括号包一段可打印内容（{...} 可与单词间有空白，如 "ae s{multi_skeleton_ok_42}"）。
# 解密成功的明文是"高可打印比例 + 成对花括号"，这两点已足够识别；
# 只要求 prefix 连写会漏掉前缀含空格/分隔符的题（实测：ae s{multi_skeleton_ok_42} 被拒 → 明明解对却报未命中）。
_GENERIC_BRACE = _re.compile(_re.escape(_LB) + "[ -~]{3,120}" + _re.escape(_RB))
def looks_flag(s):
    # 先剥掉尾部零/空白填充：分组密码解密结果常按 16 字节块补齐，明文后跟零字节。
    # 不剥离的话可打印比例会被拉低到 0.95 以下而误判为"非文本"（样本实测踩坑）。
    # 注意：这里用 chr(0) 拼接，避免正则/字符串里的转义序列在跨语言模板中被提前解释。
    _PAD = chr(0) + chr(13) + chr(10) + " " + chr(9)
    s = s.rstrip(_PAD)
    low = s.lower()
    if any(m in low for m in FLAG_RE):
        return True
    # 通用形态：prefix{可打印内容} 或 {可打印内容}。很多赛题前缀不在上面的列表里
    # （如 synthetic{}/HTB{}/picoCTF{}，甚至前缀带空格的 "ae s{...}"）。
    # 只在"整段几乎全可打印"时才认，避免把随机字节里的偶然 { } 当 flag。
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    if printable < len(s) * 0.95:
        return False
    return bool(_GENERIC_FLAG.search(s)) or bool(_GENERIC_BRACE.search(s))

def rev_words(b):
    out = []
    for i in range(0, len(b), 16):
        blk = b[i:i+16]
        out.append(blk[12:16] + blk[8:12] + blk[4:8] + blk[0:4])
    return b"".join(out)

def rev_bytes(b):
    return b"".join(b[i:i+16][::-1] for i in range(0, len(b), 16))

# ---- FK 候选：工具给的 + 紧邻密文的块 + （可选）全文件枚举 ----
# 全文件枚举很慢，仅当上面都不命中时才启用；用环境变量控制。
fk_all = list(FK_CANDS)
ENUM_ALL = ("--all-fk" in sys.argv)

print("S 盒首4字节:", " ".join("%02x" % x for x in SBOX[:4]))
print("CK首项: 0x%08x" % CK[0])
print("密文候选 %d / FK 候选 %d / key 候选 %d%s"
      % (len(CT_CANDS), len(fk_all), len(KEY_CANDS), "（+全文件枚举）" if ENUM_ALL else ""))

tried = 0
def try_all_fk(fk_list, key_list, tag=""):
    global tried
    for ct_off, ct_len in CT_CANDS:
        CT = d[ct_off:ct_off + ct_len]
        blocks = [CT[i:i+16] for i in range(0, len(CT), 16)]
        if len(blocks) * 16 != len(CT):
            continue
        for fk_off in fk_list:
            FK = list(struct.unpack_from("<4I", d, fk_off))
            for key in key_list:
                rk = key_schedule(key, FK)
                # 廉价预筛：只跑 2 个"最可能"的结构变体（标准输入序 + rk 逆序，输出状态反序的两种）。
                # ⚠️ 预筛必须覆盖输入字节序的**两种**取值：标准 SM4 用 in_bswap=False，
                #    而此前只试 True，导致正确组合被整体过滤掉（样本实测：264 组全跑完仍未命中）。
                # 阈值 8/16 可打印。
                probe_ok = False
                for _ib in (False, True):
                    probe = decrypt_block(blocks[0], rk, in_bswap=_ib, rk_rev=True, out_bswap=False, out_swap=True)
                    ps = probe.decode("latin-1")
                    good = sum(1 for c in ps if 32 <= ord(c) < 127)
                    if good >= 8 or any(ch in ps for ch in "{}_"):
                        probe_ok = True
                        break
                if not probe_ok:
                    continue
                tried += 1
                # 4 个独立维度全枚举：输入字节序 / 轮密钥顺序 / 输出字节序 / 输出状态反序
                # ⚠️ 命中判定分两级：**强命中**（已知 CTF 前缀，立即返回）与
                #    **弱命中**（通用 xxx{...} 形态，先记下、继续找更强的）。
                #    实测教训：字节重排错误时也会出现 xxx{...} 形态（如 e_t01c0mf{Wexmctf...），
                #    若在弱命中上就退出，会漏掉后面 perm=rev_words 的正确结果。
                weak_hit = None
                for in_bswap, rk_rev, out_bswap, out_swap in itertools.product([False, True], repeat=4):
                    pt = b"".join(decrypt_block(b, rk, in_bswap=in_bswap, rk_rev=rk_rev,
                                                out_bswap=out_bswap, out_swap=out_swap) for b in blocks)
                    for perm_name, q in (("asis", pt), ("rev_words", rev_words(pt)), ("rev_bytes", rev_bytes(pt))):
                        s = q.decode("latin-1")
                        strong = any(m in s.lower() for m in FLAG_RE)
                        if strong or looks_flag(s):
                            entry = (strong, ct_off, ct_len, fk_off, key, in_bswap, rk_rev, out_bswap, out_swap, perm_name, s)
                            if strong:
                                print("\\n*** FLAG 命中（强）***")
                                print("密文=0x%x len=%d FK=0x%x key=%r in_bswap=%s rk_rev=%s out_bswap=%s out_swap=%s perm=%s"
                                      % (ct_off, ct_len, fk_off, key, in_bswap, rk_rev, out_bswap, out_swap, perm_name))
                                print("FLAG:", s.rstrip("\\x00"))
                                sys.exit(0)
                            if weak_hit is None:
                                weak_hit = entry
                if weak_hit is not None:
                    _, c_o, c_l, f_o, kk, ib, rr_, ob, os_, pn, ss = weak_hit
                    print("\\n*** FLAG 命中（弱：无已知前缀）***")
                    print("密文=0x%x len=%d FK=0x%x key=%r in_bswap=%s rk_rev=%s out_bswap=%s out_swap=%s perm=%s"
                          % (c_o, c_l, f_o, kk, ib, rr_, ob, os_, pn))
                    print("FLAG:", ss.rstrip("\\x00"))
                    print("（若内容看起来错位，说明块内排列还有别的形态，请检查 perm/字节序）")
                    sys.exit(0)

# 分层：先用"key 与 FK 的字节相似度"排序，最可能的排前面（同一组常量常由同一段代码初始化）
# 分层执行：先用"最像口令的 3 个 key"跑全部 FK（多数题在这里就命中），
# 未命中再放开到其余 key。分层显著缩短典型耗时，且不牺牲召回。
print("阶段 1：%d 个 FK × %d 个高置信 key ..." % (len(fk_all), len(KEY_TIER1)), flush=True)
try_all_fk(fk_all, KEY_TIER1, "tier1")

if len(KEY_TIER2):
    print("阶段 2：补充 key（%d 个）..." % len(KEY_TIER2), flush=True)
    try_all_fk(fk_all, KEY_TIER2, "tier2")

if ENUM_ALL:
    print("阶段 3：全文件枚举 FK（慢）...", flush=True)
    extra = [o for o in range(0, _sz - 16, 4) if o not in fk_all]
    try_all_fk(extra, KEY_CANDS, "all")

print("\\n未命中（共尝试 %d 组）。" % tried)
print("提示：加 --all-fk 参数可对全文件枚举 FK。")
`;
}

// ============ AES 变体解密脚本生成器（Phase C-2）============
// 触发条件（scan_crypto/analyze_structure 已确认）：
//   · S 盒与标准 AES 表存在关系（exact/xor/add/affine），或为自定义表
//   · 找到 Rcon 形态轮常量（AES 密钥扩展铁证）
// 枚举维度（外围框架与 SM4 相同）：
//   · key 长度 16/24/32（对应轮数 10/12/14）
//   · 轮数变体（魔改题可能改轮数：± 标准轮数）
//   · 输入/输出字节序、状态重排
//   · key 候选（keyHints + 全文件可打印串，按 16/24/32 分别尝试）
// ============ AES 变体解密脚本生成器（Phase C-2，pycryptodome 主路径）============
// 为什么用 pycryptodome 而非手写解密：
//   手写 InvCipher 三处耦合（InvShiftRows 方向/轮密钥交互/InvMixColumns 位置），
//   单轮对、多轮错，调试成本远高于直接用已验证的库（pycryptodome 环境已确认存在，
//   工具的 SM4 路径同样依赖 gmssl/pycryptodome）。
// 覆盖：标准 AES（key 16/24/32 → 轮数 10/12/14）× ECB 模式 × 字节序/排列外围枚举。
// 诚实边界：轮数被改的变体、MixColumns 矩阵被替换的变体，本脚本不支持
//   （pycryptodome 无法自定义轮数）——未命中时明确提示，AI 按反编译另写。
function buildAESVariantDecryptScript({ sboxOff, sboxStride, ctCands, keyHints, rconOff, sboxRelation }) {
  const ctList = ctCands.map(c => `    (0x${c.off.toString(16)}, ${c.len}),`).join('\n');
  const keyList = (keyHints || []).slice(0, 40).map(k => `    ${JSON.stringify(k)},`).join('\n');
  return `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 由 ctf-tool 自动生成：AES 变体全组合枚举解密（pycryptodome 主路径）
#   S 盒（题目表）@文件偏移 0x${sboxOff.toString(16)}（stride=${sboxStride}）
#   S 盒关系：${sboxRelation ? sboxRelation.desc : '自定义'}
# 枚举：key 候选（16/24/32）× ECB × 输入/输出字节序 × 块排列 × 表选择（题目表→映射标准 / 直接标准）
# 注意：只支持标准轮数（10/12/14）。轮数被改/MixColumns 矩阵被替换 → 需按反编译另写。
from Crypto.Cipher import AES
import struct, itertools, sys, re
import re as _re

PATH = sys.argv[1] if len(sys.argv) > 1 else r"<目标文件>"
d = open(PATH, "rb").read()
_sz = len(d)

# 题目 S 盒（从文件读出）——用于"变表 AES"路线：key 扩展用题目表
SBOX_CUSTOM = [d[${sboxOff} + i * ${sboxStride}] for i in range(256)]
SBOX_CUSTOM_INV = [0] * 256
for i in range(256): SBOX_CUSTOM_INV[SBOX_CUSTOM[i]] = i

# 标准 S 盒（pycryptodome 内部使用，无需构造；此处只用于判断题目表是否标准）
SBOX_STD_FIRST = bytes.fromhex("637c777bf26b6fc5")
_is_std_sbox = bytes(SBOX_CUSTOM[:8]) == SBOX_STD_FIRST

CT_CANDS = [
${ctList}
]

KEY_HINTS = [
${keyList}
]

# key 候选：提示串（补齐/截断到 16/24/32）+ 全文件可打印串
KEY_CANDS = []
seen_k = set()
def _push(k):
    if k and k not in seen_k:
        seen_k.add(k); KEY_CANDS.append(k)
for h in KEY_HINTS:
    hb = h.encode("latin-1", "ignore")
    for _klen in (16, 24, 32):
        if len(hb) >= _klen: _push(hb[:_klen])
        else: _push((hb * ((_klen // max(1, len(hb))) + 1))[:_klen])
for _klen in (16, 24, 32):
    for off in range(0, _sz - _klen):
        chunk = d[off:off + _klen]
        try: s = chunk.decode("ascii")
        except Exception: continue
        if all(32 <= ord(c) < 127 for c in s): _push(chunk)
KEY_CANDS = KEY_CANDS[:80]

# 外围排列
def rev_words(b):
    out = []
    for i in range(0, len(b), 16):
        blk = b[i:i+16]
        out.append(blk[12:16] + blk[8:12] + blk[4:8] + blk[0:4])
    return b"".join(out)
def rev_bytes(b):
    return b"".join(b[i:i+16][::-1] for i in range(0, len(b), 16))

FLAG_RE = ("xmctf{", "flag{", "ctf{", "dasctf{", "nssctf{", "sctf{", "iscc{", "hgame{")
_LB = chr(123); _RB = chr(125)
_GENERIC_FLAG = _re.compile("[A-Za-z][A-Za-z0-9_]{2,24}" + _re.escape(_LB) + "[ -~]{3,120}" + _re.escape(_RB))
# 形态②：{...} 不要求 prefix 连写（前缀可含空格，如 "ae s{multi_skeleton_ok_42}"）。
_GENERIC_BRACE = _re.compile(_re.escape(_LB) + "[ -~]{3,120}" + _re.escape(_RB))
def looks_flag(s):
    _PAD = chr(0) + chr(13) + chr(10) + " " + chr(9)
    s = s.rstrip(_PAD)
    low = s.lower()
    if any(m in low for m in FLAG_RE): return True
    printable = sum(1 for c in s if 32 <= ord(c) < 127)
    if printable < len(s) * 0.95: return False
    return bool(_GENERIC_FLAG.search(s)) or bool(_GENERIC_BRACE.search(s))

print("S 盒(题目)首4:", " ".join("%02x" % x for x in SBOX_CUSTOM[:4]),
      "  标准表:" , _is_std_sbox)
print("key 候选 %d / 密文候选 %d" % (len(KEY_CANDS), len(CT_CANDS)))

tried = 0
weak_hit = None
for ct_off, ct_len in CT_CANDS:
    CT = d[ct_off:ct_off + ct_len]
    if len(CT) % 16 != 0: continue
    blocks = [CT[i:i+16] for i in range(0, len(CT), 16)]
    for key in KEY_CANDS:
        # 路线 A：标准 AES（pycryptodome，最可靠）
        # 路线 B：变表 AES——用 pycryptodome 的密钥扩展做不到（库内 S 盒固定），
        #         但 CTF 变表题常见做法是"标准 key 扩展 + 题目 S 盒"，
        #         而 pycryptodome 无法替换 S 盒 → 此路线仅当题目表==标准表时有效。
        # 变表 AES 的完整支持需要手写实现（见诚实边界），此处先覆盖标准表路线。
        try:
            cipher = AES.new(key, AES.MODE_ECB)
        except Exception:
            continue
        for in_bswap, out_bswap, out_swap in itertools.product([False, True], repeat=3):
            tried += 1
            blocks_p = []
            for b in blocks:
                bb = b
                if in_bswap:
                    bb = b"".join(bb[i:i+4][::-1] for i in range(0, 16, 4))
                blocks_p.append(bb)
            try:
                pt = b"".join(cipher.decrypt(bb) for bb in blocks_p)
            except Exception:
                continue
            if out_bswap:
                pt = b"".join(pt[i:i+4][::-1] for i in range(0, len(pt), 4))
            for perm_name, q in (("asis", pt), ("rev_words", rev_words(pt)), ("rev_bytes", rev_bytes(pt))):
                if out_swap:
                    q = q[::-1]
                s = q.decode("latin-1")
                strong = any(m in s.lower() for m in FLAG_RE)
                if strong or looks_flag(s):
                    if strong:
                        print("\\n*** FLAG 命中（强）***")
                        print("ct=0x%x key=%r klen=%d ib=%s ob=%s os=%s perm=%s"
                              % (ct_off, key, len(key), in_bswap, out_bswap, out_swap, perm_name))
                        print("FLAG:", s.rstrip(chr(0)))
                        sys.exit(0)
                    if weak_hit is None:
                        weak_hit = (ct_off, key, len(key), in_bswap, out_bswap, out_swap, perm_name, s)

if weak_hit:
    (c_o, kk, kl, ib, ob, os_, pn, ss) = weak_hit
    print("\\n*** FLAG 命中（弱）***")
    print("ct=0x%x key=%r klen=%d ib=%s ob=%s os=%s perm=%s" % (c_o, kk, kl, ib, ob, os_, pn))
    print("FLAG:", ss.rstrip(chr(0)))
    sys.exit(0)

print("\\n未命中（共尝试 %d 组）。" % tried)
print("说明：本脚本用 pycryptodome 覆盖标准 AES（ECB，10/12/14 轮）。未命中可能因为：")
print("· 使用了非标准轮数 / MixColumns 矩阵被替换 → 需按反编译手写实现")
print("· CBC/CTR 等链接模式 → 找 IV 后改用 AES.new(key, AES.MODE_CBC, iv)")
print("· key 不是可打印串（硬编码字节数组）→ 用 ida_get_bytes 从密钥扩展函数取")
`;
}

// ============ 多骨架解密脚本统一分发（Phase C-3）============
// AI 调用 gen_block_cipher_solver 时按结构推理结果分发：
//   SM4 骨架 → buildSM4VariantDecryptScript（现有，已实战验证）
//   AES 骨架 → buildAESVariantDecryptScript（新增）
//   DES/Blowfish/未知 → 明确告知不支持，返回证据让 AI 另写（诚实边界，不假装能解）
// 在分析结果里附加"可直接跑的解密脚本"
function attachSM4DecryptScript(buf, size, analysis, sboxOff) {
  const ckOff = analysis.ckFileOffset ? parseInt(analysis.ckFileOffset, 16) : -1;
  const fkOffs = (analysis.fkCandidates || []).map(x => parseInt(x, 16)).filter(x => x >= 0);
  if (ckOff < 0) return null;
  const found = findCiphertextCandidate(buf, size, { sboxOff, ckOff, fkOff: fkOffs[0] || -1 });
  if (!found || !found.cands || !found.cands.length) return null;
  const cts = found.cands;
  // FK 候选：优先用"紧邻密文/key 的 16 字节块"（SM4 初始化里 key/FK/CK 常成组出现），
  // 再加上启发式候选与全文件枚举兜底（脚本内完成）。
  const nearFk = [];
  // FK 候选的三类来源（都**不依赖**具体题目的偏移）：
  //   A. 每个密文候选/key 位置的结构邻近位置（同一组常量常相邻）
  //   B. **整个常量区**（S 盒到 CK 到 key 的包围盒）内的所有高熵 16 字节块 —— 覆盖"FK 被放在
  //      同一节的另一处、与密文不相邻"的常见布局（实测 Disguise：key@0xfa00、FK@0x10a10 相距 4KB）
  //   C. 全文件兜底（按到 key 的距离排序，取最近的若干）
  const STRUCTURAL_DELTAS = [
    0, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
    -16, -32, -48, -64, -96, -128, -192, -256, -384, -512,
  ];
  for (const c of cts) {
    for (const delta of STRUCTURAL_DELTAS) {
      const off = c.off + delta;
      if (off >= 0 && off + 16 <= size) nearFk.push(off);
    }
  }
  // B：**key 附近的同一数据区**内的 16 字节块。
  // 通用依据：SM4/AES 实现会把 key、FK、CK 一起 memcpy 到运行时缓冲区，
  // key 与 FK 通常在同一段连续数据里；而 S 盒/CK 常在另一（只读）段。
  // 只用 **key 位置**作锚点，避免把 S 盒/CK 所在的 .rdata 整段纳入（实测会从 16 个涨到 1573 个）。
  const anchors = [];
  for (const c of cts) if (c.keyOff != null) anchors.push(c.keyOff);
  anchors.push(sboxOff);
  if (ckOff >= 0) anchors.push(ckOff);
  // FK 搜索优先锚点：**key 位置**（key 与 FK 通常在同一个数据段），
  // 其次才是 S 盒/CK（可能在不同段，作为兜底）。
  const keyAnchors = cts.map(c => c.keyOff).filter(x => x != null);
  const searchAnchors = keyAnchors.length ? keyAnchors : anchors;
  // 已知常量表的占位区间：FK 不可能落在 S 盒/CK 表内部
  const occupiedRanges = [];
  occupiedRanges.push([sboxOff, sboxOff + 256 * (analysis.sboxStride || 1)]);
  if (ckOff >= 0) occupiedRanges.push([ckOff, ckOff + 128]);
  const inOccupied = (off) => occupiedRanges.some(([a, b]) => off < b && off + 16 > a);
  if (searchAnchors.length) {
    const kMin = Math.min(...searchAnchors), kMax = Math.max(...searchAnchors);
    const loA = Math.max(0, kMin - 0x2000);
    const hiA = Math.min(size, kMax + 0x4000);
    for (let off = loA; off + 16 <= hiA; off += 4) {
      if (inOccupied(off)) continue;
      const v = [0, 1, 2, 3].map(i => buf.readUInt32LE(off + i * 4));
      if (v.includes(0) || new Set(v).size !== 4) continue;
      const nz = v.reduce((n, x) => n + [0, 1, 2, 3].filter(k => ((x >>> (k * 8)) & 0xff) !== 0).length, 0);
      if (nz < 14) continue;
      const bs = Buffer.from(v.flatMap(x => [x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff]));
      if (bs.every(b => b === 0xcc || b === 0x90)) continue;
      // 排除"可读文本切片"：真正的 FK 是随机常量，16 字节里几乎不会整段是 ASCII 可打印字符。
      // （实测噪声大多来自 key 字符串附近的多字节文本、C++ 符号名等）
      const printable = bs.reduce((n, b) => n + (b >= 0x20 && b <= 0x7e ? 1 : 0), 0);
      if (printable >= 12) continue;
      nearFk.push(off);
    }
  }
  // C：兜底
  if (nearFk.length < 16) {
    const ref = anchors.length ? anchors[0] : 0;
    const all = [];
    for (let off = 0; off + 16 <= size; off += 4) {
      const v = [0, 1, 2, 3].map(i => buf.readUInt32LE(off + i * 4));
      if (v.includes(0) || new Set(v).size !== 4) continue;
      const nz = v.reduce((n, x) => n + [0, 1, 2, 3].filter(k => ((x >>> (k * 8)) & 0xff) !== 0).length, 0);
      if (nz < 14) continue;
      all.push({ off, dist: Math.abs(off - ref) });
    }
    all.sort((a, b) => a.dist - b.dist);
    for (const x of all.slice(0, 24)) nearFk.push(x.off);
  }
  // 去重。**不做数量截断**：每个 FK 候选只多一次 32 轮密钥扩展（微秒级），
  // 而截断会把真正的 FK 挤掉（实测：按距离排序时 0x10a10 被 80 个更近的噪声挤出）。
  // 只把"与锚点极近的"排在前面（大概率是真正的常量组），其余全部保留给脚本枚举。
  const anchorList = anchors.length ? anchors : [0];
  const fkUniq = [...new Set([...nearFk, ...fkOffs])];
  fkUniq.sort((a, b) => {
    const da = Math.min(...anchorList.map(x => Math.abs(a - x)));
    const db = Math.min(...anchorList.map(x => Math.abs(b - x)));
    return da - db;
  });
  const fkList = fkUniq;  return {
    ciphertextCandidates: cts.map(c => ({ offset: '0x' + c.off.toString(16), length: c.len })),
    fkCandidates: fkList.map(x => '0x' + x.toString(16)),
    strategy: found.strategy,
    keyHints: found.keyHints || [],
    script: buildSM4VariantDecryptScript({
      sboxOff, sboxStride: analysis.sboxStride, ckOff,
      fkOffs: fkList, ctCands: cts, keyHints: found.keyHints || [],
    }),
  };
}



// AES 变体解密脚本挂载（Phase C）：结构推理判定 AES 骨架时使用
// 用 pycryptodome 主路径（标准轮数 10/12/14）。诚实边界：轮数被改/矩阵被替换的变体不支持。
// ⚠️ 只对"题目量级"的文件挂载（16MB 上限，与 summary 的 bigBinary 判据一致）：
//    密文候选搜索是 O(size×512)，200MB 通用二进制（如 electron.exe 自带 OpenSSL 表）会卡死；
//    且通用二进制里的标准 S 盒来自密码库，不是本题算法，挂脚本只会误导 AI。
const SOLVER_MAX_SIZE = 16 * 1024 * 1024;
function attachAESDecryptScript(buf, size, analysis, sboxOff, structs) {
  if (size > SOLVER_MAX_SIZE) return null;
  const aes = (structs || []).find(s => s.skeleton === 'AES');
  if (!aes) return null;
  const found = findCiphertextCandidate(buf, size, {
    sboxOff,
    ckOff: -1,
    fkOff: -1,
  });
  if (!found || !found.cands || !found.cands.length) return null;
  const cts = found.cands;
  return {
    ciphertextCandidates: cts.map(c => ({ offset: '0x' + c.off.toString(16), length: c.len })),
    keyHints: found.keyHints || [],
    rconOffset: aes.rconOffset != null ? '0x' + aes.rconOffset.toString(16) : null,
    strategy: 'aes-' + found.strategy,
    skeleton: 'AES',
    script: buildAESVariantDecryptScript({
      sboxOff, sboxStride: analysis.sboxStride, ctCands: cts,
      keyHints: found.keyHints || [], rconOff: aes.rconOffset != null ? aes.rconOffset : -1,
      sboxRelation: analysis.sboxRelation,
    }),
  };
}

function attachBlockCipherSolver(buf, size, analysis, sboxOff) {
  if (size > SOLVER_MAX_SIZE) return null;   // 通用大二进制不挂解密脚本（同 attachAESDecryptScript 的理由）
  const structs = inferCipherStructure(buf, size, analysis);
  const top = structs.find(s => s.skeleton !== '未知') || structs[0];
  if (!top) return null;
  if (top.skeleton === 'SM4') {
    const r = attachSM4DecryptScript(buf, size, analysis, sboxOff);
    return r ? { ...r, skeleton: 'SM4' } : null;
  }
  if (top.skeleton === 'AES') {
    const r = attachAESDecryptScript(buf, size, analysis, sboxOff, structs);
    return r ? { ...r, skeleton: 'AES' } : null;
  }
  return null;
}

// 扫描文件字节，返回确定性算法候选
function scanCryptoFingerprints(filePath) {
  const out = [];
  let buf;
  try { buf = fs.readFileSync(filePath); } catch (e) { return { success: false, error: '读取失败: ' + e.message }; }
  const size = buf.length;
  // 表地址的 xref 闸门要用节表把文件偏移换算成 VA（32 位 PE 绝对引用 / x64 RIP-relative）。
  let imageMap = null;
  try { imageMap = parseImageMap(buf); } catch (e) { imageMap = null; }
  const fileOffToVa = (off) => {
    if (!imageMap || !Array.isArray(imageMap.sections)) return NaN;
    for (const s of imageMap.sections) {
      const rawPtr = Number(s.rawPtr), rawSize = Number(s.rawSize);
      if (!(rawSize > 0) || off < rawPtr || off >= rawPtr + rawSize) continue;
      const secVa = Number(s.va) + (imageMap.vaIsAbsolute ? 0 : (Number(imageMap.imageBase) || 0));
      return secVa + (off - rawPtr);
    }
    return NaN;
  };

  // 1) 已知常量/表模式
  for (const [name, hexPat, desc] of CRYPTO_FP) {
    const pat = hexToBytes(hexPat);
    const hits = findPattern(buf, pat);
    for (const off of hits) {
      out.push({ fp: name, desc, offset: '0x' + off.toString(16), algo: name.split('-')[0].replace(/^(SM4|SM3|AES|MD5|SHA256|TEA|CRC32|RC4|B64)$/, '$1') });
    }
  }

  // 1.5) RC4 初值表：必须是**完整 0..255**（连续字节或 dword 步长）才算证据。
  // 只匹配 "00 01 02 03..." 这种前缀会把几乎所有程序（索引数组/结构体初始化）都误判成 RC4。
  {
    let rc4Off = -1, rc4Stride = 0;
    for (let off = 0; off + 256 <= size && rc4Off < 0; off++) {
      if (buf[off] !== 0 || buf[off + 255] !== 255) continue;
      let ok = true;
      for (let i = 0; i < 256; i++) { if (buf[off + i] !== i) { ok = false; break; } }
      if (ok) { rc4Off = off; rc4Stride = 1; }
    }
    if (rc4Off < 0) {
      for (let off = 0; off + 1024 <= size && rc4Off < 0; off++) {
        if (buf[off] !== 0 || buf[off + 1020] !== 255) continue;
        let ok = true;
        for (let i = 0; i < 256; i++) {
          if (buf[off + i * 4] !== i || buf[off + i * 4 + 1] !== 0) { ok = false; break; }
        }
        if (ok) { rc4Off = off; rc4Stride = 4; }
      }
    }
    if (rc4Off >= 0) out.push({ fp: 'RC4-ID', desc: `完整 0..255 初值表（stride=${rc4Stride}）`, offset: '0x' + rc4Off.toString(16), algo: 'RC4' });
  }

  // 2) 256 项双射表（S 盒候选：0..255 每值恰出现一次）
  //    ⚠️ 必须同时扫**定长步长**形态：C 代码里 S 盒常声明为 `unsigned int sbox[256]`，
  //    即使值域只有 0..255 也占 4 字节/项（`8e 00 00 00 2f 00 00 00 ...`）。
  //    实测 Disguise stage2：自定义 S 盒就是 dword 数组 @0xd630，只扫连续字节会**完全漏掉**
  //    → 这正是此前"AI 每次把 SM4 变体认成 AES 变体"的根因。
  //
  //    性能：直接对每个偏移做 256 项检查是 O(size×256)，在 180MB 的 electron.exe 上会卡死。
  //    改为**滑动窗口预筛**——任何 0..255 的置换都满足 XOR=0 且 Σ=32640（必要条件），
  //    用前缀异或/前缀和可 O(1) 判每个窗口；只有极少数通过这一步的才做完整双射检查。
  //    stride>1 时按"同一余数类"（off, off+stride, ...）建前缀序列，同样适用。
  const sboxCands = [];   // {off, stride, head}
  const PERM_XOR = 0, PERM_SUM = 32640;   // 0..255 的异或和 / 和
  // 平凡表过滤：二进制里的偏移/跳转表、位重排表（bit-reverse/bit-scatter）也是双射但不是 S 盒。
  // 实测区分度极大（相邻差分布的种类数）：
  //   真实 S 盒：AES=160、SM4≈160、自定义/随机置换≈163、Disguise 自定义=169
  //   误报表（ntdll/electron 位重排、msvcrt 偏移表）：6~8
  // 取阈值 100（远高于误报、远低于真实 S 盒）。
  const isTrivialTable = (off, stride) => {
    const dset = new Set(), xset = new Set();
    for (let i = 0; i + 1 < 256; i++) {
      const a = buf[off + i * stride], b = buf[off + (i + 1) * stride];
      dset.add((b - a) & 0xff);
      xset.add(b ^ a);
    }
    if (Math.max(dset.size, xset.size) < 100) return true;
    // GF(2^8) 反对数表（antilog/exp table）：t[i+1] == xtime(t[i])，xtime(x)=(x<<1)^(x&0x80?0x1b:0)。
    // 用于 AES/Rijndael 的 gmul/log 实现，是双射但不是 S 盒（实测 electron.exe 命中两处）。
    // 真实 S 盒该链式关系几乎不成立（命中数接近 0），故以 100 为界。
    let xtimeChain = 0;
    for (let i = 0; i + 1 < 256; i++) {
      const a = buf[off + i * stride], b = buf[off + (i + 1) * stride];
      const xt = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
      if (b === xt) xtimeChain++;
    }
    if (xtimeChain > 100) return true;
    return false;
  };
  const fullBijection = (off, stride) => {
    const seen = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      const b = buf[off + i * stride];
      if (seen[b]) return false;
      seen[b] = 1;
    }
    return true;
  };
  const highBytesZero = (off, stride) => {
    for (let i = 0; i < 256; i++) for (let k = 1; k < stride; k++) if (buf[off + i * stride + k] !== 0) return false;
    return true;
  };
  for (const stride of [1, 2]) {
    // 对每个余数类 r，用**定长滑窗**（窗口=256 项）维护 XOR 与和，O(1) 内存、O(n) 时间。
    // 置换窗口满足 XOR=0 且 Sum=32640（必要条件）；通过者才做完整双射检查。
    for (let r = 0; r < stride && sboxCands.length < 6; r++) {
      const idx = (i) => buf[r + i * stride];
      const n = (size - r - 1 >= 0) ? Math.floor((size - r - 1) / stride) + 1 : 0;
      if (n < 256) continue;
      let wx = 0, ws = 0;
      for (let i = 0; i < 256; i++) { const b = idx(i); wx ^= b; ws += b; }
      for (let k = 0; k + 256 <= n; k++) {
        if (k > 0) {                                   // 滑动：去掉 i=k-1，加入 i=k+255
          const out = idx(k - 1), inn = idx(k + 255);
          wx ^= out; wx ^= inn; ws -= out; ws += inn;
        }
        if (wx !== PERM_XOR || ws !== PERM_SUM) continue;
        const off = r + k * stride;
        if (!fullBijection(off, stride)) continue;
        if (stride > 1 && !highBytesZero(off, stride)) continue;
        if (isTrivialTable(off, stride)) continue;
        const head = Array.from({ length: 4 }, (_, i) => buf[off + i * stride].toString(16).padStart(2, '0')).join('');
        sboxCands.push({ off, stride, head, valueLane: 0 });
        if (sboxCands.length >= 6) break;
      }
    }
    if (sboxCands.length >= 6) break;
  }
  // 2.5) 多 lane 双射表：`00 v v v`（cnbragon）与 `v 00 00 00`（dword 数组）是同一类形态。
  // 旧实现只认"高字节全 0"，把 `00 70 70 70` 直接排除了 → CUSTOM-BLOCK 从未产生。
  // 判据见 electron/crypto-detect.js：所有承载值的 lane 必须逐项相同，其余 lane 恒定。
  if (sboxCands.length < 6) {
    for (const h of detectLaneBijectionTables(buf, 6 - sboxCands.length)) {
      if (sboxCands.some(c => Math.abs(c.off - h.off) < 1024)) continue;
      const head = Array.from({ length: 4 }, (_, i) => buf[h.off + i * 4 + h.valueLane].toString(16).padStart(2, '0')).join('');
      sboxCands.push({
        off: h.off, stride: 4, head, valueLane: h.valueLane,
        // 表项实际取值位置：window 基准 + 值 lane
        valueOff: h.off + h.valueLane,
        constLanes: h.constLanes,
      });
    }
  }
  for (const { off, stride, head, valueLane, valueOff, constLanes } of sboxCands) {
    const isSM4 = head.startsWith('d690e9fe');
    const isAES = head.startsWith('637c777b');
    const isAESInv = head.startsWith('52096ad5');
    // 值不一定落在低字节：cnbragon 的真实布局是 `00 70 70 70`（值在 lane 1）。
    // 旧文案统一写"值在低字节"会让 AI 按错误位置读表。
    const lane = (valueLane === undefined) ? 0 : valueLane;
    const strideNote = stride === 1 ? ''
      : `（表项按 ${stride} 字节步长存放，值在 lane ${lane}${lane === 0 ? '（低字节）' : ''}）`;
    const readOff = (valueOff === undefined) ? off : valueOff;
    // 窗口起点（off）里含 lane 位置；值读取起点是 readOff。分析函数按 readOff 取表。
    // xref 闸门：表必须在代码里有引用；但 x64/ELF 的 RIP-relative 解析不到时只能标
    // "未验证"，**不能**降级（假阴性比假阳性更糟）。32 位 PE 才用绝对 imm32 回退。
    let xref = null;
    try {
      if (imageMap) {
        const algoLabel = isSM4 ? 'SM4' : (isAES ? 'AES' : (isAESInv ? 'AES' : 'CUSTOM-BLOCK'));
        xref = assessTableRefs({ buf, imageMap, tableVa: fileOffToVa(off), algo: algoLabel });
        if (xref && xref.log) console.log(xref.log);
      }
    } catch (e) { xref = null; }
    const item = {
      fp: 'SBOX-256', algo: isSM4 ? 'SM4' : (isAES ? 'AES' : (isAESInv ? 'AES' : 'CUSTOM-BLOCK')),
      desc: isSM4 ? 'SM4 标准 S 盒（256 项双射）'
        : (isAES ? 'AES 标准 S 盒'
        : (isAESInv ? 'AES 逆 S 盒（解密码表）'
        : `自定义分组密码 S 盒（256 项双射，非常见算法）${strideNote}`)),
      offset: '0x' + off.toString(16), head, stride,
      valueLane: lane,
      ...(xref ? { xref: { status: xref.status, refs: xref.refs, evidence: xref.evidence } } : {}),
      ...(constLanes && constLanes.length ? { constLanes } : {}),
    };
    // 自定义 S 盒 → 做**常量差分分析**（纯确定性推导，不猜算法）：
    // 逐个比对标准 SM4/AES 表，找出"是否只是字节变换"，并搜索附近的轮常量表推算差分关系。
    // 实测价值（Disguise stage2）：AI 花了 345 秒/20+ 次脚本，反复纠结 FK/CK 是否被替换、
    // 字节序怎么摆；而这些关系全都可以由工具一次性算出来。
    if (item.algo === 'CUSTOM-BLOCK') {
      try {
        // readOff = 窗口起点 + 值 lane：生成的脚本按 `d[readOff + i*stride]` 取表
        const analysis = analyzeCustomBlockConstants(buf, size, readOff, stride, lane);
        if (analysis) {
          item.constantAnalysis = analysis;
          // 附加"可直接跑"的多骨架解密脚本：按结构推理分发到 SM4 / AES 骨架
          // （SM4 已实战验证；AES 为 Phase C 新增。DES/Blowfish 明确不支持，不假装能解）
          try {
            const sk = attachBlockCipherSolver(buf, size, analysis, readOff);
            if (sk) analysis.decryptScript = sk;
          } catch (e) { /* 生成失败不影响主结论 */ }
        }
      } catch (e) { /* 分析失败不影响主结论 */ }
    }
    out.push(item);
  }

  // 2.7) 内联 MD5 轮常量：K 表允许**散落**（CrackMe2 的 64 个 K 分布在 0xB2F~ 各处），
  //      连续 8 字节匹配必然 0 命中。判据是"K 命中数 ≥48 且标准 IV 基本不在"。
  {
    const md5 = detectMd5RoundConstants(buf);
    if (md5.hit) {
      out.push({
        fp: 'MD5-K', algo: 'MD5', desc: '内联 MD5 轮常量 K 表（散落存放，无标准 IV）',
        offset: md5.firstOffset >= 0 ? '0x' + md5.firstOffset.toString(16) : '0x0',
        kHits: md5.hits, ivHits: md5.ivHits,
      });
    }
  }

  // 3) 高熵常量块（16/24/32 字节，疑似 key/密文）——只报前几个，避免噪声。
  //    ⚠️ 大文件（electron.exe 180MB）下不能对每个偏移 slice（会创建千万级 Buffer）。
  //    改为原地统计：先按 4 字节步进快速排除（低位重复/含 0），命中才 slice 取 hex。
  const highEntropy = [];
  const looksHighEntropy = (off, len) => {
    let zeros = 0;
    const seen = new Uint8Array(256);
    let dup = 0;
    for (let i = 0; i < len; i++) {
      const b = buf[off + i];
      if (b === 0) { zeros++; continue; }
      if (seen[b]) dup++; else seen[b] = 1;
    }
    if (zeros > len * 0.15) return false;
    if (dup > len * 0.4) return false;      // 重复过多 = 熵不足
    return true;
  };
  for (const len of [32, 24, 16]) {
    for (let off = 0; off + len <= size && highEntropy.length < 8; off += 4) {
      if (!looksHighEntropy(off, len)) continue;
      if (out.some(o => o.offset === '0x' + off.toString(16))) continue;
      highEntropy.push({ offset: '0x' + off.toString(16), len, hex: buf.slice(off, off + len).toString('hex').slice(0, 64) });
      off += len - 4;
    }
    if (highEntropy.length >= 8) break;
  }

  // 3.5) 载荷（下一层载体）检测流水线 —— 可插拔，按序尝试多种编码/容器形态。
  // 为什么：多阶段/壳/loader 题常把下一层 payload 编码后塞进数据段（明文搜不到 MZ/ELF/DEX 头），
  //   实测 AI 会把它当"填充物"，宣称"文件内无第二载体"直接收工。必须由工具确定性定位并给提取配方。
  // 形态覆盖：单字节 XOR/ADD×stride / 周期 XOR / 滚动 XOR/ADD / Base64·Hex 文本 / ELF·DEX / shellcode 序言。
  const payloads = detectPayloads(buf, size);

  // 4) 综合判定（交叉证据 → 置信度）
  const algos = {};
  for (const o of out) { algos[o.algo] = algos[o.algo] || []; algos[o.algo].push(o); }
  const summary = [];
  const has = (n) => out.some(o => o.fp === n);

  // 4.0) 载荷命中 → **最高优先级结论**：本层是 loader，下一层在此处、按此法解码。
  //      必须排在所有算法判定之前（loader 层可能同时含 CRC/Base64 等无关常量，不能让它们抢结论）——
  //      实测教训：只给"去找下一层"的软提示，AI 会把编码存储的 stage2 当成填充物，直接收工报 decoy。
  if (payloads.length) {
    for (const p of payloads) summary.push(payloadDescription(p, payloads.length));
  }
  if (has('SM4-FK') || has('SM4-FK-BE')) {
    const customSbox = out.find(o => o.fp === 'SBOX-256' && o.algo === 'CUSTOM-BLOCK');
    const stdSbox = out.find(o => o.fp === 'SBOX-256' && o.algo === 'SM4');
    if (customSbox) {
      summary.push({ algo: 'SM4-魔改变体', confidence: 'high',
        evidence: `命中 SM4 FK 系统参数（${out.filter(o => o.fp.startsWith('SM4-FK')).map(o => o.offset).join(',')}），` +
                  `但 S 盒非常准（@${customSbox.offset} 首字节 ${customSbox.head.slice(0, 2)} ≠ d6）→ **FK/CK/S盒 被替换的 SM4 变体**`,
        note: '用 SM4 解密框架（32 轮 + 轮密钥逆序 rk[31-i] + 块内字节反序 [3][2][1][0]），常量换成题目表；gmssl 会解出乱码（S 盒非标准）。' });
    } else if (stdSbox) {
      summary.push({ algo: 'SM4', confidence: 'high', evidence: 'FK 系统参数 + 标准 S 盒双命中', note: '直接 gmssl 解（sm4_ecb/sm4_cbc）。' });
    } else {
      summary.push({ algo: 'SM4', confidence: 'high', evidence: '命中 SM4 FK 系统参数（铁证）', note: '按 SM4 结构解；S 盒位置需在 IDA 中确认是否标准。' });
    }
  }
  if (!has('SM4-FK') && !has('SM4-FK-BE') && out.some(o => o.fp === 'SBOX-256' && o.algo === 'CUSTOM-BLOCK')) {
    const cb = out.filter(o => o.fp === 'SBOX-256' && o.algo === 'CUSTOM-BLOCK');
    // 大文件（>16MB）通常是**通用程序**（浏览器/DLL/运行时，如 electron.exe 200MB），
    // 里面合法地嵌着各种密码库与随机置换表；仅凭双射表不能断言"这是本题的算法"。
    // CTF 题目二进制极少超过 16MB，故只在"题目量级"的文件上给 high 置信度。
    const bigBinary = size > 16 * 1024 * 1024;
    // 常量差分分析（确定性推导）：把"AI 要花几十次脚本才能算出来的表关系"直接给出。
    const ca = cb.find(o => o.constantAnalysis) && cb.find(o => o.constantAnalysis).constantAnalysis;
    const caText = ca ? ('\n**工具已完成的常量差分分析（确定性推导，直接用，别重新推导）**：\n'
      + ca.notes.map(n => '  · ' + n).join('\n')
      + (ca.ckFileOffset ? `\n  · 轮常量表文件偏移 **${ca.ckFileOffset}**（VA = 文件偏移按 PE 节表换算，或直接用 ida_get_bytes 按 VA 读）` : '')
      + (ca.fkFileOffset ? `\n  · FK 候选文件偏移 **${ca.fkFileOffset}**` : '')
      + `\n  · S 盒文件偏移 **${ca.sboxFileOffset}**（stride=${ca.sboxStride}）`) : '';
    // 若已生成"可跑的解密脚本"，直接在提示词里给出——这是把"确定性推导"变成"可执行结论"的关键一步。
    // ⚠️ 必须写明适用边界：脚本只实现 SM4 骨架（32 轮 + X^X^X^rk + 可替换 S 盒/FK/CK）。
    //    不能让它读起来像"任意分组密码都能解"，否则 AI 在 AES 变体题上会误信这个脚本。
    const scriptText = (ca && ca.decryptScript) ? (
      `\n**工具已生成可直接运行的解密脚本**（自动枚举 字节序 × 轮密钥顺序 × 块内排列 的全部组合，命中即退出）：\n`
      + `- 密文候选：${(ca.decryptScript.ciphertextCandidates || []).map(c => `${c.offset}(${c.length}B)`).join('、')}\n`
      + `- 用法：把脚本写到文件后 \`python solve.py <目标文件>\`\n`
      + `- ⚠️ **适用范围：SM4 骨架**（32 轮 + \`X^X^X^rk\` 轮函数 + 可替换的 S 盒/FK/CK）。`
      + `若实测结构是 AES 骨架（SubBytes/ShiftRows/MixColumns）或其它分组密码，本脚本**不适用**——`
      + `请按对应结构另写实现，不要因为脚本失败就断定"算法认错了"。\n`
      + '```python\n' + ca.decryptScript.script + '\n```\n'
    ) : '';
    // xref 闸门（三态）：unreferenced 才降级并在 evidence 标注"未引用/库数据"；
    // unverified 保留原置信度，只标注"xref 未验证"（x64/ELF 的 RIP-relative 未解析到 ≠ 没被引用）。
    const xrefStates = cb.map(o => o.xref && o.xref.status).filter(Boolean);
    const anyUnreferenced = xrefStates.includes('unreferenced');
    const anyUnverified = xrefStates.includes('unverified');
    const xrefNote = anyUnreferenced
      ? '\n⚠️ **表未引用/库数据**：该 S 盒在代码节里没有可解析的引用，可能是密码库自带表而非本题算法；'
        + '在反编译里确认它是否出现在输入→变换→比较的路径上，再决定是否照此实现。'
      : (anyUnverified
        ? '\nℹ️ xref 未验证：x64/ELF 的 RIP-relative 引用未解析到，这不等于"没被引用"；按常量结构判断即可。'
        : '');
    summary.push({
      algo: bigBinary ? '疑似自定义分组密码' : '自定义分组密码（已确认）',
      confidence: (bigBinary || anyUnreferenced) ? 'low' : 'high',
      evidence: `发现 ${cb.length} 个 256 项双射 S 盒（非常见算法）：` + cb.map(o => `${o.offset} 首字节 ${o.head.slice(0, 2)}`).join('、')
        + (bigBinary ? `（文件 ${(size / 1048576).toFixed(0)}MB，属通用程序量级，含密码库/置换表属正常）` : '')
        + (anyUnreferenced ? '（表未引用/库数据）' : (anyUnverified ? '（xref 未验证）' : '')),
      note: (bigBinary
        ? '文件偏大，可能是通用程序自带的密码实现，**不一定是本题算法**；请结合本题的输入校验点/密文常量判断，勿直接照此下结论。'
        : '**确定存在分组密码**（双射 S 盒不会偶然出现），常量被改成自定义值。'
          + '① 先核对轮结构：32 轮 + `X^X^X^rk` 线性变换 → SM4 骨架（即使无标准 FK）；'
          + '10/12/14 轮 + SubBytes/ShiftRows/MixColumns → AES 骨架。'
          + '② 结构确认后，直接套对应框架、把 S 盒/常量换成题目表手写实现（禁止硬逆/写通用 VM 解释器）。'
          + '③ 参照技能 ctf-crypto-identify 的"魔改变体识别三问"。')
        + caText + scriptText + xrefNote
    });
  }
  // AES 判定来源有两处：①连续字节的 AES-SBOX 常量 ②双射扫描发现 stride 形态的标准 AES 表
  // （dword 数组存放的标准 AES 表只会走②，此前被漏判 → summary 报"未发现"，实际表就在那）
  if (!summary.some(s => /AES/.test(s.algo)) &&
      (has('AES-SBOX') || out.some(o => o.fp === 'SBOX-256' && o.algo === 'AES'))) {
    const viaSbox = out.find(o => o.fp === 'SBOX-256' && o.algo === 'AES');
    summary.push({
      algo: 'AES', confidence: 'high',
      evidence: viaSbox ? `AES 标准 S 盒 @${viaSbox.offset}${viaSbox.stride > 1 ? `（${viaSbox.stride} 字节步长存放）` : ''}` : 'AES 标准 S 盒（连续字节）',
      note: '按 AES 解（注意 key 长度 16/24/32；轮数由 key 长度决定 10/12/14）。',
    });
  }
  if (has('SM3-IV')) summary.push({ algo: 'SM3', confidence: 'high', evidence: 'SM3 IV（铁证）', note: '哈希不可逆：按"SM3(候选)==目标"爆破/长度扩展。' });
  if (has('TEA-DELTA') || has('TEA-DELTA-INV')) summary.push({ algo: 'TEA/XTEA/XXTEA', confidence: 'high', evidence: 'TEA delta 常量', note: `按 TEA 族解；delta 大小端/正负见偏移。` });
  // MD5：K 轮常量命中比连续 IV 更强（IV 可能被省略/内联改写，K 表是算法本体）。
  // 证据形态写成 "K 常量命中 N/64，IV M/4"，便于 AI 自己判断可信度。
  {
    const kHit = out.find(o => o.fp === 'MD5-K');
    if (kHit) {
      // 摘要目标存在性闸门：文件里没有 32 位 hex 摘要、也没有 16B 对齐的高熵窗口时，
      // "MD5(候选)==目标"的爆破方向是错的（MD5 更可能用于 KDF/掩码派生）。
      const imgForHash = (() => { try { return parseImageMap(buf); } catch (e) { return null; } })();
      const hashTarget = assessHashTarget(buf, imgForHash);
      const md5Note = buildMd5Note(hashTarget, []);
      summary.push({
        algo: 'MD5', confidence: 'high',
        evidence: `内联 MD5 轮常量：K 常量命中 ${kHit.kHits}/64，IV ${kHit.ivHits}/4，首个 K @${kHit.offset}`
          + `；文件内 32 位 hex 字面量 ${hashTarget.hexLiterals} 个、16B 高熵窗口 ${hashTarget.highEntropy16} 个`,
        note: md5Note + '⚠️ K 表散落说明实现是手写/内联的，可能存在**轮数/IV/输出字节序**改动。',
        hashTarget,
      });
    }
  }
  if (!out.some(o => o.fp === 'MD5-K') && has('MD5-IV')) summary.push({ algo: 'MD5', confidence: 'medium', evidence: 'MD5 IV', note: '哈希：爆破/碰撞/截断比较。' });
  if (has('SHA256-IV')) summary.push({ algo: 'SHA256', confidence: 'medium', evidence: 'SHA256 IV', note: '哈希：同上。' });
  if (has('CRC32-POLY')) summary.push({ algo: 'CRC32', confidence: 'medium', evidence: 'CRC32 多项式', note: '短输入可碰撞爆破（注意自定义初值/异或）。' });
  if (has('RC4-ID')) summary.push({ algo: 'RC4', confidence: 'medium', evidence: '完整 0..255 初值表（KSA 初始化特征）', note: '按 RC4 解；仍需在代码中确认 KSA 循环（`j=(j+S[i]+key[i%len])&0xff`）。' });
  if (has('B64-STD')) summary.push({ algo: 'Base64', confidence: 'low', evidence: '标准 Base64 表', note: '编码非加密；可能是自定义表 Base64 的对照。' });

  // 4.5) 无任何算法指纹 → 中性结论。
  // 旧文案直接断言"本层极可能是壳/加载器/decoy，算法常量在下一层"。
  // 实测（CrackMe2）该断言与事实相反：真实算法是 MD5（sub_4016B0），
  // K 表就在本层，payloads 为空（没有任何内嵌载荷）——扫描器只是没认出来。
  // 把"没认出来"说成"一定是壳"，等于用工具的盲区给 AI 指定错误方向。
  if (!summary.length) {
    // ⚠️ 旧实现读 `out.payloads`，但这个数组从来没有被赋值（载荷在局部变量 payloads 里）
    // → hasPayload 恒为 false，零指纹分支永远只能说"本层没有内嵌载荷"。直接用 payloads。
    const hasPayload = (Array.isArray(payloads) && payloads.length > 0);
    summary.push({
      algo: '(未发现算法指纹)', confidence: 'n/a',
      evidence: `扫描 ${size} 字节，未命中任何已知算法常量（SM4/AES/SM3/MD5/SHA/TEA/CRC32 S盒表均无）`,
      note: hasPayload
        ? '未识别到已知算法常量。本层**确实存在内嵌载荷**（见下方载荷列表）：'
          + '算法可能在下一层，先提取再对**新文件**重跑本扫描。'
        : '未识别到已知算法常量。这不等于"是壳"：可能是**自实现算法**、'
          + '**常量布局非常规**（表被拆分/加花、表项按非标准步长或 lane 交错存放、'
          + '或只用了扫描器还不认识的轮常量）、或算法写在其它函数里。'
          + '本层没有内嵌载荷，建议优先在本层找逐字节比较/位运算循环与内联常量表，'
          + '不要仅凭"扫描无命中"就断定存在下一层。',
      noPayload: !hasPayload,
    });
  }

  // 5) 标准 AES/SM4 S 盒（已知常量分支）的解密脚本挂载：
  //    CUSTOM-BLOCK 分支在双射扫描里挂脚本，但"连续字节命中 AES-SBOX 常量"的标准表
  //    不经过该分支 → 此前标准 AES 题反而没有可跑脚本。此处补齐（按 summary 判定分发）。
  try {
    const sboxHit = out.find(o => o.fp === 'SBOX-256' || o.fp === 'AES-SBOX');
    if (sboxHit && !out.some(o => o.constantAnalysis && o.constantAnalysis.decryptScript)) {
      const sboxOffN = typeof sboxHit.offset === 'string' ? parseInt(sboxHit.offset, 16) : sboxHit.offset;
      // 构造最小 analysis：标准表 → relation exact；结构推理按 summary 选骨架
      const isAes = summary.some(s => /AES/.test(s.algo));
      const isSm4 = summary.some(s => /SM4/.test(s.algo)) && !isAes;
      if (isAes || isSm4) {
        const stdTable = isAes ? STD_AES_SBOX : STD_SM4_SBOX;
        const analysis = {
          sboxFileOffset: sboxHit.offset, sboxStride: sboxHit.stride || 1,
          sboxRelation: { relatedTo: isAes ? 'AES' : 'SM4', kind: 'exact', same: 256,
            desc: `与标准 ${isAes ? 'AES' : 'SM4'} 完全相同` },
          ckFileOffset: isSm4 ? (out.find(o => o.fp === 'SM4-FK') ? null : null) : null,
          fkCandidates: [],
          notes: [`标准 ${isAes ? 'AES' : 'SM4'} S 盒（${sboxHit.stride > 1 ? sboxHit.stride + ' 字节步长存放' : '连续字节'}）`],
        };
        const structs = summary.some(s => /AES/.test(s.algo))
          ? [{ skeleton: 'AES', confidence: 'high', evidence: '标准 AES S 盒', rconOffset: -1 }]
          : [{ skeleton: 'SM4', confidence: 'high', evidence: '标准 SM4 S 盒 + FK 常量' }];
        const sk = isAes
          ? attachAESDecryptScript(buf, size, analysis, sboxOffN, structs)
          : null;   // 标准 SM4 直接用 gmssl 库即可（解密脚本意义不大），保持诚实边界
        if (sk) {
          sboxHit.constantAnalysis = {
            sboxFileOffset: sboxHit.offset, sboxStride: sboxHit.stride || 1,
            notes: analysis.notes, sboxRelation: analysis.sboxRelation,
            decryptScript: sk,
          };
        }
      }
    }
  } catch (e) { /* 挂载失败不影响主结论 */ }

  return {
    success: true, size,
    summary,                                   // 综合判定（给 AI 看的主结论）
    fingerprints: out.slice(0, 40),            // 原始命中（证据）
    highEntropy: highEntropy.slice(0, 8),      // 疑似 key/密文常量
    payloads,                                  // 下一层载体（多形态，流水线检测）
    embeddedPE: payloads.filter(p => p.type === 'pe'),  // 向后兼容：仅 PE 子集
  };
}

ipcMain.handle('scan-crypto-fingerprints', async (event, filePath) => {
  try { return scanCryptoFingerprints(filePath); }
  catch (err) { return { success: false, error: err.message }; }
});

// 提取 APK 内的 native SO（纯 Node，无 shell/编码问题）
ipcMain.handle('extract-apk-so', async (event, apkPath) => {
  try {
    if (!apkPath || !fs.existsSync(apkPath)) {
      return { success: false, error: 'APK 文件不存在: ' + apkPath };
    }
    const baseDir = path.dirname(apkPath);
    const stem = path.basename(apkPath).replace(/\.apk$/i, '');
    const outDir = path.join(baseDir, stem + '_so');
    fs.mkdirSync(outDir, { recursive: true });

    // 只提取 lib/<abi>/*.so；ABI 优先级：x86_64 > x86 > arm64-v8a > armeabi-v7a > 其它
    const abiRank = (n) => {
      if (/\/x86_64\//.test(n)) return 0;
      if (/\/x86\//.test(n)) return 1;
      if (/arm64-v8a/.test(n)) return 2;
      if (/armeabi-v7a/.test(n)) return 3;
      return 9;
    };
    // 输出按 ABI 分目录，避免同名 .so 互相覆盖（各架构同名 .so 内容不同）
    const outFor = (entry) => {
      const abi = entry.split('/')[1] || 'unknown';
      const dir = path.join(outDir, abi);
      fs.mkdirSync(dir, { recursive: true });
      return path.join(dir, path.basename(entry));
    };
    const all = extractZipEntries(apkPath, (n) => /^lib\/[^/]+\/.+\.so$/i.test(n), outFor);
    if (!all.length) return { success: true, soFile: null, extracted: [] };
    all.sort((a, b) => abiRank(a.entry) - abiRank(b.entry));
    return { success: true, soFile: all[0].outPath, extracted: all };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// PYC 反汇编/常量提取：多后端回退（pycdc 对高版本 pyc 常报 Bad MAGIC 直接失败）。
// 后端链：配置的 pycdc → 内置 pyc_decompile.py（xdis/pydisasm → 原生 marshal+dis → 纯字节串扫描）。
// 关键：**即使 pycdc 失败也返回可用结果**（反汇编/常量/字符串），交给上层 AI 分析。
// 打包注意：asar=true 时助手在 app.asar 内，**外部 python 进程读不到 asar 路径**，
// 故这里把它物化到临时文件再执行（开发态直接读原文件）。
function materializePycHelper() {
  const appDir = app.getAppPath();
  const cands = [
    path.join(__dirname, 'pyc_decompile.py'),                                         // 开发态（真实文件）
    path.join(appDir, 'electron', 'pyc_decompile.py').replace('app.asar', 'app.asar.unpacked'), // 打包态·已解包（真实文件）
    path.join(appDir, 'electron', 'pyc_decompile.py'),                                // 打包态·asar 内（需物化）
  ];
  for (const c of cands) {
    try {
      if (!fs.existsSync(c)) continue;
      // asar 内路径：Electron 的 fs 补丁能读，但外部 python 进程不能 → 复制到 temp
      if (/app\.asar([\\/]|$)/.test(c) && !/app\.asar\.unpacked/.test(c)) {
        const tmp = path.join(app.getPath('temp'), 'ctf_pyc_decompile.py');
        fs.writeFileSync(tmp, fs.readFileSync(c));
        return tmp;
      }
      return c;
    } catch (e) { /* 试下一个 */ }
  }
  return null;
}

ipcMain.handle('pyc-decompile', async (event, pycPath) => {
  try {
    if (!pycPath || !fs.existsSync(pycPath)) return { success: false, error: 'PYC 文件不存在: ' + pycPath };
    const out = { success: false, backends: [], disasm: '', consts: '', strings: '', meta: '', raw: '', error: null };

    // 1) 用户配置的 pycdc（若可用）
    const pycdc = (config.tools && config.tools.pycdc) || '';
    if (pycdc && fs.existsSync(pycdc) && /\.exe$/i.test(pycdc)) {
      const r = await spawnArgv([pycdc, pycPath], { timeoutMs: 30000 });
      if (r.success && r.stdout && !/Bad MAGIC/i.test(r.stdout + r.stderr)) {
        out.backends.push('pycdc');
        out.disasm = r.stdout;
        out.success = true;
        return out;
      }
      out.backends.push('pycdc:失败(' + ((r.stdout + r.stderr).match(/Bad MAGIC/i) ? 'Bad MAGIC' : (r.error || 'unknown')) + ')');
    }

    // 2) 内置多后端助手（含纯字节串扫描兜底，永不空手而归）
    const helper = materializePycHelper();
    if (!helper) {
      out.error = '内置 pyc 助手缺失（pyc_decompile.py 未随应用打包）';
      return out;
    }
    const r = await spawnArgv(['python', helper, pycPath], { timeoutMs: 90000 });
    const text = ((r.stdout || '') + (r.stderr ? '\n' + r.stderr : '')).trim();
    out.raw = text;
    if (!r.success && !text) {
      out.error = r.error || 'python 执行失败（请确认本机已安装 Python 并加入 PATH）';
      return out;
    }
    // 按分区解析
    const secSplit = (name, nextNames) => {
      const start = text.indexOf('### ' + name + ' ###');
      if (start < 0) return '';
      let end = text.length;
      for (const n of nextNames) {
        const i = text.indexOf('### ' + n + ' ###', start + 1);
        if (i >= 0 && i < end) end = i;
      }
      return text.slice(start + ('### ' + name + ' ###').length, end).trim();
    };
    const order = ['META', 'DISASM', 'CONSTS', 'STRINGS'];
    out.meta = secSplit('META', order);
    out.disasm = secSplit('DISASM', order);
    out.consts = secSplit('CONSTS', order);
    out.strings = secSplit('STRINGS', order);
    out.backends.push(/backend: xdis/.test(text) ? 'xdis/pydisasm' : (/backend: marshal/.test(text) ? 'marshal+dis' : 'bytes-scan'));
    out.success = !!(out.disasm || out.consts || out.strings);
    return out;
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ 安全执行原语 ============
// 渲染层禁止再自行拼接 shell 命令（历史实现把文件路径/APK 内容插进 powershell/cmd 字符串，
// 文件名或题目内容含引号/反引号/$(...) 即可逃逸注入）。统一改为主进程提供：
//  1) run-tool-args：以 argv 数组、shell:false 启动外部程序（无 shell 解析 → 无注入）
//  2) zip-list / zip-read-text：纯 Node 读取 zip 条目（替代无谓的 powershell 解压探测）
//  3) grep-in-dir：纯 Node 递归内容搜索（替代 powershell Select-String 拼接）

// 以参数数组启动外部命令（永不经过 shell）。argv[0] 为可执行文件/脚本。
// 说明：Windows 上 .bat/.cmd 无法直接 spawn（需 shell），故这里对批处理回退到
// cmd.exe /c 但**仍以参数数组传参**，路径作为独立 argv 传入，不做字符串拼接。
function spawnArgv(argv, opts = {}) {
  return new Promise((resolve) => {
    if (!Array.isArray(argv) || !argv.length || !argv[0]) {
      return resolve({ success: false, stdout: '', stderr: '', error: '空命令' });
    }
    let file = String(argv[0]);
    let args = argv.slice(1).map((a) => String(a));
    const isBatch = /\.(bat|cmd)$/i.test(file);
    let extraOpts = {};
    // GUI 工具（IDA/JEB/Nox 等带窗口程序）：直接 spawn(detached) 实测拿不到可见窗口
    // —— 进程在跑、窗口存在，但 IsWindowVisible=false（用户看不到 IDA/JEB 界面）。
    // 可靠做法是交给 cmd 的 `start` 创建独立可视窗口环境：
    //   cmd /c start "" "<exe>" <args...>
    // 用 windowsVerbatimArguments 手工拼引号，参数边界清晰、路径空格安全。
    if (opts.gui && !isBatch) {
      const quote = (s) => '"' + String(s).replace(/"/g, '\\"') + '"';
      const cmdLine = 'start "" ' + quote(file) + (args.length ? ' ' + args.map(quote).join(' ') : '');
      file = process.env.ComSpec || 'cmd.exe';
      args = ['/c', cmdLine];
      extraOpts.windowsVerbatimArguments = true;
      const child = spawn(file, args, Object.assign({ shell: false, windowsHide: false, detached: true }, extraOpts));
      child.on('error', () => {});
      child.unref();
      // start 会立即返回；800ms 后回执"已启动"
      setTimeout(() => resolve({ success: true, stdout: '已启动（可视窗口）', stderr: '', error: null }), 800);
      return;
    }
    if (isBatch) {
      // 批处理必须经 cmd.exe 执行。关键：不能简单用 ['/c', file].concat(args)——
      // cmd /s /c 会破坏含 '=' 的参数（如 JEB 的 --script=x 会被拆成两个），
      // 导致脚本参数错乱（实测：JEB 拿不到 --script，MCP.py 不加载、16161 不监听）。
      // 正解：手工拼一条已加引号的命令行，配合 windowsVerbatimArguments:true，
      // 用 cmd /s /c "<完整命令行>" 传入，参数边界即清晰无误。
      const quote = (s) => '"' + String(s).replace(/"/g, '\\"') + '"';
      const cmdLine = [quote(file)].concat(args.map(quote)).join(' ');
      args = ['/s', '/c', '"' + cmdLine + '"'];
      file = process.env.ComSpec || 'cmd.exe';
      extraOpts.windowsVerbatimArguments = true;
    }
    const childOpts = Object.assign({ shell: false, windowsHide: true, timeout: opts.timeoutMs || 30000, maxBuffer: 10 * 1024 * 1024 }, extraOpts);
    if (opts.cwd && fs.existsSync(opts.cwd)) childOpts.cwd = opts.cwd;
    // detached / gui：GUI 工具（JEB/IDA/Nox）"启动后立即返回、不阻塞、不被超时杀掉"。
    // gui 额外要求窗口可见（windowsHide:false）。
    // 关键：二者都必须走下面的"立即 resolve"分支——否则 detached 子进程不会触发 close，
    // Promise 永不 resolve → 渲染层 await 卡死（实测：JEB .bat + {gui:true} 卡在"正在启动 jeb..."）。
    const isBg = !!(opts.detached || opts.gui);
    if (isBg) {
      childOpts.detached = true;
      delete childOpts.timeout;
      if (opts.gui) childOpts.windowsHide = false;
    }
    let child;
    try { child = spawn(file, args, childOpts); } catch (e) {
      return resolve({ success: false, stdout: '', stderr: '', error: e.message });
    }
    let stdout = '', stderr = '';
    // 后台模式：不等输出，spawn 成功即视为已启动，让 GUI 独立运行
    if (isBg) {
      child.unref();
      child.on('error', (err) => resolve({ success: false, stdout: '', stderr: '', error: err.message }));
      setTimeout(() => resolve({ success: true, stdout: '已启动（后台运行）', stderr: '', error: null }), 800);
      return;
    }
    const timer = setTimeout(() => { try { child.kill(); } catch (e) {} }, opts.timeoutMs || 30000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: err.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ success: code === 0, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: code === 0 ? null : `退出码 ${code}` });
    });
  });
}

ipcMain.handle('run-tool-args', async (event, argv, opts) => {
  // 仅允许字符串数组；绝不接受整条命令字符串
  if (typeof argv === 'string') {
    return { success: false, error: 'run-tool-args 需要 argv 数组（禁止传整条命令字符串）' };
  }
  return spawnArgv(argv, opts || {});
});

// 列出 zip（APK）内的条目名（纯 Node 解析中央目录；中文/特殊字符文件名不受影响）
function listZipEntryNames(zipPath, limit = 5000) {
  const fd = fs.openSync(zipPath, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const tailLen = Math.min(size, 66000);
    const tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, size - tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('非 ZIP 或中央目录缺失');
    const cdOffset = tail.readUInt32LE(eocd + 16);
    const cdCount = tail.readUInt16LE(eocd + 10);
    const cd = Buffer.alloc(Math.min(size - cdOffset, 4 << 20));
    fs.readSync(fd, cd, 0, cd.length, cdOffset);
    const names = [];
    let p = 0;
    for (let n = 0; n < cdCount && p + 46 <= cd.length; n++) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break;
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      names.push(cd.slice(p + 46, p + 46 + nameLen).toString('utf8'));
      p += 46 + nameLen + extraLen + commentLen;
      if (names.length >= limit) break;
    }
    return names;
  } finally {
    fs.closeSync(fd);
  }
}

ipcMain.handle('zip-list', async (event, zipPath) => {
  try {
    if (!zipPath || !fs.existsSync(zipPath)) return { success: false, error: '文件不存在: ' + zipPath };
    return { success: true, names: listZipEntryNames(zipPath) };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 纯 Node 递归内容搜索：替代渲染层 `powershell ... Select-String -SimpleMatch '${kw}'` 拼接。
// 关键词只作为普通字符串参与 indexOf/RegExp，永不进入 shell。
function grepInDir(root, pattern, opts = {}) {
  const fixed = !!opts.fixed;
  const maxFiles = Number(opts.maxFiles) > 0 ? Number(opts.maxFiles) : 8000;
  const maxHits = Number(opts.maxHits) > 0 ? Number(opts.maxHits) : 200;
  const exts = Array.isArray(opts.extensions) && opts.extensions.length ? opts.extensions : null;
  let rx = null;
  if (!fixed) {
    try { rx = new RegExp(pattern, 'i'); } catch (e) { rx = null; }
  }
  const rootDir = path.resolve(String(root || '.'));
  const hits = [];
  for (const f of walkFiles(rootDir, maxFiles)) {
    if (exts && !exts.some((e) => f.toLowerCase().endsWith(e.toLowerCase()))) continue;
    let st;
    try { st = fs.statSync(f); } catch (e) { continue; }
    if (st.size > 4 * 1024 * 1024) continue;
    let content;
    try { content = fs.readFileSync(f, 'utf8'); } catch (e) { continue; }
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const hit = fixed ? (lines[i].includes(pattern)) : (rx ? rx.test(lines[i]) : lines[i].includes(pattern));
      if (hit) {
        hits.push(`${f}:${i + 1}: ${lines[i].trim().slice(0, 200)}`);
        if (hits.length >= maxHits) break;
      }
    }
    if (hits.length >= maxHits) break;
  }
  return hits;
}

ipcMain.handle('grep-in-dir', async (event, root, pattern, opts) => {
  try {
    return { success: true, hits: grepInDir(root, pattern, opts || {}) };
  } catch (err) {
    return { success: false, error: err.message, hits: [] };
  }
});

// 获取文件详细信息
ipcMain.handle('get-file-info', async (event, filePath) => {
  try {
    const stats = fs.statSync(filePath);
    const fileName = path.basename(filePath);
    const ext = path.extname(filePath);

    // 计算MD5和SHA256
    const crypto = require('crypto');
    const fileBuffer = fs.readFileSync(filePath);
    const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    return {
      success: true,
      fileName,
      extension: ext,
      size: stats.size,
      sizeFormatted: formatFileSize(stats.size),
      md5,
      sha256,
      created: stats.birthtime,
      modified: stats.mtime
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 启动工具（spawn 参数数组，避免 shell 注入；jar 自动走 java -jar）
ipcMain.handle('launch-tool', async (event, toolName, filePath) => {
  try {
    const toolPath = config.tools[toolName];
    if (!toolPath) {
      return { success: false, error: `工具 ${toolName} 未配置` };
    }
    // 启动 IDA/JEB 前固化"自动保存 + 不弹确认框"，让关闭时自动落库、无需人工点对话框
    if (['ida', 'ida64', 'jeb'].includes(toolName)) {
      try { hardenEditorConfigs(); } catch (e) { /* 配置固化失败不阻塞启动 */ }
    }

    let cmd, args;
    if (/\.jar$/i.test(toolPath)) {
      cmd = 'java';
      args = ['-jar', toolPath];
      if (filePath) args.push(filePath);
    } else if (/\.(bat|cmd)$/i.test(toolPath)) {
      // 批处理启动器（如 Burp 的 Start.bat）：经 cmd start 拉起，路径空格安全
      cmd = 'cmd';
      args = ['/c', 'start', '', toolPath];
      if (filePath) args.push(filePath);
    } else if (/\.vbs$/i.test(toolPath)) {
      cmd = 'wscript';
      args = [toolPath];
      if (filePath) args.push(filePath);
    } else {
      cmd = toolPath;
      args = filePath ? [filePath] : [];
      // IDA 无人值守：-A 自治模式抑制所有对话框（含插件/数据库确认框），
      // 避免冷启动时弹 "Please confirm" 阻塞 MCP 插件自启
      if ((toolName === 'ida' || toolName === 'ida64') && /ida.*\.exe$/i.test(toolPath)) {
        args.unshift('-A');
      }
    }

    const child = spawn(cmd, args, { shell: false, detached: true, stdio: 'ignore' });
    child.on('error', (err) => {
      console.error(`工具启动错误: ${err.message}`);
    });
    child.unref();

    return { success: true, message: `已启动 ${toolName}` };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 将命令字符串拆分为参数数组（尊重双引号/单引号）
function tokenizeCommand(input) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(String(input))) !== null) {
    out.push(m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]));
  }
  return out;
}

// 统一的输出截断（防止超大输出撑爆 IPC/模型上下文）
const MAX_OUTPUT_CHARS = 8000;
function truncateOutput(text) {
  const s = String(text || '');
  if (s.length <= MAX_OUTPUT_CHARS) return s;
  return s.slice(0, MAX_OUTPUT_CHARS) + `\n...[已截断，原始长度 ${s.length} 字符]`;
}

// 工具调用的"人话"标签：UI 上显示"正在反编译 main / 正在运行 Python 脚本"，
// 而不是裸工具名。用户等待时能看到进度，也便于复盘时定位是哪一步卡住。
function toolLabel(name, input) {
  const i = input || {};
  const short = (v, n) => {
    const s = String(v == null ? '' : v).replace(/\s+/g, ' ').trim();
    return s.length > (n || 40) ? s.slice(0, n || 40) + '…' : s;
  };
  switch (name) {
    case 'read_file': return '读取 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'write_file': return '写入 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'bash': return '执行命令 ' + short(i.command, 50);
    case 'run_python': return '运行 Python 脚本' + (i.script ? `（${String(i.script).split('\n').length} 行）` : '');
    case 'glob': return '查找文件 ' + short(i.pattern, 40);
    case 'grep': return '搜索 ' + short(i.pattern, 40) + (i.path ? ' @' + short(path.basename(i.path), 24) : '');
    case 'scan_crypto': return '扫描算法指纹 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'extract_payload': return '提取载荷';
    case 'analyze_structure': return '分析密码结构';
    case 'junk_scan': return '扫描花指令 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'junk_patch': return '去除花指令 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'junk_repair': return '修复花指令 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'gen_block_cipher_solver': case 'gen_sm4_solver': return '生成解密脚本';
    case 'ida_decompile': return 'IDA 反编译 ' + short(i.function_name || i.address, 40);
    case 'ida_open_file': return 'IDA 载入 ' + short(i.path ? path.basename(i.path) : '', 40);
    case 'angr_solve': return 'angr 求解 ' + short(i.binary ? path.basename(i.binary) : '', 30);
    case 'emu_trace': return '执行轨迹 ' + short(i.binary ? path.basename(i.binary) : '', 28) + (i.start ? ' @' + short(i.start, 12) : '');
    case 'ida_apply_trace': return '回填轨迹到 IDA';
    case 'rev_solve': return '可逆逆推' + (Array.isArray(i.ops) ? `（${i.ops.length} 条算子）` : '');
    case 'recover_string': return '还原比较字符串 ' + short(i.func || '（文本）', 24);
    case 'ida_get_bytes': return 'IDA 读取字节 ' + short(i.address, 30);
    case 'ida_list_functions': return 'IDA 列出函数';
    case 'ida_find_strings': return 'IDA 查找字符串 ' + short(i.keyword || i.pattern || '', 30);
    case 'ida_get_xrefs': return 'IDA 交叉引用 ' + short(i.address || i.function_name || i.name, 30);
    case 'ida_list_globals': return 'IDA 列出全局' + (i.filter ? ' ' + short(i.filter, 24) : '');
    case 'ida_disasm': return 'IDA 反汇编 ' + short(i.address, 28);
    case 'ida_dbg': return 'IDA 调试 ' + short(i.action, 24) + (i.addr || i.addrs ? ' ' + short(Array.isArray(i.addrs) ? i.addrs.join(',') : (i.addrs || i.addr), 26) : '');
    case 'ida_dbg_mem': return 'IDA 调试内存' + (i.action ? ' ' + short(i.action, 12) : '');
    case 'remote_exec': return '远程执行 ' + short(i.host || 'local', 10) + ' ' + short(i.command, 40);
    case 'traffic_extract': return '解析流量 ' + short(i.path ? path.basename(i.path) : '', 36);
    case 'recipe': return '变换链 ' + (i.auto ? '自动解码' : ((i.recipe || []).map(x => (x && x.op) || '?').join(' → ') || '空'));
    case 'gui_input': return 'GUI 喂输入' + (i.list_only ? '（列控件）' : (i.text ? ' ' + short(i.text, 24) : ''));
    case 'crypto': return '加密工具 ' + [i.op, i.algo, i.action].filter(Boolean).join('/');
    case 'jeb_get_manifest': return 'JEB 读取 Manifest';
    case 'jeb_get_class_decompiled': return 'JEB 反编译 ' + short(i.class_name, 36);
    case 'jeb_get_method_decompiled': return 'JEB 反编译方法 ' + short(i.class_name + '::' + (i.method_name || ''), 36);
    case 'jeb_get_all_classes': return 'JEB 列出类';
    case 'jeb_get_exported_activities': return 'JEB 读导出组件';
    case 'jeb_get_class_methods': return 'JEB 列出方法';
    case 'browser_search': return '联网搜索 ' + short(i.query, 36);
    case 'browser_open': return '打开网页 ' + short(i.url, 40);
    case 'adb_command': return 'ADB ' + short(i.command || i.args, 40);
    case 'frida_hook': return 'Frida Hook ' + short(i.script ? '脚本' : (i.target || ''), 30);
    case 'read_skill': return '读取技能 ' + short(i.name, 30);
    case 'wiki_search': return '检索知识库 ' + short(i.query, 36);
    case 'wiki_read': return '读取知识库 ' + short(i.path || i.name, 36);
    case 'burp_get_history': return 'Burp 读取历史';
    case 'burp_get_message': return 'Burp 读取报文';
    case 'burp_call': return '调用 Burp';
    case 'switch_to_next_stage': return '切换到下一阶段';
    default: return name;
  }
}

// 执行命令（渲染层/AI 通用；保留全自动，输出截断 + 控制台审计）
ipcMain.handle('exec-command', async (event, command) => {
  console.log('[exec-command]', String(command).slice(0, 500));
  return new Promise((resolve) => {
    exec(command, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({
        success: !error,
        stdout: truncateOutput(stdout || ''),
        stderr: truncateOutput(stderr || ''),
        error: error ? error.message : null
      });
    });
  });
});

// 写入路径边界：渲染层/AI 只能写"工作相关"目录，禁止写到系统目录/启动项/任意位置。
// 允许的根：userData、应用目录、临时目录、当前题目目录（currentWorkDir）、脚本输出目录。
function allowedWriteRoots() {
  const roots = [
    app.getPath('userData'),
    app.getAppPath(),
    app.getPath('temp'),
    require('os').tmpdir(),
    CONFIG_PATH ? path.dirname(CONFIG_PATH) : ''
  ];
  if (currentWorkDir) roots.push(currentWorkDir);
  if (config.workspace && config.workspace.scriptsDir) roots.push(config.workspace.scriptsDir);
  return roots.filter(Boolean).map((r) => path.resolve(r));
}
function isPathAllowedForWrite(p) {
  const target = path.resolve(String(p || ''));
  const norm = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
  const t = norm(target);
  return allowedWriteRoots().some((root) => {
    const r = norm(root);
    return t === r || t.startsWith(r + path.sep);
  });
}
// 敏感文件：工具自身配置（含 apiKey/sudo 口令），禁止被读取/写入
function isSensitivePath(p) {
  const norm = (s) => (process.platform === 'win32' ? String(s).toLowerCase() : String(s));
  return CONFIG_PATH ? norm(path.resolve(String(p || ''))) === norm(path.resolve(CONFIG_PATH)) : false;
}

// 写入/读取脚本文件（供渲染层使用）
ipcMain.handle('write-file', async (event, filePath, content) => {
  try {
    if (isSensitivePath(filePath)) return { success: false, error: '拒绝写入受保护文件' };
    if (!isPathAllowedForWrite(filePath)) return { success: false, error: '写入路径超出允许范围: ' + filePath };
    const resolved = path.resolve(filePath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, String(content), 'utf8');
    return { success: true, path: resolved };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('read-file', async (event, filePath) => {
  try {
    if (isSensitivePath(filePath)) return { success: false, error: '拒绝读取受保护文件（含凭据）' };
    return { success: true, content: fs.readFileSync(path.resolve(filePath), 'utf8') };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ── Java .class 常量池解析（裸 .class 的最后兜底）──
// 背景（40 题实测「Java逆向解密」）：JEB MCP 拉起失败 → jadx 命令行对单个 .class
// 无源码输出 → 整条降级链断掉，2 分钟放弃。.class 格式本身极简单（魔数+常量池+
// 字段/方法表），主进程有 Buffer，解析出"类名/字符串常量/方法签名/字节码 hex"
// 就足够 AI 还原简单校验逻辑。解析全部 best-effort，任何越界都降级返回已解析部分。
function parseClassSummary(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 10) return { ok: false, error: '文件过小，不是 .class' };
  if (buf.readUInt32BE(0) !== 0xCAFEBABE) return { ok: false, error: '魔数不是 CAFEBABE，不是 .class' };
  let p = 4;
  const readU2 = () => { const v = buf.readUInt16BE(p); p += 2; return v; };
  const readU4 = () => { const v = buf.readUInt32BE(p); p += 4; return v; };
  const minor = readU2(), major = readU2();
  const cpCount = readU2();
  const cp = new Array(cpCount).fill(null);
  for (let i = 1; i < cpCount; i++) {
    if (p >= buf.length) break;
    const tag = buf.readUInt8(p); p += 1;
    try {
      if (tag === 1) {
        const len = readU2();
        cp[i] = { tag, str: buf.toString('utf8', p, Math.min(p + len, buf.length)) };
        p += len;
      } else if (tag === 3 || tag === 4) { cp[i] = { tag }; p += 4; }
      else if (tag === 5 || tag === 6) { cp[i] = { tag }; p += 8; cp[++i] = { tag: 0 }; }  // long/double 占双槽
      else if (tag === 7 || tag === 8 || tag === 16 || tag === 19 || tag === 20) { cp[i] = { tag, idx: readU2() }; }
      else if (tag === 9 || tag === 10 || tag === 11 || tag === 12 || tag === 17 || tag === 18) { cp[i] = { tag, a: readU2(), b: readU2() }; }
      else if (tag === 15) { cp[i] = { tag }; p += 3; }
      else break;  // 未知 tag：停止解析常量池，用已解析部分
    } catch (e) { break; }
  }
  const utf8 = (i) => (cp[i] && cp[i].tag === 1 && typeof cp[i].str === 'string') ? cp[i].str : '';
  const className = (i) => {
    const e = cp[i];
    if (e && e.tag === 7) return utf8(e.idx).replace(/\//g, '.');
    return '';
  };
  const naType = (e) => (e && utf8(e.a) && utf8(e.b)) ? utf8(e.a) + ':' + utf8(e.b) : '';

  // 头部信息（常量池损坏时 p 已越界，后面全部跳过）
  let thisClass = '', superClass = '', interfaces = [], fields = [], methods = [];
  const strings = [];
  for (let i = 1; i < cpCount; i++) {
    const s = utf8(i);
    if (s && s.length >= 3 && /^[\x20-\x7e]+$/.test(s)) strings.push(s);
  }
  try {
    readU2();                    // access_flags
    thisClass = className(readU2());
    superClass = className(readU2());
    const ifc = readU2();
    for (let k = 0; k < ifc && p + 2 <= buf.length; k++) interfaces.push(className(readU2()));
    const readMembers = (isMethod) => {
      const out = [];
      const n = readU2();
      for (let k = 0; k < n && p + 8 <= buf.length; k++) {
        const access = readU2();
        const name = utf8(readU2());
        const desc = utf8(readU2());
        const an = readU2();
        let codeHex = '';
        for (let a = 0; a < an && p + 6 <= buf.length; a++) {
          const aname = utf8(readU2());
          const alen = readU4();
          const attrStart = p;                       // 属性内容起点（alen 从这里起算）
          if (isMethod && aname === 'Code' && p + 8 <= buf.length) {
            readU2(); readU2();                     // max_stack / max_locals
            const clen = readU4();
            const take = Math.min(clen, 512, Math.max(0, buf.length - p));
            if (take > 0) codeHex = buf.slice(p, p + take).toString('hex');
            p = attrStart + alen;                   // 跳过整个属性（含异常表/属性内属性）
            continue;
          }
          p = attrStart + alen;
        }
        out.push({ name, desc, access: '0x' + access.toString(16), ...(codeHex ? { codeHex } : {}) });
      }
      return out;
    };
    fields = readMembers(false);
    methods = readMembers(true);
  } catch (e) { /* 头部越界：用常量池部分 */ }

  const cap = (arr, n) => arr.slice(0, n);
  return {
    ok: true,
    version: major + '.' + minor,
    thisClass, superClass,
    interfaces: cap(interfaces, 8),
    fields: cap(fields, 24),
    methods: cap(methods, 40),
    strings: cap(strings, 160),
    constantsParsed: cp.filter(Boolean).length,
  };
}

// IPC: 花指令主动探测
// 为什么需要：prefetchKnowledge 的 haystack 是**反编译文本**，里面不会出现
// "花指令/sp-analysis" 这类 IDA 界面状态词 → 用词匹配永远命中不了。
// 唯一可靠的办法是从二进制本身量测：跳转目标非对齐数/比例、可疑跳转、不可达字节。
// 渲染层拿到后：① 命中则把"花指令"加进检索词 ② 提示词里直接告知 AI 该用 junk_repair。
ipcMain.handle('junk-probe', async (event, filePath) => {
  try {
    const p = path.resolve(String(filePath || ''));
    if (!fs.existsSync(p)) return { success: false, error: '文件不存在: ' + filePath };
    const buf = fs.readFileSync(p);
    let start = 0, end = buf.length;
    try {
      const map = parseImageMap(buf);
      const exec = (map && Array.isArray(map.sections) ? map.sections : []).filter(s => s.executable);
      if (exec.length) {
        start = Math.min(...exec.map(s => Number(s.rawPtr) || 0));
        end = Math.max(...exec.map(s => (Number(s.rawPtr) || 0) + (Number(s.rawSize) || 0)));
      }
    } catch (e) { /* 用全文件 */ }
    if (end - start < 64) return { success: true, probed: false, reason: '代码区过小' };

    const r = scanJunkFeatures(buf, { start, end, decodeInsn });
    if (!r.ok) return { success: false, error: r.error };

    const bad = r.stats.badTargets;
    const ratio = bad / Math.max(1, r.stats.insnCount);
    return {
      success: true, probed: true,
      start, end, size: end - start,
      insnCount: r.stats.insnCount,
      undecodable: r.stats.undecodable,
      badTargets: bad,
      badRatio: +(ratio * 100).toFixed(2),
      features: r.stats.features,
      patchable: r.stats.patchable,
      reportOnly: r.stats.reportOnly,
      suspicious: bad >= 20 || ratio > 0.002,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// IPC: .class 常量池摘要（JEB/jadx 双失败时的第三条路）
ipcMain.handle('class-file-summary', async (event, filePath) => {
  try {
    if (isSensitivePath(filePath)) return { success: false, error: '拒绝读取受保护文件（含凭据）' };
    const abs = path.resolve(String(filePath || ''));
    if (!fs.existsSync(abs)) return { success: false, error: '文件不存在: ' + filePath };
    const r = parseClassSummary(fs.readFileSync(abs));
    if (!r.ok) return { success: false, error: r.error };
    return { success: true, summary: r };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 抽取文件里的可打印字符串，供中间值自动推进（哈希爆破）当字典用。
// 为什么必须从目标文件取：CTF 的 key/口令几乎总以字符串常量出现在二进制/资源里，
// 通用字典命中率有限；文件内常量才是本题真正的候选空间。
ipcMain.handle('extract-strings', async (event, filePath) => {
  try {
    if (!filePath || !fs.existsSync(filePath)) return { success: false, error: '文件不存在: ' + filePath };
    const buf = fs.readFileSync(path.resolve(filePath));
    const { extractStringsFromBuffer } = require('./intermediate-advance');
    // 大文件只取前 8MB：字符串常量集中在头部/节表附近，全量扫没有必要且拖慢启动
    const slice = buf.length > 8 * 1024 * 1024 ? buf.subarray(0, 8 * 1024 * 1024) : buf;
    const strings = extractStringsFromBuffer(slice, { minLen: 4, maxCount: 6000 });
    return { success: true, strings };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 解析二进制的映像范围与节表（PE/ELF）。渲染层没有 require('path') 也没有 readUInt32LE，
// 所有路径规范化与字节读取都在主进程做，渲染层只传原始路径。
ipcMain.handle('file-image-map', async (event, filePath) => {
  try {
    if (!filePath) return { success: false, error: '路径为空' };
    const abs = path.resolve(filePath);
    if (!fs.existsSync(abs)) return { success: false, error: '文件不存在: ' + abs };
    const buf = fs.readFileSync(abs);
    const { parseImageMap } = require('./binary-map');
    const map = parseImageMap(buf);
    if (!map) return { success: false, error: '无法解析为 PE/ELF 映像' };
    return { success: true, path: abs.replace(/\\/g, '/').toLowerCase(), map };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

// 查询 IDA 当前实际加载的是哪个文件。
// 只在端口已监听时才调用；插件不提供 server_health 时返回 success:false，
// 调用方据此走"身份未知 → 安全重载"策略（比拿别人的库当本题证据安全）。
ipcMain.handle('ida-identity', async () => {
  try {
    const r = await idaMcpCallTool('server_health', {});
    const data = r && (r.result !== undefined ? r.result : r);
    let obj = {};
    if (isPlainObject(data)) obj = data;
    else if (typeof data === 'string') {
      try { const j = JSON.parse(data); if (isPlainObject(j)) obj = j; } catch (e) { /* 非 JSON：按未知处理 */ }
    }
    const pick = (...keys) => {
      for (const k of keys) {
        if (obj[k] != null && String(obj[k]).trim()) return String(obj[k]).trim();
      }
      return '';
    };
    const input_path = pick('input_path', 'inputPath', 'path', 'file', 'filename');
    const idb_path = pick('idb_path', 'idbPath', 'database');
    const module = pick('module', 'module_name', 'moduleName');
    const imagebase = pick('imagebase', 'image_base', 'imageBase');
    if (!input_path && !idb_path && !module) {
      return { success: false, error: 'server_health 未返回可用的加载对象信息' };
    }
    return {
      success: true,
      input_path: input_path.replace(/\\/g, '/').toLowerCase(),
      idb_path: idb_path.replace(/\\/g, '/').toLowerCase(),
      module,
      imagebase,
      raw: obj,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// P2：中间值自动推进（哈希爆破 / Base64 / hex / 单字节 XOR）。
// 放主进程的理由：renderer 关了 nodeIntegration，拿不到 crypto；且爆破要跑几十万次哈希，
// 不该占用 UI 线程。filePath 可选，提供时把文件内字符串并入字典。
ipcMain.handle('advance-intermediates', async (event, hits, filePath) => {
  try {
    const { advanceIntermediates, extractStringsFromBuffer, buildDictionary } = require('./intermediate-advance');
    let extraStrings = [];
    if (filePath && fs.existsSync(filePath)) {
      try {
        const buf = fs.readFileSync(path.resolve(filePath));
        const slice = buf.length > 8 * 1024 * 1024 ? buf.subarray(0, 8 * 1024 * 1024) : buf;
        extraStrings = extractStringsFromBuffer(slice, { minLen: 3, maxCount: 6000 });
      } catch (e) { /* 读不到就用通用字典 */ }
    }
    const needsDictionary = (Array.isArray(hits) ? hits : []).some(h => /^(0x)?[0-9a-fA-F]{32,64}$/.test(String(h || '').trim()));
    const results = advanceIntermediates(hits, needsDictionary ? { dictionary: buildDictionary(extraStrings) } : {});
    return { success: true, results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('ensure-dir', async (event, dirPath) => {
  try {
    if (!isPathAllowedForWrite(dirPath)) return { success: false, error: '目录路径超出允许范围: ' + dirPath };
    fs.mkdirSync(path.resolve(dirPath), { recursive: true });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 弹出保存对话框并写入文件（脚本/WP 保存用）
ipcMain.handle('save-file', async (event, defaultName, content, filters) => {
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      defaultPath: defaultName,
      filters: filters || [{ name: '所有文件', extensions: ['*'] }]
    });
    if (result.canceled || !result.filePath) {
      return { success: false, canceled: true };
    }
    fs.writeFileSync(result.filePath, String(content), 'utf8');
    return { success: true, path: result.filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ADB 命令（spawn 参数数组）
// adb 解析：**优先模拟器自带的 nox_adb**（若已配置且存在），其次系统 PATH 里的 adb。
//
// 为什么优先 nox_adb：Nox 的后台服务（NoxVMSVC）会自己拉起 nox_adb(v36) 来管理它
// 的设备；只要它一跑，就会把 5037 上的 daemon 换成 v36。如果工具坚持用系统 adb(v41)，
// 则每轮调用都触发 "server version (41) doesn't match this client (36); killing"——
// daemon 被反复重建、已连接设备全部掉线（表现为 devices 里 62025 突然消失、
// service check package 失败、install 秒失败）。**与 Nox 保持同一个 adb 版本**才是根治。
//
// 兼容性：若未配置/不存在 nox_adb，再回退系统 adb（纯真机/非 Nox 场景）。
let _cachedAdbPath = null;
function resolveAdbPath() {
  if (_cachedAdbPath) return _cachedAdbPath;
  // 1) 配置里的模拟器 adb（Nox 场景首选，与 Nox 服务版本一致）
  const noxAdb = (config.tools && config.tools.nox_adb) || '';
  if (noxAdb && fs.existsSync(noxAdb)) { _cachedAdbPath = noxAdb; return noxAdb; }
  // 2) 系统 PATH 里的 adb
  try {
    const which = require('child_process')
      .execSync('where adb', { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    const first = String(which || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)[0];
    if (first && fs.existsSync(first)) { _cachedAdbPath = first; return first; }
  } catch (e) { /* 系统 PATH 无 adb */ }
  // 3) 兜底
  _cachedAdbPath = 'adb';
  return _cachedAdbPath;
}

// 连接设备（幂等）：每次 adb 命令前执行，应对 daemon 被顶替后掉线的瞬时窗口
async function adbEnsureConnected(port) {
  const adb = resolveAdbPath();
  return await new Promise((resolve) => {
    const child = spawn(adb, ['connect', `127.0.0.1:${port}`], { shell: false, windowsHide: true });
    let out = '';
    const t = setTimeout(() => { try { child.kill(); } catch (e) {} }, 8000);
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', d => { out += d.toString(); });
    child.on('error', () => { clearTimeout(t); resolve(false); });
    child.on('close', () => { clearTimeout(t); resolve(/connected|already connected/i.test(out)); });
  });
}

ipcMain.handle('adb-command', async (event, args) => {
  const adbPath = resolveAdbPath();
  const port = config.emulator.adb_port;
  await adbEnsureConnected(port);
  const argv = [adbPath, '-s', `127.0.0.1:${port}`].concat(tokenizeCommand(args || ''));

  const runOnce = () => new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { shell: false, windowsHide: true });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch (e) {} }, 30000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, stdout: '', stderr: '', error: err.message });
    });
    child.on('close', () => {
      clearTimeout(timer);
      resolve({ success: true, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: null });
    });
  });

  let r = await runOnce();
  // 断桥瞬时窗口重试：daemon 刚被另一版本 adb 顶掉时，第一条命令会 not found，
  // 重连一次再试（对秒失败的 install 尤其关键）。
  // 尤其要处理 Nox 自带的 nox_adb(v36) 与本机 adb(v41) 互杀：
  // 表现是 stderr 出现 "server version (36) doesn't match this client (41); killing"。
  // 此时用我们的客户端 kill-server + start-server 重建 daemon，再重连重试。
  const combined = () => String(r.stdout) + String(r.stderr);
  const mismatch = /doesn't match this client|server version .* killing/i.test(combined());
  if (mismatch) {
    const adb = resolveAdbPath();
    const runSync = (args) => new Promise((res) => {
      const c = spawn(adb, args, { shell: false, windowsHide: true });
      const t = setTimeout(() => { try { c.kill(); } catch (e) {} res(); }, 8000);
      c.on('error', () => { clearTimeout(t); res(); });
      c.on('close', () => { clearTimeout(t); res(); });
    });
    await runSync(['kill-server']);
    await runSync(['start-server']);
  }
  if (r.success && (mismatch || /no devices|not found|device offline|offline/i.test(combined()))) {
    await adbEnsureConnected(port);
    await new Promise(res => setTimeout(res, 600));
    r = await runOnce();
  }
  return r;
});

// Frida 命令（spawn 参数数组）
ipcMain.handle('frida-command', async (event, args) => {
  const port = config.emulator.frida_port;
  const argv = ['frida', '-H', `127.0.0.1:${port}`].concat(tokenizeCommand(args || ''));

  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { shell: false, windowsHide: true });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch (e) {} }, 30000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, stdout: '', stderr: '', error: err.message });
    });
    child.on('close', () => {
      clearTimeout(timer);
      resolve({ success: true, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: null });
    });
  });
});

// 执行Frida Hook脚本
ipcMain.handle('run-frida-hook', async (event, script, target, opts) => {
  try {
    if (!script || typeof script !== 'string') {
      return { success: false, error: 'Hook脚本为空' };
    }
    const r = await execFridaHook(script, target, opts);
    if (r && typeof r === 'object') return { success: r.success !== false, output: r.output || '', error: r.error || null };
    return { success: true, output: String(r || '') };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Frida 列出进程（spawn 参数数组）
ipcMain.handle('frida-ps', async (event, opts) => {
  const port = config.emulator.frida_port;
  // opts.apps=true 时用 -a（应用列表：PID/Name/Identifier 三列），否则进程列表
  const extra = (opts && opts.apps) ? ['-a'] : [];

  return new Promise((resolve) => {
    const child = spawn('frida-ps', ['-H', `127.0.0.1:${port}`].concat(extra), { shell: false, windowsHide: true });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch (e) {} }, 10000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, stdout: '', stderr: '', error: err.message });
    });
    child.on('close', () => {
      clearTimeout(timer);
      resolve({ success: true, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: null });
    });
  });
});

// 选择文件对话框
ipcMain.handle('select-file', async (event, filters) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: '所有文件', extensions: ['*'] },
      { name: '逆向题目', extensions: ['apk', 'exe', 'dll', 'so', 'elf', 'pyc', 'dex', 'wasm', 'bin', 'out'] }
    ]
  });

  if (result.canceled) {
    return null;
  }
  return result.filePaths[0];
});

// 打开外部链接（仅允许 http/https，防止 openExternal 拉起任意协议）
ipcMain.handle('open-external', async (event, url) => {
  try {
    const u = new URL(String(url || ''));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { success: false, error: '仅允许 http/https 链接' };
    }
    await shell.openExternal(u.toString());
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 最小化窗口
ipcMain.handle('minimize-window', () => {
  mainWindow.minimize();
});

// 最大化窗口
ipcMain.handle('maximize-window', () => {
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

// 关闭窗口
ipcMain.handle('close-window', () => {
  mainWindow.close();
});

// 自动测试报告写入（主进程侧，路径可靠）。
// 渲染层用 state.appPaths.userData 拼路径，但该值在 getAppPaths 失败时为空 →
// report 静默不写、外部驱动只能等到超时（实测：第 3 题 20 秒就结束，驱动干等 10 分钟）。
ipcMain.handle('autotest-report', async (event, data) => {
  try {
    const file = path.join(app.getPath('userData'), 'autotest-report.json');
    fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data, null, 2), 'utf8');
    // 追加式轮次日志（40 题实测的观测缺口：report.json 只留最后一轮快照，
    // 外部只能靠 UI DOM 扒进度。每轮追加一行，批跑结束后可完整复盘）
    try {
      const j = typeof data === 'string' ? JSON.parse(data) : data;
      const last = j && Array.isArray(j.results) ? j.results[j.results.length - 1] : null;
      if (last) {
        fs.appendFileSync(path.join(app.getPath('userData'), 'autotest-rounds.jsonl'),
          JSON.stringify({ ts: new Date().toISOString(), round: j.results.length, name: last.name, ok: !!last.ok, note: last.note || '', flag: last.flag || '', near_miss: last.near_miss || [], difficulty: last.difficulty || '' }) + '\n', 'utf8');
      }
    } catch (e) { /* 追加失败不影响 report */ }
    return { success: true, path: file };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 退出应用（自动测试脚本用：每题结束后关闭进程，避免多个实例抢 MCP 端口）..
ipcMain.handle('quit-app', () => {
  isQuitting = true;
  app.quit();
  return { success: true };
});

// 格式化文件大小
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ========== MCP 通信函数 ==========

// 解析 MCP Streamable HTTP / SSE 响应体。
// ida-pro-mcp 等标准 MCP 服务返回的是 SSE 事件流（event: message \n data: {...}），
// 而 JEB 自定义插件返回纯 JSON。这里两种都兼容，返回 { json, raw, headers, statusCode }。
function parseMCPResponse(statusCode, headers, body) {
  const result = { statusCode, headers, raw: body, json: null };

  if (statusCode < 200 || statusCode >= 300) {
    result.error = `MCP HTTP 错误 (${statusCode}): ${body.substring(0, 300)}`;
    return result;
  }

  const text = typeof body === 'string' ? body : body.toString('utf8');
  const trimmed = text.trim();
  if (!trimmed) return result;

  // 1) 尝试整段直接解析为 JSON（JEB 插件等）
  try {
    result.json = JSON.parse(trimmed);
    return result;
  } catch (e) {
    /* 非纯 JSON，继续尝试 SSE 分帧 */
  }

  // 2) 尝试解析为 SSE：按空行分帧，取所有 data: 行，优先匹配与请求 id 一致的帧，否则取最后一帧
  const dataLines = [];
  const frames = trimmed.split(/\n\s*\n/);
  for (const frame of frames) {
    let found = null;
    for (const line of frame.split('\n')) {
      if (line.startsWith('data:')) {
        const v = line.slice(5).trim();
        if (v && v !== '[DONE]') found = found ? found + v : v; // SSE 多行 data 拼接
      }
    }
    if (found) dataLines.push(found);
  }

  // 处理分块 JSON 片段（JSON-RPC 响应分多帧，最后帧才是结果）——只解析含 "result" 或 "error" 的帧
  for (const dl of dataLines) {
    try {
      const j = JSON.parse(dl);
      if (j && (j.result !== undefined || j.error !== undefined)) {
        result.json = j;
        return result;
      }
    } catch (e) { /* 跳过非 JSON data 帧 */ }
  }

  // 3) 取最后一个能解析的 data 帧
  for (let i = dataLines.length - 1; i >= 0; i--) {
    try {
      const j = JSON.parse(dataLines[i]);
      if (j) { result.json = j; return result; }
    } catch (e) { /* ignore */ }
  }

  return result;
}

// 发送MCP请求（兼容 JEB 纯 JSON 与 IDA 的 Streamable HTTP/SSE）
// 返回值：解析后的 JSON-RPC 对象，附带 _headers / _statusCode / _raw
async function sendMCPRequest(url, method, params = {}, extraHeaders = {}, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const postData = JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method: method,
      params: params
    });

    const headers = Object.assign({
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'Content-Length': Buffer.byteLength(postData)
    }, extraHeaders);

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: `${urlObj.pathname}${urlObj.search}`,
      method: 'POST',
      headers: headers,
      timeout: timeoutMs
    };

    const req = client.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        const parsed = parseMCPResponse(res.statusCode, res.headers, data);
        if (parsed.error) {
          const err = new Error(parsed.error);
          err.statusCode = res.statusCode;
          err.body = data;
          reject(err);
          return;
        }
        let json = parsed.json || {};
        // 附加元数据，便于调用方读取会话 ID / 原始响应
        if (typeof json === 'object' && json !== null) {
          json._headers = res.headers;
          json._statusCode = res.statusCode;
          json._raw = data;
        } else {
          json = { result: json, _headers: res.headers, _statusCode: res.statusCode, _raw: data };
        }
        resolve(json);
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('MCP 请求超时'));
    });

    req.write(postData);
    req.end();
  });
}

// ========== IDA MCP 会话客户端 ==========
// ida-pro-mcp（以及多数标准 MCP 服务）需要：
//   1) initialize 建立会话并返回 Mcp-Session-Id
//   2) notifications/initialized 通知会话就绪
//   3) tools/list 发现真实工具名
//   4) tools/call 携带会话 ID，参数须匹配该工具 schema，结果在 result.result.content[].text
let idaMcpState = { sessionId: null, toolMap: null, baseUrl: null };

async function idaMcpGetBaseUrl() {
  // 扩展组在主进程层统一附加，保证 initialize / tools/list / tools/call 用的是同一个
  // 带 ?ext=dbg 的 URL（否则会话建立后看到的工具表与调用端点不一致）。
  const exts = (config.mcp && config.mcp.idaExtensions) || ['dbg'];
  const url = idaMcpEffectiveUrl(config.mcp && config.mcp.ida, exts);
  if (!idaMcpState._extLogged) {
    idaMcpState._extLogged = true;
    console.log(`[IDA MCP] 扩展组: ${(Array.isArray(exts) ? exts : [exts]).join(',')} → ${url}`);
  }
  return url;
}

// 建立/复用 IDA MCP 会话
async function idaMcpEnsureSession() {
  const baseUrl = await idaMcpGetBaseUrl();
  // 会话 URL 变化则重置（ext 组变化也必须重建，否则旧会话里没有新组的工具）
  if (needsSessionReset(idaMcpState.baseUrl, baseUrl)) {
    idaMcpState = { sessionId: null, toolMap: null, baseUrl, _extLogged: true };
  }

  if (idaMcpState.sessionId) return idaMcpState.sessionId;

  const init = await sendMCPRequest(baseUrl, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'ctf-tool', version: '1.0' }
  });

  // 读取会话 ID（标准 MCP 通过响应头 Mcp-Session-Id 返回；部分实现放在 body）
  const sessionId = (init && (init._headers || {})['mcp-session-id'])
    || (init && init.result && init.result.sessionId)
    || null;
  idaMcpState.sessionId = sessionId;

  // 发送 initialized 通知（带会话头，部分服务要求）
  const headers = {};
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  try {
    await sendMCPRequest(baseUrl, 'notifications/initialized', {}, headers, 8000);
  } catch (e) {
    // 非关键，忽略
  }

  // 发现工具名
  await idaMcpDiscoverTools(sessionId);

  return sessionId;
}

// 通过 tools/list 发现真实工具名，构建 逻辑名 -> 真实名 的映射
async function idaMcpDiscoverTools(sessionId) {
  const baseUrl = await idaMcpGetBaseUrl();
  const headers = {};
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  const resp = await sendMCPRequest(baseUrl, 'tools/list', {}, headers, 15000);
  const tools = (resp && resp.result && resp.result.tools) || [];

  // 候选名映射：逻辑名 -> 真实名候选列表（按优先级）
  const candidates = {
    'list_functions': ['list_functions', 'list_funcs', 'get_all_functions', 'enumerate_functions'],
    // 找 flag/key 用 find_regex：字符串缓存 + Python 正则，快且不阻塞 IDA UI。
    // search_text 是 IDA 原生 C++ 扫描，regex:true 时会对每个 EA 反复 find_text，
    // 在稍大的二进制上会「卡住」甚至让 IDA 无响应——因此只作兜底，且调用时禁用其原生 regex。
    'find_strings': ['find_regex', 'search_text', 'find_strings', 'get_strings', 'search_strings', 'search_string', 'get_string_list', 'list_strings'],
    'decompile': ['get_function_decompile', 'decompile_function', 'get_pseudocode', 'decompile'],
    'xrefs_to': ['get_xrefs_to', 'xrefs_to', 'get_cross_references'],
    'trace_data_flow': ['trace_data_flow', 'trace_flow', 'data_flow'],
    'get_function_by_name': ['get_function_by_name'],
    'analyze_file': ['analyze_file', 'auto_analyze'],
    // open_file 属于 ida-pro-mcp 的 discovery 组：拉起新 IDA 实例并把本 MCP 会话
    // 重定向过去（switch=true）。花指令修复后必须靠它才能在**新 IDB** 上反编译。
    'open_file': ['open_file'],
    'list_instances': ['list_instances']
  };

  const realNames = tools.map(t => t && (t.name || t.title)).filter(Boolean);
  const map = {};

  for (const logical of Object.keys(candidates)) {
    const found = candidates[logical].find(n => realNames.includes(n));
    map[logical] = found || candidates[logical][0];
  }

  // 若发现列表为空，保留候选名的第一个作为兜底
  idaMcpState.toolMap = map;
  return map;
}

// 解析真实工具名
async function idaMcpResolveTool(logicalName) {
  if (!idaMcpState.toolMap) await idaMcpEnsureSession();
  return (idaMcpState.toolMap && idaMcpState.toolMap[logicalName]) || logicalName;
}

// 将逻辑参数名转换为各工具 schema 期望的参数名。
// realName 为 tools/list 解析出的真实工具名——不同实现的参数 schema 不同，
// 尤其是字符串搜索：find_regex 用 {pattern,limit,offset}，search_text 用
// {pattern,limit,start,regex,...}，必须按真实工具名生成参数，否则会被 MCP 拒绝或走错分支。
function normalizeIdaArgs(logicalName, args, realName) {
  args = args || {};
  realName = realName || '';
  switch (logicalName) {
    case 'decompile':
      return { addr: args.address || args.addr || args.function_name || '' };
    case 'find_strings': {
      const pat = args.pattern || args.regex || args.query || '';
      const limit = args.limit || 30;
      // find_regex：字符串缓存正则搜索（Python 端），快且绝不阻塞 IDA。
      if (realName === 'find_regex') {
        return { pattern: pat, limit };
      }
      // search_text：IDA 原生文本扫描。绝不能开 regex——其 SEARCH_REGEX 会对每个
      // 候选 EA 反复调用 find_text，在大程序上会长时间卡住 IDA UI 线程（用户实测「卡住」）。
      if (realName === 'search_text' || realName === 'find_strings' || !realName) {
        // 无法用原生 regex 时，把 'a|b|c' 这类顶层字面量择一搜索（优先 flag），
        // 否则会按字面去搜 'a|b|c' 整串，必然 0 命中。
        let lit = pat;
        if (/[|]/.test(lit) && !/[()\[\]{}^$*+?\\]/.test(lit)) {
          const parts = lit.split('|').map(s => s.trim()).filter(Boolean);
          lit = parts.find(s => /^flag$/i.test(s)) || parts[0] || lit;
        }
        const out = { pattern: lit, limit, regex: false };
        if (realName === 'search_text') out.code_only = false;
        return out;
      }
      // 其他实现（get_strings 等）：尽力透传 pattern
      return { pattern: pat, limit };
    }
    case 'xrefs_to': {
      // 真实 ida-pro-mcp 的 xrefs_to 参数是数组形式 {addrs:[...]}（实测：传 {addrs:['0x..']}
      // 正常返回 [{addr, xrefs:[...]}]）。旧代码返回 {address:...}（单数）→ 被判"缺 addrs"报错。
      // 只发实际提供的字段，避免严格 schema 拒绝未知键。
      const out = {};
      let addrs = args.addrs;
      if (!Array.isArray(addrs)) {
        const one = args.address || args.addr || args.function_name || '';
        addrs = one ? [one] : [];
      }
      if (addrs.length) out.addrs = addrs;
      if (Array.isArray(args.addrs_to)) out.addrs_to = args.addrs_to;
      return out;
    }
    case 'trace_data_flow': {
      // 真实 ida-pro-mcp 的参数多为 {addr} 或 {start}；按需透传，缺失则原样（调用方已 try/catch）。
      const a = args.addr || args.address || args.start;
      return a ? { addr: a } : args;
    }
    case 'list_functions':
      return { queries: args.queries || {} };
    case 'open_file':
      // 插件签名：open_file(file_path, switch=True, autonomous=False, new_database=False, timeout=30)
      // autonomous 必须显式置 true：否则新 IDA 起来后弹模态框，MCP 端口注册不上，
      // 后续所有工具调用都会超时（表现为"IDA 卡住"）。
      return {
        file_path: args.file_path || args.path || '',
        switch: args.switch !== false,
        autonomous: args.autonomous !== false,
        new_database: args.new_database === true,
        timeout: Number(args.timeout) > 0 ? Number(args.timeout) : 90,
      };
    case 'list_globals': {
      // 插件 api_core.py 的 list_globals 只认 {queries:{filter,offset,count}}，
      // 缺省 count=100 → 全局符号表被截断。把顶层 filter/offset/count 收进 queries，
      // count 兜底 500（分页版本会再按需覆盖）。
      const q = Object.assign({}, args.queries || {});
      if (q.filter === undefined && args.filter !== undefined) q.filter = args.filter;
      if (q.offset === undefined && args.offset !== undefined) q.offset = args.offset;
      if (q.count === undefined && args.count !== undefined) q.count = args.count;
      if (q.count === undefined) q.count = 500;
      return { queries: q };
    }
    default:
      return args;
  }
}

// 从 MCP tools/call 信封中解出真实数据文本
function unwrapMcpContent(envelope) {
  if (!envelope) return null;
  // 标准 MCP: envelope.result.content[].text
  const content = envelope.result && envelope.result.content;
  if (Array.isArray(content)) {
    const text = content
      .map(c => (c && (c.text !== undefined ? c.text : (c.content !== undefined ? c.content : null))))
      .filter(t => t !== null && t !== undefined)
      .join('\n');
    if (text) return text;
  }
  // JEB 风格: envelope.result 直接是数据
  if (envelope.result !== undefined) return envelope.result;
  // 顶层直接给数据
  if (envelope.content !== undefined) return envelope.content;
  return envelope;
}

// 调用 IDA MCP 工具（逻辑名），返回解包后的数据
async function idaMcpCallTool(logicalName, args) {
  // 兼容旧调用名，统一到逻辑工具名
  const aliases = {
    list_funcs: 'list_functions'
  };
  logicalName = aliases[logicalName] || logicalName;

  const sessionId = await idaMcpEnsureSession();
  const realName = await idaMcpResolveTool(logicalName);
  const realArgs = normalizeIdaArgs(logicalName, args, realName);
  const baseUrl = await idaMcpGetBaseUrl();

  const headers = {};
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  const resp = await sendMCPRequest(baseUrl, 'tools/call', {
    name: realName,
    arguments: realArgs
  }, headers, 60000);

  if (mcpResultIsError(resp)) {
    throw new Error(mcpErrorText(resp));
  }

  let data = unwrapMcpContent(resp);

  // 文本数据尽力转 JSON
  if (typeof data === 'string') {
    const t = data.trim();
    if (t && (t.startsWith('{') || t.startsWith('['))) {
      try { data = JSON.parse(t); } catch (e) { /* 保留原始文本 */ }
    }
  }

  // ida-pro-mcp 的列表类工具把结果放在 data 字段里，且外面可能还套一层数组信封：
  //   { data: [...] }                    单对象形式
  //   [{ data: [...], next_offset: ... }]  数组形式（list_funcs / list_globals 实测如此）
  // 下游一律要求扁平数组，这里统一拆封；非列表结果原样返回。
  data = unwrapIdaDataEnvelope(data);

  return data;
}

// 分页调用列表类工具（list_functions / list_globals），把每页的 data 合并成完整数组。
// 关键点：必须在解包**之前**读 next_offset——unwrapIdaDataEnvelope 会把信封拍平，
// 游标随之丢失，只能拿到第一页（插件默认 count=100）。
async function idaMcpCallPaged(logicalName, baseQuery) {
  const sessionId = await idaMcpEnsureSession();
  const realName = await idaMcpResolveTool(logicalName);
  const baseUrl = await idaMcpGetBaseUrl();
  const headers = {};
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  const r = await callPaged(async (queries) => {
    const realArgs = normalizeIdaArgs(logicalName, { queries }, realName);
    const resp = await sendMCPRequest(baseUrl, 'tools/call', {
      name: realName,
      arguments: realArgs
    }, headers, 60000);
    if (mcpResultIsError(resp)) {
      throw new Error(mcpErrorText(resp));
    }
    let data = unwrapMcpContent(resp);
    if (typeof data === 'string') {
      const t = data.trim();
      if (t && (t.startsWith('{') || t.startsWith('['))) {
        try { data = JSON.parse(t); } catch (e) { /* 保留原始文本 */ }
      }
    }
    return data;
  }, baseQuery || {}, {
    tool: realName,
    count: 500,
    log: (text) => console.log(text),
  });

  return r.items;
}

// 只对"元素含 data 数组"的信封生效，因此 decompile（{addr,code,refs}）、
// find_regex（{n,matches,cursor}）、get_bytes（[{addr,data:"0x.. 0x.."}]）等不受影响。
// ⚠️ 会丢掉 next_offset——分页场景必须走 idaMcpCallPaged（它在解包前取游标）。
function unwrapIdaDataEnvelope(data) {
  const innerArray = v => (v && !Array.isArray(v) && Array.isArray(v.data)) ? v.data : null;
  if (Array.isArray(data)) {
    if (data.length === 1) {
      const inner = innerArray(data[0]);
      if (inner) return inner;
    }
    // 多段信封（分页）时把各段 data 合并
    const parts = data.map(innerArray);
    if (parts.length && parts.every(Boolean)) return parts.reduce((a, b) => a.concat(b), []);
    return data;
  }
  return innerArray(data) || data;
}

// IDA MCP - 获取IDA分析结果 / 工具列表
ipcMain.handle('ida-mcp-analyze', async (event, args) => {
  try {
    // 建立会话并发现工具
    await idaMcpEnsureSession();

    // 列出可用工具
    const baseUrl = await idaMcpGetBaseUrl();
    const headers = {};
    if (idaMcpState.sessionId) headers['Mcp-Session-Id'] = idaMcpState.sessionId;
    const toolsResult = await sendMCPRequest(baseUrl, 'tools/list', {}, headers);

    // 如果有逻辑工具名，调用对应工具并返回解包后的数据
    if (args && args.function) {
      const result = await idaMcpCallTool(args.function, args.arguments || {});
      return { success: true, result: result };
    }

    const tools = (toolsResult.result && toolsResult.result.tools) || [];
    // 调试能力判定集中到这里：渲染层两个连接路径都只消费这个结论，
    // 不再各自用关键词过滤（旧实现的 'ea'/'ip' 子串几乎命中了所有静态工具）。
    const debugCapability = classifyIdaDebugTools(tools.map(t => (t && (t.name || t.title)) || ''));

    return {
      success: true,
      tools,
      debugCapability,
      message: 'IDA MCP 连接成功'
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// IDA MCP - 调用特定工具（逻辑名，自动匹配真实工具 + 解包）
ipcMain.handle('ida-mcp-call', async (event, toolName, args) => {
  try {
    // 列表类工具默认只返回 100 条（插件 query.get("count", 100)）→ 必须走分页，
    // 否则函数表/全局表永远是残缺的。
    const paged = { list_funcs: 'list_functions', list_functions: 'list_functions', list_globals: 'list_globals' };
    const logical = paged[toolName];
    if (logical && !(args && args.paged === false)) {
      const q = (args && args.queries) || {};
      const result = await idaMcpCallPaged(logical, q);
      return { success: true, result, paged: true };
    }
    const result = await idaMcpCallTool(toolName, args);
    return { success: true, result: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 显式分页版本（渲染层采集用；语义上是"拿全量列表"）
ipcMain.handle('ida-mcp-call-paged', async (event, toolName, args) => {
  try {
    const logical = toolName === 'list_globals' ? 'list_globals' : 'list_functions';
    const q = (args && args.queries) || {};
    const result = await idaMcpCallPaged(logical, q);
    return { success: true, result, paged: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// JEB MCP - 启动本地 MCP 服务（需在设置中配置 mcp.jebMcpScript 指向 server.py 所在目录）
ipcMain.handle('jeb-mcp-start', async (event) => {
  try {
    const scriptDir = config.mcp.jebMcpScript;
    if (!scriptDir) {
      return {
        success: false,
        error: '未配置 mcp.jebMcpScript（JEB MCP server.py 所在目录）。JEB MCP 通常由 JEB 插件自带 HTTP 服务，直接启动 JEB 即可；确需独立启动请在设置中填写目录。'
      };
    }

    const child = spawn('uv', ['--directory', scriptDir, 'run', 'server.py'], { shell: false, detached: true, stdio: 'ignore' });
    child.on('error', (err) => {
      console.error('JEB MCP启动失败:', err.message);
    });
    child.unref();

    return { success: true, message: 'JEB MCP 启动中...' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// JEB MCP - 调用工具（直接调用JEB插件HTTP API）
ipcMain.handle('jeb-mcp-call', async (event, toolName, args) => {
  try {
    const mcpUrl = config.mcp.jebMcp;

    // 直接调用JEB插件的HTTP API
    const result = await callJebPlugin(toolName, args);

    return {
      success: true,
      result: result
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// JEB MCP 探活：向插件端口发一个空请求，能收到 HTTP 响应即视为在运行
function jebProbe() {
  // 只做 TCP 端口探测：端口在监听就说明 JEB（含 MCP 插件）已在运行。
  // 不能用"MCP 请求是否成功"判活——JEB 正忙时请求会超时，会被误判为"未运行"，
  // 从而重复拉起第二个 JEB（第二个无法绑定 16161 且同工程被占用 → 卡死）。
  return new Promise((resolve, reject) => {
    const net = require('net');
    const u = new URL(config.mcp.jebMcp);
    const port = Number(u.port) || 80;
    const sock = net.connect({ host: u.hostname || '127.0.0.1', port }, () => { sock.destroy(); resolve(true); });
    sock.setTimeout(2000, () => { sock.destroy(); reject(new Error('probe timeout')); });
    sock.on('error', (e) => reject(e));
  });
}

// 解析可用的 JDK 17+ 主目录：JEB 5.x 要求 Java 17+，而本机 PATH 命中的 java 常是 1.8，
// 会让 JEB 以 UnsupportedClassVersionError 闪退。优先级：
// config.tools.jebJdkHome > 环境变量 JEB_JAVA_HOME / JAVA_HOME > 常见安装目录自动扫描
let jebJdkHomeCache;
function resolveJebJdkHome() {
  if (jebJdkHomeCache !== undefined) return jebJdkHomeCache;
  const cands = [];
  const push = h => { if (h && cands.indexOf(h) < 0) cands.push(h); };
  push(config.tools && config.tools.jebJdkHome);
  push(process.env.JEB_JAVA_HOME);
  push(process.env.JAVA_HOME);
  for (const root of ['C:\\Program Files\\Java', 'C:\\Program Files\\Eclipse Adoptium', 'C:\\Program Files\\Microsoft\\jdk', 'C:\\Program Files\\Amazon Corretto', 'D:\\Program Files\\Java']) {
    try { fs.readdirSync(root).forEach(n => push(path.join(root, n))); } catch (e) { /* 目录不存在 */ }
  }
  // 先探测所有候选的 Java 版本，再择优：JDK 17 最佳（JEB 官方推荐，SecurityManager
  // 默认可用，dexdec 沙箱完整）；其次 18/19/20/21（需 jvmopt 里 allow，已在
  // hardenEditorConfigs 写入）。避免"目录扫描顺序"随机命中 JDK21 而丢掉 JDK17。
  let best17 = '', bestOther = '';
  for (const home of cands) {
    const javaExe = path.join(home, 'bin', 'java.exe');
    if (!fs.existsSync(javaExe)) continue;
    try {
      const r = spawnSync(javaExe, ['-version'], { encoding: 'utf8', timeout: 5000 });
      const txt = String((r && r.stderr) || '') + String((r && r.stdout) || '');
      const m = txt.match(/version "(\d+)/);
      if (!m) continue;
      const major = parseInt(m[1], 10);
      if (major === 17 && !best17) best17 = home;
      else if (major > 17 && !bestOther) bestOther = home;
    } catch (e) { /* 忽略不可用的候选 */ }
  }
  jebJdkHomeCache = best17 || bestOther || '';
  return jebJdkHomeCache;
}

// JEB MCP 自动拉起：插件未监听 16161 时，用 JEB 启动器加载 scripts/MCP.py（可选打开目标文件）
let jebLaunching = null;

// 启动前固化"不弹确认框 + 自动保存"，避免每次都要人工点掉对话框：
// - JEB：jeb-client.cfg 的 ui.DialogPersistenceData 里给相关对话框置 doNotShow=true
//   （JEB 的"以后不再显示此对话框(仅本次操作)"复选框就是存这里）
// - IDA ：idagui.cfg 的 AUTOSAVE 保持启用（>0），关闭/崩溃前会按操作数自动落库，
//   避免"关闭后不保存"导致下次打开是空库
function hardenEditorConfigs() {
  // --- JEB ---
  try {
    const jebBat = config.tools && config.tools.jeb;
    if (jebBat) {
      const jebRoot = path.dirname(jebBat);
      // jvmopt.txt：JEB 启动器读取的单行 JVM 选项。JDK 18+ 下 dexdec 反混淆沙箱需要
      // `-Djava.security.manager=allow`（否则 SecurityManager 不可用、沙箱能力受限，
      // 重度混淆 dex 反编译会失败），并按 JEB 官方提示补 --add-opens。
      // 仅在文件缺失或未包含该选项时写入，避免覆盖用户自定义。
      try {
        const jvmOptFile = path.join(jebRoot, 'jvmopt.txt');
        const wantOpts = '-Djava.security.manager=allow --add-opens java.base/java.lang=ALL-UNNAMED';
        let cur = '';
        try { cur = fs.readFileSync(jvmOptFile, 'utf8').trim(); } catch (e) { cur = ''; }
        if (!/security\.manager=allow/.test(cur)) {
          const merged = (cur ? cur + ' ' : '') + wantOpts;
          fs.writeFileSync(jvmOptFile, merged + '\n');
          console.log('[JEB] 已写入 jvmopt.txt（启用 SecurityManager 白名单 + add-opens，适配 JDK 21）');
        }
      } catch (e) { console.error('[JEB] 写入 jvmopt.txt 失败:', e.message); }
      const cfgPath = path.join(jebRoot, 'bin', 'jeb-client.cfg');
      if (fs.existsSync(cfgPath)) {
        let txt = fs.readFileSync(cfgPath, 'utf8');
        const need = ['dlgJebFileOpen', 'com.pnfsoftware.jeb.rcpclient.dialogs.AdaptivePopupDialog', 'dlgJavaVersionWarning4'];
        const m = txt.match(/^\.ui\.DialogPersistenceData\s*=\s*(.*)$/m);
        if (m) {
          // 就地合并：对话框已有的参数（如 defaultPath）保留，仅追加/覆盖 doNotShow=true，
          // 避免同一 key 出现两次（JEB 只认第一处，会白写）
          const pairs = new Map();
          const order = [];
          for (const seg of m[1].trim().split('&')) {
            if (!seg) continue;
            const eq = seg.indexOf('=');
            const k = eq >= 0 ? seg.slice(0, eq) : seg;
            const v = eq >= 0 ? seg.slice(eq + 1) : '';
            if (!pairs.has(k)) order.push(k);
            pairs.set(k, v);
          }
          let changed = false;
          for (const dlg of need) {
            const cur = pairs.get(dlg);
            if (cur === undefined) { pairs.set(dlg, 'doNotShow%3Dtrue'); order.push(dlg); changed = true; }
            else if (!/doNotShow%3Dtrue/i.test(cur)) {
              const params = cur.split('%26').filter(Boolean); // %26 = & 编码
              const idx = params.findIndex(p => /^doNotShow%3D/i.test(p));
              if (idx >= 0) params[idx] = 'doNotShow%3Dtrue'; else params.push('doNotShow%3Dtrue');
              pairs.set(dlg, params.join('%26'));
              changed = true;
            }
          }
          if (changed) {
            const val = order.map(k => k + '=' + pairs.get(k)).join('&');
            txt = txt.replace(/^\.ui\.DialogPersistenceData\s*=.*$/m, '.ui.DialogPersistenceData = ' + val);
            fs.writeFileSync(cfgPath, txt);
            console.log('[JEB] 已固化对话框 doNotShow（抑制确认页）');
          }
        }
      }
    }
  } catch (e) { console.error('[JEB] 固化配置失败:', e.message); }

  // --- IDA ---
  try {
    const idaPath = (config.tools && (config.tools.ida || config.tools.ida64)) || '';
    if (idaPath) {
      const idaRoot = path.dirname(idaPath);
      const cfgPath = path.join(idaRoot, 'cfg', 'idagui.cfg');
      if (fs.existsSync(cfgPath)) {
        let txt = fs.readFileSync(cfgPath, 'utf8');
        // AUTOSAVE 为 0 时关闭自动保存 → 改成 100（每 100 次操作落库），保证关闭前有存档
        const m = txt.match(/^AUTOSAVE\s*=\s*(\d+)/m);
        if (m && parseInt(m[1], 10) === 0) {
          txt = txt.replace(/^AUTOSAVE\s*=\s*\d+/m, 'AUTOSAVE                = 100');
          fs.writeFileSync(cfgPath, txt);
          console.log('[IDA] 已启用 AUTOSAVE=100（关闭前自动落库）');
        }
      }
    }
  } catch (e) { console.error('[IDA] 固化配置失败:', e.message); }
}

// 是否已有 JEB 进程在跑（java 加载 jebc.jar）。用于避免"第一个 JEB 还在启动、
// 端口未就绪时又拉起第二个 JEB"（两实例抢 16161/同工程 → 双双卡死）。
function isJebProcessRunning() {
  try {
    const out = require('child_process').execSync('tasklist /FI "IMAGENAME eq java.exe"', { encoding: 'latin1', windowsHide: true, timeout: 5000 });
    if (!/java\.exe/i.test(out)) return false;
    // 进一步确认是 JEB（wmic 取命令行；失败则退化为"有 java 就当在跑"）
    try {
      const cl = require('child_process').execSync('wmic process where "name=\'java.exe\'" get CommandLine', { encoding: 'latin1', windowsHide: true, timeout: 6000 });
      if (/jebc\.jar|jeb[\\/]|JEB-|jeb_wincon/i.test(cl)) return true;
      return false;
    } catch (e) {
      return true; // 有 java 进程但取不到命令行：保守认为 JEB 可能在跑，等端口即可
    }
  } catch (e) { return false; }
}

async function ensureJebPluginRunning(targetFile) {
  let existed = false;
  // jebProbe 是异步 Promise，必须 await 才能真实反映端口状态（否则 existed 恒 true，拉起永远跳过）
  try { await jebProbe(); existed = true; } catch (e) { /* 未运行 */ }
  if (existed) return { ok: true, already: true };
  // 端口未就绪，但已有 JEB 进程（正在启动中）：不要拉起第二个，轮询等端口即可。
  if (!jebLaunching && isJebProcessRunning()) {
    console.log('[JEB MCP] 检测到已有 JEB 进程在运行，等待其端口就绪（不重复启动）');
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 4000));
      try { await jebProbe(); return { ok: true, already: true }; } catch (e) { /* 继续等 */ }
    }
    return { ok: false, error: '检测到 JEB 进程在运行，但 120s 内 16161 未就绪（MCP 插件可能未加载）' };
  }
  if (jebLaunching) return jebLaunching;
  jebLaunching = (async () => {
    try {
      const jebBat = config.tools && config.tools.jeb;
      if (!jebBat || !fs.existsSync(jebBat)) {
        return { ok: false, error: '未配置 tools.jeb（JEB 启动器路径），无法自动拉起 JEB MCP' };
      }
      const mcpScript = path.join(path.dirname(jebBat), 'scripts', 'MCP.py');
      if (!fs.existsSync(mcpScript)) {
        return { ok: false, error: 'JEB scripts 目录未找到 MCP.py 插件: ' + mcpScript };
      }
      // JEB 5.x 必须跑在 Java 17+ 上；找不到就明确报错，避免"启动了但闪退"的黑盒现象
      const jdkHome = resolveJebJdkHome();
      try { hardenEditorConfigs(); } catch (e) { /* 配置固化失败不阻塞 */ }
      if (!jdkHome) {
        return { ok: false, error: '未找到 JDK 17+（JEB 5.x 必需）。请安装 JDK 21，或在设置 tools.jebJdkHome 中填写 JDK 主目录。' };
      }
      const target = (targetFile && fs.existsSync(targetFile)) ? targetFile : '';
      // JEB 启动日志落盘，便于拉起失败时定位（JEB 自身错误也会写 errorlogs/）
      const logFile = path.join(app.getPath('userData'), 'jeb-launch.log');
      const cmdLine = '"' + jebBat + '" --script="' + mcpScript + '"'
        + (target ? ' -- "' + target + '"' : '')
        + ' > "' + logFile + '" 2>&1';
      const child = spawn('cmd.exe', ['/s', '/c', '"' + cmdLine + '"'], {
        // GUI（JEB 桌面窗口）需要可见：windowsHide:false，否则用户看不到 JEB 界面
        detached: true, stdio: 'ignore', windowsHide: false,
        windowsVerbatimArguments: true,
        // 注入 JAVA_HOME，让 jeb_wincon.bat 用 JDK 17+ 而不是 PATH 里的 Java 8
        env: Object.assign({}, process.env, { JEB_MCP_DAEMON: '1', JAVA_HOME: jdkHome })
      });
      child.on('error', err => console.error('[JEB MCP] 拉起失败:', err.message));
      child.unref();
      console.log('[JEB MCP] 正在拉起 JEB 并加载 MCP.py，JDK:', jdkHome, '目标:', target || '(无)');
      // JEB 启动 + 反编译需要时间，轮询等待端口就绪（最长 120 秒）
      const deadline = Date.now() + 120000;
      while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 4000));
        try { await jebProbe(); console.log('[JEB MCP] 已就绪'); return { ok: true }; } catch (e) { /* 继续等 */ }
      }
      let tail = '';
      try { tail = fs.readFileSync(logFile, 'utf8').split('\n').slice(-8).join('\n'); } catch (e) { /* 无日志 */ }
      return { ok: false, error: '等待 JEB MCP 就绪超时（120s）。JEB 启动日志（' + logFile + '）尾部：\n' + (tail || '(空)') };
    } catch (err) {
      return { ok: false, error: err.message };
    } finally {
      jebLaunching = null;
    }
  })();
  return jebLaunching;
}

// 调用JEB插件HTTP API（未连接时自动拉起 JEB + MCP.py 后重试一次）
async function callJebPlugin(method, params) {
  try {
    return await jebHttpPost(method, params);
  } catch (e) {
    const target = Array.isArray(params) ? params.find(p => typeof p === 'string' && fs.existsSync(p)) : null;
    const ensure = await ensureJebPluginRunning(target);
    if (!ensure.ok) {
      throw new Error(`JEB MCP 未连接且自动拉起失败: ${ensure.error}（原始错误: ${e.message}）`);
    }
    return await jebHttpPost(method, params);
  }
}

// JEB 插件 HTTP 单次请求
function jebHttpPost(method, params) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(config.mcp.jebMcp);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;
    const postData = JSON.stringify({
      jsonrpc: '2.0',
      method: method,
      params: Array.isArray(params) ? params : [params],
      id: Date.now()
    });

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname || '/mcp',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 30000
    };

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) {
            reject(new Error(result.error.message));
          } else {
            resolve(result.result);
          }
        } catch (e) {
          reject(new Error('Parse error: ' + data));
        }
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.write(postData);
    req.end();
  });
}

// ========== Burp MCP 客户端（Web/JS 逆向流量分析） ==========
// 官方 PortSwigger MCP Server 扩展是「经典 SSE 传输」：GET /sse 获得 message endpoint，
// JSON-RPC POST 到该 endpoint，结果以 event:message 从 SSE 流按请求 id 回来。
// 社区扩展也有 Streamable HTTP 实现 —— transport=auto 时先试 HTTP 再转 SSE，探测结果缓存。
let burpMcpState = {
  transport: null,      // null=未探测 | 'http' | 'sse'
  sessionId: null,      // Streamable HTTP 会话
  toolMap: null,
  baseUrl: null,
  ready: false,         // 已完成 initialize + tools/list
  sseRes: null,         // SSE 长连接响应
  endpointUrl: null,    // SSE message endpoint（含 sessionId）
  endpointWaiters: [],
  pending: new Map(),   // SSE 模式下 id -> {resolve,reject,timer}
  reqSeq: 0,
  autoLaunchTried: false // 本次会话是否已尝试自动拉起 Burp（防止反复拉）
};

function burpResetConnection() {
  try { if (burpMcpState.sseRes) burpMcpState.sseRes.destroy(); } catch (e) {}
  for (const p of burpMcpState.pending.values()) {
    clearTimeout(p.timer);
    p.reject(new Error('Burp MCP 连接已重置'));
  }
  const autoLaunchTried = burpMcpState.autoLaunchTried;
  burpMcpState = {
    transport: null, sessionId: null, toolMap: null, baseUrl: config.mcp.burp, ready: false,
    sseRes: null, endpointUrl: null, endpointWaiters: [], pending: new Map(), reqSeq: 0,
    autoLaunchTried
  };
}

// 无人值守拉起 Burp + MCP Server。
// 只做「通用」的事，不针对某题：
//   1) 清掉 %TEMP%\burp*.tmp —— 残留临时工程会让 Burp 弹 "Delete old temporary files?" 阻塞启动；
//   2) 走安装目录自带的 MCP_Burp.bat（已带 --project-file，跳过欢迎界面的项目选择对话框；
//      不能加 --use-defaults，那会跳过用户配置导致扩展列表不加载、MCP 永不启动）；
//   3) 配置缺失时回退到 java -jar + 同样参数。
// 首次仍需人工点一次 MCP 页签的 "Always Allow HTTP history"（授权会持久化，之后不再询问）。
async function launchBurpForMcp() {
  const burpPath = config.tools && config.tools.burp;
  if (!burpPath || !fs.existsSync(burpPath)) {
    return { success: false, error: `未配置 Burp 启动器（tools.burp = ${burpPath || '空'}）` };
  }
  try {
    // 1) 清残留临时工程目录
    try {
      const tmp = app.getPath('temp');
      for (const ent of fs.readdirSync(tmp, { withFileTypes: true })) {
        if (ent.isDirectory() && /^burp.*\.tmp$/i.test(ent.name)) {
          try { fs.rmSync(path.join(tmp, ent.name), { recursive: true, force: true }); } catch (e) {}
        }
      }
    } catch (e) { /* 清理失败不阻塞 */ }

    // 2) 启动
    const child = /\.(bat|cmd)$/i.test(burpPath)
      ? spawn('cmd', ['/c', 'start', '', burpPath], { shell: false, detached: true, stdio: 'ignore', windowsHide: true })
      : spawn(burpPath, [], { shell: false, detached: true, stdio: 'ignore' });
    child.on('error', (err) => console.error('Burp 启动失败:', err.message));
    child.unref();
    return { success: true, message: '已拉起 Burp（等待 MCP 端口就绪）' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ---------- Streamable HTTP 传输（社区扩展常见） ----------
async function burpHttpRequest(method, params, timeoutMs = 30000) {
  await burpHttpEnsureSession();
  const headers = {};
  if (burpMcpState.sessionId) headers['Mcp-Session-Id'] = burpMcpState.sessionId;
  const resp = await sendMCPRequest(config.mcp.burp, method, params || {}, headers, timeoutMs);
  // tools/call 的失败走 result.isError（见 mcpResultIsError）；其它方法只可能有 JSON-RPC error。
  if (resp && resp.error) {
    throw new Error(resp.error.message || JSON.stringify(resp.error));
  }
  return resp;
}

async function burpHttpEnsureSession() {
  if (burpMcpState.sessionId) return;
  const init = await sendMCPRequest(config.mcp.burp, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'ctf-tool', version: '1.3' }
  });
  burpMcpState.sessionId = (init && (init._headers || {})['mcp-session-id'])
    || (init && init.result && init.result.sessionId) || null;
  const headers = {};
  if (burpMcpState.sessionId) headers['Mcp-Session-Id'] = burpMcpState.sessionId;
  try {
    await sendMCPRequest(config.mcp.burp, 'notifications/initialized', {}, headers, 8000);
  } catch (e) { /* 非关键 */ }
}

// ---------- 经典 SSE 传输（官方扩展） ----------
function burpSseHandleEvent(eventName, data) {
  if (!data || data === '[DONE]') return;
  // endpoint 事件：data 为消息端点（可能相对路径），解析后放行等待者
  if (eventName === 'endpoint' || (!data.startsWith('{') && /message|event|\/|https?:/i.test(data))) {
    try {
      const u = new URL(data, config.mcp.burp);
      if (!burpMcpState.endpointUrl) {
        burpMcpState.endpointUrl = u.toString();
        const waiters = burpMcpState.endpointWaiters;
        burpMcpState.endpointWaiters = [];
        waiters.forEach(w => w.resolve(burpMcpState.endpointUrl));
      }
    } catch (e) { /* 非 endpoint 帧 */ }
    if (eventName === 'endpoint') return;
  }
  // message 事件：JSON-RPC 响应，按 id 关联挂起请求
  try {
    const j = JSON.parse(data);
    if (j && j.id !== undefined && burpMcpState.pending.has(j.id)) {
      const p = burpMcpState.pending.get(j.id);
      burpMcpState.pending.delete(j.id);
      clearTimeout(p.timer);
      if (j.error) p.reject(new Error(j.error.message || JSON.stringify(j.error)));
      else p.resolve(j);
    }
  } catch (e) { /* 非 JSON 帧（注释/心跳） */ }
}

// 单次 SSE 连接尝试：GET sseUrl，等待 endpoint 事件
function burpSseConnectAttempt(sseUrl) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(sseUrl);
    const client = urlObj.protocol === 'https:' ? https : http;
    const waiter = { resolve, reject };
    burpMcpState.endpointWaiters.push(waiter);
    const fail = (msg) => {
      const i = burpMcpState.endpointWaiters.indexOf(waiter);
      if (i >= 0) burpMcpState.endpointWaiters.splice(i, 1);
      // 若已挂上流但没等到 endpoint，清理这条流
      if (burpMcpState.sseRes && !burpMcpState.endpointUrl) {
        try { burpMcpState.sseRes.destroy(); } catch (e) {}
        burpMcpState.sseRes = null;
      }
      reject(new Error(msg));
    };
    const attemptTimer = setTimeout(() => fail('Burp SSE 未在 12 秒内返回 endpoint（' + sseUrl + '，确认已加载 MCP Server 扩展）'), 12000);

    const req = client.get(sseUrl, { headers: { 'Accept': 'text/event-stream' }, timeout: 12000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        clearTimeout(attemptTimer);
        // 摘除 waiter 再拒绝，避免死 waiter 泄漏后被后续事件 resolve
        const i = burpMcpState.endpointWaiters.indexOf(waiter);
        if (i >= 0) burpMcpState.endpointWaiters.splice(i, 1);
        return reject(new Error('Burp SSE HTTP ' + res.statusCode + '（' + sseUrl + '）'));
      }
      burpMcpState.sseRes = res;
      let buf = '', eventName = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        buf += chunk;
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, idx).replace(/\r$/, '');
          buf = buf.slice(idx + 1);
          if (line.startsWith('event:')) eventName = line.slice(6).trim();
          else if (line.startsWith('data:')) {
            burpSseHandleEvent(eventName, line.slice(5).trim());
            eventName = '';
          } else if (line === '') eventName = '';
        }
        // endpoint 已就绪 → 本次尝试成功
        if (burpMcpState.endpointUrl) {
          clearTimeout(attemptTimer);
          resolve();
        }
      });
      res.on('error', () => {
        burpMcpState.sseRes = null;
        burpMcpState.endpointUrl = null;
      });
      res.on('end', () => {
        burpMcpState.sseRes = null;
        burpMcpState.endpointUrl = null;
      });
    });
    req.on('error', (e) => {
      clearTimeout(attemptTimer);
      const i = burpMcpState.endpointWaiters.indexOf(waiter);
      if (i >= 0) burpMcpState.endpointWaiters.splice(i, 1);
      reject(new Error('Burp SSE 连接失败: ' + e.message + '（' + sseUrl + '）'));
    });
    req.on('timeout', () => { req.destroy(); });
  });
}

// SSE 端点路径各实现不一：官方扩展在根路径 /，多数实现在 /sse。逐个候选尝试。
function burpSseConnect() {
  if (burpMcpState.sseRes && burpMcpState.endpointUrl) return Promise.resolve();
  let base = config.mcp.burp;
  try {
    const u = new URL(base);
    if (!u.pathname || u.pathname === '/') base = base.replace(/\/$/, '');
  } catch (e) {
    return Promise.reject(new Error('Burp MCP URL 无效: ' + config.mcp.burp));
  }
  const candidates = [...new Set([base + '/sse', base + '/'])];
  let chain = Promise.reject(new Error('start'));
  for (const c of candidates) {
    chain = chain.catch(() => burpSseConnectAttempt(c));
  }
  return chain;
}

function burpSseRequest(method, params, timeoutMs = 60000) {
  const isNotification = method.startsWith('notifications/');
  return burpSseConnect().then(() => new Promise((resolve, reject) => {
    if (!burpMcpState.endpointUrl) return reject(new Error('Burp SSE endpoint 未就绪'));
    const id = isNotification ? undefined : Date.now() * 1000 + ((burpMcpState.reqSeq = (burpMcpState.reqSeq + 1) % 1000));
    const body = JSON.stringify(isNotification ? { jsonrpc: '2.0', method, params: params || {} } : { jsonrpc: '2.0', id, method, params: params || {} });
    const u = new URL(burpMcpState.endpointUrl);
    const client = u.protocol === 'https:' ? https : http;

    // 通知无需等待响应
    if (isNotification) {
      const req = client.request({
        hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: 10000
      }, (res) => { res.resume(); res.on('end', resolve); });
      req.on('error', (e) => reject(new Error('Burp SSE 通知发送失败: ' + e.message)));
      req.write(body);
      req.end();
      return;
    }

    const timer = setTimeout(() => {
      burpMcpState.pending.delete(id);
      reject(new Error('Burp SSE 请求超时（' + Math.round(timeoutMs / 1000) + 's）: ' + method));
    }, timeoutMs);
    burpMcpState.pending.set(id, { resolve, reject, timer });

    const req = client.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: timeoutMs
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        // 部分实现直接在 POST 响应体里回 JSON-RPC 结果；规范的 SSE 服务器回 202 空体（结果走流）
        try {
          const j = JSON.parse(data);
          if (j && j.id === id && burpMcpState.pending.has(id)) {
            const p = burpMcpState.pending.get(id);
            burpMcpState.pending.delete(id);
            clearTimeout(p.timer);
            if (j.error) reject(new Error(j.error.message || JSON.stringify(j.error)));
            else resolve(j);
          }
        } catch (e) { /* 空体/202 属正常 */ }
      });
    });
    req.on('error', (e) => {
      if (burpMcpState.pending.has(id)) {
        burpMcpState.pending.delete(id);
        clearTimeout(timer);
        reject(e);
      }
    });
    req.write(body);
    req.end();
  }));
}

// ---------- 统一入口：transport 探测 + 会话 + tools/list ----------
async function burpEnsureReady() {
  if (burpMcpState.ready && burpMcpState.baseUrl === config.mcp.burp) return;
  // URL 被用户修改 → 传输探测结果一并作废
  if (burpMcpState.baseUrl !== config.mcp.burp) {
    burpResetConnection();
  }

  // 端口没在监听 = Burp 压根没起来。这里自动拉起一次（每次会话最多一次，避免反复拉）。
  // 为什么必须自动拉：MCP 9876 只有 Burp 进程活着且 MCP 扩展加载后才存在，
  // 靠“用户先手动开 Burp”会让所有 web 题静默退化成无流量可读。
  if (!burpMcpState.autoLaunchTried) {
    const listening = await new Promise((resolve) => {
      try {
        const u = new URL(config.mcp.burp);
        const socket = require('net').connect({ host: u.hostname, port: Number(u.port) || 80 }, () => {
          socket.destroy(); resolve(true);
        });
        socket.setTimeout(1200, () => { socket.destroy(); resolve(false); });
        socket.on('error', () => resolve(false));
      } catch (e) { resolve(false); }
    });
    if (!listening) {
      burpMcpState.autoLaunchTried = true;
      const launched = await launchBurpForMcp();
      if (launched.success) {
        // 启动到端口就绪通常 20-40s（Burp 本体较重）；按 1s 轮询，最多等 90s
        const deadline = Date.now() + 90000;
        while (Date.now() < deadline) {
          const ok = await new Promise((resolve) => {
            try {
              const u = new URL(config.mcp.burp);
              const socket = require('net').connect({ host: u.hostname, port: Number(u.port) || 80 }, () => {
                socket.destroy(); resolve(true);
              });
              socket.setTimeout(1200, () => { socket.destroy(); resolve(false); });
              socket.on('error', () => resolve(false));
            } catch (e) { resolve(false); }
          });
          if (ok) break;
          await sleep(1000);
        }
      }
    }
  }

  const doToolsList = async () => {
    const resp = burpMcpState.transport === 'sse'
      ? await burpSseRequest('tools/list', {}, 20000)
      : await burpHttpRequest('tools/list', {}, 20000);
    const tools = (resp && resp.result && resp.result.tools) || [];
    const realNames = tools.map(t => t && (t.name || t.title)).filter(Boolean);
    // _defs 保存每个工具的完整定义（含 inputSchema），调用时用于参数适配
    const defs = {};
    for (const t of tools) {
      if (t && t.name) defs[t.name] = t;
    }
    const candidates = {
      // 官方 PortSwigger MCP 扩展实际工具名是 get_proxy_http_history（实测 27 个工具）；
      // 其余是社区实现/旧版本的命名，保留以兼容。
      history: ['get_proxy_http_history', 'get_http_history', 'http_history', 'get_proxy_history', 'proxy_history', 'list_history', 'search_history', 'burp_http_history'],
      historyRegex: ['get_proxy_http_history_regex', 'search_http_history', 'search_history_regex'],
      message: ['get_http_message', 'http_message', 'get_request_response', 'get_message', 'get_request', 'burp_get_message']
    };
    const map = { _all: realNames, _defs: defs };
    for (const logical of Object.keys(candidates)) {
      map[logical] = candidates[logical].find(n => realNames.includes(n)) || null;
    }
    burpMcpState.toolMap = map;
    burpMcpState.ready = true;
    return map;
  };

  const base = config.mcp.burp;
  burpMcpState.baseUrl = base;

  // transport=auto：先 Streamable HTTP，失败转经典 SSE（官方扩展）
  // 注意：探测用 burpHttpEnsureSession（内部完成一次 initialize+initialized），
  // 不能再发第二次 initialize —— 严格服务器会拒绝已初始化会话上的 initialize
  if (!burpMcpState.transport || burpMcpState.transport === 'auto') {
    try {
      await burpHttpEnsureSession();
      burpMcpState.transport = 'http';
    } catch (httpErr) {
      try {
        await burpSseConnect();
        await burpSseRequest('initialize', {
          protocolVersion: '2024-11-05', capabilities: {},
          clientInfo: { name: 'ctf-tool', version: '1.3' }
        }, 15000);
        try { await burpSseRequest('notifications/initialized', {}, 8000); } catch (e) { /* 非关键 */ }
        burpMcpState.transport = 'sse';
      } catch (sseErr) {
        burpMcpState.transport = null;
        throw new Error(`Burp MCP 连接失败。HTTP: ${httpErr.message} ｜ SSE: ${sseErr.message}`);
      }
    }
  }

  await doToolsList();
}

// 参数适配：不同 Burp MCP 插件对参数名约定不一（keyword/limit/query...）。
// 以插件 tools/list 返回的 inputSchema 为准：直接命中原名 → 同义词改名 → 全不匹配则透传原参数
//（让服务器给出精确报错，不丢信息）。
const BURP_ARG_SYNONYMS = {
  filter: ['filter', 'keyword', 'search', 'query', 'regex', 'pattern', 'q', 'term'],
  max: ['max', 'limit', 'count', 'max_results', 'maxResults', 'size', 'top'],
  id: ['id', 'index', 'idx', 'message_id', 'messageId', 'entry', 'ref', 'tool_call_id'],
  url: ['url', 'host', 'target', 'site'],
  tool: ['tool', 'name', 'tool_name', 'toolName']
};

function adaptBurpArgs(toolDef, args) {
  const schema = toolDef && toolDef.inputSchema;
  if (!schema || !schema.properties || typeof args !== 'object' || args === null) {
    return args || {};
  }
  const props = schema.properties;
  const out = {};
  const filled = new Set();
  // 1) 直接命中 schema 声明的参数名
  for (const k of Object.keys(args)) {
    if (props[k] !== undefined) {
      out[k] = args[k];
      filled.add(k);
    }
  }
  // 2) 同义词改名（仅当目标名在 schema 中且尚未填充）
  for (const k of Object.keys(args)) {
    if (filled.has(k)) continue;
    const syn = BURP_ARG_SYNONYMS[k];
    if (!syn) continue;
    const target = syn.find(n => n !== k && props[n] !== undefined && out[n] === undefined);
    if (target) {
      out[target] = args[k];
      filled.add(target);
    }
  }
  // 3) 一个都没匹配上：透传原参数，让服务器报具体错误（比静默丢参好排查）
  if (Object.keys(out).length === 0 && Object.keys(args).length > 0) {
    return args;
  }
  // 4) 补齐 schema 的必填字段。插件把 count/offset 都标成 required，而调用方习惯只给
  //    max（被改名为 count）→ offset 缺失时服务器直接返回
  //    "Field 'offset' is required ... GetProxyHttpHistory"，整条 history 链路失效。
  //    这里按 schema 类型给"中性初值"（数字 0 / 字符串空 / 数组空），只补缺不覆盖。
  const required = Array.isArray(schema.required) ? schema.required : [];
  for (const key of required) {
    if (out[key] !== undefined) continue;
    const spec = props[key] || {};
    const type = Array.isArray(spec.type) ? spec.type[0] : spec.type;
    if (type === 'integer' || type === 'number') out[key] = 0;
    else if (type === 'boolean') out[key] = false;
    else if (type === 'array') out[key] = [];
    else if (type === 'object') out[key] = {};
    else out[key] = '';
  }
  return out;
}

// MCP 的失败既可能走 JSON-RPC error，也可能走 result.isError + content[].text
//（ida-pro-mcp / Burp MCP 都是后者）。旧实现只认前者，于是
// "Tool 'dbg_start' requires extension 'dbg'" 这类失败被当成成功文本交给 AI。
function mcpResultIsError(resp) {
  if (!resp) return false;
  if (resp.error) return true;
  const r = resp.result;
  if (!r) return false;
  if (r.isError === true) return true;
  if (Array.isArray(r.content) && r.content.some(c => c && c.isError === true)) return true;
  return false;
}
function mcpErrorText(resp) {
  if (!resp) return '';
  if (resp.error) return resp.error.message || JSON.stringify(resp.error);
  const r = resp.result || {};
  const parts = [];
  if (Array.isArray(r.content)) {
    for (const c of r.content) {
      if (c && typeof c.text === 'string' && c.text) parts.push(c.text);
    }
  }
  return parts.join('\n').slice(0, 800) || 'MCP 返回 isError=true（无错误文本）';
}

async function burpMcpCallTool(logicalName, args) {
  const knownLogical = ['history', 'historyRegex', 'message'];
  // 官方扩展没有独立取报文的工具，但 get_proxy_http_history 本身就成对返回 request+response。
  // 因此 message 逻辑名在缺工具时降级为「按索引从历史里取那一条」，而不是直接把 AI 卡死。
  if (logicalName === 'message' && !(burpMcpState.toolMap && burpMcpState.toolMap.message)) {
    await burpEnsureReady();
    if (!burpMcpState.toolMap || !burpMcpState.toolMap.message) {
      const idx = Math.max(0, Number(args && (args.index != null ? args.index : args.id)) || 0);
      const count = Math.max(1, idx + 1);
      const hist = await burpMcpCallTool('history', { count, offset: 0 });
      const text = String(hist || '');
      let picked = '';
      if (idx === 0) {
        picked = text;
      } else {
        // 历史条目是逐行 JSON；按行取第 idx 条
        const lines = text.split('\n').filter(l => l.trim());
        picked = lines[idx] || '';
      }
      if (!picked) {
        throw new Error(`历史中不存在第 ${idx} 条报文（按 get_proxy_http_history 索引）`);
      }
      return picked;
    }
  }
  const doCall = async () => {
    await burpEnsureReady();
    const map = burpMcpState.toolMap || {};
    const realName = map[logicalName] || logicalName;
    // 逻辑名映射失败时明确告知插件实际提供的工具，而不是丢给服务器报 unknown tool
    if (knownLogical.includes(logicalName) && !map[logicalName]) {
      throw new Error(`插件未提供 ${logicalName} 类工具。实际可用: ${(map._all || []).join(', ') || '（无）'}`);
    }
    const toolDef = map._defs && map._defs[realName];
    const resp = burpMcpState.transport === 'sse'
      ? await burpSseRequest('tools/call', { name: realName, arguments: adaptBurpArgs(toolDef, args) }, 60000)
      : await burpHttpRequest('tools/call', { name: realName, arguments: adaptBurpArgs(toolDef, args) }, 60000);
    if (mcpResultIsError(resp)) {
      throw new Error(mcpErrorText(resp));
    }
    return unwrapMcpContent(resp);
  };

  try {
    return await doCall();
  } catch (err) {
    // 仅对连接/会话类错误重置重试一次；tools/call 超时不重试（服务端可能已执行，避免非幂等重复）
    if (/400|404|session|ECONN|socket/i.test(err.message)) {
      burpResetConnection();
      try {
        return await doCall();
      } catch (err2) {
        // 重试仍失败且从未成功过，给出明确指引
        throw new Error(err2.message + '（请确认 Burp 已启动且加载了 MCP Server 扩展，端口见设置）');
      }
    }
    throw err;
  }
}

// ========== CTF²（DASCTF Agent Arena）开放平台 MCP 客户端 ==========
// 与 IDA/JEB/Burp 不同：这是公网 HTTPS 的 Streamable HTTP MCP 端点，用 Bearer Token 鉴权。
// 工具名固定（ctf2_list_practice_challenges / ctf2_get_practice_challenge / ctf2_get_attachment_url
// / ctf2_submit_flag / ctf2_agent_whoami 等），无需名字映射 —— 直接透传。
// 复用 sendMCPRequest 的 extraHeaders 通道放 Authorization（该通道本就为此预留）。
let ctf2McpState = { sessionId: null, baseUrl: null, token: null };

function ctf2Token() {
  return String((config.mcp && config.mcp.ctf2Token) || '').trim();
}
function ctf2BaseUrl() {
  return String((config.mcp && config.mcp.ctf2) || '').trim();
}
// 地址或 Token 变化时丢弃旧会话（换号后旧 session 无效）
function ctf2EnsureStateFresh() {
  const url = ctf2BaseUrl();
  const tok = ctf2Token();
  if (ctf2McpState.baseUrl !== url || ctf2McpState.token !== tok) {
    ctf2McpState = { sessionId: null, baseUrl: url, token: tok };
  }
}
function ctf2ResetConnection() {
  ctf2McpState = { sessionId: null, baseUrl: ctf2BaseUrl(), token: ctf2Token() };
}

// 构造请求头：有 Token 就带 Bearer（无 Token 时也让请求发出，由服务端返回 401 以便给出明确报错）
function ctf2Headers() {
  const h = {};
  const tok = ctf2Token();
  if (tok) h['Authorization'] = 'Bearer ' + tok;
  if (ctf2McpState.sessionId) h['Mcp-Session-Id'] = ctf2McpState.sessionId;
  return h;
}

async function ctf2McpEnsureSession() {
  ctf2EnsureStateFresh();
  if (!ctf2BaseUrl()) throw new Error('未配置 CTF² MCP 地址（设置页 → CTF²）');
  if (!ctf2Token()) throw new Error('未配置 CTF² Token（在平台「凭证」页创建后填入设置页 → CTF² Token）');
  if (ctf2McpState.sessionId) return ctf2McpState.sessionId;
  const init = await sendMCPRequest(ctf2BaseUrl(), 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'ctf-re-tool', version: '1.4' }
  }, ctf2Headers(), 30000);
  ctf2McpState.sessionId = (init && (init._headers || {})['mcp-session-id'])
    || (init && init.result && init.result.sessionId) || null;
  try {
    await sendMCPRequest(ctf2BaseUrl(), 'notifications/initialized', {}, ctf2Headers(), 8000);
  } catch (e) { /* 非关键 */ }
  return ctf2McpState.sessionId;
}

// 调用平台 MCP 工具（工具名直通），返回解包后的数据
async function ctf2McpCallTool(toolName, args) {
  const doCall = async () => {
    await ctf2McpEnsureSession();
    const resp = await sendMCPRequest(ctf2BaseUrl(), 'tools/call', {
      name: toolName, arguments: args || {}
    }, ctf2Headers(), 60000);
    // 平台提交的结果语义由 ctf2SubmitAccepted 判定（accepted:false 是**正常返回**，
    // 不是传输失败），所以这里只认 JSON-RPC error，不把 isError 一律当异常——
    // 否则"提交被拒"会被吞成调用失败，丢失 accepted/earned_points 等可回看字段。
    if (resp && resp.error) throw new Error(resp.error.message || JSON.stringify(resp.error));
    return unwrapMcpContent(resp);
  };
  try {
    return await doCall();
  } catch (err) {
    // 平台限流：凭据页明确要求"Respect HTTP 429 and retry_after_ms"。
    // 429 时按平台给的 retry_after_ms 等待后重试（最多 3 次），而不是立即失败。
    const msg = String(err && err.message || '');
    if (/429|rate.?limit|too many requests/i.test(msg)) {
      const m = msg.match(/retry_after_ms["':\s]+(\d+)/i) || msg.match(/retry.?after["':\s]+(\d+)/i);
      const waitMs = m ? Math.min(Number(m[1]) || 2000, 60000) : 2000;
      for (let i = 0; i < 3; i++) {
        await new Promise(r => setTimeout(r, waitMs * (i + 1)));
        try { return await doCall(); } catch (e2) { /* 继续退避 */ }
      }
      throw err;
    }
    // 会话失效/网络瞬断 → 重置重试一次；tools/call 超时不重试（可能已执行，非幂等）
    if (/400|401|403|404|session|ECONN|socket|ETIMEDOUT|EAI_AGAIN/i.test(msg) && !/timeout/i.test(msg)) {
      ctf2ResetConnection();
      try { return await doCall(); } catch (e2) { throw e2; }
    }
    throw err;
  }
}

// 探活：whoami（能返回即说明地址 + Token 均可用）
async function ctf2Probe() {
  const me = await ctf2McpCallTool('ctf2_agent_whoami', {});
  return { ok: true, me };
}

// 列出平台可用工具（供设置页/诊断显示）
async function ctf2ListTools() {
  await ctf2McpEnsureSession();
  const resp = await sendMCPRequest(ctf2BaseUrl(), 'tools/list', {}, ctf2Headers(), 30000);
  const tools = (resp && resp.result && resp.result.tools) || [];
  return tools.map(t => ({ name: t.name, description: t.description || '' }));
}

// 主进程下载附件到本地（渲染层无 HTTP 能力；下载由主进程发起，不受 write-file 白名单限制）
// 返回 { success, path, bytes, filename }
async function ctf2DownloadAttachment(url, destDir) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(String(url || '')); } catch (e) { return resolve({ success: false, error: '附件 URL 非法: ' + url }); }
    if (!/^https?:$/.test(u.protocol)) return resolve({ success: false, error: '仅支持 http/https 下载' });

    const MAX = 300 * 1024 * 1024; // 300MB 上限，防御异常大文件
    const client = u.protocol === 'https:' ? https : http;
    const req = client.get(u, { timeout: 120000, headers: { 'User-Agent': 'ctf-re-tool' } }, (res) => {
      // 跟随重定向（最多 5 跳）
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && (req._hops || 0) < 5) {
        res.resume();
        req._hops = (req._hops || 0) + 1;
        const next = new URL(res.headers.location, u).toString();
        return resolve(ctf2DownloadAttachment(next, destDir));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ success: false, error: '下载失败 HTTP ' + res.statusCode });
      }
      // 文件名：优先 Content-Disposition，其次 URL 路径末段
      let filename = '';
      const cd = res.headers['content-disposition'] || '';
      const m1 = cd.match(/filename\*?=(?:UTF-8'')?["']?([^;"']+)/i);
      if (m1) filename = decodeURIComponent(m1[1]);
      if (!filename) {
        const seg = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || '');
        filename = seg || ('attachment_' + Date.now());
      }
      filename = filename.replace(/[\\/:*?"<>|]/g, '_').slice(0, 120) || ('attachment_' + Date.now());
      const destDirSafe = destDir || app.getPath('temp');
      // 目录碰撞防御：下载目录下若已存在同名"目录"（如历史拉题建的 parallelism/），
      // writeFileSync 会 EISDIR 整轮中止 → 改名重试到不撞目录为止（同名普通文件则覆盖，属重下同一附件）。
      let destPath = path.join(destDirSafe, filename);
      if (fs.existsSync(destPath)) {
        let st = null;
        try { st = fs.statSync(destPath); } catch (e) {}
        if (st && st.isDirectory()) {
          const ext = path.extname(filename);
          const base = path.basename(filename, ext);
          let i = 1;
          do {
            destPath = path.join(destDirSafe, `${base}_${i++}${ext}`);
            st = null;
            try { st = fs.statSync(destPath); } catch (e) {}
          } while (st && st.isDirectory() && i < 100);
          filename = path.basename(destPath);
        }
      }

      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > MAX) { req.destroy(); }
        else chunks.push(c);
      });
      res.on('end', () => {
        if (total > MAX) return resolve({ success: false, error: '附件超过 300MB 上限，已中止' });
        try {
          fs.mkdirSync(destDirSafe, { recursive: true });
          fs.writeFileSync(destPath, Buffer.concat(chunks));
          resolve({ success: true, path: destPath, bytes: total, filename });
        } catch (e) {
          resolve({ success: false, error: '写入失败: ' + e.message });
        }
      });
      res.on('error', (e) => resolve({ success: false, error: '下载中断: ' + e.message }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ success: false, error: '下载超时（120s）' }); });
    req.on('error', (e) => resolve({ success: false, error: '下载请求失败: ' + e.message }));
  });
}

// IPC: CTF² MCP 工具直通调用（仅前端流水线使用；不注册进 AI 工具定义）
// CTF_NO_SUBMIT=1 时为 dry-run：只允许拉题/下载等只读操作，禁止提交 flag 与平台笔记。
ipcMain.handle('ctf2-mcp-call', async (event, toolName, args) => {
  try {
    if (process.env.CTF_NO_SUBMIT === '1' && (toolName === 'ctf2_submit_flag' || toolName === 'ctf2_agent_log_note')) {
      return { success: false, error: 'blocked: CTF_NO_SUBMIT=1 (' + toolName + ')' };
    }
    const result = await ctf2McpCallTool(toolName, args);
    return { success: true, result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});
// IPC: 探活（whoami）
ipcMain.handle('ctf2-probe', async () => {
  try { return { success: true, ...(await ctf2Probe()) }; }
  catch (err) { return { success: false, error: err.message }; }
});
// IPC: 列出平台工具
ipcMain.handle('ctf2-tools', async () => {
  try { return { success: true, tools: await ctf2ListTools() }; }
  catch (err) { return { success: false, error: err.message }; }
});
// IPC: 下载附件到本地目录
ipcMain.handle('ctf2-download', async (event, url, destDir) => {
  try { return await ctf2DownloadAttachment(url, destDir); }
  catch (err) { return { success: false, error: err.message }; }
});

// IPC: 按精确进程名清理本题拉起的外部分析工具（批量解题的"每题收尾"步骤）。
// 白名单逐个精确 taskkill（绝不全杀 node/electron/系统进程）；不存在的进程静默忽略。
ipcMain.handle('ctf2-cleanup-tools', async () => {
  const { execSync } = require('child_process');
  const targets = [
    'ida.exe', 'ida64.exe',           // IDA
    'jeb-wincon.exe', 'jeb.exe',      // JEB（jeb_wincon.bat 的实际进程名）
    'java.exe'                        // jadx/unluac/apktool 等 Java 系（Burp/JEB 都是 java 进程）
  ];
  const killed = [];
  for (const name of targets) {
    try { execSync('taskkill /F /IM ' + name, { stdio: 'ignore', timeout: 15000 }); killed.push(name); } catch (e) { /* 进程不存在 → 忽略 */ }
  }
  // 收工一并清掉 Burp 的临时工程目录，避免下一题启动时弹
  // "Delete old temporary files?" 阻塞 MCP 扩展加载（实测会卡死在欢迎界面）。
  try {
    const tmp = app.getPath('temp');
    for (const ent of fs.readdirSync(tmp, { withFileTypes: true })) {
      if (ent.isDirectory() && /^burp.*\.tmp$/i.test(ent.name)) {
        const p = path.join(tmp, ent.name);
        try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {}
      }
    }
  } catch (e) { /* 清理失败不阻塞 */ }
  return { success: true, killed };
});

// IPC: 解压平台 zip 手包（渲染层无 Node 能力，解压必须走主进程）。
// 返回 { success, dir, files: [绝对路径...] }，files 按"可分析优先级"排序（ELF/PE/pyc/无扩展名在前），
// files[0] 即推荐主文件。
ipcMain.handle('ctf2-unzip', async (event, zipPath) => {
  const { execSync } = require('child_process');
  try {
    if (!fs.existsSync(zipPath)) return { success: false, error: '文件不存在: ' + zipPath };
    // RAR/7z：BUUCTF 大量附件是 .rar（实测 reverse2/reverse3/相册 都只跑 file/binwalk 就结束，
    // 因为原逻辑只认 ZIP，整道题等于没解压）。优先用 7-Zip / WinRAR / unrar 解。
    if (/\.(rar|7z)$/i.test(zipPath)) {
      const dirR = String(zipPath).replace(/\.[^.]+$/, '') + '_x';
      try { fs.rmSync(dirR, { recursive: true, force: true }); } catch (e) { }
      const tools = [
        'C:\\Program Files\\7-Zip\\7z.exe',
        'C:\\Program Files (x86)\\7-Zip\\7z.exe',
        'C:\\Program Files\\WinRAR\\UnRAR.exe',
        'C:\\Program Files\\WinRAR\\Rar.exe',
        '7z', '7za', 'unrar',
      ];
      let ok = false, lastErr = '';
      for (const t of tools) {
        try {
          if (t.includes('\\') && !fs.existsSync(t)) continue;
          const isRar = /rar/i.test(t);
          const cmd = (t === 'unrar' || isRar)
            ? `"${t}" x -o+ -y "${zipPath}" "${dirR}\\"`
            : `"${t}" x -y -o"${dirR}" "${zipPath}"`;
          execSync(cmd, { timeout: 120000, stdio: 'ignore' });
          ok = true;
          break;
        } catch (e) { lastErr = e.message; }
      }
      if (!ok) return { success: false, error: '未找到可用的解压工具（7-Zip/WinRAR/unrar）: ' + lastErr };
      const filesR = [];
      (function walk(d) {
        let ents = [];
        try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
        for (const e of ents) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) { if (!/^__MACOSX$/i.test(e.name)) walk(p); }
          else if (!/[\\/]\._/.test(p) && !/\.DS_Store$/i.test(p)) filesR.push(p);
        }
      })(dirR);
      return { success: true, dir: dirR, files: filesR };
    }
    // ZIP 系列容器一律放行：.zip / .apk / .jar / .xlsx / .docx / .pptx / .aar / .ipa
    // （ExceLLM 实测：xlsx 附件被 "仅支持 .zip" 拒收 → 整轮 0 秒结束。OOXML 本质就是 zip）
    if (!/\.(zip|apk|jar|xlsx|xlsm|docx|pptx|aar|ipa|epub)$/i.test(zipPath)) {
      // 无扩展名/其他扩展名时看魔数：PK\x03\x04 也放行
      let head = '';
      try { head = fs.readFileSync(zipPath).slice(0, 4).toString('hex'); } catch (e) {}
      if (head !== '504b0304') return { success: false, error: '非 ZIP 容器（扩展名与魔数均不符）: ' + zipPath };
    }
    const dir = String(zipPath).replace(/\.[^.]+$/, '') + '_x';
    // 幂等解压：先删旧目录。上一轮 IDA 会在解压目录里生成 .id0/.id2/.til/.nam 数据库，
    // 残留会混进伴生文件清单污染 AI 上下文（not-baby-parallelism 第二轮实测暴露）。
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
    // Expand-Archive 对 .xlsx 等非 .zip 扩展名会拒绝 → 先复制成 .zip 再解压（PowerShell 5.1 限制）
    const tmpZip = /\.(zip)$/i.test(zipPath) ? zipPath : path.join(app.getPath('temp'), 'ctf2_unzip_' + Date.now().toString(36) + '.zip');
    if (tmpZip !== zipPath) { try { fs.copyFileSync(zipPath, tmpZip); } catch (e) { return { success: false, error: '复制为 .zip 失败: ' + e.message }; } }
    try {
      // ⚠️ 路径里的 [ ] 会被 PowerShell 当通配符（题目名常含 [GUET-CTF2019] 这类方括号）：
      // 实测 Expand-Archive -Path 'E:\...[GUET-CTF2019]re\attachment.zip' 直接失败，
      // 整道题在解压步骤就结束。用 -LiteralPath 并转义单引号。
      const psq = (s) => "'" + String(s).replace(/'/g, "''") + "'";
      execSync('powershell -NoProfile -Command "Expand-Archive -LiteralPath ' + psq(tmpZip) + ' -DestinationPath ' + psq(dir) + ' -Force"',
        { timeout: 90000, stdio: 'ignore' });
    } finally {
      if (tmpZip !== zipPath) { try { fs.rmSync(tmpZip, { force: true }); } catch (e) {} }
    }
    // xlsx/docx 解压出的是 XML 结构（xl/worksheets、word/document.xml），对 AI 直接读意义有限，
    // 但解压目录本身就是证据（sharedStrings.xml 常藏字符串、xl/workbook.xml 有 sheet 清单），
    // 原样列出即可；真正"能跑"的优先级打分保持不变。
    const JUNK = /\.(til|id2|nam|id0|id1|i64|idb|bak)$/i;
    // macOS 打包噪声：__MACOSX/ 目录与 ._ 前缀的 AppleDouble 文件是资源分支，
    // 实测（equation 题）它们被当成"主文件"送进分析，白烧一整轮。
    const isMacJunk = (p) => /[\\/]__MACOSX[\\/]/i.test(p) || /[\\/]\._[^\\/]*$/.test(p) || /[\\/]\.DS_Store$/i.test(p);
    const files = [];
    (function walk(d) {
      let ents = [];
      try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
      for (const e of ents) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) {
          if (/^__MACOSX$/i.test(e.name)) continue;   // 整个目录跳过
          walk(p);
        } else if (!JUNK.test(p) && !isMacJunk(p)) files.push(p);
      }
    })(dir);
    // 可分析优先级打分：ELF > PE > pyc > Mach-O/Class > 无扩展名 > .bin > 其他
    // OOXML 感知（ExceLLM 类 Excel 逆向题）：workbook.xml / worksheets / sharedStrings 是逻辑所在，
    // docProps（core/app/custom.xml）是元数据噪声——241 字节的 custom.xml 曾被当成"主文件"
    // 送进 Kali 固件流程白烧 60s。字体/rels/[Content_Types] 同属噪声。
    // sheet 之间再按"公式元素数 + 文件大小"分主次：展示壳 sheet1 常只有 IF(VERIFY!Z1=1,...)，
    // 真校验器（大量 SUMPRODUCT/权重）在公式最多的 sheet（ExceLLM 实测 sheet4=VERIFY 164KB）。
    const ooxmlSheetFormulaCount = (p) => {
      try {
        const t = fs.readFileSync(p, 'utf8');
        return (t.match(/<f[ >]/g) || []).length;
      } catch (e) { return 0; }
    };
    const ooxmlScore = (p) => {
      const n = p.replace(/\\/g, '/').toLowerCase();
      if (/xl\/worksheets\/sheet\d+\.xml$/.test(n)) {
        const fc = ooxmlSheetFormulaCount(p);
        // 公式数是 sheet 之间的主导因子（独立高位项，最多 900000，远大于 1MB 级的大小扣分）：
        // ExceLLM 实测 sheet1=1 公式展示壳 / sheet4=244 公式校验器。
        return 90 + Math.min(fc, 900) * 0.1 + (fc > 0 ? 6 : 0);
      }
      if (/xl\/(workbook|sharedstrings|calcchain)\.xml$/.test(n)) return 92; // sheet 结构 + 字符串 + 计算链
      if (/xl\/.*\.xml$/.test(n)) return 80;                             // 其它 xl/ 下 XML（styles 等次要）
      if (/docprops\//.test(n)) return 1;                                // 元数据噪声，最后才考虑
      if (/\[content_types\]\.xml$/.test(n) || /\.rels$/.test(n)) return 2;
      return null; // 非 OOXML 特征 → 走通用打分
    };
    const score = (p) => {
      const oo = ooxmlScore(p);
      if (oo !== null) return oo * 100000 - Math.min(fs.statSync(p).size, 99999);
      let b = Buffer.alloc(0);
      try { b = fs.readFileSync(p).slice(0, 8); } catch (e) {}
      let s = 10;
      if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) s = 100;
      else if (b[0] === 0x4d && b[1] === 0x5a) s = 95;
      else if (/\.pyc$/i.test(p)) s = 90;
      else if (b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbe) s = 85;
      else if (!/\.[a-z0-9]{1,4}$/i.test(p)) s = 60;
      else if (/\.bin$/i.test(p)) s = 40;
      // 同分时小文件优先（主程序通常比数据小）
      return s * 100000 - Math.min(fs.statSync(p).size, 99999);
    };
    files.sort((a, b) => score(b) - score(a));
    return { success: true, dir, files };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// IPC: Burp MCP 调用
ipcMain.handle('burp-mcp-call', async (event, toolName, args) => {
  try {
    const result = await burpMcpCallTool(toolName, args);
    return { success: true, result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// IPC: 探测 Burp MCP 端口是否监听（TCP 快探，1.5s）
ipcMain.handle('burp-probe', async () => {
  const net = require('net');
  return new Promise((resolve) => {
    try {
      const u = new URL(config.mcp.burp);
      const socket = net.connect({ host: u.hostname, port: Number(u.port) || 80 }, () => {
        socket.destroy();
        resolve({ listening: true });
      });
      socket.setTimeout(1500, () => {
        socket.destroy();
        resolve({ listening: false });
      });
      socket.on('error', () => resolve({ listening: false }));
    } catch (e) {
      resolve({ listening: false, error: e.message });
    }
  });
});

// IPC: 通用 TCP 端口探测（1.5s 快探）。渲染层用它轮询 IDA MCP 端口就绪，
// 替代旧的"固定 3 次握手重试"——IDA 冷启动（无缓存 IDB）常超过旧重试窗口。
ipcMain.handle('check-port', async (event, port) => {
  const net = require('net');
  return new Promise((resolve) => {
    try {
      // 兼容两种入参：纯端口号（13337）或 URL 字符串（http://127.0.0.1:13337/mcp）
      let host = '127.0.0.1', portNum = NaN;
      if (typeof port === 'string' && port.includes('://')) {
        const u = new URL(port);
        host = u.hostname || host;
        portNum = Number(u.port) || 80;
      } else {
        portNum = Number(port);
      }
      const socket = net.connect({ host, port: portNum }, () => {
        socket.destroy();
        resolve({ listening: true });
      });
      socket.setTimeout(1500, () => {
        socket.destroy();
        resolve({ listening: false });
      });
      socket.on('error', () => resolve({ listening: false }));
    } catch (e) {
      resolve({ listening: false, error: e.message });
    }
  });
});

// IPC: 拉起走 Burp 代理的隔离浏览器实例（独立 user-data-dir，保证代理参数生效）
ipcMain.handle('open-proxy-browser', async (event, targetUrl) => {
  try {
    const proxyPort = (config.web && config.web.proxy_port) || 8080;
    let browserPath = (config.web && config.web.browser_path) || '';
    if (!browserPath) {
      const candidates = [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
      ];
      browserPath = candidates.find(c => fs.existsSync(c)) || '';
    }
    if (!browserPath || !fs.existsSync(browserPath)) {
      return { success: false, error: '未找到 Chrome/Edge，请在设置 web.browser_path 手动指定浏览器路径' };
    }
    const profileDir = path.join(app.getPath('temp'), 'ctf-burp-browser');
    const args = [
      `--proxy-server=http://127.0.0.1:${proxyPort}`,
      '--ignore-certificate-errors',
      `--user-data-dir=${profileDir}`,
      '--no-first-run',
      '--no-default-browser-check'
    ];
    if (targetUrl) args.push(String(targetUrl));
    const child = spawn(browserPath, args, { shell: false, detached: true, stdio: 'ignore' });
    child.on('error', (err) => console.error('浏览器启动失败:', err.message));
    child.unref();
    return { success: true, message: `浏览器已启动（代理 127.0.0.1:${proxyPort} → Burp）` };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 浏览器 MCP - 获取网页内容（实现）
async function doBrowserMcpFetch(url) {
  const mcpUrl = config.mcp.browser;

  // 建立SSE连接获取sessionId
  const sessionUrl = await new Promise((resolve, reject) => {
    const urlObj = new URL(mcpUrl);
    const client = urlObj.protocol === 'https:' ? https : http;

    const req = client.get(mcpUrl, {
      headers: { 'Accept': 'text/event-stream' },
      timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
        // 解析第一个event获取endpoint
        const match = data.match(/data: (\S+message\?sessionId=[^\n]+)/);
        if (match) {
          resolve(match[1]);
          req.destroy();
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('SSE connection timeout'));
    });
  });

  // 提取sessionId
  const messageUrl = sessionUrl.startsWith('http')
    ? sessionUrl
    : `${mcpUrl.replace(/\/sse.*$/, '')}${sessionUrl}`;

  // 打开新标签页
  await sendMCPRequest(messageUrl, 'tools/call', {
    name: 'new-tab',
    arguments: { url: url }
  });

  // 等待页面加载
  await new Promise(resolve => setTimeout(resolve, 3000));

  // 获取页面快照
  const snapshot = await sendMCPRequest(messageUrl, 'tools/call', {
    name: 'page_snapshot',
    arguments: {}
  });

  return {
    success: true,
    snapshot: snapshot.result?.content?.[0]?.text || '',
    message: '网页内容已获取'
  };
}

// ========== 浏览器动态调试（CDP 轻量客户端，JS 逆向自动化） ==========
// 受控浏览器：Chrome/Edge + --remote-debugging-port，Node 22 全局 WebSocket/fetch 直连 CDP
let browserDebugState = { proc: null, port: 0 };

function findBrowserExe() {
  const candidates = [
    config.web && config.web.browser_path,
    // 用户偏好：默认使用 Edge
    process.env['PROGRAMFILES(X86)'] && path.join(process.env['PROGRAMFILES(X86)'], 'Microsoft\\Edge\\Application\\msedge.exe'),
    process.env['PROGRAMFILES'] && path.join(process.env['PROGRAMFILES'], 'Microsoft\\Edge\\Application\\msedge.exe'),
    process.env['PROGRAMFILES'] && path.join(process.env['PROGRAMFILES'], 'Google\\Chrome\\Application\\chrome.exe'),
    process.env['PROGRAMFILES(X86)'] && path.join(process.env['PROGRAMFILES(X86)'], 'Google\\Chrome\\Application\\chrome.exe'),
    process.env['LOCALAPPDATA'] && path.join(process.env['LOCALAPPDATA'], 'Google\\Chrome\\Application\\chrome.exe')
  ];
  for (const p of candidates) { try { if (p && fs.existsSync(p)) return p; } catch (_) {} }
  return null;
}

function cdpPortProbe(port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/json/version', timeout: timeoutMs }, (res) => { res.resume(); resolve(res.statusCode === 200); });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

async function ensureDebugBrowser() {
  const port = (config.web && config.web.debug_port) || 9223;
  if (await cdpPortProbe(port)) return { port };
  const exe = findBrowserExe();
  if (!exe) throw new Error('未找到 Chrome/Edge 浏览器（可在设置中配置 browser_path）');
  const profile = path.join(app.getPath('temp'), 'ctf-js-debug-profile');
  const child = spawn(exe, [
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', 'about:blank'
  ], { detached: true, stdio: 'ignore' });
  child.on('error', () => {});
  child.unref();
  browserDebugState = { proc: child, port };
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 500));
    if (await cdpPortProbe(port, 1000)) return { port };
  }
  throw new Error(`浏览器 CDP 端口 ${port} 未就绪`);
}

// CDP 执行核心：开新标签 → 注入 hookScript → 等待 → 取回 resultExpr 与 console 输出
async function cdpRunJs({ url, hookScript, resultExpr, waitMs } = {}) {
  const { port } = await ensureDebugBrowser();
  const resp = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url || 'about:blank')}`, { method: 'PUT' });
  if (!resp.ok) throw new Error('新建标签页失败: HTTP ' + resp.status);
  const tab = await resp.json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  let msgId = 0;
  const pending = new Map();
  const consoleLogs = [];
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('CDP WebSocket 连接失败')); });
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
    if (m.id && pending.has(m.id)) {
      const p = pending.get(m.id); pending.delete(m.id);
      m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result);
    } else if (m.method === 'Runtime.consoleAPICalled') {
      const line = (m.params.args || []).map(a => a.value !== undefined ? String(a.value) : (a.description || a.type)).join(' ');
      consoleLogs.push(line);
    }
  };
  try {
    await send('Runtime.enable');
    await send('Page.enable');
    // 页面加载缓冲（目标站点 JS 需要时间就绪）
    await new Promise(r => setTimeout(r, 2500));
    const unwrap = (r) => r && r.result ? (r.result.value !== undefined ? r.result.value : (r.result.description || null)) : null;
    let hookResult = null;
    if (hookScript) {
      hookResult = unwrap(await send('Runtime.evaluate', { expression: hookScript, awaitPromise: true, returnByValue: true }));
    }
    const wait = Math.min(Math.max(Number(waitMs) || 3000, 0), 60000);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    let finalResult = null;
    if (resultExpr) {
      finalResult = unwrap(await send('Runtime.evaluate', { expression: resultExpr, awaitPromise: true, returnByValue: true }));
    }
    return { success: true, hookResult, result: finalResult, console: consoleLogs.slice(-50) };
  } finally {
    try { ws.close(); } catch (_) {}
  }
}

ipcMain.handle('browser-js-run', async (event, params) => {
  try {
    return await cdpRunJs(params || {});
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 浏览器 MCP - 获取网页内容
ipcMain.handle('browser-mcp-fetch', async (event, url) => {
  try {
    return await doBrowserMcpFetch(url);
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 浏览器 MCP - 搜索
ipcMain.handle('browser-mcp-search', async (event, query) => {
  try {
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    return await doBrowserMcpFetch(searchUrl);
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 测试MCP连接
ipcMain.handle('test-mcp-connection', async (event, type) => {
  try {
    switch (type) {
      case 'ida':
        // 完整 MCP 握手（initialize + initialized + tools/list），确保工具可用
        await idaMcpEnsureSession();
        return {
          success: true,
          tools: idaMcpState.toolMap || {},
          message: 'IDA MCP 连接成功'
        };
      case 'jeb': {
        const url = config.mcp.jebMcp;
        const result = await sendMCPRequest(url, 'initialize', {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'ctf-tool', version: '1.0' }
        });
        return {
          success: true,
          result: result,
          message: 'JEB MCP 连接成功'
        };
      }
      case 'browser': {
        // 浏览器 MCP 仍走 SSE 端点，尚未统一到 Streamable HTTP 客户端
        return { success: false, error: '浏览器 MCP 暂未接入（SSE 端点未配置/不可用）' };
      }
      case 'burp':
        // 传输探测（HTTP/SSE）+ initialize + tools/list
        await burpEnsureReady();
        return {
          success: true,
          tools: burpMcpState.toolMap || {},
          transport: burpMcpState.transport,
          message: 'Burp MCP 连接成功（' + burpMcpState.transport + ' 传输）'
        };
      case 'ctf2': {
        // 公网 Streamable HTTP + Bearer Token：initialize + whoami 探活 + tools/list
        const probe = await ctf2Probe();
        let tools = [];
        try { tools = await ctf2ListTools(); } catch (e) { /* tools/list 失败不阻塞探活结论 */ }
        return {
          success: true,
          me: probe.me,
          tools,
          message: 'CTF² 平台连接成功'
        };
      }
      default:
        return { success: false, error: 'Unknown MCP type' };
    }
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ========== Claude API 通信 ==========

// 用户请求中断标志（claude-abort IPC 置位，下一轮/下一个数据块生效）
let claudeAborted = false;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// 组装请求头
function claudeHeaders(postData) {
  const cfg = getClaudeConfig();
  return {
    'Content-Type': 'application/json',
    'x-api-key': cfg.apiKey,
    'Authorization': `Bearer ${cfg.apiKey}`,
    'anthropic-version': '2023-06-01',
    'Content-Length': Buffer.byteLength(postData)
  };
}

// 非 流式 POST（stream 关闭时使用）。resolve {statusCode, raw}
function postClaudeJSON(requestBody) {
  return new Promise((resolve, reject) => {
    const cfg = getClaudeConfig();
    const base = String(cfg.baseUrl || '').trim();
    if (!base) return reject(new Error('未配置 AI 接口地址（Base URL）：请在「设置 → AI 接口」填写，或设置环境变量 ANTHROPIC_BASE_URL / CTF_CLAUDE_BASE_URL。'));
    const urlObj = new URL(base.replace(/\/+$/, '') + '/v1/messages');
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const postData = JSON.stringify(requestBody);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: claudeHeaders(postData),
      timeout: 600000
    };

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, raw: data, headers: res.headers });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Claude API 请求超时')); });
    req.write(postData);
    req.end();
  });
}

// 流式 POST（stream:true）。解析 Anthropic SSE 协议，边收边回调 onDelta(text)，
// 最终把事件流重建成完整 message。resolve {statusCode, raw, message?, streamed}
function postClaudeStream(requestBody, onDelta) {
  return new Promise((resolve, reject) => {
    const cfg = getClaudeConfig();
    const base = String(cfg.baseUrl || '').trim();
    if (!base) return reject(new Error('未配置 AI 接口地址（Base URL）：请在「设置 → AI 接口」填写，或设置环境变量 ANTHROPIC_BASE_URL / CTF_CLAUDE_BASE_URL。'));
    const urlObj = new URL(base.replace(/\/+$/, '') + '/v1/messages');
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const postData = JSON.stringify(Object.assign({}, requestBody, { stream: true }));
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: claudeHeaders(postData),
      // 连接阶段超时 60s：服务不可达/排队时快速失败，避免卡满 10 分钟；
      // 建立响应后改为空闲超时（120s 无数据即断，见 req.setTimeout）。
      timeout: 60000
    };

    const req = client.request(options, (res) => {
      // SSE 流内的空闲超时：异常连接若长时间无数据，会一直挂到硬超时，
      // 表现为工具"卡住不动"。这里 120s 无数据即断开，交给上层重试/报错。
      try { req.setTimeout(120000, () => { req.destroy(new Error('Claude 流空闲超时（120s 无数据）')); }); } catch (e) {}
      // 非 200：收完 body 走统一错误处理
      if (res.statusCode < 200 || res.statusCode >= 300) {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ statusCode: res.statusCode, raw: data }));
        return;
      }

      const ctype = String(res.headers['content-type'] || '');
      if (!ctype.includes('text/event-stream')) {
        // 端点忽略了 stream:true，返回普通 JSON —— 交给非流式路径解析
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ statusCode: res.statusCode, raw: data, streamed: false }));
        return;
      }

      // ---- SSE 解析 ----
      let buf = '';
      const blocks = {};
      const message = { content: [], stop_reason: null };
      // 流式推流过滤：若模型把工具调用当文本吐（<｜｜tool▁calls▁begin｜｜> 之类），
      // 这些标记不该显示到聊天区（否则用户看到一堆乱码标记）。检测到即停推。
      let streamDirty = false;

      const handleEvent = (ev) => {
        switch (ev.type) {
          case 'content_block_start': {
            const cb = ev.content_block || {};
            if (cb.type === 'tool_use') {
              blocks[ev.index] = { type: 'tool_use', id: cb.id, name: cb.name, input: {}, _json: '' };
            } else {
              blocks[ev.index] = { type: cb.type || 'text', text: '' };
            }
            break;
          }
          case 'content_block_delta': {
            const b = blocks[ev.index];
            const d = ev.delta || {};
            if (!b) break;
            if (d.type === 'text_delta') {
              b.text = (b.text || '') + (d.text || '');
              if (onDelta && !streamDirty) {
                // 一旦本流出现过工具调用标记，后续不再向 UI 推流（parseClaudeResult 会统一清理）
                if (/tool[\u2581_ ]?calls[\u2581_ ]?begin/i.test(b.text)) streamDirty = true;
                else { try { onDelta(d.text || ''); } catch (e) {} }
              }
            } else if (d.type === 'input_json_delta') {
              b._json += d.partial_json || '';
            } else if (d.type === 'thinking_delta') {
              b.text = (b.text || '') + (d.thinking || '');
            }
            break;
          }
          case 'content_block_stop': {
            const b = blocks[ev.index];
            if (b && b.type === 'tool_use' && b._json) {
              try { b.input = JSON.parse(b._json); } catch (e) { /* 半截 JSON，保留空 input */ }
              delete b._json;
            }
            break;
          }
          case 'message_delta':
            if (ev.delta && ev.delta.stop_reason) message.stop_reason = ev.delta.stop_reason;
            break;
          case 'error':
            message.error = ev.error;
            break;
        }
      };

      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (claudeAborted) {
          req.destroy();
          message.aborted = true;
          message.content = Object.keys(blocks).sort((a, b) => a - b).map(k => blocks[k]);
          resolve({ statusCode: 200, raw: '', message, streamed: true, aborted: true });
          return;
        }
        buf += chunk;
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (!line.startsWith('data:')) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === '[DONE]') continue;
          try { handleEvent(JSON.parse(payload)); } catch (e) { /* 忽略坏帧 */ }
        }
      });

      res.on('end', () => {
        message.content = Object.keys(blocks).sort((a, b) => a - b).map(k => blocks[k]);
        resolve({ statusCode: 200, raw: JSON.stringify(message), message, streamed: true, headers: res.headers });
      });
      res.on('error', (e) => reject(e));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Claude API 请求超时')); });
    req.write(postData);
    req.end();
  });
}

// 带退避重试的传输层（借鉴 openclaude withRetry）
//   · 最多 5 次；延迟 min(500ms × 2^(n-1), 32s) + 0~25% 抖动
//   · 优先用响应头 retry-after
//   · 429 单独计数（上限 3），避免限流时越重试越糟
//   · 400 类参数错误**不重试**（重试同样的请求必然同样失败），直接回给模型改参数
// 注意：流式模式一旦已向渲染层吐过增量文本就不再重试——重发会造成聊天区内容重复
async function claudeTransport(requestBody, onDelta) {
  const cfg = getClaudeConfig();
  const useStream = cfg.stream && typeof onDelta === 'function';
  const maxRetries = parseInt(process.env.CTF_API_RETRIES, 10) || 5;
  const max429 = 3;
  let lastErr = null;
  let deltaEmitted = false;
  let rateLimited = 0;
  const wrappedOnDelta = useStream ? (d) => { deltaEmitted = true; onDelta(d); } : null;

  const backoff = (attempt, retryAfterSec) => {
    if (retryAfterSec && retryAfterSec > 0) return Math.min(retryAfterSec * 1000, 32000);
    const base = Math.min(500 * Math.pow(2, attempt), 32000);
    return Math.round(base * (1 + Math.random() * 0.25));
  };

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (claudeAborted) throw new Error('已取消');
    try {
      const resp = useStream
        ? await postClaudeStream(requestBody, wrappedOnDelta)
        : await postClaudeJSON(requestBody);

      // 不可重试：请求本身有问题（400/401/403/404），直接把错误交给模型/用户
      if (resp.statusCode >= 400 && resp.statusCode < 500 && resp.statusCode !== 429) {
        return resp;
      }
      if (resp.statusCode === 429) {
        rateLimited++;
        if (rateLimited > max429 || attempt >= maxRetries) return resp;
        const ra = parseRetryAfter(resp.headers);
        await sleep(backoff(attempt, ra));
        continue;
      }
      if (resp.statusCode >= 500 && attempt < maxRetries && !deltaEmitted) {
        await sleep(backoff(attempt, parseRetryAfter(resp.headers)));
        continue;
      }
      return resp;
    } catch (e) {
      lastErr = e;
      if (!deltaEmitted && attempt < maxRetries) {
        await sleep(backoff(attempt));
        continue;
      }
      throw e;
    }
  }
  throw lastErr || new Error('Claude API 请求失败');
}

function parseRetryAfter(headers) {
  try {
    if (!headers) return 0;
    const v = headers['retry-after'] || headers['Retry-After'];
    if (!v) return 0;
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  } catch (e) { return 0; }
}

// 统一解析：非流式 JSON 或流式重建 message → { success, text, content, toolCalls, stopReason, error }
function parseClaudeResult(resp) {
  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    let msg = `Claude API HTTP ${resp.statusCode}`;
    try {
      const j = JSON.parse(resp.raw);
      msg = (j.error && j.error.message) || msg;
    } catch (e) { /* body 可能是 HTML/纯文本 */ }
    return { success: false, error: msg + (resp.raw && resp.raw.trim() ? ': ' + resp.raw.substring(0, 300) : '（空响应）') };
  }

  let content, stopReason;
  if (resp.message) {
    content = resp.message.content;
    stopReason = resp.message.stop_reason;
    if (resp.message.error) {
      return { success: false, error: (resp.message.error && resp.message.error.message) || JSON.stringify(resp.message.error) };
    }
    if (resp.aborted) return { success: false, error: '已取消', aborted: true, content, stopReason };
  } else {
    let result;
    try {
      result = JSON.parse(resp.raw);
    } catch (e) {
      return { success: false, error: 'Claude API 响应解析失败: ' + String(resp.raw).substring(0, 200) };
    }
    if (result.error) return { success: false, error: result.error.message || JSON.stringify(result.error) };
    content = result.content;
    stopReason = result.stop_reason;
  }

  if (!Array.isArray(content)) {
    return { success: true, text: resp.raw, content: [], toolCalls: [], stopReason };
  }

  const textParts = content.filter(c => c.type === 'text');
  const thinkingParts = content.filter(c => c.type === 'thinking');
  const toolParts = content.filter(c => c.type === 'tool_use');

  let text = textParts.map(c => c.text).join('');
  if (!text && thinkingParts.length > 0) {
    // 兼容两种块结构：非流式 API 的 {thinking} 与流式重建（postClaudeStream）的 {text}
    text = thinkingParts.map(c => c.thinking || c.text || '').join('');
  }

  // ── 兜底①：部分模型/代理把工具调用以"文本标记"输出，而不是标准的 tool_use 块 ──
  // 实测（deepseek 类代理）会吐 `<｜｜tool▁calls▁begin｜｜>func(arg="v")` 这种沿用了训练期特殊
  // token 的纯文本（<｜｜...｜｜> 为全角竖线，▁ 为 U+2581）。若不转换，工具调用**根本不会执行**：
  // AI 拿不到真实数据，只能凭上下文空想 → 表现为"3 秒完成、绕圈子、结论全是幻觉"。
  // 这里解析成标准 toolCalls，让后续循环正常执行。
  let toolCalls = toolParts.map(c => ({ id: c.id, name: c.name, input: c.input }));
  if (!toolCalls.length && text && /tool[\u2581_]?calls[\u2581_]?begin/i.test(text)) {
    const parsed = parseTextToolCalls(text);
    if (parsed.calls.length) {
      toolCalls = parsed.calls;
      text = parsed.cleanText;   // 剥掉标记与调用文本，只留叙述
      console.log(`[Tool Use] 兜底解析出 ${toolCalls.length} 个文本格式工具调用: ${toolCalls.map(c => c.name).join(', ')}`);
    }
  }

  return {
    success: true,
    text,
    content,
    toolCalls,
    stopReason
  };
}

// 解析"文本形态的工具调用"（非标准代理输出）。
// 形态示例（实测）：
//   <｜｜tool▁calls▁begin｜｜>start<｜｜tool▁calls▁begin｜｜>ida_list_functions()
//   <｜｜tool▁calls▁begin｜｜>ida_find_strings(regex="flag|key")
//   <｜｜tool▁calls▁begin｜｜>bash<｜｜tool▁calls▁begin｜｜>cd /e/x && dir
//   <｜｜tool▁calls▁begin｜｜>read_file(path="E:\\a\\b")
// 规则：标记是分隔符；紧随其后的标识符若是已知工具名 → 该名字本身即"调用开始"，
// 其后到下一个标记/段末的内容是参数（形如 name(args) 或裸命令行）。
function parseTextToolCalls(rawText) {
  const KNOWN = new Set([
    'read_file', 'write_file', 'bash', 'glob', 'grep',
    'jeb_get_manifest', 'jeb_get_class_decompiled', 'jeb_get_method_decompiled',
    'jeb_get_exported_activities', 'jeb_get_all_classes', 'jeb_get_class_methods',
    'ida_decompile', 'ida_list_functions', 'ida_find_strings', 'ida_get_xrefs', 'ida_get_bytes',
    'ida_list_globals', 'ida_disasm', 'ida_dbg', 'ida_dbg_mem', 'ida_open_file', 'angr_solve',
    'emu_trace', 'ida_apply_trace', 'rev_solve', 'recover_string',
    'remote_exec', 'traffic_extract', 'recipe', 'gui_input', 'crypto',
    'browser_search', 'browser_open', 'run_command', 'run_python', 'adb_command', 'frida_hook',
    'read_skill', 'wiki_search', 'wiki_read', 'burp_get_history', 'burp_get_message', 'burp_call',
    'switch_to_next_stage'
  ]);
  // 工具名 → 参数名映射（模型给裸参数时也能用；无参工具不在此表）
  const MAP = {
    bash: 'command', run_command: 'command', run_python: 'script', glob: 'pattern', grep: 'pattern',
    read_file: 'path', write_file: 'path', read_skill: 'name', wiki_read: 'name', wiki_search: 'query',
    browser_open: 'url', browser_search: 'query', ida_decompile: 'function_name', ida_get_xrefs: 'address',
    ida_get_bytes: 'address', ida_find_strings: 'regex', frida_hook: 'script', adb_command: 'command',
    ida_disasm: 'address', ida_dbg: 'action', ida_dbg_mem: 'action', remote_exec: 'command', traffic_extract: 'path',
    ida_list_globals: 'filter', ida_open_file: 'path', angr_solve: 'binary',
    emu_trace: 'binary', ida_apply_trace: 'trace', rev_solve: 'ops', recover_string: 'func'
  };
  // 标记：<｜｜tool▁calls▁begin｜｜> / <|tool_calls_begin|> / 变体（全角/半角竖线、▁/_ 分隔）
  const MARK = /<\s*[|｜]\s*[|｜]?\s*tool[\u2581_ ]?calls[\u2581_ ]?begin\s*[|｜]?\s*[|｜]\s*>/gi;
  const segs = String(rawText || '').split(MARK);
  const calls = [];
  let seq = 0;
  // 段结构：seg0(前导叙述) [seg1, seg2, ...]；每段形如 "start"、"func(args)"、"bash"、"裸命令"
  // 特例：模型可能把"工具名"与"参数"分成两段（"bash" / "ls -la"），此时裸名字段的参数取自下一段。
  for (let i = 1; i < segs.length; i++) {
    let seg = String(segs[i] || '').trim();
    if (!seg) continue;
    seg = seg.replace(/^start\b[：:\s]*/i, '').trim();   // 剥掉 "start" 控制词
    if (!seg) continue;

    let name = '', argsText = '';
    // 形态 A：func(args) 或 func()（空参）
    const mParen = seg.match(/^([a-z_][a-z0-9_]*)\s*\(([\s\S]*?)\)\s*(?=[A-Z一-龥]|$|\\n)/i)
      || seg.match(/^([a-z_][a-z0-9_]*)\s*\(([\s\S]*)\)?\s*$/i);
    if (mParen && KNOWN.has(mParen[1].toLowerCase())) {
      name = mParen[1].toLowerCase();
      argsText = mParen[2] || '';
    } else {
      // 形态 B：首 token 是工具名（可能无参，也可能后跟裸参数/换行参数）
      const mTok = seg.match(/^([a-z_][a-z0-9_]*)/i);
      if (mTok && KNOWN.has(mTok[1].toLowerCase())) {
        name = mTok[1].toLowerCase();
        argsText = seg.slice(mTok[1].length).trim();
        // 形态 C：裸名字且本段无参数 → 参数在下一段（"bash" / "ls -la /tmp"）
        if (!argsText && i + 1 < segs.length) {
          const nxt = String(segs[i + 1] || '').trim();
          // 下一段不是另一个工具名开头（避免把下一个调用当参数）
          const nxtTok = (nxt.match(/^([a-z_][a-z0-9_]*)/i) || [])[1];
          if (nxt && !(nxtTok && KNOWN.has(nxtTok.toLowerCase()))) {
            argsText = nxt;
            i++;   // 消费掉参数段
          }
        }
      }
    }
    if (!name) continue;

    // 组装 input
    let input = {};
    const at = argsText.replace(/^\s*\(\s*/, '').replace(/\)\s*$/, '').trim();
    if (at) {
      const kv = {}; let matched = false;
      const re = /([a-z_][a-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,)]+)/gi;
      let mm;
      while ((mm = re.exec(at)) !== null) {
        matched = true;
        let v = mm[2].trim();
        if (/^".*"$|^'.*'$/.test(v)) { try { v = JSON.parse(v.replace(/^'/, '"').replace(/'$/, '"')); } catch (e) { v = v.slice(1, -1); } }
        else if (/^-?\d+$/.test(v)) v = parseInt(v, 10);
        kv[mm[1]] = v;
      }
      if (matched) input = kv;
      else {
        // 裸参数：按工具语义映射。取到"下一个疑似调用/叙述边界"为止
        let raw = at;
        // 若工具是 bash/命令类，取到行尾或段末（命令可含空格与 &&）
        const key = MAP[name];
        if (key) input = { [key]: raw };
        else input = { _raw: raw };
      }
    }
    // 无参工具（如 ida_list_functions）允许空 input
    const NO_ARG_OK = new Set(['ida_list_functions', 'burp_get_history']);
    if (!Object.keys(input).length && !NO_ARG_OK.has(name)) {
      // 无参数且非无参工具 → 跳过（避免空调用误执行）
      continue;
    }
    calls.push({ id: 'textcall_' + (++seq) + '_' + Date.now(), name, input });
  }
  // cleanText：剥掉标记与"已识别的调用文本"，只留叙述
  const cleanText = String(rawText || '').split(MARK).filter(s => s && s.trim())
    .map(s => s.replace(/^start\b[：:\s]*/i, '').trim())
    .filter(s => {
      // 若该段整体是"已知工具名开头的调用"，则从叙述里去掉
      const t = s.trim();
      const mT = t.match(/^([a-z_][a-z0-9_]*)/i);
      return !(mT && KNOWN.has(mT[1].toLowerCase()));
    })
    .join('\n').trim();
  return { calls, cleanText };
}

// 全局语言约束：所有发往 AI 的请求统一在 system 头部注入。
// 为什么放在主进程单点：AI 调用路径有十余处（聊天/Tool-Use/分级快慢模型/复盘/题解/动态 Hook 决策…），
// 逐个改渲染层提示词既易漏又难维护；在请求构造处统一注入可 100% 覆盖。
// 注意：只约束"叙述/结论/解释"用中文，代码、标识符、flag、命令、寄存器名等保持原样，
// 且已有中文要求的提示词不受影响（叠加同义指令无副作用）。
const ZH_INSTRUCTION = [
  '【输出语言（最高优先级）】你的所有自然语言输出必须使用简体中文，包括思考过程、推理叙述、分析步骤、结论、经验总结、以及调用工具前后的说明文字。',
  '不要用英文写解释性文字。以下内容保持原样不翻译：代码、变量名/函数名/类名、flag 原文、文件路径、命令行、寄存器与汇编助记符、API/库名称、报错原文。',
  '即使是中间步骤（如"我先看一下 PE 头…"）也必须用中文。'
].join('\n');

function withChineseOutput(systemPrompt) {
  const base = String(systemPrompt || '');
  if (base.includes('【输出语言（最高优先级）】')) return base;   // 幂等：避免重复拼接
  return base ? (ZH_INSTRUCTION + '\n\n' + base) : ZH_INSTRUCTION;
}

// 发送Claude API请求（无工具）。
// GLM 等思考型模型可能在推理中途耗尽 max_tokens（stop_reason=max_tokens），
// 此时自动把已生成正文回传并要求"继续"，最多续写 2 轮，拼接为完整结果。
async function sendClaudeRequest(messages, systemPrompt = '', onDelta, opts = {}) {
  const cfg = getClaudeConfig();
  const useModel = opts.model || cfg.model;
  const useMaxTokens = Number(opts.maxTokens) || cfg.max_tokens;
  let history = messages.map(m => ({ ...m }));
  let fullText = '';
  let last = null;
  const MAX_CONT_ROUNDS = 2;

  for (let round = 0; round <= MAX_CONT_ROUNDS; round++) {
    const requestBody = { model: useModel, max_tokens: useMaxTokens, messages: history };
    const sysWithZh = withChineseOutput(systemPrompt);
    if (sysWithZh) requestBody.system = sysWithZh;
    // 续写轮不再向 UI 推流，避免聊天区内容重复
    const resp = await claudeTransport(requestBody, round === 0 ? onDelta : null);
    const parsed = parseClaudeResult(resp);
    if (!parsed.success) return parsed;
    last = parsed;
    if (parsed.text) fullText += (fullText ? '\n\n' : '') + parsed.text;
    if (parsed.stopReason !== 'max_tokens' || !parsed.text) break;
    console.log(`[Claude Chat] 输出被 max_tokens 截断，自动续写（第 ${round + 1}/${MAX_CONT_ROUNDS} 轮）...`);
    history = history.concat([
      { role: 'assistant', content: [{ type: 'text', text: parsed.text }] },
      { role: 'user', content: '继续，从中断处接着写。如已完成推理，请直接给出最终结论和 flag。（继续用中文）' }
    ]);
  }

  return { ...last, text: fullText || (last && last.text) || '' };
}

// IPC: 发送Claude消息（支持Tool Use；opts 可覆盖 model/maxTokens，用于模型分级）
ipcMain.handle('claude-chat', async (event, messages, systemPrompt, opts) => {
  try {
    console.log('[Claude Chat] 开始调用...');
    console.log('[Claude Chat] 消息数量:', messages.length);

    claudeAborted = false;
    const result = await claudeChatWithTools(messages, systemPrompt, (delta) => {
      // 流式增量转发到渲染层
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('claude-stream-chunk', delta);
      }
    }, opts || {});

    console.log('[Claude Chat] 调用完成:', result.success ? '成功' : '失败');
    if (!result.success) {
      console.log('[Claude Chat] 错误:', result.error);
    }

    return result;
  } catch (err) {
    console.error('[Claude Chat] 异常:', err.message);
    return { success: false, error: err.message };
  }
});

// IPC: 取消当前 AI 请求
ipcMain.handle('claude-abort', async () => {
  claudeAborted = true;
  // 同时终止正在跑的 python 子进程树——否则用户在 run_python 跑着时点取消，
  // 脚本会一直跑到自然结束或自身超时（最长 30 分钟），表现为"点了停止没反应"。
  try { killPythonTree(); } catch (e) { /* 忽略 */ }
  return { success: true };
});

// IPC: 会话列表 / 恢复（D1）
// 恢复时按 openclaude 的清洗顺序：剥离未完成的 tool_use → 剥离孤立 tool_result
// → 末尾是 user 时注入"从上次中断处继续"。不做清洗直接回放会被 API 400。
ipcMain.handle('sessions-list', async () => {
  try {
    const dir = path.join(app.getPath('userData'), 'sessions');
    return { success: true, sessions: SessionLog.list(dir) };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('session-load', async (event, id) => {
  try {
    const dir = path.join(app.getPath('userData'), 'sessions');
    const file = path.join(dir, String(id).replace(/[^\w.-]/g, '_') + '.jsonl');
    if (!fs.existsSync(file)) return { success: false, error: '会话不存在: ' + id };
    const records = SessionLog.load(file);
    const messages = sanitizeHistoryForResume(records);
    return { success: true, messages, rawCount: records.length, cleanedCount: messages.length };
  } catch (e) { return { success: false, error: e.message }; }
});

// ============ 工具预检（B3）============
// 只在**确定性可判断**的情况拦截，且每条错误必须给出"怎么改"。
// 目的：模型收到"失败"两个字只能瞎猜；给出候选/正确写法才能让它一轮改对。
function precheckToolCall(name, input) {
  const i = input || {};
  // ⚠️ 只包含 schema 里**真正有 path 字段**的工具。
  // run_python 的参数是 script、ida_decompile 是 function_name——
  // 早期版本把两者误列进来，导致所有 Python 脚本/反编译请求都被判成
  // "缺少必填参数 path" 而直接拒绝（工具彻底不可用）。
  const needPath = ['read_file', 'write_file', 'scan_crypto', 'extract_payload',
    'analyze_structure', 'gen_block_cipher_solver', 'gen_sm4_solver'];
  if (needPath.includes(name)) {
    const p = i.path;
    if (!p || !String(p).trim()) return `缺少必填参数 path。请传入目标文件的绝对路径后重试。`;
    if (!fs.existsSync(String(p))) {
      const dir = path.dirname(String(p));
      let hint = '';
      try {
        if (fs.existsSync(dir)) {
          const base = path.basename(String(p)).toLowerCase();
          const near = fs.readdirSync(dir)
            .map((f) => ({ f, d: levenshtein(base, f.toLowerCase()) }))
            .sort((a, b) => a.d - b.d)
            .slice(0, 3)
            .map((x) => path.join(dir, x.f));
          if (near.length) hint = `\n同目录下的相近文件：${near.map((x) => '`' + x + '`').join('、')}`;
        }
      } catch (e) { /* 目录不可读则不给提示 */ }
      return `文件不存在：${p}${hint}\n请确认路径（可先用 glob 或 bash 的 dir/ls 查看目录内容）。`;
    }
  }

  if (name === 'bash' && (!i.command || !String(i.command).trim())) {
    return '缺少必填参数 command。请传入要执行的命令，例如 `python solve.py`。';
  }
  if (name === 'run_python' && (!i.script || !String(i.script).trim())) {
    return '缺少必填参数 script。请把完整 Python 代码放在 script 字段里（不要传文件路径）。';
  }
  if (name === 'write_file') {
    if (!i.path || !String(i.path).trim()) return '缺少必填参数 path。';
    if (i.content === undefined || i.content === null) return '缺少必填参数 content。';
  }
  if (name === 'read_file' && !i.path) return '缺少必填参数 path。';
  // grep 的 path 是**可选**的（不传则在当前工作目录搜索），只在缺 pattern 时才拦。
  if (name === 'grep' && !i.pattern) return '缺少必填参数 pattern。';
  if (name === 'glob' && !i.pattern) return '缺少必填参数 pattern。';
  // ida_decompile 的参数名是 function_name（schema 如此），不是 function/address；
  // ida_get_bytes 用的是 address。早期版本按 function/address 判断，会把合法的
  // function_name 调用误判为"缺少参数"。
  if (name === 'ida_decompile' && !i.function_name && !i.address) {
    return '缺少 function_name 参数。IDA 需要明确的函数名；'
      + '若不确定，先调 ida_list_functions 列出函数，或 ida_xrefs 定位。';
  }
  if (name === 'ida_get_bytes' && !i.address) {
    return '缺少 address 参数。请传入虚拟地址（如 0x41C000）；不确定时可先用 ida_list_functions 定位。';
  }
  if (name === 'ida_disasm' && !i.address) {
    return '缺少 address 参数。请传入要反汇编的虚拟地址（如 0x402000）。';
  }
  if (name === 'ida_open_file' && !i.path && !i.file_path) {
    return '缺少 path 参数。请传入要载入 IDA 的二进制绝对路径'
      + '（花指令修复后通常是 junk_repair 输出的 *_repaired 文件）。';
  }
  if (name === 'angr_solve') {
    if (!i.binary || !String(i.binary).trim()) {
      return '缺少 binary 参数（目标文件路径）。';
    }
    if (i.find === undefined || i.find === null || (Array.isArray(i.find) && !i.find.length)) {
      return '缺少 find 参数。angr 需要一个"成功分支地址"作为搜索目标'
        + '（通常是打印 flag 的那个分支 0x...；不确定时先用 ida_find_strings 找 "flag" 再 ida_get_xrefs）。';
    }
  }
  if (name === 'recover_string') {
    if (!i.disasm && !i.func) {
      return 'recover_string 需要 disasm（反汇编文本）或 func（函数名/地址）之一。'
        + '最省事的方式是传 func，让工具自己去 IDA 取反汇编。';
    }
  }
  if (name === 'emu_trace') {
    if (!i.binary || !String(i.binary).trim()) {
      return '缺少 binary 参数（目标 ELF 路径）。';
    }
    const md = String(i.mode || 'function').toLowerCase();
    if (md === 'function' && !i.start) {
      return 'mode=function 需要 start（要调用的函数地址，如 0x401006）。'
        + '不确定就用 ida_list_functions 找一个"参数是输入、返回值像结果"的函数；'
        + '或改用 mode="entry" 从入口跑（仅静态链接目标可靠）。';
    }
  }
  if (name === 'rev_solve') {
    if (!Array.isArray(i.ops) || !i.ops.length) {
      return 'rev_solve 需要 ops（循环体算子列表），如 '
        + '[{op:"xor",dst:"Y",src:"X"},{op:"not",reg:"X"},{op:"swap_add",a:"X",b:"Y"}]。'
        + '先判断循环体是否只含 ^ ~ 移位 加减 交换——含 & | 查表就不能这样逆，改用 angr_solve。';
    }
    if (i.target == null && i.init == null) {
      return 'rev_solve 需要 target（目标值数组）或 init（已知初值，只回代验证）。';
    }
  }
  if (name === 'ida_apply_trace') {
    if (i.trace === undefined || i.trace === null || i.trace === '') {
      return '缺少 trace 参数。先跑 emu_trace 得到轨迹（对象或 JSON 文件路径），再传进来。';
    }
  }
  if (name === 'ida_dbg') {
    const act = String(i.action || '').toLowerCase();
    if (act === 'snapshot_diff' && !i.regions && !i.addr && !i.address) {
      return 'action=snapshot_diff 需要 regions（[{addr,size}]）或 addr+size，指明要快照哪块内存。';
    }
    if (act === 'force_continue' && !i.set) {
      return 'action=force_continue 需要 set（[{reg:"eax", value:1}]），说明要改哪个寄存器。';
    }
    if (act === 'global_reads' && !i.func) {
      return 'action=global_reads 需要 func（函数名或地址）。';
    }
  }
  if (name === 'ida_dbg') {
    if (!i.action) {
      return '缺少 action 参数。可选：start/exit/continue/run_to/step_into/step_over/'
        + 'bp_list/bp_add/bp_del/bp_toggle/regs/regs_named/stack。'
        + (i.addr || i.addrs ? '' : '');
    }
    const act = String(i.action).toLowerCase();
    const allowed = ['start', 'exit', 'continue', 'run_to', 'step_into', 'step_over',
      'bp_list', 'bp_add', 'bp_del', 'bp_toggle', 'regs', 'regs_named', 'stack'];
    if (!allowed.includes(act)) {
      return `未知的调试 action: ${i.action}。可选：${allowed.join('/')}。`;
    }
    if (act === 'run_to' && !i.addr) {
      return 'action=run_to 需要 addr 参数（目标地址，如 0x401000）。';
    }
    if ((act === 'bp_add' || act === 'bp_del') && !i.addrs && !i.addr) {
      return `action=${act} 需要 addrs 参数（地址或地址数组，如 '0x401000,0x401010'）。`;
    }
    if (act === 'bp_toggle' && !i.items && !i.addrs && !i.addr) {
      return 'action=bp_toggle 需要 items 参数（[{addr,enabled}] 或地址数组）。';
    }
    if (act === 'regs_named' && !i.regs) {
      return 'action=regs_named 需要 regs 参数（逗号分隔的寄存器名，如 "RAX,RBX"）。';
    }
  }
  if (name === 'ida_dbg_mem') {
    if (!i.action) return '缺少 action 参数。可选：read/write。';
    const act = String(i.action).toLowerCase();
    if (act !== 'read' && act !== 'write') return `未知的内存 action: ${i.action}。可选：read/write。`;
    if (!i.regions && !i.addr) {
      return act === 'read'
        ? 'action=read 需要 regions（[{addr,size}]）或 addr+size。'
        : 'action=write 需要 regions（[{addr,data}]）或 addr+data。';
    }
  }
  if (name === 'remote_exec' && (!i.command || !String(i.command).trim())) {
    return '缺少必填参数 command。例如 remote_exec({host:"kali", command:"binwalk -e file"})。';
  }
  if (name === 'traffic_extract' && (!i.path || !String(i.path).trim())) {
    return '缺少必填参数 path。请传入 pcap/pcapng 文件的绝对路径。';
  }
  if (name === 'recipe') {
    if (!i.auto && (!Array.isArray(i.recipe) || i.recipe.length === 0)) {
      return '需要 recipe（操作数组，如 [{op:"from_base64"}]）或 auto:true。';
    }
    if (Array.isArray(i.recipe) && i.recipe.some(x => !x || !x.op)) {
      return 'recipe 的每一项都必须有 op 字段（如 {op:"xor", key:"0a"}）。';
    }
  }
  if (name === 'gui_input') {
    if (!i.list_only && (!i.pid && !i.title_contains)) {
      return '需要 pid 或 title_contains 定位窗口。先用 gui_input({list_only:true}) 查看有哪些窗口与控件。';
    }
    if (!i.list_only && (i.text == null || String(i.text) === '')) {
      return '需要 text（要喂给输入框的内容）。';
    }
  }
  if (name === 'crypto') {
    const op = String(i.op || '').toLowerCase();
    if (!['symmetric', 'sm4', 'digest', 'hmac'].includes(op)) {
      return 'op 必须是 symmetric / sm4 / digest / hmac 之一。';
    }
    if (op === 'digest' && !i.algo) return 'digest 需要 algo（md5/sha256/sm3/crc32…）。';
    if ((op === 'symmetric' || op === 'sm4') && !i.key) return `${op} 需要 key。`;
    if (op === 'symmetric' && !i.algo) return 'symmetric 需要 algo（aes/des/tripledes/rc4/rabbit）。';
    if (op === 'hmac' && !i.key) return 'hmac 需要 key。';
    const mode = String(i.mode || '').toLowerCase();
    if (op === 'symmetric' && mode && mode !== 'ecb' && !i.iv) {
      return `${mode.toUpperCase()} 模式需要 iv。`;
    }
  }
  if (name === 'ida_list_globals') {
    // 参数都可选，但类型错了会让插件静默退回默认（count=100）→ 表又被截断
    if (i.count != null && !(Number(i.count) > 0)) {
      return 'count 必须是正整数（默认 500，避免插件默认 100 截断全局表）。';
    }
    if (i.offset != null && !(Number(i.offset) >= 0)) {
      return 'offset 必须是非负整数（按 count 递增翻页，如 0/500/1000）。';
    }
  }
  return null;
}

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = cur;
  }
  return prev[n];
}

// ============ 上下文压缩 ============
// 实现见 electron/agent-runtime.js: compactHistoryDeterministic
// （确定性抽取硬事实；不额外调用模型，压缩本身不会失败也不会多花 token）

// Claude API Tool Use 循环
async function claudeChatWithTools(messages, systemPrompt, onDelta, opts = {}) {
  // 初步求解提示明确要求直接分析时，不发送工具定义，
  // 避免 GLM 代理因超大 tools schema 或错误触发 Tool Use 而超时。
  if (systemPrompt && /不要调用任何工具|不调用工具|直接基于提供的代码分析/.test(systemPrompt)) {
    return await sendClaudeRequest(messages, systemPrompt, onDelta, opts);
  }

  // 骨架先行的预算纪律（P0.2）：深度求解提示词里原有"脚本必须真跑"只是软约束，
  // 实测 AI 会把 60 轮里的前 40 轮全花在反编译/读字节上，最后没预算落脚本。
  // 提到 system 级（每轮都随请求发送，不受上下文压缩影响），让模型开跑前就知道分段边界；
  // 真正的强制在循环里（第 16 轮骨架检查 / 第 45 轮收敛催促），提示词只负责提前对齐预期。
  const BUDGET_RULES = [
    '【预算纪律（硬性分段，工具轮次上限 60）】',
    '- 第 1-15 轮：只做侦察——反编译、读字节、搜字符串、确认常量表。不要在这一段写最终解密脚本。',
    '- 第 16 轮起：必须已经有一个可跑的脚本骨架（至少调用过一次 run_python；逻辑不完整也算，先跑起来再迭代）。没跑过就会被强制打断去写。',
    '- 第 45 轮起：停止扩大侦察范围，必须开始收敛——把已有发现落到 [VERIFY]、[HYPOTHESES] 或 [FLAG]。',
    '- 判据是代码检查，不是自我感觉：脚本必须真的通过 run_python 执行过并贴出真实输出。'
  ].join('\n');
  systemPrompt = (systemPrompt ? String(systemPrompt) + '\n\n' : '') + BUDGET_RULES;

  const tools = getToolDefinitions();
  let conversationHistory = [...messages];
  // 单轮工具循环上限：复杂逆向题（如并行归并+反演）实测需要大量"反编译→推演→写脚本→修正"迭代，
  // 25 次总在"写最终脚本"之前耗尽。放宽到 60，可用环境变量 CTF_MAX_TOOL_ITER 覆盖。
  const MAX_TOOL_ITERATIONS = parseInt(process.env.CTF_MAX_TOOL_ITER, 10) || 60;
  const SPRINT_AT = parseInt(process.env.CTF_SPRINT_AT, 10) || 50; // 冲刺触发点
  // 墙钟预算：轮数上限只约束"轮"，不约束每轮耗时（单轮可含 3 次工具调用，
  // run_python 单次上限 300s）。实测（CrackMe2/CrackMe5）AI 用 unicorn 单步模拟，
  // 60 轮远未用完就已跑到批量驱动的 10 分钟硬超时，连"当前进展"都没机会输出。
  // 这里给循环一个软截止：到点后**不再发新的分析轮**，而是注入一次收尾指令，
  // 强制模型把已有发现落成结论/接力请求。默认 8 分钟（驱动超时 10 分钟，留 2 分钟余量）。
  const DEADLINE_AT = Date.now() + (parseInt(process.env.CTF_TOOL_BUDGET_MS, 10) || 8 * 60 * 1000);
  let deadlineNudged = false;
  let maxIterations = MAX_TOOL_ITERATIONS;
  let lastResponse = null;
  let collectedText = '';
  let sprintInjected = false;
  // 骨架先行（P0.2）：第 16 轮检查"整个会话是否跑过脚本"，第 45 轮检查"是否开始收敛"。
  // 与 SPRINT_AT=50 的冲刺各管一段：16 轮管"有没有动手写"，45 轮管"有没有开始收口"，
  // 50 轮才是"停分析、落最终脚本"。计数上限 2，避免脚本工具确实不可用时无限催促。
  const SKELETON_AT = parseInt(process.env.CTF_SKELETON_AT, 10) || 16;
  const CONVERGE_AT = parseInt(process.env.CTF_CONVERGE_AT, 10) || 45;
  let skeletonNudgeCount = 0;
  let convergeNudged = false;
  // 轮次一律按"已消耗轮数"算，不依赖 maxIterations 的递减写法——
  // 环境变量改过上限（CTF_MAX_TOOL_ITER）时位置仍然正确。
  let roundsUsed = 0;
  // 脚本工具清单与 P0.2 的判据保持一致：run_python / bash / run_command 任一都算"动手跑过"。
  const SCRIPT_TOOL_RE = /^(run_python|bash|run_command)$/;
  // 跨上下文压缩的"跑过脚本"标记：压缩会丢掉早期 assistant 消息，
  // 只扫当前 history 会把已跑过脚本的会话误判成"零脚本"。
  let sawScriptTool = false;
  // "只说不做"催促：模型输出行动意图却零工具调用时注入催促继续执行（最多 3 次，防死循环）
  let actionNudged = false;
  let actionNudgeCount = 0;
  // "读完就收工"催促计数（已用工具但无 flag/契约；最多 2 次）
  let shallowNudgeCount = 0;
  // 分层收尾的"落地检查单"计数：与 shallowNudgeCount 分开记。
  // 前一层催的是"别只读几处，继续挖证据"；这一层催的是"手里的证据已经够多了，
  // 把它固化成可跑脚本/可验证契约"。两类话术不能互相挤占额度——复杂题往往不是
  // 缺分析，而是分析完没有落到 run_python 骨架，必须单独留出 2 次催促空间。
  let landNudgeCount = 0;
  // "零新数据"催促计数（P0.3）：前三级都在催"继续挖/落地"，但若模型连一次真实字节/数值
  // 都没带回来，任何话术都会被它改写成同一段概括性描述。这一层只催"去取数"，额度 2 次，
  // 与前面三层分开计，避免互相挤占。
  let dataNudgeCount = 0;
  // 重复调用计数（工具名+参数签名 → 次数）：同一调用重复 ≥4 次时警告换路，防"原地打转"卡死
  const dupCounter = new Map();
  // 脚本类工具的"同思路"签名池（归一化文本 → 出现次数）：截住"换写法重跑"
  const scriptSigs = new Map();
  // 去重闸的地址目标指纹层（rank 1）：结构相似还不够，观测地址也要重叠才算同一实验。
  // 旧判据单靠归一化文本相似度，把"反汇编另一个函数区间"算成 100% 相同并永久拦截。
  const dedupState = createDedupState();
  setScriptSimilarity(scriptSimilarity);
  // 连续相同调用拦截（借鉴 openclaude doomLoop）：阈值 3，签名变化即重置
  const doomGuard = new DoomLoopGuard(3);
  // 跨轮失败环（按 工具+错误类别 / 类别 / 路径 累计）：第 2 次 advisory，第 3 次要求换路线
  const failGuard = new FailureLoopGuard(3);
  // 会话日志：追加式 JSONL，崩溃/关窗后可续跑
  let sessionLog = null;
  try {
    const sessionDir = path.join(app.getPath('userData'), 'sessions');
    sessionLog = new SessionLog(sessionDir);
    sessionLog.append('user', messages && messages.length ? messages[messages.length - 1].content : '');
    // 保留最近 50 个会话（长期使用不无限增长；当前会话刚创建，不会被删）
    pruneDir(sessionDir, 50, '.jsonl');
    // 工具输出落盘目录保留最近 200 个文件
    pruneDir(path.join(app.getPath('userData'), 'tool-results'), 200, '.txt');
  } catch (e) { /* 日志失败不影响解题 */ }

  // 上下文预算：DeepSeek 128k 窗口，按 70% 触发摘要压缩（openclaude: 窗口 - 30k buffer）
  const CONTEXT_BUDGET_TOKENS = parseInt(process.env.CTF_CONTEXT_TOKENS, 10) || 90000;
  let compactFailures = 0;
  let lastCompactAt = 0;

  while (maxIterations > 0) {
    maxIterations--;
    roundsUsed++;

    // ── 上下文维护（每轮开头）──
    // 1) 微压缩：旧工具结果换成占位串（零模型调用，成本≈0）
    //    按 COMPACTABLE_TOOLS 白名单过滤：ida_list_functions 等"身份证据"永不清。
    try { microcompact(conversationHistory, 6, buildToolNameMap(conversationHistory)); } catch (e) { /* 忽略 */ }
    // 2) 超预算 → 摘要压缩（失败熔断：连续 3 次失败后冷却 5 分钟）
    try {
      const used = estimateTokens(conversationHistory);
      const cooling = compactFailures >= 3 && (Date.now() - lastCompactAt) < 5 * 60 * 1000;
      if (used > CONTEXT_BUDGET_TOKENS && !cooling) {
        lastCompactAt = Date.now();
        // 先试确定性压缩（保留最近若干轮 + 硬事实），失败才降级为截断
        const compacted = compactHistoryDeterministic(conversationHistory);
        if (compacted) {
          conversationHistory = compacted;
          compactFailures = 0;
          console.log(`[Context] 已压缩：${used} → ${estimateTokens(conversationHistory)} token`);
        } else {
          compactFailures++;
        }
      }
    } catch (e) { compactFailures++; }


    // 骨架先行检查（P0.2，第 16 轮）：只在"整个会话一次脚本都没跑过"时催。
    // 为什么按整个会话而不是本轮：AI 常见的病是连续十几轮只做反编译/读字节，
    // 每轮单独看都"有工具调用"，只有跨轮累计才看得出它从没动过手。
    // 为什么催两次就停：脚本工具本身可能不可用（run_python 起不来），
    // 无限催促会把剩下的预算全烧在同一句话术上，比不催更糟。
    // 与 SPRINT_AT 的冲刺各管一段：这里管"有没有开始写"，冲刺管"该收尾了"。
    const scriptCallsSeen = conversationHistory.reduce((n, m) => n + (m.role === 'assistant' && Array.isArray(m.content)
      ? m.content.filter(c => c.type === 'tool_use' && SCRIPT_TOOL_RE.test(c.name)).length : 0), 0);
    // sawScriptTool 是跨压缩的兜底：上下文压缩会丢掉早期的 assistant 消息，
    // 只扫 history 会在第 16 轮把"其实已经跑过脚本"误判成没跑过，白催一次。
    const hasScriptCall = sawScriptTool || scriptCallsSeen > 0;
    const skeletonNudge = roundsUsed >= SKELETON_AT && !hasScriptCall
      && skeletonNudgeCount < 2 && conversationHistory.length > 2;
    if (skeletonNudge) {
      skeletonNudgeCount++;
      const skeletonLastChance = skeletonNudgeCount >= 2;
      conversationHistory.push({
        role: 'user',
        content: [{ type: 'text', text:
          '⏱ **骨架催促**（第 ' + roundsUsed + ' 轮）：你到目前为止**一次脚本都没跑过**'
          + '（run_python/bash 调用记录为空），侦察阶段该结束了。\n'
          + (skeletonLastChance
            ? '⏰ **最后一次提醒**：不要再解释你还缺什么，**把已经读到的函数地址、常量、字节偏移先写成一个最小脚本跑起来**。'
              + '逻辑不完整没关系——先让脚本输出"当前能做到哪一步"（读到的字节、还原的中间值、校验比较结果），'
              + '拿到真实输出后再迭代。现在就用 run_python 执行。'
            : '请立刻用 run_python 写一个**可跑的最小骨架**：把已读到的函数地址/常量/偏移写成变量，'
              + '先跑通"读文件 → 定位数据 → 打印中间值"这条链，哪怕还解不出最终 flag。'
              + '骨架跑起来后再继续补逻辑；不要继续只做静态阅读。')
        }]
      });
      console.log(`[Tool Use] 骨架催促：第 ${roundsUsed} 轮仍无脚本调用（第 ${skeletonNudgeCount} 次）`);
      try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[Tool Use] 骨架催促：第 ${roundsUsed} 轮仍无脚本调用（第 ${skeletonNudgeCount} 次）` }); } catch (e) { /* 闸日志旁路失败不影响判据 */ }
    }

    // 收敛催促（P0.2，第 45 轮）：剩余轮次只够"收口"，不够再开新战场。
    // 与冲刺（SPRINT_AT=50）区分：这里只要求开始收敛到契约形态，冲刺才要求停掉全部分析。
    const hasContractSoFar = /\[FLAG\]|\[VERIFY\]|\[HYPOTHESES\]|待人工验证/.test(collectedText || '');
    const convergeNudge = !convergeNudged && roundsUsed >= CONVERGE_AT
      && !hasContractSoFar && conversationHistory.length > 2;
    if (convergeNudge) {
      convergeNudged = true;
      conversationHistory.push({
        role: 'user',
        content: [{ type: 'text', text:
          '⏱ **收敛催促**（第 ' + roundsUsed + ' 轮）：到目前为止你**还没有产出任何契约**——'
          + '既没有 [FLAG]，也没有 [VERIFY]，也没有 [HYPOTHESES]。剩余约 ' + Math.max(0, MAX_TOOL_ITERATIONS - roundsUsed) + ' 轮。\n'
          + '从现在起停止扩大侦察范围，只做收口：\n'
          + '① 用 run_python 把已有发现跑一遍，贴出真实输出；\n'
          + '② 把验证过的算法/密钥/变换写成 [VERIFY] 契约；\n'
          + '③ 若还有多组候选（算法/字节序/密钥变体），按可信度排序写成 [HYPOTHESES][...][/HYPOTHESES]；\n'
          + '④ 若确实做不出，写清卡在哪一步、已排除哪些路线——但必须给出上述三种契约之一，不能只写概括性描述。'
        }]
      });
      console.log(`[Tool Use] 收敛催促：第 ${roundsUsed} 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]`);
      try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[Tool Use] 收敛催促：第 ${roundsUsed} 轮仍无契约，要求收口到 [VERIFY]/[HYPOTHESES]` }); } catch (e) { /* 闸日志旁路失败不影响判据 */ }
    }

    // 冲刺阶段：到达 SPRINT_AT 后注入一次强制收尾指令——停止一切新分析，落地结论/脚本。
    // （复杂题 4 轮实测均耗尽预算于"写最终脚本之前"，靠提示词自约不够，代码强制兜底。）
    if (!sprintInjected && maxIterations === SPRINT_AT - 1 && conversationHistory.length > 2) {
      sprintInjected = true;
      conversationHistory.push({
        role: 'user',
        content: [{ type: 'text', text: '⏱ 冲刺指令：工具预算还剩 ' + (SPRINT_AT) + ' 轮。**立即停止一切新的分析/反编译**，把你已有的全部发现落成最终脚本（run_python）并跑出结果；若脚本失败就修正后重跑。最后必须输出 [FLAG]...[/FLAG] 或 [HYPOTHESES][...][/HYPOTHESES]。' }]
      });
    }

    // 墙钟预算到点：同样注入收尾指令（只注入一次）。与轮数冲刺互补——
    // 慢题（unicorn 单步模拟类）往往轮数没烧完、时间先到，必须靠时间触发收尾，
    // 否则外层批量驱动的超时会直接把整轮结果丢弃（连"卡在哪"都看不到）。
    if (!deadlineNudged && Date.now() > DEADLINE_AT && conversationHistory.length > 2) {
      deadlineNudged = true;
      const usedMin = Math.round((Date.now() - (DEADLINE_AT - (parseInt(process.env.CTF_TOOL_BUDGET_MS, 10) || 8 * 60 * 1000))) / 60000 * 10) / 10;
      console.log(`[Tool Use] 墙钟预算用尽（${usedMin} 分钟），注入收尾指令`);
      conversationHistory.push({
        role: 'user',
        content: [{ type: 'text', text:
          '⏰ **时间预算已用尽**（已运行 ' + usedMin + ' 分钟）。现在**不要再调用任何分析/反编译工具**，'
          + '只做两件事之一，并立刻结束：\n'
          + '① 已有足够证据 → 直接给出 [FLAG]...[/FLAG]（附 [VERIFY]）；\n'
          + '② 已解出下一层可执行内容 → 用 run_python 把它写盘，然后调用 `switch_to_next_stage` 接力；\n'
          + '③ 都没把握 → 明确写出「当前进展 + 卡点 + 下一步该做什么」，不要空转。'
        }]
      });
    }

    if (claudeAborted) {
      return {
        success: false,
        error: '已取消',
        aborted: true,
        partialText: lastResponse && lastResponse.text ? lastResponse.text : ''
      };
    }

    // 调用API（带工具定义），网络异常时返回明确错误而不是丢失上下文
    let response;
    try {
      response = await sendClaudeRequestWithTools(conversationHistory, systemPrompt, tools, onDelta, opts);
      lastResponse = response;
    } catch (err) {
      return {
        success: false,
        error: `Claude API 请求失败: ${err.message}`,
        partialText: lastResponse && lastResponse.text ? lastResponse.text : ''
      };
    }

    if (!response.success) {
      return response;
    }

    // 累计每轮的可见文本（工具调用轮也会带上模型的前置说明）
    if (response.text) {
      collectedText += (collectedText ? '\n\n' : '') + response.text;
    }

    // 如果有文本响应且没有工具调用，直接返回。
    // ⚠️ 例外①：stop_reason === 'max_tokens' 时模型只是被截断（可能正要调工具/给结论），
    // 直接返回会把"半截思考"当最终答案（not-baby-parallelism 三轮实测：95s 后文本断在半句）。
    // ⚠️ 例外②：模型"只宣布计划不执行"——输出"让我 dump/读取/反编译 X"却没发出任何工具调用。
    // 实测（Disguise stage2）：AI 完整推理出 VM 结构后停在"让我精确 dump 每轮 state"，
    // 零工具调用就收尾 → 170 秒里没拿到任何新数据。此时注入催促，让它真正执行。
    if (response.text && (!response.toolCalls || response.toolCalls.length === 0)) {
      if (response.stopReason === 'max_tokens' && maxIterations > 1) {
        conversationHistory.push({ role: 'assistant', content: response.content && response.content.length ? response.content : [{ type: 'text', text: response.text }] });
        conversationHistory.push({ role: 'user', content: [{ type: 'text', text: '（输出被 max_tokens 截断。请从中断处继续：优先给出最终结论/flag，不要再展开新分析。）' }] });
        continue;
      }
      // "只说不做"识别：文本里出现明确的"即将执行"意图，且尚未给结论。
      // 实测教训（Disguise）：AI 说 "Let me analyze with pefile"（analyze 不在原动词表）→ 未触发催促
      // → 6.8 秒就"分析完成"返回半句英文。因此动词表要宽（analyze/look/check/examine/get/verify…），
      // 且允许"意图 + up to 30 字符"的柔性匹配。
      const wantsAction = /让我(先|来|现在|再)?\s*(精确|具体|仔细)?\s*(dump|读|看|查|取|跑|写|调用|反编译|分析|执行|模拟|验证|计算|试试|试一下)/.test(response.text)
        || /(我(先|现在|接下来)|下一步|接下来我|继续).{0,16}(dump|读取|反编译|执行|跑|写脚本|调用|分析|模拟|验证)/.test(response.text)
        || /\b(let me|I'?ll|I will|now I|next,? I|let'?s)\b[\s\S]{0,40}?\b(dump|read|look|check|examine|analyze|analyse|decompile|run|execute|call|invoke|write|try|scan|verify|extract|parse|load|inspect|get)\b/i.test(response.text);
      const gaveConclusion = /\[FLAG\]|\[VERIFY\]|\[HYPOTHESES\]|待人工验证/.test(response.text);
      if (wantsAction && !gaveConclusion && maxIterations > 1 && actionNudgeCount < 3) {
        actionNudgeCount++;
        conversationHistory.push({ role: 'assistant', content: response.content && response.content.length ? response.content : [{ type: 'text', text: response.text }] });
        conversationHistory.push({ role: 'user', content: [{ type: 'text', text:
          '（检测到你只是"说明了要做什么"但没有真正调用工具。）请**立即用工具真正执行**上述动作——'
          + '例如用 ida_get_bytes 读指定地址字节、run_python 跑脚本、bash 执行命令，'
          + '拿到真实数据后再继续推理。不要只描述计划；也不要把工具调用写成文字。'
          + '若本轮确实无法执行（工具不可用），就明确说明并给出当前最优结论。' }] });
        continue;
      }

      // ── "读完就收工"识别（v1.7.5）──
      // 实测（CrackMe5）：AI 只调了 6 次工具（scan_crypto + 3 次 decompile + list + get_bytes），
      // 7 秒后返回一段描述性文字——既没有 [FLAG]、也没有 [VERIFY]、更没有 [HYPOTHESES]，
      // 流程就此结束，整题判失败。这类"浅尝辄止"和"只说不做"是两回事：
      //   · 只说不做：还没执行，需要催促去执行；
      //   · 读完就收工：执行了，但只读了几个函数就认为"没什么可做的"。
      // 判据：本轮已经发生过工具调用（collectedText 期间有过 toolCalls），且
      //       ① 结论里没有任何可验证输出（无 FLAG/VERIFY/HYPOTHESES），
      //       ② 仍未用完预算（剩余 > 1/3），
      //       ③ 还没催促过这种类型（最多 2 次，防死循环），
      //       ④ 手里还没有可落地的具体进展（有进展时交给下一层"落地检查单"，见下）。
      // 注意：不能对"明确说明卡点"的收工也催——那会把有价值的失败结论变成空转。
      const statedBlocker = /无法|不能|缺少|需要.{0,10}(提供|工具|文件)|卡在|blocked|unable|requires?\s+(a|the)?\s*(tool|file)/i.test(response.text);
      const didUseTools = conversationHistory.some(m => m.role === 'assistant' && Array.isArray(m.content)
        && m.content.some(c => c.type === 'tool_use'));
      const budgetLeft = maxIterations / MAX_TOOL_ITERATIONS;
      // "进展明确"的判据（分层收尾第二级的入口）：
      // 86 题实测里 57% 的失败不是 AI 没读代码，而是它已经读到了地址/常量/变换，
      // 却把结论写成"程序做了什么"就收工——这类题催"继续挖"没用，该催"把已知量落地"。
      // 所以这里认的是"可见文本里已经出现能直接写进脚本的东西"（地址/函数名/偏移/常量/变换），
      // 而不是工具调用次数：调用次数多但原地打转的题同样存在（见下方 dupCounter 的教训）。
      // 同时要求至少发生过 2 次工具调用，避免"只声明了一个地址就宣称有进展"。
      const toolUseCount = conversationHistory.reduce((n, m) => n + (m.role === 'assistant' && Array.isArray(m.content) ? m.content.filter(c => c.type === 'tool_use').length : 0), 0);
      const concreteEvidence = /0x[0-9a-f]{2,}|\bsub_[0-9a-f]+\b|RVA|偏移|地址|常量表|字节序列|密钥流|已验证|transform|offset\s*=\s*0x/i.test(collectedText || '');
      const hasConcreteProgress = didUseTools && toolUseCount >= 2 && concreteEvidence;
      // 三级判定的两个入口显式命名，便于单测按源码抽取判据（见 tests/test_land_nudge.js）：
      // 第一级由 !gaveConclusion 挡住；第二级只看"有进展但无契约"；第三级是剩下的无进展收工。
      const shallowGiveUp = didUseTools && !gaveConclusion && !statedBlocker && budgetLeft > 0.33 && shallowNudgeCount < 2 && !hasConcreteProgress;
      const landNudge = hasConcreteProgress && !gaveConclusion && !statedBlocker && budgetLeft > 0.33 && landNudgeCount < 2;
      if (shallowGiveUp) {
        shallowNudgeCount++;
        conversationHistory.push({ role: 'assistant', content: response.content && response.content.length ? response.content : [{ type: 'text', text: response.text }] });
        conversationHistory.push({ role: 'user', content: [{ type: 'text', text:
          '（检测到你只读了几处就准备收工，但**既没有给出 flag、也没有给出可验证的 [VERIFY] 契约**。）\n'
          + '工具预算还很充足（剩余约 ' + Math.round(budgetLeft * 100) + '%）。请不要停在这里：\n'
          + '① 若你已经有明确假设（算法/密钥/变换），**立即用 run_python 写脚本实测**，并附 [VERIFY] 契约；\n'
          + '② 若还不确定，继续追关键路径：交叉引用（ida_get_xrefs）→ 校验函数 → 常量表（ida_get_bytes）；\n'
          + '③ 若确认当前层是壳/loader，把下一层提取出来并调 switch_to_next_stage；\n'
          + '④ 若确实已穷尽手段，请明确写出「卡在哪一步、缺什么信息」，而不是只给概括性描述。\n'
          + '只输出"程序做了什么"的说明不算完成——必须落到可验证的结论。' }] });
        console.log(`[Tool Use] 浅层收工检测：已用工具但无结论，催促继续（第 ${shallowNudgeCount} 次）`);
        try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[Tool Use] 浅层收工检测：已用工具但无结论，催促继续（第 ${shallowNudgeCount} 次）` }); } catch (e) { /* 闸日志旁路失败不影响判据 */ }
        continue;
      }

      // ── 分层收尾第二级：已用工具、有明确进展，但仍没有契约（v1.9.2 / P0.1）──
      // 实测（86 题中 49 道失败）：AI 已经把函数地址、常量、字节偏移都读出来了，
      // 最后只输出一段"程序先做 A 再做 B"的说明就返回——它缺的不是分析，而是
      // 把已知量固化成可执行脚本这一步。对这类收工继续催"去挖更多证据"是错位的：
      // 证据已经够了，该催的是"落地"。所以单独开一层，话术换成"落地检查单"，
      // 并要求脚本哪怕跑不出最终 flag，也必须能跑出"当前能做到哪一步"，
      // 因为只有可跑的骨架才会暴露出下一步真正的分歧点（与最终契约的差距）。
      // 计数与 shallowNudgeCount 分开：旧层额度已被"继续挖"消耗过的题，仍然需要
      // 单独 2 次"落地"机会，否则复杂题会在旧额度耗尽后直接收工。
      if (landNudge) {
        landNudgeCount++;
        conversationHistory.push({ role: 'assistant', content: response.content && response.content.length ? response.content : [{ type: 'text', text: response.text }] });
        const lastChance = landNudgeCount >= 2;
        conversationHistory.push({ role: 'user', content: [{ type: 'text', text:
          '（检测到你已收集到具体进展，但**还没有把结论落成可验证的 [VERIFY] 契约**。）\n'
          + '不要再写"程序做了什么"的描述了。请立刻做一次**落地检查单**：\n'
          + '① 把当前所有已知量逐条列出来：函数地址（如 0x.../sub_...）、常量、字节偏移、已验证的变换（算法/密钥/轮数）；\n'
          + '② 用这些已知量写一段 **run_python 直接可跑的脚本框架**——即使还不能解出最终 flag，'
          + '也必须能跑出"当前能做到哪一步"（例如：解密到第几字节、校验到哪个分支、还原出哪段中间数据）；\n'
          + '③ 运行它，把真实输出贴出来；脚本报错就修正后重跑。\n'
          + '最后**必须**输出 [VERIFY]...[/VERIFY]（可验证的算法/密钥/变换契约）'
          + '或 [HYPOTHESES][...][/HYPOTHESES]（候选结论，按可信度排序）。'
          + (lastChance ? '\n⏰ **最后机会**：这一轮若仍无法给出 [VERIFY]，给出 [HYPOTHESES] 候选也行——'
            + '把最可能的 1-3 个假设连同支持它们的地址/常量一起写出来，不要再用概括性描述收工。' : '') }] });
        console.log(`[Tool Use] 落地检查单：有进展但无契约，要求写成可跑脚本（第 ${landNudgeCount} 次）`);
        try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[Tool Use] 落地检查单：有进展但无契约，要求写成可跑脚本（第 ${landNudgeCount} 次）` }); } catch (e) { /* 闸日志旁路失败不影响判据 */ }
        continue;
      }

      // ── 分层收尾第四级：零新数据拦截（P0.3）──
      // 还有一类收工既无 flag/契约、也没声明卡点，但文本里连一个本轮真实读到的
      // 字节/常量/代码片段都没有，只有"程序先做 A 再做 B"的概括。前三级催"继续挖/落地"
      // 时，模型可以把同一段概括换个说法再交一遍；这里只认"能与工具输出对上的硬数据"，
      // 没有就逼它先取数。探针取本轮 response.text + 最近一条 tool_result：
      // tool_result 是模型本轮真正看到的原始输出，能兜住"文本没引用但确实读到了字节"的情况。
      const recentToolText = (() => {
        for (let i = conversationHistory.length - 1; i >= 0; i--) {
          const m = conversationHistory[i];
          if (m.role === 'user' && Array.isArray(m.content)) {
            const parts = m.content.filter(c => c.type === 'tool_result')
              .map(c => String(c.content == null ? '' : c.content));
            if (parts.length) return parts.join('\n');
          }
        }
        return '';
      })();
      const newDataProbe = (response.text || '') + '\n' + recentToolText;
      // (a) 十六进制串 ≥8 位；纯英文单词（deadbeef/feedback 这类）不算，要求含数字或长到 16 位。
      const hexLike = (newDataProbe.match(/[0-9a-fA-F]{8,}/g) || []).some(s => /[0-9]/.test(s) || s.length >= 16);
      // (b) 反编译代码特征：有 ; { } 之一，且有 = 或 (
      const decompiledLike = /[;{}]/.test(newDataProbe) && /[=(]/.test(newDataProbe);
      // (c) 计算结果：等号后跟具体数值（十进制或 0x 十六进制）
      const computedLike = /=\s*(?:0x[0-9a-fA-F]+|\d+)/.test(newDataProbe);
      // (d) 至少一段 ≥20 字符的引号内字符串（真实读到的表项/密钥/常量串）
      const quotedLike = /"[^"\r\n]{20,}"|'[^'\r\n]{20,}'/.test(newDataProbe);
      const hasNewData = hexLike || decompiledLike || computedLike || quotedLike;
      // 同轮只催一次（取第一命中）：前三层已命中的本轮已在上面 continue，这里再显式排除，
      // 防止以后调整顺序时两层叠加、把 2 次额度一次烧光。
      const dataNudge = didUseTools && !gaveConclusion && !statedBlocker && !hasNewData
        && budgetLeft > 0.33 && dataNudgeCount < 2 && !shallowGiveUp && !landNudge;
      if (dataNudge) {
        dataNudgeCount++;
        conversationHistory.push({ role: 'assistant', content: response.content && response.content.length ? response.content : [{ type: 'text', text: response.text }] });
        conversationHistory.push({ role: 'user', content: [{ type: 'text', text:
          '（检测到本轮**没有任何新增的字节级数据**：既没有十六进制字节串、没有反编译代码片段，'
          + '也没有算出来的数值，只有概括性描述。这样的收工等于整题白做。）\n'
          + '请立刻取一次真实数据再说话，二选一：\n'
          + '① 调 ida_get_bytes 读取你刚才提到的关键位置的真实字节——例如校验函数附近引用的常量表地址、'
          + '输入缓冲区、循环里引用的 .rodata 地址；把返回的十六进制字节原样贴出来；\n'
          + '② 调 run_python 写一个最小脚本，算出至少一个具体数值（首轮变换结果、长度、校验目标值等），'
          + '把脚本的真实输出贴出来。\n'
          + '拿到真实字节/数值后，再基于它们给出 [VERIFY] 契约或 [HYPOTHESES]。'
          + '不要再用"程序做了什么"的描述收工。' }] });
        console.log(`[Tool Use] 零新数据拦截：无字节/数值，要求取数（第 ${dataNudgeCount} 次）`);
        try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[Tool Use] 零新数据拦截：无字节/数值，要求取数（第 ${dataNudgeCount} 次）` }); } catch (e) { /* 闸日志旁路失败不影响判据 */ }
        continue;
      }

      return {
        success: true,
        text: response.text
      };
    }

    // 检查是否有工具调用
    if (response.toolCalls && response.toolCalls.length > 0) {
      // 限制工具调用数量
      const toolCalls = response.toolCalls.slice(0, 3);
      // 跨压缩标记：只要本会话出现过脚本工具，就说明"骨架已动手"，第 16 轮的催促不该再触发。
      if (toolCalls.some(tc => tc && SCRIPT_TOOL_RE.test(tc.name))) sawScriptTool = true;

      // ── 多阶段接力：一旦出现 switch_to_next_stage，立即中断本阶段循环 ──
      // 切换涉及 UI 状态 / CASE 目录 / 外部进程管理，必须由渲染层执行；
      // 这里只把请求连同"本阶段已产出的全部文本"回传（stageSwitch 字段）。
      const stageCall = toolCalls.find(tc => tc && tc.name === 'switch_to_next_stage');
      if (stageCall) {
        const inp = stageCall.input || {};
        console.log('[阶段接力] AI 请求切换:', inp.path, '| 理由:', inp.reason);
        return {
          success: true,
          text: collectedText || (lastResponse && lastResponse.text) || '（已请求切换到下一阶段）',
          stageSwitch: {
            path: String(inp.path || '').trim(),
            reason: String(inp.reason || '').trim(),
            carried: String(inp.carried || '').trim()
          }
        };
      }

      // 执行工具调用
      const toolResults = [];

      for (const toolCall of toolCalls) {
        if (claudeAborted) break;
        console.log(`[Tool Use] 调用工具: ${toolCall.name}`, toolCall.input);
        // 持久化工具调用日志（stdout 只在 npm 窗口可见，排查"工具到底执行没执行"时需要落盘证据）
        try { logToolCall(toolCall.name, toolCall.input); } catch (e) {}

        // ── 重复调用检测（防"原地打转"卡死）──
        // 实测（Disguise）：AI 把同一个"读 stage2 常量表"脚本跑了 30 次，每次都因手算 RVA→offset
        // 换算错误拿不到数据，就换个写法再试，整个任务卡死。
        //
        // 但**只用文本相似度会误杀**（实测 CrackMe2 / CrackMe5 / not-baby-parallelism）：
        // normalizeScript 把地址与数字折叠成 ` N `，于是"反汇编另一个函数区间"的脚本
        // 归一化后相似度 = 1.000，第 3 次起被永久拦截 → AI 放弃静态分析。
        //
        // 现在的判据是两层同时成立才算同一实验：
        //   A) 参数逐字节相同（完整 sha1 签名）
        //   B) 结构相似度 > 88% **且** 观测地址集合重叠 >= 50%
        // 状态机在 electron/script-dedup.js（纯函数，可单测）。
        const dupWarn = (extra) => `⚠️ 检测到**重复劳动**：\n${extra}\n`
          + '这说明当前做法拿不到预期结果，**继续重试同一调用不会有新结果**。请立即换路径：\n'
          + '①若是在做 RVA→文件偏移换算：不要手算，改用 pefile.PE(path).get_offset_from_rva(rva) 或 pe.get_memory_mapped_image()[va]（按虚拟地址直接索引，一次就对）；\n'
          + '②若是在读常量表：先用 ida_get_bytes(address) 直接读（IDA 已加载，无需自己换算）；\n'
          + '③若脚本反复报同一错误：先把该错误原文贴出来，分析根因再改，而不是换个写法重跑；\n'
          + '④若确实无法推进：明确说明卡点并给出当前最优结论，不要空转。';
        const sig = toolCall.name + '|' + (() => {
          try { return require('crypto').createHash('sha1').update(JSON.stringify(toolCall.input || {})).digest('hex'); }
          catch (e) { return String(toolCall.input); }
        })();
        const isScriptTool = /^(run_python|bash|run_command)$/.test(toolCall.name);
        const scriptRaw = String((toolCall.input && (toolCall.input.script || toolCall.input.command)) || '');
        // 上一轮这条调用的结果是否已被微压缩清空 → 允许重取一次（否则"数据被清→重取被拦"死锁）
        const wasCleared = (() => {
          try {
            for (let i = conversationHistory.length - 1; i >= 0; i--) {
              const m = conversationHistory[i];
              if (!m || m.role !== 'user' || !Array.isArray(m.content)) continue;
              for (const b of m.content) {
                if (b && b.type === 'tool_result' && b.tool_use_id === toolCall.id) {
                  const body = typeof b.content === 'string' ? b.content : JSON.stringify(b.content);
                  return !!(body && body.indexOf('[Old tool result content cleared]') >= 0);
                }
              }
            }
          } catch (e) { /* 查不到就当未清空 */ }
          return false;
        })();
        const dedupVerdict = checkDedup(dedupState, {
          name: toolCall.name,
          sig,
          isScriptTool,
          script: scriptRaw,
          norm: isScriptTool ? normalizeScript(scriptRaw) : '',
          cleared: wasCleared,
        });
        if (dedupVerdict.reason) {
          console.log(`[去重] ${dedupVerdict.reason}`);
          try {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('claude-tool-event', { phase: 'gate', tool: 'gate', message: `[去重] ${dedupVerdict.reason}` });
            }
          } catch (e) { /* 闸日志旁路失败不影响判据 */ }
        }
        if (dedupVerdict.blocked) {
          toolResults.push({
            tool_use_id: toolCall.id,
            content: dupWarn(dedupVerdict.layer === 'A'
              ? `同一个 ${toolCall.name} 调用（参数**完全相同**）已第 ${dedupVerdict.count} 次提交。`
              : `你**第 ${dedupVerdict.count} 次**提交了"同一思路、同一观测目标"的脚本（${dedupVerdict.reason}）。`),
            is_error: true,
          });
          continue;
        }
        // 旧结构保留只用于排障对照（判据已移到 script-dedup 状态机）
        if (isScriptTool) {
          const norm = normalizeScript(scriptRaw);
          if (norm.length >= 40) scriptSigs.set(sig, { norm, count: dedupVerdict.count || 1 });
        }

        // B1) 连续相同调用拦截（工具名 + 完整入参的 sha256）。
        //     与下面"累计次数"不同：这个看的是**连续**，中间插了别的调用就重置。
        //     阈值 3（与 openclaude doomLoop 一致）；命中后保持拦截直到签名变化。
        const doom = doomGuard.check(toolCall.name, toolCall.input);
        if (doom.blocked) {
          toolResults.push({
            tool_use_id: toolCall.id,
            content: `⚠️ 已拦截：同样的调用（${toolCall.name}，参数完全相同）已连续 ${doom.count} 次。\n`
              + '继续重复不会有新结果。请改参数、换工具或换假设——如果可观测状态确实变了，再重复一次是允许的。',
            is_error: true,
          });
          continue;
        }

        // 通知渲染层"即将执行某工具"——UI 上显示为可折叠的步骤条，
        // 让用户知道长时间等待时工具真的在跑（而不是界面卡死）。
        const emitToolEvent = (phase, extra) => {
          try {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('claude-tool-event', {
                phase, tool: toolCall.name, id: toolCall.id,
                label: toolLabel(toolCall.name, toolCall.input),
                ...(extra || {}),
              });
            }
          } catch (e) { /* UI 通知失败不影响执行 */ }
        };
        emitToolEvent('start');

        // B3) 工具预检：在真正执行前做确定性检查，错误信息必须包含"怎么改"。
        //     模型现在只收到"失败"两个字时只能瞎猜，预检直接给出候选/正确写法。
        const precheck = precheckToolCall(toolCall.name, toolCall.input);
        if (precheck) {
          // ⚠️ 一个 tool_use 只能对应**一个** tool_result，且 id 必须是真实 id。
          // 早期版本额外 push 了 id+'-adv' 的"建议"结果——API 会因为找不到对应的
          // tool_use 直接 400，整轮求解中断。附加建议一律并入同一条 content。
          failGuard.recordFailure(toolCall.name, precheck, toolCall.input && toolCall.input.path);
          const advisories = failGuard.takeAdvisories();
          const body = advisories.length ? precheck + '\n\n💡 ' + advisories.join('\n') : precheck;
          toolResults.push({ tool_use_id: toolCall.id, content: body, is_error: true });
          emitToolEvent('error', { error: precheck.split('\n')[0] });
          continue;
        }

        try {
          const out = toToolResult(await executeToolCall(toolCall.name, toolCall.input));
          const resultText = persistToolResult(out.text, {
            maxChars: parseInt(process.env.CTF_TOOL_RESULT_MAX, 10) || 24000,
            dir: path.join(app.getPath('userData'), 'tool-results'),
            id: toolCall.id,
          });
          toolResults.push({
            tool_use_id: toolCall.id,
            content: resultText,
            is_error: out.isError
          });
          emitToolEvent(out.isError ? 'error' : 'done', out.isError ? { error: out.text.split('\n')[0] } : { chars: resultText.length });
          if (out.isError) {
            failGuard.recordFailure(toolCall.name, out.text, toolCall.input && toolCall.input.path);
            // advisory 必须在本条结果里消费掉：留在队列里会被下一个无关的工具错误
            // 顺手取走，变成"张冠李戴"的建议（复核指出的滞留问题）。
            const advisories = failGuard.takeAdvisories();
            if (advisories.length) {
              toolResults[toolResults.length - 1].content =
                toolResults[toolResults.length - 1].content + '\n\n💡 ' + advisories.join('\n');
            }
          } else {
            failGuard.recordSuccess(toolCall.name, toolCall.input && toolCall.input.path);
            doomGuard.reset();   // 成功且有状态变化 → 重置连续计数
          }
        } catch (err) {
          const errMsg = `工具调用失败: ${err.message}`;
          emitToolEvent('error', { error: err.message });
          // B2) 跨轮失败环：按 (工具, 错误类别) / 类别 / 路径累计。
          // 同样不能为"判定"另造一个 tool_use_id——提示并入同一条结果。
          const fr = failGuard.recordFailure(toolCall.name, errMsg, toolCall.input && toolCall.input.path);
          const body = fr.tripped
            ? errMsg + `\n\n🛑 ${toolCall.name} 已连续 ${fr.count} 次同类失败（${fr.category}）。`
              + '这条路走不通了：请换工具、换假设，或先说明卡点并给出当前最优结论。'
            : errMsg;
          toolResults.push({
            tool_use_id: toolCall.id,
            content: body,
            is_error: true,
          });
        }
      }

      // assistant 消息需保留 text 块 + tool_use 块（只回传 tool_use 会丢失模型的前置说明）
      const assistantContent = [];
      if (lastResponse.content) {
        for (const block of lastResponse.content) {
          if (block.type === 'text' && block.text) {
            assistantContent.push({ type: 'text', text: block.text });
          } else if (block.type === 'tool_use' && toolCalls.some(tc => tc.id === block.id)) {
            assistantContent.push({ type: 'tool_use', id: block.id, name: block.name, input: block.input });
          }
        }
      }
      if (assistantContent.length === 0) {
        for (const tc of toolCalls) {
          assistantContent.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.input });
        }
      }

      // 把工具结果添加到对话历史
      conversationHistory.push({
        role: 'assistant',
        content: assistantContent
      });

      const toolResultMsg = {
        role: 'user',
        content: toolResults.map(tr => ({
          type: 'tool_result',
          tool_use_id: tr.tool_use_id,
          content: tr.content,
          ...(tr.is_error ? { is_error: true } : {})
        }))
      };
      conversationHistory.push(toolResultMsg);

      // D1) 会话日志（追加式 JSONL）：崩溃/关窗后可按最后一条完整 tool_result 续跑
      try {
        if (sessionLog) {
          sessionLog.append('assistant', assistantContent);
          sessionLog.append('user', toolResultMsg.content);
        }
      } catch (e) { /* 日志失败不影响解题 */ }

      // 继续循环，让API处理工具结果
      continue;
    }

    // 没有工具调用也没有文本，返回thinking
    return {
      success: true,
      text: response.text || '分析完成，但没有返回文本内容'
    };
  }

  // 超过迭代次数，返回本轮累计的全部文本（而不是只剩最后一段前言）
  return {
    success: true,
    text: collectedText || (lastResponse && lastResponse.text) || '分析完成（达到最大迭代次数）'
  };
}

// 脚本归一化：把"同思路换写法"折叠成同一形态，供相似度比较。
// 关键点：**变量改名不算换思路**（实测 AI 就是把 `data`→`buf`、`off`→`o` 改一遍当新脚本重跑）。
// 做法：① 去注释/docstring/空白；② 字符串→S、数字→N；③ 把非关键字标识符按"首次出现顺序"
// 统一重命名为 v0,v1,…（保留 `a.b` 的 .b 方法名——方法名不同即思路不同）。这样
// `off = pe.get_offset_from_rva(rva)` 与 `o = p.get_offset_from_rva(r)` 归一化后完全相同。
const SCRIPT_KEYWORDS = new Set(('import,from,as,for,while,if,else,elif,def,return,in,is,not,and,or,None,True,False,'
  + 'with,try,except,finally,lambda,global,class,break,continue,pass,raise,yield,del,assert,await,async,'
  + 'print,len,range,int,str,bytes,bytearray,list,dict,set,tuple,open,hex,ord,chr,abs,sum,min,max,sorted,'
  + 'enumerate,zip,map,filter,repr,format,type,isinstance,getattr,setattr,struct,ord,bin,oct,divmod,'
  + 'echo,export,then,fi,do,done,set,local,function,const,let,var,read,write,readfile,readFileSync').split(','));
function normalizeScript(s) {
  let t = String(s || '')
    .replace(/"""(?:[\s\S]*?)"""|'''(?:[\s\S]*?)'''/g, ' ')     // 三引号块（docstring）
    .replace(/#[^\n]*/g, ' ')                                   // # 注释
    .replace(/\/\/[^\n]*/g, ' ');                               // // 注释
  // 字符串/数字 → 占位符（放在改名之前，避免字面量里的词被当标识符）
  t = t.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, ' S ')
    .replace(/\b0[xX][0-9a-fA-F]+\b/g, ' N ')
    .replace(/\b\d+(\.\d+)?\b/g, ' N ');
  // 标识符改名：非关键字、且不是 `obj.method` 的 method 部分 → v<i>
  const alias = new Map();
  let next = 0;
  t = t.replace(/(\.)?\b([A-Za-z_]\w*)\b/g, (m, dot, id) => {
    if (dot) return m;                       // 属性/方法名保留（承载语义）
    if (SCRIPT_KEYWORDS.has(id)) return id;
    if (!alias.has(id)) alias.set(id, 'v' + (next++));
    return alias.get(id);
  });
  return t.replace(/\s+/g, '');
}
// 归一化脚本相似度：二元组集合 Jaccard（对长文本比编辑距离快且稳）
function scriptSimilarity(a, b) {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const grams = (s) => {
    const set = new Set();
    for (let i = 0; i + 1 < s.length; i++) set.add(s.slice(i, i + 2));
    return set;
  };
  const A = grams(a), B = grams(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const g of A) if (B.has(g)) inter++;
  return inter / (A.size + B.size - inter);
}

// 工具调用落盘日志：写到 <userData>/toolcalls.jsonl，供排查"工具到底有没有被真正调用"。
// 为什么需要：主进程 console.log 只在 npm 窗口可见，事后无法取证；实测遇到过
// "AI 输出大量推理但零工具调用"的情况（模型只宣布计划不执行 / 工具调用被当文本输出），
// 有这份日志就能立刻区分"模型没调"还是"调了但失败"。
function logToolCall(name, input) {
  try {
    const dir = app.getPath('userData');
    const file = path.join(dir, 'toolcalls.jsonl');
    let brief = '';
    try { brief = JSON.stringify(input || {}).slice(0, 500); } catch (e) { brief = String(input); }
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), tool: name, input: brief }) + '\n', 'utf8');
  } catch (e) { /* 日志失败不影响主流程 */ }
}

// 获取工具定义（与终端Claude完全一致）
function getToolDefinitions() {
  return [
    // ========== 文件操作工具 ==========
    {
      name: "read_file",
      description: "读取文件内容",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件路径" }
        },
        required: ["path"]
      }
    },
    {
      name: "write_file",
      description: "写入文件",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件路径" },
          content: { type: "string", description: "文件内容" }
        },
        required: ["path", "content"]
      }
    },
    {
      name: "bash",
      description: "执行Bash命令",
      input_schema: {
        type: "object",
        properties: {
          command: { type: "string", description: "命令" }
        },
        required: ["command"]
      }
    },
    {
      name: "glob",
      description: "搜索文件",
      input_schema: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "匹配模式" }
        },
        required: ["pattern"]
      }
    },
    {
      name: "grep",
      description: "搜索文件内容",
      input_schema: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "正则表达式" },
          path: { type: "string", description: "搜索路径" }
        },
        required: ["pattern"]
      }
    },
    // ========== JEB MCP 工具 ==========
    {
      name: "jeb_get_manifest",
      description: "获取APK的AndroidManifest.xml内容，包括包名、Activity、权限等信息",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" }
        },
        required: ["filepath"]
      }
    },
    {
      name: "jeb_get_class_decompiled",
      description: "获取指定Java类的反编译代码",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" },
          class_signature: { type: "string", description: "类签名，如 Lcom/example/MainActivity;" }
        },
        required: ["filepath", "class_signature"]
      }
    },
    {
      name: "jeb_get_method_decompiled",
      description: "获取指定方法的反编译代码",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" },
          method_signature: { type: "string", description: "方法签名，如 Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V" }
        },
        required: ["filepath", "method_signature"]
      }
    },
    {
      name: "jeb_get_exported_activities",
      description: "获取APK中所有导出的Activity列表",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" }
        },
        required: ["filepath"]
      }
    },
    {
      name: "jeb_get_all_classes",
      description: "获取APK中的所有Java类列表",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" }
        },
        required: ["filepath"]
      }
    },
    {
      name: "jeb_get_class_methods",
      description: "获取指定类的所有方法列表",
      input_schema: {
        type: "object",
        properties: {
          filepath: { type: "string", description: "APK文件的完整路径" },
          class_signature: { type: "string", description: "类签名" }
        },
        required: ["filepath", "class_signature"]
      }
    },
    // ========== IDA MCP 工具 ==========
    {
      name: "ida_decompile",
      description: "反编译IDA中的函数，获取伪代码",
      input_schema: {
        type: "object",
        properties: {
          function_name: { type: "string", description: "函数名或地址" }
        },
        required: ["function_name"]
      }
    },
    {
      name: "ida_list_functions",
      description: "列出IDA中的所有函数",
      input_schema: {
        type: "object",
        properties: {}
      }
    },
    {
      name: "ida_find_strings",
      description: "在IDA中搜索字符串，可用于找flag、key等",
      input_schema: {
        type: "object",
        properties: {
          regex: { type: "string", description: "搜索的正则表达式" }
        },
        required: ["regex"]
      }
    },
    {
      name: "ida_get_xrefs",
      description: "获取函数的交叉引用，查看谁调用了这个函数",
      input_schema: {
        type: "object",
        properties: {
          address: { type: "string", description: "函数地址或名称" }
        },
        required: ["address"]
      }
    },
    {
      name: "ida_get_bytes",
      description: "读取IDA中指定地址的原始字节（hex），用于取 vtable 内容/常量表/数据段。返回每行16字节的 hex + ASCII。",
      input_schema: {
        type: "object",
        properties: {
          address: { type: "string", description: "起始地址（如 0x7D10 或 7D10）" },
          size: { type: "string", description: "要读的字节数（默认 256，最大 65536）" }
        },
        required: ["address"]
      }
    },
    {
      name: "ida_disasm",
      description: "反汇编指定地址（IDA x86/x64/arm 由插件决定）。用于查看「不在任何函数内」的代码、间接跳转目标、以及函数表缺口里的指令。",
      input_schema: {
        type: "object",
        properties: {
          address: { type: "string", description: "起始地址（如 0x402000）" },
          max_instructions: { type: "number", description: "最多返回的指令条数（默认 64，上限 400）" },
          offset: { type: "number", description: "从起始地址再偏移的字节数（默认 0）" }
        },
        required: ["address"]
      }
    },
    {
      name: "recover_string",
      description:
        "从「逐字节立即数比较」还原字符串。这类校验在反汇编里长这样：\n" +
        "  cmp byte ptr [rbx+0], 0x62   ; 'b'\n" +
        "  cmp byte ptr [rbx+1], 0x79   ; 'y'\n" +
        "  ...\n" +
        "伪代码里会折叠成字符串常量，但**读伪代码时极易抄错一个字符**" +
        "（实测：`bytectf{` 被抄成 `bytecf{`，所有输入在第一步就被拒，日志只报「校验失败」，根本看不出是前缀错）。\n" +
        "本工具按偏移把立即数拼回原文，是**确定性**的，不依赖模型记忆。\n" +
        "参数二选一：\n" +
        "  · disasm：一段反汇编文本（ida_disasm 的输出直接贴进来）\n" +
        "  · func：函数名/地址，由工具自己去 IDA 取反汇编（推荐）\n" +
        "返回提取到的 text、bytes，并给出「与已知前缀只差 1-2 字符」的警告。",
      input_schema: {
        type: "object",
        properties: {
          disasm: { type: "string", description: "反汇编文本（含 cmp/mov byte ptr [reg+disp], imm 行）" },
          func: { type: "string", description: "函数名或地址（让工具自己去取反汇编）" },
          max_instructions: { type: "number", description: "func 模式下取的指令条数（默认 400）" }
        }
      }
    },
    {
      name: "ida_list_globals",
      description: "列出 IDA 中的全局符号（自动分页，默认每页 500 条直到 next_offset=null）。可按 filter 过滤名字，用 offset/count 手动翻页。",
      input_schema: {
        type: "object",
        properties: {
          queries: {
            type: "object",
            description: "插件原始 queries 对象（filter/offset/count）；与顶层同名字段二选一",
            properties: {
              filter: { type: "string", description: "名字过滤（子串）" },
              offset: { type: "number", description: "起始偏移" },
              count: { type: "number", description: "每页条数，默认 500" }
            }
          },
          filter: { type: "string", description: "名字过滤（子串）" },
          offset: { type: "number", description: "起始偏移" },
          count: { type: "number", description: "每页条数（默认 500，避免插件默认 100 截断）" }
        },
        required: []
      }
    },
    // ========== 动态调试（合并 dbg_* 的 20 个工具） ==========
    {
      name: "ida_open_file",
      description:
        "让 IDA 打开一个二进制并在新实例里重新分析，之后所有 ida_* 调用自动路由到新实例。\n" +
        "**花指令修复后必用**：junk_repair 只改文件字节，IDA 里现存的 IDB 还是按旧的错位边界解析的，" +
        "不重开就永远拿到错误的伪代码。\n" +
        "参数 path 传修补后的文件（如 matrix_repaired）；new_database=true 会强制丢弃旧 IDB 重新分析。" +
        "返回 success=true 时新实例已就绪，可直接 ida_list_functions / ida_decompile。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "要打开的二进制绝对路径" },
          new_database: { type: "boolean", description: "true=丢弃已有 .i64/.idb 强制全新分析（默认 false，有旧库就直接开旧库）" },
          timeout: { type: "number", description: "等待新实例注册的秒数（默认 90；大程序可加长）" }
        },
        required: ["path"]
      }
    },
    {
      name: "rev_solve",
      description:
        "**可逆循环逆推**：校验主体是 N 轮循环、循环体只由双射算子组成时，从目标值逆序回退直接还原输入。\n" +
        "为什么优先用它：能倒着走就别上 Z3/angr——几千轮也只是几毫秒，而符号执行常要几百秒还可能失败。\n" +
        "支持的算子（op 字段）：\n" +
        "  xor（dst^=src）/ xor_const / xor_cond_not（dst ^= ~src if src 偶 else src）/\n" +
        "  not（reg=~reg）/ rotl_single / rotr_single / rotl_cross（(hi,lo) 当整体循环左移 1）/\n" +
        "  add / sub / swap / swap_add（t=a; a=b; b=b+a）/ mul_const（仅奇数）\n" +
        "**不能逆**的情形：循环体含 `& 掩码`、`| 或`、查表/S-box、单向哈希——这些请改用 angr_solve。\n" +
        "生成的脚本会先做「正逆互逆」自检（不依赖目标值），再反解，最后回代验证；\n" +
        "只有 VERIFY=PASS 才是真解。参数：regs / width / rounds / target / ops。",
      input_schema: {
        type: "object",
        properties: {
          ops: {
            description: "循环体算子（按正向顺序）。例：[{op:'xor',dst:'Y',src:'X'},{op:'not',reg:'X'},{op:'swap_add',a:'X',b:'Y'}]"
          },
          regs: { description: "寄存器名数组（默认 ['X','Y']）" },
          width: { type: "number", description: "位宽 8/16/32/64（默认 64）" },
          rounds: { type: "number", description: "循环轮数（默认 1）" },
          target: { description: "目标值数组，顺序对应 regs" },
          init: { description: "已知初值（可选；给出则跳过反解，只回代验证）" },
          pack: { type: "boolean", description: "是否打包成字节输出（默认 true）" },
          endian: { type: "string", enum: ["little", "big"], description: "打包字节序（默认 little）" }
        },
        required: ["ops"]
      }
    },
    {
      name: "emu_trace",
      description:
        "用 Unicorn 真跑目标，记录**运行期地面真值**：每个间接跳转点实际去了哪里、全部控制流边、执行过的区间。\n" +
        "**这是分段 dispatch / VM 混淆题的关键一步**：当程序把代码切成很多段、跳转目标在运行期用栈算出来时，" +
        "静态 CFG 是碎的、反编译读不懂。人类解法的第一步就是 \"record a execution trace and set those jump targets\"。\n" +
        "返回 JSON（默认写到 cwd/emu_trace.json）+ 摘要。摘要里 `IND 0x401138 -> N targets: v=0x2 0x4011BF(x1)` 就是" +
        "「段号 2 → 段地址 0x4011BF」这类映射，拿到后配合 ida_apply_trace 回填给 IDA，各段就会连成一片。\n" +
        "mode=function（默认）直接调用 start 处的函数，参数走 rdi/rsi/…；mode=entry 从 ELF 入口跑（需能仿真 libc 启动）。\n" +
        "动态链接目标（有 PT_INTERP）不要用 mode=entry——入口是 ld.so，仿真不出来。\n" +
        "与 angr_solve 分工：emu_trace 只求「跑通 + 看清结构」，快几百倍；结构仍读不懂再上 angr 求解。",
      input_schema: {
        type: "object",
        properties: {
          binary: { type: "string", description: "目标 ELF 绝对路径" },
          start: { type: "string", description: "起始地址。mode=function 时是要调用的函数（如 0x401006）" },
          mode: { type: "string", enum: ["function", "entry"], description: "function=直接调函数（默认，推荐）；entry=从入口跑" },
          args: { description: "mode=function 的参数（数组，按 rdi/rsi/rdx/rcx/r8/r9 写入）" },
          stop_at: { description: "额外停机地址（数组）" },
          max_insns: { type: "number", description: "指令上限（默认 2000000）" },
          stdin: { type: "string", description: "喂给 stdin 的字节（hex 串或普通文本）" },
          out: { type: "string", description: "轨迹 JSON 输出路径（默认 emu_trace.json）" },
          heap_size: { type: "number", description: "堆大小字节（默认 16MB）" }
        },
        required: ["binary"]
      }
    },
    {
      name: "ida_apply_trace",
      description:
        "把 emu_trace 的轨迹**回填进 IDA**：对每个跳转目标 create_insn、对每条控制流边 add_cref、可选 add_func。\n" +
        "这是「运行期记录 → 静态可读」的闭环第二步。回填后反编译器能顺着 xref 找到各段，" +
        "原来碎成一堆的 dispatch 会连成可读的循环/状态机；每段也能单独 ida_decompile。\n" +
        "用法：先 emu_trace 得到轨迹（对象/JSON 文本），再 ida_apply_trace({trace: <轨迹>})。\n" +
        "仍缺段时用 code_ranges=true（把执行过的整个区间都 MakeCode）；需要 IDA 重分析更稳时 auto_wait=true。",
      input_schema: {
        type: "object",
        properties: {
          trace: { description: "emu_trace 的结果对象，或轨迹 JSON 文本（键：edges / indirect_sites / exec_ranges）" },
          make_funcs: { type: "boolean", description: "在跳转目标处建函数（默认 true，便于逐段反编译）" },
          code_ranges: { type: "boolean", description: "把执行过的区间也 MakeCode（默认 false；有冲突时再开）" },
          auto_wait: { type: "boolean", description: "回填后等待 IDA 重新分析（默认 false；慢但更稳）" }
        },
        required: ["trace"]
      }
    },
    {
      name: "ida_dbg",
      description:
        "IDA 动态调试控制。action：start（幂等；远程模式会自动 suspend 并返回重定位符号）、" +
        "status（查 ON/STATE/IP）、suspend（把运行中的进程拉回暂停态）、exit、continue、run_to（需 addr）、" +
        "step_into、step_over、bp_list、bp_add（addrs，走 idaapi.add_bpt，本地/远程都可用）、" +
        "bp_del（addrs）、bp_toggle（items: [{addr,enabled}]）、regs、regs_named（regs: 'RAX,RBX'）、stack。\n" +
        "**运行期探测（混淆题首选，比读伪代码可靠）**：\n" +
        "· snapshot_diff —— 对指定内存区拍前后快照并**就地差分**，直接看出「这段代码把数据改成了什么」。\n" +
        "  mode=until_return（跑到当前函数返回，最适合整个 handler）/ single_step（单条指令效果）/\n" +
        "  until_addr（需 target）/ manual（只拍 before，之后用 once 出差分）。\n" +
        "· force_continue —— 在某点强制写寄存器再继续（set:[{reg,value}]，then=continue/step_into/step_over，\n" +
        "  repeat=N 让被混淆提前打断的循环跑满）。可配 bp_addr。\n" +
        "· global_reads —— 统计某函数引用了哪些**全局元素**及步长。若元素数 < 一行宽度，\n" +
        "  说明该函数只校验一行/一块，调用方在循环里喂多次（据此去找漏掉的常量）。\n" +
        "STATE：-1=已暂停（可单步/run_to/写内存）、0=无进程、1=运行中（单步与写内存会失败）、2=已退出。\n" +
        "continue/run_to 已自动轮询到真正停下：返回 stopped:true 才能继续单步；state:1 表示仍在跑，需 suspend。\n" +
        "本地 PE：start 后停在入口。远程 ELF：start 后不停，工具自动 suspend；断点要用重定位地址（见 start 返回的 symbols）。",
      input_schema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            enum: ["start", "exit", "continue", "run_to", "step_into", "step_over",
                   "status", "suspend",
                   "bp_list", "bp_add", "bp_del", "bp_toggle", "regs", "regs_named", "stack",
                   "clear_remote",
                   "snapshot_diff", "force_continue", "global_reads"],
            description: "调试动作。status=查状态；suspend=把运行中的进程停下（GUI 程序必须）；" +
              "clear_remote=清残留远程配置；snapshot_diff/force_continue/global_reads=运行期探测（见工具说明）"
          },
          addr: { type: "string", description: "run_to 的目标地址 / bp_add 的单地址" },
          addrs: { description: "断点地址：字符串或字符串数组（如 '0x401000,0x401010'）" },
          items: { description: "bp_toggle 的条目：[{addr, enabled}]（也接受地址数组）" },
          regs: { type: "string", description: "regs_named 的寄存器名，逗号分隔（如 'RAX,RBX'）" },
          regions: {
            description: "snapshot_diff 要快照的内存区：[{addr,size}] 或 ['0x13200']。size 缺省 256"
          },
          size: { type: "number", description: "snapshot_diff 单区字节数（配 addr 使用，默认 256）" },
          target: { type: "string", description: "snapshot_diff mode=until_addr 的目标地址" },
          set: {
            description: "force_continue 要写的寄存器：[{reg:'eax', value:1}]"
          },
          then: {
            type: "string", enum: ["continue", "step_into", "step_over", "none"],
            description: "force_continue 改完寄存器后的动作（默认 continue）"
          },
          repeat: { type: "number", description: "force_continue 重复次数（默认 1，上限 200）" },
          bp_addr: { type: "string", description: "force_continue 先在该地址下断点" },
          func: { type: "string", description: "global_reads 的函数名或地址" },
          limit: { type: "number", description: "global_reads 最多列出的引用数（默认 512）" },
          mode: {
            type: "string",
            enum: ["local", "remote"],
            description: "start 的调试模式。local=Local Windows debugger（PE）；remote=Remote GDB（ELF，需要 Kali 上跑 gdbserver）。不填则按目标类型自动选"
          },
          remote_host: { type: "string", description: "remote 模式的 gdbserver 主机（通常是 Kali 的 IP）" },
          remote_port: { type: "number", description: "remote 模式的 gdbserver 端口（默认 23946）" },
          remote_pass: { type: "string", description: "remote 模式的密码（gdbserver 未设密码则留空）" },
          target_kind: { type: "string", enum: ["PE", "ELF"], description: "显式声明目标类型，覆盖自动推断" },
          path: {
            type: "string",
            description: "start 时要调试的可执行文件路径；**留空表示调试 IDA 当前已加载的数据库**（主进程不持有当前文件路径）"
          },
          file: { type: "string", description: "path 的别名" },
          args: { type: "string", description: "start 时传给进程的命令行参数" },
          cwd: { type: "string", description: "start 时进程的工作目录" }
        },
        required: ["action"]
      }
    },
    {
      name: "ida_dbg_mem",
      description:
        "IDA 调试器内存读写。action=read：regions=[{addr,size}] 或 addr+size，返回 hex（带空格）；" +
        "action=write：regions=[{addr,data}] 或 addr+data，data 接受 'abcd' / 'ab cd' / 字节数组。",
      input_schema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["read", "write"], description: "read 或 write" },
          regions: { description: "read: [{addr,size}]；write: [{addr,data}]（单对象也接受）" },
          addr: { type: "string", description: "单区域时的地址" },
          size: { type: "number", description: "read 时单区域的大小（默认 16）" },
          data: { description: "write 时单区域的数据（hex 串/字节数组）" }
        },
        required: ["action"]
      }
    },
    // ========== 远程 / 流量 ==========
    {
      name: "remote_exec",
      description:
        "执行命令。host='kali' 走 SSH（config.kali），host='local' 走本地 shell。默认 20s 超时。" +
        "失败返回固定前缀：REMOTE_TIMEOUT / REMOTE_AUTH / REMOTE_REFUSED / REMOTE_UNCONFIGURED（均为错误）。",
      input_schema: {
        type: "object",
        properties: {
          host: { type: "string", enum: ["kali", "local"], description: "执行位置（默认 local）" },
          command: { type: "string", description: "要执行的命令" },
          timeout_ms: { type: "number", description: "超时毫秒（默认 20000）" }
        },
        required: ["command"]
      }
    },
    {
      name: "traffic_extract",
      description:
        "解析 pcap/pcapng：每流给端口/包数/字节数/熵/hex 预览（预览 ≤2048B，总输出 ≤24000 字符，超限落盘并给路径）。" +
        "protocol: auto|http|tcp。样本是二进制协议时 http=0，不要当 Web 流量。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "pcap/pcapng 文件绝对路径" },
          protocol: { type: "string", enum: ["auto", "http", "tcp"], description: "流过滤（默认 auto）" },
          max_flows: { type: "number", description: "最多返回的流数（默认 20）" }
        },
        required: ["path"]
      }
    },
    // ========== 变换链 / 解码（CyberChef 式有界操作组合） ==========
    {
      name: "recipe",
      description:
        "按顺序执行一条**变换链**（CyberChef 式），一次拿到每一层的 printable/entropy/hex/preview。" +
        "用途：别再手写 base64→xor→反转→解压 这类重复脚本。\n" +
        "输入：input（字符串或 hex/base64，用 input_encoding 指定）；recipe=[{op, ...参数}]。\n" +
        "常用 op：from_hex/to_hex、from_base64/to_base64、from_base32、custom_base64(alphabet)、" +
        "url_decode、gunzip、zlib_inflate、zlib_deflate_raw、reverse、reverse_each_4、" +
        "xor(key,key_encoding)、add(key)、sub(key)、rot(n)、bit_shift(n,direction)、" +
        "slice(start,end)、utf16le_decode、to_upper/to_lower/trim、hash(algo)、" +
        "crack(algo,dictionary)（有界字典反查，未命中原样返回）。\n" +
        "auto=true 时忽略 recipe，自动试常见解码链并返回所有可打印结果（有界，不猜 xor key）。\n" +
        "整链上限 20 步；任一步失败会指到具体步号，不会静默跳过。",
      input_schema: {
        type: "object",
        properties: {
          input: { type: "string", description: "输入数据（文本；二进制用 input_encoding=hex/base64）" },
          input_encoding: { type: "string", enum: ["utf8", "hex", "base64", "latin1"], description: "输入编码（默认 utf8）" },
          recipe: {
            type: "array",
            description: "操作链，如 [{op:'from_base64'},{op:'xor',key:'0a'},{op:'to_hex'}]",
            items: { type: "object" }
          },
          auto: { type: "boolean", description: "true = 自动尝试常见解码链（忽略 recipe）" },
          max_steps: { type: "number", description: "链长上限（默认 20，最大 50）" }
        },
        required: []
      }
    },
    // ========== GUI 输入注入（动态调试前置） ==========
    {
      name: "gui_input",
      description:
        "给正在运行的 GUI 程序**喂输入并触发按钮**，用于动态调试对话框类题目。\n" +
        "为什么需要：CrackMe 这类题的校验只在按钮点击（WM_COMMAND）时执行；" +
        "程序启动后阻塞在消息循环，dbg_run_to(校验地址) 会永远等不到。必须先把输入喂进去。\n" +
        "推荐流程：ida_dbg(action='start') → gui_input(list_only:true 看控件) → " +
        "gui_input(text+submit) → ida_dbg(action='continue') → 断点命中后 regs/mem_read。\n" +
        "⚠️ 只对**标准控件**（Edit/Button）有效；自绘 UI、Qt 自绘窗口、游戏引擎不吃这套。" +
        "这是模拟用户操作，程序逻辑一步不少跑。\n" +
        "实现细节：默认用 PostMessage（进程被调试器挂起时 SendMessage 会阻塞到超时）；" +
        "需要同步效果可设 send_message:true（内部用 SendMessageTimeout，带 800ms 上限）。",
      input_schema: {
        type: "object",
        properties: {
          pid: { type: "number", description: "目标进程 PID（list_only:true 时可看到）" },
          title_contains: { type: "string", description: "窗口标题包含的子串（与 pid 二选一，pid 优先）" },
          text: { type: "string", description: "要填入输入框的文本" },
          control_id: { type: "number", description: "指定控件 ID（GetDlgCtrlID）；不填则取第一个 Edit" },
          submit: { type: "boolean", description: "是否点击按钮（默认 true；按 OK/确定/提交/验证 优先匹配）" },
          list_only: { type: "boolean", description: "只列出窗口与控件，不注入（先用它确定 pid/控件）" },
          send_message: { type: "boolean", description: "用 SendMessageTimeout 而非 PostMessage（默认 false）" },
          send_timeout_ms: { type: "number", description: "send_message 时的超时（默认 800ms）" }
        },
        required: []
      }
    },
    // ========== 对称加密 / 摘要（离线，等价 toolhelper 加解密页） ==========
    {
      name: "crypto",
      description:
        "离线加解密与摘要（等价于在线工具的 AES/SM4/哈希页面，但**在本机算**，密文不出网）。\n" +
        "op=symmetric：algo=aes|des|tripledes|rc4|rabbit，action=encrypt|decrypt，可指定 mode=cbc|ecb|cfb|ofb|ctr、padding=pkcs7|none|zeros|iso10126|ansix923。\n" +
        "op=sm4：国密 SM4，mode=ecb|cbc（sm-crypto 只支持这两种）。\n" +
        "op=digest：md5|sha1|sha224|sha256|sha384|sha512|sha3|ripemd160|sm3|crc32（单向）。\n" +
        "op=hmac：md5|sha1|sha256|sha512|sha3。\n" +
        "格式：key_format/iv_format/data_format 取 utf8|hex|base64|latin1；缺省 key/iv 按 utf8、data 按 utf8、输出按 hex。\n" +
        "⚠️ **哈希不可逆**：本工具只能正向计算。要反查弱口令用 recipe 的 crack（有界字典）。\n" +
        "⚠️ 解密输出是二进制时自动给 hex；data_format 要与密文实际编码一致，否则得到乱码而不是报错。",
      input_schema: {
        type: "object",
        properties: {
          op: { type: "string", enum: ["symmetric", "sm4", "digest", "hmac"], description: "操作类型" },
          algo: { type: "string", description: "算法名（见描述）" },
          action: { type: "string", enum: ["encrypt", "decrypt"], description: "symmetric/sm4 的动作" },
          data: { type: "string", description: "输入数据" },
          data_format: { type: "string", enum: ["utf8", "hex", "base64", "latin1"], description: "输入编码（默认 utf8）" },
          key: { type: "string", description: "密钥" },
          key_format: { type: "string", enum: ["utf8", "hex", "base64", "latin1"], description: "密钥编码（默认 utf8）" },
          iv: { type: "string", description: "初始向量（CBC/CFB/OFB/CTR 必填）" },
          iv_format: { type: "string", enum: ["utf8", "hex", "base64", "latin1"], description: "IV 编码（默认 utf8）" },
          mode: { type: "string", description: "分组模式（默认 cbc；ecb 不需要 iv）" },
          padding: { type: "string", description: "填充（默认 pkcs7）" },
          output_format: { type: "string", enum: ["hex", "base64", "utf8", "latin1"], description: "输出编码（默认 hex）" }
        },
        required: ["op"]
      }
    },
    // ========== 浏览器 MCP 工具 ==========
    {
      name: "browser_search",
      description: "搜索网页，用于查找CTF题解、算法信息等",
      input_schema: {
        type: "object",
        properties: {
          query: { type: "string", description: "搜索关键词" }
        },
        required: ["query"]
      }
    },
    {
      name: "browser_open",
      description: "打开网页并获取内容",
      input_schema: {
        type: "object",
        properties: {
          url: { type: "string", description: "网页URL" }
        },
        required: ["url"]
      }
    },
    // ========== 命令执行工具 ==========
    {
      name: "run_command",
      description: "执行系统命令，可用于运行脚本、分析文件等",
      input_schema: {
        type: "object",
        properties: {
          command: { type: "string", description: "要执行的命令" }
        },
        required: ["command"]
      }
    },
    {
      name: "run_python",
      description: "执行Python脚本，可用于解密、数据分析等。脚本里的相对路径默认落在当前题目的 scripts/ 目录（产物会自动登记为 evidence）。",
      input_schema: {
        type: "object",
        properties: {
          script: { type: "string", description: "Python脚本内容" },
          cwd: { type: "string", description: "可选：工作目录（默认 <caseDir>/scripts；不传就走默认）" }
        },
        required: ["script"]
      }
    },
    // ========== ADB/Frida 工具 ==========
    {
      name: "adb_command",
      description: "执行ADB命令，用于操作安卓模拟器",
      input_schema: {
        type: "object",
        properties: {
          command: { type: "string", description: "ADB命令参数" }
        },
        required: ["command"]
      }
    },
    {
      name: "frida_hook",
      description: "执行Frida Hook脚本，用于动态分析",
      input_schema: {
        type: "object",
        properties: {
          script: { type: "string", description: "Frida Hook脚本内容" },
          target: { type: "string", description: "目标应用包名或进程名" }
        },
        required: ["script"]
      }
    },
    // ========== Skills 知识库 ==========
    {
      name: "read_skill",
      description: "读取一个技能（skill）的完整方法论文档。可用技能由系统提示中的技能索引列出，如 ctf-writeup、ctf-reverse-android、ctf-jsreverse 等。写题解、卡题换路、识别算法前建议先读取对应技能。",
      input_schema: {
        type: "object",
        properties: {
          name: { type: "string", description: "技能名称" }
        },
        required: ["name"]
      }
    },
    // ========== Wiki 知识库（可检索的手法/代码片段/踩坑） ==========
    {
      name: "wiki_search",
      description: "在知识库 wiki 里按关键词检索相关页面（返回标题+摘要+路径）。适合查具体手法与已验证代码片段，例如 'frida 进程内解密'、'IV 长度 incorrect'、'native 常量反演 key'、'多阶段 APK 停在首页'。命中后用 wiki_read 读整页。",
      input_schema: {
        type: "object",
        properties: {
          query: { type: "string", description: "关键词（空格分隔，可用中文）" },
          max: { type: "number", description: "最多返回页数，默认 5" }
        },
        required: ["query"]
      }
    },
    {
      name: "wiki_read",
      description: "读取知识库 wiki 某一页的完整内容（path 用 wiki_search 返回的相对路径，如 frida/in-process-decrypt.md）。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "知识页相对路径或页名" }
        },
        required: ["path"]
      }
    },
    // ========== Burp MCP 工具（Web/JS 逆向） ==========
    {
      name: "burp_get_history",
      description: "搜索 Burp 代理历史（HTTP 请求列表），用于定位带加密参数（sign/token/...）的请求和对应 JS 文件 URL。JS 逆向第一步。",
      input_schema: {
        type: "object",
        properties: {
          filter: { type: "string", description: "URL/关键词过滤，可空" },
          max: { type: "number", description: "最多返回条数，默认50" }
        },
        required: []
      }
    },
    {
      name: "burp_get_message",
      description: "获取 Burp 中某条 HTTP 报文详情（请求+响应），用于提取 JS 内容或加密参数原文。",
      input_schema: {
        type: "object",
        properties: {
          id: { type: "string", description: "报文 ID/索引（来自 burp_get_history）" }
        },
        required: ["id"]
      }
    },
    {
      name: "burp_call",
      description: "直接调用 Burp MCP 暴露的任意工具（真实工具名以连接时 tools/list 发现为准）。",
      input_schema: {
        type: "object",
        properties: {
          tool: { type: "string", description: "Burp MCP 工具名" },
          args: { type: "object", description: "工具参数" }
        },
        required: ["tool"]
      }
    },
    {
      name: "switch_to_next_stage",
      description: "多阶段题目接力：当你解出/提取出一个新的可执行文件（如壳解出的 stage2.exe、解密出的内嵌 PE/DEX/payload），调用本工具把分析切换到该文件。工具会：关闭当前 IDA/JEB 进程（释放端口）、保留你在本阶段的全部结论作为下一阶段的上下文、并以新文件建立新的分析上下文自动继续求解。层数上限 3 层。注意：同一文件不要重复接力；不确定是否有新阶段时不要调用。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "新阶段文件的绝对路径（必须已存在于磁盘）" },
          reason: { type: "string", description: "为什么判定这是下一阶段载体（如「stage1 XOR 7 解出内嵌 PE，MZ 头完整」）" },
          carried: { type: "string", description: "可选：本阶段应传给下一阶段的关键结论摘要（已识别的算法/常量/密钥/decoy 提示/已排除的路）。不填则由工具自动从你的分析文本提炼。" }
        },
        required: ["path", "reason"]
      }
    },
    // ========== 确定性分析能力（AI 主动调用）==========
    // 为什么把这些暴露成工具：此前它们只作为"工具在提示词里喂给 AI 的结论"，
    // AI 无法在解题过程中主动复查/追问（例如换了一个提取出的新文件、或想确认某段字节里有什么）。
    {
      name: "scan_crypto",
      description:
        "【确定性算法指纹扫描】直接读文件字节，返回：①已知算法常量命中（SM4 FK/S盒、AES、SM3、TEA、CRC32…）" +
        "②自定义分组密码的常量差分分析（S 盒与标准表的关系、轮常量表位置与精确差分如「标准 CK 每字节+0x1」、FK 候选、字节序线索）" +
        "③编码存储的内嵌载荷（XOR/ADD/旋转/Base64/Hex 文本/ELF/DEX/shellcode，含可直接运行的提取脚本）" +
        "④高熵常量块。不依赖 IDA，可在任何时刻对任何文件调用（包括你刚提取出的新文件）。" +
        "用途：在写脚本之前先拿到确定性结论，避免凭猜测试算法。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "要扫描的文件绝对路径" }
        },
        required: ["path"]
      }
    },
    {
      name: "extract_payload",
      description:
        "【内嵌载荷提取】按 scan_crypto 报告的编码参数（offset/编码方式/步长/密钥/长度）解码并写出文件，" +
        "自动校验头部魔数（MZ/ELF/DEX）。适合多阶段题提取下一层。若不传参数，则自动选用 scan_crypto 的最佳候选。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "载体文件绝对路径" },
          out: { type: "string", description: "输出文件路径（默认写到临时目录）" },
          offset: { type: "number", description: "可选：载荷起始文件偏移（十六进制可写 0x...）" },
          length: { type: "number", description: "可选：要解码的字节数" },
          kind: { type: "string", description: "可选：编码方式 xor|add|periodic-xor|rolling-xor|rolling-add|base64|hex|none" },
          key: { type: "string", description: "可选：密钥（单字节填数字，周期编码填逗号分隔）" },
          stride: { type: "number", description: "可选：表项步长 1|2|4" }
        },
        required: ["path"]
      }
    },
    {
      name: "gen_block_cipher_solver",
      description:
        "【分组密码解密脚本生成（多骨架）】按结构推理结果生成可运行解密脚本：" +
        "· SM4 骨架：枚举 密文×FK×key×16 种字节序/状态组合×3 种块内排列（已实战验证）" +
        "· AES 骨架：枚举 key 长度 16/24/32（轮数 10/12/14）× 字节序/状态排列（仅标准轮数；轮数或 MixColumns 被改需手写）" +
        "· DES/Blowfish：**不支持**（会明确告知，不要假装能解）" +
        "用法：先 scan_crypto + analyze_structure 确认骨架，再调用本工具（可传 skeleton 参数覆盖默认选择），" +
        "然后 bash/run_python 跑生成的脚本。未命中不代表算法认错。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "含该密码结构的文件绝对路径" },
          skeleton: { type: "string", description: "可选：强制指定骨架 sm4|aes（默认按结构推理选择）" },
          out: { type: "string", description: "可选：脚本输出路径（默认写到临时目录）" }
        },
        required: ["path"]
      }
    },
    {
      name: "gen_sm4_solver",
      description:
        "【已改名】请改用 gen_block_cipher_solver（支持 SM4 与 AES 骨架；本名保留兼容，行为等价于 skeleton='sm4'）。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "含该密码结构的文件绝对路径" },
          out: { type: "string", description: "可选：脚本输出路径" }
        },
        required: ["path"]
      }
    },
    {
      name: "analyze_structure",
      description:
        "【分组密码结构推理】基于 scan_crypto 的常量分析结果，推断" +
        "「这是哪个分组密码骨架」（SM4 / AES / 未知）并给出置信度与证据：" +
        "轮常量表形态（SM4 CK 固定差分 / AES Rcon）、S 盒与标准表的关系、字节序线索。" +
        "输出的是**假设**（按证据强度排序），最终路线由你决定。" +
        "前置：先对该文件调用过 scan_crypto。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件绝对路径（应已做过 scan_crypto）" }
        },
        required: ["path"]
      }
    },
    {
      name: "junk_scan",
      description:
        "【花指令识别】扫描代码区，报告花指令（junk code / opaque predicate）候选。" +
        "当出现以下信号时调用：反编译失败、IDA 提示 'sp-analysis failed'、伪代码明显错乱、" +
        "代码段出现成片 1~2 字节'指令'、函数边界识别错误。" +
        "默认走**递归下降**（从 entry/函数入口沿控制流展开）——线性扫描一旦偏 1 字节后续全错；" +
        "推不出更多入口时会报告'不可达区间'，那些就是花指令垃圾块的候选位置。" +
        "**强烈建议给 entries（函数入口文件偏移）**，范围越全识别越准。" +
        "判据通用：确定标志位+短跳过（xor/test/cmp 后接 jcc 且跳过 ≤2 字节）、" +
        "互补跳转对（jz/jnz 成对且一侧落进垃圾）、跳转目标不落在指令边界（边界歧义=解码错位证据）。" +
        "**只报告不修改文件**。注意：'call $+5; pop reg' 是 PIC 取址，不是花指令，已排除。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件绝对路径" },
          start: { type: "number", description: "代码区起始**文件偏移**（可选；缺省从节表推断）" },
          end: { type: "number", description: "代码区结束文件偏移（可选）" },
          entries: {
            type: "array", items: { type: "number" },
            description: "函数入口的**文件偏移**数组（可选但强烈建议）。" +
              "可由 ida_list_functions 的地址换算（PE: addr-ImageBase-节VA+节rawPtr；ELF: addr-sh_addr+sh_offset）。"
          },
          mode: { type: "string", description: "recursive（默认，推荐）/ linear（兜底）" }
        },
        required: ["path"]
      }
    },
    {
      name: "junk_patch",
      description:
        "【花指令修补】按 junk_scan 的候选把花指令整段 patch 成 0x90（nop），写出新文件（原文件不动）。" +
        "默认只处理 high 置信度且带安全 nop 范围的候选；call/ret 跳板类只会报告、不会自动改" +
        "（盲 nop 会破坏返回地址）。修补后应让 IDA 重新分析新文件（或对原进程 patch 内存）。" +
        "**前置：必须先调用过 junk_scan 并确认候选合理。**",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件绝对路径" },
          start: { type: "number", description: "代码区起始文件偏移（须与 junk_scan 一致）" },
          end: { type: "number", description: "代码区结束文件偏移（须与 junk_scan 一致）" },
          out: { type: "string", description: "输出文件路径（可选，默认 <原名>_patched.<ext>）" },
          minConfidence: { type: "string", description: "最低置信度：high（默认）/ medium / low" }
        },
        required: ["path"]
      }
    },
    {
      name: "junk_repair",
      description:
        "【花指令修补·推荐】按特征库识别花指令并修复：只把假跳转/垃圾序列替换成等长 NOP，其它字节一个不动" +
        "（字节偏移完全不变、语义不变）。实测 Matr1x：非边界跳转目标 301→70（-76.7%），" +
        "IDA 识别函数 54→90，可反编译函数 35→50。" +
        "**为什么不能整段 nop**：把前序 xor/test 一起清掉会让后续指令重新错位（实测不可解码 4→7）。" +
        "写盘后会自动让 IDA 重新分析修补后的文件，并给出修复前后同口径对比。" +
        "返回里带每条修补的判定证据与 features 统计。",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "文件绝对路径" },
          start: { type: "number", description: "代码区起始文件偏移（可选，缺省从节表推断）" },
          end: { type: "number", description: "代码区结束文件偏移（可选）" },
          out: { type: "string", description: "输出文件路径（可选，默认 <原名>_repaired.<ext>）" },
          dryRun: { type: "boolean", description: "true=只报告不写文件" },
          features: {
            type: "array", items: { type: "string" },
            description: "启用的特征（可选）：false_jump / short_skip / junk_after_jcc / dead_push_pop / opaque_pair。缺省=全部安全特征。"
          }
        },
        required: ["path"]
      }
    },
    {
      name: "angr_solve",
      description:
        "生成一份 angr 符号执行求解脚本（不直接执行；用 run_python 跑它）。\n" +
        "**什么时候用**：混淆太重、静态读不出算法，但知道\"成功分支在哪\"——让符号执行直接反求输入。\n" +
        "**关键设计（避开两个实测坑）**：\n" +
        "1) 用 call_state 从主函数进入，**不用 entry_state**：entry 会先进 __libc_start_main，\n" +
        "   该调用不返回，simulation manager 直接耗尽（Matr1x 实测 0 个 state）。\n" +
        "2) 支持 hook 间接跳转点：被混淆的函数常有\"经全局函数指针的间接跳转\"，angr 会顺指针\n" +
        "   把常量表的字节当代码解码，报 IR decoding error。用 hooks 指定这些点后，脚本只按真实目标走。\n" +
        "参数：binary（目标路径）、find（成功分支地址，必填）、avoid（失败分支地址）、\n" +
        "main（主函数地址，缺省用 ELF entry）、hooks（[{addr,kind:'opaque_jump'|'nop',length}]）、\n" +
        "base（PIE 基址）、stdin_len（符号输入长度）、timeout（秒）。\n" +
        "返回里带 script 与 notes；脚本自带到点复核（VERIFY_FOUND）。",
      input_schema: {
        type: "object",
        properties: {
          binary: { type: "string", description: "目标文件路径（远端求解时用远端路径）" },
          find: { description: "成功路径地址（字符串/数字，或数组）——通常是打印 flag 的分支" },
          avoid: { description: "失败路径地址（字符串/数字，或数组）" },
          main: { type: "string", description: "主函数地址（call_state 入口）。缺省用 ELF entry" },
          base: { type: "string", description: "PIE 基址（如 0x400000）。缺省用 angr 推断" },
          hooks: {
            type: "array",
            items: {
              type: "object",
              properties: {
                addr: { type: "string", description: "间接跳转点地址" },
                kind: { type: "string", enum: ["opaque_jump", "nop"], description: "opaque_jump=按真实目标直跳；nop=当作空操作" },
                length: { type: "number", description: "该点指令长度（用于 hook 覆盖范围）" }
              },
              required: ["addr"]
            },
            description: "要显式处理的间接跳转点（避免 angr 把数据当代码）"
          },
          stdin_len: { type: "number", description: "符号化输入长度（默认 64）" },
          timeout: { type: "number", description: "求解秒数（默认 300）" }
        },
        required: ["binary", "find"]
      }
    }
  ];
}

// 发送Claude请求（带工具定义）—— 复用统一传输层与解析
async function sendClaudeRequestWithTools(messages, systemPrompt, tools, onDelta, opts = {}) {
  const cfg = getClaudeConfig();
  const requestBody = {
    model: opts.model || cfg.model,
    max_tokens: Number(opts.maxTokens) || cfg.max_tokens,
    messages: messages,
    tools: tools
  };
  // 与 sendClaudeRequest 同一约束：Tool-Use 轮的推理叙述也必须中文
  const sysWithZh = withChineseOutput(systemPrompt);
  if (sysWithZh) requestBody.system = sysWithZh;

  const resp = await claudeTransport(requestBody, onDelta);
  return parseClaudeResult(resp);
}

// 执行工具调用
async function executeToolCall(toolName, input) {
  try {
    switch (toolName) {
      // ========== 文件操作工具 ==========
      case 'read_file':
        return readFile(input.path);

      case 'write_file':
        return writeFile(input.path, input.content);

      case 'bash':
        return execCommandAsync(input.command);

      case 'glob':
        return globFiles(input.pattern);

      case 'grep':
        return grepFiles(input.pattern, input.path);

      // ========== JEB MCP 工具 ==========
      case 'jeb_get_manifest':
        return await callJebPlugin('get_manifest', [input.filepath]);

      case 'jeb_get_class_decompiled':
        return await callJebPlugin('get_class_decompiled_code', [input.filepath, input.class_signature]);

      case 'jeb_get_method_decompiled':
        return await callJebPlugin('get_method_decompiled_code', [input.filepath, input.method_signature]);

      case 'jeb_get_exported_activities':
        return await callJebPlugin('get_all_exported_activities', [input.filepath]);

      case 'jeb_get_all_classes':
        return await callJebPlugin('get_all_classes', [input.filepath]);

      case 'jeb_get_class_methods':
        return await callJebPlugin('get_class_methods', [input.filepath, input.class_signature]);

      // ========== IDA MCP 工具 ==========
      case 'ida_decompile':
        return await callIdaMcp('decompile', { address: input.function_name });

      case 'ida_list_functions':
        return await idaMcpCallPaged('list_functions', {});

      case 'ida_find_strings':
        return await callIdaMcp('find_strings', { pattern: input.regex });

      case 'ida_get_xrefs':
        return await callIdaMcp('xrefs_to', { addr: input.address });

      case 'ida_get_bytes':
        return await idaGetBytes({ callMcp: callIdaMcp, writeTemp: writeTempFile, topLevelDir: currentWorkDir }, input);

      case 'ida_list_globals':
        return await idaMcpCallPaged('list_globals', {
          filter: input.filter || '',
          offset: input.offset,
          count: input.count,
        });

      case 'ida_open_file': {
        const p = String(input.path || input.file_path || '').trim();
        if (!p) return '参数错误：path 为空。请传入要打开的二进制绝对路径。';
        if (!fs.existsSync(p)) return `文件不存在: ${p}`;
        // 会话重定向按 MCP transport session 记录，必须复用同一个 sessionId；
        // idaMcpCallTool 内部会拿 idaMcpState.sessionId，正好是后续工具调用用的那个。
        const rr = await idaReloadAndWait(p, {
          newDatabase: input.new_database === true,
          timeout: input.timeout,
        });
        // 失败时首行必须是 FAILURE_PREFIXES 认得的"工具调用失败"，
        // 否则主循环会把它当成功结果继续（模型随后在旧 IDB 上反编译并误判）。
        if (!rr.ok) {
          return '工具调用失败: IDA 未能切换到目标文件\n' + rr.lines.join('\n');
        }
        return rr.lines.join('\n');
      }

      case 'ida_disasm': {
        const addr = String(input.address || '').trim();
        if (!addr) return '缺少 address 参数。请传入要反汇编的虚拟地址（如 0x402000）。';
        const maxInsn = Math.min(Math.max(Number(input.max_instructions) || 64, 1), 400);
        return await callIdaMcp('disasm', {
          addr,
          max_instructions: maxInsn,
          offset: Number(input.offset) || 0,
        });
      }

      case 'recover_string': {
        const { recoverComparedString } = require('./string-recover');
        let text = String(input.disasm || '');
        // func 模式：自己从 IDA 取反汇编，避免让模型把长文本搬来搬去（也避免它手动摘抄出错）
        if (!text.trim() && input.func) {
          const maxInsn = Math.min(Math.max(Number(input.max_instructions) || 400, 8), 2000);
          try {
            const r = await callIdaMcp('disasm', {
              addr: String(input.func).trim(),
              max_instructions: maxInsn,
              offset: 0,
            });
            text = typeof r === 'string' ? r : JSON.stringify(r);
          } catch (err) {
            throw new ToolCallError(`取反汇编失败: ${translateDbgError(err.message)}`);
          }
        }
        if (!text.trim()) {
          return 'recover_string 需要 disasm（反汇编文本）或 func（函数名/地址）之一。';
        }
        const res = recoverComparedString(text);
        const L = [];
        if (!res.ok) {
          L.push(`未提取到字符串：${res.reason}`);
          L.push(`（找到 ${res.pairs || 0} 条 byte ptr 比较/写入行）`);
          if (!res.pairs) {
            L.push('');
            L.push('可能的原因：');
            L.push('1. 这段代码不是"逐字节比较"（可能用 memcmp/strcmp，此时直接看字符串表）；');
            L.push('2. 反汇编语法不匹配（本工具识别 Intel 的 `cmp byte ptr [reg+disp], imm` 与 AT&T 的 `cmpb $imm,disp(%reg)`）；');
            L.push('3. 地址范围不够（增大 max_instructions）。');
          }
          return L.join('\n');
        }
        L.push('## 提取结果（逐字节比较还原）');
        L.push('');
        L.push('```');
        L.push(res.text);
        L.push('```');
        L.push('');
        L.push(`- 长度：${res.bytes.length} 字节`);
        L.push(`- 十六进制：${res.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
        L.push(`- 参与比较的指令：${res.pairs} 条`);
        if (res.gaps && res.gaps.length) {
          L.push(`- ⚠ 偏移不连续 ${res.gaps.length} 处（中间有跳过的字节，已按 0 占位）`);
        }
        if (res.warnings && res.warnings.length) {
          L.push('');
          L.push('## ⚠ 前缀提醒');
          for (const w of res.warnings) L.push('- ' + w.hint);
        }
        L.push('');
        L.push('**这是程序真正比较的字节**，以它为准；如果你在伪代码/笔记里写的是别的拼写，那是抄错了。');
        return L.join('\n');
      }

      case 'ida_dbg': {
        // ctx 让 start 能决定 local/remote：
        //   PE → Local Windows debugger；ELF 且配了 Kali → remote gdb（gdbserver）
        const cfgKali = config.kali || {};
        const dbgCtx = {
          targetKind: input.target_kind || idaDbgTargetKind(),
          remoteAvailable: !!(cfgKali.sshHost && cfgKali.sshPort),
          remoteHost: cfgKali.sshHost || '',
          remotePort: Number(cfgKali.gdbserverPort) || 23946,
          remotePass: cfgKali.sshPass || '',
        };
        const call = buildDbgCall(input.action, input, dbgCtx);
        if (call.error) return `参数错误：${call.error}`;
        const act = String(input.action || '').toLowerCase();
        // 运行态（STATE=1）下 step/run_to 必然失败（实测：Failed to step over / run to）。
        // 与其让 AI 拿到一句含糊的上游报错，不如提前拦下并给出确切下一步。
        if (/^(step_over|step_into|run_to)$/.test(act)) {
          const st = await readDbgState();
          if (st.on && st.state === 1) {
            throw new ToolCallError(
              `无法执行 ${act}：进程正在运行（STATE=1）。` +
              '先 ida_dbg(action="suspend") 把它停下（STATE 变 -1），再单步；' +
              '或先 bp_add 下断点再 continue，等命中后自动暂停。'
            );
          }
          if (st.on && st.state === 2) {
            throw new ToolCallError(`无法执行 ${act}：进程已退出（STATE=2），需要重新 ida_dbg(action="start")。`);
          }
        }
        try {
          const r = await callIdaMcp(call.tool, call.args);
          // py_eval 的 start 结果里 START_RC 才说明是否真的起来了：
          // 旧实现只看工具是否报错，会把 START_RC -1（静默失败）当成功。
          if (call.tool === 'py_eval' && /START_RC/.test(String(call.args && call.args.code || ''))) {
            const stdout = String((r && r.stdout) || '');
            const m = /START_RC\s+(-?\d+)/.exec(stdout);
            const already = /ALREADY_RUNNING True/.test(stdout);
            if (m && Number(m[1]) !== 1) {
              const rc = Number(m[1]);
              const stale = /STALE_OPTS (.*)/.exec(stdout);
              const hint = rc === 0
                ? '（启动被取消：进程选项里多半残留了上一次远程调试的 target 路径。' +
                  '本地模式已自动 set_process_options 复位；若仍失败，先 ida_dbg(action="clear_remote")）'
                : (stale && /192\.168|remote|linux/i.test(stale[1])
                  ? `；检测到残留远程配置 ${stale[1].slice(0, 120)}，先执行 ida_dbg(action="clear_remote")`
                  : '；若目标是 ELF，请用 mode="remote" 并给 remote_host（Kali 必先启动 linux_server）');
              throw new ToolCallError(`IDA 调试启动失败（START_RC=${rc}）${hint}`);
            }
            if (m && Number(m[1]) === 1) {
              // 本地 vs 远程的启动语义不同（均为实测）：
              //   本地 win32：start 后自动停在入口（STATE=-1），可直接单步
              //   远程 linux：start 后**不会**停在入口，进程直接跑（STATE=1），
              //              必须 suspend 才能单步/下断点。
              // 所以远程要立刻 suspend，抢在目标跑过关键代码之前固定它。
              const isRemote = /load_debugger\("linux"/.test(String(call.args && call.args.code || ''));
              if (isRemote && !already) {
                try {
                  await callIdaMcp('py_eval', { code: 'import ida_dbg\nprint("SUSP", ida_dbg.suspend_process())' });
                } catch (e) { /* suspend 失败下面靠轮询判断 */ }
              }
              const w = await waitDbgStop({ timeoutMs: already ? 3000 : 20000, intervalMs: 250, startupGraceMs: 1500 });
              const ip = await readDbgIp(2, 300);
              // 远程 PIE 目标需要重定位后的符号地址：start 前取到的静态地址下断点会失败（实测）。
              let symbols = null;
              if (isRemote && w.reason === 'suspended') {
                try {
                  const sym = await callIdaMcp('py_eval', {
                    code: 'import idaapi\n' +
                      'print("IMAGEBASE", hex(idaapi.get_imagebase()))\n' +
                      'for n in ("main", "start", "_start"):\n' +
                      '    ea = idaapi.get_name_ea(idaapi.BADADDR, n)\n' +
                      '    if ea != idaapi.BADADDR: print("SYM", n, hex(ea))',
                  });
                  const txt = String((sym && sym.stdout) || '');
                  const base = (/IMAGEBASE (0x[0-9a-fA-F]+)/.exec(txt) || [])[1];
                  const syms = {};
                  for (const line of txt.split('\n')) {
                    const mm = /SYM (\S+) (0x[0-9a-fA-F]+)/.exec(line);
                    if (mm) syms[mm[1]] = mm[2];
                  }
                  symbols = { imagebase: base, entries: syms };
                } catch (e) { /* 符号可选 */ }
              }
              return {
                started: true,
                already_running: already,
                mode: isRemote ? 'remote' : 'local',
                ip,
                state: w.state,
                state_name: dbgStateName(w.state),
                at_entry: w.reason === 'suspended',
                waited_ms: w.waitedMs,
                symbols,
                note: already
                  ? '调试器原本就在运行，未重复启动（start 幂等）'
                  : isRemote
                    ? (w.reason === 'suspended'
                      ? '远程已连接并已暂停（自动 suspend）。注意：PIE 目标的断点要用上面 symbols 里的重定位地址，' +
                        '用 idaapi.add_bpt（ida_dbg.add_bpt 对远程段返回 False）'
                      : '远程已连接但进程仍在运行。若目标是长时间 sleep/等待输入，可稍后 ida_dbg(action="suspend") 固定进程；' +
                        '若它很快就调用了目标函数，需要重新 start 并更早 suspend')
                    : (w.reason === 'suspended'
                      ? '已停在入口，可以 bp_add / step / run_to'
                      : '调试器已接管但进程仍在加载（未到入口）。稍后用 ida_dbg(action="status") 复查，' +
                        '或直接 ida_dbg(action="suspend") 停下'),
                raw: r,
              };
            }
          }

          // continue / run_to 是异步投递：插件返回的 ip 是投递前的旧值。
          // 必须轮询到真正停下，否则 AI 拿着旧 IP 去单步，必然失败（实测）。
          if (call.tool === 'dbg_continue' || call.tool === 'dbg_run_to') {
            const w = await waitDbgStop({ timeoutMs: Number(input.wait_ms) || 8000 });
            const ip = await readDbgIp(1, 200);
            const wantBpHit = act === 'run_to';
            if (w.reason === 'suspended') {
              const atTarget = wantBpHit && ip && String(input.addr || '').toLowerCase() === ip;
              return {
                ip,
                state: -1,
                stopped: true,
                hit_target: wantBpHit ? !!atTarget : undefined,
                waited_ms: w.waitedMs,
                note: atTarget || !wantBpHit
                  ? '已暂停，可以 step / regs / mem_read'
                  : `暂停在 ${ip}，不是请求的 ${input.addr}`,
              };
            }
            if (w.reason === 'exited') {
              return { ip, state: 2, stopped: true, exited: true, note: '进程已退出' };
            }
            if (w.reason === 'no-process') {
              return { ip, state: 0, stopped: true, note: '调试器已不在运行' };
            }
            // 还在运行：GUI 程序进消息循环等输入时是常态，不是错误。
            return {
              ip,
              state: 1,
              stopped: false,
              waited_ms: w.waitedMs,
              note: '进程仍在运行（未命中断点）。GUI 程序通常在等用户输入：' +
                '可以用 ida_dbg(action="suspend") 停下再单步，或用 gui_input 喂输入后等断点。',
            };
          }

          // status / suspend 的 py_eval 输出是逐行 key-value，转成结构化结果，
          // 免得 AI 每次自己解析 stdout。
          if (call.tool === 'py_eval' && (act === 'status' || act === 'suspend')) {
            const text = typeof r === 'string' ? r : String((r && r.stdout) || '');
            const st = /STATE\s+(-?\d+)/.exec(text);
            const ipm = /IP\s+(0x[0-9a-fA-F]+|None)/.exec(text);
            const on = /ON\s+True/.test(text);
            const stateNum = st ? Number(st[1]) : null;
            return {
              on,
              state: stateNum,
              state_name: dbgStateName(stateNum),
              ip: ipm ? ipm[1] : null,
              can_step: stateNum === -1,
              action: act,
              raw: text.trim(),
            };
          }

          // bp_add 现在走 py_eval + idaapi.add_bpt（远程后端下 dbg_add_bp 恒 False），
          // 把逐行输出转成 {addrs:[{addr,ok}], qty} 便于 AI 判断。
          if (act === 'bp_add' && call.tool === 'py_eval') {
            const text = typeof r === 'string' ? r : String((r && r.stdout) || '');
            const addrs = [];
            for (const line of text.split('\n')) {
              const m = /^BP (0x[0-9a-fA-F]+) (True|False)$/.exec(line.trim());
              if (m) addrs.push({ addr: m[1], ok: m[2] === 'True' });
              const err = /^BP_ERR (\S+) (.*)$/.exec(line.trim());
              if (err) addrs.push({ addr: err[1], ok: false, error: err[2] });
            }
            const qty = (/BP_QTY (\d+)/.exec(text) || [])[1];
            const failed = addrs.filter(a => !a.ok);
            if (failed.length) {
              throw new ToolCallError(
                `断点设置失败：${failed.map(a => a.addr).join(', ')}。` +
                '常见原因：地址不在 .text 段、PIE 目标用了未重定位的静态地址（先用 ida_dbg(action="start") 返回的 symbols）、' +
                '或目标已退出（用 ida_dbg(action="status") 确认 STATE=-1）'
              );
            }
            return { addrs, qty: qty ? Number(qty) : addrs.length, note: '断点已生效，可以 continue' };
          }

          return r;
        } catch (err) {
          if (err && err.__toolError) throw err;
          // IDA 9 的异步调试器：idaapi.step_over()/step_into() 在"命令已投递"时返回 False，
          // 但单步**确实执行了**（实测 IP 0x77d284cc → 0x4012d1）。插件按返回值判定 →
          // 报 "Failed to step over"，把成功当失败。
          // 判据改为**验证结果**：失败后读一次 IP，若与失败前不同即视为成功。
          const stepAction = /^step_(over|into)$/.test(String(input.action || '').toLowerCase());
          if (stepAction) {
            const rescued = await rescueStepFailure(call, err);
            if (rescued) return rescued;
          }
          // 上游失败必须如实报错（ToolCallError 会被主循环标 is_error）
          throw new ToolCallError(`IDA 调试调用失败: ${translateDbgError(err.message)}`);
        }
      }

      case 'angr_solve': {
        const { buildAngrScript } = require('./angr-gen');
        const r = buildAngrScript(input);
        if (r.error) return `参数错误：${r.error}`;
        const L = [];
        L.push('## angr 求解脚本已生成（未执行）');
        L.push('');
        L.push('```python');
        L.push(r.script);
        L.push('```');
        L.push('');
        L.push('## 用法');
        L.push('1. 把上面的脚本存成 `solve_angr.py`（用 write_file），或用 run_python 直接跑脚本内容');
        L.push('2. 目标在本机 → run_python；在 Kali → remote_exec');
        L.push('3. 看输出：`INPUT_HEX=` 就是能走到 find 的输入');
        L.push('');
        L.push('## 设计要点');
        for (const n of r.notes) L.push('- ' + n);
        return L.join('\n');
      }

      case 'ida_dbg_mem': {
        const act = String(input.action || '').toLowerCase() === 'write' ? 'mem_write' : 'mem_read';
        const call = buildDbgCall(act, input);
        if (call.error) return `参数错误：${call.error}`;
        // 写内存只在暂停态可靠：运行中写入会被目标覆盖或直接失败（实测）。
        if (act === 'mem_write') {
          const st = await readDbgState();
          if (!st.on) throw new ToolCallError('写内存失败：调试器未运行，先 ida_dbg(action="start")。');
          if (st.state === 1) {
            throw new ToolCallError(
              '写内存失败：进程正在运行（STATE=1），写入会被覆盖。' +
              '先 ida_dbg(action="suspend") 或下断点让进程停下，再写。'
            );
          }
        }
        try {
          const r = await callIdaMcp(call.tool, call.args);
          const text = typeof r === 'string' ? r : JSON.stringify(r);
          // dbg_read 返回无空格 hex（插件 data.hex()），统一加空格；write 回显原文
          if (act === 'mem_read') {
            return text.replace(/\b([0-9a-fA-F]{16,})\b/g, (m) => normalizeHex(m));
          }
          return text;
        } catch (err) {
          throw new ToolCallError(`IDA 调试内存调用失败: ${translateDbgError(err.message)}`);
        }
      }

      case 'remote_exec':
        return await remoteExecTool(input);

      case 'recipe': {
        // CyberChef 式变换链：一次调用跑完整条链，每一层都给可判读的指标。
        const { runRecipe, autoDecode } = require('./recipe');
        const raw = input.input == null ? '' : input.input;
        if (input.auto) {
          const hits = autoDecode(raw, { inputEncoding: input.input_encoding });
          if (!hits.length) return '自动解码：所有常见链都未产出可打印结果。可用 recipe 手动指定 op 链（例如 [{op:"from_hex"}]）。';
          return hits.map((h, i) =>
            `#${i + 1} ${h.chain}\n  len=${h.len} printable=${h.printable} entropy=${h.entropy}\n  hex=${h.hex}\n  preview=${h.preview}`
          ).join('\n\n');
        }
        const r = runRecipe(raw, input.recipe, {
          inputEncoding: input.input_encoding,
          maxSteps: input.max_steps,
        });
        const lines = r.steps.map(s =>
          `[${s.index}] ${s.op}${s.note ? ' — ' + s.note : ''}\n  len=${s.len} printable=${s.printable} entropy=${s.entropy}\n  hex=${s.hex}\n  preview=${s.preview}`
        );
        if (!r.ok) lines.push('ERROR: ' + r.error);
        if (r.output && r.output.text != null) {
          lines.push('\n=== 最终输出（可打印文本）===\n' + r.output.text.slice(0, 8000));
        }
        return lines.join('\n');
      }

      case 'crypto': {
        // 离线加解密/摘要。等价 toolhelper 的对称加密与哈希页，但数据不出本机。
        const { runCryptoTool } = require('./crypto-tool');
        const r = runCryptoTool(input);
        if (!r.ok) throw new ToolCallError(`crypto 失败: ${r.error}`);
        return r;
      }

      case 'gui_input': {
        // 动态调试前置：给 GUI 程序喂输入并触发按钮。
        // 默认 PostMessage —— 进程被调试器挂起时 SendMessage 会阻塞到超时（实测）。
        const { runGuiInput } = require('./gui-input');
        const r = runGuiInput(input, { tempDir: app.getPath('temp') });
        if (!r.ok) {
          const detail = [
            `gui_input 失败（${r.stage || 'unknown'}）: ${r.error}`,
            r.script_stderr ? `脚本 stderr: ${String(r.script_stderr).slice(0, 400)}` : '',
            r.script_stdout_tail ? `脚本输出尾部: ${String(r.script_stdout_tail).slice(0, 400)}` : '',
          ].filter(Boolean).join('\n');
          throw new ToolCallError(detail);
        }
        return JSON.stringify(r);
      }

      case 'traffic_extract': {
        const p = String(input.path || '').trim();
        if (!p) return '参数错误：path 为空';
        if (!fs.existsSync(p)) return `文件不存在: ${p}`;
        const r = trafficExtract(p, input);
        if (!r.success) return r.error;
        return r.result;
      }

      // ========== 浏览器 MCP 工具 ==========
      case 'browser_search':
        return await browserMcpSearchTool(input.query);

      case 'browser_open':
        return await browserMcpOpenTool(input.url);

      case 'browser_js': {
        try {
          const r = await cdpRunJs({ url: input.url, hookScript: input.hookScript, resultExpr: input.resultExpr, waitMs: input.waitMs });
          return JSON.stringify(r).slice(0, 6000);
        } catch (err) {
          return `browser_js 失败: ${err.message}`;
        }
      }

      // ══════ 可逆循环逆推 ══════
      case 'rev_solve': {
        const { buildRevSolveScript } = require('./rev-loop');
        const r = buildRevSolveScript(input);
        if (r.error) return `参数错误：${r.error}`;
        let saved = '';
        try {
          const dir = currentCaseDir || currentWorkDir;
          if (dir) {
            fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
            const p = path.join(dir, 'scripts', 'rev_solve.py');
            fs.writeFileSync(p, r.script, 'utf8');
            saved = p;
          }
        } catch (e) { /* 落盘失败不影响返回脚本 */ }
        const L = [];
        L.push('## rev_solve 脚本已生成（未执行）');
        L.push('');
        L.push('```python');
        L.push(r.script);
        L.push('```');
        L.push('');
        L.push(`参数：regs=${r.meta.regs.join(',')} / width=${r.meta.width} / rounds=${r.meta.rounds} / ops=${r.meta.opCount} 条`);
        L.push('');
        L.push('## 用法');
        L.push('`run_python({script:<上面的内容>})`，看三行输出：');
        L.push('- `SELFCHECK_OK` —— 正逆互逆通过（不通过说明算子表写错，别信后面的数）');
        L.push('- `VERIFY = PASS` —— 回代精确命中目标（这才算真解）');
        L.push('- `INPUT_TXT` / `INPUT_HEX` —— 解出的输入');
        if (saved) L.push(`（脚本已落盘：${saved}）`);
        L.push('');
        L.push('## 设计要点');
        for (const n of r.notes) L.push('- ' + n);
        return L.join('\n');
      }

      // ══════ 执行轨迹（分段 dispatch / VM 混淆的核心链路）══════
      // 生成脚本交给 run_python 跑（本机）或 remote_exec 跑（Kali）；
      // 这里不直接执行，因为目标可能是远程 ELF，且脚本可能跑几分钟。
      case 'emu_trace': {
        const { buildEmuTraceScript } = require('./emu-trace');
        const r = buildEmuTraceScript(input);
        if (r.error) return `参数错误：${r.error}`;
        // 顺手落盘到题目目录，AI 下一步可以直接 ida_apply_trace 读到
        let saved = '';
        try {
          const dir = currentCaseDir || currentWorkDir;
          if (dir) {
            fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
            const p = path.join(dir, 'scripts', 'emu_trace.py');
            fs.writeFileSync(p, r.script, 'utf8');
            saved = p;
          }
        } catch (e) { /* 落盘失败不影响返回脚本 */ }
        const L = [];
        L.push('## emu_trace 脚本已生成（未执行）');
        L.push('');
        L.push('```python');
        L.push(r.script);
        L.push('```');
        L.push('');
        L.push('## 用法');
        L.push('1. 目标在本机 → `run_python({script:<上面的内容>})`；在 Kali → `remote_exec({command:"python3 emu_trace.py"})`');
        L.push('2. 看输出：`TRACE_JSON=<path>` 是轨迹文件，`IND <src> -> N targets` 就是运行期算出的跳转表');
        L.push('3. 把轨迹交给 `ida_apply_trace({trace:<轨迹>})`，各段会连成可读的 CFG');
        if (saved) L.push(`（脚本已落盘：${saved}）`);
        L.push('');
        L.push('## 设计要点');
        for (const n of r.notes) L.push('- ' + n);
        return L.join('\n');
      }

      case 'ida_apply_trace': {
        const { buildApplyTraceScript, summarizeTrace } = require('./emu-trace');
        let tr = input.trace;
        // 允许 trace 传文件路径：主进程读盘，省得 AI 把大 JSON 塞回上下文
        if (typeof tr === 'string' && tr.trim() && !tr.trim().startsWith('{')) {
          try {
            tr = JSON.parse(fs.readFileSync(tr.trim(), 'utf8'));
          } catch (e) {
            throw new ToolCallError(`读取轨迹文件失败: ${tr}（${e.message}）`);
          }
        }
        const r = buildApplyTraceScript({ ...input, trace: tr });
        if (r.error) return `参数错误：${r.error}`;
        let out = '';
        try {
          out = await callIdaMcp('py_eval', r.args);
        } catch (err) {
          throw new ToolCallError(`回填轨迹失败: ${translateDbgError(err.message)}`);
        }
        const text = typeof out === 'string' ? out : JSON.stringify(out);
        const L = [];
        L.push('## 轨迹已回填到 IDA');
        L.push(text);
        L.push('');
        L.push(`统计：跳转目标 ${r.stats.indTargets} 个 / 控制流边 ${r.stats.edges} 条 / 执行区间 ${r.stats.ranges} 段`);
        if (r.stats.truncated.length) L.push(`⚠ 已截断：${r.stats.truncated.join(', ')}（轨迹过大；先用 stop_at 缩小范围再分段回填）`);
        L.push('');
        L.push('## 轨迹摘要（回填依据）');
        L.push(summarizeTrace(tr));
        L.push('');
        L.push('## 下一步');
        L.push('`ida_decompile` 原先读不懂的那个函数——各段现在应该已连成一片；');
        L.push('若仍有断段，用 `ida_apply_trace({trace, code_ranges:true})` 再补一轮。');
        return L.join('\n');
      }

      // ========== 命令执行工具 ==========
      case 'run_command':
        return await execCommandAsync(input.command);
      case 'run_python':
        return await runPythonScript(input.script, input.cwd);

      // ========== ADB/Frida 工具 ==========
      case 'adb_command':
        return await execAdbCommand(input.command);

      case 'frida_hook':
        return await execFridaHook(input.script, input.target);

      // ========== Skills 知识库 ==========
      case 'read_skill': {
        try {
          const skills = listSkillDirs();
          const skill = skills.find(s => s.name === input.name || s.dir === input.name);
          if (!skill) return `未找到技能: ${input.name}。可用: ${skills.map(s => s.name).join(', ')}`;
          const content = fs.readFileSync(skill.path, 'utf8');
          return content.length > 8000 ? content.slice(0, 8000) + '\n...[已截断]' : content;
        } catch (err) {
          return `读取技能失败: ${err.message}`;
        }
      }

      // ========== Wiki 知识库 ==========
      case 'wiki_search':
        return wikiSearch(input.query, input.max);

      case 'wiki_read':
        return wikiRead(input.path);

      // ========== Burp MCP 工具 ==========
      case 'burp_get_history':
        return await callBurpMcp('history', { filter: input.filter || '', max: input.max || 50 });

      case 'burp_get_message':
        return await callBurpMcp('message', { id: input.id, index: input.id });

      case 'burp_call':
        return await callBurpMcp(input.tool, input.args || {});

      // ========== 确定性分析能力（供 AI 主动调用）==========
      case 'scan_crypto':
        return scanCryptoCase({ fs, scanCrypto: scanCryptoFingerprints, inferCipherStructure }, input);

      case 'extract_payload': {
        const f = String(input.path || '').trim();
        if (!f) return '参数错误：path 为空';
        if (!fs.existsSync(f)) return `文件不存在: ${f}`;
        // 未给参数时自动选 scan_crypto 的最佳候选
        let spec = null;
        if (input.offset != null || input.kind) {
          const normNum = (v) => typeof v === 'string' ? Number(v) : Number(v);
          spec = {
            type: 'payload',
            offset: normNum(input.offset || 0),
            length: input.length != null ? normNum(input.length) : 0,
            encode: {
              kind: input.kind || 'none',
              key: input.key == null ? null
                : (String(input.key).includes(',') ? String(input.key).split(',').map(x => normNum(x.trim()))
                  : normNum(input.key)),
              stride: input.stride ? normNum(input.stride) : 1,
              period: 1,
            },
          };
        } else {
          const sc = scanCryptoFingerprints(f);
          const best = (sc && sc.payloads || []).find(p => ['pe', 'elf', 'dex'].includes(p.type));
          if (!best) return '未在文件中找到可提取的载荷。请先用 scan_crypto 查看，或显式提供 offset/kind。';
          spec = best;
        }
        const buf = fs.readFileSync(f);
        const py = buildPayloadExtractPython(spec);
        if (!py) return `不支持的编码方式: ${spec.encode && spec.encode.kind}（支持 xor/add/periodic-xor/rolling-xor/rolling-add/base64/hex/none）`;
        const outPath = String(input.out || '').trim() || path.join(app.getPath('temp'), `payload_${spec.offset.toString(16)}.bin`);
        const scriptPath = path.join(app.getPath('temp'), `extract_${Date.now().toString(36)}.py`);
        fs.writeFileSync(scriptPath, py, 'utf8');
        const rr = spawnSync('python', [scriptPath, f, outPath], { encoding: 'utf8', timeout: 120000 });
        const out = ((rr.stdout || '') + (rr.stderr ? '\n' + rr.stderr : '')).trim();
        try { fs.unlinkSync(scriptPath); } catch (e) { /* 忽略 */ }
        if (!/^OK\b/m.test(out)) return `提取失败:\n${out.slice(0, 1000)}`;
        const head = (() => { try { return fs.readFileSync(outPath).slice(0, 4).toString('hex'); } catch (e) { return '?'; } })();
        const magicOk = head.startsWith('4d5a') || head.startsWith('7f454c46') || head.startsWith('6465780a');
        return `提取成功\n- 输出: ${outPath}\n- 首 4 字节: ${head}${magicOk ? '  ✓ 魔数正确' : '  ⚠️ 魔数不符，请核对 offset/编码'}\n- ${out.split('\n')[0]}` +
          (magicOk ? `\n\n下一步建议：对该新文件调用 scan_crypto 重新扫描，再决定分析路线。` : '');
      }

      case 'gen_block_cipher_solver':
      case 'gen_sm4_solver': {   // 旧名兼容
        const f = String(input.path || '').trim();
        if (!f) return '参数错误：path 为空';
        if (!fs.existsSync(f)) return `文件不存在: ${f}`;
        const skeleton = String(input.skeleton || '').toLowerCase();   // 可选：ai 指定骨架
        const sc = scanCryptoFingerprints(f);
        const ca = (sc && sc.fingerprints || []).map(x => x.constantAnalysis).find(Boolean);
        if (!ca) {
          return '未找到自定义分组密码结构（无 256 项双射 S 盒）。先调用 scan_crypto 查看识别结果。';
        }
        // 按骨架分发（ai 可用 skeleton 参数覆盖结构推理的默认选择）
        const structs = inferCipherStructure(fs.readFileSync(f), sc.size, ca);
        let chosen = structs.find(s => s.skeleton !== '未知') || structs[0];
        if (skeleton) {
          const want = structs.find(s => s.skeleton.toLowerCase() === skeleton);
          if (!want) {
            return `骨架 ${skeleton} 与证据不符。当前证据支持的骨架：${structs.map(s => s.skeleton).join('、')}。\n` +
              `证据：${structs.map(s => s.evidence).join(' | ')}`;
          }
          chosen = want;
        }
        let sk = null;
        if (chosen.skeleton === 'SM4') sk = attachSM4DecryptScript(fs.readFileSync(f), sc.size, ca, (ca.sboxFileOffset ? parseInt(ca.sboxFileOffset, 16) : 0));
        else if (chosen.skeleton === 'AES') sk = attachAESDecryptScript(fs.readFileSync(f), sc.size, ca, (ca.sboxFileOffset ? parseInt(ca.sboxFileOffset, 16) : 0), structs);
        if (!sk) {
          return `骨架 ${chosen.skeleton} 的解密脚本未生成。常见原因：\n` +
            '· 密文候选定位失败（高熵块不可辨）\n' +
            '· SM4：未找到与标准 CK 固定差分的轮常量表\n' +
            '· AES：Rcon 未找到且密文不可定位\n' +
            '· 文件超过 16MB（通用程序量级）：不挂脚本——里面的标准 S 盒来自密码库而非本题算法\n' +
            '建议：查看 scan_crypto 输出确认；或自行按反编译实现（诚实边界：DES/Blowfish 暂不支持）。';
        }
        const outPath = String(input.out || '').trim() || path.join(app.getPath('temp'), `solver_${chosen.skeleton.toLowerCase()}.py`);
        fs.writeFileSync(outPath, sk.script, 'utf8');
        const lines = [`已生成 ${chosen.skeleton} 变体解密脚本: ${outPath}`];
        lines.push(`- 密文候选: ${(sk.ciphertextCandidates || []).map(x => x.offset + '(' + x.length + 'B)').join('、')}`);
        if (sk.fkCandidates) lines.push(`- FK 候选数: ${sk.fkCandidates.length}`);
        if (sk.keyHints) lines.push(`- key 提示数: ${sk.keyHints.length}`);
        if (chosen.skeleton === 'SM4') lines.push('- 覆盖: 4 维 × 16 种字节序/状态组合 + 3 种块内排列');
        if (chosen.skeleton === 'AES') lines.push('- 覆盖: key 长度 16/24/32（标准轮数 10/12/14）× 字节序/状态排列');
        lines.push(`用法: python "${outPath}" "${f}"`);
        lines.push('⚠️ 未命中不代表算法认错——可能轮结构被改写（MixColumns 矩阵/轮函数顺序等），需按反编译实现。');
        return lines.join('\n');
      }

      case 'analyze_structure': {
        const f = String(input.path || '').trim();
        if (!f) return '参数错误：path 为空';
        if (!fs.existsSync(f)) return `文件不存在: ${f}`;
        const sc = scanCryptoFingerprints(f);
        const ca = (sc && sc.fingerprints || []).map(x => x.constantAnalysis).find(Boolean);
        if (!ca) {
          return '无结构推理输入：该文件没有识别出 256 项双射 S 盒（custom 分组密码）。\n' +
            '若文件是标准 AES/SM4，scan_crypto 已直接给出算法判定，无需结构推理；\n' +
            '若是其它形态，请先用 ida_decompile 分析轮循环。';
        }
        const structs = inferCipherStructure(fs.readFileSync(f), sc.size, ca);
        const lines = [`文件: ${f}`, ''];
        lines.push('## 骨架假设（按证据强度排序——最终判断由你做）');
        for (const st of structs) {
          lines.push(`- 【${st.skeleton} 骨架】置信度 ${st.confidence}`);
          lines.push(`  证据: ${st.evidence}`);
          lines.push(`  建议: ${st.advice}`);
        }
        lines.push('');
        lines.push('## 支撑事实');
        for (const n of (ca.notes || [])) lines.push(`- ${n}`);
        return lines.join('\n');
      }

      case 'junk_scan': {
        const p = String(input.path || '').trim();
        if (!p) return '参数错误：path 为空';
        if (!fs.existsSync(p)) return `文件不存在: ${p}`;
        const buf = fs.readFileSync(p);
        let start = Number(input.start), end = Number(input.end);
        if (!Number.isFinite(start) || !Number.isFinite(end)) {
          // 未给范围：从映像节表推断可执行段
          let map = null;
          try { map = parseImageMap(buf); } catch (e) { map = null; }
          const exec = (map && Array.isArray(map.sections) ? map.sections : []).filter(s => s.executable);
          if (exec.length) {
            start = Math.min(...exec.map(s => Number(s.rawPtr) || 0));
            end = Math.max(...exec.map(s => (Number(s.rawPtr) || 0) + (Number(s.rawSize) || 0)));
          } else { start = 0; end = buf.length; }
        }
        // 入口：调用方可用 entries（文件偏移数组）显式指定，否则走自动推断
        const entries = Array.isArray(input.entries) ? input.entries.map(Number).filter(Number.isFinite) : [];
        const mode = String(input.mode || 'boundary').toLowerCase();

        // ── boundary 模式：重建指令边界图（不改字节，推荐）──
        if (mode === 'boundary') {
          const bm = buildBoundaryMap(buf, { start, end, seeds: entries });
          if (!bm.ok) return '边界重建失败: ' + bm.error;
          const L = [];
          L.push(`文件: ${p}  (${buf.length} 字节)`);
          L.push(`代码区: [0x${start.toString(16)}, 0x${end.toString(16)}) = ${end - start} 字节`);
          L.push(`模式: boundary-map（**不修改任何字节**，只重建"哪些地址是指令起点"）`);
          L.push('');
          L.push('## 结果');
          L.push(`- 指令: ${bm.stats.insnCount} 条 / 边界 ${bm.stats.boundaryCount} 个`);
          L.push(`- 覆盖率: ${bm.stats.coverage}%（未被控制流触及 ${bm.stats.unreachableBytes} 字节）`);
          L.push(`- 种子入口: ${bm.stats.seedCount} 个（含文件头 entry + 函数序言扫描结果）`);
          L.push(`- 强制对齐: ${bm.stats.forcedAlignCount} 处（跳转目标非边界 → 按"目标必为起点"纠正）`);
          L.push(`- 冲突: ${bm.stats.conflictCount} 处（已仲裁 ${bm.stats.conflictResolved}，待定 ${bm.stats.conflictUnresolved}）`);
          L.push('');
          if (bm.unreached && bm.unreached.length) {
            L.push('## 不可达区间（按大小降序，前 25）');
            L.push('**注意两义性**：这些区间从未被控制流触及，既可能是花指令垃圾，也可能是未被静态引用的真实函数。');
            L.push('判定方法：看区间首字节是否像函数序言（55 89 E5 / 53 56 57 / 83 EC）；若是，多半是真实函数。');
            const sorted = bm.unreached.slice().sort((a, b) => (b.to - b.from) - (a.to - a.from));
            for (const r of sorted.slice(0, 25)) {
              const head = buf.slice(r.from, Math.min(r.from + 4, r.to)).toString('hex');
              L.push(`- [0x${r.from.toString(16)}, 0x${r.to.toString(16)}) = ${r.to - r.from} 字节，首字节 \`${head}\``);
            }
            L.push('');
          }
          if (bm.forcedAligns && bm.forcedAligns.length) {
            L.push('## 强制对齐位置（前 20）—— 花指令制造边界歧义的地方');
            for (const f of bm.forcedAligns.slice(0, 20)) {
              L.push(`- 0x${f.from.toString(16)} ${f.kind} → 0x${f.target.toString(16)}（${f.reason}）`);
            }
            L.push('');
          }
          L.push('## 怎么用这份边界图');
          L.push('1. **不要**再按字节 patch 花指令（实测越修越乱：nop 掉 `xor;jnz` 会让后面少字节、制造新错位）。');
          L.push('2. 把上面的"不可达区间"和"强制对齐位置"当成**阅读提示**：');
          L.push('   - 伪代码出错的位置，通常落在某个不可达区间边界附近');
          L.push('   - 强制对齐处 = 反汇编器会困惑的位置，AI 应当直接从该目标地址读指令');
          L.push('3. 若要 IDA 也得到一致结果：对不可达区间按 `U`（undefine）→ 在区间内的真实起点按 `C`（MakeCode），');
          L.push('   或直接在 IDA 里跳转到强制对齐的目标地址按 `C`。');
          L.push('4. 静态仍有 400+ 冲突时，说明交叠污染严重 → 转动态（单步 tracing 取真实执行路径）。');
          L.push('');
          L.push('## 判据说明');
          for (const n of bm.notes) L.push('- ' + n);
          return L.join('\n');
        }

        const useRecursive = mode !== 'linear';   // recursive（默认）或 linear
        const r = useRecursive
          ? junkScanRecursive(buf, { start, end, entries })
          : junkScan(buf, { start, end });
        if (!r.ok) return '花指令扫描失败: ' + r.error;

        const lines = [];
        lines.push(`文件: ${p}  (${buf.length} 字节)`);
        lines.push(`扫描范围: 文件偏移 [0x${r.codeRange.start.toString(16)}, 0x${r.codeRange.end.toString(16)})  ` +
          `共 ${r.codeRange.size} 字节` + (r.mode ? `  | 模式: ${r.mode}` : ''));
        if (r.entries) lines.push(`入口: ${r.entries.map(x => '0x' + x.toString(16)).join(', ')}`);
        lines.push('');
        lines.push('## 统计');
        if (r.stats.blocks !== undefined) {
          lines.push(`- 展开基本块: ${r.stats.blocks}`);
          lines.push(`- 强制重对齐（非边界解码）: ${r.stats.realignedCount}`);
          lines.push(`- 不可达区间: ${r.stats.unreachedRegions} 段 / ${r.stats.unreachedBytes} 字节`);
        }
        lines.push(`- 解码指令: ${r.insnCount}（不可解码 ${r.stats.undecodable}）`);
        lines.push(`- 确定标志位+短跳转: ${r.stats.selfZeroFalseJump}`);
        if (r.stats.complementaryPair !== undefined) lines.push(`- 互补跳转对: ${r.stats.complementaryPair}`);
        if (r.stats.boundaryAmbiguity !== undefined) lines.push(`- 边界歧义: ${r.stats.boundaryAmbiguity}`);
        lines.push(`- call/ret 跳板: ${r.stats.callRetTrampoline || 0}`);
        lines.push(`- call $+5; pop（PIC 取址，非花指令）: ${r.stats.picCallPop}`);
        lines.push(`- 候选总数: ${r.stats.total}`);
        lines.push('');

        if (r.unreachedRegions && r.unreachedRegions.length) {
          lines.push('## 不可达区间（从未被控制流触及）');
          lines.push('这些位置最可能是花指令垃圾，**也可能是未被静态引用的真实函数**——');
          lines.push('nop 前请先确认：该区间内是否有被 data 引用的函数地址、或 IDA 是否识别为函数。');
          for (const reg of r.unreachedRegions.slice(0, 25)) {
            lines.push(`- [0x${reg.from.toString(16)}, 0x${reg.to.toString(16)}) = ${reg.to - reg.from} 字节`);
          }
          lines.push('');
        }

        if (!r.candidates.length) {
          lines.push('## 未发现可自动修补的花指令子结构');
          lines.push('这不代表没有花指令。下一步（按顺序试）：');
          lines.push('1. **给出更多入口**：用 `ida_list_functions` 取函数起始地址（或 call 目标），');
          lines.push('   转成文件偏移后用 `entries: [...]` 重跑 junk_scan —— 递归下降能展开的范围会大很多。');
          lines.push('2. 看上面的"不可达区间"：若某段刚好是伪代码出错的位置，它大概率就是花指令块。');
          lines.push('3. 走动态：目标可运行时，在关键函数断点 + instruction tracing 取真实执行路径');
          lines.push('   （执行路径是地面真值，不受解码错位影响）。');
        } else {
          lines.push('## 候选（confidence=high 且带 nopRange 的可交给 junk_patch）');
          for (const c of r.candidates.slice(0, 40)) {
            lines.push('');
            lines.push(`### [${c.confidence}] ${c.type} @ file 0x${c.off.toString(16)}`);
            lines.push('证据: ' + c.evidence);
            lines.push('建议动作: ' + c.action + (c.nopRange ? `（nop [0x${c.nopRange.from.toString(16)}, 0x${c.nopRange.to.toString(16)})，${c.nopRange.to - c.nopRange.from} 字节）` : ''));
          }
        }
        lines.push('');
        lines.push('## 判据说明');
        for (const n of r.notes) lines.push('- ' + n);
        return lines.join('\n');
      }

      case 'junk_patch': {
        const p = String(input.path || '').trim();
        if (!p) return '参数错误：path 为空';
        if (!fs.existsSync(p)) return `文件不存在: ${p}`;
        const buf = fs.readFileSync(p);
        let start = Number(input.start), end = Number(input.end);
        if (!Number.isFinite(start) || !Number.isFinite(end)) {
          let map = null;
          try { map = parseImageMap(buf); } catch (e) { map = null; }
          const exec = (map && Array.isArray(map.sections) ? map.sections : []).filter(s => s.executable);
          if (exec.length) {
            start = Math.min(...exec.map(s => Number(s.rawPtr) || 0));
            end = Math.max(...exec.map(s => (Number(s.rawPtr) || 0) + (Number(s.rawSize) || 0)));
          } else { start = 0; end = buf.length; }
        }
        const scan = junkScan(buf, { start, end });
        if (!scan.ok) return '花指令扫描失败: ' + scan.error;
        const minConf = String(input.minConfidence || 'high');
        const pr = junkPatch(buf, scan.candidates, { minConfidence: minConf });
        let outPath = String(input.out || '').trim();
        if (!outPath) {
          const ext = path.extname(p);
          outPath = p.slice(0, p.length - ext.length) + '_patched' + ext;
        }
        fs.writeFileSync(outPath, pr.buffer);
        const lines = [];
        lines.push(`原文件: ${p}`);
        lines.push(`修补后: ${outPath}  (${pr.buffer.length} 字节)`);
        lines.push(`最低置信度: ${minConf}`);
        lines.push('');
        lines.push(`## 已 patch ${pr.applied.length} 处（每处整段填 0x90）`);
        for (const a of pr.applied.slice(0, 40)) {
          lines.push(`- 0x${a.off.toString(16)} ~ 0x${a.to.toString(16)} (${a.len} 字节) ${a.type}`);
        }
        if (pr.skipped.length) {
          lines.push('');
          lines.push(`## 跳过 ${pr.skipped.length} 处（需人工确认）`);
          const byWhy = {};
          for (const s of pr.skipped) byWhy[s.why] = (byWhy[s.why] || 0) + 1;
          for (const [why, n] of Object.entries(byWhy)) lines.push(`- ${why}: ${n} 处`);
        }
        lines.push('');
        lines.push('## 下一步');
        lines.push('1. 对修补后的文件重新跑 IDA 分析（或 ida_decompile），确认伪代码可读');
        lines.push('2. 若仍有 sp-analysis failed：在 IDA 里手动修正栈指针（Alt+K），见 skill ctf-obfuscation');
        lines.push('3. 若 patch 后程序/反编译更糟：说明候选误判，删掉修补文件、改用手动 nop 或走动态 tracing');
        return lines.join('\n');
      }

      case 'junk_repair': {
        const p = String(input.path || '').trim();
        if (!p) return '参数错误：path 为空';
        if (!fs.existsSync(p)) return `文件不存在: ${p}`;
        const buf = fs.readFileSync(p);
        let start = Number(input.start), end = Number(input.end);
        if (!Number.isFinite(start) || !Number.isFinite(end)) {
          let map = null;
          try { map = parseImageMap(buf); } catch (e) { map = null; }
          const exec = (map && Array.isArray(map.sections) ? map.sections : []).filter(s => s.executable);
          if (exec.length) {
            start = Math.min(...exec.map(s => Number(s.rawPtr) || 0));
            end = Math.max(...exec.map(s => (Number(s.rawPtr) || 0) + (Number(s.rawSize) || 0)));
          } else { start = 0; end = buf.length; }
        }
        const enabled = Array.isArray(input.features) && input.features.length ? input.features.map(String) : null;
        const rp = repairJunk(buf, { start, end, decodeInsn, features: enabled });
        if (!rp.ok) return '花指令分析失败: ' + rp.error;

        const L = [];
        L.push(`文件: ${p}  (${buf.length} 字节)`);
        L.push(`代码区: [0x${start.toString(16)}, 0x${end.toString(16)})`);
        L.push('');
        L.push('## 特征命中（11 类）');
        for (const [k, v] of Object.entries(rp.stats.features || {})) {
          if (v) L.push(`- ${k}: ${v}  ${(JUNK_FEATURES && JUNK_FEATURES[k]) || ''}`);
        }
        L.push('');
        L.push('## 汇总');
        L.push(`- 跳转目标非对齐（最硬判据）: ${rp.stats.badTargets}`);
        L.push(`- 可自动修补: ${rp.stats.patchable} 处`);
        L.push(`- 仅报告（需人工/动态确认）: ${rp.stats.reportOnly} 处`);
        L.push('');

        if (!rp.candidates.length) {
          L.push('## 未发现花指令特征');
          L.push('这不等于没有。下一步：');
          L.push('1. `junk_scan mode=boundary` 看指令边界图与不可达区间');
          L.push('2. 目标可运行时走动态 tracing（执行路径 = 地面真值）');
        } else {
          L.push('## 候选明细（前 50）');
          L.push('每条都标了判据来源，不要只看 XREF 就下结论。');
          for (const c of rp.candidates.slice(0, 50)) {
            const tag = c.safe ? '可修补' : '仅报告';
            L.push('');
            L.push(`### [${tag}] ${c.feature}${c.off != null ? ' @0x' + c.off.toString(16) : ''}`);
            L.push(`证据: ${c.evidence}`);
            L.push(`判定: ${c.reason}`);
            if (c.nopRange) L.push(`→ ${c.strategy} [0x${c.nopRange.from.toString(16)}, 0x${c.nopRange.to.toString(16)}) = ${c.nopRange.to - c.nopRange.from} 字节`);
          }
        }

        if (input.dryRun) {
          L.push('');
          L.push('（dryRun=true，未写出文件）');
          return L.join('\n');
        }

        const ap = applyRepair(buf, rp.candidates);
        let outPath = String(input.out || '').trim();
        if (!outPath) {
          const ext = path.extname(p);
          outPath = p.slice(0, p.length - ext.length) + '_repaired' + ext;
        }
        fs.writeFileSync(outPath, ap.buffer);
        L.push('');
        L.push(`## 已写出: ${outPath}`);
        L.push(`- 实际修补 ${ap.applied.length} 处，跳过 ${ap.skipped.length} 处`);
        const sz = {};
        ap.applied.forEach(a => { sz[a.len + 'B:' + a.strategy] = (sz[a.len + 'B:' + a.strategy] || 0) + 1; });
        L.push(`- 改动分布: ${JSON.stringify(sz)}`);

        // 修补效果自量测：把"修复前 vs 修复后"的硬指标直接算给 AI 看。
        // 为什么必须在这里算：原始文件各指标可能看起来更好（函数少 → 分母小 → 成功率高），
        // 模型据此会误判"修补让情况变糟"，然后退回自己 nop 的错误路线。
        // 真正该看的是「冲突数」与「可反编译的真函数绝对数」，不是成功率百分比。
        try {
          const after = scanJunkFeatures(ap.buffer, { start, end, decodeInsn });
          L.push('');
          L.push('## 修补效果（工具自测，同口径对比）');
          L.push('| 指标 | 修复前 | 修复后 | 说明 |');
          L.push('|---|---|---|---|');
          L.push(`| 跳转目标非对齐 | ${rp.stats.badTargets} | ${after.stats.badTargets} | 最硬的边界判据，越少越好 |`);
          L.push(`| 可修补点 | ${rp.stats.patchable} | ${after.stats.patchable} | 本次修补掉的数量 |`);
          const dropPct = rp.stats.badTargets > 0
            ? ((1 - after.stats.badTargets / rp.stats.badTargets) * 100).toFixed(1)
            : '0.0';
          L.push('');
          L.push(`**非对齐跳转下降 ${dropPct}%**（字节长度不变: ${ap.buffer.length === buf.length ? '是' : '否，需复查'}）。`);
          L.push('跳转指令只被换成等长 NOP，字节偏移与可执行语义都不变。');
        } catch (e) {
          L.push('');
          L.push('（修补后复测失败，不影响修补本身: ' + e.message + '）');
        }

        // 自动把新 IDA 实例切到修补后的文件。
        // 为什么放在这里：AI 拿到修补路径后经常直接接着反编译**旧** IDB（旧边界），
        // 结果读到还是错位伪代码，然后误判"修补没用"。让工具自己完成交接，
        // 就不再依赖模型记得调 ida_open_file。
        if (input.reload !== false) {
          L.push('');
          L.push('## 正在让 IDA 重新分析修补后的文件…');
          const rr = await idaReloadAndWait(outPath, {
            newDatabase: true,
            timeout: input.reloadTimeout,
          });
          L.push(...rr.lines);
          L.push('');
          L.push('## 下一步');
          if (rr.ok) {
            L.push('1. 直接 ida_list_functions → ida_decompile（已指向修补后的库）');
          } else {
            // 交接失败时绝不能说"已指向修补后的库"——那会让模型在旧库上反编译并误判修复无效
            L.push('1. ⚠ IDA 尚未切到修补后的文件。请先解决上面的重载问题，');
            L.push('   或手动调用 ida_open_file({ path: "' + outPath + '" })，否则读到的是旧错位伪代码。');
          }
          L.push('2. **判读要点**：修补后函数数会变多（花指令切碎的函数被重新连起来）。');
          L.push('   此时"反编译成功率"这类百分比会下降——因为分母里多了原本没被识别出来的复杂函数。');
          L.push('   **不要**因此认为修补有害。该看的是"能反编译出可读伪代码的函数绝对数"是否增加。');
          L.push('3. 若仍有函数反编译失败：用 junk_scan mode=boundary 看不可达区间，或走动态 tracing');
          return L.join('\n');
        }
        L.push('');
        L.push('## 下一步');
        L.push('1. 直接 ida_list_functions → ida_decompile（已指向修补后的库）');
        L.push('2. **判读要点**：修补后函数数会变多（花指令切碎的函数被重新连起来）。');
        L.push('   此时"反编译成功率"这类百分比会下降——因为分母里多了原本没被识别出来的复杂函数。');
        L.push('   **不要**因此认为修补有害。该看的是"能反编译出可读伪代码的函数绝对数"是否增加。');
        L.push('3. 若仍有函数反编译失败：用 junk_scan mode=boundary 看不可达区间，或走动态 tracing');
        return L.join('\n');
      }
      case 'switch_to_next_stage': {
        const p = String(input.path || '').trim();
        if (!p) return '阶段接力失败：path 为空';
        try {
          const st = fs.statSync(p);
          if (!st.isFile()) return `阶段接力失败：不是文件 → ${p}`;
          if (st.size === 0) return `阶段接力失败：文件为空 → ${p}`;
          return `阶段接力已受理：${p}（${st.size} 字节）。工具将关闭当前反编译进程并以该文件继续分析。`;
        } catch (e) {
          return `阶段接力失败：文件不存在或不可读 → ${p}（${e.message}）`;
        }
      }

      default:
        return `未知工具: ${toolName}`;
    }
  } catch (err) {
    // 工具内部已经判定失败（并希望保留类型化异常）时，原样上抛给主循环；
    // 只有真正的意外异常才改写成文本。
    if (err && err.__toolError) throw err;
    return `工具调用失败: ${err.message}`;
  }
}

// 单步"假失败"兜底。
// IDA 9 的异步调试器投递命令后立即返回，插件却把 idaapi.step_over() 的返回值当结果：
// 命令已生效但返回 False → 插件抛 "Failed to step over"，AI 会误以为单步不可用。
// 这里在失败后再读一次 IP：与失败前不同就说明单步确实执行了，按成功返回。
async function rescueStepFailure(call, err) {
  if (!/Failed to step (over|into)/i.test(String(err && err.message))) return null;
  try {
    const before = await readDbgIp();
    // 给异步调试器一点时间落地
    await new Promise(r => setTimeout(r, 350));
    const retried = await callIdaMcp(call.tool, call.args);
    const after = await readDbgIp();
    if (before && after && before !== after) {
      // 上游这次成功了就返回它的结果；否则用读到的 IP 组成等价结果
      return retried !== undefined ? retried : { ip: after, recovered: true };
    }
    if (retried !== undefined) return retried;
  } catch (e) { /* 兜底失败，保留原始错误 */ }
  return null;
}

// 从 dbg_regs 里取当前 IP（x86 EIP / x64 RIP）。读不到返回 null。
// 刚 start 时调试事件可能还没落地（插件会报 Debugger not running），重试几次。
async function readDbgIp(retries = 3, delayMs = 400) {
  for (let i = 0; i <= retries; i++) {
    try {
      const regs = await callIdaMcp('dbg_regs', {});
      const arr = Array.isArray(regs) ? regs : (regs && regs.registers) || [];
      const hit = arr.find(r => r && /^(eip|rip)$/i.test(String(r.name || '')));
      if (hit) return String(hit.value).toLowerCase();
    } catch (e) { /* 重试 */ }
    if (i < retries) await new Promise(r => setTimeout(r, delayMs));
  }
  return null;
}

// 读进程状态。语义见 ida-dbg.js 的 dbgStateName：
//   -1 暂停 / 0 无进程 / 1 运行中 / 2 已退出
async function readDbgState() {
  try {
    const r = await callIdaMcp('py_eval', {
      code: 'import idaapi, ida_dbg\n' +
        'print("ON", ida_dbg.is_debugger_on())\n' +
        'print("STATE", idaapi.get_process_state())',
    });
    const text = typeof r === 'string' ? r : String((r && r.stdout) || '');
    const m = /STATE\s+(-?\d+)/.exec(text);
    const on = /ON\s+True/.test(text);
    return { on, state: m ? Number(m[1]) : null };
  } catch (e) {
    return { on: false, state: null };
  }
}

// continue / run_to 是**异步投递**：命令返回时进程还在跑（实测返回的 ip 是投递前的旧值）。
// 必须轮询到进程真正停下（STATE=-1）或退出（STATE=2），否则紧接着的单步/写内存必然失败。
//
// 注意：GUI 程序 continue 后会停在消息循环等用户输入，期间 STATE 一直是 1，
// 直到某个断点命中。所以这里要能区分"还在跑"和"等输入"——超时不算错误，
// 而是把控制权交回 AI，由它决定 suspend 还是继续等。
async function waitDbgStop({ timeoutMs = 8000, intervalMs = 150, startupGraceMs = 0 } = {}) {
  const t0 = Date.now();
  let last = null;
  while (Date.now() - t0 < timeoutMs) {
    const cur = await readDbgState();
    last = cur;
    // 刚 start_process 时 is_debugger_on() 会短暂为 False（进程还没被接管），
    // 不能据此判"无进程"——否则 start 后立刻检查会得到假阴性（实测 8ms 就误判）。
    if (!cur.on) {
      if (Date.now() - t0 < startupGraceMs) {
        await new Promise(r => setTimeout(r, intervalMs));
        continue;
      }
      return { stopped: true, state: 0, reason: 'no-process', waitedMs: Date.now() - t0 };
    }
    if (cur.state === -1) return { stopped: true, state: -1, reason: 'suspended', waitedMs: Date.now() - t0 };
    if (cur.state === 2) return { stopped: true, state: 2, reason: 'exited', waitedMs: Date.now() - t0 };
    await new Promise(r => setTimeout(r, intervalMs));
  }
  return {
    stopped: false,
    state: last ? last.state : null,
    reason: 'still-running',
    waitedMs: Date.now() - t0,
  };
}

// remote_exec：local 走本地 shell，kali 走 sshExec。失败必须如实抛 ToolCallError。
async function remoteExecTool(input) {
  const i = input || {};
  const cmd = String(i.command || '').trim();
  if (!cmd) return '参数错误：command 为空';
  const host = String(i.host || 'local').toLowerCase();
  const timeoutMs = Math.min(Math.max(Number(i.timeout_ms) || 20000, 1000), 600000);

  if (host === 'local') {
    const r = await new Promise((resolve) => {
      exec(cmd, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        resolve({ success: !error, stdout: stdout || '', stderr: stderr || '', error: error ? error.message : null });
      });
    });
    if (!r.success) {
      // 本地失败也用同一套前缀，便于 AI 与失败前缀表统一识别
      const cls = classifyRemoteError({
        success: false, error: r.error, stdout: r.stderr, exitCode: 1, host: 'local', port: 0,
      });
      throw new ToolCallError(cls.message.replace(/^REMOTE_REFUSED \(未配置\):0/, 'LOCAL_EXEC_FAILED'));
    }
    return r.stdout ? truncateOutput(r.stdout) : '（命令成功，无输出）';
  }

  const { sshHost, sshPort } = config.kali || {};
  if (!sshHost) {
    throw new ToolCallError(classifyRemoteError({ host: '' }).message);
  }
  const r = await sshExec(cmd, timeoutMs);
  // sshExec 现在会带回真实退出码；旧式 {success:true,exitCode:undefined} 仍按 0 处理。
  const exitCode = r.exitCode !== undefined ? r.exitCode : (r.success ? 0 : 1);
  const cls = classifyRemoteError({
    success: r.success, error: r.error || r.stderr, stdout: r.stdout, exitCode,
    host: sshHost, port: sshPort,
  });
  if (cls.isError) throw new ToolCallError(cls.message);
  return r.stdout ? truncateOutput(r.stdout) : '（远程命令成功，无输出）';
}

// 调用IDA MCP（逻辑名 -> 会话化 + 工具名匹配 + 信封解包）
async function callIdaMcp(method, params) {
  try {
    return await idaMcpCallTool(method, params);
  } catch (err) {
    throw new ToolCallError(`IDA MCP调用失败: ${err.message}`);
  }
}

// 打开文件后等新实例把自动分析与 Hex-Rays 都准备好。
// 为什么要等：open_file 只保证"实例注册到 MCP"，此时 list_funcs 可能还是空表或几十个
// 未识别函数；渲染层紧接着采集就会拿到残缺函数表，进而选错主体函数。
async function idaReloadAndWait(filePath, opts = {}) {
  const lines = [];
  // 注意传输层上限：idaMcpCallTool → sendMCPRequest 的超时是固定 60s。
  // 早先这里默认 180s 并原样传给 open_file，结果插件还没返回、HTTP 就先 destroy，
  // 大程序上必现"假失败"。现在夹到 55s 以内，剩余等待交给下面的轮询（轮询各自 60s 独立计时）。
  const waitSec = Math.min(Math.max(Number(opts.timeout) || 180, 30), 600);
  const openTimeoutSec = Math.min(waitSec, 55);
  const wantNewDb = opts.newDatabase === true;

  // 旧的 .i64/.idb 只在"要求全新分析"时才删。
  // 早期这里无条件删除，导致 ida_open_file({new_database:false}) 也会丢失旧库，
  // 与 schema 文档"默认 false，有旧库就直接开旧库"相反。
  if (wantNewDb) {
    // 为什么要删：文件旁存在同名库时 IDA -c 会弹"是否覆盖"，自治模式（-A）下
    // 该对话框的默认回答不一定是"是"，可能直接放弃打开。
    const base = filePath.replace(/\.[^./\\]+$/, '');
    for (const ext of ['.i64', '.idb']) {
      const cand = base + ext;
      try {
        if (fs.existsSync(cand)) { fs.unlinkSync(cand); lines.push(`（已删除旧数据库 ${path.basename(cand)}）`); }
      } catch (e) {
        lines.push(`⚠️ 无法删除 ${path.basename(cand)}：${e.message}（IDA 可能正占用它）`);
      }
    }
  }

  let opened;
  try {
    opened = await idaMcpCallTool('open_file', {
      file_path: filePath,
      switch: true,
      autonomous: true,
      new_database: wantNewDb,
      timeout: openTimeoutSec,
    });
  } catch (e) {
    lines.push('工具调用失败: IDA 自动重载出错（' + e.message + '）');
    lines.push(`请先启动 IDA（并确认 MCP 端口可达），再调用 ida_open_file({ path: "${filePath}" })。`);
    return { ok: false, lines };
  }

  if (!opened || opened.success === false) {
    lines.push('工具调用失败: IDA 自动重载失败（' + JSON.stringify(opened) + '）');
    lines.push(`请手动调用 ida_open_file({ path: "${filePath}" })。`);
    return { ok: false, lines };
  }

  const who = `${opened.host || '127.0.0.1'}:${opened.port || '?'}`;
  let switchedPort = opened.port || null;

  if (!opened.port) {
    // open_file 用"启动前后实例快照差集"判断哪个是新实例。机器上已堆积多个 IDA 时
    // 常拿不到新端口（实测 4 个实例时静默返回 undefined）。此时不能放弃：
    // 用 list_instances 按**路径**找到目标实例，再 select_instance 精确切换。
    lines.push(`⚠️ open_file 未返回实例端口（已有多个 IDA 实例时会这样），改用 list_instances 定位…`);
    try {
      const insts = await idaMcpCallTool('list_instances', {});
      const arr = Array.isArray(insts) ? insts : [];
      const norm = p => String(p || '').replace(/\\/g, '/').toLowerCase();
      const want = norm(filePath);
      const hit = arr.find(x => norm(x.input_path) === want || norm(x.idb_path).replace(/\.(i64|idb)$/, '') === want.replace(/\.[^./\\]+$/, ''))
        || arr.find(x => norm(x.binary) === norm(path.basename(filePath)));
      if (hit && hit.port) {
        await idaMcpCallTool('select_instance', { port: hit.port, host: hit.host || '127.0.0.1' });
        switchedPort = hit.port;
        lines.push(`✅ 已通过 list_instances 切到 ${hit.host || '127.0.0.1'}:${hit.port}（${hit.binary}）`);
      } else {
        lines.push(`⚠️ list_instances 里找不到 ${path.basename(filePath)} 对应的实例。`);
        lines.push(`   手动兜底：ida_open_file({ path: "${filePath}" })，或先用 list_instances 看端口。`);
        return { ok: false, lines, port: null };
      }
    } catch (e) {
      lines.push('⚠️ list_instances 失败: ' + e.message);
      return { ok: false, lines, port: null };
    }
  } else {
    lines.push(`✅ IDA 已切换: ${who} pid=${opened.pid || '?'}`);
  }
  lines.push('等待自动分析/反编译器就绪…');

  const deadline = Date.now() + waitSec * 1000;
  let last = null, stable = 0, prevCount = -1;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 3000));
    let h = null;
    try { h = await idaMcpCallTool('server_health', {}); } catch (e) { h = null; }
    if (!h) continue;
    last = h;
    const ready = h.auto_analysis_ready !== false && h.hexrays_ready !== false;
    if (!ready) continue;
    let count = 0;
    try {
      const fns = await idaMcpCallPaged('list_functions', {});
      count = Array.isArray(fns) ? fns.length : 0;
    } catch (e) { count = 0; }
    if (count > 0 && count === prevCount) { stable++; } else { stable = 0; }
    prevCount = count;
    // 函数数连续两次相同才算收敛（IDA 是增量识别函数，一次取样容易拿到半成品）
    if (stable >= 1) {
      lines.push(`✅ 分析就绪：识别到 ${count} 个函数（Hex-Rays 已可用）`);
      return { ok: true, lines, functions: count, port: switchedPort };
    }
  }

  lines.push(`⚠️ ${waitSec}s 内未见分析就绪（最后状态: ${JSON.stringify(last)}）。`);
  lines.push('可以照常 ida_list_functions；若结果稀少，等几十秒再试。');
  return { ok: false, lines, port: switchedPort };
}

// 调用Burp MCP（逻辑名 -> 会话化 + 工具名匹配 + 信封解包）
async function callBurpMcp(method, params) {
  try {
    return await burpMcpCallTool(method, params);
  } catch (err) {
    // 连接类失败给固定前缀：BURP_DOWN 已登记到 tool-result.js 的 FAILURE_PREFIXES，
    // 否则字符串失败不会被标 is_error（AI 会把它当成功继续）。
    if (/ECONNREFUSED|ECONNRESET|socket hang up|connect ETIMEDOUT|fetch failed/i.test(String(err.message))) {
      const bat = (config.tools && config.tools.burp) || '';
      return `BURP_DOWN ${config.mcp.burp}（${err.message}）；启动：${bat || '请在设置中配置 tools.burp 指向 MCP_Burp.bat'}`;
    }
    return `Burp MCP调用失败: ${err.message}（请确认 Burp 已启动且 MCP 插件监听 ${config.mcp.burp}）`;
  }
}

// 读取文件
function readFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return content;
  } catch (err) {
    return `读取文件失败: ${err.message}`;
  }
}

// 写入文件
function writeFile(filePath, content) {
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    return `文件已写入: ${filePath}`;
  } catch (err) {
    return `写入文件失败: ${err.message}`;
  }
}

// 纯 JS 递归遍历（替代 find/dir 双系统 shell 写法，规避注入与 cmd 语法问题）
function walkFiles(root, maxResults = 500) {
  const results = [];
  const skip = new Set(['node_modules', '.git', 'AppData', '$Recycle.Bin', 'Windows']);
  const queue = [root];
  while (queue.length && results.length < maxResults) {
    const dir = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      continue; // 无权限/已删除
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!skip.has(ent.name)) queue.push(full);
      } else if (ent.isFile()) {
        results.push(full);
        if (results.length >= maxResults) break;
      }
    }
  }
  return results;
}

// 搜索文件（文件名子串匹配，支持 * 通配）；默认从应用目录（工作目录）开始
function globFiles(pattern) {
  try {
    const root = (currentWorkDir && fs.existsSync(currentWorkDir)) ? currentWorkDir : app.getAppPath();
    const rx = new RegExp('^' + String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
    const loose = String(pattern).toLowerCase();
    const hits = walkFiles(root).filter(f => {
      const base = path.basename(f);
      return rx.test(base) || base.toLowerCase().includes(loose.replace(/\*/g, ''));
    });
    return hits.length ? hits.join('\n') : '未找到匹配文件';
  } catch (err) {
    return `搜索失败: ${err.message}`;
  }
}

// 搜索文件内容（文本文件逐行匹配，限制扫描范围防止全盘读取）
function grepFiles(pattern, searchPath) {
  try {
    let rx;
    try {
      rx = new RegExp(pattern, 'i');
    } catch (e) {
      rx = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    }
    // 与 globFiles 保持一致：默认从工作目录（当前题目目录）开始
    const root = searchPath ? path.resolve(searchPath) : ((currentWorkDir && fs.existsSync(currentWorkDir)) ? currentWorkDir : app.getAppPath());
    const hits = [];
    for (const f of walkFiles(root, 2000)) {
      // 只扫描小于 2MB 的疑似文本文件
      let st;
      try { st = fs.statSync(f); } catch (e) { continue; }
      if (st.size > 2 * 1024 * 1024) continue;
      try {
        const content = fs.readFileSync(f, 'utf8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (rx.test(lines[i])) {
            hits.push(`${f}:${i + 1}: ${lines[i].trim().slice(0, 200)}`);
            if (hits.length >= 200) break;
          }
        }
      } catch (e) { /* 二进制或无权限 */ }
      if (hits.length >= 200) break;
    }
    return hits.length ? hits.join('\n') : '未找到匹配内容';
  } catch (err) {
    return `搜索失败: ${err.message}`;
  }
}

// 浏览器 MCP 工具实现（真实调用，未配置/不可达时返回明确错误而非"开发中"占位）
async function browserMcpSearchTool(query) {
  try {
    const r = await doBrowserMcpFetch(`https://www.google.com/search?q=${encodeURIComponent(query)}`);
    return r.snapshot || JSON.stringify(r);
  } catch (err) {
    return `浏览器MCP搜索失败: ${err.message}（需在设置中配置可用的 mcp.browser 端点）`;
  }
}

async function browserMcpOpenTool(url) {
  try {
    const r = await doBrowserMcpFetch(url);
    return r.snapshot || JSON.stringify(r);
  } catch (err) {
    return `浏览器MCP打开失败: ${err.message}（需在设置中配置可用的 mcp.browser 端点）`;
  }
}

// 当前工作目录（渲染层加载题目文件时同步，AI 的 glob/grep 由此定位）
let currentWorkDir = null;
// 当前题目文件与类型（供 ida_dbg 决定 local/remote 调试模式）
let currentTargetFile = null;
let currentTargetKind = null;
function idaDbgTargetKind() {
  if (currentTargetKind) return currentTargetKind;
  const p = String(currentTargetFile || '');
  if (/\.(exe|dll)$/i.test(p)) return 'PE';
  if (/\.(so|elf)$/i.test(p) || /(^|[\\/])(chall|pppp|parallelism|obfuscat3)$/i.test(p)) return 'ELF';
  return '';
}
// 当前案件目录（渲染层 caseInit 成功后通过 set-case-dir 同步）。
// 主进程没有 state.caseDir：run_python 的 cwd 与产物登记都依赖这份主进程侧副本。
let currentCaseDir = null;

function writeTempFile(name, content) {
  const tmp = path.join(app.getPath('temp'), name);
  fs.writeFileSync(tmp, content, 'utf8');
  return tmp;
}

// 执行命令
// 在"当前案件工作目录"下执行，避免模型反复用绝对路径试探；Windows 下走 cmd.exe。
// 超时 120s（旧值 30s 对编译/大脚本/批量处理不够；同样会误导 AI"命令失败"而换路）。
async function execCommandAsync(command) {
  return runBash({
    exec,
    tempDir: app.getPath('temp'),
    cwd: (currentWorkDir && fs.existsSync(currentWorkDir)) ? currentWorkDir : undefined,
  }, command);
}

// 执行Python脚本（唯一临时文件名，避免并发覆盖）
// 超时可配置：Z3 求解 AES 变体、大规模爆破/枚举、Unicorn 模拟等常需数分钟，
// 旧值 60s 会把"正在收敛的正确解法"误杀成"Python执行失败: timeout"，AI 误判方向后换路重试，
// 60 轮预算被烧光（Disguise 实测：Z3 AES 求解反复超时 → 绕圈子）。
// 默认提到 300s（5 分钟），可用环境变量 CTF_PY_TIMEOUT_MS 覆盖；钳制到 [1s, 30min] 防负数/0 异常。
const PY_TIMEOUT_MS = Math.min(Math.max(parseInt(process.env.CTF_PY_TIMEOUT_MS, 10) || 300000, 1000), 1800000);

// 当前正在运行的 python 子进程（供 claude-abort 主动终止）。
// 为什么需要：旧实现用 exec + shell:true → kill 只杀 cmd.exe，python 孙进程逃逸继续跑
// （实测：超时 kill 后孙进程仍在写文件），且取消操作完全不响应 → 进程泄漏 + 卡住后续分析。
let currentPythonChild = null;
function killPythonTree() {
  const ch = currentPythonChild;
  if (!ch || ch.killed) return;
  try {
    if (process.platform === 'win32' && ch.pid) {
      // Windows：按 PID 杀整棵进程树（cmd → python 及其后代）
      require('child_process').execSync(`taskkill /PID ${ch.pid} /T /F`, { stdio: 'ignore', timeout: 8000 });
    } else {
      try { process.kill(-ch.pid, 'SIGKILL'); } catch (e) { ch.kill('SIGKILL'); }
    }
  } catch (e) { try { ch.kill('SIGKILL'); } catch (e2) {} }
  currentPythonChild = null;
}

async function runPythonScript(script, cwdOpt) {
  const tempFile = path.join(app.getPath('temp'), `ctf_script_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tempFile, script);

  // 脚本里的相对路径必须落在题目目录里，而不是进程 cwd（实测会写进仓库根目录）。
  const cwd = pickPythonCwd({ explicitCwd: cwdOpt, caseDir: currentCaseDir, workDir: currentWorkDir });
  let before = null;
  const sinceMs = Date.now();
  try {
    fs.mkdirSync(cwd, { recursive: true });
    before = snapshotDir(cwd);
  } catch (e) { /* 目录不可用则退化为不扫描 */ }

  const wrap = (text) => {
    if (!before) return text;
    let arts = [];
    try { arts = scanNewArtifacts(cwd, sinceMs, before); } catch (e) { arts = []; }
    if (!arts.length) return text;
    // 产物登记追加到 evidence/artifacts.jsonl，由渲染层在 finalize 时读回。
    // 不写 findings.json：那是渲染层整份覆盖写的文件，主进程写会被覆盖。
    if (currentCaseDir) {
      try {
        const rec = path.join(currentCaseDir, 'evidence', 'artifacts.jsonl');
        fs.mkdirSync(path.dirname(rec), { recursive: true });
        for (const a of arts) {
          fs.appendFileSync(rec, JSON.stringify({
            kind: 'run_python_artifact', path: a.path, size: a.size, rel: a.name, ts: new Date().toISOString(),
          }) + '\n');
        }
      } catch (e) { /* 登记失败不影响执行结果 */ }
    }
    return text + '\n' + arts.map(a => `artifact: ${a.path} (${a.size} bytes)`).join('\n');
  };

  return new Promise((resolve) => {
    // 用 spawn（shell:false）直接起 python：kill 能命中本体；Windows 上用 taskkill /T 杀树。
    const child = spawn('python', [tempFile], { windowsHide: true, cwd });
    currentPythonChild = child;

    let stdout = '', stderr = '', total = 0;
    let settled = false;
    const MAXBUF = 32 * 1024 * 1024;
    const finish = (text) => {
      if (settled) return;
      settled = true;
      if (currentPythonChild === child) currentPythonChild = null;
      try { fs.unlinkSync(tempFile); } catch (e) {}
      resolve(wrap(text));
    };
    const timer = setTimeout(() => {
      killPythonTree();
      finish(`Python执行超时（${Math.round(PY_TIMEOUT_MS / 1000)}s 上限，进程树已被终止）。`
        + `\n提示：这是"算得太久"而非"方法错误"。请改用更省时的策略：`
        + `①缩小搜索空间（利用已知前缀/格式约束）；②先小规模验证再放大；`
        + `③把长计算拆成多次短脚本（每次只解 1 个块/1 个字节）；`
        + `④避免 Z3 对全 16 字节做符号执行（块密码用正向验证/枚举，别硬逆）。`
        + `\n${truncateOutput(stderr)}`);
    }, PY_TIMEOUT_MS);

    child.stdout.on('data', (c) => { total += c.length; if (total > MAXBUF) { killPythonTree(); return; } stdout += c; });
    child.stderr.on('data', (c) => { total += c.length; if (total > MAXBUF) { killPythonTree(); return; } stderr += c; });
    child.on('error', (err) => {
      clearTimeout(timer);
      finish(`Python启动失败: ${err.message}（确认 python 在 PATH 中）`);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (signal) {
        finish(`Python被信号终止（${signal}）。\n${truncateOutput(stderr)}`);
      } else if (code !== 0) {
        // 只按"代码非零"报错——不再用 stderr 文本匹配 "timed out"（脚本自己打印该词会被误判）
        finish(`Python执行失败(exit ${code}):\n${truncateOutput(stderr) || truncateOutput(stdout)}`);
      } else {
        finish(stdout ? truncateOutput(stdout) : 'Python执行成功（无输出）');
      }
    });
  });
}

// 执行ADB命令（spawn 参数数组）
async function execAdbCommand(command) {
  const adbPath = resolveAdbPath();
  const port = config.emulator.adb_port;
  await adbEnsureConnected(port);
  const argv = [adbPath, '-s', `127.0.0.1:${port}`].concat(tokenizeCommand(command || ''));

  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { shell: false, windowsHide: true });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch (e) {} }, 30000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve(`ADB命令失败: ${err.message}`);
    });
    child.on('close', () => {
      clearTimeout(timer);
      resolve(stdout ? truncateOutput(stdout) : (stderr ? truncateOutput(stderr) : 'ADB命令成功（无输出）'));
    });
  });
}

// 用 frida-ps 列出远程设备进程，把"包名"解析成真实的"进程名"。
// Android 上进程名常是 App 名（如 "My Application"）而非包名（com.cr.myapplication），
// frida 的 -n 需要的是**进程名**，直接用包名会 "unable to find process with name 'com.x.y'"。
// 关键：`frida-ps` 默认列的是进程名；加 `-a` 才带 "PID  Name  Identifier" 三列，
// Identifier 才是包名。两个列表都要查，才能把包名映射到进程名。
// 返回 { pid, name } 或 null。
function resolveFridaProcessName(target) {
  const port = config.emulator.frida_port;
  const runPs = (extraArgs) => new Promise((resolve) => {
    const child = spawn('frida-ps', ['-H', `127.0.0.1:${port}`].concat(extraArgs), { shell: false, windowsHide: true });
    let out = '';
    const t = setTimeout(() => { try { child.kill(); } catch (e) {} resolve(''); }, 12000);
    child.stdout.on('data', d => { out += d.toString(); });
    child.on('error', () => { clearTimeout(t); resolve(''); });
    child.on('close', () => { clearTimeout(t); resolve(out); });
  });
  return (async () => {
    // `-a`：应用列表，形如 " 3372  My Application  com.cr.myapplication"
    const appOut = await runPs(['-a']);
    // 默认：进程列表，形如 " 3372  My Application"
    const psOut = await runPs([]);
    const norm = (s) => String(s || '').toLowerCase().replace(/\s+/g, '');
    const q = norm(target);
    const seg = q.split('.').pop();
    // 解析 -a 三列：PID  Name  Identifier
    const appRows = appOut.split(/\r?\n/)
      .map(l => l.match(/^\s*(\d+)\s+(.+?)\s{2,}(\S+)\s*$/))
      .filter(Boolean)
      .map(m => ({ pid: Number(m[1]), name: m[2].trim(), identifier: m[3].trim() }));
    // 优先：Identifier（包名）精确/包含匹配 → 取其 Name 作为 frida -n 目标
    if (q) {
      const byId = appRows.find(r => norm(r.identifier) === q)
        || appRows.find(r => norm(r.identifier).includes(q) || q.includes(norm(r.identifier)));
      if (byId) return byId;
    }
    // 退而求其次：按进程名匹配（可能 target 本就是进程名）
    const psRows = psOut.split(/\r?\n/)
      .filter(l => /^\s*\d+\s+\S/.test(l))
      .map(l => { const m = l.match(/^\s*(\d+)\s+(.+?)\s*$/); return m ? { pid: Number(m[1]), name: m[2] } : null; })
      .filter(Boolean);
    const allRows = psRows.concat(appRows.map(r => ({ pid: r.pid, name: r.name })));
    return allRows.find(r => norm(r.name) === q)
      || allRows.find(r => norm(r.name).includes(q) || q.includes(norm(r.name)))
      || (seg.length >= 4 ? allRows.find(r => norm(r.name).includes(seg) || seg.includes(norm(r.name))) : null)
      || null;
  })();
}

// 用 adb `pidof <包名>` 拿 PID —— 这是 frida-ps 枚举失败时的**可靠后备**。
// 背景：frida 16.7.19 + 某些 Nox Android9 镜像上，frida-ps（枚举进程/应用，
// 内部走 queryIntentActivities）会抛 NullPointerException，导致 -f/-n/-F 全部不可用；
// 但 **`frida -p <PID>` 直接按 PID attach 完全正常**（已实测：ATTACH_OK）。
// 返回 pid(数字) 或 null。
function adbPidOf(name) {
  return new Promise((resolve) => {
    const port = config.emulator.adb_port;
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const c = spawn(resolveAdbPath(), ['-s', `127.0.0.1:${port}`, 'shell', 'pidof', String(name)], { shell: false, windowsHide: true });
      let o = '';
      c.stdout.on('data', d => o += d.toString());
      c.on('error', () => fin(null));
      c.on('close', () => {
        const m = String(o).trim().match(/\b(\d+)\b/);
        fin(m ? Number(m[1]) : null);
      });
      setTimeout(() => { try { c.kill(); } catch (e) {} fin(null); }, 8000);
    } catch (e) { fin(null); }
  });
}

// 用 adb `ps -A` 全表搜进程名（pidof 取不到时的兜底，兼容只按包名/末段匹配）。
function adbFindPidByPs(name) {
  return new Promise((resolve) => {
    const port = config.emulator.adb_port;
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const c = spawn(resolveAdbPath(), ['-s', `127.0.0.1:${port}`, 'shell', 'ps', '-A'], { shell: false, windowsHide: true });
      let o = '';
      c.stdout.on('data', d => o += d.toString());
      c.on('error', () => fin(null));
      c.on('close', () => {
        const q = String(name || '').toLowerCase();
        const seg = q.split('.').pop();
        const rows = String(o).split(/\r?\n/).map(l => {
          const m = l.match(/^\S+\s+(\d+)\s+\d+\s+.*?\s(\S+)\s*$/);
          return m ? { pid: Number(m[1]), name: m[2] } : null;
        }).filter(Boolean);
        const hit = rows.find(r => r.name.toLowerCase() === q)
          || rows.find(r => r.name.toLowerCase().includes(q) || q.includes(r.name.toLowerCase()))
          || (seg && seg.length >= 4 ? rows.find(r => r.name.toLowerCase().includes(seg)) : null);
        fin(hit ? hit.pid : null);
      });
      setTimeout(() => { try { c.kill(); } catch (e) {} fin(null); }, 10000);
    } catch (e) { fin(null); }
  });
}

// 解析"包名/进程名 → PID"（先 pidof，再 ps -A 兜底）
async function resolvePidByName(name) {
  let pid = await adbPidOf(name);
  if (!pid) pid = await adbFindPidByPs(name);
  return pid || null;
}

// 执行Frida Hook
// 执行Frida Hook脚本（spawn，避免 shell 注入；唯一临时文件名，finally 清理）
async function execFridaHook(script, target, opts) {
  const tempFile = path.join(app.getPath('temp'), `frida_hook_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.js`);
  fs.writeFileSync(tempFile, script);

  const port = config.emulator.frida_port;
  // 目标可选：'spawn:<包名>' 用 -f 自动拉起并挂启动期 hook（动态调试自动化用）；
  // 普通目标 attach 指定进程；未指定则 attach 当前前台应用（最常用）
  const isSpawn = target && String(target).startsWith('spawn:');
  const spawnPkg = isSpawn ? String(target).slice(6) : '';

  const buildAttachArgs = async (t) => {
    const a = ['-H', `127.0.0.1:${port}`];
    if (t) {
      // 优先按 PID attach：frida-ps 枚举在部分环境（frida16.7.19+Nox9）会 NPE，
      // 而 -p <PID> 走的是完全不同的路径，实测稳定可用。用 adb 直接取 PID，绕开枚举。
      const pid = await resolvePidByName(t);
      if (pid) {
        a.push('-p', String(pid));
      } else {
        // 兜底：仍按进程名（-n），仅在确实取不到 PID 时用
        const resolved = await resolveFridaProcessName(t);
        a.push('-n', (resolved && resolved.name) ? resolved.name : t);
      }
    } else {
      a.push('-F');
    }
    a.push('-l', tempFile);
    return a;
  };

  try {
    if (isSpawn) {
      const spawnArgs = ['-H', `127.0.0.1:${port}`, '-f', spawnPkg, '-l', tempFile];
      const out = await runFridaOnce(spawnArgs, tempFile, opts);
      // 兼容性兜底：某些 frida-server 版本在特定模拟器上 spawn 会失败
      // （实测 frida 17.x 于 Nox Android9：java.lang.NullPointerException
      //  queryIntentActivities）。此时 **自动回退 attach**：先用 adb 拉起 App，
      //  再 -n attach 到其进程，同样能挂上启动期钩子（多数场景等价可用）。
      if (out && /Failed to spawn|queryIntentActivities|NullPointerException|unable to spawn|permission denied|Unable to find process|unable to attach|process not found|not found/i.test(out) && !/\[DATA\]|\[HIT\]/.test(out)) {
        console.warn('[Frida] spawn 失败，回退 attach 模式: ' + String(out).slice(0, 200));
        const adbPort = config.emulator.adb_port;
        try {
          await adbEnsureConnected(adbPort);
          // 用 monkey 拉起主 Activity（比 am start 更省心：自动解析 launcher）
          await new Promise((res) => {
            const c = spawn(resolveAdbPath(), ['-s', `127.0.0.1:${adbPort}`, 'shell', 'monkey', '-p', spawnPkg, '-c', 'android.intent.category.LAUNCHER', '1'], { shell: false, windowsHide: true });
            c.on('error', () => res()); c.on('close', () => res());
            setTimeout(() => { try { c.kill(); } catch (e) {} res(); }, 8000);
          });
          await new Promise(r => setTimeout(r, 2500)); // 等进程起来
          const attachArgs = await buildAttachArgs(spawnPkg);
          const attachOut = await runFridaOnce(attachArgs, tempFile, opts);
          return { success: true, output: `[spawn 失败已回退 attach]\n` + attachOut };
        } catch (e) {
          return { success: true, output: out };
        }
      }
      return { success: true, output: out };
    }
    // 普通 attach 路径：若目标是包名且当前没有对应进程，frida 的 -n 会
    // "unable to find process"（App 还没启动）。这里先自动用 adb 拉起 App，再 attach，
    // 避免"未在运行进程中找到"直接失败（本题场景：装包成功后 App 未启动就点运行 Hook）。
    if (target) {
      const resolved = await resolveFridaProcessName(target);
      if (!resolved) {
        // 目标看起来是包名（含点）→ 尝试拉起来
        if (/^[a-zA-Z][\w]*(\.[\w]+)+$/.test(String(target))) {
          const adbPort = config.emulator.adb_port;
          await adbEnsureConnected(adbPort);
          await new Promise((res) => {
            const c = spawn(resolveAdbPath(), ['-s', `127.0.0.1:${adbPort}`, 'shell', 'monkey', '-p', String(target), '-c', 'android.intent.category.LAUNCHER', '1'], { shell: false, windowsHide: true });
            c.on('error', () => res()); c.on('close', () => res());
            setTimeout(() => { try { c.kill(); } catch (e) {} res(); }, 8000);
          });
          await new Promise(r => setTimeout(r, 2500)); // 等进程起来
        }
      }
    }
    const attachArgs = await buildAttachArgs(target);
    let out = await runFridaOnce(attachArgs, tempFile, opts);
    // `-F`（附加前台应用）在 frida-ps 枚举坏掉的环境也会失败；此时取"当前前台包名的 PID"再 attach。
    if (!target && out && /queryIntentActivities|NullPointerException|Unable to get frontmost|unable to find process|not found/i.test(out) && !/\[DATA\]|\[HIT\]/.test(out)) {
      const fg = await adbForegroundPackage();
      if (fg) {
        const pid = await resolvePidByName(fg);
        if (pid) {
          const args2 = ['-H', `127.0.0.1:${port}`, '-p', String(pid), '-l', tempFile];
          const out2 = await runFridaOnce(args2, tempFile, opts);
          return { success: true, output: `[-F 失败，改按前台应用 PID=${pid}(${fg}) attach]\n` + out2 };
        }
      }
    }
    return { success: true, output: out };
  } catch (err) {
    try { fs.unlinkSync(tempFile); } catch (e) {}
    return { success: false, error: err.message, output: '' };
  }
}

// 取当前前台包名（dumpsys activity）。frida -F 失败时的替代定位方式。
function adbForegroundPackage() {
  return new Promise((resolve) => {
    const port = config.emulator.adb_port;
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const c = spawn(resolveAdbPath(), ['-s', `127.0.0.1:${port}`, 'shell', 'dumpsys', 'activity', 'activities'], { shell: false, windowsHide: true });
      let o = '';
      c.stdout.on('data', d => o += d.toString());
      c.on('error', () => fin(null));
      c.on('close', () => {
        // 形如：mResumedActivity: ActivityRecord{... com.pkg/.Activity ...}
        const m = String(o).match(/mResumedActivity:.*?\s([a-zA-Z][\w]*(\.[\w]+)+)\//)
          || String(o).match(/topResumedActivity.*?\s([a-zA-Z][\w]*(\.[\w]+)+)\//);
        fin(m ? m[1] : null);
      });
      setTimeout(() => { try { c.kill(); } catch (e) {} fin(null); }, 8000);
    } catch (e) { fin(null); }
  });
}

// 单次 frida 执行：spawn 一个 frida 进程，滚动窗口抓取输出后解析。
// 返回合并后的输出字符串（不抛异常）。
function runFridaOnce(args, tempFile, opts) {
  return new Promise((resolve) => {
    const child = spawn('frida', args, { shell: false });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let idleTimer = null;
    // 抓取策略：滚动窗口（rolling window）。
    //  - 每隔 windowMs 收到"新数据"就重置窗口 → 只要持续有数据就一直抓；
    //  - 连续 windowMs 无任何新数据才收尾；
    //  - 另设一个宽松的绝对上限 hardCapMs 防永久挂死。
    // 默认：首次/空闲窗口 60s，绝对上限 600s（10 分钟）。
    const o = (typeof opts === 'object' && opts) || {};
    const IDLE_WINDOW = Number(o.windowMs) > 0 ? Number(o.windowMs) : (Number(o.idleMs) > 0 ? Number(o.idleMs) : 60000);
    const HARD_CAP = Number(o.hardCapMs) > 0 ? Number(o.hardCapMs) : (Number(o.maxMs) > 0 ? Math.max(Number(o.maxMs), 120000) : 600000);
    let lastDataAt = Date.now();
    let dataCount = 0;    // 关键数据条数（[DATA] + flag），用于收尾报告
    let hitCount = 0;     // [HIT] 命中痕迹条数，用于收尾报告（噪音也提示"确实有输出"）
    let chunkCount = 0;   // 收到的 stdout 数据块数

    const finish = (msg) => {
      if (settled) return;
      settled = true;
      try { clearTimeout(hardTimer); } catch (e) {}
      try { clearTimeout(idleTimer); } catch (e) {}
      try { child.kill(); } catch (e) {}
      // 注意：不在此删除 tempFile —— spawn 失败回退 attach 时会复用同一脚本文件，
      // 由 execFridaHook 在所有尝试结束后统一清理。
      resolve(msg);
    };

    // 重置空闲计时：每次调用表示"刚有新数据"
    const bump = () => {
      lastDataAt = Date.now();
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        finish((stdout || stderr) + `\n[连续 ${Math.round(IDLE_WINDOW / 1000)}s 无新数据，抓取结束（共 ${dataCount} 条关键数据、${hitCount} 条命中痕迹、${chunkCount} 个输出块）]`);
      }, IDLE_WINDOW);
    };

    child.stdout.on('data', (d) => {
      stdout += d.toString();
      chunkCount++;
      // 统计进度：[DATA]/flag 记为"关键数据"，[HIT] 记为"命中痕迹"，两者都进收尾报告
      const dataHits = (stdout.match(/\[DATA\]/g) || []).length;
      const hitHits = (stdout.match(/\[HIT\]/g) || []).length;
      const flagHit = /NCTF\{|flag\{|ctf\{/i.test(stdout);
      dataCount = dataHits + (flagHit ? 1 : 0);
      hitCount = hitHits;
      // 关键：滚动窗口按"任何新输出"续期（这才是"连续 N 秒无*任何*数据"的本意）。
      // 旧逻辑只在 [DATA]/flag 出现时续期 —— 当输出全是 [HIT] 噪音或 send() 信息时，
      // 窗口不续期，60s 后误报"共 0 条关键数据"直接收尾（实战踩坑）。
      bump();
      // 脚本 [done]：仅在已经抓到过"关键数据"后才认，避免脚本过早收尾
      if (/\[done\]/.test(stdout) && (dataHits > 0 || flagHit)) {
        finish(stdout + '\n[脚本主动收尾，frida 已停止]');
      }
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      // frida 的致命错误（attach/spawn 失败）走 stderr，需据此提前结束并如实返回
      if (/Failed to spawn|unable to find process|unable to attach|Failed to connect|not found/i.test(stderr)) {
        finish((stdout + '\n' + stderr).trim());
      }
      // `connection closed` 单独识别：它九成是**客户端与服务端版本不匹配**，
      // 而不是"服务没起来"。不点破的话会让人反复重启 frida-server 白耗时间。
      if (/connection closed|Connection closed/i.test(stderr)) {
        finish((stdout + '\n' + stderr).trim()
          + '\n\n⚠ `connection closed` 最常见的原因是 **frida 客户端与 frida-server 版本不一致**'
          + '（服务端进程在、端口也通，但握手即断）。'
          + '\n排查：`adb shell /data/local/tmp/frida-server --version` 与 `frida --version` 对比，'
          + '用 `pip install -U "frida==<服务端版本>"` 对齐后重试。'
          + '\n注意：Frida 17 起**移除了内置 Java bridge**，脚本里的 `Java.perform` 会报 "Java is not defined"，'
          + '此时改用纯 Native hook（Interceptor.attach + Module.enumerateExports），或降级到 frida 16.x。');
      }
    });

    child.on('error', (err) => {
      finish(`无法启动 frida: ${err.message}\n请确认已安装 frida、frida-server 已在模拟器运行并做好端口转发（adb forward tcp:${config.emulator.frida_port} tcp:${config.emulator.frida_port}）`);
    });

    child.on('close', () => {
      // frida 脚本会保持 attach；正常退出时返回已收集输出（stdout 与 stderr 合并，错误优先）
      finish(stdout || stderr || 'Frida已结束（无输出）');
    });

    // 绝对安全上限（防永久挂死）：到点即止，但通常会先被 idle 窗口结束
    const hardTimer = setTimeout(() => {
      finish((stdout || stderr || `（${Math.round(HARD_CAP / 1000)}秒内无输出）`) + `\n[达到绝对上限 ${Math.round(HARD_CAP / 1000)}s，frida 已停止]`);
    }, HARD_CAP);
    // 启动即开窗：若首窗内一直没有数据，也会在 IDLE_WINDOW 后收尾（不再是 25s 硬断）
    bump();
  });
}

// IPC: 用 adb 驱动 App 界面（点击/手势/输入），让界面触发的校验代码真正执行。
// 输入 steps: [{type:'tap',x,y} | {type:'swipe',points:[[x,y],...],duration} | {type:'text',value} |
//              {type:'key',code} | {type:'sleep',ms}]
ipcMain.handle('drive-app-ui', async (event, steps) => {
  // 与其它 adb 路径统一：走 resolveAdbPath()（系统 adb 优先），并在驱动前重连设备，
  // 避免用 nox_adb(v36) 直连导致的 daemon 版本互杀（旧实现硬用 config.tools.nox_adb）。
  const adbPath = resolveAdbPath();
  const port = config.emulator.adb_port;
  const dev = `127.0.0.1:${port}`;
  await adbEnsureConnected(port);
  const run = (args, timeout = 15000) => new Promise((resolve) => {
    const child = spawn(adbPath, ['-s', dev, 'shell'].concat(args), { shell: false, windowsHide: true });
    let out = '', err = '';
    const t = setTimeout(() => { try { child.kill(); } catch (e) {} }, timeout);
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', d => { err += d.toString(); });
    child.on('error', e => { clearTimeout(t); resolve({ ok: false, err: e.message }); });
    child.on('close', () => { clearTimeout(t); resolve({ ok: true, out: out.trim(), err: err.trim() }); });
  });

  const log = [];
  try {
    for (const s of (Array.isArray(steps) ? steps : [])) {
      if (!s || !s.type) continue;
      if (s.type === 'sleep') { await sleep(Number(s.ms) || 500); log.push(`sleep ${s.ms || 500}ms`); continue; }
      if (s.type === 'tap') {
        const r = await run(['input', 'tap', String(Math.round(s.x)), String(Math.round(s.y))]);
        log.push(`tap(${Math.round(s.x)},${Math.round(s.y)}) ${r.ok ? 'ok' : 'err'}`);
      } else if (s.type === 'text') {
        // adb input text 不支持空格/特殊字符，逐段转义（空格用 %s）
        const v = String(s.value || '').replace(/ /g, '%s');
        const r = await run(['input', 'text', v]);
        log.push(`text(${v}) ${r.ok ? 'ok' : 'err'}`);
      } else if (s.type === 'key') {
        const r = await run(['input', 'keyevent', String(s.code)]);
        log.push(`key(${s.code}) ${r.ok ? 'ok' : 'err'}`);
      } else if (s.type === 'swipe' && Array.isArray(s.points) && s.points.length >= 2) {
        // 折线手势：分段连续 swipe（每段用连续 duration 保证粘连）
        const pts = s.points;
        for (let i = 0; i < pts.length - 1; i++) {
          const [x1, y1] = pts[i], [x2, y2] = pts[i + 1];
          const dur = Number(s.duration) || Math.max(60, Math.round(Math.hypot(x2 - x1, y2 - y1) / 2));
          await run(['input', 'swipe', String(Math.round(x1)), String(Math.round(y1)), String(Math.round(x2)), String(Math.round(y2)), String(dur)]);
        }
        log.push(`swipe ${pts.length} 点`);
      }
    }
    return { success: true, log };
  } catch (err) {
    return { success: false, error: err.message, log };
  }
});

// IPC: 校验（并尝试修复）Frida 脚本语法。
// 渲染层受 CSP 限制无法用 new Function 校验，故放主进程（Node vm）做。
// 返回 { ok, script, repaired, error }
ipcMain.handle('validate-frida-script', async (event, src) => {
  try {
    const vm = require('vm');
    const code = String(src || '');
    const tryParse = (s) => { try { new vm.Script(s); return null; } catch (e) { return e.message; } };

    // 结构 lint 先跑：语法合法但注释写坏（`/ ==== /`）的情况 vm.Script 抓不到，
    // 脚本能注入却整段失效（NaughtyBoy 实测：0 条 [DATA]、白白注入一轮）。
    let structural = null;
    try {
      const { lintAndRepair } = require('./frida-lint');
      structural = lintAndRepair(code);
    } catch (e) { structural = null; }

    let err = tryParse(code);
    if (!err) {
      if (structural && !structural.ok && structural.remaining.length) {
        // 修复后仍有结构问题 → 当作失败，让上层带错误重新生成
        return {
          ok: false, script: null, repaired: false,
          error: '结构检查未通过: '
            + structural.remaining.slice(0, 3).map(x => (x.line ? `L${x.line} ` : '') + x.hint).join('; '),
          structuralIssues: structural.remaining,
        };
      }
      const out = (structural && structural.repairs.length) ? structural.script : code;
      return {
        ok: true, script: out, repaired: !!(structural && structural.repairs.length),
        structuralIssues: structural ? structural.remaining : undefined,
      };
    }

    // 修复：转义正则字面量内部未转义的 '/'（如 /data/dalvik、res/x.xml）
    const repaired = code.split('\n').map(line => {
      let out = '', i = 0, inRegex = false, inStr = null, prevSig = '';
      while (i < line.length) {
        const ch = line[i];
        if (inStr) {
          out += ch;
          if (ch === '\\') { out += (line[i + 1] || ''); i += 2; continue; }
          if (ch === inStr) inStr = null;
          i++; continue;
        }
        if (inRegex) {
          if (ch === '\\') { out += ch + (line[i + 1] || ''); i += 2; continue; }
          if (ch === '[') {
            out += ch; i++;
            while (i < line.length && line[i] !== ']') { if (line[i] === '\\') { out += line[i] + (line[i + 1] || ''); i += 2; continue; } out += line[i]; i++; }
            if (i < line.length) { out += ']'; i++; }
            continue;
          }
          if (ch === '/') {
            const rest = line.slice(i + 1);
            if (/^[gimsuy]*\s*([,;)\]}.]|$)/.test(rest)) { out += ch; inRegex = false; i++; continue; }
            out += '\\/'; i++; continue;
          }
          out += ch; i++; continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; out += ch; i++; prevSig = ch; continue; }
        if (ch === '/' && !/[\w)\]]$/.test(prevSig)) {
          if (line[i + 1] === '/' || line[i + 1] === '*') { out += ch; i++; prevSig = ch; continue; }
          inRegex = true; out += ch; i++; prevSig = ch; continue;
        }
        out += ch;
        if (!/\s/.test(ch)) prevSig = ch;
        i++;
      }
      return out;
    }).join('\n');

    const err2 = tryParse(repaired);
    if (!err2) {
      // 正则修复成功后再过一遍结构 lint（坏注释可能同时存在）
      let s2 = null;
      try {
        const { lintAndRepair } = require('./frida-lint');
        s2 = lintAndRepair(repaired);
      } catch (e) { s2 = null; }
      if (s2 && !s2.ok && s2.remaining.length) {
        return {
          ok: false, script: null, repaired: false,
          error: '结构检查未通过: '
            + s2.remaining.slice(0, 3).map(x => (x.line ? `L${x.line} ` : '') + x.hint).join('; '),
          structuralIssues: s2.remaining,
        };
      }
      return { ok: true, script: s2 ? s2.script : repaired, repaired: true };
    }

    // 修复：输出被截断（"Unexpected end of input"，max_tokens 不足的 Hook 脚本常见）
    // → 从尾部逐步回退到最近的完整语句边界，按括号栈补齐未闭合的 { ( [ ，
    //   直到能通过语法解析。每一步都以真实 vm 解析为闸，修不好就如实返回失败。
    if (/end of input/i.test(String(err || '') + String(err2 || ''))) {
      const lines = code.split('\n');
      const closers = { '{': '}', '(': ')', '[': ']' };
      const scan = (txt) => {
        const st = [];
        let inStr = null, esc = false, ln = false, bk = false;
        for (let i = 0; i < txt.length; i++) {
          const ch = txt[i], nx = txt[i + 1];
          if (ln) { if (ch === '\n') ln = false; continue; }
          if (bk) { if (ch === '*' && nx === '/') { bk = false; i++; } continue; }
          if (inStr) {
            if (esc) { esc = false; continue; }
            if (ch === '\\') { esc = true; continue; }
            if (ch === inStr) inStr = null;
            continue;
          }
          if (ch === '/' && nx === '/') { ln = true; continue; }
          if (ch === '/' && nx === '*') { bk = true; i++; continue; }
          if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
          if (ch === '{' || ch === '(' || ch === '[') st.push(ch);
          else if (ch === '}' || ch === ')' || ch === ']') st.pop();
        }
        return st;
      };
      for (let cut = lines.length; cut >= Math.max(1, lines.length - 14); cut--) {
        const cand = lines.slice(0, cut).join('\n');
        const fixed = cand + scan(cand).slice().reverse().map(c => closers[c] || '').join('');
        if (!tryParse(fixed)) return { ok: true, script: fixed, repaired: true };
      }
    }
    return { ok: false, script: null, repaired: false, error: (err || err2) };
  } catch (e) {
    return { ok: false, script: null, repaired: false, error: e.message };
  }
});

// IPC: 测试Claude连接
ipcMain.handle('test-claude-connection', async (event) => {
  try {
    const result = await sendClaudeRequest([
      { role: 'user', content: '你好，请回复"连接成功"' }
    ], '你是CTF逆向工程助手，请简短回复。');

    return {
      success: result.success,
      message: result.success ? 'Claude API 连接成功' : result.error
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ========== Kali 虚拟机 ==========

// 查找 .vmx（找不到返回 null）
function findVmxFile() {
  const kaliPath = config.kali.vmxPath;
  try {
    if (kaliPath && fs.existsSync(kaliPath)) {
      const st = fs.statSync(kaliPath);
      if (st.isFile() && kaliPath.toLowerCase().endsWith('.vmx')) return kaliPath;
      if (st.isDirectory()) {
        const files = fs.readdirSync(kaliPath);
        const vmx = files.find(f => f.toLowerCase().endsWith('.vmx'));
        if (vmx) return path.join(kaliPath, vmx);
      }
    }
  } catch (e) { /* 目录不可读 */ }
  return null;
}

// 解析 vmrun.exe 的绝对路径。
// 为什么需要：vmrun 默认不在 PATH（实测本机装在 E:\xnj\，Windows 的 PATH 里没有它），
// spawn('vmrun') 找不到就报 ENOENT → Kali 从未被真正启动过，
// 历次日志里的 "Timed out while waiting for handshake" 全是这一个根因。
// 解析顺序：PATH → VMware 注册表 InstallPath → 常见安装目录。
function findVmrunPath() {
  const pathMod = require('path');
  const execSync = require('child_process').execSync;
  // 1) PATH 里能找到就直接用
  try {
    const out = execSync('where vmrun 2>nul', { encoding: 'utf8', windowsHide: true, timeout: 5000 }).trim();
    if (out) return out.split(/\r?\n/)[0];
  } catch (e) { /* 不在 PATH */ }
  // 2) VMware 注册表 InstallPath（本机实测在 HKLM\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation）
  try {
    const reg = execSync('reg query "HKLM\\SOFTWARE\\WOW6432Node\\VMware, Inc.\\VMware Workstation" /v InstallPath',
      { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    const m = reg.match(/InstallPath\s+REG_SZ\s+(\S+)/);
    if (m) {
      const p = pathMod.join(m[1].trim(), 'vmrun.exe');
      if (fs.existsSync(p)) return p;
    }
  } catch (e) { /* 注册表键不存在 */ }
  try {
    const reg = execSync('reg query "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Workstation" /v InstallPath',
      { encoding: 'utf8', windowsHide: true, timeout: 5000 });
    const m = reg.match(/InstallPath\s+REG_SZ\s+(\S+)/);
    if (m) {
      const p = pathMod.join(m[1].trim(), 'vmrun.exe');
      if (fs.existsSync(p)) return p;
    }
  } catch (e) { /* 同上 */ }
  // 3) 常见安装目录兜底
  for (const d of ['C:\\Program Files (x86)\\VMware\\VMware Workstation', 'C:\\Program Files\\VMware\\VMware Workstation']) {
    const p = pathMod.join(d, 'vmrun.exe');
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// 启动Kali虚拟机
ipcMain.handle('kali-start-vm', async (event) => {
  try {
    const vmxFile = findVmxFile();
    if (!vmxFile) {
      return { success: false, error: `未找到 .vmx 文件，请检查 kali.vmxPath 配置（当前: ${config.kali.vmxPath}）` };
    }

    // 等待 spawn 结果：vmrun 不存在/不可执行时如实报错，而不是假成功
    // vmrun 用绝对路径（见 findVmrunPath 的说明：PATH 里通常没有它）
    const vmrunExe = findVmrunPath();
    if (!vmrunExe) {
      return { success: false, error: '未找到 vmrun.exe（PATH、注册表 InstallPath、常见目录都没有）。请确认已安装 VMware Workstation。' };
    }
    const spawnErr = await new Promise((resolve) => {
      const child = spawn(vmrunExe, ['start', vmxFile, 'nogui'], { shell: false, windowsHide: true });
      const t = setTimeout(() => resolve(null), 3000); // 3秒无 error 视为已拉起
      child.on('error', (err) => { clearTimeout(t); resolve(err.message); });
    });
    if (spawnErr) {
      return { success: false, error: `vmrun 启动失败: ${spawnErr}（请确认已安装 VMware Workstation 且 vmrun 在 PATH 中）` };
    }

    return {
      success: true,
      message: 'Kali虚拟机启动中，请等待1-2分钟...',
      vmxPath: vmxFile
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 关闭Kali虚拟机
ipcMain.handle('kali-stop-vm', async (event) => {
  try {
    const vmxFile = findVmxFile();
    if (!vmxFile) {
      return { success: false, error: `未找到 .vmx 文件，无法关闭虚拟机（kali.vmxPath: ${config.kali.vmxPath}）` };
    }

    // 同 start：vmrun 用绝对路径（findVmrunPath）
    const vmrunExe = findVmrunPath() || 'vmrun';
    const child = spawn(vmrunExe, ['stop', vmxFile, 'soft'], { shell: false, windowsHide: true });
    child.on('error', (err) => {
      console.log('VMware关闭失败:', err.message);
    });

    return {
      success: true,
      message: 'Kali虚拟机关闭中...'
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 通过 ssh2 在 Kali 中执行命令（Windows 无 sshpass，原 exec+sshpass 方案在 Windows 上不可用）
function sshExec(command, timeoutMs = 60000) {
  return new Promise((resolve) => {
    const { sshHost, sshPort, sshUser, sshPass } = config.kali;
    const conn = new SshClient();
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch (e) {}
      resolve(r);
    };
    const timer = setTimeout(() => done({ success: false, stdout: '', stderr: '', error: 'SSH 执行超时' }), timeoutMs);

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return done({ success: false, stdout: '', stderr: '', error: err.message });
        }
        let stdout = '', stderr = '';
        // ssh2 的 close 回调带 (code, signal)。旧实现忽略它，于是 `binwalk ...` 以退出码 1
        // 失败时仍然返回 success:true + 空 stdout —— 上层只能看到"成功了但没输出"，
        // 这正是 Kali 链路把失败当空结果、继续往下走的根因。
        stream.on('close', (code, signal) => {
          clearTimeout(timer);
          const exitCode = Number.isFinite(code) ? code : (signal ? 1 : 0);
          // 退出码非 0 = 命令失败；但保留 stdout/stderr 原文，便于上层展示真实错误。
          done({
            success: exitCode === 0,
            exitCode,
            signal: signal || null,
            stdout: truncateOutput(stdout),
            stderr: truncateOutput(stderr),
            error: exitCode === 0 ? null
              : (truncateOutput(stderr).trim() || `命令退出码 ${exitCode}`),
          });
        });
        stream.on('data', (d) => { stdout += d.toString(); });
        stream.stderr.on('data', (d) => { stderr += d.toString(); });
      });
    });

    conn.on('error', (err) => {
      clearTimeout(timer);
      done({ success: false, stdout: '', stderr: '', error: err.message });
    });

    conn.connect({
      host: sshHost,
      port: Number(sshPort) || 22,
      username: sshUser,
      password: sshPass,
      readyTimeout: 15000,
      // CTF 内网环境，跳过主机指纹校验
      hostVerifier: () => true
    });
  });
}

// 在Kali中执行命令
ipcMain.handle('kali-exec-command', async (event, command) => {
  try {
    return await sshExec(command, 60000);
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 测试Kali连接
ipcMain.handle('kali-test-connection', async (event) => {
  try {
    const r = await sshExec('echo connected && uname -a', 20000);
    if (!r.success) {
      return { success: false, error: '无法连接到Kali: ' + (r.error || '未知错误') };
    }
    return { success: true, message: 'Kali连接成功', info: r.stdout };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ========== 工作目录与就绪轮询 ==========

// 渲染层同步当前题目文件所在目录（AI glob/grep 的搜索根）
// file/fileType 可选：用于 ida_dbg 判断 PE(local) 还是 ELF(remote)
ipcMain.handle('set-workdir', async (event, dir, file, fileType) => {
  currentWorkDir = dir || null;
  if (file) currentTargetFile = String(file);
  if (fileType) currentTargetKind = String(fileType).toUpperCase();
  return { success: true };
});

// 渲染层在 caseInit 成功后同步 CASE 目录（主进程没有 state.caseDir）
ipcMain.handle('set-case-dir', async (event, dir) => {
  currentCaseDir = dir ? String(dir) : null;
  return { success: true, caseDir: currentCaseDir };
});

// 读取 run_python 产物登记（渲染层在 finalizeSolve 时逐条转成 evidence）
ipcMain.handle('case-artifacts', async () => {
  try {
    if (!currentCaseDir) return { success: true, artifacts: [] };
    const file = path.join(currentCaseDir, 'evidence', 'artifacts.jsonl');
    if (!fs.existsSync(file)) return { success: true, artifacts: [] };
    const artifacts = fs.readFileSync(file, 'utf8')
      .split(/\r?\n/).filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch (e) { return null; } })
      .filter(Boolean);
    return { success: true, artifacts };
  } catch (e) {
    return { success: false, error: e.message, artifacts: [] };
  }
});

// Kali 预检决策（渲染层需要先知道"要不要发远程命令"；决策逻辑留在纯模块里可单测）
ipcMain.handle('kali-preflight-decide', async (event, input) => {
  try { return { success: true, decision: decideKaliPreflight(input || {}) }; }
  catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('kali-remote-plan', async (event, input) => {
  try { return { success: true, plan: decideKaliRemotePlan(input || {}) }; }
  catch (e) { return { success: false, error: e.message }; }
});

// 远程执行错误分类（渲染层/工具共用一份前缀语义）
ipcMain.handle('classify-remote-error', async (event, input) => {
  try { return { success: true, result: classifyRemoteError(input || {}) }; }
  catch (e) { return { success: false, error: e.message }; }
});

// 文件能力分诊（渲染层在分派前调用，取代按扩展名/口令的路由）
ipcMain.handle('detect-capabilities', async (event, filePath, fileTypeHint) => {
  try {
    if (!filePath || !fs.existsSync(filePath)) return { success: false, error: '文件不存在: ' + filePath };
    const buf = fs.readFileSync(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const capabilities = detectCapabilities(buf, ext);
    // 路由决策与能力判定同源，避免渲染层再写一份规则（两处规则必然漂移）
    return { success: true, capabilities, ext, route: decideRoute({ fileType: fileTypeHint, ext, capabilities }) };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 自修改特征 + 摘要目标存在性（渲染层提示词用；两者都只读文件字节，不依赖 IDA）
ipcMain.handle('analyze-smc', async (event, filePath) => {
  try {
    if (!filePath || !fs.existsSync(filePath)) return { success: false, error: '文件不存在: ' + filePath };
    const buf = fs.readFileSync(filePath);
    const imageMap = parseImageMap(buf);
    const smc = detectSmcSignals(buf, imageMap);
    const hash = assessHashTarget(buf, imageMap);
    return { success: true, smc, hash };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 流量提取的公共实现（AI 工具 traffic_extract 与 IPC traffic-extract 共用）。
// 输出限额：每流 previewHex ≤2048 字节、总返回 ≤24000 字符；超限部分落盘并返回路径，
// 否则会被 truncateOutput(8000) 或 persistToolResult(24000) 从尾部截断。
function trafficExtract(filePath, opts) {
  const o = opts || {};
  const r = pcap.analyzePcap(filePath, { previewBytes: 2048 });
  if (!r.success) return { success: false, error: `traffic_extract 失败: ${r.error}` };

  const proto = String(o.protocol || 'auto').toLowerCase();
  let flows = r.flows;
  if (proto === 'http') flows = flows.filter(f => f.http);
  else if (proto === 'tcp') flows = flows.slice();
  const maxFlows = Number(o.max_flows) > 0 ? Number(o.max_flows) : 20;
  flows = flows.slice(0, maxFlows);

  const lines = [];
  lines.push(`pcap: ${path.basename(filePath)}  magic=${r.magic}  packets=${r.packets}  flows=${r.flows.length}  http=${r.http}`);
  for (const f of flows) {
    lines.push('');
    lines.push(`## ${f.src} ↔ ${f.dst}（ports ${f.ports.join('/')}）`);
    lines.push(`- packets=${f.packets} bytes=${f.bytes} payload=${f.payloadBytes} http=${f.http} entropy=${f.entropy}`);
    lines.push(`- previewHex${f.previewTruncated ? `（前 2048B，原 ${f.payloadBytes}B）` : ''}: ${f.previewHex}`);
  }
  let text = lines.join('\n');

  const MAX_RET = 24000;
  let outPath = '';
  if (text.length > MAX_RET) {
    try {
      const dir = currentCaseDir ? path.join(currentCaseDir, 'evidence') : app.getPath('temp');
      fs.mkdirSync(dir, { recursive: true });
      outPath = path.join(dir, `traffic_${Date.now()}.json`);
      fs.writeFileSync(outPath, JSON.stringify(r, null, 1));
      text = text.slice(0, MAX_RET) + `\n...[已截断，完整结果落盘: ${outPath}]`;
    } catch (e) {
      text = text.slice(0, MAX_RET) + '\n...[已截断]';
    }
  }
  return { success: true, result: text, magic: r.magic, packets: r.packets, flows: r.flows.length, http: r.http, outPath };
}

// 流量提取（渲染层走这条：executeToolCall 只在 AI 循环内，渲染层没有通用工具通道）
ipcMain.handle('traffic-extract', async (event, args) => {
  try {
    const a = args || {};
    const p = String(a.path || '').trim();
    if (!p) return { success: false, error: '参数错误：path 为空' };
    if (!fs.existsSync(p)) return { success: false, error: '文件不存在: ' + p };
    return trafficExtract(p, a);
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 获取应用路径（渲染层保存脚本/WP 用，替代硬编码桌面路径）
ipcMain.handle('get-app-paths', async () => {
  return {
    appDir: app.getAppPath(),
    userData: app.getPath('userData'),
    temp: app.getPath('temp'),
    scriptsDir: (config.workspace && config.workspace.scriptsDir) || path.join(writableBase(), 'scripts')
  };
});

// ========== Agent Skills 引擎 ==========
// skills/（内置，随应用分发）+ userData/skills/（用户自装），frontmatter 格式兼容
// Anthropic Agent Skills / ljagiello/ctf-skills（MIT）。AI 通过 read_skill 工具按需加载。

function parseSkillFrontmatter(text) {
  const meta = {};
  const m = text.match(/^---\s*\n([\s\S]*?)\n---\s*\n/);
  if (!m) return meta;
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([A-Za-z_-]+)\s*:\s*(.*)$/);
    if (kv) meta[kv[1].trim()] = kv[2].trim().replace(/^["']|["']$/g, '');
  }
  return meta;
}

function listSkillDirs() {
  const dirs = [
    path.join(app.getAppPath(), 'skills'),
    path.join(app.getPath('userData'), 'skills')
  ];
  const seen = new Set();
  const out = [];
  for (const dir of dirs) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      const skillFile = path.join(dir, ent.name, 'SKILL.md');
      if (!fs.existsSync(skillFile) || seen.has(ent.name)) continue;
      seen.add(ent.name);
      let content = '';
      try { content = fs.readFileSync(skillFile, 'utf8'); } catch (e) { continue; }
      const meta = parseSkillFrontmatter(content);
      out.push({
        name: meta.name || ent.name,
        description: meta.description || '',
        dir: ent.name,
        path: skillFile,
        source: dir.startsWith(app.getPath('userData')) ? 'user' : 'builtin'
      });
    }
  }
  return out;
}

ipcMain.handle('skills-list', async () => {
  try {
    const skills = listSkillDirs();
    return { success: true, skills };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('skill-read', async (event, name) => {
  try {
    const skills = listSkillDirs();
    const skill = skills.find(s => s.name === name || s.dir === name);
    if (!skill) return { success: false, error: `未找到技能: ${name}` };
    const content = fs.readFileSync(skill.path, 'utf8');
    return { success: true, name: skill.name, content };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ========== Wiki 知识库引擎 ==========
// wiki/（内置，随应用分发）+ userData/wiki/（用户自加），纯 .md 目录。
// 与 skills/ 的分工：skills=方法论/工作流，wiki=具体手法+验证过的代码片段+踩坑。
// AI 通过 wiki_search（按关键词找页）/ wiki_read（读整页）按需检索，为后续"知识库 wiki 化"铺路。

function listWikiDirs() {
  const dirs = [
    path.join(app.getAppPath(), 'wiki'),
    path.join(app.getPath('userData'), 'wiki')
  ];
  const seen = new Set();
  const out = [];
  for (const dir of dirs) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
    for (const ent of entries) {
      if (ent.isDirectory()) {
        const sub = path.join(dir, ent.name);
        let files;
        try { files = fs.readdirSync(sub, { withFileTypes: true }); } catch (e) { continue; }
        for (const f of files) {
          if (!f.isFile() || !/\.(md|markdown|txt)$/i.test(f.name)) continue;
          const rel = `${ent.name}/${f.name}`;
          if (seen.has(rel)) continue;
          seen.add(rel);
          out.push({ rel, name: f.name.replace(/\.[^.]+$/, ''), group: ent.name, path: path.join(sub, f.name), source: dir.startsWith(app.getPath('userData')) ? 'user' : 'builtin' });
        }
      } else if (ent.isFile() && /\.(md|markdown|txt)$/i.test(ent.name)) {
        const rel = ent.name;
        if (seen.has(rel)) continue;
        seen.add(rel);
        out.push({ rel, name: ent.name.replace(/\.[^.]+$/, ''), group: '(root)', path: path.join(dir, ent.name), source: dir.startsWith(app.getPath('userData')) ? 'user' : 'builtin' });
      }
    }
  }
  return out;
}

// 关键词检索：按标题/文件名/正文计分，返回最相关的若干页（含摘要片段）。
// 升级（借鉴 Des-CTF-KB）：解析 YAML front matter，让命中 tags/vuln_type/attack_chain/
// reasoning_chain/key_observations 的条目**加权**（结构化 meta 命中远重于正文散命中）；
// 并优先把带 meta 的"条目页"排前，方便 AI 直接拿到 attack_chain/思维链。
// 解析 YAML meta 的单个字段值，兼容三种真实写法：
//   ① 行内：`key: value`
//   ② 列表：`key:` 换行 + `- 步骤`（43 篇逆向条目大量使用这种！）
//   ③ 块标量：`key: |` 或 `> ` + 后续缩进行
// 修复史：旧实现用 `^key:[\s\S]*?(?=\n\w+:|$)` + 'm' 标志，因 `$` 在 m 下匹配"行尾"，
// 当 `key:` 后面紧跟换行时非贪婪立即坍缩为空 → 列表写法的 attack_chain/failed_attempts
// 全部解析为空，结构化攻略"存了却传不到 AI"。改为逐行解析，按缩进/列表标记续读。
function pickMetaValue(src, key) {
  const lines = String(src || '').split('\n');
  const parts = [];
  let collecting = false;
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    const top = line.match(/^([A-Za-z_][A-Za-z0-9_]*):(.*)$/);
    if (collecting) {
      if (/^\s*[-*]\s+/.test(line)) { parts.push(line.replace(/^\s*[-*]\s+/, '').trim()); continue; } // 列表项（可零缩进）
      if (/^\s+\S/.test(line)) { parts.push(line.trim()); continue; }                              // 块标量续行（缩进）
      if (top) break;                                                                              // 下一个顶层键
      if (!line.trim()) continue;
      break;
    }
    if (top && top[1].toLowerCase() === String(key).toLowerCase()) {
      const inline = top[2].trim().replace(/^['"]|['"]$/g, '');
      if (inline && inline !== '|' && inline !== '>') parts.push(inline);
      collecting = true;
    }
  }
  return parts.join(' → ');
}

function wikiSearch(query, max = 5) {
  const pages = listWikiDirs();
  const terms = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  const scored = [];
  for (const p of pages) {
    let content = '';
    try { content = fs.readFileSync(p.path, 'utf8'); } catch (e) { continue; }
    const low = content.toLowerCase();
    const rel = p.rel.toLowerCase();
    const firstLine = (content.split('\n').find(l => /^#\s/.test(l)) || '').replace(/^#\s*/, '');
    // 解析结构化 meta 的加权字段。兼容两种写法：
    //   ① YAML front matter（`---` 包裹，用于 wiki 通用页）
    //   ② 正文中的 ```yaml 围栏块（逆向条目库 reverse/*.md 用的是这种）
    // 早先只认 ①，导致 43 篇逆向条目的 tags/attack_chain 加权**完全失效**（结构化 meta 形同虚设）。
    let metaText = '';
    const fmM = content.match(/^---\n([\s\S]*?)\n---/);
    if (fmM) metaText = fmM[1];
    else {
      const fenceM = content.match(/(?:^|\n)[ \t]*```ya?ml[^\n]*\n([\s\S]*?)\n[ \t]*```/);
      if (fenceM) metaText = fenceM[1];
    }
    const hasMeta = !!metaText;
    // 命中打分用小写；展示片段（one_liner/attack_chain 含 flag、密钥，大小写敏感）保留原文。
    let tags = '', attack = '', reasoning = '', keys = '', one = '', vtype = '', fails = '';
    let oneRaw = '', attackRaw = '', failsRaw = '';
    if (metaText) {
      const fm = metaText.toLowerCase();
      // 打分用小写、展示用原文（attack_chain 含 flag/密钥，必须大小写敏感）
      tags = pickMetaValue(fm, 'tags'); attack = pickMetaValue(fm, 'attack_chain'); reasoning = pickMetaValue(fm, 'reasoning_chain');
      keys = pickMetaValue(fm, 'key_observations') + pickMetaValue(fm, 'key_payload') + pickMetaValue(fm, 'failed_attempts') + pickMetaValue(fm, 'lesson');
      // 手法页（wiki/frida、firmware）用 keywords 声明检索词，旧实现未纳入 → 命中率低，补上
      keys += pickMetaValue(fm, 'keywords');
      one = pickMetaValue(fm, 'one_liner');
      vtype = pickMetaValue(fm, 'vuln_type') + pickMetaValue(fm, 'contest') + pickMetaValue(fm, 'difficulty');
      oneRaw = pickMetaValue(metaText, 'one_liner'); attackRaw = pickMetaValue(metaText, 'attack_chain');
      // 失败教训往往比成功更有价值（少走弯路）→ 单列并单独展示
      fails = pickMetaValue(fm, 'failed_attempts') + pickMetaValue(fm, 'lesson');
      failsRaw = pickMetaValue(metaText, 'failed_attempts') + (pickMetaValue(metaText, 'lesson') || '');
    }
    let score = 0;
    for (const t of terms) {
      if (!t) continue;
      score += (rel.includes(t) ? 3 : 0);
      score += (firstLine.toLowerCase().includes(t) ? 4 : 0);
      score += Math.min(low.split(t).length - 1, 8);           // 正文命中
      score += (tags.includes(t) ? 6 : 0);                     // 结构化加权
      score += (one.includes(t) ? 5 : 0);
      score += (attack.includes(t) ? 4 : 0);
      score += (reasoning.includes(t) ? 4 : 0);
      score += (keys.includes(t) ? 5 : 0);
      score += (fails.includes(t) ? 4 : 0);                    // 失败教训同为加权项
      score += (vtype.includes(t) ? 3 : 0);
    }
    if (!terms.length) score = 1;
    if (score > 0) scored.push({ score, page: p, content, title: firstLine, hasMeta, oneRaw, attackRaw, failsRaw });
  }
  scored.sort((a, b) => (b.score - a.score) || (b.hasMeta - a.hasMeta));
  const top = scored.slice(0, Math.max(1, Math.min(Number(max) || 5, 20)));
  if (!top.length) return `未找到与「${query}」相关的知识页。可用页面：\n` + pages.map(p => `- ${p.rel}`).join('\n');
  return top.map(r => {
    // 带结构化 meta 的条目：给"要点 + 解法链 + 避坑"（决策最有用），而不是从正文随便凑 6 行；
    // 无 meta 的页面仍按关键词行取上下文。
    let snippet = '';
    if (r.hasMeta && (r.oneRaw || r.attackRaw || r.failsRaw)) {
      const fmt = (s) => s.replace(/^[a-z_]+:\s*/i, '').replace(/\s+/g, ' ').trim().slice(0, 320);
      snippet = [
        r.oneRaw && `要点：${fmt(r.oneRaw)}`,
        r.attackRaw && `解法链：${fmt(r.attackRaw)}`,
        r.failsRaw && `避坑（失败教训）：${fmt(r.failsRaw)}`,
      ].filter(Boolean).join('\n');
    }
    if (!snippet) {
      const lines = r.content.split('\n');
      const idx = lines.findIndex(l => l.toLowerCase().includes(terms[0] || '\u0000'));
      snippet = lines.slice(Math.max(0, idx), Math.max(0, idx) + 6).join('\n').slice(0, 600);
    }
    return `### ${r.title || r.page.name}  [${r.page.rel}]${r.hasMeta ? '  ★含结构化meta' : ''}\n${snippet}`;
  }).join('\n\n') + `\n\n（用 wiki_read(path=<rel>) 读取整页）`;
}

function wikiRead(nameOrRel) {
  const pages = listWikiDirs();
  const key = String(nameOrRel || '').toLowerCase().replace(/\\/g, '/');
  let page = pages.find(p => p.rel.toLowerCase() === key)
    || pages.find(p => p.rel.toLowerCase().endsWith('/' + key) || p.rel.toLowerCase().endsWith(key + '.md'))
    || pages.find(p => p.name.toLowerCase() === key)
    || pages.find(p => p.rel.toLowerCase().includes(key));
  if (!page) return `未找到知识页: ${nameOrRel}。可用：\n` + pages.map(p => `- ${p.rel}`).join('\n');
  let content = '';
  try { content = fs.readFileSync(page.path, 'utf8'); } catch (e) { return `读取失败: ${e.message}`; }
  return `# 知识页: ${page.rel}\n\n` + (content.length > 12000 ? content.slice(0, 12000) + '\n...[已截断]' : content);
}

ipcMain.handle('wiki-list', async () => {
  try { return { success: true, pages: listWikiDirs().map(p => ({ rel: p.rel, group: p.group, source: p.source })) }; }
  catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('wiki-search', async (event, query, max) => {
  try { return { success: true, result: wikiSearch(query, max) }; }
  catch (err) { return { success: false, error: err.message }; }
});

ipcMain.handle('wiki-read', async (event, nameOrRel) => {
  try { return { success: true, content: wikiRead(nameOrRel) }; }
  catch (err) { return { success: false, error: err.message }; }
});

// ========== CASE 证据体系 ==========
// 每道题一个独立目录：cases/<题名>_<md5前8>/，下有 evidence/（MCP抓取物）、
// scripts/（生成与验证脚本）、timeline.jsonl（操作时间线）。findings.json 由渲染层整体写入。

ipcMain.handle('case-init', async (event, baseName, md5) => {
  try {
    const root = path.join(writableBase(), 'cases');
    const safe = String(baseName || 'challenge').replace(/[^a-zA-Z0-9._\-\u4e00-\u9fa5]/g, '_').slice(0, 60) || 'challenge';
    const dirName = `${safe}_${String(md5 || '').slice(0, 8) || Date.now().toString(36)}`;
    const caseDir = path.join(root, dirName);
    fs.mkdirSync(path.join(caseDir, 'evidence'), { recursive: true });
    fs.mkdirSync(path.join(caseDir, 'scripts'), { recursive: true });
    pruneCases(root);
    return { success: true, caseDir, caseName: dirName };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// cases/ 修剪：只增不减会让取证目录无限膨胀。
// 保留最近 config.cases.keep 个 case（按 mtime），超出的移入 cases/_archive/（同卷 rename 瞬时、可找回）；
// _archive 超过 config.cases.archiveKeep 个时真正删除最旧的。
function pruneCases(root) {
  try {
    const keep = (config.cases && Number(config.cases.keep)) || 20;
    const archiveKeep = (config.cases && Number(config.cases.archiveKeep)) || 60;
    const archiveDir = path.join(root, '_archive');
    const listDirs = (dir) => fs.readdirSync(dir, { withFileTypes: true })
      .filter(e => e.isDirectory() && e.name !== '_archive')
      .map(e => {
        const p = path.join(dir, e.name);
        let mtime = 0;
        try { mtime = fs.statSync(p).mtimeMs; } catch (e2) {}
        return { name: e.name, path: p, mtime };
      })
      .sort((a, b) => b.mtime - a.mtime);

    const overflow = listDirs(root).slice(keep);
    if (overflow.length) {
      fs.mkdirSync(archiveDir, { recursive: true });
      for (const item of overflow) {
        try {
          fs.renameSync(item.path, path.join(archiveDir, item.name));
          console.log(`[cases] 归档旧取证目录: ${item.name}`);
        } catch (e2) { console.warn(`[cases] 归档失败 ${item.name}: ${e2.message}`); }
      }
    }

    if (fs.existsSync(archiveDir)) {
      for (const item of listDirs(archiveDir).slice(archiveKeep)) {
        try {
          fs.rmSync(item.path, { recursive: true, force: true });
          console.log(`[cases] 删除过期归档: ${item.name}`);
        } catch (e2) { console.warn(`[cases] 删除归档失败 ${item.name}: ${e2.message}`); }
      }
    }
  } catch (err) {
    console.warn('[cases] 修剪失败（不影响主流程）:', err.message);
  }
}

ipcMain.handle('append-file', async (event, filePath, line) => {
  try {
    if (isSensitivePath(filePath)) return { success: false, error: '拒绝写入受保护文件' };
    if (!isPathAllowedForWrite(filePath)) return { success: false, error: '写入路径超出允许范围: ' + filePath };
    fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
    fs.appendFileSync(path.resolve(filePath), String(line).endsWith('\n') ? String(line) : String(line) + '\n', 'utf8');
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 等待 ADB 设备就绪（轮询 get-state，替代固定 sleep）
ipcMain.handle('adb-wait-device', async (event, timeoutMs) => {
  const deadline = Date.now() + (Number(timeoutMs) || 90000);
  const adbPath = resolveAdbPath();
  const port = config.emulator.adb_port;

  while (Date.now() < deadline) {
    if (claudeAborted) return { success: false, error: '已取消' };
    await adbEnsureConnected(port); // 每轮先重连：daemon 被另一版本 adb 顶掉后自动恢复
    const r = await new Promise((resolve) => {
      const child = spawn(adbPath, ['-s', `127.0.0.1:${port}`, 'get-state'], { shell: false, windowsHide: true });
      let out = '', err = '';
      const t = setTimeout(() => { try { child.kill(); } catch (e) {} }, 5000);
      child.stdout.on('data', d => { out += d.toString(); });
      child.stderr.on('data', d => { err += d.toString(); });
      child.on('error', (e) => { clearTimeout(t); resolve({ ok: false, out: '', err: e.message }); });
      child.on('close', () => { clearTimeout(t); resolve({ ok: out.trim() === 'device', out: out.trim(), err }); });
    });
    if (r.ok) return { success: true, message: '设备已就绪' };
    await sleep(2000);
  }
  return { success: false, error: `等待设备超时（${Math.round((Number(timeoutMs) || 90000) / 1000)}s），请确认模拟器已启动` };
});
