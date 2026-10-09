const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { exec, spawn, spawnSync } = require('child_process');
const fs = require('fs');
const zlib = require('zlib');
const http = require('http');
const https = require('https');
const { Client: SshClient } = require('ssh2');

// Claude API 基础配置（从 CC Switch 读取环境变量；config.claude 可覆盖 baseUrl/model/max_tokens）
const CLAUDE_ENV = {
  // 兼容 CCSwitch / Claude Code 环境变量；CTF_* 仅作为显式覆盖项
  baseUrl: process.env.CTF_CLAUDE_BASE_URL || process.env.ANTHROPIC_BASE_URL || 'https://llm.goaichat.top',
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
    jebMcp: 'http://127.0.0.1:16161/mcp',
    // Burp MCP（官方 PortSwigger 扩展为 SSE 传输，默认 9876；客户端 auto 兼容 SSE/Streamable HTTP）
    burp: 'http://127.0.0.1:9876',
    // 可选：独立 JEB MCP server.py 所在目录（留空 = 依赖 JEB 插件自带 HTTP 服务）
    jebMcpScript: '',
    // 可选：自备的浏览器 MCP（SSE 端点）；留空则用内置受控浏览器 CDP
    browser: ''
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
  }
};

let mainWindow;
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
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, 16, 0);
    fs.closeSync(fd);

    const magic = buffer.toString('hex', 0, 4).toUpperCase();
    console.log('Magic:', magic);

    let fileType = 'UNKNOWN';
    let description = '';

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
    // APK / JAR / ZIP 区分：同为 PK 头，看中央目录内容
    else if (magic === '504B0304' || ext === '.zip' || ext === '.apk' || ext === '.jar') {
      if (ext === '.apk' || zipContainsEntry(filePath, 'AndroidManifest.xml')) {
        fileType = 'APK';
        description = 'Android Package';
      } else if (ext === '.jar' || zipContainsEntry(filePath, 'META-INF/MANIFEST.MF')) {
        fileType = 'JAR';
        description = 'Java Archive（可用 jadx 反编译）';
      } else {
        fileType = 'ZIP';
        description = 'ZIP Archive';
      }
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
    if (isBatch) {
      args = ['/d', '/s', '/c', file].concat(args);
      file = process.env.ComSpec || 'cmd.exe';
    }
    const childOpts = { shell: false, windowsHide: true, timeout: opts.timeoutMs || 30000, maxBuffer: 10 * 1024 * 1024 };
    if (opts.cwd && fs.existsSync(opts.cwd)) childOpts.cwd = opts.cwd;
    // detached：GUI 工具（JEB/IDA）需要"启动后立即返回、不被超时杀掉"
    if (opts.detached) { childOpts.detached = true; delete childOpts.timeout; }
    let child;
    try { child = spawn(file, args, childOpts); } catch (e) {
      return resolve({ success: false, stdout: '', stderr: '', error: e.message });
    }
    let stdout = '', stderr = '';
    // detached 模式：不等输出，spawn 成功即视为已启动，让 GUI 独立运行
    if (opts.detached) {
      child.unref();
      child.on('error', (err) => resolve({ success: false, stdout: '', stderr: '', error: err.message }));
      setTimeout(() => resolve({ success: true, stdout: '已启动（分离运行）', stderr: '', error: null }), 800);
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
ipcMain.handle('adb-command', async (event, args) => {
  const adbPath = config.tools.nox_adb;
  const port = config.emulator.adb_port;
  const argv = [adbPath, '-s', `127.0.0.1:${port}`].concat(tokenizeCommand(args || ''));

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
    const output = await execFridaHook(script, target, opts);
    return { success: true, output };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Frida 列出进程（spawn 参数数组）
ipcMain.handle('frida-ps', async (event) => {
  const port = config.emulator.frida_port;

  return new Promise((resolve) => {
    const child = spawn('frida-ps', ['-H', `127.0.0.1:${port}`], { shell: false, windowsHide: true });
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
  return config.mcp.ida;
}

// 建立/复用 IDA MCP 会话
async function idaMcpEnsureSession() {
  const baseUrl = await idaMcpGetBaseUrl();
  // 会话 URL 变化则重置
  if (idaMcpState.baseUrl !== baseUrl) {
    idaMcpState = { sessionId: null, toolMap: null, baseUrl };
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
    'find_strings': ['find_strings', 'get_strings', 'search_strings', 'search_string', 'find_regex', 'get_string_list', 'list_strings'],
    'decompile': ['get_function_decompile', 'decompile_function', 'get_pseudocode', 'decompile'],
    'xrefs_to': ['get_xrefs_to', 'xrefs_to', 'get_cross_references'],
    'get_function_by_name': ['get_function_by_name'],
    'analyze_file': ['analyze_file', 'auto_analyze']
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

// 将逻辑参数名转换为各工具 schema 期望的参数名
function normalizeIdaArgs(logicalName, args) {
  args = args || {};
  switch (logicalName) {
    case 'decompile':
      return { addr: args.address || args.addr || args.function_name || '' };
    case 'find_strings':
      return { pattern: args.pattern || args.regex || args.query || '' };
    case 'xrefs_to':
      return { address: args.address || args.addr || '' };
    case 'list_functions':
      return { queries: args.queries || {} };
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
    list_funcs: 'list_functions',
    find_regex: 'find_strings'
  };
  logicalName = aliases[logicalName] || logicalName;

  const sessionId = await idaMcpEnsureSession();
  const realName = await idaMcpResolveTool(logicalName);
  const realArgs = normalizeIdaArgs(logicalName, args);
  const baseUrl = await idaMcpGetBaseUrl();

  const headers = {};
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  const resp = await sendMCPRequest(baseUrl, 'tools/call', {
    name: realName,
    arguments: realArgs
  }, headers, 60000);

  if (resp && resp.error) {
    throw new Error(resp.error.message || JSON.stringify(resp.error));
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

// 拆掉 ida-pro-mcp 列表结果的 data 信封，返回扁平数组。
// 只对"元素含 data 数组"的信封生效，因此 decompile（{addr,code,refs}）、
// find_regex（{n,matches,cursor}）、get_bytes（[{addr,data:"0x.. 0x.."}]）等不受影响。
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

    return {
      success: true,
      tools: (toolsResult.result && toolsResult.result.tools) || [],
      message: 'IDA MCP 连接成功'
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// IDA MCP - 调用特定工具（逻辑名，自动匹配真实工具 + 解包）
ipcMain.handle('ida-mcp-call', async (event, toolName, args) => {
  try {
    const result = await idaMcpCallTool(toolName, args);
    return { success: true, result: result };
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
  for (const home of cands) {
    const javaExe = path.join(home, 'bin', 'java.exe');
    if (!fs.existsSync(javaExe)) continue;
    try {
      const r = spawnSync(javaExe, ['-version'], { encoding: 'utf8', timeout: 5000 });
      const txt = String((r && r.stderr) || '') + String((r && r.stdout) || '');
      const m = txt.match(/version "(\d+)/);
      if (m && parseInt(m[1], 10) >= 17) { jebJdkHomeCache = home; return home; }
    } catch (e) { /* 忽略不可用的候选 */ }
  }
  jebJdkHomeCache = '';
  return '';
}

// JEB MCP 自动拉起：插件未监听 16161 时，用 JEB 启动器加载 scripts/MCP.py（可选打开目标文件）
let jebLaunching = null;
async function ensureJebPluginRunning(targetFile) {
  let existed = false;
  // jebProbe 是异步 Promise，必须 await 才能真实反映端口状态（否则 existed 恒 true，拉起永远跳过）
  try { await jebProbe(); existed = true; } catch (e) { /* 未运行 */ }
  if (existed) return { ok: true, already: true };
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
        detached: true, stdio: 'ignore', windowsHide: true,
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
  reqSeq: 0
};

function burpResetConnection() {
  try { if (burpMcpState.sseRes) burpMcpState.sseRes.destroy(); } catch (e) {}
  for (const p of burpMcpState.pending.values()) {
    clearTimeout(p.timer);
    p.reject(new Error('Burp MCP 连接已重置'));
  }
  burpMcpState = {
    transport: null, sessionId: null, toolMap: null, baseUrl: config.mcp.burp, ready: false,
    sseRes: null, endpointUrl: null, endpointWaiters: [], pending: new Map(), reqSeq: 0
  };
}

// ---------- Streamable HTTP 传输（社区扩展常见） ----------
async function burpHttpRequest(method, params, timeoutMs = 30000) {
  await burpHttpEnsureSession();
  const headers = {};
  if (burpMcpState.sessionId) headers['Mcp-Session-Id'] = burpMcpState.sessionId;
  const resp = await sendMCPRequest(config.mcp.burp, method, params || {}, headers, timeoutMs);
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
      history: ['get_http_history', 'http_history', 'get_proxy_history', 'proxy_history', 'list_history', 'search_history', 'burp_http_history'],
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
  return out;
}

async function burpMcpCallTool(logicalName, args) {
  const knownLogical = ['history', 'message'];
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
    if (resp && resp.error) {
      throw new Error(resp.error.message || JSON.stringify(resp.error));
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
    const urlObj = new URL(cfg.baseUrl + '/v1/messages');
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
        resolve({ statusCode: res.statusCode, raw: data });
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
    const urlObj = new URL(cfg.baseUrl + '/v1/messages');
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const postData = JSON.stringify(Object.assign({}, requestBody, { stream: true }));
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: claudeHeaders(postData),
      timeout: 600000
    };

    const req = client.request(options, (res) => {
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
              if (onDelta) { try { onDelta(d.text || ''); } catch (e) {} }
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
        resolve({ statusCode: 200, raw: JSON.stringify(message), message, streamed: true });
      });
      res.on('error', (e) => reject(e));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Claude API 请求超时')); });
    req.write(postData);
    req.end();
  });
}

// 带退避重试的传输层：429/5xx 或网络异常时重试（最多 2 次，2s/4s 退避）
// 注意：流式模式一旦已向渲染层吐过增量文本就不再重试——重发会造成聊天区内容重复
async function claudeTransport(requestBody, onDelta) {
  const cfg = getClaudeConfig();
  const useStream = cfg.stream && typeof onDelta === 'function';
  const maxRetries = 2;
  let lastErr = null;
  let deltaEmitted = false;
  const wrappedOnDelta = useStream ? (d) => { deltaEmitted = true; onDelta(d); } : null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (claudeAborted) throw new Error('已取消');
    try {
      const resp = useStream
        ? await postClaudeStream(requestBody, wrappedOnDelta)
        : await postClaudeJSON(requestBody);
      if ([403, 429, 500, 502, 503, 504].includes(resp.statusCode) && attempt < maxRetries) {
        await sleep(2000 * (attempt + 1));
        continue;
      }
      return resp;
    } catch (e) {
      lastErr = e;
      if (!deltaEmitted && attempt < maxRetries) {
        await sleep(2000 * (attempt + 1));
        continue;
      }
      throw e;
    }
  }
  throw lastErr || new Error('Claude API 请求失败');
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

  return {
    success: true,
    text,
    content,
    toolCalls: toolParts.map(c => ({ id: c.id, name: c.name, input: c.input })),
    stopReason
  };
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
    if (systemPrompt) requestBody.system = systemPrompt;
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
      { role: 'user', content: '继续，从中断处接着写。如已完成推理，请直接给出最终结论和 flag。' }
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
  return { success: true };
});

// Claude API Tool Use 循环
async function claudeChatWithTools(messages, systemPrompt, onDelta, opts = {}) {
  // 初步求解提示明确要求直接分析时，不发送工具定义，
  // 避免 GLM 代理因超大 tools schema 或错误触发 Tool Use 而超时。
  if (systemPrompt && /不要调用任何工具|不调用工具|直接基于提供的代码分析/.test(systemPrompt)) {
    return await sendClaudeRequest(messages, systemPrompt, onDelta, opts);
  }

  const tools = getToolDefinitions();
  let conversationHistory = [...messages];
  // 单轮工具循环上限：过小会导致"反编译→还原→求解"这类多步任务被硬截断，
  // 模型只能返回半截前言。默认放宽到 25，可用环境变量 CTF_MAX_TOOL_ITER 覆盖。
  const MAX_TOOL_ITERATIONS = parseInt(process.env.CTF_MAX_TOOL_ITER, 10) || 25;
  let maxIterations = MAX_TOOL_ITERATIONS;
  let lastResponse = null;
  let collectedText = '';

  while (maxIterations > 0) {
    maxIterations--;

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

    // 如果有文本响应且没有工具调用，直接返回
    if (response.text && (!response.toolCalls || response.toolCalls.length === 0)) {
      return {
        success: true,
        text: response.text
      };
    }

    // 检查是否有工具调用
    if (response.toolCalls && response.toolCalls.length > 0) {
      // 限制工具调用数量
      const toolCalls = response.toolCalls.slice(0, 3);

      // 执行工具调用
      const toolResults = [];

      for (const toolCall of toolCalls) {
        if (claudeAborted) break;
        console.log(`[Tool Use] 调用工具: ${toolCall.name}`, toolCall.input);

        try {
          const result = await executeToolCall(toolCall.name, toolCall.input);
          const resultText = truncateOutput(typeof result === 'string' ? result : JSON.stringify(result, null, 2));
          toolResults.push({
            tool_use_id: toolCall.id,
            content: resultText,
            is_error: false
          });
        } catch (err) {
          toolResults.push({
            tool_use_id: toolCall.id,
            content: `工具调用失败: ${err.message}`,
            is_error: true
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

      conversationHistory.push({
        role: 'user',
        content: toolResults.map(tr => ({
          type: 'tool_result',
          tool_use_id: tr.tool_use_id,
          content: tr.content,
          ...(tr.is_error ? { is_error: true } : {})
        }))
      });

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
      description: "执行Python脚本，可用于解密、数据分析等",
      input_schema: {
        type: "object",
        properties: {
          script: { type: "string", description: "Python脚本内容" }
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
  if (systemPrompt) requestBody.system = systemPrompt;

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
        return await callIdaMcp('list_functions', { queries: {} });

      case 'ida_find_strings':
        return await callIdaMcp('find_strings', { pattern: input.regex });

      case 'ida_get_xrefs':
        return await callIdaMcp('xrefs_to', { addr: input.address });

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

      // ========== 命令执行工具 ==========
      case 'run_command':
        return await execCommandAsync(input.command);

      case 'run_python':
        return await runPythonScript(input.script);

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

      default:
        return `未知工具: ${toolName}`;
    }
  } catch (err) {
    return `工具调用失败: ${err.message}`;
  }
}

// 调用IDA MCP（逻辑名 -> 会话化 + 工具名匹配 + 信封解包）
async function callIdaMcp(method, params) {
  try {
    return await idaMcpCallTool(method, params);
  } catch (err) {
    return `IDA MCP调用失败: ${err.message}`;
  }
}

// 调用Burp MCP（逻辑名 -> 会话化 + 工具名匹配 + 信封解包）
async function callBurpMcp(method, params) {
  try {
    return await burpMcpCallTool(method, params);
  } catch (err) {
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

// 执行命令
async function execCommandAsync(command) {
  // 在"当前案件工作目录"下执行，避免模型反复用绝对路径试探；Windows 下走 cmd.exe
  const opts = { timeout: 30000, maxBuffer: 10 * 1024 * 1024 };
  if (currentWorkDir && fs.existsSync(currentWorkDir)) opts.cwd = currentWorkDir;
  return new Promise((resolve) => {
    exec(command, opts, (error, stdout, stderr) => {
      if (error) {
        resolve(`命令执行失败: ${error.message}\n${truncateOutput(stderr)}`);
      } else {
        resolve(stdout ? truncateOutput(stdout) : '命令执行成功（无输出）');
      }
    });
  });
}

// 执行Python脚本（唯一临时文件名，避免并发覆盖）
async function runPythonScript(script) {
  const tempFile = path.join(app.getPath('temp'), `ctf_script_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tempFile, script);

  return new Promise((resolve) => {
    exec(`python "${tempFile}"`, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      // 清理临时文件
      try { fs.unlinkSync(tempFile); } catch (e) {}

      if (error) {
        resolve(`Python执行失败: ${error.message}\n${truncateOutput(stderr)}`);
      } else {
        resolve(stdout ? truncateOutput(stdout) : 'Python执行成功（无输出）');
      }
    });
  });
}

// 执行ADB命令（spawn 参数数组）
async function execAdbCommand(command) {
  const adbPath = config.tools.nox_adb;
  const port = config.emulator.adb_port;
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
// Android 上进程名常是 App 名（如 "Hook My Secret"）而非包名（com.x.y），
// frida 的 -n 需要的是进程名，直接用包名会 "Failed to spawn: unable to find process"。
// 返回 { pid, name } 或 null。
function resolveFridaProcessName(target) {
  return new Promise((resolve) => {
    const port = config.emulator.frida_port;
    const child = spawn('frida-ps', ['-H', `127.0.0.1:${port}`], { shell: false, windowsHide: true });
    let out = '';
    const t = setTimeout(() => { try { child.kill(); } catch (e) {} resolve(null); }, 12000);
    child.stdout.on('data', d => { out += d.toString(); });
    child.on('error', () => { clearTimeout(t); resolve(null); });
    child.on('close', () => {
      clearTimeout(t);
      // 输出行形如 " 3372  Hook My Secret"（也可能含应用标识符列）
      const lines = out.split(/\r?\n/).filter(l => /^\s*\d+\s+\S/.test(l));
      const rows = lines.map(l => { const m = l.match(/^\s*(\d+)\s+(.+?)\s*$/); return m ? { pid: Number(m[1]), name: m[2] } : null; }).filter(Boolean);
      // 归一化：去皮、去空格、小写 —— 包名末段（如 "myapp"）与进程名（"My App"）需归一后比对
      const norm = (s) => String(s || '').toLowerCase().replace(/\s+/g, '');
      const q = norm(target);
      const seg = q.split('.').pop();
      let hit = rows.find(r => norm(r.name) === q)
        || rows.find(r => norm(r.name).includes(q) || q.includes(norm(r.name)))
        || (seg.length >= 4 ? rows.find(r => norm(r.name).includes(seg) || seg.includes(norm(r.name))) : null);
      resolve(hit || null);
    });
  });
}

// 执行Frida Hook
// 执行Frida Hook脚本（spawn，避免 shell 注入；唯一临时文件名，finally 清理）
async function execFridaHook(script, target, opts) {
  const tempFile = path.join(app.getPath('temp'), `frida_hook_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.js`);
  fs.writeFileSync(tempFile, script);

  const port = config.emulator.frida_port;
  // 目标可选：'spawn:<包名>' 用 -f 自动拉起并挂启动期 hook（动态调试自动化用）；
  // 普通目标 attach 指定进程；未指定则 attach 当前前台应用（最常用）
  const args = ['-H', `127.0.0.1:${port}`];
  if (target && String(target).startsWith('spawn:')) {
    args.push('-f', String(target).slice(6));
  } else if (target) {
    // 关键：-n 需要"进程名"，而调用方常传"包名"。先尝试解析成真实进程名；
    // 解析不到则按原样传（部分 App 进程名确实等于包名）。
    const resolved = await resolveFridaProcessName(target);
    if (resolved && resolved.name) {
      if (resolved.name.toLowerCase() !== String(target).toLowerCase()) {
        console.log(`[Frida] 目标 "${target}" 解析为进程名 "${resolved.name}" (pid ${resolved.pid})`);
      }
      args.push('-n', resolved.name);
    } else {
      args.push('-n', target);
    }
  } else {
    args.push('-F'); // 远程设备上的前台应用
  }
  args.push('-l', tempFile);

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
    let dataCount = 0;

    const finish = (msg) => {
      if (settled) return;
      settled = true;
      try { clearTimeout(hardTimer); } catch (e) {}
      try { clearTimeout(idleTimer); } catch (e) {}
      try { child.kill(); } catch (e) {}
      try { fs.unlinkSync(tempFile); } catch (e) {}
      resolve(msg);
    };

    // 重置空闲计时：每次调用表示"刚有新数据"
    const bump = () => {
      lastDataAt = Date.now();
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        finish((stdout || stderr) + `\n[连续 ${Math.round(IDLE_WINDOW / 1000)}s 无新数据，抓取结束（共 ${dataCount} 条关键数据）]`);
      }, IDLE_WINDOW);
    };

    child.stdout.on('data', (d) => {
      stdout += d.toString();
      // 统计"关键数据"进度：脚本显式 [done] 仅在有数据后尊重
      const dataHits = (stdout.match(/\[DATA\]/g) || []).length;
      const hitHits = (stdout.match(/\[HIT\]/g) || []).length;
      const flagHit = /NCTF\{|flag\{|ctf\{/i.test(stdout);
      const prev = dataCount;
      dataCount = dataHits + (flagHit ? 1 : 0);
      // 有新的 [DATA]/flag → 重置滚动窗口（持续有数据就继续抓）
      if (dataCount > prev || flagHit) bump();
      // 脚本 [done]：仅在已经抓到过数据后才认，避免脚本过早收尾
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
    });

    child.on('error', (err) => {
      finish(`无法启动 frida: ${err.message}\n请确认已安装 frida、frida-server 已在模拟器运行并做好端口转发（adb forward tcp:${port} tcp:${port}）`);
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
  const adbPath = config.tools.nox_adb;
  const port = config.emulator.adb_port;
  const dev = `127.0.0.1:${port}`;
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
    let err = tryParse(code);
    if (!err) return { ok: true, script: code, repaired: false };

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
    if (!err2) return { ok: true, script: repaired, repaired: true };
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

// 启动Kali虚拟机
ipcMain.handle('kali-start-vm', async (event) => {
  try {
    const vmxFile = findVmxFile();
    if (!vmxFile) {
      return { success: false, error: `未找到 .vmx 文件，请检查 kali.vmxPath 配置（当前: ${config.kali.vmxPath}）` };
    }

    // 等待 spawn 结果：vmrun 不存在/不可执行时如实报错，而不是假成功
    const spawnErr = await new Promise((resolve) => {
      const child = spawn('vmrun', ['start', vmxFile, 'nogui'], { shell: false, windowsHide: true });
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

    const child = spawn('vmrun', ['stop', vmxFile, 'soft'], { shell: false, windowsHide: true });
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
        stream.on('close', () => {
          clearTimeout(timer);
          done({ success: true, stdout: truncateOutput(stdout), stderr: truncateOutput(stderr), error: null });
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
ipcMain.handle('set-workdir', async (event, dir) => {
  currentWorkDir = dir || null;
  return { success: true };
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

// 关键词检索：按标题/文件名/正文计分，返回最相关的若干页（含摘要片段）
function wikiSearch(query, max = 5) {
  const pages = listWikiDirs();
  const terms = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  const scored = [];
  for (const p of pages) {
    let content = '';
    try { content = fs.readFileSync(p.path, 'utf8'); } catch (e) { continue; }
    const hay = (p.rel + '\n' + content).toLowerCase();
    const firstLine = (content.split('\n').find(l => /^#\s/.test(l)) || '').replace(/^#\s*/, '');
    let score = 0;
    for (const t of terms) {
      if (!t) continue;
      const inName = p.rel.toLowerCase().includes(t) ? 3 : 0;
      const inTitle = firstLine.toLowerCase().includes(t) ? 4 : 0;
      const occ = hay.split(t).length - 1;
      score += inName + inTitle + Math.min(occ, 8);
    }
    if (!terms.length) score = 1;
    if (score > 0) scored.push({ score, page: p, content, title: firstLine });
  }
  scored.sort((a, b) => b.score - a.score);
  const top = scored.slice(0, Math.max(1, Math.min(Number(max) || 5, 20)));
  if (!top.length) return `未找到与「${query}」相关的知识页。可用页面：\n` + pages.map(p => `- ${p.rel}`).join('\n');
  return top.map(r => {
    const lines = r.content.split('\n');
    const idx = lines.findIndex(l => l.toLowerCase().includes(terms[0] || '\u0000'));
    const snippet = lines.slice(Math.max(0, idx), Math.max(0, idx) + 4).join('\n').slice(0, 400);
    return `### ${r.title || r.page.name}  [${r.page.rel}]\n${snippet}`;
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
  const adbPath = config.tools.nox_adb;
  const port = config.emulator.adb_port;

  while (Date.now() < deadline) {
    if (claudeAborted) return { success: false, error: '已取消' };
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
