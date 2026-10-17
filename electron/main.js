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
  persistToolResult, microcompact, DoomLoopGuard, FailureLoopGuard,
  estimateTokens, SessionLog, sanitizeHistoryForResume, compactHistoryDeterministic, pruneDir,
} = require('./agent-runtime');

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
  ['RC4-ID', '00 01 02 03 04 05 06 07 08 09', 'RC4 KSA 初值/常见排列'],
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
  const isContainer = p.type !== 'shellcode';
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

function analyzeCustomBlockConstants(buf, size, sboxOff, sboxStride) {
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
  // 搜索范围：S 盒前后 0x4000 字节，按 4 字节对齐
  const lo = Math.max(0, sboxOff - 0x4000), hi = Math.min(size - 128, sboxOff + 0x4000);
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
  if (sboxStride === 4) {
    notes.push('S 盒按 **dword 数组**存放（每项 4 字节、值在低字节）→ 读表时必须按 4 字节步长取低字节，不能当连续 256 字节读');
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

  // 1) 已知常量/表模式
  for (const [name, hexPat, desc] of CRYPTO_FP) {
    const pat = hexToBytes(hexPat);
    const hits = findPattern(buf, pat);
    for (const off of hits) {
      out.push({ fp: name, desc, offset: '0x' + off.toString(16), algo: name.split('-')[0].replace(/^(SM4|SM3|AES|MD5|SHA256|TEA|CRC32|RC4|B64)$/, '$1') });
    }
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
  for (const stride of [1, 4, 2]) {
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
        sboxCands.push({ off, stride, head });
        if (sboxCands.length >= 6) break;
      }
    }
    if (sboxCands.length >= 6) break;
  }
  for (const { off, stride, head } of sboxCands) {
    const isSM4 = head.startsWith('d690e9fe');
    const isAES = head.startsWith('637c777b');
    const isAESInv = head.startsWith('52096ad5');
    const strideNote = stride === 1 ? '' : `（表项按 ${stride} 字节步长存放，值在低字节）`;
    const item = {
      fp: 'SBOX-256', algo: isSM4 ? 'SM4' : (isAES ? 'AES' : (isAESInv ? 'AES' : 'CUSTOM-BLOCK')),
      desc: isSM4 ? 'SM4 标准 S 盒（256 项双射）'
        : (isAES ? 'AES 标准 S 盒'
        : (isAESInv ? 'AES 逆 S 盒（解密码表）'
        : `自定义分组密码 S 盒（256 项双射，非常见算法）${strideNote}`)),
      offset: '0x' + off.toString(16), head, stride,
    };
    // 自定义 S 盒 → 做**常量差分分析**（纯确定性推导，不猜算法）：
    // 逐个比对标准 SM4/AES 表，找出"是否只是字节变换"，并搜索附近的轮常量表推算差分关系。
    // 实测价值（Disguise stage2）：AI 花了 345 秒/20+ 次脚本，反复纠结 FK/CK 是否被替换、
    // 字节序怎么摆；而这些关系全都可以由工具一次性算出来。
    if (item.algo === 'CUSTOM-BLOCK') {
      try {
        const analysis = analyzeCustomBlockConstants(buf, size, off, stride);
        if (analysis) {
          item.constantAnalysis = analysis;
          // 附加"可直接跑"的多骨架解密脚本：按结构推理分发到 SM4 / AES 骨架
          // （SM4 已实战验证；AES 为 Phase C 新增。DES/Blowfish 明确不支持，不假装能解）
          try {
            const sk = attachBlockCipherSolver(buf, size, analysis, off);
            if (sk) analysis.decryptScript = sk;
          } catch (e) { /* 生成失败不影响主结论 */ }
        }
      } catch (e) { /* 分析失败不影响主结论 */ }
    }
    out.push(item);
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
    summary.push({
      algo: bigBinary ? '疑似自定义分组密码' : '自定义分组密码（已确认）',
      confidence: bigBinary ? 'low' : 'high',
      evidence: `发现 ${cb.length} 个 256 项双射 S 盒（非常见算法）：` + cb.map(o => `${o.offset} 首字节 ${o.head.slice(0, 2)}`).join('、')
        + (bigBinary ? `（文件 ${(size / 1048576).toFixed(0)}MB，属通用程序量级，含密码库/置换表属正常）` : ''),
      note: (bigBinary
        ? '文件偏大，可能是通用程序自带的密码实现，**不一定是本题算法**；请结合本题的输入校验点/密文常量判断，勿直接照此下结论。'
        : '**确定存在分组密码**（双射 S 盒不会偶然出现），常量被改成自定义值。'
          + '① 先核对轮结构：32 轮 + `X^X^X^rk` 线性变换 → SM4 骨架（即使无标准 FK）；'
          + '10/12/14 轮 + SubBytes/ShiftRows/MixColumns → AES 骨架。'
          + '② 结构确认后，直接套对应框架、把 S 盒/常量换成题目表手写实现（禁止硬逆/写通用 VM 解释器）。'
          + '③ 参照技能 ctf-crypto-identify 的"魔改变体识别三问"。')
        + caText + scriptText
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
  if (has('MD5-IV')) summary.push({ algo: 'MD5', confidence: 'medium', evidence: 'MD5 IV', note: '哈希：爆破/碰撞/截断比较。' });
  if (has('SHA256-IV')) summary.push({ algo: 'SHA256', confidence: 'medium', evidence: 'SHA256 IV', note: '哈希：同上。' });
  if (has('CRC32-POLY')) summary.push({ algo: 'CRC32', confidence: 'medium', evidence: 'CRC32 多项式', note: '短输入可碰撞爆破（注意自定义初值/异或）。' });
  if (has('RC4-ID')) summary.push({ algo: 'RC4（疑）', confidence: 'low', evidence: '出现 00 01 02.. 连续初值（RAM 初始化特征，非铁证）', note: '需在代码中确认 KSA/PRGA。' });
  if (has('B64-STD')) summary.push({ algo: 'Base64', confidence: 'low', evidence: '标准 Base64 表', note: '编码非加密；可能是自定义表 Base64 的对照。' });

  // 4.5) 无任何算法指纹 → 关键判定（实测 Disguise：第一层是 XOR 编码的内嵌 PE + decoy 表，
  //      常量全在 stage2 里，本层零指纹）。此时必须提示"先找/提取下一层"，而不是让 AI 在当前层硬猜算法。
  if (!summary.length) {
    summary.push({
      algo: '(未发现算法指纹)', confidence: 'n/a',
      evidence: `扫描 ${size} 字节，未命中任何已知算法常量（SM4/AES/SM3/MD5/SHA/TEA/CRC32 S盒表均无）`,
      note: '本层极可能是**壳/加载器/decoy**：算法常量在下一层（内嵌/解密后的文件）里。'
        + '请先找"内嵌 PE/解密逻辑/资源段"，提取出下一层后**对新文件重跑本扫描**；'
        + '切勿在当前层盲猜算法或硬逆它的 VM。'
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
    case 'gen_block_cipher_solver': case 'gen_sm4_solver': return '生成解密脚本';
    case 'ida_decompile': return 'IDA 反编译 ' + short(i.function_name || i.address, 40);
    case 'ida_get_bytes': return 'IDA 读取字节 ' + short(i.address, 30);
    case 'ida_list_functions': return 'IDA 列出函数';
    case 'ida_find_strings': return 'IDA 查找字符串 ' + short(i.keyword || i.pattern || '', 30);
    case 'ida_get_xrefs': return 'IDA 交叉引用 ' + short(i.address || i.function_name || i.name, 30);
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
    // 找 flag/key 用 find_regex：字符串缓存 + Python 正则，快且不阻塞 IDA UI。
    // search_text 是 IDA 原生 C++ 扫描，regex:true 时会对每个 EA 反复 find_text，
    // 在稍大的二进制上会「卡住」甚至让 IDA 无响应——因此只作兜底，且调用时禁用其原生 regex。
    'find_strings': ['find_regex', 'search_text', 'find_strings', 'get_strings', 'search_strings', 'search_string', 'get_string_list', 'list_strings'],
    'decompile': ['get_function_decompile', 'decompile_function', 'get_pseudocode', 'decompile'],
    'xrefs_to': ['get_xrefs_to', 'xrefs_to', 'get_cross_references'],
    'trace_data_flow': ['trace_data_flow', 'trace_flow', 'data_flow'],
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
ipcMain.handle('ctf2-mcp-call', async (event, toolName, args) => {
  try {
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
    'java.exe'                        // jadx/unluac/apktool 等 Java 系（JEB 也走 java？JEB 用自带 jvm 进程名同上）
  ];
  const killed = [];
  for (const name of targets) {
    try { execSync('taskkill /F /IM ' + name, { stdio: 'ignore', timeout: 15000 }); killed.push(name); } catch (e) { /* 进程不存在 → 忽略 */ }
  }
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
      execSync('powershell -NoProfile -Command "Expand-Archive -Path \'' + tmpZip + '\' -DestinationPath \'' + dir + '\' -Force"', { timeout: 90000, stdio: 'ignore' });
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
    'browser_search', 'browser_open', 'run_command', 'run_python', 'adb_command', 'frida_hook',
    'read_skill', 'wiki_search', 'wiki_read', 'burp_get_history', 'burp_get_message', 'burp_call',
    'switch_to_next_stage'
  ]);
  // 工具名 → 参数名映射（模型给裸参数时也能用；无参工具不在此表）
  const MAP = {
    bash: 'command', run_command: 'command', run_python: 'script', glob: 'pattern', grep: 'pattern',
    read_file: 'path', write_file: 'path', read_skill: 'name', wiki_read: 'name', wiki_search: 'query',
    browser_open: 'url', browser_search: 'query', ida_decompile: 'function_name', ida_get_xrefs: 'address',
    ida_get_bytes: 'address', ida_find_strings: 'regex', frida_hook: 'script', adb_command: 'command'
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

  const tools = getToolDefinitions();
  let conversationHistory = [...messages];
  // 单轮工具循环上限：复杂逆向题（如并行归并+反演）实测需要大量"反编译→推演→写脚本→修正"迭代，
  // 25 次总在"写最终脚本"之前耗尽。放宽到 60，可用环境变量 CTF_MAX_TOOL_ITER 覆盖。
  const MAX_TOOL_ITERATIONS = parseInt(process.env.CTF_MAX_TOOL_ITER, 10) || 60;
  const SPRINT_AT = parseInt(process.env.CTF_SPRINT_AT, 10) || 50; // 冲刺触发点
  let maxIterations = MAX_TOOL_ITERATIONS;
  let lastResponse = null;
  let collectedText = '';
  let sprintInjected = false;
  // "只说不做"催促：模型输出行动意图却零工具调用时注入催促继续执行（最多 3 次，防死循环）
  let actionNudged = false;
  let actionNudgeCount = 0;
  // 重复调用计数（工具名+参数签名 → 次数）：同一调用重复 ≥4 次时警告换路，防"原地打转"卡死
  const dupCounter = new Map();
  // 脚本类工具的"同思路"签名池（归一化文本 → 出现次数）：截住"换写法重跑"
  const scriptSigs = new Map();
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

    // ── 上下文维护（每轮开头）──
    // 1) 微压缩：旧工具结果换成占位串（零模型调用，成本≈0）
    try { microcompact(conversationHistory, 6); } catch (e) { /* 忽略 */ }
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


    // 冲刺阶段：到达 SPRINT_AT 后注入一次强制收尾指令——停止一切新分析，落地结论/脚本。
    // （复杂题 4 轮实测均耗尽预算于"写最终脚本之前"，靠提示词自约不够，代码强制兜底。）
    if (!sprintInjected && maxIterations === SPRINT_AT - 1 && conversationHistory.length > 2) {
      sprintInjected = true;
      conversationHistory.push({
        role: 'user',
        content: [{ type: 'text', text: '⏱ 冲刺指令：工具预算还剩 ' + (SPRINT_AT) + ' 轮。**立即停止一切新的分析/反编译**，把你已有的全部发现落成最终脚本（run_python）并跑出结果；若脚本失败就修正后重跑。最后必须输出 [FLAG]...[/FLAG] 或 [HYPOTHESES][...][/HYPOTHESES]。' }]
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
      return {
        success: true,
        text: response.text
      };
    }

    // 检查是否有工具调用
    if (response.toolCalls && response.toolCalls.length > 0) {
      // 限制工具调用数量
      const toolCalls = response.toolCalls.slice(0, 3);

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
        // 两层检测：
        //   A) 完全相同（完整 sha1 签名）→ 第 4 次拦。
        //   B) **同思路换写法**（脚本归一化后高度相似，>88%）→ 第 3 次拦。
        //      实测"换个写法重跑"绕过了 A（签名不同），必须靠相似度才能截住。
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
        const cnt = (dupCounter.get(sig) || 0) + 1;
        dupCounter.set(sig, cnt);
        // 脚本类工具：字节完全相同的脚本重跑必然得到相同输出，第 2 次即拦；
        // 其它工具（read_file/ida_get_bytes 等）允许 4 次（"读→改→再读"是合理模式）。
        if (cnt >= (isScriptTool ? 2 : 4)) {
          toolResults.push({ tool_use_id: toolCall.id, content: dupWarn(`同一个 ${toolCall.name} 调用（参数**完全相同**）已出现 ${cnt} 次，且脚本/命令内容**逐字节相同**。`), is_error: true });
          continue;
        }
        // B) 脚本类工具的"同思路"相似度检测
        if (isScriptTool) {
          const raw = String((toolCall.input && (toolCall.input.script || toolCall.input.command)) || '');
          const norm = normalizeScript(raw);
          if (norm.length >= 40) {
            let similarHit = null;
            for (const [k, v] of scriptSigs.entries()) {
              if (k === sig) continue;
              if (scriptSimilarity(norm, v.norm) > 0.88) { similarHit = v; break; }
            }
            if (similarHit) {
              similarHit.count++;
              if (similarHit.count >= 3) {
                toolResults.push({ tool_use_id: toolCall.id, content: dupWarn(`你**第 ${similarHit.count} 次**提交了"同一思路、仅换写法"的脚本（归一化后相似度 >88%）。`), is_error: true });
                continue;
              }
            } else {
              scriptSigs.set(sig, { norm, count: 1 });
            }
          }
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
          const result = await executeToolCall(toolCall.name, toolCall.input);
          const rawText = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
          // A1) 大输出落盘：只截头会丢掉尾部的错误堆栈/flag，改为 60/40 头尾预览 + 落盘路径。
          const resultText = persistToolResult(rawText, {
            maxChars: parseInt(process.env.CTF_TOOL_RESULT_MAX, 10) || 24000,
            dir: path.join(app.getPath('userData'), 'tool-results'),
            id: toolCall.id,
          });
          toolResults.push({
            tool_use_id: toolCall.id,
            content: resultText,
            is_error: false
          });
          emitToolEvent('done', { chars: resultText.length });
          failGuard.recordSuccess(toolCall.name, toolCall.input && toolCall.input.path);
          doomGuard.reset();   // 成功且有状态变化 → 重置连续计数
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
        return await callIdaMcp('list_functions', { queries: {} });

      case 'ida_find_strings':
        return await callIdaMcp('find_strings', { pattern: input.regex });

      case 'ida_get_xrefs':
        return await callIdaMcp('xrefs_to', { addr: input.address });

      case 'ida_get_bytes': {
        // 真实 ida-pro-mcp 的 get_bytes schema 实测是 { regions: [{address,size}] }；
        // 不同实现可能是 {address,size}。两种形态都试，参数被拒（missing/invalid）则换下一种，
        // 全失败再回退 py_exec_file 跑 IDAPython（终兜底）。
        const addr = String(input.address || '').trim();
        const size = Math.min(parseInt(input.size, 10) || 256, 65536);
        const isBad = (r) => !r || /missing|required param|invalid|error|失败|Expected/i.test(String(r).slice(0, 300));
        const addrNum = /^[0-9a-fA-Fx]+$/.test(addr) ? '0x' + addr.replace(/^0x/i, '') : addr;
        const attempts = [
          { regions: [{ address: addrNum, size }] },
          { regions: [addrNum] },
          { address: addrNum, size },
          { address: addrNum, count: size }
        ];
        let lastResp = '';
        for (const args of attempts) {
          try {
            const r = await callIdaMcp('get_bytes', args);
            lastResp = String(r || '');
            if (!isBad(lastResp)) return r;
          } catch (e) { lastResp = e.message; }
        }
        // 终兜底：py_exec_file 跑 IDAPython
        try {
          const py = `import ida_bytes
ea=${/^[0-9a-fA-F]+$/.test(addr.replace(/^0x/i, '')) ? '0x' + addr.replace(/^0x/i, '') : JSON.stringify(addr)}
n=${size}
data=ida_bytes.get_bytes(ea,n) or b''
print('BYTES '+data.hex())
`;
          const tmp = path.join(app.getPath('temp'), 'ctf_get_bytes.py');
          fs.writeFileSync(tmp, py, 'utf8');
          const r = await callIdaMcp('py_exec_file', { path: tmp });
          const mm = String(r || '').match(/BYTES\s+([0-9a-f]+)/i);
          if (mm) {
            const buf = Buffer.from(mm[1], 'hex');
            const lines = [];
            for (let i = 0; i < buf.length; i += 16) {
              const seg = buf.slice(i, i + 16);
              const ascii = [...seg].map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
              lines.push(('0000' + i.toString(16)).slice(-4) + '  ' + seg.toString('hex').replace(/(..)/g, '$1 ').trim() + '  ' + ascii);
            }
            return lines.join('\n');
          }
          return r;
        } catch (e2) {
          return 'ida_get_bytes 全部形态失败（最后错误: ' + lastResp.slice(0, 150) + '）。替代方案：用 run_python 直接解析本地 ELF 文件读该地址（文件在 ' + (state && state.currentFile) + '）';
        }
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

      // ========== 确定性分析能力（供 AI 主动调用）==========
      case 'scan_crypto': {
        const f = String(input.path || '').trim();
        if (!f) return '参数错误：path 为空';
        if (!fs.existsSync(f)) return `文件不存在: ${f}`;
        const r = scanCryptoFingerprints(f);
        if (!r.success) return `扫描失败: ${r.error}`;
        // 输出为结构化文本，便于 AI 直接阅读；不放原始 JSON（token 更省、重点更突出）
        const lines = [];
        lines.push(`文件: ${f}  (${r.size} 字节)`);
        lines.push('');
        lines.push('## 主结论');
        for (const s of (r.summary || [])) {
          lines.push(`- 【${s.algo}】置信度 ${s.confidence}`);
          if (s.evidence) lines.push(`  证据: ${s.evidence}`);
          if (s.note) lines.push(`  建议: ${String(s.note).replace(/\n/g, '\n        ')}`);
        }
        if ((r.payloads || []).length) {
          lines.push('');
          lines.push('## 内嵌载荷（可用 extract_payload 提取）');
          for (const p of r.payloads) {
            const e = p.encode || {};
            lines.push(`- ${String(p.type).toUpperCase()} @0x${p.offset.toString(16)}` +
              ` 编码=${e.kind || 'none'}${e.key != null ? ' key=0x' + Number(e.key).toString(16) : ''}` +
              `${e.stride ? ' stride=' + e.stride : ''}${p.length ? ' len=' + p.length : ''}` +
              ` 置信度=${p.confidence || 'high'}`);
          }
        }
        const ca = (r.fingerprints || []).map(x => x.constantAnalysis).filter(Boolean);
        if (ca.length) {
          lines.push('');
          lines.push('## 常量差分分析（确定性推导）');
          for (const c of ca) {
            for (const n of (c.notes || [])) lines.push(`- ${n}`);
            if (c.decryptScript) {
              lines.push(`- 已生成 SM4 变体解密脚本（可用 gen_sm4_solver 取用）`);
              lines.push(`  密文候选: ${(c.decryptScript.ciphertextCandidates || []).map(x => x.offset + '(' + x.length + 'B)').join('、')}`);
            }
          }
          // 结构推理（Phase B）：给 AI 一个"骨架假设 + 置信度"，由 AI 决定路线
          const structs = inferCipherStructure(buf, size, ca[0]);
          if (structs.length) {
            lines.push('');
            lines.push('## 结构推理（假设，按证据强度排序——最终判断由你做）');
            for (const st of structs) {
              lines.push(`- 【${st.skeleton} 骨架】置信度 ${st.confidence}`);
              lines.push(`  证据: ${st.evidence}`);
              lines.push(`  建议: ${st.advice}`);
            }
          }
        }
        if ((r.fingerprints || []).length) {
          lines.push('');
          lines.push('## 原始命中（前 20）');
          lines.push((r.fingerprints || []).slice(0, 20).map(x => `${x.fp || x.algo}@${x.offset}${x.stride ? '(stride' + x.stride + ')' : ''}`).join('  '));
        }
        if ((r.highEntropy || []).length) {
          lines.push('');
          lines.push('## 高熵常量块（疑似 key/密文）');
          lines.push((r.highEntropy || []).map(h => `${h.offset}(${h.len}B) ${h.hex}`).join('\n'));
        }
        return lines.join('\n');
      }

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

      // ========== 多阶段接力（不在主进程执行，只发信号让渲染层切换）==========
      // 渲染层收到 stageSwitch 后会：kill 旧 IDA/JEB → 保留结论 → analyzeFile(新文件) + autoAnalyze。
      // 主进程这里只做存在性校验并回一个确认串（该串不会被 AI 看到——循环会立即中断）。
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
  // 超时 120s（旧值 30s 对编译/大脚本/批量处理不够；同样会误导 AI"命令失败"而换路）
  const opts = { timeout: 120000, maxBuffer: 32 * 1024 * 1024 };
  if (currentWorkDir && fs.existsSync(currentWorkDir)) opts.cwd = currentWorkDir;
  return new Promise((resolve) => {
    exec(command, opts, (error, stdout, stderr) => {
      if (error) {
        const timedOut = error.killed || /timed out|ETIMEDOUT/i.test(error.message || '');
        resolve(timedOut
          ? `命令执行超时（120s 上限，已终止）。请改用更省时的命令或拆分执行。\n${truncateOutput(stderr)}`
          : `命令执行失败: ${error.message}\n${truncateOutput(stderr)}`);
      } else {
        resolve(stdout ? truncateOutput(stdout) : '命令执行成功（无输出）');
      }
    });
  });
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

async function runPythonScript(script) {
  const tempFile = path.join(app.getPath('temp'), `ctf_script_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.py`);
  fs.writeFileSync(tempFile, script);

  return new Promise((resolve) => {
    // 用 spawn（shell:false）直接起 python：kill 能命中本体；Windows 上用 taskkill /T 杀树。
    const child = spawn('python', [tempFile], { windowsHide: true });
    currentPythonChild = child;

    let stdout = '', stderr = '', total = 0;
    let settled = false;
    const MAXBUF = 32 * 1024 * 1024;
    const finish = (text) => {
      if (settled) return;
      settled = true;
      if (currentPythonChild === child) currentPythonChild = null;
      try { fs.unlinkSync(tempFile); } catch (e) {}
      resolve(text);
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
