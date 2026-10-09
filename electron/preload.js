const { contextBridge, ipcRenderer, webUtils } = require('electron');

// 安全暴露 API 到渲染进程
contextBridge.exposeInMainWorld('electronAPI', {
  // 配置管理
  getConfig: () => ipcRenderer.invoke('get-config'),
  saveConfig: (config) => ipcRenderer.invoke('save-config', config),

  // 文件分析
  detectFileType: (filePath) => ipcRenderer.invoke('detect-file-type', filePath),
  getFileInfo: (filePath) => ipcRenderer.invoke('get-file-info', filePath),
  extractApkSO: (apkPath) => ipcRenderer.invoke('extract-apk-so', apkPath),
  selectFile: (filters) => ipcRenderer.invoke('select-file', filters),
  getFilePath: (file) => webUtils.getPathForFile(file),

  // 工具调用
  launchTool: (toolName, filePath) => ipcRenderer.invoke('launch-tool', toolName, filePath),

  // 命令执行
  execCommand: (command) => ipcRenderer.invoke('exec-command', command),

  // 安全参数化执行（argv 数组，无 shell 解析，杜绝命令注入）
  runToolArgs: (argv, opts) => ipcRenderer.invoke('run-tool-args', argv, opts),
  // 纯 Node 读取 zip（APK）条目名，替代 powershell 解压探测
  zipList: (zipPath) => ipcRenderer.invoke('zip-list', zipPath),
  // 纯 Node 递归内容搜索，替代 powershell Select-String 拼接
  grepInDir: (root, pattern, opts) => ipcRenderer.invoke('grep-in-dir', root, pattern, opts),

  // 写入文件（供脚本保存/VS Code 打开）
  writeFile: (filePath, content) => ipcRenderer.invoke('write-file', filePath, content),
  readFile: (filePath) => ipcRenderer.invoke('read-file', filePath),
  ensureDir: (dirPath) => ipcRenderer.invoke('ensure-dir', dirPath),
  saveFile: (defaultName, content, filters) => ipcRenderer.invoke('save-file', defaultName, content, filters),

  // ADB 命令
  adbCommand: (args) => ipcRenderer.invoke('adb-command', args),

  // Frida 命令
  fridaCommand: (args) => ipcRenderer.invoke('frida-command', args),
  runFridaHook: (script, target, opts) => ipcRenderer.invoke('run-frida-hook', script, target, opts),
  fridaPs: () => ipcRenderer.invoke('frida-ps'),
  validateFridaScript: (src) => ipcRenderer.invoke('validate-frida-script', src),

  // 窗口控制
  minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
  maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
  closeWindow: () => ipcRenderer.invoke('close-window'),

  // 窗口状态变化监听
  onWindowStateChanged: (callback) => {
    ipcRenderer.on('window-state-changed', (event, state) => callback(state));
  },

  // 外部链接
  openExternal: (url) => ipcRenderer.invoke('open-external', url),

  // MCP 功能
  idaMcpAnalyze: (args) => ipcRenderer.invoke('ida-mcp-analyze', args),
  idaMcpCall: (toolName, args) => ipcRenderer.invoke('ida-mcp-call', toolName, args),
  jebMcpStart: () => ipcRenderer.invoke('jeb-mcp-start'),
  jebMcpCall: (toolName, args) => ipcRenderer.invoke('jeb-mcp-call', toolName, args),
  browserMcpFetch: (url) => ipcRenderer.invoke('browser-mcp-fetch', url),
  browserMcpSearch: (query) => ipcRenderer.invoke('browser-mcp-search', query),
  browserJsRun: (params) => ipcRenderer.invoke('browser-js-run', params),
  burpMcpCall: (toolName, args) => ipcRenderer.invoke('burp-mcp-call', toolName, args),
  testMcpConnection: (type) => ipcRenderer.invoke('test-mcp-connection', type),
  checkPort: (port) => ipcRenderer.invoke('check-port', port),

  // Claude API 功能
  claudeChat: (messages, systemPrompt, opts) => ipcRenderer.invoke('claude-chat', messages, systemPrompt, opts),
  testClaudeConnection: () => ipcRenderer.invoke('test-claude-connection'),
  claudeAbort: () => ipcRenderer.invoke('claude-abort'),
  // 流式增量回调（主进程 → 渲染层）
  onClaudeStreamChunk: (callback) => {
    ipcRenderer.on('claude-stream-chunk', (event, delta) => callback(delta));
  },

  // 工作目录 / 应用路径 / 设备就绪
  setWorkdir: (dir) => ipcRenderer.invoke('set-workdir', dir),
  getAppPaths: () => ipcRenderer.invoke('get-app-paths'),
  adbWaitDevice: (timeoutMs) => ipcRenderer.invoke('adb-wait-device', timeoutMs),
  driveAppUi: (steps) => ipcRenderer.invoke('drive-app-ui', steps),

  // Agent Skills
  skillsList: () => ipcRenderer.invoke('skills-list'),
  skillRead: (name) => ipcRenderer.invoke('skill-read', name),

  // Wiki 知识库
  wikiList: () => ipcRenderer.invoke('wiki-list'),
  wikiSearch: (query, max) => ipcRenderer.invoke('wiki-search', query, max),
  wikiRead: (nameOrRel) => ipcRenderer.invoke('wiki-read', nameOrRel),

  // CASE 证据体系
  caseInit: (baseName, md5) => ipcRenderer.invoke('case-init', baseName, md5),
  appendFile: (filePath, line) => ipcRenderer.invoke('append-file', filePath, line),

  // Burp 自动化（探测端口 / 拉起走 Burp 代理的隔离浏览器）
  burpProbe: () => ipcRenderer.invoke('burp-probe'),
  openProxyBrowser: (targetUrl) => ipcRenderer.invoke('open-proxy-browser', targetUrl),

  // Kali 虚拟机功能
  kaliStartVm: () => ipcRenderer.invoke('kali-start-vm'),
  kaliStopVm: () => ipcRenderer.invoke('kali-stop-vm'),
  kaliExecCommand: (command) => ipcRenderer.invoke('kali-exec-command', command),
  kaliTestConnection: () => ipcRenderer.invoke('kali-test-connection')
});
