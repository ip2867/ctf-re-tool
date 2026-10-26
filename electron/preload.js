const { contextBridge, ipcRenderer, webUtils } = require('electron');

// 安全暴露 API 到渲染进程
contextBridge.exposeInMainWorld('electronAPI', {
  // 配置管理
  getConfig: () => ipcRenderer.invoke('get-config'),
  saveConfig: (config) => ipcRenderer.invoke('save-config', config),

  // 文件分析
  detectFileType: (filePath) => ipcRenderer.invoke('detect-file-type', filePath),
  // 加密算法指纹扫描（读文件字节，确定性识别 SM4/AES/SM3/TEA… 及"本层无指纹=可能是壳"）
  scanCryptoFingerprints: (filePath) => ipcRenderer.invoke('scan-crypto-fingerprints', filePath),
  getFileInfo: (filePath) => ipcRenderer.invoke('get-file-info', filePath),
  extractApkSO: (apkPath) => ipcRenderer.invoke('extract-apk-so', apkPath),
  // PYC 反汇编/常量提取（多后端回退，pycdc 失败也能出结果）
  pycDecompile: (pycPath) => ipcRenderer.invoke('pyc-decompile', pycPath),
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
  // 裸 .class 常量池摘要（JEB/jadx 双失败的兜底，主进程解析二进制）
  classFileSummary: (filePath) => ipcRenderer.invoke('class-file-summary', filePath),
  // 花指令主动探测（从二进制本身判断是否存在花指令，供知识库检索与提示词引导）
  junkProbe: (filePath) => ipcRenderer.invoke('junk-probe', filePath),
  // 抽取文件内可打印字符串（中间值自动推进做字典用）
  extractStrings: (filePath) => ipcRenderer.invoke('extract-strings', filePath),
  // 解析 PE/ELF 映像范围与节表（IDA 落界校验用）
  fileImageMap: (filePath) => ipcRenderer.invoke('file-image-map', filePath),
  // 查询 IDA 当前实际加载的是哪个文件（身份绑定）
  idaIdentity: () => ipcRenderer.invoke('ida-identity'),
  // P2：中间值自动推进（哈希爆破 / Base64 / hex / 单字节 XOR），filePath 可选（补充文件内字典）
  advanceIntermediates: (hits, filePath) => ipcRenderer.invoke('advance-intermediates', hits, filePath),
  ensureDir: (dirPath) => ipcRenderer.invoke('ensure-dir', dirPath),
  saveFile: (defaultName, content, filters) => ipcRenderer.invoke('save-file', defaultName, content, filters),

  // ADB 命令
  adbCommand: (args) => ipcRenderer.invoke('adb-command', args),

  // Frida 命令
  fridaCommand: (args) => ipcRenderer.invoke('frida-command', args),
  runFridaHook: (script, target, opts) => ipcRenderer.invoke('run-frida-hook', script, target, opts),
  fridaPs: (opts) => ipcRenderer.invoke('frida-ps', opts),
  validateFridaScript: (src) => ipcRenderer.invoke('validate-frida-script', src),

  // 窗口控制
  minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
  maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
  closeWindow: () => ipcRenderer.invoke('close-window'),
  // 退出应用（自动测试：每题结束后关闭，避免实例残留抢 MCP 端口）
  quitApp: () => ipcRenderer.invoke('quit-app'),
  // 自动测试报告（主进程写盘，避免渲染层 userData 路径为空导致静默丢失）
  autotestReport: (data) => ipcRenderer.invoke('autotest-report', data),

  // 窗口状态变化监听
  onWindowStateChanged: (callback) => {
    ipcRenderer.on('window-state-changed', (event, state) => callback(state));
  },

  // 外部链接
  openExternal: (url) => ipcRenderer.invoke('open-external', url),

  // MCP 功能
  idaMcpAnalyze: (args) => ipcRenderer.invoke('ida-mcp-analyze', args),
  idaMcpCall: (toolName, args) => ipcRenderer.invoke('ida-mcp-call', toolName, args),
  // 分页版本：列表类工具必须拿全量（插件默认每页 100 条）
  idaMcpCallPaged: (toolName, args) => ipcRenderer.invoke('ida-mcp-call-paged', toolName, args),
  jebMcpStart: () => ipcRenderer.invoke('jeb-mcp-start'),
  jebMcpCall: (toolName, args) => ipcRenderer.invoke('jeb-mcp-call', toolName, args),
  browserMcpFetch: (url) => ipcRenderer.invoke('browser-mcp-fetch', url),
  browserMcpSearch: (query) => ipcRenderer.invoke('browser-mcp-search', query),
  browserJsRun: (params) => ipcRenderer.invoke('browser-js-run', params),
  burpMcpCall: (toolName, args) => ipcRenderer.invoke('burp-mcp-call', toolName, args),
  testMcpConnection: (type) => ipcRenderer.invoke('test-mcp-connection', type),
  checkPort: (port) => ipcRenderer.invoke('check-port', port),

  // CTF²（DASCTF Agent Arena）开放平台：练习题 / 附件 / 提交 flag（仅前端流水线调用，不开放给 AI）
  ctf2McpCall: (toolName, args) => ipcRenderer.invoke('ctf2-mcp-call', toolName, args),
  ctf2Probe: () => ipcRenderer.invoke('ctf2-probe'),
  ctf2Tools: () => ipcRenderer.invoke('ctf2-tools'),
  ctf2Download: (url, destDir) => ipcRenderer.invoke('ctf2-download', url, destDir),
  ctf2CleanupTools: () => ipcRenderer.invoke('ctf2-cleanup-tools'),
  ctf2Unzip: (zipPath) => ipcRenderer.invoke('ctf2-unzip', zipPath),

  // Claude API 功能
  claudeChat: (messages, systemPrompt, opts) => ipcRenderer.invoke('claude-chat', messages, systemPrompt, opts),
  testClaudeConnection: () => ipcRenderer.invoke('test-claude-connection'),
  claudeAbort: () => ipcRenderer.invoke('claude-abort'),
  // 流式增量回调（主进程 → 渲染层）
  onClaudeStreamChunk: (callback) => {
    ipcRenderer.on('claude-stream-chunk', (event, delta) => callback(delta));
  },
  // 工具执行事件（start / done / error）：UI 显示"正在跑哪个工具"
  onClaudeToolEvent: (callback) => {
    ipcRenderer.on('claude-tool-event', (event, info) => callback(info));
  },
  // 会话恢复（D1）：列出可续跑的会话 / 读取并清洗后的消息
  sessionsList: () => ipcRenderer.invoke('sessions-list'),
  sessionLoad: (id) => ipcRenderer.invoke('session-load', id),

  // 工作目录 / 应用路径 / 设备就绪
  setWorkdir: (dir, file, fileType) => ipcRenderer.invoke('set-workdir', dir, file, fileType),
  // CASE 目录同步（主进程没有 state.caseDir；run_python 的 cwd/产物登记靠它）
  setCaseDir: (dir) => ipcRenderer.invoke('set-case-dir', dir),
  // run_python 产物登记（渲染层在 finalize 时逐条转成 evidence）
  caseArtifacts: () => ipcRenderer.invoke('case-artifacts'),
  // 文件能力分诊（容器/文件系统/流量/文本/可执行）
  detectCapabilities: (filePath) => ipcRenderer.invoke('detect-capabilities', filePath),
  // 自修改特征 + 摘要目标存在性（只读文件字节，不依赖 IDA）
  analyzeSmc: (filePath) => ipcRenderer.invoke('analyze-smc', filePath),
  // pcap 流量提取（渲染层专用通道：executeToolCall 只在 AI 循环内）
  trafficExtract: (args) => ipcRenderer.invoke('traffic-extract', args),
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
  kaliTestConnection: () => ipcRenderer.invoke('kali-test-connection'),
  // Kali 远程预检决策（纯模块在主进程；渲染层只传事实、消费结论）
  kaliPreflightDecide: (input) => ipcRenderer.invoke('kali-preflight-decide', input),
  kaliRemotePlan: (input) => ipcRenderer.invoke('kali-remote-plan', input),
  classifyRemoteError: (input) => ipcRenderer.invoke('classify-remote-error', input)
});
