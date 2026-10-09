// CTF Reverse Engineering Tool - Main Application

// 全局状态
const state = {
  currentFile: null,
  fileInfo: null,
  fileType: null,
  fileDescription: '',
  config: null,
  chatHistory: [], // 聊天历史
  solveNotes: [],      // 解题过程记录（供生成WP）
  mcpStatus: { ida: false, jeb: false, burp: false, browser: false, emulator: false, frida: false }, // 真实连接状态（供AI提示词）
  aiBusy: false,       // AI 请求进行中（发送按钮变为"停止"）
  appPaths: null,      // 主进程路径（scripts 目录等）
  caseDir: null,       // 当前题目的 CASE 证据目录
  caseName: null,      // CASE 目录名
  findings: null,      // 结构化发现（findings.json 内容）
  skills: [],          // 可用技能索引（来自 skills/ 目录）
  wikiPages: [],       // Wiki 知识库索引（来自 wiki/ 目录，AI 用 wiki_search/wiki_read 检索）
  lastAiText: '',      // 最近一次 AI 求解输出（枚举假设的解析来源）
  lastVerifyContracts: null, // 最近一次解析出的 [VERIFY] 契约（供 Hook 主动解密复用）
  currentScript: null, // 最近生成的脚本 {content,type}（聊天即预览，自动落盘）
  experience: '',      // 全局经验库（experience.md 内容，注入系统提示）
  flowAbortRequested: false // 自动化流程（analyzeWebJS 轮询等）的中止标志
};

// 新建 findings 结构
function newFindings(fileInfo, fileType) {
  return {
    meta: {
      fileName: fileInfo ? fileInfo.fileName : null,
      fileType: fileType || null,
      md5: fileInfo ? fileInfo.md5 : null,
      sha256: fileInfo ? fileInfo.sha256 : null,
      startedAt: new Date().toISOString()
    },
    notes: [],        // 结构化过程记录 [{section,text,ts}]
    evidence: [],     // 证据文件 [{kind,label,file,ts}]
    flags: [],        // flag 候选 [{flag,verified,source,ts}]
    algorithms: []    // 算法/密钥/密文发现 [{text,ts}]
  };
}

// 更新 MCP 状态点与 state.mcpStatus（保证 AI 提示词与 UI 一致）
function setMcpStatus(name, online) {
  if (name in state.mcpStatus) state.mcpStatus[name] = !!online;
  const dot = document.getElementById(`${name}-mcp-status`) ||
              document.getElementById(`${name}-status`);
  if (dot) dot.className = `status-dot ${online ? 'status-online' : 'status-offline'}`;
}

// 初始化应用
document.addEventListener('DOMContentLoaded', async () => {
  await loadConfig();
  try { state.appPaths = await window.electronAPI.getAppPaths(); } catch (e) { /* 可选 */ }
  try {
    const sk = await window.electronAPI.skillsList();
    if (sk && sk.success) state.skills = sk.skills;
  } catch (e) { /* 可选 */ }
  try {
    // Wiki 知识库索引（可检索的手法/代码片段；AI 用 wiki_search/wiki_read 调用）
    const wl = await window.electronAPI.wikiList();
    if (wl && wl.success) state.wikiPages = wl.pages;
  } catch (e) { /* 可选 */ }
  try {
    // 全局经验库（reverse-skill 进化层思路：完成任务回写经验，下次任务先速查）
    if (state.appPaths && window.electronAPI.readFile) {
      const exp = await window.electronAPI.readFile(`${state.appPaths.userData}/experience.md`);
      if (exp && exp.success) state.experience = exp.content || '';
    }
  } catch (e) { /* 经验库为空属正常 */ }
  setupEventListeners();
  setupWindowStateListener();
  setupStreamListener();
  addLog('info', `应用启动完成，已加载 ${state.skills.length} 个技能，等待文件输入...`);
});

// 流式输出：主进程 → 渲染层逐字渲染
let streamBubble = null;   // 当前流式消息的 .message-text 元素
let streamText = '';

function setupStreamListener() {
  if (!window.electronAPI.onClaudeStreamChunk) return;
  window.electronAPI.onClaudeStreamChunk((delta) => {
    if (!streamBubble || !delta) return;
    streamText += delta;
    streamBubble.innerHTML = formatMessage(streamText) + '<span class="stream-cursor">▌</span>';
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
  });
}

function beginStreamMessage() {
  const chatMessages = document.getElementById('chat-messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message message-system';
  messageDiv.innerHTML = `
    <div class="message-avatar">
      <i class="fas fa-robot"></i>
    </div>
    <div class="message-content">
      <div class="message-text"></div>
    </div>
  `;
  chatMessages.appendChild(messageDiv);
  streamBubble = messageDiv.querySelector('.message-text');
  streamText = '';
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function endStreamMessage() {
  if (streamBubble) {
    streamBubble.innerHTML = formatMessage(streamText || '（无输出）');
  }
  streamBubble = null;
  streamText = '';
}

// 恢复收缩/展开状态
function restoreCollapseStates() {
  // 恢复整体工具状态
  const toolsState = localStorage.getItem('tools-collapsed');
  if (toolsState === 'collapsed') {
    document.getElementById('tools-content').classList.add('collapsed');
    document.getElementById('btn-collapse-tools').classList.add('collapsed');
  }

  // 恢复各分类状态（左侧 + 右侧）
  ['static', 'unpack', 'python', 'log', 'frida', 'actions'].forEach(category => {
    const state = localStorage.getItem(`category-${category}`);
    if (state === 'collapsed') {
      const header = document.querySelector(`[data-category="${category}"]`);
      const content = document.getElementById(`category-${category}`);
      if (header && content) {
        header.classList.add('collapsed');
        content.classList.add('collapsed');
      }
    }
  });

  // 恢复MCP状态
  const mcpState = localStorage.getItem('mcp-collapsed');
  if (mcpState === 'collapsed') {
    document.getElementById('mcp-content').classList.add('collapsed');
    document.getElementById('btn-collapse-mcp').classList.add('collapsed');
  }
}

// 监听窗口状态变化
function setupWindowStateListener() {
  window.electronAPI.onWindowStateChanged((state) => {
    const maximizeBtn = document.getElementById('btn-maximize');
    const icon = maximizeBtn.querySelector('i');

    if (state === 'maximized') {
      icon.className = 'fas fa-clone';
      maximizeBtn.title = '还原';
    } else {
      icon.className = 'fas fa-square';
      maximizeBtn.title = '最大化';
    }
  });
}

// 加载配置
async function loadConfig() {
  try {
    state.config = await window.electronAPI.getConfig();
    addLog('info', '配置加载成功');
  } catch (err) {
    addLog('error', '配置加载失败: ' + err.message);
  }
}

// 设置事件监听器
function setupEventListeners() {
  // 窗口控制
  document.getElementById('btn-minimize').addEventListener('click', () => {
    window.electronAPI.minimizeWindow();
  });
  document.getElementById('btn-maximize').addEventListener('click', () => {
    window.electronAPI.maximizeWindow();
  });
  document.getElementById('btn-close').addEventListener('click', () => {
    window.electronAPI.closeWindow();
  });

  // 双击标题栏切换最大化
  document.querySelector('.titlebar-drag').addEventListener('dblclick', () => {
    window.electronAPI.maximizeWindow();
  });

  // 文件拖入
  const dropZone = document.getElementById('file-drop-zone');
  dropZone.addEventListener('dragover', handleDragOver);
  dropZone.addEventListener('dragleave', handleDragLeave);
  dropZone.addEventListener('drop', handleDrop);

  // 选择文件按钮（只绑定一次，阻止事件冒泡）
  document.getElementById('btn-select-file').addEventListener('click', (e) => {
    e.stopPropagation();
    handleSelectFile();
  });

  // 清除文件
  document.getElementById('btn-clear-file').addEventListener('click', clearFile);

  // 工具按钮
  document.querySelectorAll('.tool-btn').forEach(btn => {
    btn.addEventListener('click', () => launchTool(btn.dataset.tool));
  });

  // 模拟器操作
  document.getElementById('btn-check-emulator').addEventListener('click', checkEmulatorStatus);
  document.getElementById('btn-frida-ps').addEventListener('click', listFridaProcesses);
  document.getElementById('btn-install-apk').addEventListener('click', installApk);

  // 标签页切换
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // 发送消息
  document.getElementById('btn-send').addEventListener('click', sendMessage);
  document.getElementById('chat-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // 聊天工具栏（此前无事件绑定）
  const attachBtn = document.getElementById('btn-attach-file');
  if (attachBtn) attachBtn.addEventListener('click', sendFileInfoToChat);
  const clearChatBtn = document.getElementById('btn-clear-chat');
  if (clearChatBtn) clearChatBtn.addEventListener('click', clearChat);

  // 通用输入弹窗（替代 prompt()）
  const promptOk = document.getElementById('btn-prompt-ok');
  if (promptOk) promptOk.addEventListener('click', () => closeAppPrompt(true));
  const promptOk2 = document.getElementById('btn-prompt-cancel2');
  if (promptOk2) promptOk2.addEventListener('click', () => closeAppPrompt(false));
  const promptCancel = document.getElementById('btn-prompt-cancel');
  if (promptCancel) promptCancel.addEventListener('click', () => closeAppPrompt(false));
  const promptInput = document.getElementById('prompt-input');
  if (promptInput) promptInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') closeAppPrompt(true);
    if (e.key === 'Escape') closeAppPrompt(false);
  });

  // 快速操作按钮
  document.querySelectorAll('.quick-btn').forEach(btn => {
    btn.addEventListener('click', () => handleQuickAction(btn.dataset.action));
  });

  // 清空日志（阻止冒泡触发面板折叠；CSP 禁止内联 onclick，必须在 JS 里 stopPropagation）
  document.getElementById('btn-clear-log').addEventListener('click', (e) => {
    e.stopPropagation();
    clearLog();
  });

  // 快速操作按钮
  document.getElementById('btn-auto-analyze').addEventListener('click', autoAnalyze);
  document.getElementById('btn-deploy-frida').addEventListener('click', deployFrida);
  document.getElementById('btn-run-hook').addEventListener('click', runHook);
  document.getElementById('btn-generate-script').addEventListener('click', generateScript);
  document.getElementById('btn-generate-wp').addEventListener('click', generateWriteup);

  // 按钮可用状态
  const actionsButtons = ['btn-auto-analyze', 'btn-deploy-frida', 'btn-run-hook', 'btn-generate-script', 'btn-generate-wp'];
  actionsButtons.forEach(id => { if (document.getElementById(id)) document.getElementById(id).disabled = false; });

  // 设置按钮
  document.getElementById('btn-settings').addEventListener('click', openSettings);
  document.getElementById('btn-close-modal').addEventListener('click', closeSettings);
  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('btn-cancel-settings').addEventListener('click', closeSettings);
  const testAiBtn = document.getElementById('btn-test-ai');
  if (testAiBtn) testAiBtn.addEventListener('click', testAiConnection);

  // MCP按钮
  document.getElementById('btn-ida-mcp').addEventListener('click', connectIdaMcp);
  document.getElementById('btn-jeb-mcp').addEventListener('click', connectJebMcp);
  const burpMcpBtn = document.getElementById('btn-burp-mcp');
  if (burpMcpBtn) burpMcpBtn.addEventListener('click', connectBurpMcp);
  document.getElementById('btn-browser-mcp').addEventListener('click', connectBrowserMcp);

  // Kali按钮
  document.getElementById('btn-kali-start').addEventListener('click', startKaliVm);
  document.getElementById('btn-kali-stop').addEventListener('click', stopKaliVm);
  document.getElementById('btn-kali-test').addEventListener('click', testKaliConnection);

  // 工具分类收缩/展开
  document.querySelectorAll('.category-header').forEach(header => {
    header.addEventListener('click', () => {
      const category = header.dataset.category;
      const content = document.getElementById(`category-${category}`);
      const icon = header.querySelector('i');

      header.classList.toggle('collapsed');
      content.classList.toggle('collapsed');

      // 保存状态到localStorage
      localStorage.setItem(`category-${category}`, content.classList.contains('collapsed') ? 'collapsed' : 'expanded');
    });
  });

  // 整体工具收缩/展开
  document.getElementById('btn-collapse-tools').addEventListener('click', () => {
    const content = document.getElementById('tools-content');
    const btn = document.getElementById('btn-collapse-tools');

    content.classList.toggle('collapsed');
    btn.classList.toggle('collapsed');

    // 保存状态
    localStorage.setItem('tools-collapsed', content.classList.contains('collapsed') ? 'collapsed' : 'expanded');
  });

  // MCP收缩/展开
  document.getElementById('btn-collapse-mcp').addEventListener('click', () => {
    const content = document.getElementById('mcp-content');
    const btn = document.getElementById('btn-collapse-mcp');

    content.classList.toggle('collapsed');
    btn.classList.toggle('collapsed');

    // 保存状态
    localStorage.setItem('mcp-collapsed', content.classList.contains('collapsed') ? 'collapsed' : 'expanded');
  });

  // 初始化面板拖拽调整大小
  initResizeHandles();

  // 恢复保存的状态
  restoreCollapseStates();
}

// ========== 面板拖拽调整大小 ==========
function initResizeHandles() {
  const leftHandle = document.getElementById('resize-left');
  const rightHandle = document.getElementById('resize-right');
  const leftPanel = document.querySelector('.panel-left');
  const centerPanel = document.querySelector('.panel-center');
  const rightPanel = document.querySelector('.panel-right');

  let isResizing = false;
  let currentHandle = null;
  let startX = 0;
  let startWidth = 0;

  // 左侧分割线
  leftHandle.addEventListener('mousedown', (e) => {
    isResizing = true;
    currentHandle = 'left';
    startX = e.clientX;
    startWidth = leftPanel.offsetWidth;
    leftHandle.classList.add('active');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });

  // 右侧分割线
  rightHandle.addEventListener('mousedown', (e) => {
    isResizing = true;
    currentHandle = 'right';
    startX = e.clientX;
    startWidth = rightPanel.offsetWidth;
    rightHandle.classList.add('active');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });

  // 鼠标移动
  document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;

    const diff = e.clientX - startX;

    if (currentHandle === 'left') {
      const newWidth = Math.max(200, Math.min(500, startWidth + diff));
      leftPanel.style.width = newWidth + 'px';
      leftPanel.style.minWidth = newWidth + 'px';
      localStorage.setItem('left-panel-width', newWidth);
    } else if (currentHandle === 'right') {
      const newWidth = Math.max(250, Math.min(600, startWidth - diff));
      rightPanel.style.width = newWidth + 'px';
      rightPanel.style.minWidth = newWidth + 'px';
      localStorage.setItem('right-panel-width', newWidth);
    }
  });

  // 鼠标释放
  document.addEventListener('mouseup', () => {
    if (isResizing) {
      isResizing = false;
      currentHandle = null;
      leftHandle.classList.remove('active');
      rightHandle.classList.remove('active');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  });

  // 恢复保存的面板宽度
  const savedLeftWidth = localStorage.getItem('left-panel-width');
  const savedRightWidth = localStorage.getItem('right-panel-width');

  if (savedLeftWidth) {
    leftPanel.style.width = savedLeftWidth + 'px';
    leftPanel.style.minWidth = savedLeftWidth + 'px';
  }

  if (savedRightWidth) {
    rightPanel.style.width = savedRightWidth + 'px';
    rightPanel.style.minWidth = savedRightWidth + 'px';
  }
}

// 文件拖放处理
function handleDragOver(e) {
  e.preventDefault();
  e.stopPropagation();
  e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
  e.preventDefault();
  e.stopPropagation();
  e.currentTarget.classList.remove('drag-over');
}

async function handleDrop(e) {
  e.preventDefault();
  e.stopPropagation();
  e.currentTarget.classList.remove('drag-over');

  const files = e.dataTransfer.files;
  if (files.length > 0) {
    // 使用webUtils获取文件路径（Electron安全要求）
    const filePath = window.electronAPI.getFilePath(files[0]);
    if (filePath) {
      await analyzeFile(filePath);
    } else {
      addLog('error', '无法获取文件路径，请使用"选择文件"按钮');
    }
  }
}

async function handleSelectFile() {
  const filePath = await window.electronAPI.selectFile();
  if (filePath) {
    addLog('info', '选择的文件: ' + filePath);
    await analyzeFile(filePath);
  } else {
    addLog('info', '未选择文件或对话框已取消');
  }
}

// 分析文件
async function analyzeFile(filePath) {
  addLog('info', `正在分析文件: ${filePath}`);

  try {
    // 检测文件类型
    addLog('info', '步骤1: 检测文件类型...');
    const typeResult = await window.electronAPI.detectFileType(filePath);
    addLog('info', '类型检测结果: ' + JSON.stringify(typeResult));

    if (!typeResult.success) {
      addLog('error', '文件类型检测失败: ' + typeResult.error);
      return;
    }

    // 获取文件信息
    addLog('info', '步骤2: 获取文件信息...');
    const infoResult = await window.electronAPI.getFileInfo(filePath);
    addLog('info', '文件信息结果: ' + JSON.stringify(infoResult));

    if (!infoResult.success) {
      addLog('error', '文件信息获取失败: ' + infoResult.error);
      return;
    }

    // 更新状态
    state.currentFile = filePath;
    state.fileType = typeResult.fileType;
    state.fileDescription = typeResult.description || '';
    state.fileInfo = infoResult;

    // 同步工作目录给主进程（AI 的 glob/grep 搜索根）
    try {
      const dir = filePath.replace(/[\\/][^\\/]+$/, '');
      await window.electronAPI.setWorkdir(dir);
    } catch (e) { /* 可选 */ }

    // 创建 CASE 证据目录（本题为一个小案件：evidence/scripts/timeline）
    try {
      const cs = await window.electronAPI.caseInit(infoResult.fileName, infoResult.md5);
      if (cs && cs.success) {
        state.caseDir = cs.caseDir;
        state.caseName = cs.caseName;
        state.findings = newFindings(infoResult, typeResult.fileType);
        await persistFindings();
        addLog('info', `CASE 目录: ${cs.caseDir}`);
      }
    } catch (e) { /* CASE 失败不阻塞主流程 */ }

    // 更新UI
    updateFileInfoUI(typeResult, infoResult);
    enableActionButtons();

    addLog('success', `文件识别成功: ${typeResult.fileType} - ${typeResult.description}`);
    addLog('info', `MD5: ${infoResult.md5}`);
    addLog('info', `SHA256: ${infoResult.sha256}`);

    // 添加AI分析消息
    addSystemMessage(`已识别文件类型: **${typeResult.fileType}** (${typeResult.description})

文件信息:
- 文件名: ${infoResult.fileName}
- 大小: ${infoResult.sizeFormatted}
- MD5: ${infoResult.md5}

您可以:
1. 点击 "分析文件" 进行深度分析
2. 点击工具按钮直接启动对应工具
3. 输入具体问题向我提问`);

  } catch (err) {
    addLog('error', '文件分析失败: ' + err.message);
  }
}

// 更新文件信息UI
function updateFileInfoUI(typeResult, infoResult) {
  document.getElementById('file-drop-zone').style.display = 'none';
  document.getElementById('file-info-panel').style.display = 'block';

  document.getElementById('info-filename').textContent = infoResult.fileName;
  document.getElementById('info-filetype').textContent = typeResult.fileType;
  document.getElementById('info-filesize').textContent = infoResult.sizeFormatted;
  document.getElementById('info-md5').textContent = infoResult.md5;
  document.getElementById('info-sha256').textContent = infoResult.sha256;

  // 设置类型徽章配色（挂载主题类，具体色值见 style.css .type-badge.t-*）
  const typeBadge = document.getElementById('info-filetype');
  const typeToken = String(typeResult.fileType || 'ZIP').replace(/[^A-Za-z0-9]/g, '-');
  typeBadge.className = 'info-value type-badge t-' + typeToken;
}

// 清除文件
function clearFile() {
  state.currentFile = null;
  state.fileType = null;
  state.fileInfo = null;
  state.fileDescription = '';
  // CASE 指针一并清空，避免后续操作误写入上一题的证据目录
  state.caseDir = null;
  state.caseName = null;
  state.findings = null;

  document.getElementById('file-drop-zone').style.display = 'block';
  document.getElementById('file-info-panel').style.display = 'none';
  disableActionButtons();
  // 清除旧题的解题记录，避免 WP 混入上一题内容
  try { state.solveNotes = []; } catch (e) {}

  addLog('info', '已清除文件');
}

// 启用/禁用操作按钮
function enableActionButtons() {
  document.getElementById('btn-install-apk').disabled = state.fileType !== 'APK';
  document.getElementById('btn-auto-analyze').disabled = false;
  document.getElementById('btn-deploy-frida').disabled = false;
  document.getElementById('btn-run-hook').disabled = false;
  document.getElementById('btn-generate-script').disabled = false;
  document.getElementById('btn-generate-wp').disabled = false;
}

function disableActionButtons() {
  document.getElementById('btn-install-apk').disabled = true;
  document.getElementById('btn-auto-analyze').disabled = true;
  document.getElementById('btn-deploy-frida').disabled = true;
  document.getElementById('btn-run-hook').disabled = true;
  document.getElementById('btn-generate-script').disabled = true;
  document.getElementById('btn-generate-wp').disabled = true;
}

// 启动工具
async function launchTool(toolName, filePath = null) {
  const needFile = ['ida', 'ida64', 'die', 'jadx', 'pycdc', 'pycdas'];
  const fileToOpen = filePath || state.currentFile;

  if (!fileToOpen && needFile.includes(toolName)) {
    addLog('warning', '请先选择文件');
    return;
  }

  addLog('info', `正在启动 ${toolName}...`);

  try {
    let result;

    if (toolName === 'apktool') {
      const jarPath = state.config.tools.apktool;
      if (fileToOpen) {
        // 参数数组 + shell:false，路径不做字符串拼接（防注入）
        result = await window.electronAPI.runToolArgs(['java', '-jar', jarPath, 'd', fileToOpen, '-o', fileToOpen + '_decoded']);
      }
    } else if (toolName === 'jeb') {
      // 防重复实例：16161 在监听即说明已有 JEB+MCP 在跑，直接复用。
      // 只判端口（JEB 忙时 MCP 握手会超时，不能作为"是否在运行"的依据）。
      try {
        const p = await window.electronAPI.checkPort(16161);
        if (p && p.listening) {
          addLog('info', '检测到 JEB MCP 已在运行（16161），跳过再次启动 JEB');
          return;
        }
      } catch (e) { /* 未运行则继续启动 */ }

      const jebPath = state.config.tools.jeb;
      const mcpScriptPath = (state.config.tools && state.config.tools.jebMcpPy) || '';
      if (fileToOpen) {
        // 以参数数组分离启动 JEB 并加载 MCP 脚本（若为 .bat 由主进程安全回退执行）
        result = await window.electronAPI.runToolArgs([jebPath, `--script=${mcpScriptPath}`, fileToOpen], { detached: true });
        addLog('info', `JEB打开文件: ${fileToOpen}`);
        addLog('info', 'JEB MCP脚本自动加载中...');
      } else {
        result = await window.electronAPI.runToolArgs([jebPath, `--script=${mcpScriptPath}`], { detached: true });
        addLog('info', 'JEB MCP脚本自动加载中...');
      }
    } else if (toolName === 'ida' || toolName === 'ida64') {
      // 防重复实例：13337 在监听即说明已有 IDA+MCP 在跑，跳过再启动
      try {
        const p = await window.electronAPI.checkPort(13337);
        if (p && p.listening) {
          addLog('info', '检测到 IDA MCP 已在运行（13337），跳过再次启动 IDA');
          return;
        }
      } catch (e) { /* 未运行则继续启动 */ }

      const idaPath = state.config.tools[toolName] || state.config.tools.ida;
      if (fileToOpen) {
        // 参数数组分离启动 IDA 并打开文件（防注入）
        result = await window.electronAPI.runToolArgs([idaPath, fileToOpen], { detached: true });
        addLog('info', `IDA打开文件: ${fileToOpen}`);
      } else {
        result = await window.electronAPI.runToolArgs([idaPath], { detached: true });
      }
    } else {
      result = await window.electronAPI.launchTool(toolName, fileToOpen);
    }

    if (result && result.success) {
      addLog('success', `${toolName} 已启动`);
    } else if (result) {
      addLog('error', result.error || result.stderr);
    }
  } catch (err) {
    addLog('error', '工具启动失败: ' + err.message);
  }
}

// 检查模拟器状态（自动启动）
async function checkEmulatorStatus() {
  addLog('info', '=== 检查模拟器状态 ===');

  try {
    const port = (state.config.emulator && state.config.emulator.adb_port) || 62025;
    const device = `127.0.0.1:${port}`;
    // 先尝试连接设备
    await window.electronAPI.adbCommand(`connect ${device}`);

    // 检查是否连接成功
    const devicesResult = await window.electronAPI.adbCommand('devices');
    const isOnline = devicesResult.success && devicesResult.stdout.includes(device);

    if (isOnline) {
      // 模拟器已在线
      const result = await window.electronAPI.adbCommand('shell getprop ro.build.version.release');
      setMcpStatus('emulator', true);
      if (result.success) {
        addLog('success', `✅ 模拟器在线 - Android ${result.stdout.trim()}`);
      }
      return true;
    }

    // 模拟器不在线，自动启动
    addLog('info', '模拟器未运行，正在自动启动...');
    await startNoxEmulator();

    return false;
  } catch (err) {
    addLog('error', '检查失败: ' + err.message);
    return false;
  }
}

// 启动安卓9模拟器（就绪轮询替代固定60秒等待）
async function startNoxEmulator() {
  addLog('info', '正在启动安卓9模拟器 (Nox_1)...');

  try {
    const emulator = state.config.emulator || {};
    const noxPath = emulator.nox_path || '';
    const noxInstance = emulator.nox_instance || 'Nox_1';
    const port = emulator.adb_port || 62025;
    const device = `127.0.0.1:${port}`;
    // 启动安卓9实例（参数数组分离启动；替代 `start "" "path" -clone:x` 拼接）
    const result = await window.electronAPI.runToolArgs([noxPath, `-clone:${noxInstance}`], { detached: true });

    if (result.success) {
      addLog('info', '安卓9模拟器启动中，等待设备就绪（最长90秒）...');

      // 轮询：connect + devices，替代固定60秒等待
      const deadline = Date.now() + 90000;
      while (Date.now() < deadline) {
        await window.electronAPI.adbCommand(`connect ${device}`);
        const devicesResult = await window.electronAPI.adbCommand('devices');
        if (devicesResult.success && devicesResult.stdout.includes(device)) {
          setMcpStatus('emulator', true);

          // 验证Android版本
          const versionResult = await window.electronAPI.adbCommand('shell getprop ro.build.version.release');
          const version = versionResult.success ? versionResult.stdout.trim() : '未知';

          addLog('success', `✅ 安卓9模拟器启动成功 - Android ${version}`);
          return true;
        }
        await new Promise(resolve => setTimeout(resolve, 3000));
      }

      addLog('warning', '模拟器启动超时，请手动检查');
      setMcpStatus('emulator', false);
      return false;
    } else {
      addLog('error', '模拟器启动失败: ' + result.error);
      return false;
    }
  } catch (err) {
    addLog('error', '模拟器启动失败: ' + err.message);
    return false;
  }
}

// 列出Frida进程
async function listFridaProcesses() {
  addLog('info', '=== 获取Frida进程列表 ===');

  try {
    const result = await window.electronAPI.fridaPs();
    if (result.success) {
      const fridaOutput = document.getElementById('category-frida');
      if (fridaOutput) {
        fridaOutput.textContent = result.stdout || '（无输出）';
      }
      addLog('success', '进程列表已更新');
    } else {
      addLog('error', 'Frida连接失败: ' + (result.error || result.stderr));
      addLog('info', '请确保:');
      addLog('info', '1. 安卓9模拟器已启动');
      addLog('info', '2. frida-server已部署并运行');
      addLog('info', `3. 端口${(state.config.emulator && state.config.emulator.frida_port) || 27042}已转发`);
    }
  } catch (err) {
    addLog('error', '获取进程列表失败: ' + err.message);
  }
}

// 安装APK
async function installApk() {
  if (state.fileType !== 'APK') {
    addLog('warning', '请选择APK文件');
    return;
  }

  addLog('info', '=== 安装APK到模拟器 ===');
  addLog('info', '文件: ' + state.fileInfo.fileName);

  try {
    // 先连接设备
    const adbPort = (state.config.emulator && state.config.emulator.adb_port) || 62025;
    await window.electronAPI.adbCommand(`connect 127.0.0.1:${adbPort}`);

    addLog('info', '正在安装...');
    const result = await window.electronAPI.adbCommand(`install "${state.currentFile}"`);
    if (result.success) {
      addLog('success', 'APK安装成功！');
    } else {
      addLog('error', 'APK安装失败: ' + (result.error || result.stderr));
      addLog('info', '可能原因:');
      addLog('info', '- 模拟器未启动');
      addLog('info', '- APK与模拟器架构不兼容');
      addLog('info', '- 存储空间不足');
    }
  } catch (err) {
    addLog('error', '安装失败: ' + err.message);
  }
}

// 标签页切换
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `tab-${tabId}`);
  });
}

// 发送消息（AI 请求进行中时，再次点击发送 = 请求停止）
async function sendMessage() {
  const input = document.getElementById('chat-input');
  const message = input.value.trim();

  if (state.aiBusy) {
    addLog('info', '已请求停止当前 AI 任务...');
    state.flowAbortRequested = true; // 同步中止自动化流程的轮询阶段
    try { await window.electronAPI.claudeAbort(); } catch (e) { /* 可选 */ }
    return;
  }

  if (!message) return;

  // 添加用户消息
  addUserMessage(message);
  input.value = '';

  // 添加到聊天历史
  state.chatHistory.push({ role: 'user', content: message });

  // 根据消息内容处理
  await processUserMessage(message);
}

// 处理用户消息 - 基于ctf-agent智能响应
async function processUserMessage(message) {
  const lowerMessage = message.toLowerCase();
  // 词边界匹配工具（必须先于所有使用点声明，否则 TDZ 崩溃）
  const hasWord = (w) => new RegExp('(^|[^a-z0-9])' + w + '($|[^a-z0-9])').test(lowerMessage);

  // 简单命令直接处理（不需要AI理解）
  if (lowerMessage === '分析' || lowerMessage === '自动分析' || lowerMessage === 'analyze') {
    await autoAnalyze();
    return;
  }

  // 主动触发Tool Use分析
  if (lowerMessage.includes('详细分析') || lowerMessage.includes('tool use') ||
      lowerMessage.includes('深入分析') || lowerMessage.includes('用工具分析')) {
    if (state.currentFile) {
      addLog('info', '用户主动触发Tool Use分析...');
      if (state.fileType === 'APK') {
        await detailedAnalysis({
          manifest: null,
          activities: null,
          classes: null,
          mainActivityCode: null,
          packageName: null
        });
      } else {
        await detailedBinaryAnalysis(state.fileType, {
          functions: null,
          strings: null,
          mainCode: null
        });
      }
    } else {
      addLog('warning', '请先选择文件');
    }
    return;
  }

  // 生成 WP/题解报告
  if (/^(wp|writeup|生成wp|生成题解|题解报告|报告)$/i.test(lowerMessage.trim())) {
    await generateWriteup();
    return;
  }

  // AI 增强轨题解（ctf-writeup 技能）
  if (/^(aiwp|ai题解|生成aiwp)$/i.test(lowerMessage.trim()) || lowerMessage.includes('ai写wp')) {
    await generateAIWriteup();
    return;
  }

  // 本地枚举假设（验证失败后的兜底也可手动触发）
  if (/^(枚举假设|跑假设|hypotheses)$/i.test(lowerMessage.trim())) {
    await runHypotheses(state.lastAiText || '');
    return;
  }

  // 一键求 flag（对齐系统提示词中的约定）
  if (lowerMessage.includes('求出flag') || lowerMessage.includes('求解flag') || lowerMessage.includes('自动求解')) {
    await autoAnalyze();
    return;
  }

  // Windows PE 反调试脚本
  if (lowerMessage.includes('windows') && (lowerMessage.includes('反调试') || lowerMessage.includes('bypass'))) {
    await generateWindowsAntiDebugScript();
    return;
  }

  // APK 重打包签名
  if (lowerMessage.includes('重打包') || lowerMessage.includes('repack') || lowerMessage.includes('回编') || lowerMessage.includes('签名')) {
    await generateSmaliRepackScript();
    return;
  }

  // RC4 动态脚本
  if (lowerMessage.includes('rc4') && (lowerMessage.includes('动态') || lowerMessage.includes('hook') || lowerMessage.includes('调试'))) {
    await generateRc4DynamicScript();
    return;
  }

  // 生成脚本
  if (lowerMessage.includes('脚本') || hasWord('script')) {
    if (lowerMessage.includes('hook') || lowerMessage.includes('frida')) {
      await generateFridaScript();
    } else if (lowerMessage.includes('解密') || lowerMessage.includes('decrypt')) {
      await generateDecryptScript();
    } else if (lowerMessage.includes('反调试') || lowerMessage.includes('bypass')) {
      await generateAntiDebugScript();
    } else {
      await generateScript();
    }
    return;
  }

  // 反调试
  if (lowerMessage.includes('反调试') || lowerMessage.includes('anti-debug')) {
    await generateAntiDebugScript();
    return;
  }

  // Burp 命令（启动/历史/说明）
  if (lowerMessage.startsWith('burp')) {
    const sub = message.replace(/^burp\s*/i, '').trim();
    if (/^启动|^start$/i.test(sub)) {
      await launchTool('burp');
      addLog('info', '等待 Burp 就绪并自动连接 MCP...');
      const deadline = Date.now() + 150000;
      let ready = false;
      while (Date.now() < deadline) {
        const p = await window.electronAPI.burpProbe();
        if (p.listening) { ready = true; break; }
        await new Promise(r => setTimeout(r, 3000));
      }
      if (ready) {
        try {
          await window.electronAPI.burpMcpCall('history', { max: 5 });
          setMcpStatus('burp', true);
          addLog('success', '✅ Burp 已启动且 MCP 自动连接成功，可直接说"分析这个站的加密参数"');
        } catch (e) {
          addLog('warning', 'Burp 已启动但 MCP 连接失败: ' + e.message);
        }
      } else {
        addLog('warning', 'Burp 启动超时，请手动检查');
      }
    } else if (/^历史|^history/i.test(sub)) {
      const r = await window.electronAPI.burpMcpCall('history', { max: 20 });
      if (r.success) {
        const text = typeof r.result === 'string' ? r.result : JSON.stringify(r.result, null, 2);
        addSystemMessage(`**Burp 代理历史（最近20条）**\n\n\`\`\`\n${text.substring(0, 3000)}\n\`\`\`\n\n直接说"分析这个站的加密参数"可进入 JS 逆向流程。`);
      } else {
        addLog('error', '获取代理历史失败: ' + r.error);
      }
    } else {
      addSystemMessage(`**Burp MCP（Web/JS 逆向流量分析）**

**启动与连接：**
- \`burp 启动\` - 拉起 BurpSuite（路径见设置）
- 启动后加载 Burp MCP 插件，点击左侧 "Burp MCP" 连接

**AI 可用工具（连接后）：**
- \`burp_get_history\` - 搜索代理历史，定位加密参数请求
- \`burp_get_message\` - 获取报文详情（提取 JS/参数）
- \`burp_call\` - 调用插件暴露的任意工具

**JS 逆向工作流：** 浏览器代理指向 Burp → 触发目标请求 → 对我说"分析这个站的加密参数"→ 我会走五阶段流程（观察→捕获→复现→验证→记录），输入 \`js逆向\` 查看完整方法论。`);
    }
    return;
  }

  // Web/JS 逆向自动流程（像 IDA/JEB：自动拉起 Burp/浏览器 → 连 MCP → AI 分析）
  if (/(分析|看看|定位|找).{0,16}(加密参数|签名参数)|(加密参数|抓包).{0,10}(分析|逆向)|自动抓包/.test(lowerMessage)) {
    await analyzeWebJS();
    return;
  }

  // JS 逆向方法论卡片（仅精确命令；"分析这个站的加密参数"这类自然语言放行给 AI，
  // 由 AI read_skill ctf-jsreverse + burp 工具真正执行五阶段流程）
  if (/^(js逆向|js reverse|jsreverse)$/i.test(lowerMessage.trim())) {
    let skillText = '';
    try {
      const sk = await window.electronAPI.skillRead('ctf-jsreverse');
      if (sk && sk.success) skillText = sk.content;
    } catch (e) { /* 技能未装时给精简版 */ }
    if (skillText) {
      addSystemMessage(`**JS 逆向方法论（ctf-jsreverse）**\n\n${skillText.replace(/^---[\s\S]*?---\s*\n/, '').slice(0, 3000)}\n\n> 完整文档已随技能注入 AI（对话中直接说"分析这个站的加密参数"即可按此流程执行）。`);
    } else {
      addSystemMessage(`**JS 逆向五阶段流程**

1. **观察 Observe**：抓包（Burp 代理），定位加密参数（sign/token/X-Bogus/a_bogus...）
2. **捕获 Capture**：搜 JS 关键词（encrypt/sign/JSEncrypt/CryptoJS）→ XHR 断点回溯调用栈
3. **复现 Rebuild**：路径A 算法追踪（Hook/插桩还原算法）｜路径B 环境伪装（jsdom/vm 补环境直接跑原码）
4. **验证 Verify**：把还原的 JS 函数给我，走 \`[VERIFY]\` 契约本地 node 复现
5. **记录 Document**：\`aiwp\` 生成题解

判型：\`_0x\` 前缀大量出现 = obfuscator.io 混淆；控制流Flat = JSVMP；412/Cookie跳转 = 瑞数。`);
    }
    return;
  }

  // 经验库（reverse-skill 进化层：完成任务回写经验，下次任务自动速查）
  if (lowerMessage.startsWith('经验') || lowerMessage.startsWith('查经验')) {
    const text = message.replace(/^(经验|查经验)\s*/, '').trim();
    if (text && state.appPaths) {
      const line = `- [${new Date().toISOString().slice(0, 10)}] ${text}\n`;
      const expPath = `${state.appPaths.userData}/experience.md`;
      // 首次创建补表头（read-file 对缺失文件返回 {success:false} 而不是抛异常）
      const rf = await window.electronAPI.readFile(expPath);
      if (!rf || !rf.success) {
        await window.electronAPI.writeFile(expPath, '# 解题经验库（reverse-skill 进化层：AI 解题前自动速查）\n\n');
      }
      const r = await window.electronAPI.appendFile(expPath, line);
      if (r && r.success) {
        state.experience += line;
        addSolveNote('经验', text);
        addSystemMessage(`**💡 经验已入库**\n\n> ${text}\n\n下次分析时自动注入系统提示（经验速查），同类题可直接复用。`);
        await pruneExperience();
      } else {
        addLog('error', '经验写入失败');
      }
    } else {
      const lines = (state.experience || '').trim();
      addSystemMessage(lines ? `**📚 经验库（自动注入AI提示词）**\n\n${lines.slice(-1500)}` : '**📚 经验库为空**\n\n输入 `经验 <内容>` 记录一条可复用的解题经验。');
    }
    return;
  }

  // 决策树查询
  if (lowerMessage.includes('决策树') || lowerMessage.includes('流程') || lowerMessage.includes('workflow')) {
    addSystemMessage(`**ctf-agent 决策树**

拿到逆向/Mobile题:
├── 文件类型判断
│   ├── APK → Android 分析流程
│   │   ├── 查壳 → 有壳 → 脱壳流程
│   │   ├── 无壳 → jadx/JEB 静态分析
│   │   ├── native so → IDA 分析 SO
│   │   └── 动态调试 → Frida + 安卓9(62025)
│   ├── SO (ELF ARM/ARM64) → IDA + Frida
│   ├── EXE/DLL → PE 分析流程
│   │   ├── 查壳 (DIE) → 有壳 → 脱壳
│   │   └── 无壳 → IDA + x64dbg
│   ├── ELF → IDA + GDB
│   └── 其他 → binwalk + strings
├── 算法识别
│   ├── 0x9E3779B9 → TEA 系列
│   ├── S盒 0x63 → AES
│   ├── SM4 S盒 → 国密 SM4
│   └── 自定义 → Z3/angr 求解
└── 反调试检测 → 绕过策略`);
    return;
  }

  // hasWord 已在函数顶部声明（词边界匹配，避免 "open/type"→PE、"steal/team"→TEA 误伤）

  // APK分析流程
  if (hasWord('apk') || lowerMessage.includes('android') || lowerMessage.includes('安卓')) {
    addSystemMessage(`**Android APK 分析流程（ctf-agent）**

**第1步：信息收集与查壳**
- file challenge.apk
- DIE查壳 / APK查壳神器

**第2步：脱壳（如有壳）**
- Frida dump DEX: \`frida -H 127.0.0.1:27042 -n "目标应用" -l frida_dump_dex.js\`
- BlackDex（需Root）

**第3步：静态分析**
- jadx 反编译（查看Java层）
- JEB 反编译（更强大，支持混淆）
- 搜索关键字符串：flag、encrypt、decrypt、password、key

**第4步：动态分析（Frida Hook）**
- 安装: \`E:/Nox/bin/nox_adb.exe -s 127.0.0.1:62025 install app.apk\`
- Hook: \`frida -H 127.0.0.1:27042 -n "AppName" -l hook.js\`

**第5步：算法还原 → Python/Z3 解密脚本**

**第6步：提交 FLAG{...}**`);
    return;
  }

  // PE分析流程
  if (hasWord('pe') || hasWord('exe') || lowerMessage.includes('windows')) {
    addSystemMessage(`**Windows PE 分析流程（ctf-agent）**

**第1步：DIE查壳**
- 检测是否加壳（VMP/Themida/UPX等）

**第2步：有壳 → 脱壳**
- ESP定律/单步跟踪/内存dump
- UPX脱壳: \`upx -d target.exe\`

**第3步：无壳 → IDA分析**
- 定位关键函数（main/WinMain/加密函数）
- 识别字符串比较点（strcmp/memcmp）
- 分析控制流和数据流

**第4步：反调试检测 → 绕过**
- IsDebuggerPresent → Hook返回0
- NtGlobalFlag → 清除标志
- CheckRemoteDebuggerPresent → Hook

**第5步：算法还原 → 解密脚本**`);
    return;
  }

  // ELF分析流程
  if (hasWord('elf') || lowerMessage.includes('linux') || lowerMessage.includes('so文件')) {
    addSystemMessage(`**ELF 分析流程（ctf-agent）**

**第1步：IDA静态分析**
- 定位main函数
- 分析关键函数调用链
- 识别字符串比较点

**第2步：反调试检测与绕过**
- ptrace(PTRACE_TRACEME) → 返回0绕过
- TracerPid检测 → 修改/proc/self/status
- 时间检测(rdtsc) → Hook时间函数

**第3步：算法识别**
- 0x9E3779B9 → TEA系列
- S盒 0x63,0x7C... → AES
- 固定多项式 0xEDB88320 → CRC32
- 256字节S盒初始化 → RC4

**第4步：动态分析**
- Frida Hook
- GDB调试

**第5步：算法还原 → 解密脚本**`);
    return;
  }

  // TEA算法 - 自动搜索更多信息
  if (hasWord('tea') || lowerMessage.includes('0x9e3779b9')) {
    addSystemMessage(`**TEA算法识别（ctf-agent）**

**特征常量：** \`0x9E3779B9\` (delta)

**TEA解密函数：**
\`\`\`python
def tea_decrypt(v0, v1, key, rounds=32):
    delta = 0x9E3779B9
    sum_val = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    return v0, v1
\`\`\`

**常见变种：**
- TEA: 32轮，delta=0x9E3779B9
- XTEA: 使用数组key
- XXTEA: 支持变长数据

**识别方法：**
- 查找0x9E3779B9常量
- 查找32轮循环
- 查找左移4位和右移5位操作

**正在搜索更多TEA相关信息...**`);

    // 自动使用浏览器MCP搜索
    try {
      const searchResult = await window.electronAPI.browserMcpSearch('TEA加密算法 CTF逆向 解密');
      if (searchResult.success) {
        addLog('info', '已获取TEA相关搜索结果');
      }
    } catch (err) {
      // 搜索失败不影响主流程
    }

    return;
  }

  // AES算法
  if (hasWord('aes') || lowerMessage.includes('s盒') || lowerMessage.includes('sbox')) {
    addSystemMessage(`**AES算法识别（ctf-agent）**

**特征：** S盒起始值 \`0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5...\`

**AES解密函数：**
\`\`\`python
from Crypto.Cipher import AES

def aes_decrypt(encrypted, key, mode='ECB'):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return cipher.decrypt(encrypted)
\`\`\`

**识别方法：**
- 查找S盒常量（256字节）
- 查找轮常量（Rcon）
- 检查密钥长度（128/192/256位）
- 查找MixColumns/ShiftRows操作

**常见模式：**
- ECB: 电子密码本
- CBC: 密码分组链接
- CTR: 计数器模式`);
    return;
  }

  // SM4算法
  if (hasWord('sm4') || lowerMessage.includes('国密')) {
    addSystemMessage(`**SM4算法识别（ctf-agent）**

**特征：** S盒 \`0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7...\`

**SM4解密函数：**
\`\`\`python
from gmssl import sm4

def sm4_decrypt(encrypted, key):
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_DECRYPT)
    return crypt.crypt_ecb(encrypted)
\`\`\`

**特点：**
- 国密算法（中国国家密码标准）
- 128位密钥
- 32轮Feistel结构
- S盒与AES不同

**识别方法：**
- 查找SM4 S盒（与AES不同）
- 查找32轮循环
- 查找线性变换L`);
    return;
  }

  // RC4算法
  if (hasWord('rc4') || lowerMessage.includes('s盒初始化')) {
    addSystemMessage(`**RC4算法识别（ctf-agent）**

**特征：** 256字节S盒初始化（KSA）

**RC4解密函数：**
\`\`\`python
def rc4_decrypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)
\`\`\`

**识别方法：**
- 查找256字节循环初始化（KSA）
- 查找PRGA逻辑
- 查找i/j两个索引变量

**特点：**
- 对称加密
- 密钥长度可变
- 流密码`);
    return;
  }

  // MD5算法
  if (hasWord('md5') || lowerMessage.includes('0x67452301')) {
    addSystemMessage(`**MD5算法识别（ctf-agent）**

**特征：** 初始向量 \`0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476\`

**MD5计算：**
\`\`\`python
import hashlib

def md5_hash(data):
    return hashlib.md5(data).hexdigest()
\`\`\`

**识别方法：**
- 查找4个32位初始向量
- 查找64轮运算常量（T表）
- 查找左移位数表

**特点：**
- 不可逆（哈希）
- 128位输出
- 常用于校验

**破解方式：**
- 彩虹表：cmd5.com, hashcat
- 暴力破解：hashcat, john`);
    return;
  }

  // CRC32算法
  if (hasWord('crc') || lowerMessage.includes('0xedb88320')) {
    addSystemMessage(`**CRC32算法识别（ctf-agent）**

**特征：** 多项式 \`0xEDB88320\`（反转）

**CRC32碰撞：**
\`\`\`python
import binascii
import itertools

def crc32_bruteforce(target, length, charset='abcdefghijklmnopqrstuvwxyz'):
    for combo in itertools.product(charset, repeat=length):
        s = ''.join(combo).encode()
        if binascii.crc32(s) & 0xFFFFFFFF == target:
            return s
    return None
\`\`\`

**特点：**
- CRC32不可逆，只能暴力碰撞
- 通常用于校验，不是加密
- 32位输出

**识别方法：**
- 查找0xEDB88320多项式
- 查找256项查找表
- 查找异或和移位操作

**加速工具：**
- hashcat
- CRC32碰撞脚本`);
    return;
  }

  // 输出规范
  if (lowerMessage.includes('输出') || lowerMessage.includes('规范') || lowerMessage.includes('format')) {
    addSystemMessage(`**ctf-agent 输出规范**

**解题报告要求：**

1. **程序行为简述**
   - 输入输出
   - 核心保护机制

2. **静态分析流程**
   - 定位关键函数
   - 识别算法
   - 数据流分析

3. **动态验证与反调试绕过**
   - 如有反调试，说明绕过方法

4. **注册机/解密脚本**
   - Python 3 单文件
   - 带注释
   - 可直接运行

5. **最终 flag**
   - FLAG{...} 格式`);
    return;
  }

  // 工具链查询
  if (lowerMessage.includes('工具') || hasWord('tool')) {
    addSystemMessage(`**ctf-agent 工具链**

**静态分析：**
- IDA Pro 9.2 → 静态分析
- JEB 5.14 → Android DEX/ARM
- jadx 1.5.0 → DEX→Java
- DIE 3.10 → 查壳
- pycdc → Python 字节码

**脱壳工具：**
- UPX 5.0.2 → UPX 脱壳
- Frida dump DEX → 动态脱壳
- BlackDex → 免Root脱壳

**动态分析：**
- Frida 17.9.8 → 动态 hook
- frida-server → Android端服务
- GDB → Linux调试

**模拟器：**
- 安卓9模拟器 → ADB端口 62025
- Frida端口 → 27042

**MCP工具（实时集成）：**
- IDA MCP → 127.0.0.1:13337
- JEB MCP → Desktop/jebmcp
- 浏览器 MCP → 网页搜索/内容获取`);
    return;
  }

  // IDA MCP 命令
  if (lowerMessage.startsWith('ida')) {
    const idaCommand = lowerMessage.replace('ida', '').trim();

    if (idaCommand.includes('分析') || idaCommand.includes('analyze')) {
      addLog('info', '调用IDA MCP分析...');
      const result = await window.electronAPI.idaMcpAnalyze();
      if (result.success) {
        addSystemMessage(`**IDA MCP 分析结果**\n\n${JSON.stringify(result.result, null, 2)}`);
      } else {
        addSystemMessage(`**IDA MCP 分析失败**\n\n${result.error}`);
      }
    } else if (idaCommand.includes('反编译') || idaCommand.includes('decompile')) {
      addLog('info', '调用IDA MCP反编译...');
      addSystemMessage(`**IDA MCP 反编译**\n\n请在IDA中选择要反编译的函数，然后重试。`);
    } else {
      addSystemMessage(`**IDA MCP 命令**

可用命令:
- \`ida 分析\` - 分析当前二进制文件
- \`ida 反编译\` - 反编译选中的函数
- \`ida 字符串\` - 搜索字符串
- \`ida 交叉引用\` - 查看交叉引用

点击左侧 "IDA MCP" 按钮连接IDA。`);
    }
    return;
  }

  // JEB MCP 命令
  if (lowerMessage.startsWith('jeb')) {
    addSystemMessage(`**JEB MCP 命令**

可用命令:
- \`jeb 分析\` - 分析Android应用
- \`jeb 反编译\` - 反编译DEX代码
- \`jeb 类\` - 查看类列表
- \`jeb 方法\` - 查看方法列表

点击左侧 "JEB MCP" 按钮启动JEB。`);
    return;
  }

  // 浏览器搜索命令
  if (lowerMessage.startsWith('搜索') || lowerMessage.startsWith('search')) {
    const query = message.replace(/^(搜索|search)\s*/i, '').trim();

    if (query) {
      addLog('info', `搜索: ${query}`);
      const result = await window.electronAPI.browserMcpSearch(query);

      if (result.success) {
        addSystemMessage(`**搜索结果: ${query}**\n\n${result.snapshot}`);
      } else {
        addSystemMessage(`**搜索失败**\n\n${result.error}`);
      }
    } else {
      addSystemMessage(`**浏览器搜索**\n\n使用方法: \`搜索 [关键词]\`\n\n例如:\n- 搜索 TEA算法解密\n- 搜索 AES S盒\n- 搜索 CTF逆向技巧`);
    }
    return;
  }

  // 打开网页命令
  if (lowerMessage.startsWith('打开') || lowerMessage.startsWith('open')) {
    const url = message.replace(/^(打开|open)\s*/i, '').trim();

    if (url) {
      addLog('info', `打开网页: ${url}`);
      const result = await window.electronAPI.browserMcpFetch(url);

      if (result.success) {
        addSystemMessage(`**网页内容: ${url}**\n\n${result.snapshot}`);
      } else {
        addSystemMessage(`**获取网页失败**\n\n${result.error}`);
      }
    } else {
      addSystemMessage(`**打开网页**\n\n使用方法: \`打开 [URL]\`\n\n例如:\n- 打开 https://ctf-wiki.org\n- 打开 https://www.root-me.org`);
    }
    return;
  }

  // Kali命令
  if (lowerMessage.startsWith('kali')) {
    const kaliCmd = message.replace(/^kali\s*/i, '').trim();

    if (!kaliCmd) {
      addSystemMessage(`**Kali Linux 虚拟机**

**启动/关闭：**
- 点击左侧 "启动" 按钮启动虚拟机
- 点击 "关闭" 按钮关闭虚拟机
- 点击 "测试" 按钮检查连接

**执行命令：**
\`kali [命令]\`

**常用示例：**
- \`kali binwalk -e firmware.bin\` - 提取固件
- \`kali strings flag\` - 提取字符串
- \`kali file mystery\` - 检查文件类型
- \`kali gdb ./binary\` - GDB调试
- \`kali strace ./program\` - 系统调用跟踪
- \`kali ltrace ./program\` - 库调用跟踪
- \`kali r2 -A binary\` - radare2分析
- \`kali python3 solve.py\` - 运行Python脚本
- \`kali cat /etc/passwd\` - 查看文件

**可用工具：**
binwalk, strings, file, gdb, strace, ltrace, radare2, pwntools, john, hashcat, nmap, sqlmap...`);
      return;
    }

    // 执行Kali命令
    const output = await execKaliCommand(kaliCmd);
    if (output) {
      addSystemMessage(`**Kali 执行结果:**\n\n\`\`\`\n${output}\n\`\`\``);
    }
    return;
  }

  // 默认响应 - 使用Claude API
  await callClaudeAPI(message);
}

// 快速操作处理
async function handleQuickAction(action) {
  switch (action) {
    case 'analyze':
      await autoAnalyze();
      break;
    case 'decrypt':
      await generateDecryptScript();
      break;
    case 'hook':
      await generateFridaScript();
      break;
    case 'bypass':
      await generateAntiDebugScript();
      break;
  }
}

// 智能分析（基于ctf-agent）
async function autoAnalyze() {
  if (!state.currentFile) {
    addLog('warning', '请先选择文件');
    return;
  }

  addLog('info', '========================================');
  addLog('info', '智能分析模式（基于ctf-agent）');
  addLog('info', '========================================');

  // 根据文件类型执行不同的分析流程
  switch (state.fileType) {
    case 'APK':
      await analyzeAPK();
      // 添加智能提示
      addSystemMessage(`**APK分析完成，接下来可以：**

**静态分析（推荐先试）：**
直接问我问题，我会通过JEB MCP分析：
- "分析加密算法"
- "找flag比较点"
- "分析JNI函数"
- "找关键字符串"

**动态Hook（需要时使用）：**
1. 在模拟器中启动APP
2. 点击"运行Hook"按钮
3. 查看Frida日志获取运行时数据

**脚本求解：**
- 生成解密脚本
- 在VS Code中运行
- 获取flag`);
      break;
    case 'PE':
      await analyzePE();
      addSystemMessage(`**PE分析完成，接下来可以：**

**MCP分析（推荐）：**
直接问我问题，我会通过IDA MCP分析：
- "分析main函数"
- "找字符串比较点"
- "识别加密算法"
- "分析反调试"

**脚本求解：**
- 生成解密脚本
- 在VS Code中运行
- 获取flag`);
      break;
    case 'ELF':
      await analyzeELF();
      addSystemMessage(`**ELF分析完成，接下来可以：**

**MCP分析（推荐）：**
直接问我问题，我会通过IDA MCP分析：
- "分析main函数"
- "找字符串比较点"
- "识别加密算法"
- "分析反调试"

**脚本求解：**
- 生成解密脚本
- 在VS Code中运行
- 获取flag`);
      break;
    case 'DEX':
      await analyzeDEX();
      break;
    case 'PYC':
      await analyzePYC();
      break;
    case 'JAR':
    case 'JAVA_CLASS':
      await analyzeJava();
      break;
    case 'MACHO':
      await analyzeMachO();
      break;
    case 'LUAC':
      await analyzeLua();
      break;
    case 'JS':
    case 'HTML':
      addSolveNote('文件', `Web/JS 文件分析：${state.fileInfo.fileName}`);
      try {
        const rf = await window.electronAPI.readFile(state.currentFile);
        if (rf && rf.success) await caseAddEvidence('js_source', 'JS 原文', rf.content || '');
        else addLog('warning', 'JS 原文读取失败: ' + ((rf && rf.error) || '未知') + '（继续流程）');
      } catch (e) {
        addLog('warning', 'JS 原文存证失败: ' + e.message + '（继续流程）');
      }
      await analyzeWebJS();
      break;
    case 'ZIP':
      addSystemMessage('**ZIP 压缩包**\n\n不是 APK（未找到 AndroidManifest.xml）。\n建议：`kali binwalk -e 文件名` 提取内容，或检查是否嵌套题目文件。');
      break;
    case 'BIN':
    case 'UNKNOWN':
      // 尝试用Kali分析（固件/bin文件）
      await analyzeBIN();
      break;
    default:
      addLog('warning', '不支持的文件类型，尝试用Kali分析...');
      await analyzeBIN();
  }
}

// JAR/.class 分析（jadx 反编译）
async function analyzeJava() {
  addLog('info', '执行 Java（JAR/.class）分析流程...');

  addLog('info', '[1/1] 启动jadx反编译...');
  await window.electronAPI.launchTool('jadx', state.currentFile);

  addSystemMessage(`**Java 分析流程已启动**

1. ✅ jadx 已启动并加载文件

下一步:
- 在 jadx 中搜索 flag / encrypt / password / key
- 定位 main 方法和校验逻辑
- 需要时生成解密脚本（输入"生成解密脚本"）`);
}

// Mach-O 分析指引
async function analyzeMachO() {
  addLog('info', 'Mach-O 分析指引');

  addSystemMessage(`**Mach-O (macOS/iOS) 分析流程**

1. **确认架构**：file 文件名（x86_64 / arm64 / fat binary）
2. **IDA Pro** 直接打开（支持 Mach-O）；fat 二进制需先拆分：\`lipo -thin arm64 fat.bin -output arm64.bin\`
3. **静态分析**：定位 main → 关键函数 → 字符串比较
4. **Objective-C/Swift**：关注 objc_msgSend 调用和方法名
5. **动态调试**：macOS 上用 lldb；iOS 需砸壳后的 ipa + frida

本机为 Windows，Mach-O 动态调试建议传到 Kali/macOS 虚拟机进行。`);
}

// Lua 字节码分析指引
async function analyzeLua() {
  addLog('info', 'Lua 字节码分析指引');

  addSystemMessage(`**Lua 字节码 (.luac) 分析流程**

1. **确认 Lua 版本**：文件头第 5 字节（0x51=5.1, 0x52=5.2, 0x53=5.3, 0x54=5.4）
2. **反编译**：unluac（Java 工具，需选对版本）
   \`java -jar unluac_2015.jar file.luac > out.lua\`
   5.3/5.4 也可用 luac -l 查看字节码
3. **字符串提取**：常量表通常明文，\`strings 文件名 | grep -i flag\`
4. 遇到自定义 VM/字节码混淆时，先还原 opcode 映射表`);
}

// APK分析 - 基于ctf-agent工作流（完整自动化，如实汇报每步结果）
async function analyzeAPK() {
  addSolveNote('文件', `开始分析 APK：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', '开始APK自动化分析流程');
  addLog('info', '========================================');

  const steps = { jebMcp: false, soExtracted: false, idaMcp: false, emulator: false, install: false, frida: false };

  // ========== 第1步：信息收集与查壳 ==========
  addLog('info', '[1/7] 检查是否加壳...');
  await launchTool('die');

  // ========== 第2步：JEB分析Java层 ==========
  addLog('info', '[2/7] 启动JEB分析Java层...');
  addLog('info', `JEB打开文件: ${state.currentFile}`);

  // 先探测 16161：端口在监听就说明已有 JEB（含 MCP 插件）在跑，直接复用，
  // 避免重复启动第二个 JEB（第二个无法绑定 16161，且同工程被占用会卡死）。
  // 注意：只判端口，不做 MCP 握手——JEB 正忙时握手会超时，会误判成"未运行"。
  let jebAlreadyRunning = false;
  try {
    const p = await window.electronAPI.checkPort(16161);
    jebAlreadyRunning = !!(p && p.listening);
  } catch (e) { jebAlreadyRunning = false; }

  if (jebAlreadyRunning) {
    setMcpStatus('jeb', true);
    steps.jebMcp = true;
    addLog('success', '检测到 JEB MCP 已在运行（端口 16161），直接复用，不重复启动');
  } else {
    await launchTool('jeb');

    // 等待JEB完全启动（JEB启动较慢，需要更多时间）
    addLog('info', '等待JEB启动（约10秒）...');
    await new Promise(resolve => setTimeout(resolve, 10000));

    // 自动连接JEB MCP（30秒内轮询探测）
    addLog('info', '正在连接JEB MCP (端口: 16161)...');
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      try {
        const jebResult = await window.electronAPI.testMcpConnection('jeb');
        if (jebResult.success) {
          setMcpStatus('jeb', true);
          addLog('success', '✅ JEB MCP 已连接');
          steps.jebMcp = true;
          break;
        }
      } catch (err) { /* 继续重试 */ }
      addLog('info', 'JEB MCP 未就绪，3秒后重试...');
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
  if (!steps.jebMcp) {
    setMcpStatus('jeb', false);
    addLog('warning', 'JEB MCP 连接失败，请手动在JEB中启用MCP插件');
    addLog('info', 'JEB MCP端口: 127.0.0.1:16161');
  }

  // ========== 第3步：IDA分析SO层（如有） ==========
  addLog('info', '[3/7] 检查是否包含Native SO文件...');
  const hasSO = await checkAPKForSOFiles();

  // Unity IL2CPP 检测：存在 global-metadata.dat 时给出专项流程
  try {
    const zl = await window.electronAPI.zipList(state.currentFile);
    const il2cppHit = zl && zl.success && Array.isArray(zl.names)
      ? zl.names.find((n) => /global-metadata\.dat$/i.test(String(n)))
      : null;
    if (il2cppHit) {
      addLog('warning', '检测到 Unity IL2CPP（global-metadata.dat）');
      addSystemMessage(`**Unity IL2CPP 提示**

该 APK 使用 IL2CPP 编译，C# 逻辑编译进了 native so，JEB 看不到校验/加密逻辑。

推荐流程:
1. 用 Il2CppDumper：输入 libil2cpp.so + global-metadata.dat → 输出 dummy.dll 与脚本（含所有 C# 类名与方法地址）
2. 用 IDA 打开 libil2cpp.so，加载 Il2CppDumper 生成的 script.json 恢复符号
3. 定位到校验/加密函数后正常逆向

工具: https://github.com/Perfare/Il2CppDumper`);
      addSolveNote('提示', 'Unity IL2CPP 应用，需 Il2CppDumper + IDA 加载符号后分析 native 层');
    }
  } catch (e) { /* 检测失败不阻塞 */ }

  if (hasSO) {
    addLog('info', '发现SO文件，提取并启动IDA分析...');

    const soFile = await extractSOFromAPK();
    if (soFile) {
      steps.soExtracted = true;
      addLog('info', `SO文件已提取: ${soFile}`);

      // 启动IDA并自动打开SO文件（若 IDA MCP 已在跑则复用，launchTool 内部会跳过）
      addLog('info', 'IDA打开SO文件...');
      await launchTool('ida', soFile);

      // 自动连接IDA MCP：IDA 冷启动 + 插件自启监听需要时间，
      // 用端口轮询等待（最长 180s），而不是固定 2s 后一次性判定失败。
      addLog('info', '正在连接IDA MCP (端口: 13337)，等待 IDA + MCP 插件就绪...');
      try {
        const idaOk = await connectIdaMcpWithWait({ waitMs: 180000, pollMs: 3000 });
        steps.idaMcp = !!idaOk;
        if (!idaOk) {
          addLog('warning', 'IDA MCP 未就绪（IDA 是否已打开该 SO？插件是否启用？）');
        }
      } catch (err) {
        setMcpStatus('ida', false);
        addLog('warning', 'IDA MCP 连接失败: ' + err.message);
      }

      // IDA MCP 连上后**真正调用它**：枚举导出函数 → 定位 JNI 函数（Java_*）→ 反编译，
      // 把伪代码/关键字符串喂给后续 AI（此前只"连上"不用，等于白连）。
      if (steps.idaMcp) {
        try {
          await collectIdaNativeIntel();
        } catch (e) {
          addLog('warning', 'IDA 反编译取数失败（不影响主流程）: ' + e.message);
        }
      }

      // 生成Native Hook脚本
      await generateNativeHookScript();
    }
  } else {
    addLog('info', '未发现SO文件，跳过IDA分析');
  }

  // ========== 第4步：检查模拟器并安装APK ==========
  addLog('info', '[4/7] 检查模拟器状态...');
  steps.emulator = await checkEmulatorStatus();
  if (!steps.emulator) {
    // checkEmulatorStatus 内部已尝试自动启动；再确认一次
    steps.emulator = await checkEmulatorStatus();
  }

  addLog('info', '[5/7] 安装APK到模拟器...');
  steps.install = await installApkToEmulator();

  // ========== 第5步：启动Frida并执行Hook ==========
  addLog('info', '[6/7] 启动Frida服务...');
  steps.frida = await startFridaServer();

  // ========== 第6步：生成Hook脚本 ==========
  addLog('info', '[7/7] 生成Frida Hook脚本...');
  await generateFridaScript();

  // ========== 第7步：自动求解flag ==========
  addLog('info', '========================================');
  addLog('info', '[自动求解] 开始通过MCP分析求解flag...');
  addLog('info', '========================================');

  await autoSolveFlag();

  // 构建结果消息（按实际执行结果汇报，不再无条件打勾）
  const mark = (ok) => ok ? '✅' : '❌';
  const adbPort = (state.config.emulator && state.config.emulator.adb_port) || 62025;
  const fridaPort = (state.config.emulator && state.config.emulator.frida_port) || 27042;
  let resultMsg = `**APK自动化分析流程完成**

**第1步：查壳**
✅ DIE已启动

**第2步：Java层分析（JEB）**
✅ JEB已启动 - 自动加载APK文件
${mark(steps.jebMcp)} JEB MCP连接 (端口: 16161)`;

  if (hasSO) {
    resultMsg += `

**第3步：Native层分析（IDA）**
${mark(steps.soExtracted)} 检测到SO文件并提取
✅ IDA已启动 - 自动打开SO文件
${mark(steps.idaMcp)} IDA MCP连接 (端口: 13337)
✅ Native Hook脚本已生成`;
  }

  resultMsg += `

**第4步：模拟器部署**
${mark(steps.emulator)} 模拟器连接 (端口: ${adbPort})
${mark(steps.install)} APK安装

**第5步：Frida动态分析**
${mark(steps.frida)} Frida服务 (端口: ${fridaPort})
✅ Java Hook脚本已生成

**使用方法：**
- 查看脚本预览标签页获取Hook脚本
- 在模拟器中运行目标APP
- 使用Frida进行动态分析

**常用命令：**
\`\`\`bash
# 列出进程
frida-ps -H 127.0.0.1:${fridaPort}

# Hook应用
frida -H 127.0.0.1:${fridaPort} -n "AppName" -l hook.js
\`\`\``;

  if (!steps.jebMcp || !steps.install || !steps.frida) {
    resultMsg += `\n\n> ⚠️ 存在未成功的步骤（见❌项），动态分析前请先手动修复对应环节。`;
  }

  addSystemMessage(resultMsg);
}

// 安装APK到模拟器（返回是否成功）
async function installApkToEmulator() {
  try {
    // 前置校验：没有题目文件时 install -r "null" 会被 adb 拒绝，
    // 而 IPC 只要没抛异常就 success=true，曾导致"假成功"（日志打勾但实际未安装）。
    if (!state.currentFile) {
      addLog('warning', '未选择 APK 文件，无法安装');
      return false;
    }
    if (state.fileType && state.fileType !== 'APK') {
      addLog('warning', `当前文件类型为 ${state.fileType}，不是 APK，跳过安装`);
      return false;
    }

    // 先连接设备
    const adbPort = (state.config.emulator && state.config.emulator.adb_port) || 62025;
    await window.electronAPI.adbCommand(`connect 127.0.0.1:${adbPort}`);

    // 就绪轮询（最多15秒），避免设备半就绪时 install 直接失败
    const wait = await window.electronAPI.adbWaitDevice(15000);
    if (!wait.success) {
      addLog('warning', '设备未就绪: ' + wait.error);
      return false;
    }

    // 安装APK（使用-r允许覆盖安装）
    addLog('info', '正在安装APK...');
    const result = await window.electronAPI.adbCommand(`install -r "${state.currentFile}"`);

    // 必须校验 adb 的真实输出：install 成功 stdout 含 "Success"，
    // 失败含 "Failure"/"Missing APK file"/"no devices" 等（且 stderr 非空）。
    const out = `${(result && result.stdout) || ''}\n${(result && result.stderr) || ''}`;
    const installOk = /Success/i.test(out) && !/Failure|Missing APK file|no devices\/emulators found/i.test(out);
    if (installOk) {
      addLog('success', '✅ APK安装成功');

      // 获取包名
      const packageName = await getPackageNameFromAPK();
      if (packageName) {
        addLog('info', `包名: ${packageName}`);

        // 启动应用
        addLog('info', '启动应用...');
        await window.electronAPI.adbCommand(`shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`);
      }
      return true;
    } else {
      addLog('warning', 'APK安装失败: ' + (out.trim() || (result && result.error) || '未知错误'));
      return false;
    }
  } catch (err) {
    addLog('warning', 'APK安装失败: ' + err.message);
    return false;
  }
}

// 从APK获取包名
async function getPackageNameFromAPK() {
  try {
    // 优先 aapt（Android SDK build-tools，通常不在 PATH，取不到再降级）
    // 参数数组 + shell:false；不再用 `| findstr` 管道（shell 注入面）
    const result = await window.electronAPI.runToolArgs(['aapt', 'dump', 'badging', state.currentFile]);
    if (result.success && result.stdout) {
      const match = result.stdout.match(/name='([^']+)'/);
      if (match) return match[1];
    }
  } catch (err) { /* 降级到 androguard */ }
  // 兜底：用 androguard 直接解析 APK 包名（不依赖 aapt / Android SDK）
  // 路径作为独立 argv 传入（scripts 里用 sys.argv[1]），不做字符串拼接
  try {
    const pyCode = 'import sys,logging;logging.disable(logging.CRITICAL);from androguard.core.apk import APK;print(APK(sys.argv[1]).get_package())';
    const tmp = await window.electronAPI.runToolArgs(['python', '-c', pyCode, state.currentFile]);
    if (tmp.success && tmp.stdout) {
      const m = String(tmp.stdout).trim().match(/^([A-Za-z][\w.]*)$/m);
      if (m) return m[1];
    }
  } catch (e) { /* 两种都失败则返回 null，由调用方弹框兜底 */ }
  return null;
}

// 启动Frida服务器（返回是否成功）
async function startFridaServer() {
  try {
    const fridaPort = (state.config.emulator && state.config.emulator.frida_port) || 27042;
    // 检查设备连接
    const deviceCheck = await window.electronAPI.adbCommand('devices');
    if (!deviceCheck.success || !deviceCheck.stdout.includes('device')) {
      addLog('warning', '模拟器未连接，跳过Frida启动');
      return false;
    }

    // 检查frida-server是否存在
    addLog('info', '检查frida-server...');
    const checkResult = await window.electronAPI.adbCommand('shell "ls -la /data/local/tmp/frida-server"');
    if (!checkResult.success) {
      addLog('warning', 'frida-server未部署');
      addLog('info', '请手动部署: adb push frida-server /data/local/tmp/');
      return false;
    }

    // 已在运行则复用（避免无谓重启造成的端口转发空窗/打断正在进行的会话）
    const already = await window.electronAPI.adbCommand('shell "ps | grep frida-server"');
    if (already.success && /frida-server/.test(already.stdout || '')) {
      await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);
      addLog('success', `Frida 服务已在运行，复用（端口: ${fridaPort}）`);
      setMcpStatus('frida', true);
      return true;
    }

    // 杀死残留的 frida-server（未正常退出时）
    await window.electronAPI.adbCommand('shell "su -c \'pkill frida-server\'"');
    await new Promise(resolve => setTimeout(resolve, 1000));

    // 启动frida-server
    addLog('info', '启动frida-server...');
    await window.electronAPI.adbCommand(
      'shell "su -c \'nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &\'"'
    );

    // 等待启动
    await new Promise(resolve => setTimeout(resolve, 2000));

    // 设置端口转发
    await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);

    // 验证frida-server是否运行
    const psResult = await window.electronAPI.adbCommand('shell "ps | grep frida"');
    if (psResult.success && psResult.stdout.includes('frida')) {
      addLog('success', `✅ Frida服务已启动 (端口: ${fridaPort})`);
      setMcpStatus('frida', true);
      return true;
    } else {
      addLog('warning', 'Frida启动可能失败，请手动检查');
      setMcpStatus('frida', false);
      return false;
    }
  } catch (err) {
    addLog('warning', 'Frida启动失败: ' + err.message);
    setMcpStatus('frida', false);
    return false;
  }
}

// 检查APK是否包含SO文件
// 确保 APK 已用 apktool 解包出 smali（内容命中筛查/常量反查依赖它）。
// 已存在则直接复用；apktool 不可用时不阻塞主流程。
async function ensureDecodedDir() {
  try {
    const apkPath = state.currentFile;
    if (!apkPath) return null;
    const sepIdx = Math.max(apkPath.lastIndexOf('\\'), apkPath.lastIndexOf('/'));
    const apkDir = apkPath.substring(0, sepIdx);
    const apkName = apkPath.substring(sepIdx + 1).replace(/\.apk$/i, '');
    const outDir = `${apkDir}/${apkName}_decoded`;
    const chk = await window.electronAPI.runToolArgs(['node', '-e', 'process.exit(require("fs").existsSync(process.argv[1])?0:1)', `${outDir}/smali`]);
    if (chk.success) return outDir;
    const jar = state.config.tools && state.config.tools.apktool;
    if (!jar) return null;
    addLog('info', '解包 APK（apktool）用于内容命中筛查...');
    const r = await window.electronAPI.runToolArgs(['java', '-jar', jar, 'd', '-f', '-o', outDir, apkPath]);
    if (r.success) { addLog('success', `解包完成: ${outDir}`); return outDir; }
    addLog('warning', 'apktool 解包失败，跳过内容命中筛查');
    return null;
  } catch (e) {
    return null;
  }
}

// 用 IDA MCP 采集 native 情报：枚举导出函数 → 挑 JNI 函数（Java_*）与语义关键函数 → 反编译。
// 结果存入 mcpCache.nativeIntel，供 autoSolveFlag/Tool-Use 阶段的 AI 直接使用。
async function collectIdaNativeIntel() {
  addLog('info', 'IDA 采集中：枚举函数与导出...');
  const intel = { exports: '', jniFuncs: [], decompiled: [] };

  // 1. 枚举函数（IDA MCP 有多种命名，逐个试到可用）
  let fnText = '';
  for (const [tool, args] of [
    ['export_funcs', {}],
    ['list_functions', { queries: {} }],
    ['survey_binary', {}]
  ]) {
    try {
      const r = await window.electronAPI.idaMcpCall(tool, args);
      if (r && r.success && r.result) { fnText = typeof r.result === 'string' ? r.result : JSON.stringify(r.result); break; }
    } catch (e) { /* 换下一个工具名 */ }
  }
  if (fnText) intel.exports = fnText.slice(0, 4000);

  // 2. 挑 JNI 导出函数（Java_…）与语义关键函数名
  const jniNames = [...new Set((fnText.match(/Java_[A-Za-z0-9_]+/g) || []))].slice(0, 8);
  const semantic = [...new Set((fnText.match(/\b[A-Za-z_][A-Za-z0-9_]*(?:encrypt|decrypt|cipher|check|verify|key|flag|crypt|sign|hash|stage)[A-Za-z0-9_]*\b/gi) || []))].slice(0, 8);
  intel.jniFuncs = [...jniNames, ...semantic].filter((v, i, a) => a.indexOf(v) === i);

  // 3. 逐个反编译（优先 JNI 函数）
  for (const name of intel.jniFuncs.slice(0, 6)) {
    try {
      const r = await window.electronAPI.idaMcpCall('decompile', { address: name });
      if (r && r.success && r.result) {
        const code = typeof r.result === 'string' ? r.result : JSON.stringify(r.result);
        intel.decompiled.push({ name, code: code.slice(0, 6000) });
        addLog('success', `IDA 已反编译: ${name}（${code.length} 字符）`);
      }
    } catch (e) { /* 单个失败继续 */ }
  }

  // 4. 搜关键字符串（flag/key/密文常量）
  try {
    const rs = await window.electronAPI.idaMcpCall('find_strings', { pattern: 'flag|ctf|key|secret|[0-9a-fA-F]{32,}' });
    if (rs && rs.success && rs.result) {
      intel.strings = (typeof rs.result === 'string' ? rs.result : JSON.stringify(rs.result)).slice(0, 3000);
    }
  } catch (e) { /* 忽略 */ }

  mcpCache.nativeIntel = intel;
  if (intel.decompiled.length) {
    addLog('success', `IDA 情报采集完成：反编译 ${intel.decompiled.length} 个函数，JNI 候选 ${intel.jniFuncs.length} 个`);
  } else {
    addLog('info', `IDA 情报采集：枚举到导出/函数 ${fnText ? '成功' : '失败'}，未取到反编译结果（可手动在 IDA 中查看）`);
  }
  return intel;
}

async function checkAPKForSOFiles() {
  try {
    // 用主进程的纯 Node 解压探测 lib/*.so（无 shell、无中文路径编码问题）。
    const apkPath = state.currentFile;
    const r = await window.electronAPI.extractApkSO(apkPath);
    if (!r || !r.success) return false;
    return !!(r.soFile || (r.extracted && r.extracted.length));
  } catch (err) {
    addLog('warning', '检查SO文件失败: ' + err.message);
    return false;
  }
}

// 从APK提取SO文件（走主进程纯 Node 解压：无 shell、无中文路径编码问题）
async function extractSOFromAPK() {
  try {
    const apkPath = state.currentFile;
    addLog('info', '提取 APK 内的 native SO（Node 原生解压）...');
    const r = await window.electronAPI.extractApkSO(apkPath);
    if (!r || !r.success) {
      addLog('warning', '提取SO失败: ' + ((r && r.error) || '未知错误'));
      return null;
    }
    if (!r.soFile) {
      addLog('warning', 'APK 内未找到 lib/*.so');
      return null;
    }
    addLog('success', `找到SO文件: ${r.soFile}（共 ${r.extracted.length} 个架构）`);
    return r.soFile;
  } catch (err) {
    addLog('warning', '提取SO文件失败: ' + err.message);
    return null;
  }
}

// PE分析 - 基于ctf-agent工作流
async function analyzePE() {
  addSolveNote('文件', `开始分析 PE：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', '开始PE分析流程');
  addLog('info', '========================================');

  // .NET 程序集：优先 dnSpy/ilspycmd，IDA 仅作辅助
  if (/\.NET/.test(state.fileDescription || '')) {
    addLog('info', '检测到 .NET 程序集，建议使用 dnSpy / ilspycmd 反编译');
    addSystemMessage(`**.NET 逆向流程**

1. **dnSpy**（推荐）：直接拖入 exe/dll，可看 C# 源码并动态调试
2. **ilspycmd**: \`ilspycmd -p target.exe > decompiled.cs\`
3. 关注：字符串加密、资源中的密文、Convert.FromBase64String
4. 混淆时可用 de4dot 先去混淆
5. IDA 仍可用于分析原生依赖

识别依据：文件头引用 mscoree.dll`);
    addSolveNote('提示', '.NET 程序集，优先 dnSpy/ilspycmd；混淆时先用 de4dot');
  }

  // 第1步：DIE查壳
  addLog('info', '[1/5] 检查是否加壳...');
  await launchTool('die');

  // 第2步：启动IDA
  addLog('info', '[2/5] 启动IDA分析...');
  addLog('info', `IDA打开文件: ${state.currentFile}`);
  await launchTool('ida');

  // 等待IDA进程拉起（文件加载与插件初始化由下方端口轮询接管）
  addLog('info', '等待IDA进程拉起（3秒）...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // 自动连接IDA MCP（端口轮询等待，冷启动不再因固定重试窗口失败）
  const idaMcpConnected = await connectIdaMcpWithWait();

  // 第3步：检查反调试
  addLog('info', '[3/5] 检查反调试特征...');
  addLog('info', '常见反调试：IsDebuggerPresent/NtGlobalFlag/ptrace等');

  // 第4步：算法识别
  addLog('info', '[4/5] 识别加密算法...');
  addLog('info', '特征：0x9E3779B9→TEA, S盒0x63→AES, SM4 S盒→国密');

  // 第5步：生成解密脚本
  addLog('info', '[5/5] 生成解密脚本...');
  await generateDecryptScript();

  // ========== 第6步：自动求解flag（混合方案） ==========
  addLog('info', '========================================');
  addLog('info', '[自动求解] 开始通过MCP分析求解flag...');
  addLog('info', '========================================');

  await autoSolveBinaryFlag('PE');

  // 构建结果消息
  let resultMsg = `**PE分析流程已启动**

**第1步：DIE查壳**
✅ DIE已启动 - 检查是否加壳

**第2步：IDA静态分析**
✅ IDA已启动 - 自动打开文件
${idaMcpConnected ? '✅ IDA MCP已连接' : '⚠️ IDA MCP连接失败，请手动检查'}

**第3步：反调试检测与绕过**
- IsDebuggerPresent → Hook返回0
- NtGlobalFlag → 清除标志
- ptrace → 返回0绕过

**第4步：算法识别**
- 0x9E3779B9 → TEA系列
- S盒 0x63,0x7C,0x77... → AES
- S盒 0xD6,0x90,0xE9... → SM4
- 0x67452301,0xEFCDAB89... → MD5

**第5步：算法还原**
✅ 解密脚本已生成

**最终：提交 FLAG{...}**

**提示：** 你可以问我问题，我会结合IDA MCP的分析结果回答！`;

  addSystemMessage(resultMsg);
}

// ELF分析 - 基于ctf-agent工作流
async function analyzeELF() {
  addSolveNote('文件', `开始分析 ELF：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', '开始ELF分析流程');
  addLog('info', '========================================');

  // 第1步：启动IDA
  addLog('info', '[1/4] 启动IDA分析...');
  addLog('info', `IDA打开文件: ${state.currentFile}`);
  await launchTool('ida');

  // 等待IDA进程拉起（文件加载与插件初始化由下方端口轮询接管）
  addLog('info', '等待IDA进程拉起（3秒）...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // 自动连接IDA MCP（端口轮询等待，冷启动不再因固定重试窗口失败）
  const idaMcpConnected = await connectIdaMcpWithWait();

  // 第2步：检查反调试
  addLog('info', '[2/4] 检查反调试特征...');
  addLog('info', '常见：ptrace(PTRACE_TRACEME)/TracerPid检测');

  // 第3步：算法识别
  addLog('info', '[3/4] 识别加密算法...');
  addLog('info', '特征：0x9E3779B9→TEA, S盒→AES, CRC多项式→CRC32');

  // 第4步：生成Hook脚本
  addLog('info', '[4/4] 生成Frida Hook脚本...');
  await generateFridaScript();

  // ========== 第5步：自动求解flag ==========
  addLog('info', '========================================');
  addLog('info', '[自动求解] 开始通过MCP分析求解flag...');
  addLog('info', '========================================');

  await autoSolveBinaryFlag('ELF');

  // 构建结果消息
  let resultMsg = `**ELF分析流程已启动**

**第1步：IDA静态分析**
✅ IDA已启动 - 自动打开文件
${idaMcpConnected ? '✅ IDA MCP已连接' : '⚠️ IDA MCP连接失败，请手动检查'}

**第2步：反调试检测与绕过**
- ptrace(PTRACE_TRACEME) → 返回0绕过
- TracerPid检测 → 修改/proc/self/status
- 时间检测(rdtsc) → Hook时间函数

**第3步：算法识别**
- 0x9E3779B9 → TEA系列
- S盒 0x63,0x7C... → AES
- 固定多项式 0xEDB88320 → CRC32
- 256字节S盒初始化 → RC4

**第4步：动态分析**
✅ Frida脚本已生成

**最终：提交 FLAG{...}**

**提示：** 你可以问我问题，我会结合IDA MCP的分析结果回答！`;

  addSystemMessage(resultMsg);
}

// DEX分析
async function analyzeDEX() {
  addLog('info', '执行DEX分析流程...');

  // 启动jadx
  addLog('info', '[1/1] 启动jadx反编译...');
  await window.electronAPI.launchTool('jadx', state.currentFile);

  addSystemMessage(`DEX分析流程已启动:

1. ✅ jadx反编译 - 已启动

下一步:
- 在jadx中查看Java代码
- 搜索关键字符串
- 分析加密逻辑`);
}

// PYC分析
async function analyzePYC() {
  addLog('info', '执行PYC分析流程...');

  // 使用pycdc反编译
  addLog('info', '[1/1] 使用pycdc反编译...');
  const result = await window.electronAPI.runToolArgs([state.config.tools.pycdc, state.currentFile]);

  if (result.success) {
    addLog('success', 'pycdc反编译成功');
    addSystemMessage(`PYC反编译结果:

\`\`\`python
${result.stdout}
\`\`\`

下一步:
- 分析Python代码逻辑
- 识别加密算法
- 编写解密脚本`);
  } else {
    addLog('error', 'pycdc反编译失败: ' + result.error);
  }
}

// BIN/固件分析 - 使用Kali
async function analyzeBIN() {
  addLog('info', '执行固件分析流程（Kali模式）...');

  // 第1步：测试Kali连接
  addLog('info', '[1/4] 测试Kali连接...');
  await testKaliConnection();

  // 第2步：使用file命令检查文件类型
  addLog('info', '[2/4] 检查文件类型...');
  const fileInfo = await execKaliCommand(`file ${shq(state.currentFile)}`);
  if (fileInfo) {
    addLog('info', '文件类型: ' + fileInfo.trim());
  }

  // 第3步：使用binwalk分析
  addLog('info', '[3/4] 使用binwalk分析固件...');
  const binwalkInfo = await execKaliCommand(`binwalk ${shq(state.currentFile)}`);
  if (binwalkInfo) {
    addLog('info', 'binwalk分析结果:\n' + binwalkInfo);
  }

  // 第4步：提取字符串
  addLog('info', '[4/4] 提取字符串...');
  const stringsInfo = await execKaliCommand(`strings ${shq(state.currentFile)} | head -50`);
  if (stringsInfo) {
    addLog('info', '提取的字符串:\n' + stringsInfo);
  }

  addSystemMessage(`**固件分析流程已启动（Kali模式）**

**第1步：文件类型检查**
${fileInfo ? '```\n' + fileInfo.trim() + '\n```' : '等待执行...'}

**第2步：binwalk分析**
${binwalkInfo ? '```\n' + binwalkInfo + '\n```' : '等待执行...'}

**第3步：字符串提取**
${stringsInfo ? '```\n' + stringsInfo.substring(0, 500) + '...\n```' : '等待执行...'}

**后续步骤：**
- \`kali binwalk -e ${state.fileInfo.fileName}\` - 提取固件
- \`kali strings ${state.fileInfo.fileName} | grep flag\` - 搜索flag
- \`kali hexdump -C ${state.fileInfo.fileName} | head -100\` - 查看十六进制

**可用工具：**
binwalk, strings, file, hexdump, dd, gzip, tar, unsquashfs, jefferson...`);
}

// ========== Web/JS 逆向自动化（像 IDA/JEB：自动拉起 Burp/浏览器 → 连 MCP → AI 分析） ==========

// 代理历史空判断：兼容 JSON 数组/对象包装/常见空标记（供 analyzeWebJS 轮询复用）
function burpHistoryLooksEmpty(t) {
  if (!t) return true;
  const s = String(t).trim();
  if (s.length < 8) return true;
  if (/^(无|null|empty|not found|没有)/i.test(s)) return true;
  try {
    const j = JSON.parse(s);
    if (Array.isArray(j)) return j.length === 0;
    if (j && typeof j === 'object') {
      for (const key of ['entries', 'history', 'data', 'messages', 'results']) {
        if (Array.isArray(j[key])) return j[key].length === 0;
      }
      return Object.keys(j).length === 0;
    }
  } catch (e) { /* 非JSON，按非空处理 */ }
  return false;
}

async function analyzeWebJS(targetUrl) {
  // 并发守卫：另一条自动化流程/AI 任务进行中时拒绝重入
  if (state.aiBusy) {
    addLog('warning', '已有 AI 任务进行中，请先等待完成或点击发送键停止');
    addSystemMessage('**⏳ 已有任务进行中**\n\n等待完成，或再点一次发送按钮停止当前任务后重试。');
    return;
  }
  // 全程占锁（含 [1/5]~[3/5] 轮询阶段），防止并发触发双流程
  state.aiBusy = true;
  state.flowAbortRequested = false;
  try {
    await analyzeWebJSCore(targetUrl);
  } finally {
    state.aiBusy = false;
    state.flowAbortRequested = false;
  }
}

async function analyzeWebJSCore(targetUrl) {
  addSolveNote('文件', `开始 Web/JS 逆向流程${targetUrl ? '（目标: ' + targetUrl + '）' : ''}`);
  addLog('info', '开始 Web/JS 逆向自动化流程');
  addLog('info', '========================================');
  const steps = { burpReady: false, mcpConnected: false, browserLaunched: false, hasTraffic: false };

  // [1/5] Burp 运行探测 → 未运行自动拉起（MCP_Burp.bat 自带 MCP 扩展）+ 端口轮询
  addLog('info', '[1/5] 检查 Burp MCP 端口...');
  let probe = await window.electronAPI.burpProbe();
  if (!probe.listening) {
    addLog('info', 'Burp 未运行，自动启动（MCP_Burp.bat，自动加载 MCP 扩展）...');
    await launchTool('burp');
    const deadline = Date.now() + 150000; // Burp 冷启动较慢
    while (Date.now() < deadline) {
      if (state.flowAbortRequested) break;
      probe = await window.electronAPI.burpProbe();
      if (probe.listening) break;
      await new Promise(r => setTimeout(r, 3000));
    }
    if (state.flowAbortRequested) {
      addLog('info', '流程已停止');
      return;
    }
  }
  steps.burpReady = probe.listening;
  if (!probe.listening) {
    addLog('error', 'Burp 启动超时（150s）');
    addSystemMessage('**❌ Burp 启动超时**\n\n请手动启动 Burp 并确认 MCP Server 扩展 Enabled，然后重新触发。');
    return;
  }
  addLog('success', '✅ Burp MCP 端口已就绪');

  // [2/5] 连接 Burp MCP（history 调用 = 连接 + 数据双用途）
  addLog('info', '[2/5] 连接 Burp MCP...');
  let historyText = '';
  try {
    const r = await window.electronAPI.burpMcpCall('history', { max: 30 });
    if (!r.success) throw new Error(r.error);
    steps.mcpConnected = true;
    setMcpStatus('burp', true);
    historyText = typeof r.result === 'string' ? r.result : JSON.stringify(r.result, null, 1);
    addLog('success', '✅ Burp MCP 已连接（传输自适应）');
  } catch (err) {
    setMcpStatus('burp', false);
    addLog('error', 'Burp MCP 连接失败: ' + err.message);
    addSystemMessage('**❌ Burp MCP 连接失败**\n\n' + err.message + '\n\n可输入 `burp 启动` 重试。');
    return;
  }

  // [3/5] 流量检查：无流量 → 自动拉起走 Burp 代理的隔离浏览器 + 后台轮询
  addLog('info', '[3/5] 检查代理流量...');
  const looksEmpty = burpHistoryLooksEmpty(historyText);
  if (looksEmpty) {
    addLog('info', '代理历史为空，自动拉起走 Burp 代理的浏览器...');
    const br = await window.electronAPI.openProxyBrowser(targetUrl || '');
    steps.browserLaunched = br.success;
    if (!br.success) {
      addLog('error', '浏览器拉起失败: ' + br.error);
      addLog('info', '请手动配置浏览器代理 127.0.0.1:8080 后访问目标站');
    } else {
      addLog('success', '✅ 浏览器已启动（代理 → Burp）');
      addSystemMessage('**🌐 浏览器已自动打开（走 Burp 代理）**\n\n请在浏览器里访问目标站并触发请求（登录/翻页等），我在后台等流量（最长 90 秒）...');
      const deadline = Date.now() + 90000;
      while (Date.now() < deadline && !steps.hasTraffic && !state.flowAbortRequested) {
        await new Promise(r => setTimeout(r, 6000));
        try {
          const r2 = await window.electronAPI.burpMcpCall('history', { max: 10 });
          if (r2.success) {
            const t = typeof r2.result === 'string' ? r2.result : JSON.stringify(r2.result);
            if (!burpHistoryLooksEmpty(t)) { steps.hasTraffic = true; historyText = t; }
          }
        } catch (e) { /* 继续等 */ }
      }
    }
  } else {
    steps.hasTraffic = true;
  }
  addLog(steps.hasTraffic ? 'success' : 'warning', steps.hasTraffic ? '✅ 已捕获代理流量' : '⚠️ 未等到新流量（用现有历史继续分析）');
  if (state.flowAbortRequested) {
    addLog('info', '流程已停止');
    return;
  }
  if (historyText) await caseAddEvidence('burp_history', '代理历史', String(historyText).slice(0, 8000));

  // [4/5] AI 接手：五阶段流程 + 自主调用 burp 工具深挖
  addLog('info', '[4/5] AI 接手分析（可自主调用 Burp 工具深挖）...');
  const jsFileHint = (state.fileType === 'JS' || state.fileType === 'HTML') && state.currentFile
    ? `\n用户还拖入了 ${state.fileType} 文件：${state.currentFile} —— 先用 read_file 读取原文，结合抓包数据分析其中的加密/签名逻辑。\n`
    : '';
  const prompt = `Web/JS 逆向任务。${targetUrl ? '目标: ' + targetUrl + '。' : ''}${jsFileHint}
当前 Burp 代理历史（实时数据）：
${String(historyText).substring(0, 5000)}

请按 ctf-jsreverse 五阶段流程执行（先用 read_skill 加载完整方法论）：
1. 从代理历史定位带加密参数的请求（sign/token/data/X-Bogus 等）
2. 需要更多数据时用 burp_get_history（关键词过滤）继续查询
3. 判型（路径A 算法追踪 / 路径B 环境伪装）并给出定位思路
4. 若能还原算法，用 [VERIFY] 契约交出（JS 函数用 algo=node_js + input + expected）
5. 给出 flag 或明确的下一步引导（编号选项）`;

  beginStreamMessage();
  try {
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      buildSystemPrompt()
    );
    if (result.success && result.text) {
      endStreamMessage();
      addLog('success', 'AI 分析完成');
      state.lastAiText = result.text;
      const clean = String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000);
      addSolveNote('求解结果', clean);
      const vr = await runVerification(result.text);
      if (vr && !vr.verified) await runHypotheses(result.text);
      extractFlags(result.text).forEach(f => { recordFlag(f, 'ai', false); addSolveNote('Flag', f); });
      addSystemMessage(`**🎯 Web/JS 逆向分析结果**\n\n${result.text}`);
    } else if (result.success) {
      endStreamMessage();
      addLog('warning', 'AI 未返回内容（网络波动或内容被过滤），可重试');
      addSystemMessage('**⚠️ AI 未返回内容**\n\n可重新触发一次；已有证据已存入 CASE 目录。');
    } else if (result.aborted || /已取消/.test(result.error || '')) {
      const had = streamText.trim().length > 0;
      endStreamMessage();
      addLog('info', 'AI 任务已停止');
      addSystemMessage(had ? '**⏹ 已停止**（停止前内容见上）' : '**⏹ 已停止**');
    } else {
      endStreamMessage();
      addLog('error', 'AI 分析失败: ' + (result.error || '未知错误'));
      addSystemMessage(`**AI 分析失败**\n\n${result.error}`);
    }
  } catch (err) {
    endStreamMessage();
    addLog('error', 'AI 分析异常: ' + err.message);
  }

  // [5/5] 记录
  addLog('info', '[5/5] 流程完成（结论已入 findings，经验可用 `经验 <一句话>` 沉淀）');
}

// 生成Frida脚本 - 基于ctf-agent模板
async function generateFridaScript() {
  if (!state.currentFile) {
    addLog('warning', '请先选择文件');
    return;
  }

  const script = `// Frida Hook Script
// Target: ${state.fileInfo.fileName}
// Generated: ${new Date().toISOString()}
// Based on: ctf-agent Frida Hook Template

'use strict';

Java.perform(function() {
    console.log('[*] Frida Hook Script Loaded');
    console.log('[*] Target: ${state.fileInfo.fileName}');

    // ========== 1. Hook Cipher (加密函数) ==========
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        // Hook doFinal
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log("\\n[Cipher] ====== doFinal ======");
            console.log("[Cipher] Algorithm: " + this.getAlgorithm());
            console.log("[Cipher] Input (" + input.length + " bytes): " + bytesToHex(input));
            var result = this.doFinal(input);
            console.log("[Cipher] Output (" + result.length + " bytes): " + bytesToHex(result));
            console.log("[Cipher] ========================\\n");
            return result;
        };

        // Hook init with key
        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var modeStr = mode === 1 ? "ENCRYPT" : "DECRYPT";
            console.log("[Cipher] init mode=" + modeStr + ", algorithm=" + this.getAlgorithm());
            return this.init(mode, key);
        };

        console.log('[*] Cipher hooks installed');
    } catch(e) {
        console.log('[-] Cipher hook failed: ' + e);
    }

    // ========== 2. Hook String.equals (字符串比较，必须降噪) ==========
    try {
        var String = Java.use("java.lang.String");
        // 降噪：只保留"可能是校验"的比较，过滤 AndroidX/资源名等海量噪音
        function interesting(a, b) {
            a = a || ''; b = b || '';
            if (/flag|ctf|key|secret|token|pass|stage|iv|\\{/i.test(a) || /flag|ctf|key|secret|token|pass|stage|iv|\\{/i.test(b)) return true;
            if (a.length >= 6 && b.length >= 6 && Math.abs(a.length - b.length) <= 2) return true;
            if ((a.length >= 16 || b.length >= 16) && /^[0-9a-fA-F+/=]+$/.test(a || b)) return true;
            return false;
        }

        String.equals.implementation = function(other) {
            var result = this.equals(other);
            var a = this.toString(), b = other ? other.toString() : '';
            if (interesting(a, b)) {
                console.log("[HIT] String.equals " + result + ": '" + a + "' == '" + b + "'");
            }
            return result;
        };

        String.compareTo.overload('java.lang.String').implementation = function(other) {
            var result = this.compareTo(other);
            var a = this.toString(), b = other ? other.toString() : '';
            if (interesting(a, b)) {
                console.log("[HIT] String.compareTo '" + a + "' vs '" + b + "' -> " + result);
            }
            return result;
        };

        console.log('[*] String hooks installed');
    } catch(e) {
        console.log('[-] String hook failed: ' + e);
    }

    // ========== 3. Hook MessageDigest (哈希函数) ==========
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");

        MessageDigest.digest.overload('[B').implementation = function(input) {
            console.log("\\n[Hash] ====== digest ======");
            console.log("[Hash] Algorithm: " + this.getAlgorithm());
            console.log("[Hash] Input (" + input.length + " bytes): " + bytesToHex(input));
            var result = this.digest(input);
            console.log("[Hash] Output (" + result.length + " bytes): " + bytesToHex(result));
            console.log("[Hash] ========================\\n");
            return result;
        };

        console.log('[*] MessageDigest hooks installed');
    } catch(e) {
        console.log('[-] MessageDigest hook failed: ' + e);
    }

    // ========== 4. Hook SharedPreferences（含写入正确值的关键点） ==========
    try {
        // 正确的内部类名是 SharedPreferencesImpl$EditorImpl（此前用 SharedPreferencesImpl.EditorImpl 会 undefined）
        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        EditorImpl.putBoolean.implementation = function(key, value) {
            console.log("[DATA] SharedPreferences.putBoolean: " + key + " = " + value);
            return this.putBoolean(key, value);
        };
        EditorImpl.putString.implementation = function(key, value) {
            console.log("[DATA] SharedPreferences.putString: " + key + " = " + value);
            return this.putString(key, value);
        };
        EditorImpl.putInt.implementation = function(key, value) {
            console.log("[DATA] SharedPreferences.putInt: " + key + " = " + value);
            return this.putInt(key, value);
        };
        var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferences.getString.implementation = function(key, defValue) {
            var value = this.getString(key, defValue);
            if (/key|flag|secret|pass|stage|token|iv/i.test(key)) {
                console.log("[DATA] SharedPreferences.getString: " + key + " = " + value);
            }
            return value;
        };
        console.log('[*] SharedPreferences hooks installed');
    } catch(e) {
        console.log('[-] SharedPreferences hook failed: ' + e);
    }

    // ========== 5. Hook Base64 ==========
    try {
        var Base64 = Java.use("android.util.Base64");

        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            console.log("[Base64] decode input: " + str);
            var result = this.decode(str, flags);
            console.log("[Base64] decode output: " + bytesToHex(result));
            return result;
        };

        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            console.log("[Base64] encode input: " + bytesToHex(input));
            var result = this.encodeToString(input, flags);
            console.log("[Base64] encode output: " + result);
            return result;
        };

        console.log('[*] Base64 hooks installed');
    } catch(e) {
        console.log('[-] Base64 hook failed: ' + e);
    }

    // ========== 6. Hook Native函数 ==========
    try {
        // 尝试Hook常见的native库
        var nativeModules = Process.enumerateModules();
        for (var i = 0; i < nativeModules.length; i++) {
            var mod = nativeModules[i];
            if (mod.name.indexOf('native') !== -1 || mod.name.indexOf('lib') !== -1) {
                console.log("[Native] Found module: " + mod.name + " @ " + mod.base);
            }
        }
    } catch(e) {
        console.log('[-] Native enumeration failed: ' + e);
    }

    // 辅助函数：字节数组转十六进制
    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }

    console.log('[*] All hooks installed successfully');
});
`;

  await showScript(script, 'frida');

  addLog('success', 'Frida Hook脚本已生成（基于ctf-agent模板）');
  addSystemMessage('已生成 Frida Hook 脚本，包含以下Hook点：\n1. Cipher - 加密函数\n2. String - 字符串比较\n3. MessageDigest - 哈希函数\n4. SharedPreferences - 配置读取\n5. Base64 - 编解码\n6. Native - 原生函数');
}

// 生成解密脚本 - 基于ctf-agent模板
async function generateDecryptScript() {
  const script = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF 解密脚本
Target: ${state.fileInfo ? state.fileInfo.fileName : 'Unknown'}
Generated: ${new Date().toISOString()}
Based on: ctf-agent Python解密脚本模板
"""

import base64
import hashlib
from Crypto.Cipher import AES, DES
import struct

# ========== XOR 解密 ==========
def xor_decrypt(data, key):
    """XOR解密"""
    key_bytes = key.encode() if isinstance(key, str) else key
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

# ========== TEA 解密 ==========
def tea_decrypt(v0, v1, key, rounds=32):
    """
    TEA解密
    特征: 0x9E3779B9 (delta常量)
    """
    delta = 0x9E3779B9
    sum_val = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    return v0, v1

def xxtea_decrypt(data, key, variant='le32'):
    """XXTEA解密（正确的 btea 算法：MX 轮函数，轮数=6+52//n）"""
    fmt = '>' if variant == 'be32' else '<'
    n = len(data) // 4
    if n < 2:
        return data
    M = 0xFFFFFFFF
    delta = 0x9E3779B9
    v = list(struct.unpack(fmt + '%dI' % n, data[:n * 4]))
    k = list(struct.unpack(fmt + '4I', key[:16]))

    def mx(z, y, s, e, p):
        return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))

    s = ((6 + 52 // n) * delta) & M
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[(p + 1) % n]
            v[p] = (v[p] - mx(z, y, s, e, p)) & M
        z = v[n - 1]
        y = v[1]
        v[0] = (v[0] - mx(z, y, s, e, 0)) & M
        s = (s - delta) & M
    return struct.pack(fmt + '%dI' % n, *v)

# ========== AES 解密 ==========
def aes_ecb_decrypt(encrypted, key):
    """AES ECB解密"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(encrypted)

def aes_cbc_decrypt(encrypted, key, iv=None):
    """AES CBC解密"""
    if iv is None:
        iv = key[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted)

# ========== DES 解密 ==========
def des_ecb_decrypt(encrypted, key):
    """DES ECB解密"""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(encrypted)

def des_cbc_decrypt(encrypted, key, iv=None):
    """DES CBC解密"""
    if iv is None:
        iv = key[:8]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(encrypted)

# ========== Base64 解码 ==========
def base64_decode(data):
    """Base64解码"""
    return base64.b64decode(data)

# ========== RC4 解密 ==========
def rc4_decrypt(data, key):
    """RC4解密"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)

# ========== CRC32 碰撞 ==========
def crc32_bruteforce(target_crc, length, charset='abcdefghijklmnopqrstuvwxyz0123456789'):
    """CRC32暴力碰撞"""
    import itertools
    import binascii

    for combo in itertools.product(charset, repeat=length):
        s = ''.join(combo).encode()
        if binascii.crc32(s) & 0xFFFFFFFF == target_crc:
            return s
    return None

# ========== SM4 解密（国密，特征S盒 0xD6,0x90,0xE9...） ==========
def sm4_decrypt(encrypted, key, mode='ECB', iv=None):
    """SM4解密：pip install gmssl；key/iv 均为16字节"""
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    c = CryptSM4()
    c.set_key(key, SM4_DECRYPT)
    return c.crypt_ecb(encrypted) if mode == 'ECB' else c.crypt_cbc(iv, encrypted)

# ========== 3DES 解密 ==========
def des3_ecb_decrypt(encrypted, key):
    """3DES ECB解密：key 16或24字节"""
    from Crypto.Cipher import DES3
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.decrypt(encrypted)

# ========== 自定义码表 Base64 ==========
def base64_custom_decode(data, table):
    """自定义码表 Base64：table 为64字符的自定义码表"""
    import string
    std = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
    trans = str.maketrans(table, std)
    return base64.b64decode(data.translate(trans))

# ========== RSA 常见套路 ==========
def rsa_solve(n, e, c):
    """
    RSA 常见攻击脚手架：pip install pycryptodome gmpy2
    1) e 很小(如3)且明文短 -> 直接开e次方
    2) factordb 分解 n -> 求 d
    3) Wiener (e很大) -> 连分数
    """
    import gmpy2
    from Crypto.Util.number import long_to_bytes, inverse

    # 1. 小指数直接开方
    root, exact = gmpy2.iroot(c, e)
    if exact:
        return long_to_bytes(int(root))

    # 2. factordb 分解 n（联网）后求 d
    try:
        from factordb.factordb import FactorDB
        f = FactorDB(n)
        f.connect()
        factors = f.get_factor_list()
        if len(factors) >= 2:
            phi = 1
            for p in set(factors):
                phi *= (p - 1)
            d = inverse(e, phi)
            return long_to_bytes(pow(c, d, n))
    except Exception:
        pass

    # 3. Wiener 攻击（连分数展开，e 很大时尝试）
    def wiener(e, n):
        # 计算 e/n 的连分数收敛因子，验证 d
        cf = []
        k, d_ = e, n
        while d_:
            cf.append(k // d_)
            k, d_ = d_, k % d_
        for i in range(2, len(cf) + 1):
            kk, dd = 1, cf[i - 2]
            for j in range(i - 3, -1, -1):
                kk, dd = cf[j] * kk + dd, kk
            if (e * dd - 1) % kk == 0:
                phi = (e * dd - 1) // kk
                m = pow(c, dd, n)
                if long_to_bytes(m).startswith(b'flag'):
                    return long_to_bytes(m)
        return None

    r = wiener(e, n)
    if r:
        return r
    return None

def rsa_common_modulus(n, e1, e2, c1, c2):
    """RSA 共模攻击：同一明文用同一 n 不同 e 加密"""
    import gmpy2
    from Crypto.Util.number import long_to_bytes
    g, s1, s2 = gmpy2.gcdext(e1, e2)
    s1, s2 = int(s1), int(s2)
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

# ========== Z3 约束求解脚手架 ==========
def z3_solve():
    """
    Z3 约束求解：pip install z3-solver
    用于：逐字节校验、方程组、自定义轮函数还原
    """
    from z3 import BitVec, Solver, sat

    # 示例：8个32位变量满足约束（把约束换成逆向出的实际逻辑）
    x = [BitVec(f'x{i}', 32) for i in range(8)]
    s = Solver()
    # 示例约束（替换为实际约束）:
    # s.add(x[0] + x[1] == 0x1234)
    # s.add(x[0] ^ 0x5678 == 0xABCD)
    if s.check() == sat:
        m = s.model()
        return [m[xi].as_long() for xi in x]
    return None

# ========== angr 符号执行脚手架 ==========
def angr_solve(binary_path):
    """
    angr 符号执行直达成功分支：pip install angr
    适用于：输入被复杂变换后与密文比较的题
    """
    import angr, claripy

    proj = angr.Project(binary_path, auto_load_libs=False)
    flag = claripy.BVS('flag', 8 * 32)  # 32字节输入

    state = proj.factory.entry_state(stdin=flag)
    sm = proj.factory.simgr(state)
    # 成功/失败分支的输出特征（按题目实际字符串修改）
    sm.explore(find=lambda s: b'correct' in s.posix.dumps(1),
               avoid=lambda s: b'wrong' in s.posix.dumps(1))
    if sm.found:
        return sm.found[0].posix.dumps(0)
    return None

# ========== 自定义算法模板 ==========
def custom_decrypt(data, key):
    """
    TODO: 根据逆向分析结果实现自定义解密逻辑
    常见模式:
    1. 逐字节XOR
    2. 移位变换
    3. S盒替换
    4. 自定义轮函数
    """
    pass

# ========== 主函数 ==========
def main():
    # TODO: 根据逆向分析结果填入以下参数

    # 加密数据（从二进制中提取）
    encrypted_data = b""

    # 密钥（从代码中提取）
    key = b""

    # 解密方式（根据分析选择其中一种）

    # 1. XOR解密
    # result = xor_decrypt(encrypted_data, key)

    # 2. TEA解密
    # v0, v1 = struct.unpack('<II', encrypted_data[:8])
    # v0, v1 = tea_decrypt(v0, v1, struct.unpack('<4I', key))
    # result = struct.pack('<II', v0, v1)

    # 3. AES解密
    # result = aes_ecb_decrypt(encrypted_data, key)
    # result = aes_cbc_decrypt(encrypted_data, key)

    # 4. DES解密
    # result = des_ecb_decrypt(encrypted_data, key)

    # 5. RC4解密
    # result = rc4_decrypt(encrypted_data, key)

    # 6. Base64解码
    # result = base64_decode(encrypted_data)

    # 7. SM4解密（pip install gmssl）
    # result = sm4_decrypt(encrypted_data, key)

    # 8. 3DES解密
    # result = des3_ecb_decrypt(encrypted_data, key)

    # 9. RSA（n, e, c 从逆向中提取）
    # n, e, c = 0x..., 65537, 0x...
    # result = rsa_solve(n, e, c)

    # 输出结果
    # print(f"Decrypted: {result}")
    # print(f"FLAG{{{result.decode('utf-8', errors='ignore')}}}")

    print("请根据逆向分析结果修改脚本参数")
    print("\\n算法识别特征:")
    print("  - 0x9E3779B9 -> TEA系列")
    print("  - S盒 0x63,0x7C,0x77... -> AES")
    print("  - S盒 0xD6,0x90,0xE9... -> SM4")
    print("  - 0x67452301,0xEFCDAB89... -> MD5")
    print("  - 固定多项式 0xEDB88320 -> CRC32")
    print("  - 256字节S盒初始化 -> RC4")

if __name__ == "__main__":
    main()
`;

  await showScript(script, 'decrypt');

  addLog('success', 'Python解密脚本已生成（基于ctf-agent模板）');
  addSystemMessage('已生成 Python 解密脚本，包含以下算法：\n1. XOR\n2. TEA/XXTEA\n3. AES (ECB/CBC)\n4. DES/3DES (ECB/CBC)\n5. RC4\n6. Base64（含自定义码表）\n7. CRC32碰撞\n8. SM4（国密）\n9. RSA（小指数/factordb/Wiener/共模）\n10. Z3 约束求解脚手架\n11. angr 符号执行脚手架\n12. 自定义算法模板');
}

// 生成反调试绕过脚本 - 基于ctf-agent模板
async function generateAntiDebugScript() {
  const script = `// Anti-Debug Bypass Script
// Generated: ${new Date().toISOString()}
// Based on: ctf-agent反调试绕过模板

'use strict';

// ---- Frida 17+ 兼容：v17 移除了 Module 静态查找 API，缺失时用新 API 重建 ----
if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (modName, expName) {
        if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(expName) : null; }
        return Module.getGlobalExportByName ? Module.getGlobalExportByName(expName) : null;
    };
}
if (typeof Module.getExportByName !== 'function') {
    Module.getExportByName = function (modName, expName) {
        var r = Module.findExportByName(typeof expName === 'undefined' ? null : modName, typeof expName === 'undefined' ? modName : expName);
        if (!r) throw new Error('export not found');
        return r;
    };
}

Java.perform(function() {
    console.log('[*] Anti-Debug Bypass Script Loaded');

    // ========== 1. 绕过 ptrace 检测 ==========
    try {
        var ptrace = Module.findExportByName("libc.so", "ptrace");
        if (ptrace) {
            Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
                console.log("[AntiDebug] ptrace bypassed, request=" + request);
                return 0;
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            console.log('[*] ptrace bypass installed');
        }
    } catch(e) {
        console.log('[-] ptrace bypass failed: ' + e);
    }

    // ========== 2. 绕过 Debuggable 检测 ==========
    try {
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        // 只清 FLAG_DEBUGGABLE (0x2)，保留其他标志位（清零全部会破坏应用行为）
        ApplicationInfo.flags.value = (ApplicationInfo.flags.value & ~2);
        console.log('[*] FLAG_DEBUGGABLE cleared, flags=' + ApplicationInfo.flags.value);
    } catch(e) {
        console.log('[-] Debuggable bypass failed: ' + e);
    }

    // ========== 3. 绕过 Frida 检测 ==========
    try {
        // 绕过文件检测
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var name = this.getName();
            if (name.indexOf("frida") !== -1 || name.indexOf("gadget") !== -1) {
                console.log("[AntiDebug] Frida file check bypassed: " + name);
                return false;
            }
            return this.exists();
        };

        // 绕过端口检测
        var BufferedReader = Java.use("java.io.BufferedReader");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        var FileInputStream = Java.use("java.io.FileInputStream");

        // Hook /proc/net/tcp 读取
        BufferedReader.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && (line.indexOf("1337") !== -1 || line.indexOf("27042") !== -1)) {
                console.log("[AntiDebug] Frida port check bypassed");
                return null;
            }
            return line;
        };

        console.log('[*] Frida detection bypass installed');
    } catch(e) {
        console.log('[-] Frida bypass failed: ' + e);
    }

    // ========== 4. 绕过 TracerPid 检测 ==========
    try {
        var BufferedReader2 = Java.use("java.io.BufferedReader");
        BufferedReader2.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && line.indexOf("TracerPid") !== -1) {
                console.log("[AntiDebug] TracerPid check bypassed");
                return "TracerPid:\\t0";
            }
            return line;
        };
        console.log('[*] TracerPid bypass installed');
    } catch(e) {
        console.log('[-] TracerPid bypass failed: ' + e);
    }

    // ========== 5. 绕过 System.exit 检测 ==========
    try {
        var System = Java.use("java.lang.System");
        System.exit.implementation = function(code) {
            console.log("[AntiDebug] System.exit(" + code + ") blocked");
            // 不执行退出
        };
        console.log('[*] System.exit bypass installed');
    } catch(e) {
        console.log('[-] System.exit bypass failed: ' + e);
    }

    // ========== 6. 绕过 Process.killProcess 检测 ==========
    try {
        var Process = Java.use("android.os.Process");
        Process.killProcess.implementation = function(pid) {
            console.log("[AntiDebug] Process.killProcess(" + pid + ") blocked");
            // 不执行杀死进程
        };
        console.log('[*] Process.killProcess bypass installed');
    } catch(e) {
        console.log('[-] Process.killProcess bypass failed: ' + e);
    }

    // ========== 7. 绕过 Debugger 检测 ==========
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[AntiDebug] isDebuggerConnected -> false");
            return false;
        };
        console.log('[*] Debug.isDebuggerConnected bypass installed');
    } catch(e) {
        console.log('[-] Debug.isDebuggerConnected bypass failed: ' + e);
    }

    // ========== 8. 绕过 Native 反调试 ==========
    try {
        // Hook strstr 用于检测frida相关字符串
        var strstr = Module.findExportByName("libc.so", "strstr");
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function(args) {
                    this.str1 = args[0].readCString();
                    this.str2 = args[1].readCString();
                },
                onLeave: function(retval) {
                    if (this.str2 && (this.str2.indexOf("frida") !== -1 || this.str2.indexOf("gadget") !== -1)) {
                        console.log("[AntiDebug] strstr bypass: " + this.str2);
                        retval.replace(ptr(0));
                    }
                }
            });
            console.log('[*] strstr bypass installed');
        }
    } catch(e) {
        console.log('[-] strstr bypass failed: ' + e);
    }

    console.log('[*] Anti-Debug Bypass Complete');
    console.log('[*] All hooks installed successfully');
});
`;

  await showScript(script, 'bypass');

  addLog('success', '反调试绕过脚本已生成（基于ctf-agent模板）');
  addSystemMessage('已生成反调试绕过脚本，包含以下绕过点：\n1. ptrace检测\n2. Debuggable标志\n3. Frida文件/端口检测\n4. TracerPid检测\n5. System.exit\n6. Process.killProcess\n7. Debug.isDebuggerConnected\n8. Native strstr检测');
}





// 部署Frida
async function deployFrida() {
  addLog('info', '=== 部署Frida到模拟器 ===');

  try {
    // 先检查模拟器连接
    addLog('info', '步骤1: 检查模拟器连接...');
    const deviceCheck = await window.electronAPI.adbCommand('devices');
    if (!deviceCheck.success || !deviceCheck.stdout.includes('device')) {
      addLog('error', '模拟器未连接，请先启动安卓9模拟器');
      return;
    }

    // 检查frida-server
    addLog('info', '步骤2: 检查frida-server...');
    const checkResult = await window.electronAPI.adbCommand('shell "ls -la /data/local/tmp/frida-server"');
    if (!checkResult.success) {
      addLog('warning', 'frida-server未找到，请先将frida-server推送到模拟器');
      addLog('info', '命令: adb push frida-server /data/local/tmp/');
      return;
    }

    // 启动frida-server
    addLog('info', '步骤3: 启动frida-server...');
    const startResult = await window.electronAPI.adbCommand('shell "su -c \'nohup /data/local/tmp/frida-server -D &\'"');
    if (startResult.success) {
      addLog('success', 'Frida-server已启动！');
      addLog('info', 'Frida端口: 27042');
    } else {
      addLog('error', 'Frida启动失败: ' + (startResult.error || startResult.stderr));
    }
  } catch (err) {
    addLog('error', '部署失败: ' + err.message);
  }
}

// 运行Hook
async function runHook() {
  addLog('info', '=== 运行Frida Hook ===');

  if (!state.currentFile) {
    addLog('warning', '请先选择文件');
    return;
  }

  // 检查是否有生成的脚本
  const scriptContent = state.currentScript ? state.currentScript.content : '';
  if (!scriptContent) {
    addLog('warning', '请先生成Hook脚本（快捷命令"生成Hook脚本"）');
    return;
  }

  // 若已有已求解的加密参数（[VERIFY]/[HYPOTHESES] 契约），前置注入"进程内解密"段：
  // 让手动 Hook 也能直接在 App 进程内解出 flag，而不是只被动抓取噪音。
  // 注意：内置兜底脚本（buildFallbackFridaScript）本身已含该段，需按标记去重，避免重复解密/重复 [FLAG]。
  let scriptToRun = scriptContent;
  const cryptoParams = pickCryptoParams();
  if (cryptoParams && cryptoParams.key && cryptoParams.ciphertext && !/__CTF_KNOWN/.test(scriptContent)) {
    scriptToRun = fridaSolvePreamble(cryptoParams) + '\n' + scriptContent;
    addLog('info', '已向 Hook 注入进程内解密段（key/iv/密文来自已验证契约），将尝试直接解出 flag');
  }

  // 目标进程名解析：frida -n 匹配的是"进程名"（如 Hook My Secret），不是包名（com.x.y）。
  // Android 进程名常等于 App 名而非包名，直接用包名会 Failed to spawn。
  // 策略：拿 frida-ps 列表，按"包名精确/包含/末段关键词"匹配出真实进程名；
  // 匹配不到再退回前台应用(-F 由主进程处理)或人工输入。
  let target = null;
  const pkg = state.fileType === 'APK' ? await getPackageNameFromAPK() : null;
  try {
    const ps = await window.electronAPI.fridaPs();
    if (ps && ps.success && ps.stdout) {
      const rows = String(ps.stdout).split(/\r?\n/)
        .map(l => { const m = l.match(/^\s*(\d+)\s+(.+?)\s*$/); return m ? { pid: Number(m[1]), name: m[2] } : null; })
        .filter(Boolean);
      const q = String(pkg || '').toLowerCase();
      const seg = q.split('.').pop();
      // 归一化去空格：包名末段（如 "myapp"）对应进程名（如 "My App"）
      const norm = (s) => String(s || '').toLowerCase().replace(/\s+/g, '');
      let hit = null;
      if (q) {
        const nq = norm(q), ns = norm(seg);
        hit = rows.find(r => norm(r.name) === nq)
          || rows.find(r => norm(r.name).includes(nq) || nq.includes(norm(r.name)))
          || (ns.length >= 4 ? rows.find(r => norm(r.name).includes(ns) || ns.includes(norm(r.name))) : null);
      }
      if (hit) {
        target = hit.name;
        addLog('info', `已解析目标：包名 ${pkg || '(无)'} → 进程名 "${hit.name}" (pid ${hit.pid})`);
      } else if (rows.length) {
        addLog('info', `未在运行进程中找到与 ${pkg || '当前文件'} 匹配的进程；可先在模拟器启动 App，或手动输入进程名`);
      }
    }
  } catch (e) { /* 忽略，走人工输入 */ }

  if (!target) {
    target = await appPrompt('输入Hook目标',
      '请输入要附加的进程名（是进程名如 "Hook My Secret"，不是包名 com.x.y；可先点击"Frida进程"查看；留空表示附加当前前台应用）：',
      pkg || '');
  }
  if (!target) {
    // 留空 = 附加前台应用（主进程用 -F 处理），不再视为取消
    addLog('info', '未指定目标，将附加当前前台应用');
    target = null;
  }

  addLog('info', `目标应用: ${target || '(当前前台应用)'}`);
  addLog('info', '正在执行Frida Hook（滚动窗口：每来数据续 60s，连续 60s 无数据才结束）...');
  // 手动 Hook 用滚动窗口：你在模拟器里操作 App 时，只要 Hook 有数据产出就持续续期，
  // 不会因为你操作慢而被硬停；连续 60s 无数据才收尾（绝对上限 10 分钟防挂死）。
  const result = await window.electronAPI.runFridaHook(scriptToRun, target, { windowMs: 60000, hardCapMs: 600000 });
  if (result && result.success) {
    const output = result.output || '无输出';
    // 直接从输出收割脚本打印的 [FLAG]（进程内解密成功的最硬证据）
    const directFlags = (output.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/gi) || [])
      .map(s => (s.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/i) || [])[1])
      .filter(v => v && looksLikeFlag(v));
    const uniqDirect = [...new Set(directFlags)];
    uniqDirect.forEach(f => { recordFlag(f, 'frida-flag', true); addSolveNote('Flag(动态-进程内解密)', f); });
    if (uniqDirect.length) {
      addLog('success', `Hook 直接命中 flag：${uniqDirect.join(', ')}`);
      addSystemMessage(`**🎯 Hook 直接命中 Flag**\n\n${uniqDirect.map(f => `\`${f}\``).join('\n\n')}`);
    }
    // 未 attach 成功时如实报告，不再一律打"完成"（frida 的错误也写在 output 里）
    if (/Failed to spawn|unable to find process|unable to attach|not found/i.test(output)) {
      addLog('error', 'Frida Hook 未成功附加目标（详见下方输出）');
      // 常见原因提示
      if (/Failed to spawn|unable to find process/i.test(output)) {
        addLog('warning', '提示：目标进程名可能是 App 名而非包名，请先在模拟器启动 App，再点"Frida进程"确认进程名后重试');
      }
    } else if (!directFlags.length) {
      addLog('success', 'Frida Hook执行完成');
    }
    const fridaOutput = document.getElementById('category-frida');
    if (fridaOutput) fridaOutput.textContent = output;
  } else {
    addLog('error', 'Frida Hook失败: ' + ((result && result.error) || '未知错误'));
  }
}


// 生成脚本
async function generateScript() {
  if (!state.currentFile) {
    addLog('warning', '请先选择文件');
    return;
  }

  switch (state.fileType) {
    case 'APK':
    case 'ELF':
      await generateFridaScript();
      break;
    case 'PE':
    case 'DEX':
    case 'PYC':
      await generateDecryptScript();
      break;
    default:
      await generateFridaScript();
  }
}

// 添加日志（textContent 写入，防 HTML 注入；同时落盘到 CASE timeline）
function addLog(type, message) {
  const logOutput = document.getElementById('category-log');
  if (!logOutput) return;

  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });

  const logLine = document.createElement('div');
  logLine.className = `log-line log-${type}`;
  logLine.innerHTML = `<span class="log-time">[${time}]</span><span class="log-text"></span>`;
  logLine.querySelector('.log-text').textContent = String(message);

  logOutput.appendChild(logLine);
  logOutput.scrollTop = logOutput.scrollHeight;

  // 时间线持久化（尽力而为，失败静默）
  if (state.caseDir && window.electronAPI.appendFile) {
    const line = JSON.stringify({ ts: new Date().toISOString(), type, message: String(message).slice(0, 500) });
    window.electronAPI.appendFile(`${state.caseDir}/timeline.jsonl`, line).catch(() => {});
  }
}

// 清空日志
function clearLog() {
  const logOutput = document.getElementById('category-log');
  if (logOutput) {
    logOutput.innerHTML = '';
    addLog('info', '日志已清空');
  }
}

// 添加用户消息
function addUserMessage(message) {
  const chatMessages = document.getElementById('chat-messages');

  const messageDiv = document.createElement('div');
  messageDiv.className = 'message message-user';
  messageDiv.innerHTML = `
    <div class="message-avatar">
      <i class="fas fa-user"></i>
    </div>
    <div class="message-content">
      <div class="message-text">${escapeHtml(message)}</div>
    </div>
  `;

  chatMessages.appendChild(messageDiv);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 添加系统消息
function addSystemMessage(message) {
  const chatMessages = document.getElementById('chat-messages');

  const messageDiv = document.createElement('div');
  messageDiv.className = 'message message-system';
  messageDiv.innerHTML = `
    <div class="message-avatar">
      <i class="fas fa-robot"></i>
    </div>
    <div class="message-content">
      <div class="message-text">${formatMessage(message)}</div>
    </div>
  `;

  chatMessages.appendChild(messageDiv);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 格式化消息（支持简单Markdown；先做 HTML 转义再替换标记，防止 AI/工具输出注入）
function formatMessage(message) {
  return escapeHtml(String(message))
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]*?)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>');
}

// HTML转义
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// 打开设置
function openSettings() {
  document.getElementById('settings-modal').style.display = 'flex';

  // 填充当前配置
  if (state.config) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v == null ? '' : v; };
    set('setting-ida', state.config.tools.ida);
    set('setting-die', state.config.tools.die);
    set('setting-jeb', state.config.tools.jeb);
    set('setting-jadx', state.config.tools.jadx);
    set('setting-pycdc', state.config.tools.pycdc);
    set('setting-upx', state.config.tools.upx);
    set('setting-apktool', state.config.tools.apktool);
    set('setting-adb', state.config.tools.nox_adb);
    set('setting-adb-port', state.config.emulator && state.config.emulator.adb_port);
    set('setting-frida-port', state.config.emulator && state.config.emulator.frida_port);

    const claude = state.config.claude || {};
    set('setting-ai-baseurl', claude.baseUrl);
    set('setting-ai-key', claude.apiKey);
    set('setting-ai-model', claude.model);
    set('setting-ai-fastmodel', claude.fastModel || '');
    set('setting-ai-maxtokens', claude.max_tokens || 8192);

    const mcp = state.config.mcp || {};
    set('setting-mcp-ida', mcp.ida);
    set('setting-mcp-jeb', mcp.jebMcp);
    set('setting-mcp-jeb-script', mcp.jebMcpScript);
    set('setting-mcp-burp', mcp.burp);
    set('setting-burp', state.config.tools.burp);

    const kali = state.config.kali || {};
    set('setting-kali-vmx', kali.vmxPath);
    set('setting-kali-host', kali.sshHost);
    set('setting-kali-port', kali.sshPort);
    set('setting-kali-user', kali.sshUser);
    set('setting-kali-pass', kali.sshPass);

    set('setting-scripts-dir', (state.config.workspace && state.config.workspace.scriptsDir) || '');
  }
}

// 生成Native Hook脚本
async function generateNativeHookScript() {
  if (!state.currentFile) {
    addLog('warning', '请先选择文件');
    return;
  }

  const script = `// Native/SO Frida Hook Script
// Target: ${state.fileInfo.fileName}
// Generated: ${new Date().toISOString()}
// 用于Hook Native层函数

'use strict';

// ---- Frida 17+ 兼容：v17 移除了 Module 静态查找 API，缺失时用新 API 重建 ----
if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (modName, expName) {
        if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(expName) : null; }
        return Module.getGlobalExportByName ? Module.getGlobalExportByName(expName) : null;
    };
}
if (typeof Module.getExportByName !== 'function') {
    Module.getExportByName = function (modName, expName) {
        var r = Module.findExportByName(typeof expName === 'undefined' ? null : modName, typeof expName === 'undefined' ? modName : expName);
        if (!r) throw new Error('export not found');
        return r;
    };
}
if (typeof Module.findBaseAddress !== 'function') {
    Module.findBaseAddress = function (name) { var m = Process.findModuleByName(name); return m ? m.base : null; };
}

// ========== 1. Hook libc.so 常见函数 ==========
Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
    onEnter: function(args) {
        this.str1 = args[0].readCString();
        this.str2 = args[1].readCString();
    },
    onLeave: function(retval) {
        if (this.str1 && this.str2 && this.str1.length > 0 && this.str2.length > 0) {
            console.log("[strcmp] '" + this.str1 + "' == '" + this.str2 + "' -> " + retval);
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function(args) {
        this.haystack = args[0].readCString();
        this.needle = args[1].readCString();
    },
    onLeave: function(retval) {
        if (this.needle && this.needle.length > 0) {
            console.log("[strstr] haystack='" + this.haystack + "', needle='" + this.needle + "'");
        }
    }
});

// ========== 2. Hook JNI函数 ==========
Java.perform(function() {
    // 枚举已加载的SO模块
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].name.indexOf("libnative") !== -1 ||
            modules[i].name.indexOf("libencrypt") !== -1 ||
            modules[i].name.indexOf("libcrack") !== -1) {
            console.log("[Native] Found target module: " + modules[i].name + " @ " + modules[i].base);

            // 枚举导出函数
            var exports = modules[i].enumerateExports();
            for (var j = 0; j < exports.length; j++) {
                if (exports[j].type === 'function') {
                    console.log("[Native] Export: " + exports[j].name + " @ " + exports[j].address);
                }
            }
        }
    }
});

// ========== 3. Hook malloc/free (内存操作) ==========
var mallocAddr = Module.findExportByName("libc.so", "malloc");
var freeAddr = Module.findExportByName("libc.so", "free");

if (mallocAddr) {
    Interceptor.attach(mallocAddr, {
        onEnter: function(args) {
            this.size = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.size > 16 && this.size < 1024) {
                console.log("[malloc] size=" + this.size + " -> " + retval);
            }
        }
    });
}

// ========== 4. Hook open/read (文件操作) ==========
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = args[0].readCString();
    },
    onLeave: function(retval) {
        if (this.path && (this.path.indexOf("flag") !== -1 || this.path.indexOf("secret") !== -1)) {
            console.log("[open] " + this.path + " -> fd=" + retval);
        }
    }
});

// ========== 5. 自定义SO函数Hook模板 ==========
/*
// 如果知道SO中的函数名，可以直接Hook：
var targetFunc = Module.findExportByName("libnative.so", "Java_com_example_app_NativeClass_encrypt");
if (targetFunc) {
    Interceptor.attach(targetFunc, {
        onEnter: function(args) {
            console.log("[encrypt] called");
            // args[0] = JNIEnv*
            // args[1] = jobject
            // args[2+] = 用户参数
            console.log("[encrypt] arg0=" + args[2].readCString());
        },
        onLeave: function(retval) {
            console.log("[encrypt] result=" + retval.readCString());
        }
    });
}
*/

console.log('[*] Native Hook Script Loaded');
console.log('[*] Monitoring: strcmp, strstr, malloc, open');
console.log('[*] Enumerating loaded SO modules...');
`;

  await showScript(script, 'frida');

  addLog('success', 'Native Hook脚本已生成');
}

// ========== Claude API 集成 ==========

// 模型分级 cascade（初步求解专用）：先用快速模型（省 token、提速），
// 未出现 flag 信号再自动升级思考模型；快速模型失败同样回退思考模型。
// config.claude.fastModel 留空或与主模型相同 = 禁用分级。
async function claudeChatCascade(messages, systemPrompt) {
  const claudeCfg = (state.config && state.config.claude) || {};
  const fastModel = String(claudeCfg.fastModel || '').trim();
  const mainModel = String(claudeCfg.model || '').trim();
  if (!fastModel || (mainModel && fastModel === mainModel)) {
    return await window.electronAPI.claudeChat(messages, systemPrompt);
  }
  const hasFlagSignal = (text) => {
    if (!text) return false;
    if (/\[FLAG\][^\[\]]+\[\/FLAG\]/.test(text)) return true;
    try { return extractFlags(text).length > 0; } catch (e) { return false; }
  };
  addLog('info', `模型分级：先用快速模型 ${fastModel} 初步求解...`);
  const fastResult = await window.electronAPI.claudeChat(messages, systemPrompt, {
    model: fastModel,
    maxTokens: Number(claudeCfg.fastMaxTokens) || 8192
  });
  if (fastResult.success && hasFlagSignal(fastResult.text)) {
    addLog('success', `快速模型 ${fastModel} 直接命中 flag，无需升级思考模型`);
    fastResult.cascade = 'fast';
    fastResult.modelUsed = fastModel;
    return fastResult;
  }
  addLog('info', fastResult.success
    ? `快速模型未给出 flag，升级思考模型深度求解...`
    : `快速模型失败（${fastResult.error || '未知'}），回退思考模型...`);
  const deepResult = await window.electronAPI.claudeChat(messages, systemPrompt);
  deepResult.cascade = 'deep';
  return deepResult;
}

// ========== Frida 动态调试自动化 ==========
function sleepMs(ms) { return new Promise(r => setTimeout(r, Number(ms) || 0)); }

// 解析一次 uiautomator 层级，返回控件数组
async function dumpUiNodes() {
  try {
    await window.electronAPI.adbCommand('shell uiautomator dump /sdcard/ctf_ui.xml');
    const cat = await window.electronAPI.adbCommand('shell cat /sdcard/ctf_ui.xml');
    const xml = (cat && (cat.stdout || cat)) || '';
    const text = typeof xml === 'string' ? xml : String(xml);
    const nodes = [];
    const re = /<node\b[^>]*>/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const tag = m[0];
      const g = (k) => { const mm = tag.match(new RegExp(k + '="([^"]*)"')); return mm ? mm[1] : ''; };
      const b = g('bounds').match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
      if (!b) continue;
      nodes.push({
        cls: g('class'), text: g('text'), rid: g('resource-id'),
        clickable: g('clickable') === 'true',
        cx: Math.round((+b[1] + +b[3]) / 2), cy: Math.round((+b[2] + +b[4]) / 2),
        x1: +b[1], y1: +b[2], x2: +b[3], y2: +b[4]
      });
    }
    return nodes;
  } catch (e) { return []; }
}

// 迭代式驱动界面：每轮 dump → 执行一个动作 → 再 dump（真正"逐屏推进"）。
// 单次 dump 只能看到首页（那时还没手势盘/输入框），必须边操作边重新识别。
// 与 Hook 并行运行，让界面触发的校验代码真正执行。
async function driveAppIteratively(packageName, totalMs = 18000) {
  const deadline = Date.now() + totalMs;
  const seen = new Set();
  const log = [];
  const keyOf = (n) => `${n.cls}|${n.rid}|${n.text}|${n.cx},${n.cy}`;
  let patternDone = false;
  let patternViewWarned = false;

  while (Date.now() < deadline) {
    let nodes = await dumpUiNodes();
    if (!nodes.length) { await sleepMs(800); continue; }

    // 手势盘：3x3，遍历候选手势（Hook 会指出哪个对）
    const patternView = nodes.find(n => (n.x2 - n.x1) > 400 && (n.y2 - n.y1) > 400 && /View/i.test(n.cls)
      && !/android\.widget/i.test(n.cls));
    if (patternView && !patternDone) {
      patternDone = true;
      const w = patternView.x2 - patternView.x1, h = patternView.y2 - patternView.y1;
      const step = Math.min(w, h) / 4;
      const padX = patternView.x1 + (w - 2 * step) / 2;
      const padY = patternView.y1 + (h - 2 * step) / 2;
      const node = (i) => [Math.round(padX + (i % 3) * step), Math.round(padY + Math.floor(i / 3) * step)];
      for (const c of [[0, 1, 2, 4, 8], [0, 3, 6, 7, 8], [0, 4, 8], [2, 4, 6], [0, 1, 3, 4, 6, 7]]) {
        if (Date.now() > deadline) break;
        const r = await window.electronAPI.driveAppUi([{ type: 'swipe', points: c.map(node), duration: 130 }]);
        log.push('swipe[' + c.join(',') + ']' + (r && r.success ? ' ok' : ' err'));
        await sleepMs(1100);
      }
      continue;
    }
    if (!patternView && !patternDone && !patternViewWarned && Date.now() > deadline - totalMs + 6000) {
      patternViewWarned = true; // 6 秒后仍无手势盘，不报错（可能本题无手势）
    }

    // 输入框：填入占位值（真实正确值靠 Hook 抓；这里只为触发校验分支）
    const edit = nodes.find(n => /EditText/i.test(n.cls) && !seen.has('edit:' + keyOf(n)));
    if (edit) {
      seen.add('edit:' + keyOf(edit));
      const r = await window.electronAPI.driveAppUi([
        { type: 'tap', x: edit.cx, y: edit.cy }, { type: 'sleep', ms: 300 },
        { type: 'text', value: 'A' }, { type: 'sleep', ms: 300 }
      ]);
      log.push('input' + (r && r.success ? ' ok' : ' err'));
      continue;
    }

    // 按钮：优先"开始/提交/确认"语义
    const btn = nodes.find(n => /Button/i.test(n.cls) && n.clickable && !seen.has(keyOf(n))
      && /start|开始|submit|提交|confirm|确认|check|verify|next|下一步|enter|登录|continue/i.test((n.text || '') + (n.rid || '')));
    if (btn) {
      seen.add(keyOf(btn));
      const r = await window.electronAPI.driveAppUi([{ type: 'tap', x: btn.cx, y: btn.cy }, { type: 'sleep', ms: 900 }]);
      log.push('tap(' + (btn.text || btn.rid || 'btn') + ')' + (r && r.success ? ' ok' : ' err'));
      continue;
    }

    // 兜底：点第一个未点过的可点按钮
    const anyBtn = nodes.find(n => /Button/i.test(n.cls) && n.clickable && !seen.has(keyOf(n)));
    if (anyBtn) {
      seen.add(keyOf(anyBtn));
      const r = await window.electronAPI.driveAppUi([{ type: 'tap', x: anyBtn.cx, y: anyBtn.cy }, { type: 'sleep', ms: 900 }]);
      log.push('tap(any)' + (r && r.success ? ' ok' : ' err'));
      continue;
    }

    // 本屏无可操作项：稍等再看（可能正在跳转）
    await sleepMs(1000);
  }
  return log;
}
// 校验（并尝试修复）AI 生成的 Frida 脚本。
// 高频错误：正则字面量里出现未转义的 '/'（如 /data/dalvik、res/x.xml），
// 会让 JS 解析器提前结束正则并报 "invalid regular expression flags"，整脚本不加载。
// 渲染层受 CSP(script-src 'self') 限制无法用 new Function，故交由主进程(validate-frida-script)校验。
async function validateAndRepairFridaScript(src) {
  try {
    return await window.electronAPI.validateFridaScript(src);
  } catch (e) {
    return { ok: true, script: String(src || ''), repaired: false, error: e.message };
  }
}

// 兜底 Hook 脚本：AI 脚本不可用时使用（语法保证正确）。
// 覆盖本类题的关键点：JNI 导出、自定义 JNI 方法、Cipher、MessageDigest、Base64、
// SharedPreferences、Arrays.equals、Cipher 相关 spec，且做严格降噪。
// 从最近的 [VERIFY]/[HYPOTHESES] 契约或 AI 文本里挑出可用的加密参数，供 Hook 主动解密。
// 优先带 iv 的 AES 类契约（本题为 aes_cbc），其次任何含 key+ciphertext 的契约。
function pickCryptoParams() {
  const score = (c) => {
    if (!c || !c.key || !c.ciphertext) return -1;
    const algo = String(c.algo || '').toLowerCase();
    let s = 1;
    if (algo.includes('aes')) s += 4;
    if (algo.includes('cbc')) s += 3;
    if (c.iv) s += 3;
    if (c.expected && /NCTF\{|flag\{|ctf\{/i.test(String(c.expected))) s += 2;
    return s;
  };
  const pools = [];
  if (Array.isArray(state.lastVerifyContracts)) pools.push(...state.lastVerifyContracts);
  try { pools.push(...parseVerifyContracts(String(state.lastAiText || ''))); } catch (e) {}
  try { pools.push(...parseHypotheses(String(state.lastAiText || ''))); } catch (e) {}
  let best = null, bestScore = 0;
  for (const c of pools) { const s = score(c); if (s > bestScore) { bestScore = s; best = c; } }
  return best;
}

// 把契约里的 key/iv 归一成"确定可用"的字节编码（默认 hex），避免 AI 把 IV 写成
// base64/明文而 Hook 端按 ASCII 解出错误长度（对应 Python 侧 iv_bytes 的自适应修复）。
function normalizeCrypto(c) {
  if (!c) return null;
  const out = { key: c.key, ciphertext: c.ciphertext, encoding: c.encoding || 'base64', algo: c.algo || 'aes_cbc' };
  const hexLike = (s) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
  const b64ToArr = (s) => { try { const bin = atob(s.replace(/\s+/g, '') + '='.repeat((-s.length) % 4)); const a = []; for (let i = 0; i < bin.length; i++) a.push(bin.charCodeAt(i)); return a; } catch (e) { return null; } };
  const asciiToArr = (s) => { const a = []; for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff); return a; };
  const hexToArr = (s) => { const a = []; for (let i = 0; i < s.length; i += 2) a.push(parseInt(s.substr(i, 2), 16)); return a; };
  const pick16 = (val, encHint) => {
    if (!val) return null;
    const s = String(val).trim();
    const cands = [];
    if (encHint === 'hex' || encHint === 'ascii' || encHint === 'base64') {
      if (encHint === 'hex') cands.push(hexToArr(s));
      else if (encHint === 'base64') cands.push(b64ToArr(s));
      else cands.push(asciiToArr(s));
    }
    if (hexLike(s)) cands.push(hexToArr(s));
    cands.push(b64ToArr(s));
    cands.push(asciiToArr(s));
    for (const a of cands) if (a && a.length === 16) return a;
    for (const a of cands) if (a && [8, 24, 32].includes(a.length)) return a;
    return cands[0] || null;
  };
  // key：优先显式编码；否则 ASCII（CTF 里 key 多为可打印字符串）
  const keyArr = c.key_encoding === 'hex' && hexLike(String(c.key)) ? hexToArr(String(c.key))
    : (c.key_encoding === 'base64' ? b64ToArr(String(c.key)) : asciiToArr(String(c.key)));
  if (keyArr) { out.key = keyArr.map(x => (x & 0xff).toString(16).padStart(2, '0')).join(''); out.key_encoding = 'hex'; }
  const ivArr = pick16(c.iv, c.iv_encoding);
  if (ivArr && ivArr.length === 16) { out.iv = ivArr.map(x => (x & 0xff).toString(16).padStart(2, '0')).join(''); out.iv_encoding = 'hex'; }
  return out;
}

// Hook 的"进程内解密"前置段：只要能拿到 key/iv/密文（静态已求或运行时捕获），
// 就让 Hook 在 App 进程内直接解密并打印 [FLAG]。这是"Hook 出 flag"的核心，
// 也让多阶段/离线题不依赖人工在模拟器里逐屏操作。
// 函数名统一带 __ctf 前缀，避免与 AI 生成脚本里的同名辅助函数冲突。
function fridaSolvePreamble(crypto) {
  crypto = normalizeCrypto(crypto);
  const c = (crypto && typeof crypto === 'object') ? crypto : {};
  const j = (v) => JSON.stringify(v == null ? '' : String(v));
  return `// ==== ctf-tool: in-process flag decryptor (auto-injected) ====
var __CTF_KNOWN = { key: ${j(c.key)}, keyEnc: ${j(c.key_encoding || 'ascii')}, iv: ${j(c.iv)}, ct: ${j(c.ciphertext)}, enc: ${j(c.encoding || 'base64')}, ivEnc: ${j(c.iv_encoding || '')}, algo: ${j(c.algo || 'aes_cbc')} };
var __CTF_DONE = false;
function __ctfToBytes(s, enc){
  try {
    if (s == null) return null;
    s = String(s);
    if (enc === 'hex') { var o=[]; for (var i=0;i<s.length;i+=2) o.push(parseInt(s.substr(i,2),16)); return o; }
    if (enc === 'base64') { var B=Java.use('android.util.Base64'); var b=B.decode(s,2); var a=[]; for (var k=0;k<b.length;k++) a.push(b[k]); return a; }
    var sb=Java.use('java.lang.String').$new(s).getBytes('UTF-8'); var a2=[]; for (var m=0;m<sb.length;m++) a2.push(sb[m]); return a2;
  } catch(e){ return null; }
}
function __ctfDecrypt(tag){
  if (__CTF_DONE) return;
  if (!__CTF_KNOWN.key || !__CTF_KNOWN.ct) return;
  try {
    var keyB = __ctfToBytes(__CTF_KNOWN.key, __CTF_KNOWN.keyEnc || 'ascii');
    var ctB  = __ctfToBytes(__CTF_KNOWN.ct, __CTF_KNOWN.enc || 'base64');
    if (!keyB || !ctB) return;
    var algo = String(__CTF_KNOWN.algo || 'aes_cbc').toLowerCase();
    var mode = algo.indexOf('ecb') >= 0 ? 'AES/ECB/PKCS5Padding' : 'AES/CBC/PKCS5Padding';
    var C = Java.use('javax.crypto.Cipher').getInstance(mode);
    var kSpec = Java.use('javax.crypto.spec.SecretKeySpec').$new(Java.array('byte', keyB), 'AES');
    var ivB = __ctfToBytes(__CTF_KNOWN.iv, __CTF_KNOWN.ivEnc || '');
    if (mode.indexOf('CBC') >= 0) {
      if (ivB && ivB.length === 16) C.init(2, kSpec, Java.use('javax.crypto.spec.IvParameterSpec').$new(Java.array('byte', ivB)));
      else { send('[!] cbc 需要 16 字节 IV，实际 ' + (ivB ? ivB.length : 0)); return; }
    } else { C.init(2, kSpec); }
    var s = String(Java.use('java.lang.String').$new(C.doFinal(Java.array('byte', ctB))));
    send('[DATA] (' + tag + ') DECRYPTED = ' + s);
    if (/NCTF\\{|flag\\{|ctf\\{/i.test(s)) { __CTF_DONE = true; send('[FLAG]' + s + '[/FLAG]'); }
  } catch(e) { send('[!] decrypt(' + tag + '): ' + e); }
}
if (typeof Java !== 'undefined' && Java.available) {
  Java.perform(function () {
    __ctfDecrypt('bootstrap');
    // 周期性重试：脚本可能稍后才拿到运行时参数（Hook 捕获）或注入的已知参数
    if (!__CTF_DONE) setInterval(function () { try { __ctfDecrypt('tick'); } catch(e){} }, 3000);
  });
}
// ==== end auto-injected decryptor ====
`;
}

function buildFallbackFridaScript(packageName, crypto) {
  crypto = normalizeCrypto(crypto);
  // crypto（可选）：已求解的加密参数 {key, iv, ciphertext, encoding, iv_encoding, algo}
  // 有了它，Hook 可在 App 进程内**直接解密并打印 [FLAG]**，实现"Hook 出 flag"，
  // 不依赖人工在模拟器里逐屏操作（本题外网/离线的多阶段题尤其如此）。
  const c = (crypto && typeof crypto === 'object') ? crypto : {};
  const j = (v) => JSON.stringify(v == null ? '' : String(v));
  return `'use strict';
send('[*] fallback hook script loaded');
${fridaSolvePreamble(crypto)}
function hr(b){ try { var h=''; for (var i=0;i<b.length;i++){ var c=b[i]&0xff; h+=(c<16?'0':'')+c.toString(16);} return h; } catch(e){ return '<err>'; } }
function ia(a){ try { var s=[]; for(var i=0;i<a.length;i++) s.push(a[i]); return '['+s.join(',')+']'; } catch(e){ return '<err>'; } }
if (Java.available) {
  Java.perform(function () {
    // 1) 自定义 JNI 方法（类名/方法名因题而异，见下方"通用扫描"）
    //    这里不写死具体类；靠 (2) 的 JNI 导出扫描 + (3) Cipher 钩子覆盖绝大多数情况。
    //    若已知目标类（AI 分析得出），把类名/方法名作为参数注入即可。
${crypto && crypto.hookClass ? `    try {
      var __cls = Java.use(${j(crypto.hookClass)});
      ${crypto.hookMethod ? `if (__cls[${j(crypto.hookMethod)}]) {
        __cls[${j(crypto.hookMethod)}].implementation = function () {
          var r = this[${j(crypto.hookMethod)}].apply(this, arguments);
          send('[DATA] ${crypto.hookMethod}(' + JSON.stringify(Array.prototype.slice.call(arguments)) + ') = ' + (r === null || r === undefined ? String(r) : (r.length !== undefined ? ia(r) : String(r))));
          return r;
        };
        send('[HIT] hooked ${crypto.hookClass}.${crypto.hookMethod}');
      }` : ''}
    } catch (e) { send('[!] hookClass: ' + e); }` : ''}
    // 2) JNI 导出（扫题目自带 lib*.so，不写死具体 so 名）
    try {
      Process.enumerateModules().forEach(function (m) {
        if (/^lib.*\.so$/i.test(m.name) && !/^\/(system|apex|vendor)\//.test(m.path)) {
          m.enumerateExports().forEach(function (ex) {
            if (ex.type === 'function' && ex.name.indexOf('Java_') === 0) {
              send('[HIT] JNI export: ' + ex.name);
              Interceptor.attach(ex.address, { onEnter: function (a) { send('[DATA] call ' + ex.name); } });
            }
          });
        }
      });
    } catch (e) {}
    // 3) Cipher
    try {
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var a = Array.prototype.slice.call(arguments);
          var kk = '';
          try { if (a[1] && a[1].getEncoded) { var kb = a[1].getEncoded(); kk = hr(kb); if (kb && kb.length === 16) __CTF_KNOWN.key = kk; } } catch (e) {}
          var iv = '';
          try { if (a[2] && a[2].getIV) { var ib = a[2].getIV(); iv = hr(ib); if (ib && ib.length === 16) __CTF_KNOWN.iv = iv; } } catch (e) {}
          send('[HIT] Cipher.init ' + this.getAlgorithm() + ' mode=' + a[0] + ' key=' + kk + ' iv=' + iv);
          return ov.apply(this, arguments);
        };
      });
      Cipher.doFinal.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var a = Array.prototype.slice.call(arguments);
          var r = ov.apply(this, arguments);
          send('[DATA] Cipher.doFinal in=' + hr(a[0]) + ' out=' + hr(r));
          // 明文直接可见 → 尝试捕获 flag；密文（含 '{' 的 base64）则作为待解明文重试
          try {
            var s = String(Java.use('java.lang.String').$new(a[0]));
            if (/NCTF\{|flag\{|ctf\{/i.test(s)) { __CTF_DONE = true; send('[FLAG]' + s + '[/FLAG]'); }
          } catch (e) {}
          if (!__CTF_DONE) { try { __ctfDecrypt('doFinal'); } catch (e) {} }
          return r;
        };
      });
      send('[HIT] Cipher hooked');
    } catch (e) {}
    // 4) MessageDigest / Base64
    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.digest.overload('[B').implementation = function (d) { var r = this.digest(d); send('[DATA] digest ' + hr(d) + ' -> ' + hr(r)); return r; };
    } catch (e) {}
    try {
      var B64 = Java.use('android.util.Base64');
      B64.encodeToString.overload('[B','int').implementation = function (d,f){ var r=this.encodeToString(d,f); send('[DATA] b64enc -> ' + r); return r; };
      B64.decode.overload('java.lang.String','int').implementation = function (s,f){ var r=this.decode(s,f); send('[DATA] b64dec ' + s + ' -> ' + (r?hr(r):'null')); return r; };
    } catch (e) {}
    // 5) SharedPreferences（内部类正确写法）
    try {
      var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
      Ed.putString.overloads.forEach(function (ov) { ov.implementation = function () { var a = Array.prototype.slice.call(arguments); send('[DATA] SP.putString ' + a[0] + ' = ' + a[1]); return ov.apply(this, arguments); }; });
      Ed.putBoolean.overloads.forEach(function (ov) { ov.implementation = function () { var a = Array.prototype.slice.call(arguments); send('[DATA] SP.putBoolean ' + a[0] + ' = ' + a[1]); return ov.apply(this, arguments); }; });
    } catch (e) {}
    // 6) Arrays.equals（校验常在此）
    try {
      var Arrays = Java.use('java.util.Arrays');
      Arrays.equals.overload('[I','[I').implementation = function (a,b){ var r=this.equals(a,b); send('[HIT] Arrays.equals(int[]) ' + ia(a) + ' vs ' + ia(b) + ' -> ' + r); if(r) send('[DATA] ARRAY MATCH ' + ia(a)); return r; };
    } catch (e) {}
    // 7) String.equals（严格降噪）
    try {
      var JStr = Java.use('java.lang.String');
      var NOI = /(AndroidNSSP|AndroidOpenSSL|code_cache|layout_inflater|pathInterpolator|transitionSet|androidx[.]|res[\\/])/;
      JStr.equals.implementation = function (o) {
        var a = this.toString(); var b = o ? o.toString() : '';
        var r = this.equals(o);
        if (a.length >= 8 && b.length >= 8 && !NOI.test(a) && !NOI.test(b) && (/[{]/.test(a) || /[{]/.test(b) || /flag|ctf|key|secret|stage/i.test(a) || /flag|ctf|key|secret|stage/i.test(b))) {
          send('[HIT] String.equals ' + r + ': "' + a + '" == "' + b + '"');
        }
        return r;
      };
    } catch (e) {}
    // 8) SuccessActivity 文本
    try {
      var TV = Java.use('android.widget.TextView');
      TV.setText.overload('int').implementation = function (id) { var r = this.setText(id); try { send('[DATA] setText(res) -> ' + this.getText().toString()); } catch (e) {} return r; };
    } catch (e) {}
    // 9) 主动触发：对已识别目标类做试探调用 + dump 可见文本
    setTimeout(function () { Java.perform(function () {
      send('[HIT] active trigger');
${crypto && crypto.hookClass && crypto.hookMethod ? `      try {
        Java.choose(${j(crypto.hookClass)}, { onMatch: function (inst) {
          ['', 'a', 'test', '1234567890123456'].forEach(function (p) { try { send('[DATA] probe ${crypto.hookMethod}("' + p + '") = ' + ia(inst[${j(crypto.hookMethod)}](p))); } catch (e) {} });
        }, onComplete: function () {} });
      } catch (e) {}` : '      // 未指定目标类：跳过主动调用（靠 Cipher/SP/JNI 扫描被动捕获）'}
      try { Java.choose('android.widget.EditText', { onMatch: function (e) { try { var s = e.getText().toString(); if (s) send('[DATA] EditText = ' + s); } catch (x) {} }, onComplete: function () {} }); } catch (e) {}
    }); }, 3000);
  });
} else { send('[!] Java not available'); }
`;
}

async function autoFridaStage() {
  if (state.fileType !== 'APK' || !state.currentFile) return;

  addLog('info', '========================================');
  addLog('info', '[阶段3] 动态调试自动化（Frida）');
  addLog('info', '========================================');

  // 1. 探测 frida-server
  const fridaPort = (state.config && state.config.emulator && state.config.emulator.frida_port) || 27042;
  let online = false;
  try {
    const probe = await window.electronAPI.checkPort(`http://127.0.0.1:${fridaPort}/`);
    online = !!(probe && probe.listening);
  } catch (e) { online = false; }
  if (!online) {
    addLog('info', `Frida 未在线（127.0.0.1:${fridaPort} 不可达），跳过动态调试自动化；可启动模拟器+frida-server 后点"运行Hook"手动执行`);
    return;
  }

  // 2. 确定包名（spawn 目标）
  let packageName = null;
  const pm = String(mcpCache.manifest || '').match(/package="([^"]+)"/);
  if (pm) packageName = pm[1];
  if (!packageName) { try { packageName = await getPackageNameFromAPK(); } catch (e) {} }
  if (!packageName) {
    addLog('warning', '无法确定包名，跳过 Frida 自动化');
    return;
  }

  // 3. AI 生成 Hook 脚本（直接生成，不走工具循环；脚本生成是模式化任务，走快速模型）
  const contextSummary = [
    mcpCache.mainCode ? `## MainActivity 代码（节选）\n${String(mcpCache.mainCode).slice(0, 2500)}` : '',
    Object.keys(mcpCache.otherClasses).length
      ? `## 关键类（节选）\n${Object.entries(mcpCache.otherClasses).map(([k, v]) => `### ${k}\n${String(v).slice(0, 1000)}`).join('\n').slice(0, 2500)}`
      : '',
    state.lastAiText ? `## 静态分析结论（节选）\n${String(state.lastAiText).slice(0, 2000)}` : ''
  ].filter(Boolean).join('\n\n');

  const genPrompt = `我在做 CTF APK 题（包名 ${packageName}），静态分析未能直接得出 flag。
请生成一个 Frida Hook 脚本，在 APP 启动期**主动触发校验并抓取运行时数据**。

${contextSummary}
${mcpCache.nativeIntel && mcpCache.nativeIntel.jniFuncs && mcpCache.nativeIntel.jniFuncs.length ? `
## 已知的 native/JNI 候选函数（优先 hook）
${mcpCache.nativeIntel.jniFuncs.slice(0, 12).join('\n')}
${mcpCache.nativeIntel.decompiled && mcpCache.nativeIntel.decompiled.length ? '（对应伪代码已在上下文，可直接据此定位算法与常量）' : ''}` : ''}

**关键要求（务必遵守）：**
1. 只输出一个 [FRIDA_SCRIPT]...[/FRIDA_SCRIPT] 块，块内是完整可运行 JS，不要其他解释，不要调用任何工具。
2. 用 Java.perform；hook 已识别的加密/校验函数（含自定义 JNI 方法）、Cipher.init/doFinal、MessageDigest、Base64、以及 SharedPreferences 读写。
3. **降噪（必须，且要严格）**：hook String.equals / compareTo 时**必须过滤**——只打印**同时**满足以下条件的比较：两串长度都 ≥ 8，**且**（任一侧匹配 /\{.*\}|flag|ctf|NCTF|key|secret|token/i 或 任一侧是 ≥ 20 的 hex/base64）。**典型噪音要排除**：AndroidNSSP / AndroidOpenSSL / code_cache / layout_inflater / pathInterpolator / transitionSet / androidx.* / res/*.xml / 绝对路径等，一律不打印（这些长度都≥6，仅用长度过滤会漏）。
4. **收尾时机（关键，勿过早收尾）**：只有**确认真实命中校验数据**（抓到 flag 形态的字符串、或加密/校验函数的实际入参返回、或 SharedPreferences 写入了 key/密文）才 \`send("[done]")\`；**绝不要因为捕获到普通 String.equals 噪音就收尾**。工具采用滚动窗口抓取（每来数据续 60s、连续 60s 无数据才结束），所以不要在脚本里写 12s/15s 之类的固定超时收尾。
5. **主动触发（关键，否则 App 停在首页、校验代码永不执行）**：
   - 优先用字节码/反射主动调用：对已识别的关键类用 \`Java.choose(类名, {...})\` 找到实例并调用其校验方法；或用 \`Class.forName(...).getDeclaredMethod(...)\` 主动调用（传入合理输入）。
   - 若题目是「界面流程题」（手势/输入框多阶段），脚本侧也应尝试直接调用：hook 底层 \`Arrays.equals(int[],int[])\`、\`Arrays.equals(byte[],byte[])\`、\`MessageDigest.digest\`、\`Cipher.doFinal\`、\`SharedPreferences\$EditorImpl.put*\` 来观察"正确值/中间值"。
   - \`android.app.SharedPreferencesImpl\$EditorImpl\` 是内部类，正确写法 \`Java.use('android.app.SharedPreferencesImpl\$EditorImpl')\`（不要用 \`SharedPreferencesImpl.EditorImpl\`，会 undefined）。
6. 打印统一前缀：[HIT] 表示"可能是校验/关键函数被调用"，[DATA] 表示"抓到含 flag/key/密文/正确值的数据"。
7. 不要用 Process.exit（保持 attach，由工具按时截断）。`;

  let script = null;
  try {
    state.aiBusy = true;
    beginStreamMessage();
    const genResult = await window.electronAPI.claudeChat(
      [{ role: 'user', content: genPrompt }],
      '你是 Frida 动态插桩专家。只输出一个 [FRIDA_SCRIPT] 块。不要调用任何工具。',
      { model: String((state.config && state.config.claude && state.config.claude.fastModel) || '').trim() || undefined }
    );
    endStreamMessage();
    if (genResult.success && genResult.text) {
      const sm = genResult.text.match(/\[FRIDA_SCRIPT\]([\s\S]+?)\[\/FRIDA_SCRIPT\]/);
      if (sm) script = sm[1].replace(/^```(?:javascript|js)?\s*/i, '').replace(/```\s*$/, '').trim();
    }
  } catch (e) {
    endStreamMessage();
    addLog('warning', 'Frida 脚本生成异常: ' + e.message);
  } finally {
    state.aiBusy = false;
  }

  if (!script) {
    addLog('warning', 'AI 未给出 [FRIDA_SCRIPT] 契约块，跳过动态执行');
    return;
  }

  // 脚本语法校验：AI 生成的正则常含未转义的 '/'（如 /data/dalvik），会让 frida 直接
  // 报 "invalid regular expression flags" 而整脚本不加载（表现为零输出、白等 25s）。
  // 这里做静态语法预检，并尝试自动修复"正则中裸露的 /"这类高频错误。
  const vres = await validateAndRepairFridaScript(script);
  const cryptoParams = pickCryptoParams();
  if (!vres.ok) {
    addLog('warning', 'AI Hook 脚本语法校验未通过（' + vres.error + '）；改用内置模板脚本');
    script = buildFallbackFridaScript(packageName, cryptoParams);
  } else {
    if (vres.repaired) addLog('info', 'Hook 脚本已自动修复语法问题（正则转义）');
    script = vres.script;
    // 即便 AI 脚本可用，也前置注入"进程内解密"段：只要已知 key/iv/密文，
    // 就能让 Hook 自己解出 flag（AI 脚本常只做被动抓取，不会主动解密）。
    if (cryptoParams && cryptoParams.key && cryptoParams.ciphertext) {
      script = fridaSolvePreamble(cryptoParams) + '\n' + script;
      addLog('info', '已向 Hook 注入进程内解密段（用已求解的 key/iv/密文主动出 flag）');
    }
  }
  await caseAddEvidence('frida', 'Frida Hook 脚本（自动生成）', script, 'js');

  // 4. spawn 拉起 APP 并注入 Hook，同时**并行驱动界面**（关键：否则 App 停在首页，
  //    手势/输入框触发的校验代码永不执行，Hook 抓到的全是启动噪音）。
  addLog('info', `以 spawn 模式拉起 ${packageName} 并注入 Hook，同时自动驱动界面（抓取约 25s）...`);

  // 4a. 迭代式驱动界面（每轮 dump→操作→再dump），与 Hook 并行；
  //     让界面触发的校验代码真正执行（否则 App 停在首页，Hook 只抓到启动噪音）。
  const drivePromise = (async () => {
    try {
      await sleepMs(5000); // 等 App 完成启动 + hook 安装
      addLog('info', '开始自动驱动界面（逐屏推进：点开始→画手势→填输入→提交）...');
      const log = await driveAppIteratively(packageName, 30000);
      addLog('success', `界面驱动完成：${log.length} 个动作 → ${log.join(' | ')}`);
    } catch (e) {
      addLog('warning', '界面驱动失败（不影响 Hook 抓取）: ' + e.message);
    }
  })();

  // 4b. 同时执行 Frida Hook（阻塞至命中/超时）
  // 抓取窗口必须长于 UI 驱动（5s 启动 + 30s 驱动），否则等校验真正发生时窗口已关闭。
  // 用滚动窗口：每来一条数据就续 60s，持续有数据就一直抓；连续 60s 无数据才收尾。
  const hookPromise = window.electronAPI.runFridaHook(script, 'spawn:' + packageName, { windowMs: 60000, hardCapMs: 600000 });

  const [run] = await Promise.all([hookPromise, drivePromise]);
  if (!run || !run.success) {
    addLog('warning', 'Frida 执行失败: ' + ((run && run.error) || '未知') + '（可检查 frida-server 与端口转发）');
    return;
  }
  const output = String(run.output || '');
  await caseAddEvidence('frida', 'Frida Hook 运行输出', output.slice(0, 20000));
  addLog('success', `Frida 抓取完成（${output.length} 字符），回灌 AI 做最终结论...`);

  // 5a. 直接从 Hook 输出里收割 [FLAG]（脚本在进程内解密成功时会显式打印）。
  //     这是"最硬的证据"：Hook 自身完成解密 → 直接记录并标 verified，不等 AI 复述。
  const directFlags = (output.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/gi) || [])
    .map(s => (s.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/i) || [])[1])
    .filter(v => v && looksLikeFlag(v));
  if (directFlags.length) {
    const uniq = [...new Set(directFlags)];
    uniq.forEach(f => { recordFlag(f, 'frida-flag', true); addSolveNote('Flag(动态-进程内解密)', f); });
    addLog('success', `[动态验证] Hook 进程内解密命中 ${uniq.length} 个 flag：${uniq.join(', ')}`);
    addSystemMessage(`**🎯 Hook 直接命中 Flag（进程内解密）**\n\n${uniq.map(f => `\`${f}\``).join('\n\n')}\n\n（由 Hook 在 App 进程内捕获密钥并解密得到，非 AI 复述）`);
  }

  // 5. 输出回灌 AI → 最终结论（沿用验证闭环）
  // 关键：Frida 输出常达数万字符，前几千行多是启动噪音；直接 slice(0,6000) 会把
  // 真正命中校验的 [DATA]/[HIT] 行截掉（本次 Hook 失败的教训）。改为优先抽取关键行。
  const keyLines = String(output).split(/\r?\n/).filter(l =>
    /\[DATA\]|\[HIT\]|NCTF\{|flag\{|ctf\{|Arrays\.equals|Cipher\.|SP\.|putString|putBoolean/i.test(l)
  );
  const noiseCount = String(output).split(/\r?\n/).length - keyLines.length;
  const outputSummary = keyLines.length
    ? `（已从 ${noiseCount + keyLines.length} 行中抽取 ${keyLines.length} 条关键行）\n` + keyLines.slice(-120).join('\n')
    : String(output).slice(-6000);
  const concludePrompt = `Frida 动态 Hook 抓取到以下运行时输出，请据此给出最终 flag 结论。

## Frida 关键输出（含 [DATA]/[HIT] 命中）
${outputSummary.slice(0, 9000)}

## Frida 原始输出（尾部节选，供参考）
${String(output).slice(-2500)}

${state.lastAiText ? `## 此前静态分析结论（节选）\n${String(state.lastAiText).slice(0, 1500)}` : ''}

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，附 \`[VERIFY]{"algo":"...","key":"...","ciphertext":"...","encoding":"hex|base64|ascii","expected":"flag或前缀"}[/VERIFY]\`（工具会本地复现验证；aes_cbc/des_cbc 另附 "iv"）
3. 不要调用任何工具；没有证据时明确标记"待人工验证"，不要猜 flag`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: concludePrompt }],
      '你是CTF逆向解题专家。结合动态抓取数据给出 flag。不要调用任何工具。'
    );
    endStreamMessage();
    if (result.success && result.text) {
      state.lastAiText = result.text;
      await harvestExperience(result.text);
      const vr = await runVerification(result.text);
      if (vr && !vr.verified) await runHypotheses(result.text);
      const flags = extractFlags(result.text);
      if (!vr) flags.forEach(f => recordFlag(f, 'frida', false));
      flags.forEach(f => addSolveNote('Flag(动态)', f));
      addSystemMessage(`**🎯 动态调试结论**\n\n${result.text}`);
    } else {
      addLog('warning', '动态结论生成失败: ' + (result.error || '未知'));
    }
  } catch (e) {
    endStreamMessage();
    addLog('warning', '动态结论异常: ' + e.message);
  } finally {
    state.aiBusy = false;
  }
}

// 调用Claude（使用API + Tool Use + 流式渲染）
async function callClaudeAPI(userMessage) {
  addLog('info', '正在分析...（再次点击发送可停止）');

  // 构建系统提示（包含当前文件信息）
  const systemPrompt = buildSystemPrompt();

  state.aiBusy = true;
  beginStreamMessage();

  try {
    const result = await window.electronAPI.claudeChat(
      state.chatHistory,
      systemPrompt
    );

    if (result.success) {
      endStreamMessage();
      state.lastAiText = result.text || '';
      state.chatHistory.push({ role: 'assistant', content: result.text });
      if (state.chatHistory.length > 20) {
        state.chatHistory = state.chatHistory.slice(-20);
      }
      addLog('success', '分析完成');
    } else if (result.aborted || /已取消/.test(result.error || '')) {
      const hadContent = streamText.trim().length > 0;
      endStreamMessage();
      addLog('info', 'AI 任务已停止');
      if (hadContent) {
        addSystemMessage('**⏹ 已停止**\n\n以上为停止前已生成的内容。');
      } else {
        addSystemMessage('**⏹ 已停止**');
      }
    } else {
      endStreamMessage();
      addLog('error', 'AI 错误: ' + result.error);
      addSystemMessage(`**AI 响应失败**\n\n${result.error}`);
    }
  } catch (err) {
    endStreamMessage();
    addLog('error', 'AI 请求失败: ' + err.message);
    addSystemMessage(`**请求失败**\n\n无法连接到 AI，请检查网络。`);
  } finally {
    state.aiBusy = false;
  }
}

// MCP结果缓存
const mcpCache = {
  manifest: null,
  activities: null,
  classes: null,
  mainClass: null,
  mainCode: null,
  otherClasses: {},
  strings: null,
  nativeIntel: null
};

// 清除缓存
function clearMcpCache() {
  mcpCache.manifest = null;
  mcpCache.activities = null;
  mcpCache.classes = null;
  mcpCache.mainClass = null;
  mcpCache.mainCode = null;
  mcpCache.otherClasses = {};
  mcpCache.strings = null;
}

// 自动求解flag（混合方案：直接MCP + Tool Use）
async function autoSolveFlag() {
  if (!state.currentFile) {
    addLog('warning', '未选择文件，跳过自动求解');
    return;
  }

  // 清除缓存
  clearMcpCache();

  addLog('info', '========================================');
  addLog('info', '[阶段1] 直接调用MCP快速收集数据');
  addLog('info', '========================================');

  // 收集分析数据
  let analysisData = {
    manifest: null,
    activities: null,
    classes: null,
    mainActivityCode: null,
    otherClassesCode: [],
    packageName: null
  };

  // 1. 获取Manifest
  try {
    const manifestResult = await window.electronAPI.jebMcpCall('get_manifest', [state.currentFile]);
    if (manifestResult.success) {
      analysisData.manifest = manifestResult.result;
      mcpCache.manifest = manifestResult.result;
      addLog('success', '✅ 已获取AndroidManifest');

      // 提取包名
      const packageMatch = manifestResult.result.match(/package="([^"]+)"/);
      if (packageMatch) {
        analysisData.packageName = packageMatch[1];
        addLog('info', `包名: ${packageMatch[1]}`);
      }
    }
  } catch (e) {
    addLog('warning', '获取Manifest失败: ' + e.message);
  }

  // 2. 获取Activity列表
  try {
    const activitiesResult = await window.electronAPI.jebMcpCall('get_all_exported_activities', [state.currentFile]);
    if (activitiesResult.success) {
      analysisData.activities = activitiesResult.result;
      mcpCache.activities = activitiesResult.result;
      addLog('success', '✅ 已获取Activity列表');
    }
  } catch (e) {
    addLog('warning', '获取Activity失败: ' + e.message);
  }

  // 3. 获取所有类
  try {
    const classesResult = await window.electronAPI.jebMcpCall('get_all_classes', [state.currentFile]);
    if (classesResult.success) {
      analysisData.classes = classesResult.result;
      mcpCache.classes = classesResult.result;
      addLog('success', '✅ 已获取类列表');

      // 识别关键类（应用自身包优先 + 加解密/编解码/校验语义加权，避免只靠硬编码关键词漏掉 Encoder）
      if (Array.isArray(classesResult.result)) {
        const keyClasses = selectKeyClasses(classesResult.result, analysisData.packageName, null, 10);
        addLog('info', `发现 ${keyClasses.length} 个关键类: ${keyClasses.map(c => String(c).split('/').pop()).join(', ')}`);
      }
    }
  } catch (e) {
    addLog('warning', '获取类列表失败: ' + e.message);
  }

  // 3.5 内容命中筛查：光看类名选不中混淆类，改为"在解包产物里搜关键常量/字符串反查类"。
  // 关键词来自 manifest/已获代码里的高熵常量与关键字符串（64位hex、base64密文、stage/key/flag 等）。
  try {
    if (analysisData.classes && Array.isArray(analysisData.classes)) {
      const seeds = new Set();
      // 噪音关键词：命中它们只会反查出 androidx/kotlin 等无关类，必须过滤
      const kwNoise = /^(androidx?|kotlin|kotlinx|java|javax|dalvik|com\.google|org\.jetbrains|org\.apache|com\.squareup)/i;
      const kwGenericNoise = /^(vector|path|merge|include|fragment|window|view|include|drawable|layout|style|theme|attr|string|color|dimen|animation|transition|interpolator|content|context|application|activity|service|receiver|provider)/i;
      const addSeed = (x) => {
        const v = String(x == null ? '' : x).trim();
        if (v.length < 4 || v.length > 64) return;
        if (kwNoise.test(v) || kwGenericNoise.test(v)) return;
        seeds.add(v);
      };
      const harvest = (txt) => {
        const s = String(txt || '');
        // 高熵常量优先（SHA256/MD5 目标、密钥、base64 密文）——这些最能定位"承载算法的类"
        (s.match(/\b[0-9a-fA-F]{32,64}\b/g) || []).slice(0, 8).forEach(addSeed);
        (s.match(/\b[A-Za-z0-9+/]{24,}={0,2}\b/g) || []).filter(x => /[A-Z]/.test(x) && /[a-z]/.test(x) && /[0-9]/.test(x)).slice(0, 6).forEach(addSeed);
        // 关键字符串字面量：只留"像题目自定义"的（含语义词或下划线驼峰），排除通用资源名
        (s.match(/["']([A-Za-z0-9_\-{}]{4,24})["']/g) || [])
          .map(x => x.replace(/["']/g, ''))
          .filter(x => /flag|ctf|key|secret|iv|pass|token|stage|check|verify|encrypt|decrypt|cipher|native/i.test(x) || /_/.test(x))
          .slice(0, 20).forEach(addSeed);
        ['stage1Passed', 'stage2Passed', 'stage3Passed', 'stage1Key', 'stage2Key', 'successMessage'].forEach(addSeed);
      };
      harvest(analysisData.manifest);
      harvest(analysisData.mainActivityCode);
      analysisData.otherClassesCode.forEach(c => harvest(c.code));
      const kws = [...seeds].filter(k => k.length >= 4).slice(0, 25);
      if (kws.length) {
        // 需要解包产物；若不存在，先用 apktool 解一次（已有产物则秒回）
        await ensureDecodedDir();
        const byContent = await scanKeyClassesByContent(state.currentFile, kws);
        state._keyClassesByContent = byContent;
        const names = Object.keys(byContent);
        if (names.length) addLog('info', `内容命中筛查定位到 ${names.length} 个承载校验/常量的类: ${names.slice(0, 12).join(', ')}`);
      }
    }
  } catch (e) {
    addLog('warning', '内容命中筛查失败（不影响主流程）: ' + e.message);
  }

  // 4. 反编译MainActivity（从Manifest的 LAUNCHER activity 精确提取）
  let mainClass = null;
  if (analysisData.manifest) {
    mainClass = extractLauncherActivity(analysisData.manifest, analysisData.packageName);
    if (mainClass) {
      // 转换为JNI格式
      if (!mainClass.startsWith('L')) {
        mainClass = 'L' + mainClass.replace(/\./g, '/') + ';';
      }
      addLog('info', `主Activity(LAUNCHER): ${mainClass}`);
    } else {
      addLog('warning', '未在Manifest中找到 LAUNCHER activity');
    }
  }
  mcpCache.mainClass = mainClass;

  if (mainClass) {
    try {
      const mainActivityResult = await window.electronAPI.jebMcpCall('get_class_decompiled_code', [
        state.currentFile,
        mainClass
      ]);
      if (mainActivityResult.success) {
        analysisData.mainActivityCode = mainActivityResult.result;
        mcpCache.mainCode = mainActivityResult.result;
        addLog('success', '✅ 已反编译MainActivity');
      }
    } catch (e) {
      addLog('warning', '反编译MainActivity失败: ' + e.message);
    }
  }

  // 5. 反编译其他关键类（应用自身包优先 + 加解密/编解码/校验语义加权）
  //    注意：不要只匹配 encrypt 这类硬编码关键词——Encoder / vm_operad 等命名不在表内，
  //    会把真正承载算法的类漏掉（APK 题与 2.exe 题暴露的同一根因）。
  if (analysisData.classes && Array.isArray(analysisData.classes)) {
    const keyClasses = selectKeyClasses(analysisData.classes, analysisData.packageName, mainClass, 12); // 含内容命中类，放宽到 12

    for (const cls of keyClasses) {
      try {
        const clsResult = await window.electronAPI.jebMcpCall('get_class_decompiled_code', [
          state.currentFile,
          cls
        ]);
        if (clsResult.success) {
          analysisData.otherClassesCode.push({ class: cls, code: clsResult.result });
          mcpCache.otherClasses[cls] = clsResult.result;
          addLog('success', `✅ 已反编译: ${cls.split('/').pop()}`);
        }
      } catch (e) {
        // 忽略单个类的失败
      }
    }
  }

  // 阶段2：AI初步分析
  addLog('info', '========================================');
  addLog('info', '[阶段2] AI初步分析');
  addLog('info', '========================================');

  // 构建其他类的代码
  let otherClassesText = '';
  if (analysisData.otherClassesCode.length > 0) {
    otherClassesText = '\n## 其他关键类\n';
    for (const cls of analysisData.otherClassesCode) {
      otherClassesText += `\n### ${cls.class}\n${String(cls.code).substring(0, 3000)}\n`;
    }
  }

  const analysisPrompt = `我正在分析一个CTF APK题目。

文件路径：${state.currentFile}
包名：${analysisData.packageName || '未知'}
主Activity：${mainClass || '未知'}

以下是通过JEB MCP获取的代码：

## AndroidManifest
${analysisData.manifest ? analysisData.manifest.substring(0, 1500) : '暂无'}

## 主Activity反编译代码
${analysisData.mainActivityCode ? analysisData.mainActivityCode.substring(0, 4000) : '暂无'}
${otherClassesText}

请直接分析上面的代码，找出：
1. 加密算法是什么
2. flag的生成或验证逻辑
3. 直接给出flag

注意：不要调用任何工具，直接基于上面的代码分析。

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，必须附验证数据（工具会本地复现）：
   \`[VERIFY]{"algo":"rc4|tea|xtea|xxtea|xor|aes_ecb|aes_cbc|des_ecb|des_cbc|des3_ecb|sm4_ecb|base64|base64_custom|custom","key":"密钥","key_encoding":"ascii|hex","ciphertext":"密文","encoding":"hex|base64|ascii","expected":"flag或前缀"}[/VERIFY]\`
   （custom 需附 "code":"def decrypt(data,key): ...完整函数"；多个候选时输出 \`[HYPOTHESES][{...},{...}][/HYPOTHESES]\` 供本地枚举）

如果无法可靠得到完整 flag，不要只回复“无法分析”，必须输出以下结构：
## 题目掌握度
- 已确认的关键点：
- 当前推断及置信度：高/中/低
- 仍缺少的信息：
## 人工引导
- 请用户在指定函数/比较点提供哪些寄存器、内存或运行结果：
## CyberChef 参数
- 算法：
- 密钥（ASCII/HEX）：
- IV/Nonce（如有）：
- 密文/输入（HEX/Base64）：
- CyberChef 操作顺序：
不要猜测密钥、密文或 flag；没有证据时明确标记“待动态验证”。`;

  try {
    addLog('info', '正在调用AI分析代码...');
    addLog('info', '请等待，这可能需要30-60秒...（再次点击发送可停止）');

    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await claudeChatCascade(
      [{ role: 'user', content: analysisPrompt }],
      `你是CTF逆向解题专家。请直接分析代码并给出flag。直接基于提供的代码分析，不要调用任何工具。\n解题学习闭环（强制）：回答最后必须输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条、每条200字内[/EXPERIENCE]（确无新收获则写"无新增经验"），工具会自动写入经验库，下次同类题优先复用、避免重复踩坑。`
    );

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    addLog('info', `AI响应完成，耗时 ${elapsed} 秒`);

    if (result.success && result.text) {
      endStreamMessage();
      if (result.stopReason === 'max_tokens') {
        addLog('warning', '⚠️ AI 输出被 max_tokens 截断（思考耗尽预算，可能缺少最终结论），建议在设置中调大 max_tokens 后重试');
      }
      addLog('success', 'AI分析成功！');

      // MCP 采集物落盘为证据（供 WP 引用与离线复盘）
      await caseAddEvidence('manifest', 'AndroidManifest', analysisData.manifest || '（未获取）');
      if (analysisData.mainActivityCode) await caseAddEvidence('decompile', `主Activity ${mainClass || ''}`, analysisData.mainActivityCode, 'java');
      if (analysisData.otherClassesCode.length) {
        await caseAddEvidence('decompile', '关键类反编译', analysisData.otherClassesCode.map(c => `// ==== ${c.class} ====\n${c.code}`).join('\n\n'), 'java');
      }

      // 记录到解题报告（APK 路径此前缺失，导致 WP 没有结论）
      const clean = String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000);
      addSolveNote('求解结果', clean);
      state.lastAiText = result.text;
      await harvestExperience(result.text);

      // 验证闭环 + 失败时本地枚举兜底
      const vr = await runVerification(result.text);
      if (vr && !vr.verified) await runHypotheses(result.text);
      const flags = extractFlags(result.text);
      if (!vr) flags.forEach(f => recordFlag(f, 'ai', false));
      flags.forEach(f => addSolveNote('Flag', f));

      const verifiedFlags = (state.findings ? state.findings.flags : []).filter(f => f.verified);
      const resultMsg = `**🎯 自动求解结果**

**文件**: ${state.fileInfo.fileName}
${verifiedFlags.length ? `**Flag（✅已验证）**: \`${verifiedFlags[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`;

      addSystemMessage(resultMsg);
    } else if (result.aborted || /已取消/.test(result.error || '')) {
      endStreamMessage();
      addLog('info', '自动求解已停止');
      addSystemMessage('**⏹ 自动求解已停止**\n\n可再次点击"自动分析"重新开始。');
    } else {
      endStreamMessage();
      addLog('error', 'AI分析失败: ' + (result.error || '未知错误'));
      addSystemMessage('**AI分析失败**\n\n请手动分析或重试。');
    }
  } catch (err) {
    endStreamMessage();
    addLog('error', 'AI分析异常: ' + err.message);
    addSystemMessage('**AI分析异常**\n\n错误: ' + err.message);
  } finally {
    state.aiBusy = false;
  }

  // 静态流水线结束仍无已验证 flag → 先走 Tool-Use 深度求解（AI 自主挖类/反汇编/写脚本），
  // 仍无结果再进入动态调试（Frida 不在线则优雅跳过）。
  // 关键：固定清单喂代码的方式会漏掉混淆类（N0.d 等），必须给 AI 自己调工具的能力。
  const stillNoVerified = !(state.findings && state.findings.flags && state.findings.flags.some(f => f.verified));
  if (stillNoVerified) {
    const solved = await toolUseDeepSolve(analysisData, mainClass);
    if (solved) return;
  }
  const stillNoVerified2 = !(state.findings && state.findings.flags && state.findings.flags.some(f => f.verified));
  if (stillNoVerified2) await autoFridaStage();
}

// 阶段2.5：Tool-Use 深度求解 —— 让 AI 自主调用 JEB/IDA/run_python/read_file 等工具，
// 突破"预选固定类清单"的局限（混淆类、SO 里的 native 算法都在清单之外）。
// 返回 true 表示已产出已验证 flag。
async function toolUseDeepSolve(analysisData, mainClass) {
  addLog('info', '========================================');
  addLog('info', '[阶段2.5] Tool-Use 深度求解（AI 自主调用 JEB/IDA/脚本）');
  addLog('info', '========================================');

  const pkg = (analysisData && analysisData.packageName) || '';
  const classesList = (analysisData && Array.isArray(analysisData.classes))
    ? analysisData.classes.slice(0, 200).join('\n') : '（未获取）';

  const deepPrompt = `我正在解一道 CTF APK 题，静态固定清单分析未能得出 flag。请你**使用工具**自主深入分析并求出 flag。

文件路径：${state.currentFile}
包名：${pkg || '未知'}
主Activity：${mainClass || '未知'}

## 已获取的类列表（完整，供你挑目标类反编译）
${classesList}
${mcpCache.nativeIntel && mcpCache.nativeIntel.decompiled.length ? `
## IDA 已反编译的 native 函数（直接用，勿重复反编译）
${mcpCache.nativeIntel.decompiled.map(d => `### ${d.name}\n\`\`\`c\n${d.code}\n\`\`\``).join('\n\n')}
${mcpCache.nativeIntel.strings ? `\n## IDA 关键字符串\n${mcpCache.nativeIntel.strings}` : ''}` : ''}

## 你必须做的（按需调用工具，不要只凭已有片段下结论）
1. 用 jeb_get_all_classes 拿到完整类列表；对**混淆类**（短包名单字母类名，如 N0/d、C/h、K0/a）以及任何与校验/加密/状态相关的类，用 jeb_get_class_decompiled **逐个反编译**——真正的校验逻辑几乎总在这些类里，Activity 只是 UI。
2. 读关键资源：用 bash 或 read_file 查看 strings.xml / resources.arsc（flag 或校验常量常在其中），以及 SharedPreferences 里用到的键名。
3. 若题目含 native SO：用 bash 找到 lib/*.so，用 run_python(capstone) 反汇编导出的 JNI 函数（Java_<包>_<类>_<方法>），还原算法；也可用 IDA MCP（ida_decompile / ida_find_strings）。
4. 用 run_python 写求解脚本并**本地验证**（正反双向：反推 key 后正向加密对回目标常量）。
5. 仅在确实无法推进时才停；有把握就给出 flag。

**输出契约（必须遵守）：**
1. 得到 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 必须附验证数据（工具会本地复现）：
   \`[VERIFY]{"algo":"rc4|tea|xtea|xxtea|xor|aes_ecb|aes_cbc|des_ecb|des_cbc|des3_ecb|sm4_ecb|base64|base64_custom|node_js|custom","key":"密钥","key_encoding":"ascii|hex","ciphertext":"密文","encoding":"hex|base64|ascii","expected":"flag或前缀","iv":"(aes_cbc/des_cbc 需要)","code":"(custom/node_js 需要)完整函数"}[/VERIFY]\`
3. 多个候选组合：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 回答最后输出 \`[EXPERIENCE]...[/EXPERIENCE]\`（每条一行，最多5条）
不要臆造工具结果；工具失败时换一条路径继续，不要重复同一失败写法。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: deepPrompt }],
      buildSystemPrompt()
    );
    endStreamMessage();
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    addLog('info', `Tool-Use 深度求解完成，耗时 ${elapsed} 秒`);

    if (result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(Tool-Use)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      await harvestExperience(result.text);
      const vr = await runVerification(result.text);
      if (vr && !vr.verified) await runHypotheses(result.text);
      extractFlags(result.text).forEach(f => { recordFlag(f, 'ai-deep', false); addSolveNote('Flag', f); });

      const verifiedFlags = (state.findings ? state.findings.flags : []).filter(f => f.verified);
      const flags = extractFlags(result.text);
      addSystemMessage(`**🎯 Tool-Use 深度求解结果**

${verifiedFlags.length ? `**Flag（✅已验证）**: \`${verifiedFlags[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`);
      return verifiedFlags.length > 0;
    }
    if (result.aborted || /已取消/.test(result.error || '')) {
      addLog('info', 'Tool-Use 深度求解已停止');
      return false;
    }
    addLog('warning', 'Tool-Use 深度求解未返回内容: ' + (result.error || '未知'));
    return false;
  } catch (err) {
    try { endStreamMessage(); } catch (e) {}
    addLog('warning', 'Tool-Use 深度求解异常: ' + err.message);
    return false;
  } finally {
    state.aiBusy = false;
  }
}

// 详细分析（Tool Use，限制迭代次数）
async function detailedAnalysis(analysisData) {
  addLog('info', '使用Tool Use进行详细分析（最多5次工具调用）...');

  // 构建已缓存的数据摘要
  let cachedDataSummary = '';
  if (mcpCache.manifest) cachedDataSummary += '- AndroidManifest: 已获取\n';
  if (mcpCache.mainCode) cachedDataSummary += '- MainActivity代码: 已获取\n';
  if (mcpCache.classes) cachedDataSummary += `- 类列表: ${mcpCache.classes.length}个\n`;
  if (Object.keys(mcpCache.otherClasses).length > 0) {
    cachedDataSummary += `- 其他类: ${Object.keys(mcpCache.otherClasses).join(', ')}\n`;
  }

  const detailedPrompt = `我正在分析一个CTF APK题目，初步分析没有找到flag。请使用工具进行更深入的分析。

文件路径：${state.currentFile}
包名：${analysisData.packageName || '未知'}
主Activity：${analysisData.mainClass || mcpCache.mainClass || '未知'}

## 已缓存的数据
${cachedDataSummary || '暂无'}

## 已获取的代码

### 主Activity
${analysisData.mainActivityCode ? analysisData.mainActivityCode.substring(0, 2000) : '暂无'}

## 任务
请使用工具进行分析（最多5次调用）：
1. 反编译可能包含flag的其他类
2. 搜索关键字符串
3. 找出flag的生成逻辑

注意：
- 最多调用5次工具
- 优先分析可能包含flag的类
- 找到flag后立即停止`;

  try {
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: detailedPrompt }],
      `你是CTF逆向解题专家。请使用工具分析代码并找出flag。最多调用5次工具，找到flag后立即停止。当前文件: ${state.fileInfo.fileName}`
    );

    if (result.success && result.text) {
      addLog('success', '========================================');
      addLog('success', '详细分析完成！');
      addLog('success', '========================================');

      const resultMsg = `**🔍 详细分析结果**

**文件**: ${state.fileInfo.fileName}
**包名**: ${analysisData.packageName || '未知'}

${result.text}`;

      addSystemMessage(resultMsg);
    } else {
      addLog('error', '详细分析失败: ' + (result.error || '未知错误'));
      addSystemMessage('**分析失败**\n\n请手动分析或重试。');
    }
  } catch (err) {
    addLog('error', '详细分析失败: ' + err.message);
    addSystemMessage('**分析失败**\n\n错误: ' + err.message);
  }
}

// 自动求解PE/ELF flag（混合方案）
async function autoSolveBinaryFlag(fileType) {
  if (!state.currentFile) {
    addLog('warning', '未选择文件，跳过自动求解');
    return;
  }

  addLog('info', '========================================');
  addLog('info', '[阶段1] 直接调用IDA MCP快速收集数据');
  addLog('info', '========================================');

  // 收集分析数据
  let analysisData = {
    functions: null,
    strings: null,
    mainCode: null,
    otherFunctions: []
  };

  // 1. 获取函数列表
  try {
    const funcsResult = await window.electronAPI.idaMcpCall('list_functions', { queries: {} });
    if (funcsResult.success) {
      analysisData.functions = funcsResult.result;
      addLog('success', '✅ 已获取函数列表');

      // 识别关键函数（语义加权：加解密/编解码/校验/VM 派发等，避免漏掉 vm_operad 这类核心函数）
      if (Array.isArray(funcsResult.result)) {
        const keyFuncs = selectKeyFunctions(funcsResult.result, 10);
        addLog('info', `发现 ${keyFuncs.length} 个关键函数: ${keyFuncs.map(f => (f && f.name) || f).join(', ')}`);
      }
    }
  } catch (e) {
    addLog('warning', '获取函数列表失败: ' + e.message);
  }

  // 2. 搜索关键字符串
  try {
    const stringsResult = await window.electronAPI.idaMcpCall('find_strings', { pattern: 'flag|correct|wrong|success|key|encrypt|decrypt' });
    if (stringsResult.success) {
      analysisData.strings = stringsResult.result;
      addLog('success', '✅ 已搜索关键字符串');
    }
  } catch (e) {
    addLog('warning', '搜索字符串失败: ' + e.message);
  }

  // 3. 反编译入口函数
  //    入口名随工具链而异：mingw 编出来是 _main，MSVC 是 main / _WinMainCRTStartup。
  //    硬编码 'main' 会拿到 {"code":null,"error":"Not found: 'main'"}——2.exe 题暴露的根因。
  try {
    const entry = await decompileEntryFunction(analysisData.functions);
    if (entry) {
      analysisData.mainCode = entry.code;
      analysisData.mainRefs = (entry.raw && entry.raw.refs) || [];
      analysisData.mainName = entry.name;
      addLog('success', `✅ 已反编译入口函数: ${entry.name}（${entry.code.length} 字符）`);
    } else {
      addLog('warning', '未找到入口函数反编译（已尝试 main/_main/__main/WinMain/_WinMainCRTStartup）');
    }
  } catch (e) {
    addLog('warning', '反编译入口函数失败: ' + e.message);
  }

  // 4. 反编译其他关键函数（语义加权挑选，含 VM/派发/解释器类函数）
  if (analysisData.functions && Array.isArray(analysisData.functions)) {
    const keyFuncs = selectKeyFunctions(analysisData.functions, 6);

    for (const func of keyFuncs) {
      try {
        const funcName = (func && typeof func === 'object') ? String(func.name || '') : String(func || '');
        if (!funcName || funcName === '[object Object]') continue;
        const funcResult = await window.electronAPI.idaMcpCall('decompile', { address: funcName });
        const code = idaPickCode(funcResult && funcResult.result);
        if (code) {
          analysisData.otherFunctions.push({
            name: funcName,
            code,
            refs: (funcResult.result && funcResult.result.refs) || []
          });
          addLog('success', `✅ 已反编译: ${funcName}（${code.length} 字符）`);
        } else {
          addLog('info', `⏭️ 跳过（IDA 未给出代码）: ${funcName}`);
        }
      } catch (e) {
        // 忽略单个函数的失败
      }
    }
  }

  // 5. 读取反编译里引用到的全局数据表
  //    VM 字节码 / 密文表 / S 盒 / 密钥常量通常放在全局数组里，只给代码 AI 无法还原。
  //    2.exe 的 src_（0x403040，114 个 int32）就是 VM 程序本体，缺它必解不出。
  try {
    const refAddrs = idaCollectRefAddrs([
      { refs: analysisData.mainRefs },
      ...analysisData.otherFunctions.map(f => ({ refs: f.refs }))
    ]);
    if (refAddrs.size) {
      const gRes = await window.electronAPI.idaMcpCall('list_globals', { queries: {} });
      const globals = (gRes && gRes.success && Array.isArray(gRes.result)) ? gRes.result : [];
      const byAddr = globals
        .map(g => ({ addr: String((g && g.addr) || ''), name: String((g && g.name) || ''), val: parseInt((g && g.addr) || '', 16) }))
        .filter(g => Number.isFinite(g.val))
        .sort((a, b) => a.val - b.val);
      const wanted = [];
      for (let i = 0; i < byAddr.length; i++) {
        const g = byAddr[i];
        if (!refAddrs.has(g.addr.toLowerCase())) continue;
        const next = byAddr[i + 1];
        let size = next ? next.val - g.val : 256;
        if (!(size > 0) || size > 8192) size = 256;
        wanted.push({ addr: g.addr, name: g.name, size });
      }
      if (wanted.length) {
        const bRes = await window.electronAPI.idaMcpCall('get_bytes', {
          regions: wanted.map(w => ({ addr: w.addr, size: w.size }))
        });
        if (bRes && bRes.success && Array.isArray(bRes.result)) {
          analysisData.globals = bRes.result.map((r, i) => ({
            name: (wanted[i] && wanted[i].name) || (r && r.addr) || 'global',
            addr: (r && r.addr) || (wanted[i] && wanted[i].addr) || '',
            data: (r && r.data) || ''
          }));
          addLog('success', `✅ 已读取 ${analysisData.globals.length} 个被引用的全局数据表: ${analysisData.globals.map(g => g.name).join(', ')}`);
        }
      } else {
        addLog('info', '未发现需要读取的全局数据表');
      }
    }
  } catch (e) {
    addLog('warning', '读取全局数据失败: ' + e.message);
  }

  // 前置短路：IDA 一点有效数据都没拿到时不要调 AI——模型只能凭空编造 flag，
  // 反而把臆测的 flag{test}/flag{abcde} 之类写进 findings，污染验收结论。
  const hasAnyData = !!analysisData.mainCode
    || (Array.isArray(analysisData.functions) && analysisData.functions.length > 0)
    || (analysisData.otherFunctions && analysisData.otherFunctions.length > 0);
  if (!hasAnyData) {
    addLog('warning', '❌ IDA MCP 未返回任何有效数据（函数列表/反编译均为空），已中止 AI 分析以避免臆测');
    addSolveNote('依赖缺失', 'IDA MCP 未返回有效数据，AI 分析已短路跳过。请确认 IDA 已加载目标文件且 MCP 插件（127.0.0.1:13337）在线。');
    return;
  }

  // 阶段2：AI初步分析
  addLog('info', '========================================');
  addLog('info', '[阶段2] AI初步分析');
  addLog('info', '========================================');
  addLog('info', '准备构建分析提示...');

  try {

    // 构建其他函数的代码
    let otherFuncsText = '';
    if (analysisData.otherFunctions && analysisData.otherFunctions.length > 0) {
      otherFuncsText = '\n## 其他关键函数\n';
      for (const func of analysisData.otherFunctions) {
        otherFuncsText += `\n### ${func.name}\n${func.code ? String(func.code).substring(0, 6000) : '暂无'}\n`;
      }
    }

    // 构建被引用的全局数据表（VM 字节码 / 密文 / S 盒 / 密钥常量）
    let globalsText = '';
    if (analysisData.globals && analysisData.globals.length > 0) {
      globalsText = '\n## 反编译中引用到的全局数据（int32 已按小端解码）\n';
      for (const g of analysisData.globals) {
        const ints = bytesToInt32LE(g.data);
        globalsText += `\n### ${g.name} @${g.addr}｜共 ${ints.length} 个 int32\n`;
        globalsText += `int32[] = [${ints.slice(0, 600).join(', ')}]\n`;
        if (ints.length > 600) globalsText += `（其余 ${ints.length - 600} 个已省略）\n`;
      }
    }

    // 安全地转换函数列表
    let functionsText = '暂无';
    try {
      if (analysisData.functions) {
        functionsText = JSON.stringify(analysisData.functions).substring(0, 4000);
      }
    } catch (e) {
      functionsText = '函数列表解析失败';
    }

    // 安全地转换字符串列表
    let stringsText = '暂无';
    try {
      if (analysisData.strings) {
        stringsText = JSON.stringify(analysisData.strings).substring(0, 2000);
      }
    } catch (e) {
      stringsText = '字符串列表解析失败';
    }

    // 安全地获取main函数代码
    let mainCodeText = '暂无';
    try {
      if (analysisData.mainCode) {
        if (typeof analysisData.mainCode === 'string') {
          mainCodeText = analysisData.mainCode.substring(0, 9000);
        } else if (analysisData.mainCode.code) {
          mainCodeText = analysisData.mainCode.code.substring(0, 9000);
        } else {
          mainCodeText = JSON.stringify(analysisData.mainCode).substring(0, 9000);
        }
      }
    } catch (e) {
      mainCodeText = 'main函数代码解析失败';
    }

    const analysisPrompt = `我正在分析一个CTF ${fileType}题目。

文件路径：${state.currentFile}

以下是通过IDA MCP获取的分析数据：

## 函数列表
${functionsText}

## 关键字符串
${stringsText}

## 入口函数（${analysisData.mainName || 'main'}）反编译代码
${mainCodeText}
${otherFuncsText}
${globalsText}

请直接分析上面的代码，找出：
1. 加密算法是什么
2. flag的生成或验证逻辑
3. 直接给出flag

注意：不要调用任何工具，直接基于上面的代码分析。

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，必须附验证数据（工具会本地复现）：
   \`[VERIFY]{"algo":"rc4|tea|xtea|xxtea|xor|aes_ecb|aes_cbc|des_ecb|des_cbc|des3_ecb|sm4_ecb|base64|base64_custom|custom","key":"密钥","key_encoding":"ascii|hex","ciphertext":"密文","encoding":"hex|base64|ascii","expected":"flag或前缀"}[/VERIFY]\`
   （custom 需附 "code":"def decrypt(data,key): ...完整函数"；多个候选时输出 \`[HYPOTHESES][{...},{...}][/HYPOTHESES]\` 供本地枚举）

如果无法可靠得到完整 flag，不要只回复“无法分析”，必须输出以下结构：
## 题目掌握度
- 已确认的关键点：
- 当前推断及置信度：高/中/低
- 仍缺少的信息：
## 人工引导
- 请用户在指定函数/比较点提供哪些寄存器、内存或运行结果：
## CyberChef 参数
- 算法：
- 密钥（ASCII/HEX）：
- IV/Nonce（如有）：
- 密文/输入（HEX/Base64）：
- CyberChef 操作顺序：
不要猜测密钥、密文或 flag；没有证据时明确标记“待动态验证”。`;

    addLog('info', '分析提示构建完成，长度: ' + analysisPrompt.length + ' 字符');

    addLog('info', '正在调用AI分析代码...');
    addLog('info', '请等待，这可能需要30-60秒...（再次点击发送可停止）');

    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await claudeChatCascade(
      [{ role: 'user', content: analysisPrompt }],
      `你是CTF逆向解题专家。请直接分析代码并给出flag。不要调用任何工具，直接基于提供的代码分析。\n解题学习闭环（强制）：回答最后必须输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条、每条200字内[/EXPERIENCE]（确无新收获则写"无新增经验"），工具会自动写入经验库，下次同类题优先复用、避免重复踩坑。`
    );

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    addLog('info', `AI响应完成，耗时 ${elapsed} 秒`);

    if (result.success && result.text) {
      endStreamMessage();
      if (result.stopReason === 'max_tokens') {
        addLog('warning', '⚠️ AI 输出被 max_tokens 截断（思考耗尽预算，可能缺少最终结论），建议在设置中调大 max_tokens 后重试');
      }
      addLog('success', 'AI分析成功！');

      // MCP 采集物落盘为证据
      await caseAddEvidence('ida_functions', '函数列表', typeof analysisData.functions === 'string' ? analysisData.functions : JSON.stringify(analysisData.functions, null, 2));
      if (analysisData.strings) await caseAddEvidence('ida_strings', '关键字符串', typeof analysisData.strings === 'string' ? analysisData.strings : JSON.stringify(analysisData.strings, null, 2));
      if (analysisData.mainCode) await caseAddEvidence('decompile', 'main反编译', typeof analysisData.mainCode === 'string' ? analysisData.mainCode : JSON.stringify(analysisData.mainCode));
      if (analysisData.otherFunctions.length) {
        await caseAddEvidence('decompile', '关键函数反编译', analysisData.otherFunctions.map(f => `// ==== ${f.name} ====\n${f.code}`).join('\n\n'), 'c');
      }

      // 记录到解题报告（仅保留结论/flag，不重复大段代码）
      const clean = String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000);
      addSolveNote('求解结果', clean);
      state.lastAiText = result.text;
      await harvestExperience(result.text);

      // 验证闭环 + 失败时本地枚举兜底
      const vr = await runVerification(result.text);
      if (vr && !vr.verified) await runHypotheses(result.text);
      const flags = extractFlags(result.text);
      if (!vr) flags.forEach(f => recordFlag(f, 'ai', false));
      flags.forEach(f => addSolveNote('Flag', f));

      const verifiedFlags = (state.findings ? state.findings.flags : []).filter(f => f.verified);
      const resultMsg = `**🎯 自动求解结果**

**文件**: ${state.fileInfo.fileName}
**类型**: ${fileType}
${verifiedFlags.length ? `**Flag（✅已验证）**: \`${verifiedFlags[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`;

      addSystemMessage(resultMsg);
    } else if (result.aborted || /已取消/.test(result.error || '')) {
      endStreamMessage();
      addLog('info', '自动求解已停止');
      addSystemMessage('**⏹ 自动求解已停止**\n\n可再次点击"自动分析"重新开始。');
    } else {
      endStreamMessage();
      addLog('error', 'AI分析失败: ' + (result.error || '未知错误'));
      addSystemMessage('**AI分析失败**\n\n请手动分析或重试。');
    }
  } catch (err) {
    endStreamMessage();
    addLog('error', 'AI分析异常: ' + err.message);
    addLog('error', '错误详情: ' + (err.stack || '无'));
    addSystemMessage('**AI分析异常**\n\n错误: ' + err.message);
  } finally {
    state.aiBusy = false;
  }
}

// 详细分析PE/ELF（Tool Use，限制迭代次数）
async function detailedBinaryAnalysis(fileType, analysisData) {
  addLog('info', '使用Tool Use进行详细分析（最多5次工具调用）...');

  // 构建已缓存的数据摘要
  let cachedDataSummary = '';
  if (analysisData.functions) cachedDataSummary += `- 函数列表: ${Array.isArray(analysisData.functions) ? analysisData.functions.length : '已获取'}个\n`;
  if (analysisData.strings) cachedDataSummary += `- 关键字符串: 已获取\n`;
  if (analysisData.mainCode) cachedDataSummary += '- main函数: 已反编译\n';
  if (analysisData.otherFunctions && analysisData.otherFunctions.length > 0) {
    cachedDataSummary += `- 其他函数: ${analysisData.otherFunctions.map(f => f.name).join(', ')}\n`;
  }

  const detailedPrompt = `我正在分析一个CTF ${fileType}题目，初步分析没有找到flag。请使用工具进行更深入的分析。

文件路径：${state.currentFile}

## 已缓存的数据
${cachedDataSummary || '暂无'}

## 已获取的代码

### main函数
${analysisData.mainCode ? analysisData.mainCode.substring(0, 2000) : '暂无'}

## 任务
请使用工具进行分析（最多5次调用）：
1. 反编译其他可能包含flag的函数
2. 搜索更多关键字符串
3. 找出flag的生成逻辑

注意：
- 最多调用5次工具
- 优先分析可能包含flag的函数
- 找到flag后立即停止`;

  try {
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: detailedPrompt }],
      `你是CTF逆向解题专家。请使用工具分析代码并找出flag。最多调用5次工具，找到flag后立即停止。当前文件: ${state.fileInfo.fileName}`
    );

    if (result.success && result.text) {
      addLog('success', '========================================');
      addLog('success', '详细分析完成！');
      addLog('success', '========================================');

      const resultMsg = `**🔍 详细分析结果**

**文件**: ${state.fileInfo.fileName}
**类型**: ${fileType}

${result.text}`;

      addSystemMessage(resultMsg);
    } else {
      addLog('error', '详细分析失败: ' + (result.error || '未知错误'));
      addSystemMessage('**分析失败**\n\n请手动分析或重试。');
    }
  } catch (err) {
    addLog('error', '详细分析失败: ' + err.message);
    addSystemMessage('**分析失败**\n\n错误: ' + err.message);
  }
}

// 构建系统提示（连接状态取真实探测结果，不夸大）
function buildSystemPrompt() {
  const mc = state.mcpStatus;
  const st = (ok) => (ok ? '已连接' : '未连接');
  const skillsIndex = state.skills.length
    ? `\n## 可用技能（用 read_skill 工具读取全文）\n${state.skills.map(s => `- ${s.name}：${s.description}`).join('\n')}\n`
    : '';
  const wikiIndex = (state.wikiPages && state.wikiPages.length)
    ? `\n## 知识库 Wiki（可检索：用 wiki_search 找页 / wiki_read 读全文）\n${state.wikiPages.map(p => `- ${p.rel}`).join('\n')}\n遇到具体手法/踩坑（如 Frida 进程内解密、native 常量反演、IV 编码坑、多阶段 APK）先用 wiki_search 检索，命中即 wiki_read 取完整代码片段。\n`
    : '';
  let prompt = `你是 CTF 逆向解题专家，就像在 Claude Code 中一样工作。

## 当前分析文件
- 文件名：${state.currentFile ? state.fileInfo.fileName : '未选择'}
- 文件类型：${state.fileType || '未知'}
- 文件路径：${state.currentFile || '无'}
- MD5：${state.fileInfo ? state.fileInfo.md5 : '-'}
- SHA256：${state.fileInfo ? state.fileInfo.sha256 : '-'}

## 工具状态（真实探测结果）
- JEB MCP：${st(mc.jeb)}（端口16161）- 可分析APK/DEX
- IDA MCP：${st(mc.ida)}（端口13337）- 可分析PE/ELF
- Burp MCP：${st(mc.burp)} - 可搜索代理历史/取HTTP报文（Web/JS逆向）
- 安卓9模拟器：${st(mc.emulator)}
- Frida：${st(mc.frida)}

未连接的工具不要假装调用过；如需使用，先提示用户连接。

## 你的能力
1. 通过JEB MCP分析APK文件（获取Manifest、反编译类和方法）
2. 通过IDA MCP分析PE/ELF文件（反编译函数、搜索字符串）
3. 生成Frida Hook脚本
4. 生成Python解密脚本
5. 执行命令和脚本

## 规则
1. 问文件相关问题时，主动使用已连接的MCP工具分析
2. 给出具体的分析结果，不要泛泛而谈
3. 如果需要解密，生成完整的Python脚本（带注释，可直接运行）
4. 回答用代码块展示关键信息
5. 如果用户说"求出flag"，直接分析当前文件并给出答案
6. 得到 flag 时用 [FLAG]flag内容[/FLAG] 标记
7. 给出验证数据：[VERIFY]{"algo":"rc4|tea|xtea|xxtea|xor|aes_ecb|aes_cbc|des_ecb|des_cbc|des3_ecb|sm4_ecb|base64|base64_custom|node_js|custom","key":"密钥","key_encoding":"ascii|hex","ciphertext":"密文","encoding":"hex|base64|ascii","expected":"期望的flag或前缀"}[/VERIFY]，工具会本地复现验证；custom 需附 "code":"def decrypt(data,key): 完整函数"；JS逆向还原的加密函数用 node_js：附 "code":"function decrypt(input){...}"（返回字符串或Uint8Array）和 "input":"抓到的参数原文"
8. 有多个候选（算法/字节序/密钥变体）时：[HYPOTHESES][{...},{...}][/HYPOTHESES]，工具会本地枚举
9. 解题学习闭环（每次解题强制遵守）：
   - 解题前：先读上方「历史经验速查」，同类场景直接复用已验证套路与避坑点；需要完整方法论时用 read_skill 加载对应技能（ctf-reverse-binary / ctf-reverse-android / ctf-jsreverse 等）；遇到具体手法/踩坑（Frida 进程内解密、native 常量反演 key、IV 编码坑、多阶段 APK 停在首页等）先用 wiki_search 检索知识库，命中即 wiki_read 取完整代码片段。禁止无视知识库从零摸索
   - 解题中：严格按知识库流程执行，知识库已记录的坑（如 VM 题必须连常量表一起采集、mingw 入口是 _main、IV 编码不能借用 key 的编码）不得重踩
   - 解题后（无论成功失败）：回答最后输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"[/EXPERIENCE]，工具自动写入经验库；没有新收获则写"无新增经验"
${skillsIndex}${wikiIndex}${state.experience ? `\n## 历史经验速查（此前解题沉淀，同类场景优先复用）\n${state.experience.trim().split('\n').slice(-15).join('\n')}\n` : ''}

## 工具使用约定（Windows 环境，务必遵守）
- 本机是 Windows。shell 工具（bash/run_command）由 cmd.exe 执行，默认工作目录已是当前题目所在文件夹：
  - 用 Windows 风格路径（如 \`2.exe\`、\`C:\\work\\challenge\\...\`），**不要**用 \`/e/...\`、\`ls\`、\`which\`、\`cat\` 等 POSIX 写法。
  - 列目录用 \`dir\`；需要二进制分析优先用 run_python。
- 优先用专用工具而不是 shell：读文件用 read_file，找文件用 glob，搜内容用 grep，解密/爆破/数据处理一律用 run_python（本机已装 python，含 z3、androguard）。
- 需要反编译 PE 时用 IDA 无头模式：run_command 执行
  \`"<IDA目录>\\idat.exe" -A -S"脚本.py 输出.c" -c "目标.exe"\`（IDAPython 里用 ida_hexrays/ida_funcs/ida_auto）。
- 分析 APK 优先用 JEB 工具（jeb_get_manifest / jeb_get_all_classes / jeb_get_class_decompiled / jeb_get_method_decompiled 等）：
  JEB MCP 未连接时软件会**自动拉起 JEB 并加载 MCP 插件**（首次约 1~2 分钟，期间会阻塞等待），就绪后自动重试——直接调用即可，不要因为"未连接"就绕开 JEB；只有自动拉起也失败时才退回 run_python/androguard。
- 不要臆造工具结果；MCP 工具返回失败时立刻改用 run_python / 无头 IDA 这条路径继续，不要重复试探同一失败写法。

请用中文回答，像一个真正的逆向工程师一样分析问题。`;

  return prompt;
}

// ========== Kali 虚拟机函数 ==========

// 启动Kali虚拟机
async function startKaliVm() {
  addLog('info', '正在启动Kali虚拟机...');

  try {
    const result = await window.electronAPI.kaliStartVm();

    if (result.success) {
      addLog('success', result.message);
      addSystemMessage(`**Kali虚拟机启动中**

虚拟机路径: ${result.vmxPath}

请等待1-2分钟让虚拟机完全启动。

启动后可以使用以下命令：
- \`kali [命令]\` - 在Kali中执行命令
- \`kali binwalk -e firmware.bin\` - 提取固件
- \`kali strings flag\` - 提取字符串
- \`kali file mystery\` - 检查文件类型
- \`kali gdb ./binary\` - GDB调试
- \`kali strace ./program\` - 系统调用跟踪

可用工具: binwalk, strings, file, gdb, strace, ltrace, radare2, pwntools, john, hashcat...`);
    } else {
      addLog('error', '启动失败: ' + result.error);
    }
  } catch (err) {
    addLog('error', '启动错误: ' + err.message);
  }
}

// 关闭Kali虚拟机
async function stopKaliVm() {
  addLog('info', '正在关闭Kali虚拟机...');

  try {
    const result = await window.electronAPI.kaliStopVm();

    if (result.success) {
      const statusDot = document.getElementById('kali-status');
      statusDot.className = 'status-dot status-offline';
      addLog('success', result.message);
    } else {
      addLog('error', '关闭失败: ' + result.error);
    }
  } catch (err) {
    addLog('error', '关闭错误: ' + err.message);
  }
}

// 测试Kali连接
async function testKaliConnection() {
  addLog('info', '正在测试Kali连接...');

  try {
    const result = await window.electronAPI.kaliTestConnection();

    if (result.success) {
      const statusDot = document.getElementById('kali-status');
      statusDot.className = 'status-dot status-online';
      addLog('success', result.message);
      addLog('info', '系统信息: ' + result.info);
    } else {
      const statusDot = document.getElementById('kali-status');
      statusDot.className = 'status-dot status-offline';
      addLog('error', result.error);
    }
  } catch (err) {
    addLog('error', '测试错误: ' + err.message);
  }
}

// 在Kali中执行命令
// POSIX shell 单引号转义：把任意字符串安全嵌入远程 shell 命令（防 `$()`、反引号、引号逃逸）
function shq(s) {
  return "'" + String(s == null ? '' : s).replace(/'/g, "'\\''") + "'";
}

async function execKaliCommand(command) {
  addLog('info', `Kali执行: ${command}`);

  try {
    const result = await window.electronAPI.kaliExecCommand(command);

    if (result.success) {
      addLog('success', '命令执行完成');
      return result.stdout;
    } else {
      addLog('error', '执行失败: ' + (result.error || result.stderr));
      return null;
    }
  } catch (err) {
    addLog('error', '执行错误: ' + err.message);
    return null;
  }
}

// ========== 通用辅助 ==========

// 持久化 findings.json（串行化写队列，避免并发写交错导致内容回退）
let findingsWriteChain = Promise.resolve();
async function persistFindings() {
  if (!state.caseDir || !state.findings) return;
  const snapshot = JSON.stringify(state.findings, null, 2);
  const dir = state.caseDir;
  findingsWriteChain = findingsWriteChain.then(() =>
    window.electronAPI.writeFile(`${dir}/findings.json`, snapshot)
  ).catch(() => { /* 尽力而为 */ });
  await findingsWriteChain;
}

// 证据落盘：内容写入 evidence/ 文件并登记到 findings
async function caseAddEvidence(kind, label, content, ext = 'txt') {
  if (!state.caseDir) return null;
  try {
    const safe = String(label || kind).replace(/[^a-zA-Z0-9._\-\u4e00-\u9fa5]/g, '_').slice(0, 50) || kind;
    const file = `evidence/${Date.now().toString(36)}_${safe}.${ext}`;
    await window.electronAPI.writeFile(`${state.caseDir}/${file}`, String(content));
    state.findings.evidence.push({ kind, label: String(label), file, ts: new Date().toISOString() });
    await persistFindings();
    return file;
  } catch (e) {
    return null;
  }
}

// flag 登记去重
// 判断一个值是否"像 flag"（xxx{...} 形态，或明确带 flag 前缀）。
// 用于防止把 [VERIFY] 契约里的中间值（key/密文/期望值）当成 flag 记录。
function looksLikeFlag(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s || s.length < 5 || s.length > 300) return false;
  // 标准 flag 形态：prefix{...}
  if (/^[A-Za-z][A-Za-z0-9_]*\{[^}]{1,250}\}$/.test(s)) return true;
  // 带明确 flag 前缀（flag/ctf/NCTF/SCTF...）
  if (/^(flag|ctf|nctf|nssctf|sctf|dasctf|hgame|iscc|sictf|moectf|hnctf|bjdctf|gwht|picoctf|cyberpeace)/i.test(s) && /\{/.test(s)) return true;
  return false;
}

function recordFlag(flag, source, verified = false) {
  if (!state.findings) return;
  // 只记录 flag 形态的值；中间值（Stage2 key 等）不得当 flag 入库
  if (!looksLikeFlag(flag)) return;
  const existing = state.findings.flags.find(f => f.flag === flag);
  if (existing) {
    if (verified) existing.verified = true;
    if (source && !existing.source.includes(source)) existing.source += ',' + source;
  } else {
    state.findings.flags.push({ flag, verified, source: source || 'ai', ts: new Date().toISOString() });
  }
  persistFindings();
}

// ========== 验证闭环 & 本地枚举（D3/D4） ==========

// 从 AI 文本提取 [VERIFY]{...} 契约。
// 容错要点：
//  1) 闭合标签可能缺失（AI 常漏），因此不能只靠 [VERIFY]...[/VERIFY] 配对；
//  2) code 字段里含 } ]，用"配对大括号"定位 JSON 结束更稳；
//  3) 每个契约独立解析，一个坏的不影响其余。
function parseVerifyContracts(text) {
  const src = String(text || '');
  const out = [];
  const starts = [];
  const reStart = /\[VERIFY\]/gi;
  let m;
  while ((m = reStart.exec(src)) !== null) starts.push(m.index);
  for (let i = 0; i < starts.length; i++) {
    const from = starts[i] + '[VERIFY]'.length;
    const nextStart = (i + 1 < starts.length) ? starts[i + 1] : src.length;
    // 在该段内找第一个 '{'，然后用大括号配对定位 JSON 结束
    const seg = src.slice(from, nextStart);
    const braceStart = seg.indexOf('{');
    if (braceStart < 0) continue;
    let depth = 0, end = -1, inStr = false, esc = false;
    for (let k = braceStart; k < seg.length; k++) {
      const ch = seg[k];
      if (inStr) {
        if (esc) { esc = false; }
        else if (ch === '\\') { esc = true; }
        else if (ch === '"') { inStr = false; }
        continue;
      }
      if (ch === '"') { inStr = true; continue; }
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) { end = k + 1; break; } }
    }
    let jsonStr = end > 0 ? seg.slice(braceStart, end) : null;
    if (!jsonStr) {
      // 兜底：大括号没配对（被截断）→ 尝试去掉尾部闭标签后强行解析
      jsonStr = seg.slice(braceStart).replace(/\[\/VERIFY\][\s\S]*$/, '').trim();
    }
    try { out.push(JSON.parse(jsonStr)); } catch (e) { /* 坏 JSON 跳过 */ }
  }
  return out;
}

// 从 AI 文本提取 [HYPOTHESES][...][...] 候选组合（同样匹配到闭合标签）
function parseHypotheses(text) {
  const out = [];
  const re = /\[HYPOTHESES\]\s*([\s\S]*?)\s*\[\/HYPOTHESES\]/gi;
  let m;
  while ((m = re.exec(String(text || ''))) !== null) {
    try {
      const arr = JSON.parse(m[1]);
      if (Array.isArray(arr)) out.push(...arr);
    } catch (e) { /* 坏 JSON 跳过 */ }
  }
  return out;
}

// 生成"从契约到打印命中结果"的 Python 求解脚本
// 渲染层是浏览器上下文，没有 Node 的 Buffer —— 用 TextEncoder + btoa 做 UTF-8 base64
function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function buildSolvePython(attempts) {
  // 契约走 base64 内嵌：AI 的 custom code 可能含 ''' / 反斜杠等，任何引号方案都会碎
  const payload = utf8ToBase64(JSON.stringify(attempts));
  return `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auto-generated by ctf-tool: verify / hypotheses enumeration
import base64, json, re, struct, sys

ATTEMPTS = json.loads(base64.b64decode("${payload}").decode("utf-8"))

M = 0xFFFFFFFF

def to_bytes(s, enc):
    if s is None:
        return b""
    s = str(s).strip()
    if enc == "hex":
        return bytes.fromhex(re.sub(r"\\s+", "", s))
    if enc == "base64":
        return base64.b64decode(s + "=" * (-len(s) % 4))
    return s.encode("latin-1", "replace")

def iv_bytes(a):
    # IV 解析：AI 给的 iv 可能是 ASCII 明文（"ExampleVector123"）、hex、或 base64
    # （"RXhhbXBsZVZlY3RvcjEyMw=="）。逐个候选尝试，返回"解码后长度为合法块长(8/16/24/32)"
    # 的那个；显式 iv_encoding 时优先按它解。
    iv = a.get("iv", "")
    if not iv:
        return None
    if a.get("iv_encoding"):
        return to_bytes(iv, a["iv_encoding"])
    s = str(iv).strip()
    cands = []
    # 1) ASCII 原文
    try:
        cands.append(s.encode("latin-1", "replace"))
    except Exception:
        pass
    # 2) hex
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            cands.append(bytes.fromhex(s))
        except Exception:
            pass
    # 3) base64（含 +/= 或虽为字母数字但长度是4的倍数）
    b64chars = re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s)
    if b64chars and len(s) % 4 == 0:
        try:
            cands.append(base64.b64decode(s + "=" * (-len(s) % 4)))
        except Exception:
            pass
    # 优先返回长度合法的候选（AES/des 块长 8/16/24）——IV 通常 16
    for c in cands:
        if len(c) == 16:
            return c
    for c in cands:
        if len(c) in (8, 24, 32):
            return c
    # 都不合法：返回 ASCII 原文（让上层报出真实错误）
    return cands[0] if cands else None

def dec_xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

def dec_rc4(d, k):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in d:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def dec_tea(d, k, be=False):
    f = ">" if be else "<"
    v = list(struct.unpack(f + "2I", d[:8]))
    kk = list(struct.unpack(f + "4I", k[:16]))
    delta = 0x9E3779B9; s = (delta * 32) & M
    for _ in range(32):
        v[1] = (v[1] - ((((v[0] << 4) + kk[2]) ^ (v[0] + s) ^ ((v[0] >> 5) + kk[3])))) & M
        v[0] = (v[0] - ((((v[1] << 4) + kk[0]) ^ (v[1] + s) ^ ((v[1] >> 5) + kk[1])))) & M
        s = (s - delta) & M
    return struct.pack(f + "2I", *v)

def dec_xtea(d, k, be=False, rounds=32):
    f = ">" if be else "<"
    v = list(struct.unpack(f + "2I", d[:8]))
    kk = list(struct.unpack(f + "4I", k[:16]))
    delta = 0x9E3779B9; s = (delta * rounds) & M
    for _ in range(rounds):
        v[1] = (v[1] - (((((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (s + kk[(s >> 11) & 3])))) & M
        s = (s - delta) & M
        v[0] = (v[0] - (((((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (s + kk[s & 3])))) & M
    return struct.pack(f + "2I", *v)

def _mx(z, y, s, e, k, p):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))

def dec_xxtea(d, k, be=False):
    f = ">" if be else "<"
    n = len(d) // 4
    if n < 2:
        return d
    v = list(struct.unpack(f + "%dI" % n, d[: n * 4]))
    kk = list(struct.unpack(f + "4I", k[:16]))
    delta = 0x9E3779B9; s = ((6 + 52 // n) * delta) & M
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            y = v[(p + 1) % n]; z = v[p - 1]
            v[p] = (v[p] - _mx(z, y, s, e, kk, p)) & M
        y = v[1]; z = v[n - 1]
        v[0] = (v[0] - _mx(z, y, s, e, kk, 0)) & M
        s = (s - delta) & M
    return struct.pack(f + "%dI" % n, *v)

def dec_aes(d, k, mode, iv=None):
    from Crypto.Cipher import AES
    c = AES.new(k, AES.MODE_ECB) if mode == "ecb" else AES.new(k, AES.MODE_CBC, iv)
    return c.decrypt(d)

def dec_des(d, k, mode, iv=None):
    from Crypto.Cipher import DES
    c = DES.new(k, DES.MODE_ECB) if mode == "ecb" else DES.new(k, DES.MODE_CBC, iv)
    return c.decrypt(d)

def dec_des3(d, k):
    from Crypto.Cipher import DES3
    return DES3.new(k, DES3.MODE_ECB).decrypt(d)

def dec_sm4(d, k):
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    c = CryptSM4(); c.set_key(k, SM4_DECRYPT)
    return c.crypt_ecb(d)

def dec_b64(d, table=None):
    s = d.decode("utf-8", "ignore").strip() if isinstance(d, (bytes, bytearray)) else str(d).strip()
    if table:
        import string
        std = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
        s = s.translate(str.maketrans(table, std))
    s = re.sub(r"\\s+", "", s)
    return base64.b64decode(s + "=" * (-len(s) % 4))

def dec_node_js(code, inp):
    """执行 AI 还原的 JS 加密函数：code 须定义 decrypt(input)，返回字符串/字节数组"""
    import subprocess, tempfile, os
    wrapper = (
        "const __inp = process.argv[2];\\n" +
        str(code) + "\\n" +
        "let __o = decrypt(__inp);\\n" +
        "if (__o === null || __o === undefined) __o = '';\\n" +
        "if (typeof __o === 'object' && !(__o instanceof Uint8Array)) __o = JSON.stringify(__o);\\n" +
        "if (__o instanceof Uint8Array) __o = Buffer.from(__o).toString('hex');\\n" +
        "console.log(String(__o));"
    )
    fd, p = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(wrapper)
        r = subprocess.run(['node', p, str(inp)], capture_output=True, text=True, timeout=20, encoding='utf-8', errors='replace')
        if r.returncode != 0 and not r.stdout:
            raise RuntimeError((r.stderr or 'node failed')[:200])
        return (r.stdout or '').strip().encode('utf-8', 'replace')
    finally:
        try:
            os.unlink(p)
        except Exception:
            pass

FLAG_RE = re.compile(rb"(?:nctf|flag|ctf|nssctf|sctf|dasctf|hgame|iscc|sictf|moectf|hnctf|bjdctf|gwht|picoctf|cyberpeace)\\{[^}\\s]{1,200}\\}", re.I)

def printable(b):
    try:
        t = b.decode("utf-8")
        if all(ch.isprintable() or ch in "\\r\\n\\t" for ch in t):
            return t
    except Exception:
        pass
    return b.hex()

def run_one(i, a):
    algo = str(a.get("algo", "custom")).lower()
    ct = to_bytes(a.get("ciphertext", ""), a.get("encoding", "hex"))
    exp = str(a.get("expected") or "").strip().lower()
    keyspec = a.get("key")
    if a.get("key_encoding"):
        keyencs = [a["key_encoding"]]
    elif keyspec and re.fullmatch(r"[0-9a-fA-F]+", str(keyspec)) and len(str(keyspec)) % 2 == 0:
        keyencs = ["ascii", "hex"]
    else:
        keyencs = ["ascii"]
    outs = []
    for ke in keyencs:
        try:
            k = to_bytes(keyspec or "", ke)
            if algo == "custom":
                ns = {}
                exec(a["code"], ns)
                # 契约语义歧义兜底：AI 写的 decrypt(data,key) 通常期望"原始字符串"
                # （自己在函数内 base64.b64decode），而工具曾按已解码 bytes 传入 ->
                # 双重解码/str.encode 报错。这里先传原始字符串，失败再回退 bytes。
                raw_ct = a.get("ciphertext", "")
                raw_key = "" if keyspec is None else str(keyspec)
                try:
                    out = ns["decrypt"](raw_ct, raw_key)
                except Exception:
                    out = ns["decrypt"](ct, k)
            elif algo == "xor":
                out = dec_xor(ct, k)
            elif algo == "rc4":
                out = dec_rc4(ct, k)
            elif algo == "tea":
                out = dec_tea(ct, k, a.get("variant") == "be32")
            elif algo == "xtea":
                out = dec_xtea(ct, k, a.get("variant") == "be32")
            elif algo == "xxtea":
                out = dec_xxtea(ct, k, a.get("variant") == "be32")
            elif algo == "aes_ecb":
                out = dec_aes(ct, k, "ecb")
            elif algo == "aes_cbc":
                # IV 用独立编码（iv_encoding），默认自适应：显式 hex 或"看起来是hex"按 hex，否则按原文。
                # 注意：不能借用 key 的编码 ke —— 契约里 iv 可能是明文（如 ExampleVector123），
                # 若 ciphertext 是 base64 会导致 iv 被误当 base64 解出错误长度而报 Incorrect IV length。
                out = dec_aes(ct, k, "cbc", iv_bytes(a))
            elif algo == "des_ecb":
                out = dec_des(ct, k, "ecb")
            elif algo == "des_cbc":
                out = dec_des(ct, k, "cbc", iv_bytes(a))
            elif algo == "des3_ecb":
                out = dec_des3(ct, k)
            elif algo == "sm4_ecb":
                out = dec_sm4(ct, k)
            elif algo == "base64":
                out = dec_b64(ct)
            elif algo == "base64_custom":
                out = dec_b64(ct, a.get("table"))
            elif algo == "node_js":
                out = dec_node_js(a.get("code", ""), a.get("input", a.get("ciphertext", "")))
            else:
                outs.append((ke, "unknown algo " + algo)); continue
        except Exception as e:
            outs.append((ke, "ERR: " + str(e)[:120])); continue
        pt = printable(out)
        outs.append((ke, pt))
        m = FLAG_RE.search(out)
        hit = (exp and exp in pt.lower()) or bool(m)
        if hit:
            fl = m.group(0).decode("utf-8", "ignore") if m else exp
            print("[HIT] attempt=%d keyenc=%s algo=%s flag=%s" % (i, ke, algo, fl))
    for ke, pt in outs:
        print("[OUT] attempt=%d keyenc=%s: %s" % (i, ke, pt[:400]))

for i, a in enumerate(ATTEMPTS):
    try:
        run_one(i, a)
    except Exception as e:
        print("[OUT] attempt=%d FATAL %s" % (i, e))
`;
}

// 落盘并执行求解脚本，解析 [HIT]/[OUT] 行
async function runContractScript(attempts) {
  const baseDir = state.caseDir || (await getScriptsDir());
  const scriptPath = `${baseDir}/scripts/solve_enum_${Date.now().toString(36)}.py`;
  await window.electronAPI.ensureDir(`${baseDir}/scripts`);
  await window.electronAPI.writeFile(scriptPath, buildSolvePython(attempts));
  addLog('info', `[本地求解] ${attempts.length} 个尝试 -> ${scriptPath}`);
  const r = await window.electronAPI.runToolArgs(['python', scriptPath]);
  const output = ((r.stdout || '') + (r.stderr ? '\n' + r.stderr : '')).trim();
  const hits = [];
  const re = /\[HIT\][^\n]*?flag=([^\r\n]+)/gi;
  let m;
  while ((m = re.exec(output)) !== null) hits.push(m[1].trim());
  return { hits, output, path: scriptPath };
}

// 验证闭环：解析 [VERIFY] → 本地复现 → 标记 flag 验证状态
async function runVerification(aiText) {
  const contracts = parseVerifyContracts(aiText);
  if (!contracts.length) return null;
  state.lastVerifyContracts = contracts; // 供后续 Hook 主动解密复用（key/iv/ciphertext）
  addLog('info', `[验证闭环] 检测到 ${contracts.length} 个 [VERIFY] 契约，开始本地复现...`);
  const r = await runContractScript(contracts);
  if (r.output) caseAddEvidence('verify', '验证运行输出', r.output, 'log');
  // 先记录 AI 文本里提取到的候选 flag（未验证）
  extractFlags(aiText).forEach(f => recordFlag(f, 'ai', false));
  // 契约里 expected 明确是 flag 形态的，也记下来（未验证）
  contracts.forEach(c => { if (c && looksLikeFlag(c.expected)) recordFlag(String(c.expected).trim(), 'verify-contract', false); });

  // 命中值：只有"确实像 flag"的才是真 flag；其余（key/中间值）仅视为复现成功、不入 flag 库
  const flagHits = r.hits.filter(h => looksLikeFlag(h));
  const verified = r.hits.length > 0;
  // 命中是 flag → 标同值 flag 为已验证
  flagHits.forEach(h => recordFlag(h, 'verify', true));
  // 命中不是 flag（中间值/key）但复现成功 → 把契约 expected 对应的 flag 一并标验证？
  // 不能：中间值复现不等于 flag 被验证。故仅当存在 flag 形态命中时才标验证。
  const note = flagHits.length
    ? `本地复现通过（flag）：${flagHits.join(', ')}`
    : (verified ? `本地复现通过（命中中间值/密钥，非 flag）：${r.hits.join(', ')}` : `本地复现失败（${contracts.length} 个契约无命中）`);
  addSolveNote('验证', note);
  addLog(flagHits.length ? 'success' : (verified ? 'info' : 'warning'), `[验证闭环] ${note}`);
  return { verified: flagHits.length > 0, intermediateVerified: verified, hits: r.hits, flagHits };
}

// 本地枚举：解析 [HYPOTHESES] → 并行尝试全部组合 → 命中即记
async function runHypotheses(aiText, opts = {}) {
  let attempts = Array.isArray(aiText) ? aiText : parseHypotheses(aiText);
  if (!attempts.length) {
    addLog('warning', '[本地枚举] 未找到 [HYPOTHESES] 契约（AI 需按输出契约给出候选组合）');
    return null;
  }
  if (attempts.length > 16) attempts = attempts.slice(0, 16);
  addLog('info', `[本地枚举] ${attempts.length} 个候选组合（算法/密钥/字节序）...`);
  const r = await runContractScript(attempts);
  if (r.output) caseAddEvidence('hypotheses', '假设枚举输出', r.output, 'log');
  if (r.hits.length) {
    r.hits.forEach(h => recordFlag(h, 'hypotheses', true));
    addSolveNote('本地枚举命中', r.hits.join(', '));
    addLog('success', `[本地枚举] ✅ 命中: ${r.hits.join(', ')}`);
    addSystemMessage(`**🎯 本地枚举命中**\n\n${r.hits.map(h => `\`${h}\``).join('\n\n')}\n\n（算法/密钥/字节序组合由 AI 假设 + 本地并行验证得出）`);
    return { verified: true, hits: r.hits };
  }
  addLog(opts.quiet ? 'info' : 'warning', '[本地枚举] 全部候选未命中，输出已存入证据目录');
  return { verified: false, hits: [] };
}

// 解题学习闭环：从 AI 回答中收割 [EXPERIENCE]...[/EXPERIENCE] 经验块，写入经验库供下次解题自动速查
async function harvestExperience(aiText) {
  try {
    const text = String(aiText || '');
    const m = text.match(/\[(?:EXPERIENCE|经验)\]([\s\S]*?)\[\/(?:EXPERIENCE|经验)\]/i);
    if (!m || !state.appPaths) return;
    const lines = m[1].split('\n')
      .map(l => l.trim().replace(/^[-*•]+\s*/, '').replace(/^\d+[.、)]?\s*/, '').replace(/^[-*•]+\s*/, ''))
      .filter(l => l && !/^(无|无新增经验|无新增|none)$/i.test(l) && l.length > 4);
    if (!lines.length) return;
    const expPath = `${state.appPaths.userData}/experience.md`;
    const rf = await window.electronAPI.readFile(expPath);
    if (!rf || !rf.success) {
      await window.electronAPI.writeFile(expPath, '# 解题经验库（reverse-skill 进化层：AI 解题前自动速查）\n\n');
    }
    let n = 0;
    for (const l of lines.slice(0, 5)) {
      const line = `- [${new Date().toISOString().slice(0, 10)}] ${l.slice(0, 200)}\n`;
      const r = await window.electronAPI.appendFile(expPath, line);
      if (r && r.success) {
        state.experience += line;
        addSolveNote('经验沉淀', l.slice(0, 200));
        n++;
      }
    }
    if (n) {
      addLog('success', `✅ 本题经验已沉淀 ${n} 条进知识库，下次解题自动速查（避坑复用）`);
      await pruneExperience();
    }
  } catch (e) {
    addLog('warning', '经验沉淀失败: ' + e.message);
  }
}

// 经验库修剪：条目超过上限（默认 120 条）时把最旧的搬到 experience-archive.md，
// 保证"末 15 行注入"始终是最新经验、文件不会无限膨胀。旧经验不丢，可人工回捞。
async function pruneExperience(keep) {
  try {
    const KEEP = keep || 120;
    const expPath = `${state.appPaths.userData}/experience.md`;
    const rf = await window.electronAPI.readFile(expPath);
    if (!rf || !rf.success) return;
    const all = String(rf.content || '').split('\n');
    const entries = all.filter(l => l.trim().startsWith('- ['));
    if (entries.length <= KEEP) return;
    const drop = entries.slice(0, entries.length - KEEP);
    const keepSet = new Set(drop);
    const remained = all.filter(l => !keepSet.has(l));
    const archPath = `${state.appPaths.userData}/experience-archive.md`;
    const af = await window.electronAPI.readFile(archPath);
    if (!af || !af.success) {
      await window.electronAPI.writeFile(archPath, '# 经验库归档（超出保留上限的历史条目，按时间倒序追加）\n\n');
    }
    await window.electronAPI.appendFile(archPath, drop.join('\n') + '\n');
    const wf = await window.electronAPI.writeFile(expPath, remained.join('\n'));
    if (wf && wf.success) {
      state.experience = remained.join('\n');
      addLog('info', `经验库已修剪：${drop.length} 条最旧条目归档到 experience-archive.md（保留最近 ${KEEP} 条）`);
    }
  } catch (e) {
    addLog('warning', '经验库修剪失败: ' + e.message);
  }
}

// flag 提取：支持 flag/ctf/NSSCTF/SCTF/DASCTF 等常见前缀，去重
function extractFlags(text) {
  const out = [];
  const re = /\b(?:flag|ctf|nssctf|sctf|dasctf|hgame|iscc|sictf|moectf|hnctf|bjdctf|gwht|picoctf|cyberpeace)\{[^}\s]{1,200}\}/gi;
  let m;
  const s = String(text || '');
  // 过滤占位符/模板（如 flag{...}、flag{?????}、flag{xxxxxxxxx}、flag{?????????}），
  // 否则 AI 正文里的示例文本会污染 findings.flags，看起来像"解出了 flag"。
  const isPlaceholder = v => {
    const inner = String(v).replace(/^[a-z0-9_]+\{/i, '').replace(/\}$/, '').trim();
    if (!inner || inner.length < 3) return true;
    if (/^[.?？*#\-_×xX\s]+$/.test(inner)) return true;   // 纯占位符号
    if (/\.\.\.|…/.test(inner)) return true;              // 含省略号
    if (/^(.)\1*$/.test(inner)) return true;              // 单一字符重复
    if (/['"]\s*\+|\+\s*['"]|bytes\(/.test(inner)) return true;  // 代码拼接片段（如 '+bytes(s)+b'）不是 flag
    if (/[\u4e00-\u9fff]/.test(inner)) return true;       // 中文说明文字（如"flag内容"）不是 flag
    return false;
  };
  const push = v => { if (v && !isPlaceholder(v) && !out.includes(v)) out.push(v); };
  // 优先提取 [FLAG]...[/FLAG] 契约标记
  const contractRe = /\[FLAG\]([\s\S]*?)\[\/FLAG\]/gi;
  while ((m = contractRe.exec(s)) !== null) push(m[1].trim());
  while ((m = re.exec(s)) !== null) push(m[0]);
  return out;
}

// ---- IDA 结果归一化助手 ----
// IDA MCP 的 decompile 返回 { addr, code, refs }，code 为 null 表示函数不存在（名字不对）。
// 只认真正拿到的代码，避免把 {"code":null,"error":"Not found"} 当成分析结果塞给 AI。
function idaPickCode(res) {
  if (!res) return '';
  if (typeof res === 'string') return res.trim();
  if (typeof res.code === 'string' && res.code) return res.code;
  if (typeof res.text === 'string' && res.text) return res.text;
  if (typeof res.content === 'string' && res.content) return res.content;
  return '';
}

// 汇总反编译结果里引用到的地址（用于回头读取全局数据表）
function idaCollectRefAddrs(results) {
  const set = new Set();
  for (const r of (results || [])) {
    if (!r || !Array.isArray(r.refs)) continue;
    for (const ref of r.refs) {
      if (ref && typeof ref.addr === 'string') set.add(ref.addr.toLowerCase());
    }
  }
  return set;
}

// 反编译入口函数。入口名随工具链而异（mingw→_main、MSVC→main/_WinMainCRTStartup），
// 逐个候选尝试，命中「有代码」即返回；全失败时退回函数表里形如 main 的符号。
async function decompileEntryFunction(functionList) {
  const candidates = ['main', '_main', '__main', 'wmain', '_wmain', 'WinMain', '_WinMain@16',
    '_WinMainCRTStartup', '__tmainCRTStartup', '_mainCRTStartup', 'start', '_start'];
  if (Array.isArray(functionList)) {
    for (const f of functionList) {
      const n = String((f && f.name) || '');
      if (n && /^_*(win)?main(_?crtstartup)?@?\d*$/i.test(n) && !candidates.includes(n)) {
        candidates.push(n);
      }
    }
  }
  for (const name of candidates) {
    try {
      const r = await window.electronAPI.idaMcpCall('decompile', { address: name });
      if (r && r.success) {
        const code = idaPickCode(r.result);
        if (code) return { name, code, raw: r.result };
      }
    } catch (e) {
      // 换下一个候选名
    }
  }
  return null;
}

// get_bytes 返回 "0xa 0x0 0x4 ..." 形式，按小端还原成 C 的 int32 数组
function bytesToInt32LE(hexStr) {
  const nums = String(hexStr || '').split(/\s+/).map(s => parseInt(s, 16)).filter(n => !Number.isNaN(n));
  const out = [];
  for (let i = 0; i + 3 < nums.length; i += 4) {
    out.push((nums[i] | (nums[i + 1] << 8) | (nums[i + 2] << 16) | (nums[i + 3] << 24)) | 0);
  }
  return out;
}

// 从 IDA 函数列表中挑选"最可能承载本题算法"的函数。
// 规则：加解密/编解码/校验类命名强加权；VM/派发/解释器/查表类命名次加权；main 加权。
// 非语义命名（sub_/loc_ 等）不排除、只降序，保证名额未被占满时仍会被选中。
// **不能只靠 hardcoded 关键词**：vm_operad / handler / dispatcher 这类真实核心函数不在
// main|encrypt|decrypt|flag|check|verify|key 表内，会被漏掉（2.exe 题暴露的根因）。
function selectKeyFunctions(funcs, limit) {
  if (!Array.isArray(funcs)) return [];
  const max = limit || 5;
  const nameOf = f => String((f && f.name) || f || '');
  // 工具链/CRT 噪声：命名看着像加解密（__decode_pointer / ____w64_mingwthr_add_key_dtor
  // 含 decode、key），其实是运行时支撑代码，必须压权重，否则会把真正的题目函数挤出名额。
  const runtimeNoise = /mingw|_w64|w64|mingwthr|tls|tmain|crtstartup|_pre_c|exception|_lock|_unlock|atexit|_onexit|cxa|__gcc|security_cookie|findpesection|section_writable|invalidparameter|__dyn|__runtime|__main(_|$)|_p\.\d|pointer|_dtor|_ctor|__gnu|__mingw/i;
  const score = n => {
    let s = 0;
    if (/encrypt|decrypt|encode|decode|crypt|cipher|flag|key|check|verify|hash|digest|md5|sha\d?|base64|rc4|tea|aes|sm4/i.test(n)) s += 4;
    if (/vm_|operad|operand|opcode|bytecode|dispatch|handler|interp|exec|eval|table|scramble|obfuscat|translat|transform/i.test(n)) s += 3;
    if (/^_*(win)?main(_?crtstartup)?(@\d+)?$/i.test(n) || /^_?start$/i.test(n)) s += 2;
    if (runtimeNoise.test(n)) s -= 5;
    return s;
  };
  return funcs
    .slice()
    .filter(f => nameOf(f) && nameOf(f) !== '[object Object]')
    .map(f => ({ f, s: score(nameOf(f)) }))
    .sort((a, b) => b.s - a.s)
    .slice(0, max)
    .map(x => x.f);
}

// 从 JEB 类列表中挑选"最可能承载本题算法"的类。
// 规则：排除三方库（androidx/kotlin/java 等）；应用自身包内的类加权；名称含加解密/编解码/
// 校验/混淆等语义再加权。**不要只靠硬编码关键词**（如只匹配 encrypt）——Encoder、
// Scrambler、vm_operad 这类命名不在关键词表内，会被漏掉，导致核心算法代码从未进入 AI 上下文。
function selectKeyClasses(classes, packageName, mainClass, limit) {
  if (!Array.isArray(classes)) return [];
  const max = limit || 6;
  const bare = c => String(c).replace(/^L/, '').replace(/;$/, '');
  const noise = /^(androidx?|kotlin|kotlinx|java|javax|dalvik|com\/google|org\/jetbrains|org\/intellij|org\/apache|com\/squareup)\//i;
  const pkgSlash = String(packageName || '').replace(/\./g, '/');
  const mainBare = mainClass ? bare(mainClass) : '';
  // 是否为"短包名单字母类"（混淆类，如 N0/a、C/h、K0/a）：
  // 这类类的类名无任何语义，但绝大多数 CTF 题的核心校验/算法就藏在其中，
  // 必须给保底分，否则会被语义加权的常规类挤掉（APK 题暴露的根因）。
  const isObfuscated = (b) => {
    const parts = b.split('/');
    if (parts.length < 2) return false;
    const cls = parts[parts.length - 1];
    const pkgSeg = parts[parts.length - 2];
    return cls.length <= 2 && pkgSeg.length <= 3;
  };
  const score = c => {
    const b = bare(c);
    let s = 0;
    // 应用自身包的类优先（题目算法几乎总写在自己的包里）
    if (pkgSlash && b.indexOf(pkgSlash + '/') === 0) s += 2;
    // 语义加权：覆盖 encrypt/decrypt/encode/decode/crypt/scramble/obfuscate/transform/sign/hash 等
    if (/encrypt|decrypt|encode|decode|crypt|cipher|scramble|obfuscat|translat|transform|sign|hash|digest|md5|sha\d?|base64|flag|key|check|verify|util|helper|native|jni|bridge/i.test(b)) s += 3;
    // 混淆短名类保底分（低于语义命中，但高于普通无关键词类）
    if (isObfuscated(b)) s += 2;
    return s;
  };
  // "内容命中"类（由外部预扫描填充）：含关键常量/字符串的类，强制置顶
  const contentHits = (state && state._keyClassesByContent) || {};
  const hitBonus = c => (contentHits[c] || contentHits[bare(c)]) ? 100 : 0;
  return classes
    .slice()
    .filter(c => !noise.test(bare(c)))
    .filter(c => bare(c) !== mainBare)
    .sort((a, b) => (hitBonus(b) + score(b)) - (hitBonus(a) + score(a)))
    .slice(0, max);
}

// 内容命中筛查：在反编译产物/smali/资源里搜关键常量与关键字符串，
// 反查出"承载校验逻辑"的类（尤其混淆类，光看类名永远选不中）。
// 返回 { className -> hitKeyword }。无 apktool 产物时返回空对象（不影响主流程）。
async function scanKeyClassesByContent(apkPath, keywords) {
  const result = {};
  try {
    if (!apkPath) return result;
    const sepIdx = Math.max(apkPath.lastIndexOf('\\'), apkPath.lastIndexOf('/'));
    const apkDir = apkPath.substring(0, sepIdx);
    const apkName = apkPath.substring(sepIdx + 1).replace(/\.apk$/i, '');
    // 优先用 apktool 产物（smali），其次用主进程解压出的 dex 目录
    const candidates = [`${apkDir}/${apkName}_decoded/smali`, `${apkDir}/${apkName}_decoded`, `${apkDir}/${apkName}_extracted`, `${apkDir}/${apkName}_so`];
    let base = null;
    for (const c of candidates) {
      const r = await window.electronAPI.runToolArgs(['node', '-e', 'process.exit(require("fs").existsSync(process.argv[1])?0:1)', c]);
      if (r.success && base === null) { base = c; break; }
    }
    if (!base) return result;
    // 对每个关键词，在目录里搜命中的 smali/java 文件，反推类名。
    // 关键：关键词可能直接来自 APK 内容（不可信），必须走纯 Node 搜索（grep-in-dir），
    // 绝不能拼进 shell（历史实现用 powershell Select-String '${safe}'，含 $(...) 即可注入）。
    for (const kw of keywords) {
      const safe = String(kw).trim();
      if (!safe) continue;
      const r = await window.electronAPI.grepInDir(base, safe, { fixed: true, extensions: ['.smali', '.java'], maxHits: 30 });
      if (!r || !r.success || !r.hits || !r.hits.length) continue;
      for (const line of r.hits) {
        const p = String(line).replace(/:\d+:.*$/, '');
        const m = p.match(/[\\/](smali(?:_classes\d+)?)[\\/](.+?)\.smali$/i) || p.match(/[\\/](.+?)\.(java|smali)$/i);
        if (!m) continue;
        // 由文件路径构造 JEB 类签名：smali/com/example/Foo.smali -> Lcom/example/Foo;
        const rel = p.replace(/\\/g, '/');
        const i = rel.indexOf('/smali');
        const after = i >= 0 ? rel.slice(rel.indexOf('/', i + 1) + 1) : rel.split('/').slice(-3).join('/');
        const cls = 'L' + after.replace(/\.(smali|java)$/i, '') + ';';
        if (!result[cls]) result[cls] = safe;
      }
      if (Object.keys(result).length >= 40) break;
    }
  } catch (e) { /* 扫描失败不阻塞主流程 */ }
  return result;
}

// 从 AndroidManifest XML 中提取 LAUNCHER activity（含 activity-alias；而非第一个 android:name）
function extractLauncherActivity(manifestXml, packageName) {
  if (!manifestXml) return null;
  const blocks = manifestXml.match(/<activity(?:-alias)?[^>]*>[\s\S]*?<\/activity(?:-alias)?>|<activity(?:-alias)?[^>]*\/>/g) || [];
  // 优先普通 activity，其次 alias（alias 的 android:name 也是可反编译的类）
  for (const prefer of ['activity', 'activity-alias']) {
    for (const block of blocks) {
      if (!block.startsWith('<' + prefer)) continue;
      if (/android\.intent\.category\.LAUNCHER/.test(block)) {
        const nameMatch = block.match(/android:name="([^"]+)"/);
        if (nameMatch) {
          let name = nameMatch[1];
          if (name.startsWith('.')) name = (packageName || '') + name;
          return name;
        }
      }
    }
  }
  return null;
}

// 通用输入弹窗（替代 window.prompt）
let appPromptResolve = null;
function appPrompt(title, message, defaultValue = '') {
  return new Promise((resolve) => {
    appPromptResolve = resolve;
    document.getElementById('prompt-title').textContent = title;
    document.getElementById('prompt-message').textContent = message || '';
    const input = document.getElementById('prompt-input');
    input.value = defaultValue || '';
    document.getElementById('prompt-modal').style.display = 'flex';
    setTimeout(() => { input.focus(); input.select(); }, 50);
  });
}

function closeAppPrompt(ok) {
  const input = document.getElementById('prompt-input');
  const value = ok ? input.value.trim() : '';
  document.getElementById('prompt-modal').style.display = 'none';
  if (appPromptResolve) {
    appPromptResolve(value || null);
    appPromptResolve = null;
  }
}

// 脚本/WP 输出目录（配置 > 主进程提供的应用目录/scripts）
async function getScriptsDir() {
  const cfgDir = state.config && state.config.workspace && state.config.workspace.scriptsDir;
  if (cfgDir) return cfgDir;
  if (state.appPaths && state.appPaths.scriptsDir) return state.appPaths.scriptsDir;
  return 'scripts';
}

// 把当前文件信息作为消息发进聊天（工具栏回形针）
function sendFileInfoToChat() {
  if (!state.currentFile || !state.fileInfo) {
    addLog('warning', '请先选择文件');
    return;
  }
  const info = `请结合当前文件分析：${state.fileInfo.fileName}（${state.fileType}，MD5: ${state.fileInfo.md5}）`;
  addUserMessage(info);
  state.chatHistory.push({ role: 'user', content: info });
  processUserMessage(info);
}

// 清空聊天（工具栏垃圾桶）
function clearChat() {
  const chatMessages = document.getElementById('chat-messages');
  if (chatMessages) chatMessages.innerHTML = '';
  state.chatHistory = [];
  addLog('info', '聊天已清空');
}


// ========== WP / 解题报告 ==========
function addSolveNote(section, text) {
  if (!text) return;
  const note = `[${section}] ${String(text)}`;
  if (!state.solveNotes.includes(note)) state.solveNotes.push(note);
  // 双写结构化 findings（WP/证据体系的数据源）
  if (state.findings) {
    state.findings.notes.push({ section, text: String(text), ts: new Date().toISOString() });
    persistFindings();
  }
}

function safeWriteupName(name) {
  return String(name || 'challenge').replace(/[^a-zA-Z0-9._-]/g, '_').replace(/^\.+/, '') || 'challenge';
}

// 生成可复制、可保存的 Markdown WP；不依赖再次调用 AI，避免已成功解题后生成报告失败
async function generateWriteup() {
  if (!state.currentFile || !state.fileInfo) {
    addLog('warning', '请先选择并分析题目文件');
    return;
  }

  const fileName = state.fileInfo.fileName || state.currentFile.split(/[\\/]/).pop();
  const type = state.fileType || 'UNKNOWN';
  const notes = state.solveNotes.length ? state.solveNotes.map(n => '- ' + n).join('\n') : '- 暂无过程记录，请补充关键函数和动态调试结果';
  // flag 优先取结构化 findings（验证过的排最前），无 findings 时回退正则提取
  let flags = [];
  if (state.findings && state.findings.flags.length) {
    flags = state.findings.flags.slice().sort((a, b) => (b.verified ? 1 : 0) - (a.verified ? 1 : 0)).map(f => f.flag);
  } else {
    flags = extractFlags(state.solveNotes.join('\n'));
  }
  const knownFlag = flags.length ? flags[0] : '待填入已验证结果';
  const flagVerified = state.findings && state.findings.flags.some(f => f.verified && f.flag === knownFlag);
  const algoNotes = state.solveNotes.filter(n => !n.startsWith('[Flag]'));
  const evidenceLines = (state.findings && state.findings.evidence.length)
    ? state.findings.evidence.map(e => `- ${e.label} → \`${e.file}\``).join('\n')
    : '';
  const mc = state.mcpStatus;
  const wp = '# CTF 逆向题解：' + fileName + '\n'
    + '\n## 1. 题目信息\n\n'
    + '| 项目 | 内容 |\n| --- | --- |\n'
    + '| 文件名 | ' + fileName + ' |\n'
    + '| 类型 | ' + type + ' |\n'
    + '| 大小 | ' + (state.fileInfo.sizeFormatted || state.fileInfo.size || '未知') + ' |\n'
    + '| MD5 | ' + (state.fileInfo.md5 || '未知') + ' |\n'
    + '| SHA256 | ' + (state.fileInfo.sha256 || '未知') + " |\n\n"
    + '## 2. 分析环境与工具\n\n'
    + '- 静态分析：IDA Pro' + (mc.ida ? '（IDA MCP 已连接）' : '') + '\n'
    + '- Android：JEB' + (mc.jeb ? '（JEB MCP 已连接）' : '') + '\n'
    + '- 动态分析：' + (mc.frida ? 'Frida（已连接）' : 'Frida（未连接）') + ' / IDA Local Debugger\n'
    + '- 脚本验证：Python / CyberChef\n'
    + '\n## 3. 已确认的分析过程\n\n'
    + notes + '\n'
    + '\n## 4. 静态分析思路\n\n'
    + '1. 确认文件类型、架构和保护/加壳情况。\n'
    + '2. 从入口函数追踪输入处理、关键函数和比较分支。\n'
    + '3. 搜索 flag、correct、wrong、key、encrypt、decrypt 等字符串。\n'
    + '4. 反编译并记录关键函数的参数、返回值、数据流和调用关系。\n'
    + '\n## 5. 动态验证\n\n'
    + '在 IDA 中选择 Debugger → Select debugger → Local Windows debugger，使用 F2 下断点、F9 运行、F7 步入、F8 步过；'
    + '在比较函数处记录参数地址、寄存器、输入/输出缓冲区和比较长度。所有地址、密钥和密文必须以实际运行结果为准。\n'
    + '\n## 6. 算法与数据\n\n'
    + '| 项目 | 内容 |\n| --- | --- |\n'
    + '| 算法类型 | 待确认 |\n'
    + '| 密钥（ASCII/HEX） | 待动态验证 |\n'
    + '| IV/Nonce | 无或待验证 |\n'
    + '| 密文/输入 | 待提取 |\n'
    + '\n- 若使用 CyberChef：按实际算法、字节序、编码和填充方式配置 Recipe。\n'
    + (algoNotes.length ? '\n### 过程中的关键结论\n\n' + algoNotes.map(n => '- ' + n).join('\n') + '\n' : '')
    + (evidenceLines ? '\n### 证据清单\n\n' + evidenceLines + '\n' : '')
    + '\n## 7. 求解关键点\n\n'
    + '- 明确校验函数的输入和目标数据。\n'
    + '- 区分“程序中存储的密文”和“运行时生成的密文”。\n'
    + '- RC4 需要确认 KSA 的 key、初始 S 盒和 PRGA 输入长度。\n'
    + '- 不要把未验证的推断写成最终结论。\n'
    + '\n## 8. 最终结果\n\n'
    + '- Flag：' + knownFlag + (flags.length ? (flagVerified ? '（✅已验证）' : '（⚠️未验证，请复核）') : '') + '\n'
    + (flags.length > 1 ? '- 其他候选：' + flags.slice(1).join(', ') + '\n' : '')
    + '- 验证方式：使用原程序成功分支、Python 或 CyberChef 复核\n'
    + '\n> 本报告由 CTF Reverse Tool 生成。请将动态调试得到的真实地址、算法参数、密文和最终 flag 补充到对应章节。\n';

  addSystemMessage(`## WP 已生成\n\n已生成 **${fileName}** 的 Markdown 题解报告，可在"脚本预览"中复制或保存。\n\n报告包含：文件信息、分析流程、静态分析思路、动态调试步骤、算法/密钥/密文区块和求解关键点。`);

  try {
    const dir = await getScriptsDir();
    await window.electronAPI.ensureDir(dir);
    const outputPath = `${dir}/wp_${safeWriteupName(fileName)}.md`;
    const result = await window.electronAPI.writeFile(outputPath, wp);
    if (result && result.success) addLog('success', `WP已保存: ${outputPath}`);
    else addLog('warning', 'WP已生成，但自动保存失败: ' + ((result && result.error) || '未知错误'));
  } catch (err) {
    addLog('warning', 'WP已生成，但自动保存失败: ' + err.message);
  }
}

// AI 增强轨 WP：按 ctf-writeup 技能生成提交级题解（原模板轨保留：wp 命令 / 生成WP按钮）
async function generateAIWriteup() {
  if (!state.currentFile || !state.findings) {
    addLog('warning', '请先选择文件并完成分析（需要 CASE 证据数据）');
    return;
  }

  addLog('info', '[WP-AI] 按 ctf-writeup 技能生成提交级题解...（再次点击发送可停止）');

  // 读取技能规范（渐进披露：只把这一篇注入）
  let skillContent = '';
  try {
    const sk = await window.electronAPI.skillRead('ctf-writeup');
    if (sk && sk.success) skillContent = sk.content;
  } catch (e) { /* 无技能时退化为通用指令 */ }

  const evidenceList = state.findings.evidence.length
    ? state.findings.evidence.map(e => `- ${e.label} → ${e.file}`).join('\n')
    : '（暂无落盘证据）';
  const verifiedFlags = state.findings.flags.filter(f => f.verified).map(f => f.flag);
  const allFlags = state.findings.flags.map(f => `${f.flag}${f.verified ? '（✅已验证）' : '（⚠️未验证）'}`);

  const prompt = `请严格依据以下技能规范，为本题生成提交级 Writeup。

<skill>
${skillContent || '（技能未安装，按"摘要-分步解法-单一完整求解脚本-Flag"结构输出）'}
</skill>

## 题目数据
- 文件：${state.fileInfo.fileName}（${state.fileType}，MD5 ${state.fileInfo.md5}）
- Flag 候选（状态以本清单为准，不得篡改）：${allFlags.length ? allFlags.join(' ; ') : '暂无'}
- 已验证 Flag：${verifiedFlags.length ? verifiedFlags.join(', ') : '无'}
- 证据清单：\n${evidenceList}
- 解题过程记录：
${state.solveNotes.join('\n').slice(0, 2500)}
- findings.json 结构化数据：
${JSON.stringify({ meta: state.findings.meta, algorithms: state.findings.algorithms, evidence: state.findings.evidence.map(e => ({ label: e.label, file: e.file })) }, null, 2).slice(0, 3500)}

要求：
- 输出完整 Markdown（含 frontmatter），除此之外不要有任何多余说明
- 求解脚本必须是"从题目数据到打印 flag"的单一可运行脚本
- flag 的验证状态必须与上面清单一致
- 不要调用任何工具，直接输出`;

  state.aiBusy = true;
  beginStreamMessage();
  try {
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      '你是CTF题解作者。严格按技能规范写作，忠实于给定数据，不虚构。'
    );
    endStreamMessage();
    if (result.success && result.text) {
      const wp = result.text.replace(/^```(?:markdown|md)?\s*\n?/, '').replace(/\n?```\s*$/, '');

      // 保存到 CASE 目录（无 CASE 则退回 scripts 目录）
      const baseDir = state.caseDir || (await getScriptsDir());
      const outPath = `${baseDir}/writeup.md`;
      await window.electronAPI.ensureDir(baseDir);
      const wr = await window.electronAPI.writeFile(outPath, wp);
      if (wr && wr.success) addLog('success', `AI题解已保存: ${outPath}`);

      addSystemMessage(`**📝 AI 题解已生成（提交级）**\n\n按 ctf-writeup 技能规范输出，已保存 \`${outPath}\`。\n\n原模板轨仍可用：输入 \`wp\` 或点"生成WP"。`);
    } else {
      addLog('warning', 'AI题解生成失败，回退到模板轨 WP');
      addSystemMessage(`**AI 题解失败**\n\n${result.error || '未知错误'}\n\n已回退生成模板轨 WP：`);
      await generateWriteup();
    }
  } catch (err) {
    endStreamMessage();
    addLog('warning', 'AI题解异常，回退到模板轨 WP: ' + err.message);
    await generateWriteup();
  } finally {
    state.aiBusy = false;
  }
}

// ========== MCP 连接函数 ==========

// 检测当前 IDA MCP 是否暴露了动态调试类工具（断点/单步/进程/寄存器/内存）
function detectIdaDebugCapability(tools) {
  try {
    if (!Array.isArray(tools) || tools.length === 0) {
      addLog('info', '[IDA调试能力] 未取得工具列表，无法判断是否支持动态调试');
      return;
    }
    const kw = ['breakpoint', 'debug', 'debugger', 'continue', 'step', 'memory', 'register', 'attach', 'process', 'start', 'pause', 'resume', 'write_mem', 'read_mem', 'get_reg', 'set_reg', 'get_state', 'ea', 'ip', 'rip', 'regs'];
    const debugTools = tools.filter(t => {
      const name = (t && (t.name || t.title)) || '';
      const desc = (t && t.description) || '';
      return kw.some(k => name.toLowerCase().includes(k) || desc.toLowerCase().includes(k));
    });

    if (debugTools.length === 0) {
      addLog('info', '[IDA调试能力] 当前 IDA MCP 仅提供静态分析工具，不包含断点/单步/内存/寄存器控制');
      addLog('info', '[IDA调试能力] 动态调试请使用 IDA Local Windows Debugger，或本软件“生成RC4动态脚本”');
    } else {
      addLog('success', `[IDA调试能力] 检测到 ${debugTools.length} 个调试相关工具，可用自动化动态调试`);
      addLog('info', '[IDA调试能力] ' + debugTools.slice(0, 30).map(t => t.name || t.title).join(', '));
    }
  } catch (e) {
    addLog('info', '[IDA调试能力] 检测异常: ' + e.message);
  }
}

// 生成面向 RC4 题目的 Frida 自动化动态调试脚本（Windows PE，模块名/偏移可参数化）
async function generateRc4DynamicScript() {
  if (!state.currentFile) { addLog('warning', '请先选择文件'); return; }

  const defaultModule = state.fileInfo.fileName || 'target.exe';
  const moduleName = await appPrompt('Hook 参数', '目标模块名（运行中的进程名，默认当前文件名）：', defaultModule);
  if (!moduleName) { addLog('info', '已取消'); return; }
  const initRva = parseInt(await appPrompt('Hook 参数', 'rc4_init 的 RVA（IDA地址 - ImageBase，可留空跳过）：', '') || '0', 16) || 0;
  const cryptRva = parseInt(await appPrompt('Hook 参数', 'rc4_crypt 的 RVA（可留空跳过）：', '') || '0', 16) || 0;

  const script = `// RC4 自动化动态调试脚本 (Windows PE, Frida)
// 目标：找到 rc4_crypt / rc4_init，读取密钥与明文输入，观察输出
// 用法:  frida -n “${moduleName}” -l rc4_dynamic.js
'use strict';

// ---- Frida 17+ 兼容：v17 移除了 Module 静态查找 API，缺失时用新 API 重建 ----
if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (modName, expName) {
        if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(expName) : null; }
        return Module.getGlobalExportByName ? Module.getGlobalExportByName(expName) : null;
    };
}
if (typeof Module.findBaseAddress !== 'function') {
    Module.findBaseAddress = function (name) { var m = Process.findModuleByName(name); return m ? m.base : null; };
}

const MODULE_NAME = '${moduleName}';
const mod = Module.findBaseAddress(MODULE_NAME);
console.log('[*] module base = ' + mod);

// RVA 来自 IDA：RVA = IDA显示地址 - ImageBase
const RC4_INIT_RVA  = ${initRva ? '0x' + initRva.toString(16) : '0x0'};
const RC4_CRYPT_RVA = ${cryptRva ? '0x' + cryptRva.toString(16) : '0x0'};

function hookByName(name) {
  let target = Module.findExportByName(MODULE_NAME, name);
  if (target) { hookAddr(target, name); }
}

function hookAddr(addr, label) {
  Interceptor.attach(addr, {
    onEnter(args) {
      console.log('\\n[+] ' + label + ' @ ' + addr);
      // x64 前4个参数: RCX RDX R8 R9 (以 IDA 调用约定为准)
      for (let i = 0; i < 4; i++) {
        try { console.log('    arg' + i + ' = ' + args[i]); } catch (e) {}
      }
    },
    onLeave(retval) {
      console.log('    ret = ' + retval);
    }
  });
}

// 尝试按导出名 Hook（如果函数是导出的）
['rc4_crypt', 'rc4_init', 'encrypt', 'decrypt', 'main', 'memcmp', 'strcmp'].forEach(hookByName);

// 按 RVA Hook（更通用）
if (RC4_INIT_RVA)  hookAddr(mod.add(RC4_INIT_RVA), 'rc4_init (by RVA)');
if (RC4_CRYPT_RVA) hookAddr(mod.add(RC4_CRYPT_RVA), 'rc4_crypt (by RVA)');

console.log('[*] 已就绪，触发目标函数后将打印参数');
`;
  await showScript(script, 'frida');
  addLog('success', 'RC4 动态调试脚本已生成');
  addLog('info', `运行: frida -n “${moduleName}” -l rc4_dynamic.js  或点击”运行Hook”`);
}

// 生成 Windows PE 反调试绕过 Frida 脚本
async function generateWindowsAntiDebugScript() {
  const script = `// Windows PE Anti-Debug Bypass Script (Frida)
// Generated: ${new Date().toISOString()}
// 覆盖：IsDebuggerPresent / CheckRemoteDebuggerPresent / NtGlobalFlag /
//       PEB BeingDebugged / OutputDebugString / NtQueryInformationProcess
'use strict';

// ---- Frida 17+ 兼容：v17 移除了 Module 静态查找 API，缺失时用新 API 重建 ----
if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (modName, expName) {
        if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(expName) : null; }
        return Module.getGlobalExportByName ? Module.getGlobalExportByName(expName) : null;
    };
}
if (typeof Module.getExportByName !== 'function') {
    Module.getExportByName = function (modName, expName) {
        var r = Module.findExportByName(typeof expName === 'undefined' ? null : modName, typeof expName === 'undefined' ? modName : expName);
        if (!r) throw new Error('export not found');
        return r;
    };
}

const kernel32 = 'kernel32.dll';
const ntdll = 'ntdll.dll';

// ========== 1. IsDebuggerPresent -> 永远返回 0 ==========
try {
    var idp = Module.getExportByName(kernel32, 'IsDebuggerPresent');
    Interceptor.replace(idp, new NativeCallback(function () {
        console.log('[AntiDebug] IsDebuggerPresent -> 0');
        return 0;
    }, 'int', []));
} catch (e) { console.log('[-] IsDebuggerPresent: ' + e); }

// ========== 2. CheckRemoteDebuggerPresent -> 强制 pbDebuggerPresent=0 ==========
try {
    var crdp = Module.getExportByName(kernel32, 'CheckRemoteDebuggerPresent');
    Interceptor.attach(crdp, {
        onEnter: function (args) { this.pb = args[1]; },
        onLeave: function (retval) {
            if (!this.pb.isNull()) {
                this.pb.writeU32(0);
                console.log('[AntiDebug] CheckRemoteDebuggerPresent -> 0');
            }
        }
    });
} catch (e) { console.log('[-] CheckRemoteDebuggerPresent: ' + e); }

// ========== 3. PEB BeingDebugged / NtGlobalFlag 清零 ==========
try {
    var isX64 = Process.pointerSize === 8;
    var tebAddr = null;
    try { tebAddr = Module.getExportByName(ntdll, 'NtCurrentTeb')(); } catch (e) {}
    if (tebAddr) {
        var peb = Memory.readPointer(tebAddr.add(isX64 ? 0x60 : 0x30));
        // PEB.BeingDebugged 偏移 0x2
        Memory.writeU8(peb.add(0x2), 0);
        // PEB.NtGlobalFlag 偏移 x64: 0xBC / x86: 0x68
        Memory.writeU32(peb.add(isX64 ? 0xBC : 0x68), 0);
        console.log('[AntiDebug] PEB.BeingDebugged & NtGlobalFlag cleared');
    }
} catch (e) { console.log('[-] PEB patch: ' + e); }

// ========== 4. NtQueryInformationProcess(ProcessDebugPort) -> 0 ==========
try {
    var nqip = Module.getExportByName(ntdll, 'NtQueryInformationProcess');
    Interceptor.attach(nqip, {
        onEnter: function (args) {
            this.infoClass = args[1].toInt32();
            this.buf = args[2];
        },
        onLeave: function (retval) {
            // ProcessDebugPort=7, ProcessDebugObjectHandle=30, ProcessDebugFlags=31
            if (this.infoClass === 7 || this.infoClass === 30) {
                if (!this.buf.isNull()) this.buf.writePointer(ptr(0));
            } else if (this.infoClass === 31) {
                if (!this.buf.isNull()) this.buf.writeU32(1);
            }
        }
    });
    console.log('[*] NtQueryInformationProcess hooked');
} catch (e) { console.log('[-] NtQueryInformationProcess: ' + e); }

// ========== 5. OutputDebugStringA 检测绕过 ==========
try {
    Interceptor.replace(Module.getExportByName(kernel32, 'OutputDebugStringA'),
        new NativeCallback(function () {}, 'void', ['pointer']));
    console.log('[*] OutputDebugStringA neutralized');
} catch (e) {}

console.log('[*] Windows Anti-Debug Bypass 全部安装完成');
`;

  await showScript(script, 'bypass');
  addLog('success', 'Windows PE 反调试绕过脚本已生成');
  addSystemMessage('已生成 **Windows PE 反调试绕过** Frida 脚本：\n1. IsDebuggerPresent\n2. CheckRemoteDebuggerPresent\n3. PEB BeingDebugged/NtGlobalFlag\n4. NtQueryInformationProcess (DebugPort/DebugObject/DebugFlags)\n5. OutputDebugString\n\n运行: frida -n “目标.exe” -l script.js（本地附加）');
}

// 生成 APK 重打包签名批处理脚本
async function generateSmaliRepackScript() {
  if (!state.currentFile) { addLog('warning', '请先选择文件'); return; }
  const apkPath = state.currentFile.replace(/\\/g, '/');
  const baseName = (state.fileInfo.fileName || 'app').replace(/\.apk$/i, '');
  const apktoolJar = (state.config.tools && state.config.tools.apktool) || 'apktool.jar';

  const script = `@echo off
REM ============================================================
REM APK 重打包签名脚本（smali patch 后执行）
REM 目标: ${baseName}
REM 用法: 先 apktool d 解包 -> 修改 smali/资源 -> 运行本脚本
REM ============================================================
setlocal enabledelayedexpansion

set APKTOOL=${apktoolJar}
set APK=${apkPath}
set WORK=%~dp0${baseName}_repack
set KEYSTORE=%~dp0ctf.keystore
set PASS=password123

echo [1/5] 反编译 APK...
if not exist “%WORK%\\apktool_out” (
  java -jar “%APKTOOL%” d “%APK%” -o “%WORK%\\apktool_out” -f
)

echo.
echo [2/5] 请此时修改 smali/资源文件，完成后按任意键继续回编...
pause

echo [3/5] 回编 APK...
java -jar “%APKTOOL%” b “%WORK%\\apktool_out” -o “%WORK%\\patched.apk”
if errorlevel 1 ( echo 回编失败，检查 smali 语法 & exit /b 1 )

echo [4/5] 生成签名 keystore（已存在则跳过）...
if not exist “%KEYSTORE%” (
  keytool -genkeypair -keystore “%KEYSTORE%” -alias ctf -keyalg RSA -keysize 2048 ^
    -validity 10000 -storepass %PASS% -keypass %PASS% ^
    -dname “CN=CTF, OU=CTF, O=CTF, L=CTF, S=CTF, C=CN”
)

echo [5/5] 对齐 + 签名...
zipalign -f 4 “%WORK%\\patched.apk” “%WORK%\\patched_aligned.apk”
if exist “%WORK%\\patched_aligned.apk” ( set TARGET=%WORK%\\patched_aligned.apk ) else ( set TARGET=%WORK%\\patched.apk )
jarsigner -keystore “%KEYSTORE%” -storepass %PASS% -keypass %PASS% “%TARGET%” ctf

echo.
echo 完成: %TARGET%
echo 安装: adb install -r -t “%TARGET%”
pause
`;

  await showScript(script, 'repack');
  addLog('success', 'APK 重打包签名脚本已生成（bat）');
  addSystemMessage(`已生成 **重打包签名脚本**，流程：\n1. apktool d 解包\n2. 修改 smali（如去反调试、patch 校验）\n3. apktool b 回编\n4. zipalign + jarsigner 签名（自动生成 keystore）\n\n需要 JDK 的 keytool/jarsigner 和 Android SDK 的 zipalign。smali patch 完成后在脚本窗口按任意键继续。`);
}

// ========== 脚本产出（聊天即预览；自动落盘 CASE scripts/） ==========
const SCRIPT_FILENAMES = { frida: 'hook.js', decrypt: 'solve.py', bypass: 'anti_debug.js', repack: 'apk_repack.bat' };

// 生成的脚本直接在聊天中展示（代码块即可预览/复制），同时自动保存到当前 CASE 的 scripts/ 目录
async function showScript(script, type) {
  state.currentScript = { content: script, type };
  const name = SCRIPT_FILENAMES[type] || 'script.txt';
  let savedPath = '';
  try {
    const caseDir = state.caseDir;
    const baseDir = caseDir ? caseDir + '/scripts' : (await getScriptsDir());
    await window.electronAPI.ensureDir(baseDir);
    const target = baseDir + '/' + name;
    const wr = await window.electronAPI.writeFile(target, script);
    if (wr && wr.success) savedPath = target;
  } catch (e) { /* 落盘失败不影响聊天内预览 */ }
  const body = script.length > 4000 ? script.slice(0, 4000) + '\n...[已截断，完整内容见保存文件]' : script;
  const fence = '```';
  addSystemMessage(`**📄 ${name} 已生成**${savedPath ? '\n\n已保存: `' + savedPath + '`' : ''}\n\n${fence}\n${body}\n${fence}\n\n运行：Frida 类脚本点右栏"运行Hook"；解密脚本按代码块内容本地执行。`);
}

// 连接 IDA MCP（端口轮询版）：先 TCP 快探 13337 直到监听（默认最多 180s），
// 再做 MCP 握手（3 次快容错）。替代旧"固定 3 次×3s"窗口——IDA 冷启动
// （无缓存 IDB）常超过旧窗口导致假性连接失败。
async function connectIdaMcpWithWait(opts) {
  const o = Object.assign({ port: 13337, pollMs: 2000, waitMs: 180000 }, opts || {});
  const t0 = Date.now();
  addLog('info', `正在连接IDA MCP (端口: ${o.port})，冷启动最多等待 ${Math.round(o.waitMs / 1000)}s（端口轮询）...`);
  // 阶段1：TCP 端口轮询（等待插件随 IDA 自启监听）
  let listening = false;
  while (Date.now() - t0 < o.waitMs) {
    try {
      const p = await window.electronAPI.checkPort(o.port);
      if (p && p.listening) { listening = true; break; }
    } catch (e) { /* 端口未就绪，继续轮询 */ }
    if (state.flowAbortRequested) { addLog('warning', 'IDA MCP 等待已被用户中止'); return false; }
    const waited = Math.round((Date.now() - t0) / 1000);
    if (waited % 10 < Math.ceil(o.pollMs / 1000)) addLog('info', `IDA MCP 端口未就绪，已等待 ${waited}s...`);
    await new Promise(r => setTimeout(r, o.pollMs));
  }
  if (!listening) {
    setMcpStatus('ida', false);
    addLog('warning', `IDA MCP 端口 ${o.port} 等待超时（${Math.round(o.waitMs / 1000)}s），IDA 可能未启动或插件未加载`);
    return false;
  }
  addLog('success', `IDA MCP 端口 ${o.port} 已监听（等待 ${((Date.now() - t0) / 1000).toFixed(1)}s），进行 MCP 握手...`);
  // 阶段2：MCP 握手（端口通了之后一般一次成功，保留 3 次容错）
  for (let i = 0; i < 3; i++) {
    try {
      const idaResult = await window.electronAPI.testMcpConnection('ida');
      if (idaResult.success) {
        setMcpStatus('ida', true);
        addLog('success', '✅ IDA MCP 已连接');
        const toolsResult = await window.electronAPI.idaMcpAnalyze();
        if (toolsResult.success && toolsResult.tools) {
          addLog('info', `IDA MCP 可用工具: ${toolsResult.tools.length}个`);
          detectIdaDebugCapability(toolsResult.tools);
        }
        return true;
      }
    } catch (err) { /* 握手容错 */ }
    addLog('info', `IDA MCP 握手尝试 ${i + 1}/3 失败，3s 后重试...`);
    await new Promise(r => setTimeout(r, 3000));
  }
  setMcpStatus('ida', false);
  addLog('warning', 'IDA MCP 握手失败（端口已监听，插件可能仍在初始化）');
  return false;
}

// 连接IDA MCP
async function connectIdaMcp() {
  addLog('info', '正在连接 IDA MCP...');

  try {
    const result = await window.electronAPI.testMcpConnection('ida');

    if (result.success) {
      setMcpStatus('ida', true);
      addLog('success', 'IDA MCP 连接成功');

      // 获取IDA分析工具列表
      const toolsResult = await window.electronAPI.idaMcpAnalyze();
      if (toolsResult.success && toolsResult.tools) {
        addLog('info', `IDA MCP 可用工具: ${toolsResult.tools.length}个`);
        detectIdaDebugCapability(toolsResult.tools);
      }

      addSystemMessage(`**IDA MCP 已连接**

可用功能:
- 反编译函数
- 分析二进制文件
- 搜索字符串
- 获取交叉引用
- 列出全局变量

使用方法: 在对话框中输入 "ida 分析" 或 "ida 反编译 [函数名]"`);
    } else {
      setMcpStatus('ida', false);
      addLog('error', 'IDA MCP 连接失败: ' + result.error);
      addSystemMessage(`**IDA MCP 连接失败**

请确保:
1. IDA Pro 已打开
2. IDA MCP 插件已加载
3. MCP 服务运行在 127.0.0.1:13337`);
    }
  } catch (err) {
    addLog('error', 'IDA MCP 连接错误: ' + err.message);
  }
}

// 连接JEB MCP
async function connectJebMcp() {
  addLog('info', '正在启动 JEB MCP...');

  try {
    // 先探测是否已在运行（JEB 插件自带 HTTP 服务时无需独立启动）
    try {
      const probe = await window.electronAPI.testMcpConnection('jeb');
      if (probe.success) {
        setMcpStatus('jeb', true);
        addLog('success', 'JEB MCP 已在运行（16161端口探测成功）');
        addSystemMessage(`**JEB MCP 已连接**

可用功能:
- 获取Manifest/Activity/类/方法
- 反编译DEX代码

使用方法: 直接发起APK分析，或在对话框输入 "jeb 分析"`);
        return;
      }
    } catch (e) { /* 未运行，继续尝试启动 */ }

    const result = await window.electronAPI.jebMcpStart();

    if (result.success) {
      setMcpStatus('jeb', true);
      addLog('success', 'JEB MCP 启动成功');

      addSystemMessage(`**JEB MCP 已启动**

可用功能:
- 反编译DEX代码
- 分析Android应用
- 获取类和方法
- 交叉引用分析
- 重命名符号

使用方法: 在对话框中输入 "jeb 分析" 或 "jeb 反编译 [类名]"`);
    } else {
      setMcpStatus('jeb', false);
      addLog('error', 'JEB MCP 启动失败: ' + result.error);
      addLog('info', '提示：JEB MCP 通常由 JEB 插件提供（端口16161），直接启动 JEB 并加载 MCP.py 脚本即可');
    }
  } catch (err) {
    addLog('error', 'JEB MCP 启动错误: ' + err.message);
  }
}

// 连接Burp MCP（Web/JS 逆向流量分析）
async function connectBurpMcp() {
  addLog('info', '正在连接 Burp MCP...');

  try {
    const result = await window.electronAPI.testMcpConnection('burp');

    if (result.success) {
      setMcpStatus('burp', true);
      const toolNames = (result.tools && result.tools._all) || [];
      addLog('success', 'Burp MCP 连接成功');
      if (toolNames.length) addLog('info', `Burp MCP 可用工具: ${toolNames.join(', ')}`);

      addSystemMessage(`**Burp MCP 已连接**

可用能力:
- 搜索代理历史（定位加密参数请求）
- 获取 HTTP 报文详情（提取 JS / 参数）
- 由 AI 调用插件暴露的任意工具

**JS 逆向用法：** 输入 \`js逆向\` 查看五阶段流程，或直接说"分析这个站的加密参数"（需 Burp 已抓到目标流量）。`);
    } else {
      setMcpStatus('burp', false);
      addLog('error', 'Burp MCP 连接失败: ' + result.error);
      addLog('info', `请先启动 Burp 并加载 MCP 插件（监听 ${state.config.mcp && state.config.mcp.burp || 'http://127.0.0.1:9876'}）`);
      addLog('info', '可输入 "burp 启动" 拉起 Burp，或检查插件端口设置');
    }
  } catch (err) {
    addLog('error', 'Burp MCP 连接错误: ' + err.message);
  }
}

// 连接浏览器MCP
async function connectBrowserMcp() {
  addLog('info', '正在连接 浏览器 MCP...');

  try {
    const result = await window.electronAPI.testMcpConnection('browser');

    if (result.success) {
      setMcpStatus('browser', true);
      addLog('success', '浏览器 MCP 连接成功');

      addSystemMessage(`**浏览器 MCP 已连接**

可用功能:
- 网页内容获取
- 搜索引擎搜索
- CTF题目信息查找
- 技术文档查阅

使用方法:
- 输入 "搜索 [关键词]" - 搜索网页
- 输入 "打开 [URL]" - 获取网页内容
- 输入 "查 [算法名称]" - 搜索算法信息`);
    } else {
      addLog('error', '浏览器 MCP 连接失败: ' + result.error);
    }
  } catch (err) {
    addLog('error', '浏览器 MCP 连接错误: ' + err.message);
  }
}

// 关闭设置
function closeSettings() {
  document.getElementById('settings-modal').style.display = 'none';
}

// 测试 AI 连接（设置页；先保存当前表单再测，保证测的是刚填的配置）
async function testAiConnection() {
  addLog('info', '正在测试 AI 连接...');
  const btn = document.getElementById('btn-test-ai');
  if (btn) btn.disabled = true;
  try {
    await saveSettings({ keepOpen: true });
    const result = await window.electronAPI.testClaudeConnection();
    if (result.success) {
      addLog('success', '✅ ' + result.message);
      addSystemMessage('**AI 连接成功**\n\n当前配置可用（模型与密钥已生效）。');
    } else {
      addLog('error', 'AI 连接失败: ' + result.error);
      addSystemMessage(`**AI 连接失败**\n\n${result.error}\n\n请检查 Base URL / API Key / 模型名，或 CCSwitch 环境变量。`);
    }
  } catch (err) {
    addLog('error', 'AI 连接测试异常: ' + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// 保存设置（只合并表单存在的键，保留 emulator.nox_path、浏览器MCP 等未展示字段）
async function saveSettings(opts = {}) {
  const keepOpen = !!(opts && opts.keepOpen);
  const val = (id) => {
    const el = document.getElementById(id);
    return el ? el.value : null;
  };

  const newConfig = JSON.parse(JSON.stringify(state.config || {}));

  // 工具路径
  newConfig.tools = newConfig.tools || {};
  const toolFields = {
    'setting-ida': 'ida', 'setting-die': 'die', 'setting-jeb': 'jeb',
    'setting-jadx': 'jadx', 'setting-pycdc': 'pycdc', 'setting-upx': 'upx',
    'setting-apktool': 'apktool', 'setting-adb': 'nox_adb', 'setting-burp': 'burp'
  };
  for (const [id, key] of Object.entries(toolFields)) {
    const v = val(id);
    if (v !== null) newConfig.tools[key] = v;
  }

  // 模拟器
  newConfig.emulator = newConfig.emulator || {};
  const adbPort = parseInt(val('setting-adb-port'));
  const fridaPort = parseInt(val('setting-frida-port'));
  if (adbPort) newConfig.emulator.adb_port = adbPort;
  if (fridaPort) newConfig.emulator.frida_port = fridaPort;

  // AI（留空 = 沿用环境变量）
  newConfig.claude = newConfig.claude || {};
  newConfig.claude.baseUrl = val('setting-ai-baseurl') || '';
  newConfig.claude.apiKey = val('setting-ai-key') || '';
  newConfig.claude.model = val('setting-ai-model') || '';
  newConfig.claude.fastModel = val('setting-ai-fastmodel') || '';
  const maxTokens = parseInt(val('setting-ai-maxtokens'));
  if (maxTokens) newConfig.claude.max_tokens = maxTokens;

  // MCP
  newConfig.mcp = newConfig.mcp || {};
  const mcpIda = val('setting-mcp-ida');
  const mcpJeb = val('setting-mcp-jeb');
  const mcpJebScript = val('setting-mcp-jeb-script');
  const mcpBurp = val('setting-mcp-burp');
  if (mcpIda !== null) newConfig.mcp.ida = mcpIda;
  if (mcpJeb !== null) newConfig.mcp.jebMcp = mcpJeb;
  if (mcpJebScript !== null) newConfig.mcp.jebMcpScript = mcpJebScript;
  if (mcpBurp !== null) newConfig.mcp.burp = mcpBurp;

  // Kali
  newConfig.kali = newConfig.kali || {};
  const kaliHost = val('setting-kali-host');
  const kaliPort = parseInt(val('setting-kali-port'));
  const kaliUser = val('setting-kali-user');
  const kaliPass = val('setting-kali-pass');
  const kaliVmx = val('setting-kali-vmx');
  if (kaliVmx !== null) newConfig.kali.vmxPath = kaliVmx;
  if (kaliHost !== null) newConfig.kali.sshHost = kaliHost;
  if (kaliPort) newConfig.kali.sshPort = kaliPort;
  if (kaliUser !== null) newConfig.kali.sshUser = kaliUser;
  if (kaliPass !== null) newConfig.kali.sshPass = kaliPass;

  // 输出目录
  newConfig.workspace = newConfig.workspace || {};
  newConfig.workspace.scriptsDir = val('setting-scripts-dir') || '';

  try {
    await window.electronAPI.saveConfig(newConfig);
    state.config = await window.electronAPI.getConfig();
    addLog('success', '配置已保存');
    if (!keepOpen) closeSettings();
  } catch (err) {
    addLog('error', '配置保存失败: ' + err.message);
  }
}
