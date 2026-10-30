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
  flowAbortRequested: false, // 自动化流程（analyzeWebJS 轮询等）的中止标志
  platformBusy: false,  // CTF² 平台拉题流程进行中（防重入）
  platformLoop: false,  // CTF² 连续解题模式（true=自动下一题）
  platformAbort: false, // 平台循环中止标志（比 flowAbortRequested 更专一）
  platformSkipOnFail: true,  // 解不出是否跳过继续（自动测试模式=true；严格模式=false）
  platformLoopLimit: 50,     // 单轮最多尝试题数（防止无限循环）
  // ── 多阶段接力（壳/packer 题：stage1 解出 stage2 后自动切过去继续分析）──
  stageDepth: 0,            // 当前已接力层数（0=原始文件；上限 STAGE_MAX_DEPTH）
  stageContext: '',         // 前序阶段结论摘要（注入下一阶段提示词）
  stageVisitedMd5: [],      // 已分析过的文件 md5（防同一文件反复接力死循环）
  stageOriginal: null       // 接力链的起始文件名（供报告/复盘）
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
    // 裸答案（口令/序列号/裸字符串）：不是 flag 形态，但可能是真答案（平台要求自行包壳）
    answers: [],      // [{value,verified,source,evidence,ts}]
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
  setupToolEventListener();
  addLog('info', `应用启动完成，已加载 ${state.skills.length} 个技能，等待文件输入...`);
});

// 流式输出：主进程 → 渲染层逐字渲染
let streamBubble = null;   // 当前流式消息的 .message-text 元素
let streamText = '';

// ---------- 滚动跟随（stick-to-bottom）----------
// 旧行为：**每个流式 token** 都执行 scrollTop = scrollHeight。用户往上滑一次，
// 下一个 token 立刻把视口拽回底部 —— 表现就是"一直跳、根本不能向上滑"。
// 现在逻辑收口到 js/scroll-follow.js（可单测）：只在贴底时跟随；上滑脱离；
// 脱离后由"回到底部"悬浮按钮提示新内容。
const SCROLL_STICK_PX = 48;          // 距底部 48px 内视为"贴底"

function isNearBottom(el) {
  if (window.ScrollFollow) return window.ScrollFollow.isNearBottom(el);
  return el.scrollHeight - el.scrollTop - el.clientHeight <= SCROLL_STICK_PX;
}

function followScroll(el) {
  if (!el) return;
  if (window.ScrollFollow) {
    window.ScrollFollow.follow(el);
    updateScrollFab(el);
    return;
  }
  // 兜底（scroll-follow.js 未加载时保持旧语义，但只在不溢出的情况下滚）
  if (el.scrollHeight - el.scrollTop - el.clientHeight > SCROLL_STICK_PX) return;
  el.scrollTop = el.scrollHeight;
}

// 强制回到底部（用户自己发消息、或点了"回到底部"按钮时）
function scrollToBottomEl(el) {
  if (!el) return;
  if (window.ScrollFollow) window.ScrollFollow.toBottom(el);
  else el.scrollTop = el.scrollHeight;
  updateScrollFab(el);
}

function attachStickScroll(el, onStateChange) {
  if (!el) return;
  if (window.ScrollFollow) window.ScrollFollow.attach(el, onStateChange);
}

// 底部的"回到底部"悬浮按钮：脱离跟随时出现，点击后恢复跟随
function updateScrollFab(el) {
  const fab = document.getElementById('btn-scroll-bottom');
  if (!fab) return;
  const chat = document.getElementById('chat-messages');
  if (el !== chat) return;
  const stick = window.ScrollFollow
    ? window.ScrollFollow.isNearBottom(chat)
    : isNearBottom(chat);
  fab.classList.toggle('visible', !stick);
}

function setupStreamListener() {
  // 日志面板也要绑定"贴底跟随"：addLog 是高频路径（工具每一步都刷），
  // 不绑定的话用户往上看日志时会被持续追加拽回底部。
  const logPanel = document.getElementById('category-log');
  attachStickScroll(logPanel);

  if (!window.electronAPI.onClaudeStreamChunk) return;
  const chatMessages = document.getElementById('chat-messages');
  attachStickScroll(chatMessages, (el) => updateScrollFab(el));
  setupScrollFab();

  // 大流（>60000 字符）800ms 节流 + 只渲染尾部纯文本：全量 markdown 重渲染曾致分钟级 CPU 自旋
  let pending = false, lastHeavy = 0;
  window.electronAPI.onClaudeStreamChunk((delta) => {
    if (!streamBubble || !delta) return;
    streamText += delta;
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      if (!streamBubble) return;
      const big = streamText.length > 60000;
      if (big && Date.now() - lastHeavy < 800) return;   // 节流：本帧跳过
      if (big) {
        lastHeavy = Date.now();
        streamBubble.textContent = streamText.slice(-20000) + '\n▌';
      } else {
        streamBubble.innerHTML = formatMessage(streamText) + '<span class="stream-cursor">▌</span>';
      }
      followScroll(document.getElementById('chat-messages'));
    });
  });
}

function setupScrollFab() {
  const fab = document.getElementById('btn-scroll-bottom');
  if (!fab || fab._bound) return;
  fab._bound = true;
  fab.addEventListener('click', () => {
    scrollToBottomEl(document.getElementById('chat-messages'));
  });
}

// ---------- 工具执行步骤（AI 调用工具时可见的进度）----------
// 为什么需要：长任务里 AI 可能连续跑 20+ 个工具、几分钟不出文字，
// 旧 UI 只有一句"分析中"，用户无法判断是卡死还是在工作。
// 现在每个工具调用渲染成一行：⏳ 正在反编译 main → ✅ 完成（3.2s）/ ❌ 失败。
const toolRows = new Map();   // tool_use_id -> element

function toolLabelOf(info) {
  return info.label || info.tool || '工具';
}

function startToolRow(info) {
  let container = document.getElementById('tool-steps');
  if (!container) {
    const chat = document.getElementById('chat-messages');
    if (!chat) return;
    container = document.createElement('div');
    container.id = 'tool-steps';
    container.className = 'tool-steps';
    chat.appendChild(container);
  }
  const row = document.createElement('div');
  row.className = 'tool-step tool-step-running';
  row.innerHTML = `<span class="tool-step-icon"><i class="fas fa-spinner fa-spin"></i></span>`
    + `<span class="tool-step-label"></span><span class="tool-step-meta"></span>`;
  row.querySelector('.tool-step-label').textContent = toolLabelOf(info);
  row._startedAt = Date.now();
  container.appendChild(row);
  // DOM 上限：深度求解一轮 60+ 次工具调用，已完成行长期滞留只增不减（同日志面板问题）。
  // 只裁已完成/失败行，运行中的永不裁。
  if (container.children.length > 400) {
    let removed = 0;
    while (container.firstChild && removed < 100) {
      const first = container.firstChild;
      if (first.classList && first.classList.contains('tool-step-running')) break;
      container.removeChild(first);
      removed++;
    }
  }
  if (info.id) toolRows.set(info.id, row);
  followScroll(document.getElementById('chat-messages'));
}

function finishToolRow(info, failed) {
  const row = info.id ? toolRows.get(info.id) : null;
  if (!row) return;
  const ms = Date.now() - (row._startedAt || Date.now());
  row.classList.remove('tool-step-running');
  row.classList.add(failed ? 'tool-step-error' : 'tool-step-done');
  row.querySelector('.tool-step-icon').innerHTML = failed
    ? '<i class="fas fa-circle-xmark"></i>'
    : '<i class="fas fa-circle-check"></i>';
  const meta = row.querySelector('.tool-step-meta');
  if (failed) {
    meta.textContent = String(info.error || '失败').slice(0, 120);
    meta.title = String(info.error || '');
  } else {
    meta.textContent = (ms / 1000).toFixed(1) + 's'
      + (info.chars ? ` · ${info.chars} 字符` : '');
  }
  toolRows.delete(info.id);
  followScroll(document.getElementById('chat-messages'));
}

function resetToolSteps() {
  const el = document.getElementById('tool-steps');
  if (el) el.remove();
  toolRows.clear();
}

function setupToolEventListener() {
  if (!window.electronAPI.onClaudeToolEvent) return;
  window.electronAPI.onClaudeToolEvent((info) => {
    if (!info || !info.phase) return;
    if (info.phase === 'start') startToolRow(info);
    else if (info.phase === 'done') finishToolRow(info, false);
    else if (info.phase === 'error') finishToolRow(info, true);
    else if (info.phase === 'gate') addLog('warning', info.message || info.label || '闸触发');
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
  // 新的回答开始：用户通常想看到它（若正在读历史，按钮仍提示，不强拽）
  followScroll(chatMessages);
}

function endStreamMessage() {
  if (streamBubble) {
    // 超长流的收尾格式化本身是 O(n)：>30 万字符时降级为纯文本，避免结束帧再卡一次
    if (streamText.length > 300000) {
      streamBubble.textContent = streamText;
    } else {
      streamBubble.innerHTML = formatMessage(streamText || '（无输出）');
    }
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
    // 平台批量解题的「已处理」清单（config.platform.skipChallenges）——
    // 记录**已解出**或人工明确指定跳过的题，连续模式会跳过它们。
    // 未解出的题不会自动写入（见批量循环里的持久化逻辑），以便下次重试。
    // 字段名沿用 skipChallenges 以兼容旧配置。
    const skip = state.config && state.config.platform && state.config.platform.skipChallenges;
    if (Array.isArray(skip) && skip.length) {
      state.platformSkipSet = new Set(skip.map(s => String(s)));
      addLog('info', '[平台] 已处理清单（' + skip.length + ' 题，批量时跳过）: ' + skip.join(', '));
    }
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
  // 会话恢复（D1）：从最近一次中断的对话继续
  const resumeBtn = document.getElementById('btn-resume-session');
  if (resumeBtn) resumeBtn.addEventListener('click', resumeLastSession);

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
  // （v1.5.0：平台拉题按钮已移除——CTF² 自动解题流水线为内部测试功能，不随版本发布；
  //   solveOneFromPlatform/solveOnePlatformRound 保留在代码中，可经控制台调用）

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
  const testCtf2Btn = document.getElementById('btn-test-ctf2');
  if (testCtf2Btn) testCtf2Btn.addEventListener('click', testCtf2Connection);

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
// opts.stageContext：多阶段接力时由上一阶段传入的结论摘要（注入下一阶段提示词）。
// opts.isHandoff：true 表示这是接力来的新阶段（不清 stageContext、不改 stageDepth）。
async function analyzeFile(filePath, opts = {}) {
  addLog('info', `正在分析文件: ${filePath}`);
  state.lastBlockedReason = '';

  try {
    // 检测文件类型
    addLog('info', '步骤1: 检测文件类型...');
    let typeResult = await window.electronAPI.detectFileType(filePath);
    // 杀软短暂持锁重试（实测 CrackMe4：解压刚落盘时 Defender 实时扫描会持锁几秒，
    // 报"文件存在但无法读取"；等 2.5s 同路径重读一次通常即可通过，避免整轮被
    // blocked-by-av 吞掉。只重试一次，仍是 AV 拦截才按原分支处理）。
    if (typeResult && typeResult.success === false && typeResult.blocked && !opts.noAvRetry) {
      addLog('info', '文件被杀软短暂锁定，2.5 秒后重试读取一次...');
      await new Promise(r => setTimeout(r, 2500));
      typeResult = await window.electronAPI.detectFileType(filePath);
      if (typeResult && typeResult.success) {
        addLog('success', '重试读取成功（锁定已解除）');
      }
    }
    addLog('info', '类型检测结果: ' + JSON.stringify(typeResult));

    if (!typeResult.success) {
      // 杀软拦截与"文件不存在"必须区分：前者是环境阻断（不是题目难度，也不是工具缺陷），
      // 后者说明下载/解压链路坏了。混在一起会让失败统计失真。
      if (typeResult.blocked) {
        addLog('error', '文件被系统阻止读取（杀软/Defender 实时保护）: ' + typeResult.error);
        state.lastBlockedReason = typeResult.error;
        addSystemMessage(`**⚠️ 无法读取附件（环境阻断）**\n\n${typeResult.error}`);
      } else {
        addLog('error', '文件类型检测失败: ' + typeResult.error);
        state.lastBlockedReason = '';
      }
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
    // 换题清空"待保存经验"：暂存区属本题 AI 输出，跨题残留会让上一题的经验
    // 在下一题被误入库/误注入（且 pendingExperience 纯内存、不持久化）。
    state.pendingExperience = [];
    // 换题同时清 lastAiText 与平台上下文：否则上一题的 AI 结论会串进
    // 本题的失败档案（recordFailure）/复盘（postSolveReview）/静态结论注入。
    state.lastAiText = '';
    // 平台流程会在 analyzeFile 之后立即恢复这三项（见 restorePlatformContext）；
    // 平台题面是最高价值的检索目标（实测 22/22 份会话 prompt 里完全没有它），
    // 所以平台/zip 路径要能 opt-out 这次清理。
    if (!opts.keepPlatformContext) {
      state._platformChallenge = null;
      state._platformChallengeDesc = '';
      state._platformFiles = null;
    }
    // 扫描结果按题缓存：换题必须清空，否则上一题的反证证据会串到本题
    state.lastAlgScan = null;
    // 多阶段接力：接力来的新阶段保留上一阶段摘要；非接力（拖入/选择/平台新题）则清空接力态。
    if (opts.isHandoff) {
      state.stageContext = String(opts.stageContext || state.stageContext || '');
    } else {
      state.stageContext = '';
      state.stageDepth = 0;
      state.stageVisitedMd5 = [];
      state.stageOriginal = null;
    }

    // 同步工作目录给主进程（AI 的 glob/grep 搜索根）
    // 一并传文件与类型：ida_dbg 用它判断 PE(local Windows debugger) 还是 ELF(remote gdb)
    try {
      const dir = filePath.replace(/[\\/][^\\/]+$/, '');
      await window.electronAPI.setWorkdir(dir, filePath, state.fileType);
    } catch (e) { /* 可选 */ }

    // 创建 CASE 证据目录（本题为一个小案件：evidence/scripts/timeline）
    try {
      const cs = await window.electronAPI.caseInit(infoResult.fileName, infoResult.md5);
      if (cs && cs.success) {
        state.caseDir = cs.caseDir;
        state.caseName = cs.caseName;
        state.findings = newFindings(infoResult, typeResult.fileType);
        await persistFindings();
        // 主进程没有 state.caseDir：run_python 的 cwd 与产物登记都靠这份副本
        try { await window.electronAPI.setCaseDir(cs.caseDir); } catch (e2) { /* 可选 */ }
        addLog('info', `CASE 目录: ${cs.caseDir}`);
      }
    } catch (e) { /* CASE 失败不阻塞主流程 */ }

    // 更新UI
    updateFileInfoUI(typeResult, infoResult);
    enableActionButtons();

    addLog('success', `文件识别成功: ${typeResult.fileType} - ${typeResult.description}`);
    addLog('info', `MD5: ${infoResult.md5}`);
    addLog('info', `SHA256: ${infoResult.sha256}`);

    // 多阶段接力：登记已分析文件的 md5（防同一文件反复接力），接力时提示来源
    if (infoResult.md5 && !state.stageVisitedMd5.includes(infoResult.md5)) {
      state.stageVisitedMd5.push(infoResult.md5);
    }
    if (opts.isHandoff) {
      addLog('info', `[阶段接力] 已切入第 ${state.stageDepth} 层：${infoResult.fileName}`);
      addSystemMessage(`**🔄 阶段接力（第 ${state.stageDepth}/${STAGE_MAX_DEPTH} 层）**\n\n已从上一阶段切换到：\`${infoResult.fileName}\`\n\n- 类型: ${typeResult.fileType}（${typeResult.description}）\n- 上一阶段结论已保留并注入本题上下文`);
    }

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

// ========== CTF²（DASCTF Agent Arena）平台：拉一道逆向题 → 本地解题 → 提交 flag ==========
// 设计：平台工具只由本流水线（前端）调用，不注册进 AI 工具定义 → AI 无法自主提交/改靶机。
// 依赖：设置页填 CTF² Token；附件下载目录默认 E:\ctf\pratice（可配置）。

// 判断一道平台题是否属于"逆向"（字段名容错：category/tags/type/challenge_type 都可能）
function ctf2IsReverse(ch) {
  if (!ch || typeof ch !== 'object') return false;
  const RE = /^(reverse|re|reversing|逆向)$/i;
  const cands = [ch.category, ch.type, ch.challenge_type, ch.tag, ch.direction];
  for (const c of cands) { if (c && RE.test(String(c).trim())) return true; }
  const tags = ch.tags || ch.tag_list || ch.categories;
  if (Array.isArray(tags)) { for (const t of tags) { if (t && RE.test(String(t).trim())) return true; } }
  return false;
}

// 从平台返回里尽量取出题目数组（字段名容错）
function ctf2ExtractList(res) {
  if (!res) return [];
  if (Array.isArray(res)) return res;
  for (const k of ['challenges', 'items', 'list', 'data', 'results']) {
    if (Array.isArray(res[k])) return res[k];
  }
  // 有些 MCP 返回 result.content[].text 是 JSON 字符串，unwrap 后可能是字符串
  if (typeof res === 'string') {
    try { const j = JSON.parse(res); return ctf2ExtractList(j); } catch (e) { return []; }
  }
  return [];
}

function ctf2ChallengeId(ch) {
  return ch && (ch.id ?? ch.challenge_id ?? ch.challengeId ?? ch.uuid ?? ch.slug);
}
function ctf2ChallengeName(ch) {
  return ch && (ch.name || ch.title || ch.challenge_name || ('#' + ctf2ChallengeId(ch)));
}
// 是否已解（字段容错）
function ctf2IsSolved(ch) {
  if (!ch) return false;
  return !!(ch.solved || ch.is_solved || ch.solve_status === 'solved' || ch.status === 'solved' || ch.passed);
}

// 平台笔记（凭据页规则要求：用 ctf2_agent_log_note 记录 plan/finding/result，
// 供 owner 在平台侧回看解题回放）。失败不阻塞主流程。
async function ctf2LogNote(kind, content) {
  try {
    const body = String(content || '').slice(0, 1800);   // note_max_chars=2000，留余量
    if (!body.trim()) return;
    await window.electronAPI.ctf2McpCall('ctf2_agent_log_note', { kind, content: body });
  } catch (e) { /* 笔记失败不影响解题 */ }
}

// 主流程：拉一道未解逆向题 → 下载附件 → 解题 → 提交 flag
// 平台真实契约（2026-10-14 实测 tools/list schema）：
//   - 列题必须带 practice_ground_id；分类字段 category，逆向的值是 "REVERSE"（大写）
//   - 附件参数是 file_id；提交必须带 confirmation:true
// 返回 { ok, submitted, challenge, note }；ok=false 时 note 说明原因。
async function solveOnePlatformRound(opts = {}) {
  const dlDir = (state.config && state.config.platform && state.config.platform.downloadDir) || 'E:\\ctf\\pratice';
  try {
    addLog('info', '========================================');
    addLog('info', '[平台] 从 CTF² 拉取一道未解的逆向题');
    addLog('info', '========================================');

    // 0) 探活
    const probe = await window.electronAPI.ctf2Probe();
    if (!probe || !probe.success) {
      addLog('error', '平台连接失败: ' + ((probe && probe.error) || '未知'));
      addSystemMessage(`**平台连接失败**\n\n${(probe && probe.error) || '未知'}\n\n请在设置页填写 CTF² 地址与 Token（平台「凭证」页创建）。`);
      return { ok: false, note: 'connect-failed' };
    }
    addLog('success', '✅ 平台连接成功（whoami 通过）');

    // 1) 发现练习场（列题必须带 practice_ground_id）
    // ⚠️ 只取第一个场会漏掉绝大部分题：实测平台有 6 个场，逆向题主要分布在
    // BUUCTF（537 道，Easy 居多）和日常练习场（8 道）；只查第一个场只剩 3 道。
    addLog('info', '[1/6] 发现练习场...');
    const groundsRes = await window.electronAPI.ctf2McpCall('ctf2_list_practice_grounds', { limit: 50 });
    if (groundsRes && groundsRes.success === false) { addLog('error', '列练习场失败: ' + groundsRes.error); return { ok: false, note: 'grounds-failed' }; }
    const groundsRaw = (groundsRes && groundsRes.result !== undefined) ? groundsRes.result : groundsRes;
    const allGrounds = ctf2ExtractList(groundsRaw).filter(g => g && g.is_active !== false);
    if (!allGrounds.length) { addLog('error', '未发现任何练习场'); return { ok: false, note: 'no-grounds' }; }
    // 练习场优先级：显式 preferGround > 题量降序（大题库 Easy 多，先跑能快速拿到成功率）
    // ⚠️ 之前按"发现顺序"取第一个场 → 永远先跑 8 道题的日常场（全是 Medium/Hard），
    // 500+ 的 BUUCTF Easy 题永远轮不到（实测：连续两轮都卡在 not-baby-parallelism）。
    const preferName = (state.config && state.config.platform && state.config.platform.preferGround) || '';
    const ordered = allGrounds.slice().sort((a, b) => {
      if (preferName) {
        const pa = String(a.name || '').includes(preferName) ? 1 : 0;
        const pb = String(b.name || '').includes(preferName) ? 1 : 0;
        if (pa !== pb) return pb - pa;
      }
      return (Number(b.challenge_count) || 0) - (Number(a.challenge_count) || 0);
    });
    addLog('info', `发现 ${allGrounds.length} 个练习场：${allGrounds.map(g => `${g.name}(${g.challenge_count || '?'})`).join('、')}`);

    // 逐个练习场找一个有未解逆向题的（拉不到就换下一个）
    let ground = null, groundId = null, listRaw = null, listTotal = 0;
    // 定向模式下，点名题目可能不在"题量最大的那个场"里（实测 PlutoChat /
    // not-baby-parallelism 在 BUUCTF 11 页里都没有，但存在于其它练习场）。
    // 因此先记下所有场的首页结果，点名题命中哪个场就用哪个场。
    const groundFirstPage = new Map();
    const wantNamesForGround = (opts && Array.isArray(opts.wantNames) ? opts.wantNames : []).map(String);
    for (const g of ordered) {
      try {
        const lr = await window.electronAPI.ctf2McpCall('ctf2_list_practice_challenges', {
          practice_ground_id: g.id, category: 'REVERSE', unsolved_only: true, limit: 50, page: 1
        });
        if (lr && lr.success === false) continue;
        const parsed = ctf2ParsePayload((lr && lr.result !== undefined) ? lr.result : lr);
        const arr = ctf2ExtractList(parsed);
        const cands = arr.filter(ch => ctf2IsReverse(ch) && !ctf2IsSolved(ch) && ch.has_attachments);
        groundFirstPage.set(String(g.id), { parsed, arr, cands });
        addLog('info', `  场「${g.name}」：返回 ${arr.length} 条（total=${parsed && parsed.total}），可解 ${cands.length} 道`);
        // 定向优先：该场首页就命中点名题 → 直接选这个场
        if (wantNamesForGround.length) {
          const hitHere = arr.some(ch => wantNamesForGround.some(w =>
            String(ch.name) === w || String(ch.name).toLowerCase() === w.toLowerCase()));
          if (hitHere) {
            ground = g; groundId = g.id; listRaw = parsed; listTotal = parsed && parsed.total;
            addLog('info', `[定向] 点名题在「${g.name}」场首页，改用该场`);
            break;
          }
        }
        if (cands.length && !ground) { ground = g; groundId = g.id; listRaw = parsed; listTotal = parsed && parsed.total; }
      } catch (e) { /* 换下一个场 */ }
    }
    if (!ground) {
      addSystemMessage('**所有练习场都没有带附件的逆向未解题**');
      addLog('warning', '所有练习场均无候选');
      return { ok: false, note: 'no-candidates' };
    }
    addLog('info', `选定练习场: ${ground.name}（共 ${listTotal || '?'} 道逆向题）`);

    // 2) 列逆向未解题（已在上一步拉取；此处只做过滤）
    addLog('info', '[2/6] 过滤可解题目...');
    // 分页：单页固定 50 条，537 道要 11 页。只取第 1 页会永远卡在同样的 50 道题上
    //（实测：BUUCTF 537 道逆向题，page=1 永远是 easyre 开头那 50 道）。
    // 用"已尝试题数"推算该翻到第几页——外部驱动会持续累加这个集合。
    let all = ctf2ExtractList(listRaw);
    const excludeSetEarly = (opts && opts.exclude instanceof Set) ? opts.exclude : new Set();
    const attemptedCount = excludeSetEarly.size;
    // 定向验证要跨页找题：点名的题可能不在当前页，逐页扫到命中或扫完为止。
    const wantNamesEarly = (opts && Array.isArray(opts.wantNames) ? opts.wantNames : [])
      .map(s => String(s || '').trim()).filter(Boolean);
    if (wantNamesEarly.length) {
      const found = new Map();
      // 先在本场逐页找，找不到再换其它练习场（点名题可能不在题量最大的场里）。
      const searchGrounds = [ground, ...ordered.filter(g => String(g.id) !== String(groundId))];
      let pagesScanned = 0;
      for (const g of searchGrounds) {
        if (found.size >= wantNamesEarly.length) break;
        const meta = groundFirstPage.get(String(g.id));
        const maxPageS = Math.ceil(((meta && meta.parsed && meta.parsed.total) || (g === ground ? listTotal : 0) || 0) / 50) || 1;
        for (let pg = 1; pg <= maxPageS; pg++) {
          if (found.size >= wantNamesEarly.length) break;
          try {
            const pr = await window.electronAPI.ctf2McpCall('ctf2_list_practice_challenges', {
              practice_ground_id: g.id, category: 'REVERSE', unsolved_only: true, limit: 50, page: pg
            });
            const parsed2 = ctf2ParsePayload((pr && pr.result !== undefined) ? pr.result : pr);
            const arr2 = ctf2ExtractList(parsed2);
            if (!arr2.length) break;
            pagesScanned++;
            for (const w of wantNamesEarly) {
              const hit = arr2.find(ch => String(ch.name) === w)
                || arr2.find(ch => String(ch.name).toLowerCase() === w.toLowerCase());
              if (hit && !found.has(w)) found.set(w, { ch: hit, ground: g });
            }
            // 命中题来自别的场：把 ground 切到那个场（同一轮只能用一个 groundId 取详情）
            if (found.size && g !== ground) {
              ground = g; groundId = g.id; listRaw = parsed2; listTotal = parsed2 && parsed2.total;
              addLog('info', `[定向] 点名题在「${g.name}」，已切换练习场`);
            }
          } catch (e) { /* 该页拉取失败，继续下一页 */ }
        }
      }
      if (found.size) {
        // 把命中的题并入 all（去重），后续 candidates 就能选到它们
        const extras = [...found.values()].map(v => v.ch).filter(ch => !all.some(x => String(x.id) === String(ch.id)));
        all = all.concat(extras);
        addLog('info', `[定向] 扫 ${pagesScanned} 页找到 ${found.size}/${wantNamesEarly.length} 道：${[...found.values()].map(v => v.ch.name).join('、')}`);
      } else {
        addLog('warning', `[定向] 扫描 ${pagesScanned} 页（含 ${searchGrounds.length} 个练习场）均未找到点名题目：${wantNamesEarly.join('、')}`);
      }
    }
    if (attemptedCount > 0 && !wantNamesEarly.length) {
      const wantPage = Math.floor(attemptedCount / 50) + 1;
      const maxPage = Math.ceil((listTotal || 0) / 50) || 1;
      if (wantPage <= maxPage && wantPage > 1) {
        try {
          const pr = await window.electronAPI.ctf2McpCall('ctf2_list_practice_challenges', {
            practice_ground_id: groundId, category: 'REVERSE', unsolved_only: true, limit: 50, page: wantPage
          });
          const parsed2 = ctf2ParsePayload((pr && pr.result !== undefined) ? pr.result : pr);
          const arr2 = ctf2ExtractList(parsed2);
          if (arr2.length) { all = arr2; addLog('info', `翻页到 page=${wantPage}（${arr2.length} 条，已尝试 ${attemptedCount}）`); }
        } catch (e) { /* 翻页失败就用第 1 页 */ }
      }
    }
    // 跳过清单：本地已人工解出/不想自动跑的题（state.platformSkipSet，UI 或控制台预置）
    const skipSet = (state.platformSkipSet instanceof Set) ? state.platformSkipSet : new Set();
    // 本轮已尝试过的题（失败后加入）：避免解不出时无限拉同一道题
    const excludeSet = (opts && opts.exclude instanceof Set) ? opts.exclude : new Set();
    // ⚠️ 跨进程去重：自动测试每题重启工具，内存里的 exclude 会丢 → 同一题被反复拉取
    //（实测：not-baby-parallelism 连续跑了两轮）。失败/已尝试的题写进 config 持久化，
    // 下次启动仍然排除；解题成功或用户手动清空时才移除。
    const persistedSkip = new Set(
      ((state.config && state.config.platform && state.config.platform.skipChallenges) || []).map(String)
    );
    const candidates = all.filter(ch => ctf2IsReverse(ch) && !ctf2IsSolved(ch) && ch.has_attachments
      && !skipSet.has(String(ch.name)) && !excludeSet.has(String(ch.name))
      && !persistedSkip.has(String(ch.name)));
    const allSkipped = [...new Set([...skipSet, ...excludeSet, ...persistedSkip])];
    const skippedNote = allSkipped.length ? `（已跳过 ${allSkipped.join(', ')}）` : '';
    addLog('info', `平台返回 ${all.length} 道逆向未解题，其中带附件 ${candidates.length} 道${skippedNote}` + (candidates.length ? `：${candidates.map(c => c.name).join(', ')}` : ''));

    // 定向验证：调用方可以点名要跑哪几道（P1 VERIFY_FAIL 复查、回归测试都用它）。
    // 语义是「优先」而非「只跑」——点名的题不在本页时，会继续往后翻页找，
    // 找到就提到队首；全都不在本场/本页则退回普通选法，保证批量流程不被打断。
    const wantNames = (opts && Array.isArray(opts.wantNames) ? opts.wantNames : [])
      .map(s => String(s || '').trim()).filter(Boolean);
    if (wantNames.length) {
      // 点名题不受 skip/exclude 限制：定向复验就是要重跑那些"上次失败"的题
      const pool = all.filter(ch => ctf2IsReverse(ch) && ch.has_attachments);
      const hit = wantNames.map(w => pool.find(ch => String(ch.name) === w)
        || pool.find(ch => String(ch.name).toLowerCase() === w.toLowerCase())).filter(Boolean);
      if (hit.length) {
        // 注意：不能写成 `unshift(...hit.filter(ch => !candidates.includes(ch)))` ——
        // 已在候选里的点名题会被去重过滤掉，等于"点名了却没排到队首"
        //（实测：日志显示「点名优先: QuiZow」却选中了 cnbragon）。
        // 正确做法是重建候选顺序：点名题在前（按点名顺序），其余保持原序。
        const hitIds = new Set(hit.map(c => String(c.id)));
        const rest = candidates.filter(ch => !hitIds.has(String(ch.id)));
        candidates.length = 0;
        candidates.push(...hit, ...rest);
        addLog('info', `[定向] 点名优先：${hit.map(c => c.name).join('、')}`);
      } else {
        addLog('warning', `[定向] 本页未找到点名题目（${wantNames.join('、')}），按普通顺序继续`);
      }
    }

    if (!candidates.length) {
      addSystemMessage(`**无带附件的逆向未解题**\n\n练习场「${ground.name || groundId}」返回 ${all.length} 道逆向未解题，但均无附件（可能需要靶机）。当前流水线只处理带附件的题。`);
      addLog('warning', '无带附件的逆向未解题');
      return { ok: false, note: 'no-candidates' };
    }

    // 3) 取第一道，拿详情 + 附件清单
    const ch = candidates[0];
    const cid = ch.id;
    addLog('info', `[3/6] 选定题目: ${ch.name}（难度 ${ch.difficulty || '?'}，${ch.friendly_id || cid}）`);
    // 平台笔记：记录"开始解这道题"（凭据页要求留下可回看的 plan）
    ctf2LogNote('plan', `开始分析 ${ch.name}（${ch.difficulty || '?'}）· 文件类型待识别`);
    state._platformChallenge = ch;   // 供失败提示注入/复盘取题名
    const detailRes = await window.electronAPI.ctf2McpCall('ctf2_get_practice_challenge', { challenge_id: cid, practice_ground_id: groundId });
    if (detailRes && detailRes.success === false) { addLog('error', '取题目详情失败: ' + detailRes.error); return { ok: false, note: 'detail-failed', challenge: { id: cid, name: ch.name } }; }
    const detail = ctf2ParsePayload((detailRes && detailRes.result !== undefined) ? detailRes.result : detailRes);
    try { addLog('info', '[平台] 题目详情（诊断，节选）: ' + JSON.stringify(detail).slice(0, 1500)); } catch (e) {}
    // 实测详情外面包了一层 { challenge: {...}, ... }（诊断日志证实）——解一层，并容错多层包裹
    const cDetail = ctf2ParsePayload((detail && (detail.challenge || detail.data)) || detail);
    await caseAddEvidence('platform_challenge', '平台题目详情', JSON.stringify(detail, null, 2), 'json');
    // 题目描述（官方用法说明，如 "Run with pppp -n ..."）存到平台上下文，Tool-Use 提示词直接内联
    // （此前被丢弃 → AI 每轮都在猜 -n/-i/-o 的语义，其实题面写着）
    state._platformChallengeDesc = (cDetail && (cDetail.description || cDetail.desc)) || '';

    // 附件在详情 files[] 里，结构 { id, file: { original_name, mime_type, size } }（2026-10-14 实测）
    // file_id = files[].id（外层），文件名在 files[].file.original_name
    const atts = (cDetail && cDetail.files) || (detail && detail.files) || (cDetail && (cDetail.attachments || cDetail.attachment)) || [];
    const attList = (Array.isArray(atts) ? atts : [atts]).filter(Boolean);
    if (!attList.length) {
      addLog('warning', '该题无附件（可能是靶机型逆向题，暂不支持）');
      addSystemMessage(`**${ch.name} 无附件**\n\n该题可能是需要靶机的类型，当前流水线只处理「带附件的逆向题」。`);
      return { ok: false, note: 'no-attachment', challenge: { id: cid, name: ch.name } };
    }

    // 4) 取附件下载地址并下载（参数：challenge_id + file_id + practice_ground_id）
    // 每题附件下载到独立子目录 <dlDir>/<题名>/：共享根目录会把所有题的文件混在一起，
    // AI 的 workdir 也落在根目录 → glob/翻目录时翻到上一题的解压残留（RomanRomance 实测：
    // AI 把上一题 ExceLLM 的 sheet 当本题逻辑，把上题 flag 当本题答案）。
    const chDir = dlDir.replace(/[\\/]+$/, '') + '\\' + String(ch.name).replace(/[\\/:*?"<>|]/g, '_');
    addLog('info', `[4/6] 下载附件（${attList.length} 个）到 ${chDir} ...`);
    let localFile = null;
    const downloaded = [];
    for (const att of attList) {
      const fileId = att.id ?? att.file_id;                       // 外层 id 即 file_id（实测）
      const inner = att.file || {};                                // 内层文件元数据
      const attName = inner.original_name || att.filename || att.name || ('file_' + fileId);
      let urlRes;
      try {
        urlRes = await window.electronAPI.ctf2McpCall('ctf2_get_attachment_url', { challenge_id: cid, file_id: fileId, practice_ground_id: groundId });
      } catch (e) { addLog('warning', `取附件地址失败(${attName}): ${e.message}`); continue; }
      if (urlRes && urlRes.success === false) { addLog('warning', `取附件地址失败(${attName}): ${urlRes.error}`); continue; }
      const uObj = ctf2ParsePayload((urlRes && urlRes.result !== undefined) ? urlRes.result : urlRes);
      // URL 实测在 attachment.url（2026-10-14），其余字段名做容错
      const url = (uObj && ((uObj.attachment && uObj.attachment.url) || uObj.url || uObj.download_url || uObj.href)) || (typeof uObj === 'string' ? uObj : '');
      if (!url) { addLog('warning', `附件 ${attName} 未返回下载地址: ` + JSON.stringify(uObj).slice(0, 200)); continue; }
      const dl = await window.electronAPI.ctf2Download(url, chDir);
      if (dl && dl.success) {
        addLog('success', `✅ 已下载: ${dl.path}（${(dl.bytes / 1024).toFixed(1)} KB）`);
        downloaded.push(dl.path);
        if (!localFile) localFile = dl.path;
      } else {
        addLog('warning', `下载失败(${attName}): ${(dl && dl.error) || '未知'}`);
      }
    }
    if (!localFile) { addLog('error', '所有附件均下载失败，流程中止'); return { ok: false, note: 'download-failed', challenge: { id: cid, name: ch.name } }; }
    // 同题伴生附件（如 enc.txt + ELF 主程序）：主文件=第一个可分析物，其余登记供 AI read_file
    // 选择策略：文本小文件常是"密文/输入"（enc.txt），ELF/PE/pyc/zip 才是"主程序" → 主文件按类型权重挑
    if (downloaded.length > 1) {
      const typeWeight = (p) => {
        const ext = String(p).toLowerCase();
        if (/\.(zip|apk|jar|xlsx|docx|pptx|rar|7z)$/.test(ext)) return 5;
        if (/\.(pyc|dex)$/.test(ext)) return 5;
        if (!/\.[a-z0-9]{1,5}$/.test(ext)) return 5;              // 无扩展名 = ELF/PE 常见
        // RSA/密码学题常见组合：flag.enc + pub.key / private.pem / cipher.txt。
        // 主文件应是**可执行体或密文**，密钥是"辅助材料"——但两者都要给 AI。
        if (/\.(pem|key|pub|crt|cer|der)$/.test(ext)) return 2;
        if (/\.(txt|enc|bin|dat|json|xml|log|md)$/.test(ext)) return 3;
        return 3;
      };
      downloaded.sort((a, b) => typeWeight(b) - typeWeight(a));
      localFile = downloaded[0];
      addLog('info', `[多附件] 主文件: ${localFile.split('\\').pop()}，伴生: ${downloaded.slice(1).map(p => p.split('\\').pop()).join(', ')}`);
      state._platformFiles = downloaded.slice();                  // 全部登记（AI 可 read_file）
      // 密码学类题（有 .enc/.key/.pem 而无二进制）：直接走 RSA/密码分析提示，而不是硬套 ELF/PE 流程
      const hasCryptoPair = downloaded.some(p => /\.(enc|key|pem|pub|crt|cer|der)$/i.test(p))
        && !downloaded.some(p => /\.(exe|dll|elf|so|apk|dex)$/i.test(p));
      if (hasCryptoPair) {
        addLog('info', '[多附件] 识别为密码学材料组合（密文+密钥），走 crypto 分析路径');
        state._platformCryptoMaterials = downloaded.slice();
      }
    }

    // 5) 走现有逆向解题流程（analyzeFile 识别类型 → autoAnalyze 分派 → finalizeSolve 验证）
    addLog('info', `[5/6] 交给本地逆向流程解题: ${localFile}`);
    state._platformContext = true;   // 平台上下文：ZIP 附件自动解压取主文件（区别于手动拖 zip）
    // 题面与伴生文件是平台题最高价值的检索目标，必须在 analyzeFile 的"换题清理"里活下来
    const savedPlatform = {
      challenge: state._platformChallenge,
      desc: state._platformChallengeDesc,
      files: state._platformFiles,
    };
    await analyzeFile(localFile, { keepPlatformContext: true });
    restorePlatformContext(state, savedPlatform);
    addLog('info', '开始自动分析（现有逆向分流）...');
    await autoAnalyze();

    // 6) 收集"已验证"的 flag → 提交平台（必须带 confirmation:true）
    addLog('info', '[6/6] 检查是否产出已验证 flag 并提交平台...');
    const verified = ((state.findings && state.findings.flags) || []).filter(f => f.verified);
    // 裸答案（口令/序列号/裸字符串）经契约复现确认的，按平台外壳规则包装后一并尝试。
    // 实测（CrackMe3）：771535 满足 sum==0x2979 且 AI 明确写成 [FLAG]771535[/FLAG]，
    // 但因为没有 `flag{}` 外壳被整条丢弃，整题记为未解出。
    const verifiedAnswers = ((state.findings && state.findings.answers) || []).filter(a => a.verified);
    const submitCandidates = verified.map(f => ({ flag: f.flag, origin: 'flag', ref: f }));
    for (const a of verifiedAnswers) {
      const tpl = state._platformWrapTemplate || 'flag{%s}';
      const wrapped = applyWrap(a.value, tpl);
      if (!looksLikeFlag(wrapped)) continue;
      if (submitCandidates.some(x => x.flag === wrapped)) continue;
      submitCandidates.push({ flag: wrapped, origin: 'answer', ref: a, template: tpl });
      addLog('info', `[平台] 裸答案 ${a.value} 按题面外壳包装为 ${wrapped}`);
      addSolveNote('平台提交', `裸答案 ${a.value} → ${wrapped}（模板 ${tpl}）`);
    }
    if (!submitCandidates.length) {
      // 近失识别（40 题实测）：AI 明确给过答案/flag 但没过验证闸（如 z3 解出却无契约复现）。
      // 不提交（未验证不提交的原则不变），但 note 必须区分"颗粒无收"与"差一步确认"——
      // 两者的下一步动作完全不同（前者换题，后者人工复核一眼就能翻盘）。
      const allAnswers = ((state.findings && state.findings.answers) || []);
      const allFlags = ((state.findings && state.findings.flags) || []);
      const nearMiss = []
        .concat(allAnswers.map(a => ({ kind: 'answer', value: a.value })))
        .concat(allFlags.filter(f => !f.verified).map(f => ({ kind: 'flag', value: f.flag })))
        .filter(x => x && x.value && String(x.value).trim().length >= 2)
        .slice(0, 5);
      const note = state.lastBlockedReason ? 'blocked-by-av'
        : (nearMiss.length ? 'near-miss-answer' : 'no-verified-flag');
      if (nearMiss.length) {
        addLog('warning', `[平台] 近失：已产出候选但未过验证闸（${nearMiss.map(x => x.value).join('、')}），不提交、留人工复核`);
        addSystemMessage(`**${ch.name}**：本地拿到候选答案但未通过验证闭环，未提交。\n\n候选：${nearMiss.map(x => '`' + x.value + '`').join('、')}\n\n可人工复核后手动提交。`);
        addSolveNote('近失候选', nearMiss.map(x => x.value).join('、'));
      } else {
        addLog('warning', '未产出「已验证」flag，跳过提交（未验证不提交，避免污染正确率）');
        addSystemMessage(`**${ch.name}**：本地未得到已验证 flag，未提交。\n\n可人工复核后手动提交，或重试。`);
      }
      return { ok: false, note, detail: state.lastBlockedReason || '', near_miss: nearMiss.map(x => String(x.value)), challenge: { id: cid, name: ch.name, difficulty: ch.difficulty }, verified_flags: [] };
    }
    let submitResult = null;
    for (const cand of submitCandidates) {
      const f = { flag: cand.flag };
      const sub = await window.electronAPI.ctf2McpCall('ctf2_submit_flag', {
        challenge_id: cid, practice_ground_id: groundId, flag: f.flag, confirmation: true
      });
      if (sub && sub.success === false) { addLog('warning', `提交请求失败: ${sub.error}`); continue; }
      const subData = ctf2ParsePayload((sub && sub.result !== undefined) ? sub.result : sub);
      const s = JSON.stringify(subData);
      // ⚠️ 判定必须优先看结构化布尔字段。
      // 旧实现用 /accepted|correct|valid/ 匹配整个 JSON 字符串——平台返回
      // `{"accepted":false,...}` 时 "accepted" 这个词本身就会命中，导致**错误 flag 被记为成功**
      // （实测「内涵的软件」：accepted=false，驱动仍打印"解出"）。
      const ok = ctf2SubmitAccepted(subData, s);
      submitResult = { flag: f.flag, correct: ok, raw: s.slice(0, 400), origin: cand.origin };
      addLog(ok ? 'success' : 'warning', `提交 ${f.flag} → ${s.slice(0, 200)}`);
      addSolveNote('平台提交', `challenge=${ch.name} flag=${f.flag} result=${s.slice(0, 200)}`);
      // 平台笔记：记录解题结果（凭据页要求 result 可回看）
      ctf2LogNote('result', `${ch.name} · ${ok ? '解出并提交成功' : '提交未通过'} · flag=${f.flag}`);
      addSystemMessage(ok
        ? `**🎯 题目「${ch.name}」已解出并提交成功**\n\n\`${f.flag}\``
        : `**题目「${ch.name}」提交结果**\n\n\`${f.flag}\`\n\n平台返回: ${s.slice(0, 300)}`);
      if (ok) {
        if (cand.origin === 'answer') {
          addLog('success', `[平台] 裸答案经平台外壳规则包装后提交通过（模板 ${cand.template}）`);
        }
        break; // 一道题命中即可
      }
      // 裸答案包装后提交未通过 → 降级为未验证，避免下一轮误判已解出
      if (cand.origin === 'answer') {
        try {
          cand.ref.verified = false;
          cand.ref.source = String(cand.ref.source || '') + ',wrap-rejected';
          persistFindings();
        } catch (e) { /* 降级失败不阻塞 */ }
        addLog('warning', `[平台] 裸答案 ${cand.ref.value} 包装后提交未通过，已降级为未验证`);
      }
    }
    // 提交被平台拒绝时，必须把"已验证"标记降级：否则下一轮会认为这题已解出，
      // 既不再重试，报告里也会把它算成成功（实测「内涵的软件」accepted=false 却记为解出）。
    if (submitResult && !submitResult.correct) {
      for (const f of verified) {
        if (f.flag === submitResult.flag) {
          f.verified = false;
          f.source = String(f.source || '') + ',rejected-by-platform';
        }
      }
      try { await persistFindings(); } catch (e) { /* 忽略 */ }
      addLog('warning', '[平台] 提交未被接受，该 flag 已降级为「未验证」，后续可重试');
    }
    return {
      ok: !!(submitResult && submitResult.correct),
      note: (submitResult && !submitResult.correct) ? 'submit-rejected' : '',
      submitted: submitResult,
      challenge: { id: cid, name: ch.name, difficulty: ch.difficulty, friendly_id: ch.friendly_id },
      ground_id: groundId,
      local_file: localFile,
      verified_flags: verified.map(f => f.flag)
    };
  } catch (err) {
    addLog('error', '平台拉题流程异常: ' + err.message);
    return { ok: false, note: 'exception: ' + err.message };
  }
}

// 循环模式：拉题 → 解题 → 提交 → 清理外部工具 → 下一题。
// 两种继续策略：
//   · 默认（自动测试模式 state.platformSkipOnFail=true）：**解不出也继续下一题**，
//     只把失败题加入本轮跳过集合，避免在同一题反复空转（用户明确要求"求解不出来的自动跳过"）。
//   · 严格模式：只在平台判对后继续（避免空转烧配额）。
// 每轮之间检查 flowAbortRequested / state.platformAbort。
async function solveOneFromPlatform() {
  if (state.platformBusy) { addLog('warning', '平台拉题流程进行中，请稍候'); return; }
  state.platformBusy = true;
  const loopMode = !!state.platformLoop;
  // 自动测试模式：失败继续；严格模式：失败即停
  const skipOnFail = state.platformSkipOnFail !== false;
  // 本轮已尝试过的题目（失败后加入，下一轮排除，防止无限拉同一道）
  const attempted = new Set();
  try {
    let total = 0, solved = 0, skipped = 0;
    const limit = Number(state.platformLoopLimit) || 50;
    do {
      if (state.flowAbortRequested || state.platformAbort) {
        addLog('info', '[平台] 收到停止信号，结束循环');
        break;
      }
      if (total >= limit) {
        addLog('info', `[循环] 已达本轮上限 ${limit} 题，结束`);
        break;
      }
      // 每轮开始前强制清理外部工具（IDA/JEB/java）：上一题若未清（如本轮是循环首轮但用户之前
      // 手动跑过），旧 IDA 会占住 13337，新 IDA 实例连不上 MCP → 采集打到旧题目的库上。必须先清。
      try {
        const cl0 = await window.electronAPI.ctf2CleanupTools();
        if (cl0 && cl0.killed && cl0.killed.length) addLog('info', '[循环] 轮前清理外部工具: ' + cl0.killed.join(', '));
      } catch (e) { /* 清理失败不阻塞 */ }
      if (total > 0) {
        addLog('info', `[循环] 等待 3 秒后开始下一题...`);
        await new Promise(r => setTimeout(r, 3000));
      }
      state.flowAbortRequested = false;   // 每轮开始清零：停止信号只作用于"当前这轮的边界"
      const r = await solveOnePlatformRound({ exclude: attempted });
      total++;
      const chName = (r && r.challenge && r.challenge.name) || 'unknown';
      // 无论本题成败都清理（未解出也会走 skip/break——清理放前面）
      try {
        const cl = await window.electronAPI.ctf2CleanupTools();
        addLog('info', `[循环] 题后清理外部工具进程: ${(cl && cl.killed && cl.killed.length) ? cl.killed.join(', ') : '（无运行中的）'}`);
      } catch (e) { /* 清理失败不阻塞 */ }
      if (r && r.ok) {
        solved++;
        attempted.add(chName);
        addLog('success', `[循环] ✅ ${chName} 已解出并提交成功（累计 ${solved}/${total}）`);
        // 成长闭环②：曾失败过的题解出 → 自动复盘证伪（清除被证伪的污染经验，沉淀复盘教训）
        if (state.lastAiText) {
          try { await postSolveReview(chName, state.lastAiText); } catch (e) { /* 复盘失败不阻塞 */ }
        }
      } else {
        const note = (r && r.note) || 'unknown';
        const structuralFail = ['no-attachment', 'no-candidates', 'no-grounds', 'connect-failed',
          'grounds-failed', 'list-failed', 'detail-failed', 'download-failed'].includes(note);
        // 成长闭环①：失败存档（方向结论），下次拉到同题自动注入"已排除的路"。
        // 仅当 AI 真正产出过分析（lastAiText 非空）才存档——结构性失败没有方向结论可言。
        if (!structuralFail && state.lastAiText) {
          try {
            await recordFailure(chName, state.lastAiText, note);
          } catch (e) { /* 存档失败不阻塞 */ }
        }
        // 结构性失败（无题可拉）→ 直接结束，继续也没有意义
        if (['no-candidates', 'no-grounds', 'connect-failed', 'grounds-failed', 'list-failed'].includes(note)) {
          addLog('warning', `[循环] 无法继续拉题（${note}），结束`);
          break;
        }
        if (!loopMode) {
          addLog('warning', `[循环] 本题未解出（${note}）`);
          break;
        }
        if (!skipOnFail) {
          addLog('warning', `[循环] 本题未解出（${note}），严格模式下停止`);
          addSystemMessage('**循环停止**\n\n本题未解出。严格模式只在"平台判对"后继续，避免卡在同一题空转。');
          break;
        }
        // 自动测试模式：跳过本题，继续下一题
        skipped++;
        attempted.add(chName);
        addLog('warning', `[循环] ⏭ ${chName} 未解出（${note}），已跳过，继续下一题（跳过 ${skipped}）`);
      }
    } while (loopMode);
    if (loopMode) {
      addLog('info', `[循环] 结束：共尝试 ${total} 题，解出 ${solved} 题，跳过 ${skipped} 题`);
      addSystemMessage(`**循环解题结束**\n\n尝试 ${total} 题，解出 **${solved}** 题，跳过 ${skipped} 题。`);
    }
    state._lastPlatformRun = { total, solved, skipped, at: new Date().toISOString() };
  } finally {
    state.platformBusy = false;
    state.platformAbort = false;
  }
}

// ============ 自动测试入口（控制台/自动化脚本调用）============
// 用法（DevTools 控制台）：
//   await window.__ctfAutoTest({ limit: 10, quitAfterEach: true })
// 行为：逐题 拉取→分析→求解→提交；解不出自动跳过下一题；每题结束（含失败）后退出进程。
// 为什么要每题退出：IDA/JEB 的 MCP 端口（13337/16161）在进程退出后不一定立刻释放，
// 长时间连续跑会累积僵尸实例；每题重启一次最稳（代价 ~5s 启动时间）。
async function __ctfAutoTest(opts = {}) {
  const limit = Number(opts.limit) || 20;
  const quitAfterEach = opts.quitAfterEach !== false;
  const results = [];
  state.platformLoop = true;
  state.platformSkipOnFail = true;
  state.platformLoopLimit = 1;          // 每轮只做一题，便于逐题退出
  state.platformAbort = false;

  // 外部驱动传入的"已尝试题名"（跨进程持久化）：500+ 题必须靠它做分页与去重，
  // 否则每题重启后都从第 1 页第 1 道开始，永远在原地打转。
  const seedExclude = Array.isArray(opts.exclude) ? opts.exclude.map(String) : [];
  const attempted = new Set(seedExclude);
  // 定向验证：调用方点名要跑的题（优先、可跨页找）。队列会被消费掉，跑过的题不再重复优先。
  const wantQueue = Array.isArray(opts.wantNames) ? opts.wantNames.map(String).filter(Boolean) : [];

  for (let i = 0; i < limit; i++) {
    if (state.platformAbort) break;
    const r = await (async () => {
      // 直接复用单轮逻辑（内部已含清理与失败存档）
      state.platformBusy = true;
      try {
        // 先传"本次运行产生的"排除集；种子排除集由 solveOnePlatformRound 内部读 config 处理，
        // 这里把两者合并，保证翻页位置也对（attempted.size 决定 page）。
        const round = await solveOnePlatformRound({
          exclude: attempted,
          wantNames: wantQueue.length ? wantQueue.slice() : undefined
        });
        return round || { ok: false, note: 'null-round' };
      } catch (e) {
        return { ok: false, note: 'exception: ' + e.message };
      } finally {
        state.platformBusy = false;
      }
    })();

    const name = (r.challenge && r.challenge.name) || '(unknown)';
    // 进程内去重：无论成败都把本题名加入 exclude，否则下一轮 candidates[0]
    // 仍是同一道题（实测：limit=10 连跑时 10 轮全是同一道 CrackMe，
    // 第 2 轮起被 zip 防死循环闸短路成秒级 no-verified-flag）。
    // 失败题的跨进程重试仍由"不写持久化清单"保证（见下方 noPersistSkip 分支）。
    if (name && name !== '(unknown)') attempted.add(name);
    // 定向队列：本轮跑过的题从队列里移除，避免下一轮又优先同一道
    if (wantQueue.length && name && name !== '(unknown)') {
      const qi = wantQueue.findIndex(w => w === name || w.toLowerCase() === String(name).toLowerCase());
      if (qi >= 0) wantQueue.splice(qi, 1);
    }
    results.push({
      name, ok: !!r.ok, note: r.note || '',
      flag: (r.submitted && r.submitted.flag) || (r.verified_flags && r.verified_flags[0]) || '',
      near_miss: Array.isArray(r.near_miss) ? r.near_miss : [],
      difficulty: (r.challenge && r.challenge.difficulty) || '',
    });
    addLog(r.ok ? 'success' : 'warning',
      `[自动测试] ${i + 1}/${limit} ${name}: ${r.ok ? '解出' : '跳过（' + (r.note || '') + '）'}`);

    // 结构性失败（无题可拉）→ 提前结束
    if (['no-candidates', 'no-grounds', 'connect-failed', 'grounds-failed', 'list-failed'].includes(r.note)) break;

    // 跨进程去重：把"本轮已处理过"写进 config.platform.skipChallenges，
    // 否则每题重启工具后 exclude 丢失 → 同一题被反复拉取（实测 not-baby-parallelism 连跑两轮）。
    //
    // ⚠️ 只记录**已解出**的题，失败的不写。历史上这里无条件写入，
    // 导致批量跑失败的题（CrackMe 系列 8 道等）永久进入跳过清单、后续再也不会重试，
    // 混入人工已解题的语义里，无法区分"解过"与"没解成"。
    // 失败题的去重靠本轮的 exclude 集合（内存态），下次启动可以重试。
    if (opts.noPersistSkip) {
      addLog('info', `[自动测试] 定向模式：不把「${name}」写入跳过清单`);
    } else if (r.ok && name && name !== '(unknown)') {
      try {
        const cur = ((state.config && state.config.platform && state.config.platform.skipChallenges) || []).slice();
        if (!cur.includes(name)) {
          cur.push(name);
          state.config = state.config || {};
          state.config.platform = state.config.platform || {};
          state.config.platform.skipChallenges = cur;
          state.platformSkipSet = new Set(cur.map(String));
          if (window.electronAPI && window.electronAPI.saveConfig) {
            await window.electronAPI.saveConfig({ platform: { skipChallenges: cur } });
          }
          addLog('info', `[自动测试] 「${name}」已解出，记入已处理清单（${cur.length} 条），后续批量不再重复拉取`);
        }
      } catch (e) { /* 记录失败不阻塞 */ }
    } else if (!r.ok && name && name !== '(unknown)') {
      addLog('info', `[自动测试] 「${name}」未解出（${r.note || '未知原因'}），不写入清单，下次可重试`);
    }

    // 存档本轮报告（供外部脚本读取）
    // ⚠️ 改走主进程 IPC：渲染层 state.appPaths.userData 在 getAppPaths 失败时为空，
    // 会导致 report 静默不写 → 外部驱动只能干等到超时（实测 20 秒结束的题等了 10 分钟）。
    try {
      const report = {
        at: new Date().toISOString(),
        total: results.length,
        solved: results.filter(x => x.ok).length,
        skipped: results.filter(x => !x.ok).length,
        results,
      };
      if (window.electronAPI && window.electronAPI.autotestReport) {
        await window.electronAPI.autotestReport(report);
      } else if (window.electronAPI && window.electronAPI.writeFile) {
        const dir = (state.appPaths && state.appPaths.userData) || '';
        if (dir) await window.electronAPI.writeFile(dir + '/autotest-report.json', JSON.stringify(report, null, 2));
      }
    } catch (e) { /* 报告写失败不阻塞 */ }

    // 每题结束都退出（quitAfterEach），由外部驱动重新拉起下一题。
    // ⚠️ 旧实现写成 i < limit - 1，当 limit=1 时恒 false → 工具永不退出（实测卡住）。
    // 外部驱动按"一次只跑一题"的方式调用，所以只要本函数结束就应退出。
    if (quitAfterEach) {
      addLog('info', '[自动测试] 本题结束，关闭工具进程...');
      try {
        await window.electronAPI.ctf2CleanupTools();
      } catch (e) { }
      // 先落盘最终报告（退出后外部驱动靠它读结果）
      try {
        const report = {
          at: new Date().toISOString(),
          total: results.length,
          solved: results.filter(x => x.ok).length,
          skipped: results.filter(x => !x.ok).length,
          results,
        };
        const dir = (state.appPaths && state.appPaths.userData) || '';
        if (dir && window.electronAPI.writeFile) {
          await window.electronAPI.writeFile(dir + '/autotest-report.json', JSON.stringify(report, null, 2));
        }
      } catch (e) { }
      try {
        await window.electronAPI.quitApp();
      } catch (e) { /* 退出失败则继续（外部脚本兜底 taskkill） */ }
      return { finished: true, ...{ total: results.length, solved: results.filter(x => x.ok).length, skipped: results.filter(x => !x.ok).length, results } };
    }
  }

  state.platformLoop = false;
  const summary = {
    at: new Date().toISOString(),
    total: results.length,
    solved: results.filter(x => x.ok).length,
    skipped: results.filter(x => !x.ok).length,
    results,
  };
  addLog('info', `[自动测试] 结束：共 ${summary.total} 题，解出 ${summary.solved}，跳过 ${summary.skipped}`);
  return { finished: true, ...summary };
}
window.__ctfAutoTest = __ctfAutoTest;

// MCP 返回的 content[].text 常是 JSON 字符串 → 先解一层
function ctf2ParsePayload(x) {
  if (typeof x === 'string') { try { return JSON.parse(x); } catch (e) { return x; } }
  return x;
}

// 判定平台提交是否真的成功。
// 为什么单独抽出来：旧实现是 `s = JSON.stringify(...); /accepted|correct|valid/.test(s)`——
// **`{"accepted":false}` 里的 "accepted" 会命中**，于是错误 flag 被记为"解出"。
// 实测「内涵的软件」：平台 accepted=false / is_solved=false，驱动仍打印"解出"并停止重试。
// 规则（按可信度排序）：
//   ① 有布尔字段 accepted → 直接采信（false 就是失败，不再看别的）
//   ② 有 is_solved → 采信
//   ③ 都没有 → 文本匹配，但要排除否定式（incorrect/wrong/invalid/未通过…）
function ctf2SubmitAccepted(data, text) {
  const findBool = (obj, keys, depth = 0) => {
    if (!obj || typeof obj !== 'object' || depth > 4) return null;
    for (const k of keys) {
      if (typeof obj[k] === 'boolean') return obj[k];
    }
    for (const v of Object.values(obj)) {
      if (v && typeof v === 'object') {
        const r = findBool(v, keys, depth + 1);
        if (r !== null) return r;
      }
    }
    return null;
  };
  const acc = findBool(data, ['accepted', 'is_accepted']);
  if (acc !== null) return acc === true;
  const solved = findBool(data, ['is_solved', 'solved']);
  if (solved !== null) return solved === true;
  const s = String(text || '');
  if (/incorrect|wrong|invalid|未通过|不正确|错误/i.test(s)) return false;
  return /correct|正确|通过|valid|success|成功/i.test(s);
}

// 平台 zip 手包处理：解压（主进程）→ 按"可分析物优先"挑主文件（ELF/PE/pyc/无扩展名…）
// → analyzeFile+autoAnalyze 继续流程。渲染层无 Node 能力：解压走 ctf2Unzip IPC，
// 文件头魔数走 readFile 读 base64？——readFile 返回 utf8 文本，二进制会坏 → 魔数判定改在主进程做。
async function analyzeZipHandout(zipPath) {
  // 防无限循环（实测 CrackMe4：解压目录里又出现同名 zip → analyzeFile → 再解压 → 死循环，
  // 8 分钟内 analyzeFile 被调用 69 次、解压 3 次，整轮批量卡死在这里）。
  // 判据：同一路径最多解压一次；解压后主文件若仍是同一个 zip（自引用），直接放弃。
  state._zipHandoutSeen = state._zipHandoutSeen || new Set();
  state._zipHandoutMain = state._zipHandoutMain || new Map();   // normZip → 上次选定的主文件
  const normZip = String(zipPath || '').toLowerCase();
  if (state._zipHandoutSeen.has(normZip)) {
    // 重复进入 ≠ 死循环（40 题实测：平台批量对同一题重拉同一附件时，旧实现直接 return，
    // 整轮被短路成秒级 no-verified-flag）。真正的死循环由下方"自引用压缩包"检查兜底。
    // 这里改为：跳到上次已解压的主文件**继续求解**；主文件已不在（AV 隔离/目录被清）才重新解压。
    const prevMain = state._zipHandoutMain.get(normZip);
    if (prevMain) {
      let alive = false;
      try { const head = await window.electronAPI.readFile(prevMain); alive = !!(head && head.success !== false); } catch (e) { alive = false; }
      if (alive) {
        addLog('info', '[zip手包] 同一压缩包已处理过，直接复用已解压主文件继续求解: ' + String(prevMain).split('\\').pop());
        const files = (state._platformFiles || []).slice();
        await analyzeFile(prevMain, { keepPlatformContext: true });
        restorePlatformContext(state, { challenge: state._platformChallenge, desc: state._platformChallengeDesc, files });
        await autoAnalyze();
        return;
      }
      addLog('warning', '[zip手包] 上次解压的主文件已不存在（可能被杀软隔离），重新解压');
    }
    state._zipHandoutSeen.delete(normZip);
  }
  state._zipHandoutSeen.add(normZip);

  addLog('info', '[zip手包] 解压: ' + zipPath);
  const r = await window.electronAPI.ctf2Unzip(zipPath);
  if (!r || !r.success) {
    addLog('error', '[zip手包] 解压失败: ' + ((r && r.error) || '未知'));
    addSystemMessage('**ZIP 解压失败**\n\n' + ((r && r.error) || '未知'));
    return;
  }
  const files = r.files || [];
  addLog('info', `[zip手包] 共 ${files.length} 个文件: ${files.map(f => String(f).split('\\').pop()).join(', ')}`);
  if (!files.length) { addLog('warning', '[zip手包] 解压后为空'); return; }
  // 主进程已按"可分析优先级"排好序（ctf2-unzip 返回 files[0] 即最佳候选）
  const main = files[0];
  // 自引用防护：解压出来的"主文件"若又是同一个压缩包（或仍以 .zip 结尾且与源同名），
  // 继续 analyzeFile 会再次进入本函数 → 无限递归。直接放弃，交给人工/上层处理。
  if (String(main || '').toLowerCase() === normZip
    || (/\.zip$/i.test(String(main)) && String(main).toLowerCase().includes(String(zipPath).toLowerCase().replace(/\.zip$/, '').split(/[\\/]/).pop()))) {
    addLog('warning', '[zip手包] 解压结果是自引用压缩包，停止（防递归）: ' + main);
    return;
  }
  addLog('success', '[zip手包] 选定主文件: ' + String(main).split('\\').pop());
  state._zipHandoutMain.set(normZip, String(main));   // 记住主文件：同包重复进入时直接复用
  // 同包其它文件（输入样例/数据/说明）登记到平台上下文，供提示词与 Tool-Use AI 取用
  // 教训（not-baby-parallelism）：flag.out/input.bin 这类伴生文件被无视，AI 明确要"配套输入输出"
  // 却拿不到 → 判成"无法静态还原"。手包里所有文件都是题目证据，必须全部交给 AI。
  state._platformFiles = files.slice();
  if (files.length > 1) {
    addLog('info', '[zip手包] 同包伴生文件（已登记，AI 可 read_file）: '
      + files.slice(1).map(f => String(f).split('\\').pop()).join(', '));
    try {
      await caseAddEvidence('zip_handout_files', '手包全部文件清单', files.join('\n'), 'txt');
    } catch (e) { /* 证据失败不阻塞 */ }
  }
  await analyzeFile(main, { keepPlatformContext: true });
  restorePlatformContext(state, { challenge: state._platformChallenge, desc: state._platformChallengeDesc, files: files.slice() });
  await autoAnalyze();
}

// ========== 多阶段接力（壳/packer 题：AI 解出内嵌文件后自动切过去继续）==========
// 背景（Disguise 题实测）：stage1 是 decoy，真逻辑在内嵌 stage2.exe 里。AI 明明已经
// 解出并写出了 stage2 文件，却停在原地——因为工具没有"切换分析目标"的机制，换文件
// 还会清空上一阶段结论、且 IDA 单实例（13337）无法同时开两个目标。
// 本函数承载 AI 的 switch_to_next_stage 请求：校验 → 存证 → 提炼摘要 → kill 旧进程
// → analyzeFile(新文件, isHandoff) → autoAnalyze 继续求解。
// Phase 4.3：层数上限不再硬编码。
// 固定 3 层在"三层壳 + 一层真实逻辑"的题上会提前截断；但无限接力又会因 AI 反复提取同一
// 无效文件而空转。折中：按"是否确实产生了**新的、未访问过的**可执行文件"判断——
// runStageHandoff 已有 md5 去重（stageVisitedMd5），这里把上限放宽到 6，由去重负责防循环。
const STAGE_MAX_DEPTH = 6;
// 兼容旧引用：实际判断改用 state.stageDepth 与 STAGE_MAX_DEPTH

// 从 AI 文本 + findings 提炼"给下一阶段用"的摘要（控制长度，信息密度优先）
// Phase 4.2：升级为**结构化交接包**——不只是自由文本，而是"已知事实 / 已排除路 / 下一层线索"三段式。
// 结构化的价值：下一阶段 AI 能直接复用（密钥、算法、偏移），而不是重新读一遍散文。
function buildStageSummary(aiText, handoff) {
  const parts = [];
  const st = state.fileInfo || {};
  // 与 runNegativeAssertionCheck 同因：本函数在接力作用域执行，读不到局部 `analysisData`。
  // 统一走 state.lastAlgScan（扫描时写入、换题时清空）。
  const sc = state.lastAlgScan || {};
  const f = state.findings || {};

  parts.push(`# 第 ${state.stageDepth} 层交接包：${st.fileName || '未知文件'}（${state.fileType || '?'}）`);

  // ── 1. 已知事实（确定性数据优先，AI 推测其次）──
  const facts = [];
  facts.push(`- 文件：\`${st.fileName || '?'}\`，大小 ${st.sizeFormatted || st.size || '?'}，类型 ${state.fileType || '?'}`);
  if (sc.summary && sc.summary.length) {
    for (const s of sc.summary) facts.push(`- 工具识别：**${s.algo}**（置信度 ${s.confidence}）—— ${s.evidence}`);
  }
  const pl = (sc.payloads || []).concat(sc.embeddedPE || []);
  if (pl.length) {
    const p = pl[0], e = p.encode || {};
    facts.push(`- 本层载荷：${p.type.toUpperCase()} @0x${p.offset.toString(16)}，编码 ${e.kind || 'none'}` +
      (p.length ? `，长度 ${p.length}` : ''));
  }
  if (f.algorithms && f.algorithms.length) {
    facts.push('- 已识别算法/结构：' + f.algorithms.map(a => (a && a.text) || a).join('；'));
  }
  if (handoff && handoff.carried) facts.push(`- 上一阶段显式传下的结论：\n${String(handoff.carried).slice(0, 1200)}`);
  parts.push('## 1. 已知事实\n' + facts.join('\n'));

  // ── 2. 已排除的路（来自本地枚举的失败归因，避免下一层重复烧预算）──
  // 注意：这里用同步可用的内存态；跨阶段持久化由 excluded_paths.json 承担（提示词侧注入）。
  if (f.flags && f.flags.length) {
    const decoys = f.flags.filter(x => x && !x.verified);
    if (decoys.length) {
      parts.push('## 2. 已排除 / 存疑\n- 本层出现的 flag 候选（**未验证，可能是诱饵**）：'
        + decoys.map(x => `\`${x.flag}\``).join('、'));
    }
  }

  // ── 3. 本层结论（截断；保留具体数值/偏移，去掉客套）──
  const clean = String(aiText || '').replace(/\s+/g, ' ').trim();
  if (clean) parts.push(`## 3. 本层分析结论（节选）\n${clean.slice(0, 2000)}`);

  // ── 4. 下一层任务 ──
  parts.push(`## 4. 下一层任务\n- 当前文件是上一层的下一阶段（已提取）。**不要重复上一层的工作**。`
    + `\n- 优先对**本层**重新做算法扫描，按识别结果走标准框架。`
    + `\n- 若本层仍是壳/loader，继续按同样方式提取；若已是主逻辑，直接求解 flag。`);
  return parts.join('\n\n');
}

// 执行接力：返回 { ok, note }
async function runStageHandoff(handoff, fromAiText) {
  const newPath = String((handoff && handoff.path) || '').trim();
  const reason = String((handoff && handoff.reason) || '').trim();
  // 1) 深度上限
  if (state.stageDepth >= STAGE_MAX_DEPTH) {
    addLog('warning', `[阶段接力] 已达层数上限（${STAGE_MAX_DEPTH}），停止接力并交人工`);
    addSystemMessage(`**⏹ 阶段接力已达上限（${STAGE_MAX_DEPTH} 层）**\n\n当前仍在分析：\`${(state.fileInfo && state.fileInfo.fileName) || '?'}\`\n\n如确需更深层，请人工拖入下一阶段文件继续。`);
    return { ok: false, note: 'depth-exceeded' };
  }
  // 2) 文件有效性
  let info = null;
  try {
    info = await window.electronAPI.getFileInfo(newPath);
  } catch (e) { info = null; }
  if (!info || !info.success) {
    addLog('error', `[阶段接力] 新文件不可读：${newPath}`);
    addSystemMessage(`**❌ 阶段接力失败**\n\n文件不可读：\`${newPath}\`\n\n（AI 给出的路径可能拼错，或文件已被删除。）`);
    return { ok: false, note: 'bad-path' };
  }
  // 3) 防重复：同一 md5 已分析过则拒绝（否则 AI 可能反复提取同一文件造成空转）
  if (info.md5 && state.stageVisitedMd5.includes(info.md5)) {
    addLog('warning', `[阶段接力] 该文件已分析过（md5 ${info.md5.slice(0, 8)}…），拒绝重复接力`);
    addSystemMessage(`**ℹ️ 跳过重复接力**\n\n\`${info.fileName}\` 已在本轮分析过（同一 md5），为避免空转已忽略本次接力请求。`);
    return { ok: false, note: 'already-visited' };
  }

  // 4) 落盘本阶段结论 + 接力记录（证据）
  try {
    await caseAddEvidence('stage_handoff', `阶段接力：${(state.fileInfo && state.fileInfo.fileName) || '?'} → ${info.fileName}`, 
      `理由：${reason}\n新文件：${newPath}\n新文件 MD5：${info.md5}\n\n--- 本阶段 AI 结论 ---\n${String(fromAiText || '').slice(0, 20000)}`, 'md');
  } catch (e) { /* 证据失败不阻塞 */ }

  // 4.5) 接力前先收割本阶段经验——否则 runStageHandoff 直接 return 会跳过 finalizeSolve，
  //      导致本阶段的 [EXPERIENCE] 永久丢失（Disguise 实测：阶段1 的 thunk/CRT 识别经验没入库）。
  //      这里只做经验入库（不做验证闭环——上一阶段已知未出 flag，不重复跑契约）。
  try {
    if (fromAiText) await harvestExperience(fromAiText, { autoSave: true });
    addLog('info', '[阶段接力] 已收割本阶段经验（[EXPERIENCE] 入库）');
  } catch (e) { addLog('warning', '[阶段接力] 经验收割失败（不阻塞）: ' + e.message); }

  const summary = buildStageSummary(fromAiText, handoff);
  state.stageDepth += 1;

  addLog('info', `[阶段接力] ${state.stageDepth - 1}→${state.stageDepth}：${(state.fileInfo && state.fileInfo.fileName) || '?'} 解出 ${info.fileName}（理由：${reason || '未说明'}）`);

  // 5) 关闭旧反编译进程（IDA 单实例占 13337；不清理则新阶段 IDA 起不来）
  try {
    const cl = await window.electronAPI.ctf2CleanupTools();
    const killed = (cl && cl.killed && cl.killed.length) ? cl.killed.join(', ') : '（无运行中的）';
    addLog('info', `[阶段接力] 已清理外部工具进程: ${killed}`);
  } catch (e) { addLog('warning', '[阶段接力] 清理进程失败（不阻塞）: ' + e.message); }

  addSystemMessage(`**🔄 阶段接力 ${state.stageDepth}/${STAGE_MAX_DEPTH}**\n\n- 从：\`${(state.fileInfo && state.fileInfo.fileName) || '?'}\`\n- 到：\`${info.fileName}\`（${info.sizeFormatted}）\n- 理由：${reason || '（未说明）'}\n\n已关闭上一阶段反编译进程、保留其结论，开始分析新阶段…`);

  // 6) 切换并继续（analyzeFile 建新 CASE + autoAnalyze 走完整求解流程）
  try {
    state._inStageHandoff = true;   // 告知 autoAnalyze：这是接力内调用，勿重置接力态
    await analyzeFile(newPath, { isHandoff: true, stageContext: summary });
    await autoAnalyze();
    return { ok: true, note: 'handoff-done' };
  } catch (e) {
    addLog('error', '[阶段接力] 新阶段分析失败: ' + e.message);
    return { ok: false, note: 'handoff-error: ' + e.message };
  } finally {
    state._inStageHandoff = false;
  }
}

// ========== Phase 4：载荷自动提取与接力 ==========
// 为什么：即使扫描器给出了"下一层在哪、怎么解码"，实际提取仍要 AI 写脚本跑一遍。
// 多阶段题的下一步是**确定性的**（按 offset/编码参数解码写文件），没有理由让 AI 消耗工具预算。
// 工具直接做：解码 → 写盘 → 校验魔数 → 自动接力。
//
// 只处理"高置信度且参数完整"的载荷（PE/ELF/DEX、已知编码），失败则静默交给 AI 手动处理。
function buildPayloadExtractPython(p) {
  const e = p.encode || {};
  const off = p.offset;
  const n = p.length;
  const lines = [
    'import sys, re, base64',
    'src, dst = sys.argv[1], sys.argv[2]',
    'd = open(src, "rb").read()',
    `o = ${off}`,
  ];
  if (n) lines.push(`n = ${n}`);
  else lines.push('n = len(d) - o');
  switch (e.kind) {
    case 'none':
      lines.push('blob = d[o:o+n]');
      break;
    case 'xor':
      lines.push(`s = ${e.stride || 1}`, `key = ${e.key}`);
      lines.push('blob = bytes(d[o+i*s] ^ key for i in range(n))');
      break;
    case 'add':
      lines.push(`s = ${e.stride || 1}`, `key = ${e.key}`);
      // 编码是 out = in + key，解码必须 **减** key（此前误写成加，导致解出乱码）。
      lines.push('blob = bytes((d[o+i*s] - key) & 0xff for i in range(n))');
      break;
    case 'periodic-xor':
      lines.push(`keys = [${(e.key || []).join(', ')}]`);
      lines.push('blob = bytes(d[o+i] ^ keys[i % len(keys)] for i in range(n))');
      break;
    case 'rolling-xor':
      lines.push('blob = bytearray(); prev = 0');
      lines.push('for i in range(n):');
      lines.push('    prev = d[o+i] ^ prev');
      lines.push('    blob.append(prev)');
      lines.push('blob = bytes(blob)');
      break;
    case 'rolling-add':
      lines.push('blob = bytearray(); prev = 0');
      lines.push('for i in range(n):');
      lines.push('    prev = (d[o+i] - prev) & 0xff');
      lines.push('    blob.append(prev)');
      lines.push('blob = bytes(blob)');
      break;
    case 'base64':
      lines.push('s = re.sub(rb"[^A-Za-z0-9+/=]", b"", d[o:])');
      lines.push('s += b"=" * (-len(s) % 4)');
      lines.push('blob = base64.b64decode(s)[:n]');
      break;
    case 'hex':
      lines.push('s = re.sub(r"[^0-9a-fA-F]", "", d[o:].decode("latin-1"))');
      lines.push('blob = bytes.fromhex(s[:n*2])');
      break;
    default:
      return null;   // 未知编码：不自动提取
  }
  lines.push('open(dst, "wb").write(blob)');
  lines.push('print("OK", len(blob), blob[:4].hex())');
  return lines.join('\n');
}

// 尝试自动提取载荷。返回 { ok, path, head, p } 或 { ok:false, reason }
async function autoExtractPayload(filePath, payload) {
  const py = buildPayloadExtractPython(payload);
  if (!py) return { ok: false, reason: 'unsupported-encoding' };
  // 有 CASE 目录时用 CASE（每题独立归档）；否则用全局 scripts 目录。
  // ⚠️ getScriptsDir() 返回的**已经是** .../scripts，不能再拼 /scripts，
  //    否则会生成 scripts/scripts/xxx.py（实测留下的脏目录）。
  const caseDir = state.caseDir || '';
  const scriptsBase = caseDir ? `${caseDir}/scripts` : await getScriptsDir();
  const outDir = caseDir ? `${caseDir}/extracted` : `${scriptsBase}/extracted`;
  try { await window.electronAPI.ensureDir(outDir); } catch (e) { /* 忽略 */ }
  try { await window.electronAPI.ensureDir(scriptsBase); } catch (e) { /* 忽略 */ }
  const stem = payload.type || 'payload';
  const outPath = `${outDir}/stage_${stem}_${payload.offset.toString(16)}.bin`;
  const scriptPath = `${scriptsBase}/extract_${payload.offset.toString(16)}.py`;
  await window.electronAPI.writeFile(scriptPath, py);
  const r = await window.electronAPI.runToolArgs(['python', scriptPath, filePath, outPath]);
  const out = ((r.stdout || '') + (r.stderr ? '\n' + r.stderr : '')).trim();
  if (!/^OK\b/m.test(out)) return { ok: false, reason: 'extract-failed: ' + out.slice(0, 300) };
  const m = out.match(/^OK\s+(\d+)\s+([0-9a-f]+)/m);
  return { ok: true, path: outPath, size: m ? +m[1] : 0, head: m ? m[2] : '' };
}

// Phase 4.1：扫描到高置信度载荷时，由**工具**自动提取并接力（不等 AI 喊 switch_to_next_stage）
async function tryAutoHandoffByPayload(filePath, algScan) {
  const pl = (algScan && Array.isArray(algScan.payloads)) ? algScan.payloads
    : (algScan && Array.isArray(algScan.embeddedPE) ? algScan.embeddedPE : []);
  if (!pl.length) return { took: false };
  // 只处理真实容器 + 高置信度（shellcode/low 不自动接力）
  const p = pl.find(x => (x.type === 'pe' || x.type === 'elf' || x.type === 'dex') && (x.confidence === 'high' || !x.confidence));
  if (!p) return { took: false };
  // 已有接力深度限制 / 同文件已访问检查复用 runStageHandoff
  addLog('info', `[自动接力] 扫描到 ${p.type.toUpperCase()} 载荷 @0x${p.offset.toString(16)}，尝试自动提取…`);
  const ex = await autoExtractPayload(filePath, p);
  if (!ex.ok) {
    addLog('warning', `[自动接力] 自动提取失败（${ex.reason}），交回 AI 手动处理`);
    return { took: false, reason: ex.reason };
  }
  // 校验魔数，避免把"碰巧通过结构校验"的数据接力下去
  const expectHead = p.type === 'pe' ? '4d5a' : p.type === 'elf' ? '7f454c46' : '6465780a';
  if (!String(ex.head || '').startsWith(expectHead.slice(0, 4))) {
    addLog('warning', `[自动接力] 提取结果魔数不符（得到 ${ex.head}，期望 ${expectHead}），放弃自动接力`);
    return { took: false, reason: 'bad-magic' };
  }
  addLog('success', `[自动接力] 已提取 ${p.type.toUpperCase()} → ${ex.path}（${ex.size} 字节，头 ${ex.head}）`);
  addSystemMessage(`**⚙️ 工具自动提取了下一层载荷**\n\n- 类型：${p.type.toUpperCase()}\n- 来源偏移：0x${p.offset.toString(16)}\n- 提取结果：\`${ex.path}\`（${ex.size} 字节）\n\n正在自动接力到新文件…`);
  const handoff = {
    path: ex.path,
    reason: `工具扫描识别的 ${p.type.toUpperCase()} 载荷（编码：${(p.encode || {}).kind || 'none'}）`,
    carried: `上一层文件：${filePath}\n扫描结论：${(algScan.summary || []).map(s => s.algo + '/' + s.confidence).join(', ')}`,
  };
  const r = await runStageHandoff(handoff, '');
  return { took: true, ok: r.ok, note: r.note, path: ex.path };
}

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
  // 多阶段接力态一并重置：否则残留的 stageVisitedMd5/stageDepth 会让"清空后分析新题"
  // 的合法接力被误判为"已分析过"而拒绝，且深度预算被上一题预支。
  state.stageContext = '';
  state.stageDepth = 0;
  state.stageVisitedMd5 = [];
  state.stageOriginal = null;

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

// ===== IDA 会话身份判定（rank 3）=====
// 与 electron/binary-map.js 里同名函数保持同一语义；渲染层不能 require，
// 因此这里保留一份最小实现，由 tests/test_ida_identity.js 双向比对。
function normalizePathForCompare(p) {
  return String(p || '').trim().replace(/\\/g, '/').toLowerCase();
}

function basenameOf(p) {
  const s = String(p || '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i >= 0 ? s.slice(i + 1) : s;
}

function decideIdaAction(input) {
  const i = input || {};
  if (!i.listening) {
    return { action: 'launch', reason: 'not-listening', log: '[IDA] 13337 未监听，启动新实例' };
  }
  const id = i.identity || {};
  if (!id.success) {
    return {
      action: 'reload', reason: 'unknown',
      log: '[IDA] 身份未知（server_health 不可用），按安全策略重载目标文件'
    };
  }
  const loaded = normalizePathForCompare(id.input_path || id.module || id.idb_path);
  const target = normalizePathForCompare(i.targetPath);
  if (!loaded || !target) {
    return {
      action: 'reload', reason: 'unknown',
      log: '[IDA] 身份信息不完整（缺少 input_path/module），按安全策略重载'
    };
  }
  if (loaded === target) {
    return {
      action: 'reuse', reason: 'same',
      log: '[IDA] 身份校验通过: ' + basenameOf(id.input_path || id.module)
    };
  }
  return {
    action: 'reload', reason: 'mismatch',
    log: '[IDA] 目标不一致：已加载 ' + basenameOf(loaded) + '，当前题需要 ' + basenameOf(target) + '，重载'
  };
}

function planPidClose(before, after) {
  const prev = new Set((before || []).map(Number).filter(Number.isFinite));
  return (after || []).map(Number).filter(p => Number.isFinite(p) && !prev.has(p));
}

// 把不属于当前文件地址空间的函数剔除（与 electron/binary-map.js 同一语义）。
// funcs 支持 [{address|addr|start|ea, name}] 与裸地址数组。
function parseAddrLoose(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const m = v.trim().match(/^(?:0x)?([0-9a-fA-F]+)$/);
    return m ? parseInt(m[1], 16) : NaN;
  }
  return NaN;
}

function isAddrInImageLoose(map, addr) {
  if (!map || !Number.isFinite(addr) || addr <= 0) return false;
  const abs = (s) => (map.vaIsAbsolute ? s.va : map.imageBase + s.va);
  const lo = map.imageBase;
  const hi = lo + map.sizeOfImage;
  if (addr < lo || addr >= hi) return false;
  for (const s of (map.sections || [])) {
    const start = abs(s);
    const size = s.vsize || s.rawSize || 0;
    if (size > 0 && addr >= start && addr < start + size) return true;
  }
  return false;
}

function filterFunctionsInImage(funcs, map) {
  const kept = [];
  const dropped = [];
  if (!Array.isArray(funcs) || !map) return { kept: funcs || [], dropped, mapOk: false };
  for (const f of funcs) {
    let raw;
    if (typeof f === 'number' || typeof f === 'string') raw = f;
    else if (f && typeof f === 'object') {
      raw = f.address != null ? f.address : (f.addr != null ? f.addr : (f.start != null ? f.start : f.ea));
    }
    const addr = parseAddrLoose(raw);
    if (!Number.isFinite(addr) || addr <= 0) { dropped.push(f); continue; }
    if (isAddrInImageLoose(map, addr)) kept.push(f); else dropped.push(f);
  }
  return { kept, dropped, mapOk: true };
}

async function listIdaPids() {
  const pids = [];
  for (const img of ['ida.exe', 'ida64.exe']) {
    try {
      const r = await window.electronAPI.runToolArgs(['tasklist', '/FI', 'IMAGENAME eq ' + img, '/FO', 'CSV', '/NH'], {});
      const out = String((r && r.stdout) || '');
      for (const line of out.split(/\r?\n/)) {
        const m = line.match(/^"[^"]*","(\d+)"/);
        if (m) pids.push(Number(m[1]));
      }
    } catch (e) { /* 查询失败按无进程处理 */ }
  }
  return pids;
}

// ===== 平台题目契约（rank 4）=====
// 题面是平台题最高价值的检索目标：实测 22/22 份会话 prompt 里都没有它，
// 因为 analyzeFile 的"换题清理"把刚写进去的 desc/files 立刻清空了。
// 平台/zip 流程在 analyzeFile 之后用这个函数把三项恢复回来。
function restorePlatformContext(target, saved) {
  const s = target || {};
  const v = saved || {};
  if (v.challenge !== undefined) s._platformChallenge = v.challenge;
  if (v.desc !== undefined) s._platformChallengeDesc = v.desc;
  if (v.files !== undefined) s._platformFiles = v.files;
  return s;
}

// 从题面里识别"答案要包什么外壳"。
// 实测（CrackMe3）：「注意：得到的 flag 请包上 flag{} 提交」——这句话一直存在，
// 但旧的 8 条 shapeRules 只认邮箱/md5/base64 等数据形态，匹配不到"包装指令"，
// 于是 AI 算出的 771535 因不是 flag{...} 形态被静默丢弃。
function parseWrapDirective(desc) {
  const s = String(desc || '');
  if (!s) return null;
  // 显式模板：flag{...} / flag{} / XXX{}
  const explicit = s.match(/([A-Za-z][A-Za-z0-9_]{0,15})\s*\{\s*\}/);
  if (explicit) {
    const prefix = explicit[1];
    if (/包上|包裹|包成|加上|套上|外层|格式为|提交格式|wrap/i.test(s)) {
      return { template: prefix + '{%s}', evidence: explicit[0] };
    }
  }
  // 只说了"包 flag{}"（不带前缀名）
  if (/包上\s*flag\s*\{\s*\}|包成\s*flag\s*\{\s*\}|flag\s*\{\s*\}\s*提交/.test(s)) {
    return { template: 'flag{%s}', evidence: (s.match(/[^。\n]{0,30}flag\s*\{\s*\}[^。\n]{0,20}/) || [''])[0] };
  }
  return null;
}

function applyWrap(value, tpl) {
  const v = String(value == null ? '' : value).trim();
  const t = String(tpl || 'flag{%s}');
  if (!v) return v;

  // 从模板取出目标前缀（如 'flag{%s}' → 'flag'；无 %s 时按裸值处理）
  const tplPrefix = (/^([A-Za-z][A-Za-z0-9_]*)\{/.exec(t) || [])[1] || '';

  // 值本身已是 prefix{...} 形态时，分两种情况：
  //   ① 内层前缀 == 目标前缀 → 原样返回（避免 flag{flag{x}}）
  //   ② 内层前缀 != 目标前缀 → **先脱内层再套外层**
  // ② 就是历史缺陷 A：题面要求 "flag{裸值}"，而求解得到的裸值本身带着
  // 题目自定义壳（如 hack1ng_fo1_fun{...}）。旧实现看到"已有外壳"直接返回，
  // 产出 hack1ng_fo1_fun{...} 这种不合目标形态的答案，平台判错。
  const inner = /^([A-Za-z][A-Za-z0-9_]*)\{([^}]*)\}$/.exec(v);
  if (inner) {
    if (!tplPrefix || inner[1] === tplPrefix) return v;   // 同前缀（或模板无前缀）→ 不重复套
    return t.replace('%s', inner[2]);                     // 异前缀 → 脱内层，套目标壳
  }

  return t.replace('%s', v);
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
      let mcpScriptPath = (state.config.tools && state.config.tools.jebMcpPy) || '';
      // 兜底自动定位 MCP.py：配置为空时 jebMcpPy 会拼出 --script=（空值），
      // 让 JEB 反复弹"资源确认/脚本确认"对话框。优先配置，其次 <JEB目录>/scripts/MCP.py。
      if (!mcpScriptPath && jebPath) {
        const guess = jebPath.replace(/[\\/][^\\/]+$/, '') + '\\scripts\\MCP.py';
        mcpScriptPath = guess;
      }
      const scriptArg = mcpScriptPath ? [`--script=${mcpScriptPath}`] : [];
      if (fileToOpen) {
        // 以参数数组分离启动 JEB 并加载 MCP 脚本（若为 .bat 由主进程安全回退执行）
        result = await window.electronAPI.runToolArgs([jebPath, ...scriptArg, fileToOpen], { gui: true });
        addLog('info', `JEB打开文件: ${fileToOpen}`);
        addLog('info', mcpScriptPath ? `JEB MCP脚本: ${mcpScriptPath}` : 'JEB MCP脚本路径未配置（跳过 --script）');
      } else {
        result = await window.electronAPI.runToolArgs([jebPath, ...scriptArg], { gui: true });
        addLog('info', mcpScriptPath ? `JEB MCP脚本: ${mcpScriptPath}` : 'JEB MCP脚本路径未配置（跳过 --script）');
      }
    } else if (toolName === 'ida' || toolName === 'ida64') {
      // 防重复实例 + **身份校验**：
      // 旧实现只判断"13337 在监听"，等于假设"端口后面那个库就是当前文件"。
      // 实测代价极高：cnbragon / not-baby-parallelism / QuiZow 整轮的分析证据
      // 都来自上一题的数据库（一个 12KB 的 PE 被反编译出映像外的 0x42F038），
      // AI 在错误样本上烧满 60 轮。现在必须先问清"你加载的是谁"。
      let listening = false;
      try {
        const p = await window.electronAPI.checkPort(13337);
        listening = !!(p && p.listening);
      } catch (e) { /* 探测失败按未监听处理 */ }

      if (listening) {
        let identity = { success: false };
        try { identity = await window.electronAPI.idaIdentity(); } catch (e) { identity = { success: false, error: e.message }; }
        const verdict = decideIdaAction({
          listening: true,
          identity,
          targetPath: fileToOpen || ''
        });
        addLog(verdict.action === 'reuse' ? 'info' : 'warning', verdict.log);
        if (verdict.action === 'reuse') return;
        // reload：身份未知或目标不一致 —— 先试 open_file 切换，失败再按 PID 重启
        if (identity && identity.success) {
          try {
            const opened = await window.electronAPI.idaMcpCall('open_file', {
              file_path: fileToOpen, switch: true, autonomous: true
            });
            const okOpen = opened && (opened.success !== false);
            if (okOpen) {
              addLog('info', '[IDA] 已通过 open_file 切换目标文件: ' + basenameOf(fileToOpen));
              return;
            }
            addLog('warning', '[IDA] open_file 不可用，改为按 PID 重启实例');
          } catch (e) {
            addLog('warning', '[IDA] open_file 调用失败（' + e.message + '），改为按 PID 重启实例');
          }
        }
        // 按 PID 只结束"本次启动新增"的实例，绝不动用户自己开的 IDA
        const before = await listIdaPids();
        try { await window.electronAPI.runToolArgs(['taskkill', '/F', '/IM', 'ida.exe'], {}); } catch (e) { /* 可能已不存在 */ }
        try { await window.electronAPI.runToolArgs(['taskkill', '/F', '/IM', 'ida64.exe'], {}); } catch (e) { /* 同上 */ }
        const after = await listIdaPids();
        const leftover = planPidClose(before, after);
        if (leftover.length) addLog('info', '[IDA] 已结束旧实例 PID: ' + leftover.join(','));
        await new Promise(r => setTimeout(r, 2500));
      }

      const idaPath = state.config.tools[toolName] || state.config.tools.ida;
      // 残留数据库检测：上次 IDA 非正常退出会留下 <file>.id0/.id1 等未打包残件；
      // -A 模式下 "Database already exists" 会被自动应答为 Load existing，
      // 残留库一旦损坏（强杀/崩溃）IDA 会静默退出、MCP 端口永远起不来。
      try {
        const ex = await window.electronAPI.runToolArgs(['cmd', '/c', 'if', 'exist', fileToOpen + '.id0', 'echo', 'STALE_DB'], {});
        if (/STALE_DB/.test(String((ex && ex.stdout) || ''))) {
          let anyIda = false;
          try {
            const tl = await window.electronAPI.runToolArgs(['tasklist', '/FI', 'IMAGENAME eq ida.exe'], {});
            anyIda = /ida\.exe/i.test(String((tl && tl.stdout) || ''));
          } catch (e) { /* 无法判定时按没有实例占用处理 */ }
          if (!anyIda) {
            for (const ext of ['.id0', '.id1', '.id2', '.nam', '.til']) {
              await window.electronAPI.runToolArgs(['cmd', '/c', 'move', '/y', fileToOpen + ext, fileToOpen + ext + '.bak'], {});
            }
            addLog('info', '检测到上次未正常关闭的 IDA 数据库残留，已重命名为 .bak 后重新建库');
          } else {
            addLog('warning', '检测到 IDA 数据库残留且 ida.exe 正在运行：若 MCP 始终连不上，请先关闭该 IDA 再重试');
          }
        }
      } catch (e) { /* 检测失败不阻塞启动 */ }
      // IDA 不能把 .apk 当数据库打开：会停在 "Load a new file" 对话框等人工确认，
      // 插件 autostart 永不触发 → MCP 端口起不来。必须先提取 SO 再让 IDA 分析。
      if (/\.apk$/i.test(String(fileToOpen || ''))) {
        addLog('warning', 'IDA 不能直接分析 APK：请先点"分析文件"提取 SO，再让 IDA 打开 .so');
        return;
      }
      if (fileToOpen) {
        // 参数数组分离启动 IDA 并打开文件（防注入）；-A 自主模式：
        // 跳过 "Load a new file" 等人工对话框，按默认加载器自动建库分析。
        // 冷启动时若模态框卡住，MCP 插件的 autostart 永远不会执行（13337 起不来）。
        // ⚠️ 曾尝试 -o<独立数据库路径>（目录与完整 .i64 两种写法都试过）→ IDA 9 弹对话框卡死、
        // 13337 永不监听（两轮实测）。结论：**不要用 -o**，同目录建库；数据库文件污染问题由
        // ctf2-unzip 的"幂等解压 + .til/.id0/... 过滤"兜底（已验证有效）。
        result = await window.electronAPI.runToolArgs([idaPath, '-A', fileToOpen], { gui: true });
        addLog('info', `IDA打开文件: ${fileToOpen}（-A 自主模式）`);
      } else {
        result = await window.electronAPI.runToolArgs([idaPath, '-A'], { gui: true });
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

    // 检查是否连接成功：必须匹配到 "device" 状态那一行（address 后跟空白+device）。
    // 仅用 includes(device) 会把 offline/unauthorized 也判成在线 —— 这正是
    // "刚报在线，下一秒 install 报 Can't find service: package" 的根因。
    const devicesResult = await window.electronAPI.adbCommand('devices');
    const out = (devicesResult && devicesResult.stdout) || '';
    const readyRe = new RegExp(device.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+device\\b');
    const isOnline = devicesResult.success && readyRe.test(out);

    if (isOnline) {
      // 模拟器已在线（getprop 首次可能为空，重试几次取版本）
      let version = '';
      for (let i = 0; i < 5; i++) {
        const result = await window.electronAPI.adbCommand('shell getprop ro.build.version.release');
        version = result.success ? (result.stdout || '').trim() : '';
        if (version) break;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      setMcpStatus('emulator', true);
      addLog('success', `✅ 模拟器在线 - Android ${version || '未知'}`);
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

    // nox_path 缺失/不存在时明确报错，避免"启动了但什么都没发生"的黑盒现象
    if (!noxPath) {
      addLog('error', '未配置模拟器启动器路径（设置 → 模拟器 → nox_path），无法自动启动');
      setMcpStatus('emulator', false);
      return false;
    }
    try {
      await window.electronAPI.runToolArgs(['cmd', '/c', 'if', 'exist', noxPath, 'echo', 'NOX_OK'], {});
    } catch (e) { /* 路径探测失败不阻塞，交给启动结果判定 */ }

    // 启动安卓9实例（参数数组分离启动；替代 `start "" "path" -clone:x` 拼接）
    const result = await window.electronAPI.runToolArgs([noxPath, `-clone:${noxInstance}`], { gui: true });

    if (result.success) {
      addLog('info', '安卓9模拟器启动中，等待设备就绪（最长90秒）...');

      // 轮询：connect + devices，替代固定60秒等待
      const deadline = Date.now() + 90000;
      while (Date.now() < deadline) {
        await window.electronAPI.adbCommand(`connect ${device}`);
        const devicesResult = await window.electronAPI.adbCommand('devices');
        const out = (devicesResult && devicesResult.stdout) || '';
        // 必须匹配到 "device" 状态那一行（address 后跟 \tdevice），
        // 仅含 address（offline/unauthorized）不算就绪——否则会假成功。
        const readyRe = new RegExp(device.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+device\\b');
        if (devicesResult.success && readyRe.test(out)) {
          setMcpStatus('emulator', true);

          // 验证Android版本（getprop 首次可能为空，重试几次）
          let version = '未知';
          for (let i = 0; i < 5; i++) {
            const versionResult = await window.electronAPI.adbCommand('shell getprop ro.build.version.release');
            version = versionResult.success ? (versionResult.stdout || '').trim() : '';
            if (version) break;
            await new Promise(resolve => setTimeout(resolve, 1000));
          }
          if (!version) version = '未知';

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

// 安装APK（手动按钮）——复用自动版 installApkToEmulator()，
// 以获得 -r -t、package 服务就绪轮询、瞬时错误重试、真实输出校验等能力。
async function installApk() {
  if (state.fileType !== 'APK') {
    addLog('warning', '请选择APK文件');
    return;
  }

  addLog('info', '=== 安装APK到模拟器 ===');
  addLog('info', '文件: ' + state.fileInfo.fileName);

  try {
    const ok = await installApkToEmulator();
    if (!ok) {
      addLog('info', '可能原因:');
      addLog('info', '- 模拟器未启动或 package 服务未就绪');
      addLog('info', '- APK 与模拟器架构不兼容');
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
    await runHypotheses(state.lastAiText || '', { synthFrom: state.lastVerifyContracts });
    return;
  }

  // 一键求 flag（对齐系统提示词中的约定）
  if (lowerMessage.includes('求出flag') || lowerMessage.includes('求解flag') || lowerMessage.includes('自动求解')) {
    await autoAnalyze();
    return;
  }

  // Windows PE 反调试脚本
  if ((lowerMessage.includes('windows') || hasWord('pe')) &&
      (lowerMessage.includes('反调试') || lowerMessage.includes('bypass')) &&
      /(脚本|script|生成|写个?|给我)/.test(lowerMessage)) {
    await generateWindowsAntiDebugScript();
    return;
  }

  // APK 重打包签名
  if (/^(重打包|repack|回编|签名|重打包签名)$/i.test(lowerMessage.trim()) ||
      /(重打包|repack).{0,6}(脚本|怎么|如何|方法)|(生成|写).{0,6}(重打包|签名)/.test(lowerMessage)) {
    await generateSmaliRepackScript();
    return;
  }

  // RC4 动态脚本
  if (lowerMessage.includes('rc4') &&
      (lowerMessage.includes('动态') || lowerMessage.includes('hook') || lowerMessage.includes('调试')) &&
      /(脚本|script|生成|写个?|hook起来|hook一下)/.test(lowerMessage)) {
    await generateRc4DynamicScript();
    return;
  }

  // 生成脚本（精确匹配：旧 includes('脚本') 会把"写个加密脚本思路"等正常提问拦死）
  if (/^(生成脚本|脚本|script)$/i.test(lowerMessage.trim()) ||
      /(生成.*脚本|写个.*脚本|写.*hook脚本|生成.*hook)/.test(lowerMessage)) {
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
  if (/^(反调试|anti-?debug)$/i.test(lowerMessage.trim()) ||
      /(生成|写个?|给我).{0,4}反调试.{0,4}脚本/.test(lowerMessage)) {
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

  // 「保存」：把暂存的解题经验写入经验库（自动入库已改为手动触发）
  if (/^(保存|保存经验|入库)$/.test(message.trim())) {
    await flushPendingExperience();
    return;
  }

  // 「复盘」：对当前题的历史失败做证伪复盘（清除被证伪的污染经验 + 沉淀复盘教训）
  if (/^复盘$/.test(message.trim())) {
    const name = (state._platformChallenge && state._platformChallenge.name) || (state.fileInfo && state.fileInfo.fileName);
    if (!name) { addSystemMessage('**当前没有题目上下文**\n\n请先通过平台拉题或选择文件，再发「复盘」。'); return; }
    await postSolveReview(name, state.lastAiText || '');
    return;
  }

  // 经验库（reverse-skill 进化层：完成任务回写经验，下次任务自动速查）
  if (lowerMessage.startsWith('经验') || lowerMessage.startsWith('查经验')) {
    const text = message.replace(/^(经验|查经验)\s*/, '').trim();
    if (text && state.appPaths) {
      // 走与自动入库相同的"内容级去重 + 统一写入器"，避免手动回写绕过去重造成重复
      const line = `- [${new Date().toISOString().slice(0, 10)}] ${text}`;
      const key = experienceKey(text);
      const existing = [];
      for (const l of String(state.experience || '').split('\n')) { const k = experienceKey(l); if (k) existing.push(k); }
      const dup = existing.some(k => k === key || experienceSimilar(k, key));
      if (dup) {
        addSystemMessage(`**ℹ️ 该经验已存在（去重命中）**\n\n> ${text}\n\n未重复入库。发送 \`查经验\` 查看现有经验库。`);
      } else {
        const n = await writeExperienceEntries([line]);
        if (n) {
          addSolveNote('经验', text);
          addSystemMessage(`**💡 经验已入库**\n\n> ${text}\n\n下次分析时自动注入系统提示（经验速查），同类题可直接复用。`);
        } else {
          addLog('error', '经验写入失败');
        }
      }
    } else {
      const lines = (state.experience || '').trim();
      addSystemMessage(lines ? `**📚 经验库（自动注入AI提示词）**\n\n${lines.slice(-1500)}` : '**📚 经验库为空**\n\n输入 `经验 <内容>` 记录一条可复用的解题经验。');
    }
    return;
  }

  // 决策树查询（精确匹配：旧 includes('流程') 会把"解题流程/分析流程"等正常提问拦死）
  if (/^(决策树|流程|workflow|决策树查询)$/i.test(lowerMessage.trim()) ||
      /(决策树|解题流程是什么|分析流程是什么)/.test(lowerMessage)) {
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
  if (/^(apk|android|安卓)$/i.test(lowerMessage.trim()) || lowerMessage.includes('apk逆向') || lowerMessage.includes('安卓逆向')) {
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
- 安装: \`<adb 路径> -s 127.0.0.1:62025 install app.apk\`（adb 路径见设置页 _adb 项）
- Hook: \`frida -H 127.0.0.1:27042 -n "AppName" -l hook.js\`

**第5步：算法还原 → Python/Z3 解密脚本**

**第6步：提交 FLAG{...}**`);
    return;
  }

  // PE分析流程
  if (/^(pe|exe|windows)$/i.test(lowerMessage.trim()) || lowerMessage.includes('pe结构') || lowerMessage.includes('windows逆向')) {
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
  if (/^(elf|linux|so文件)$/i.test(lowerMessage.trim()) || lowerMessage.includes('elf结构')) {
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
  if (/^(tea|tea算法|tea加解密)$/i.test(lowerMessage.trim()) || lowerMessage.includes('0x9e3779b9')) {
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
  if (/^(aes|aes算法)$/i.test(lowerMessage.trim()) || lowerMessage.includes('s盒') || lowerMessage.includes('sbox')) {
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
  if (/^(sm4|sm4算法|国密)$/i.test(lowerMessage.trim()) || lowerMessage.includes('国密算法')) {
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
  if (/^(rc4|rc4算法)$/i.test(lowerMessage.trim()) || lowerMessage.includes('s盒初始化')) {
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
  if (/^(md5|md5算法)$/i.test(lowerMessage.trim()) || lowerMessage.includes('0x67452301')) {
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
  if (/^(crc|crc32)$/i.test(lowerMessage.trim()) || lowerMessage.includes('0xedb88320')) {
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

  // 输出规范（精确匹配：旧逻辑 includes('输出') 会把"输出语言用中文"等正常诉求拦死）
  if (/^(输出规范|解题规范|报告规范|format)$/i.test(lowerMessage.trim()) ||
      /(输出规范|解题报告要求)/.test(lowerMessage)) {
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

  // 工具链查询（精确匹配：仅"工具链/有哪些工具"这类提问才回固定清单）
  // 旧逻辑用 lowerMessage.includes('工具') 做子串匹配 → "不要调用工具""用什么工具解"等
  // 都命中并直接 return，用户消息根本到不了 AI（实测被此拦死）。改为精确短语匹配。
  if (/^(工具链|工具列表|有哪些工具|可用工具|tool\s*list|list\s*tools)$/i.test(lowerMessage.trim()) ||
      /(工具链|有哪些工具|可用工具)/.test(lowerMessage)) {
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

  // 重跑即新一轮：重置多阶段接力态。否则上一轮接力留下的 stageVisitedMd5/stageDepth
  // 会让本轮的合法接力被误判"已分析过"而拒绝，深度预算也被上一轮预支。
  // （接力自身的递归调用走 runStageHandoff → analyzeFile(isHandoff) → autoAnalyze，
  //  那里 depth 已由 runStageHandoff 递增，此处重置不会干扰接力链——因为接力时
  //  是先 analyzeFile 再 autoAnalyze，重入时 currentFile 已换、且仅在用户直接重跑时重置。）
  if (!state._inStageHandoff) {
    state.stageDepth = 0;
    state.stageContext = '';
    state.stageVisitedMd5 = [];
  }

  addLog('info', '========================================');
  addLog('info', '智能分析模式（基于ctf-agent）');
  addLog('info', '========================================');

  // 能力分诊（一次决策）：路由依据是文件能力/容器，不是扩展名或用户口令。
  // 旧实现把 UNKNOWN 无条件送 analyzeBIN（Kali 固件流程），而 pcap 样本恰好落进 UNKNOWN。
  // decideRoute 在主进程（与 detectCapabilities 同源），渲染层只消费结论。
  let capRoute = '';
  try {
    const cr = await window.electronAPI.detectCapabilities(state.currentFile, state.fileType);
    if (cr && cr.success) {
      state._capabilities = cr.capabilities;
      capRoute = cr.route || '';
      addLog('info', `[分诊] capabilities=${JSON.stringify(cr.capabilities)} → route=${capRoute}`);
    }
  } catch (e) { /* 能力分诊失败则退回按类型分派 */ }

  if (capRoute === 'traffic' || capRoute === 'burp') {
    // pcap：纯二进制 → 本地解析（不启动 Burp）；含 HTTP → 走 Burp 历史
    await analyzePcapFile(state.currentFile, { useBurp: capRoute === 'burp' });
    return;
  }
  if (capRoute === 'extract' && !['APK', 'ZIP', 'XLSX', 'JAR'].includes(state.fileType)) {
    // 容器/文件系统（squashfs/cramfs/ubifs/ext…）：本地优先解包，不先打 Kali
    addLog('info', '[分诊] 检测到容器/文件系统能力 → 本地优先解包');
    await analyzeBinContainer(state.currentFile);
    return;
  }

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
    case 'XLSX': {
      // 平台附件常是 zip 手包（内含 ELF/EXE/pyc 等）。自动解压 → 挑可分析的主文件继续流程；
      // 非"平台拉题"上下文（手动拖 zip）仍走原提示。
      // XLSX/OOXML（ExceLLM 类 Excel 逆向题）本质是 ZIP 容器，同路径解压看内部结构。
      if (state._platformContext) {
        await analyzeZipHandout(state.currentFile);
      } else {
        addSystemMessage('**ZIP 压缩包**\n\n不是 APK（未找到 AndroidManifest.xml）。\n建议：`kali binwalk -e 文件名` 提取内容，或检查是否嵌套题目文件。');
      }
      break;
    }
    case 'XML':
    case 'TXT': {
      // 结构化文本（OOXML 解压产物：sheet 公式 / sharedStrings / plist 等）与纯文本
      // （enc.txt 密文等）：直读全文喂 AI 文本分析——绝不进 Kali 固件流程
      //（ExceLLM/enc.txt 实测：UNKNOWN 落 Kali，3 次握手超时白烧 60s，而信息就在文本里）。
      await analyzeXMLText();
      break;
    }
    case 'PCAP': {
      // detect-file-type 的 PCAP 分支命中时直接落到这里（分诊失败也不能回退到 Kali）
      await analyzePcapFile(state.currentFile, { useBurp: !!(state._capabilities && state._capabilities.httpHint) });
      break;
    }
    case 'WASM': {
      // detect-file-type 会产出 WASM（main.js 的 0061736D 分支），但这里此前没有对应 case，
      // 于是落到 default 走"未知类型"提示。Wasm 模块是结构化二进制：
      // 走本地探测（magic/strings/熵），Kali 预检不可达时不会发远程命令。
      addLog('info', '[WASM] WebAssembly 模块：本地探测 + AI 分析（不走 Burp）');
      await analyzeBIN();
      break;
    }
    case 'UNKNOWN': {
      // 未知二进制：有 pcap/容器/文件系统能力时上面的分诊已接管；
      // 走到这里说明确实没有可识别能力 → 本地探测 + Kali 预检（不可达则纯本地兜底）。
      // （detect-file-type 从不产出 'BIN'，此前的 case 'BIN' 是死分支，已删除。）
      await analyzeBIN();
      break;
    }
    default:
      addLog('warning', '不支持的文件类型，尝试本地探测 + Kali 预检...');
      await analyzeBIN();
  }
}

// 结构化文本（XML/JSON/plist）分析：读全文（≤256KB 截断）→ 证据 → AI 文本求解闭环。
// Excel 公式题（ExceLLM）、Android manifest、macOS plist 等都靠这条路。
// 注意：不进 analyzeWebJS（那是 Burp/浏览器抓包流程）；直接复用 autoSolveBinaryFlag 的
// "AI 提示 → claudeChatCascade → finalizeSolve 三件套"骨架，但数据源是文件原文而非 IDA。
async function analyzeXMLText() {
  const label = (state.fileInfo && state.fileInfo.fileName) || 'structured.xml';
  addSolveNote('文件', `开始分析结构化文本：${label}`);
  addLog('info', 'XML/结构化文本分析流程（直读内容，不走 Kali/IDA）');
  addLog('info', '========================================');

  // [1/2] 读全文进证据（≤256KB 截断；表格类 XML 公式常达百 KB）
  let xmlText = '';
  try {
    const rf = await window.electronAPI.readFile(state.currentFile);
    if (rf && rf.success) {
      xmlText = rf.content || '';
      await caseAddEvidence('xml_source', 'XML/结构化文本原文', xmlText.length > 262144 ? xmlText.slice(0, 262144) + '\n...(truncated)' : xmlText, 'xml');
      addLog('success', `✅ XML 原文已读入并存证（${xmlText.length} 字符${xmlText.length > 262144 ? '，超 256KB 已截断' : ''}）`);
    } else {
      addLog('warning', 'XML 读取失败: ' + ((rf && rf.error) || '未知'));
    }
  } catch (e) {
    addLog('warning', 'XML 读取异常: ' + e.message);
  }

  // 伴生文件（同包其它 XML）预览清单——AI 可用 read_file 自取
  const sideFiles = (Array.isArray(state._platformFiles) ? state._platformFiles : [])
    .filter(p => String(p) !== String(state.currentFile));
  // ⚠️ 伴生文件不能只给路径：实测 rsa 题（flag.enc + pub.key）里 pub.key 只有 800 字节，
  // AI 拿到"可 read_file"提示后并没有去读，直接对着 31 字节密文瞎猜，30 秒就结束。
  // 小文件（≤8KB 的文本/密钥）直接内联进提示词，大文件才给路径让 AI 按需读取。
  let sideInline = '';
  const sideList = [];
  for (const sp of sideFiles.slice(0, 6)) {
    try {
      const rf = await window.electronAPI.readFile(sp);
      if (rf && rf.success) {
        const body = String(rf.content || '');
        const isTexty = body.length > 0 && !/[\x00-\x08\x0e-\x1f]/.test(body.slice(0, 400));
        if (isTexty && body.length <= 8192) {
          sideInline += `\n### ${String(sp).split(/[\\/]/).pop()}（内联全文，${body.length} 字符）\n\`\`\`\n${body}\n\`\`\`\n`;
        } else {
          sideList.push(`${sp}（${body.length} 字符${isTexty ? '' : '，二进制'}）`);
        }
      } else {
        sideList.push(sp);
      }
    } catch (e) { sideList.push(sp); }
  }
  const sideNote = (sideInline || sideList.length)
    ? `\n\n## 同包伴生文件（本题材料，**必须一起看**）`
      + (sideInline ? `\n${sideInline}` : '')
      + (sideList.length ? `\n其余（用 read_file 读取）：\n${sideList.map(p => `- ${p}`).join('\n')}\n` : '')
      + `\n⚠️ 密码学类题（密文+.key/.pem/.crt）的密钥参数就在伴生文件里：先解析它（openssl rsa -pubin -text -noout 或 Python ` + '`' + `Crypto.PublicKey.RSA.import_key` + '`' + `），再决定攻击方式（小 e 开方/共模/Wiener/factordb）。\n`
    : '';

  // [2/2] AI 求解（直接分析 XML 文本；Excel 公式题的公式就是"代码"）
  addLog('info', '[2/2] AI 分析 XML 内容并求解...');
  const xmlSlice = xmlText.length > 200000 ? xmlText.slice(0, 200000) + '\n...(truncated)' : xmlText;
  const knowledge = await prefetchKnowledge(xmlText.slice(0, 30000), 'XML');

  const analysisPrompt = `我正在分析一个CTF题目，载体是结构化文本（XML/JSON/plist，可能来自 Excel/OOXML 解压）。

文件路径：${state.currentFile}

## 文件全文
\`\`\`xml
${xmlSlice || '（读取失败，请用 read_file 工具自行读取）'}
\`\`\`${sideNote}
${knowledge}

⚠️ 题目边界（重要）：只分析**当前文件与上面列出的伴生文件**。下载目录里可能有其它题目的历史
残留文件（目录名是别的题名），那些与本题无关——绝不读取、更不要把它们的内容当本题答案。
经验库的相似经验只作方法参考，本题的结论必须来自本题文件。

请分析上面的内容，找出：
1. 该文件的用途与题目机制（如 Excel 公式实现的校验器/神经网络：SUMPRODUCT 加权求和、MAX(0,...)=ReLU、--(...)=布尔转整数、sheet 间的引用链）
2. flag 的生成或验证逻辑（公式中的常量表/权重表/约束条件如何反推输入）
3. 直接给出 flag

方法指引：
- Excel 公式题把 SUMPRODUCT(BITS!..., WEIGHTS!...) 看作矩阵乘法，阈值比较看作激活函数；
- 主文件常常只是校验器的一部分（如 VERIFY sheet），**BITS（输入位展开）/WEIGHTS（权重常量）在伴生文件里**：
  用 read_file 工具读取伴生文件（同包 sheet XML 均在），把权重表和 BITS 公式看全后再反推；
- 数据齐了用 bash 工具写 Python 复现前向计算，从约束（如"27 个神经元全为 1"）反推每位输入的 ASCII。
- 若当前文件是**密文/编码文本**（enc.txt 等）：优先做单字节 XOR / 移位 / 换表等轻量变换枚举，
  用 bash 跑 Python 暴力扫描并匹配常见 flag 前缀（flag|ctf|sun|dice|sunshine...）；不要急着复杂化。

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，必须附验证数据（工具会本地复现）：
   \`${VERIFY_CONTRACT}\`
   （custom 需附 "code":"def decrypt(data,key): ...完整函数"；多个候选时输出 \`[HYPOTHESES][{...},{...}][/HYPOTHESES]\` 供本地枚举）

如果无法可靠得到完整 flag，不要只回复"无法分析"，必须输出：
## 题目掌握度
- 已确认的关键点：
- 当前推断及置信度：高/中/低
- 仍缺少的信息：
## 人工引导
- 需要用户补充哪些文件/数据：`;

  addLog('info', '分析提示构建完成，长度: ' + analysisPrompt.length + ' 字符');

  state.aiBusy = true;
  beginStreamMessage();
  const startTime = Date.now();
  try {
    // 不带"不要调用任何工具"措辞 → claudeChatWithTools 走 Tool-Use 路径，
    // AI 可 read_file 读伴生 sheet / bash 跑 Python 反推（ExceLLM 类多 sheet 题必需）。
    const result = await claudeChatCascade(
      [{ role: 'user', content: analysisPrompt }],
      `你是CTF逆向解题专家。可以调用工具：read_file 读取题目伴生文件，bash 执行 Python 复现计算。拿到完整数据后再给结论。\n解题学习闭环（强制）：回答最后必须输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条、每条200字内[/EXPERIENCE]（确无新收获则写"无新增经验"），工具会自动写入经验库，下次同类题优先复用、避免重复踩坑。` + experienceSection()
    );
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    addLog('info', `AI响应完成，耗时 ${elapsed} 秒`);
    endStreamMessage();
    if (result.success && result.text) {
      const clean = String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000);
      addSolveNote('求解结果', clean);
      state.lastAiText = result.text;
      await finalizeSolve(result.text, { source: 'ai' });
      addSystemMessage(`**🎯 XML 分析结果**\n\n**文件**: ${label}\n\n${result.text}`);
    } else {
      addLog('warning', 'AI 分析未返回有效结果: ' + ((result && result.error) || '未知'));
      endStreamMessage();
    }
  } catch (e) {
    endStreamMessage();
    addLog('error', 'XML AI 分析异常: ' + e.message);
  } finally {
    state.aiBusy = false;
  }
}

// JAR/.class 分析（jadx 反编译）
async function analyzeJava() {
  // JAR/.class：走 JEB 统一求解（JEB 对 JAR/class 同样可加载；不可用时降级 jadx）
  await analyzeJavaLike('JAR', 'Java(JAR/.class)');
}

// Mach-O 分析：IDA 支持 Mach-O（含 fat binary），走与 PE/ELF 相同的二进制求解闭环
async function analyzeMachO() {
  addSolveNote('文件', `开始分析 Mach-O：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', '开始 Mach-O (macOS/iOS) 分析流程');
  addLog('info', '========================================');

  // fat binary（通用二进制）IDA 也能打开（可选架构）；这里直接交给 IDA MCP 采集
  addLog('info', '[1/3] 启动 IDA 分析（支持 Mach-O / fat binary）...');
  await launchTool('ida');
  await new Promise(resolve => setTimeout(resolve, 3000));
  const idaMcpConnected = await connectIdaMcpWithWait();
  if (!idaMcpConnected) {
    addLog('warning', 'IDA MCP 未连接，Mach-O 静态求解需 IDA 就绪');
    addSystemMessage(`**Mach-O 分析：IDA 未就绪**

请确认 IDA 已加载该 Mach-O 且 MCP 插件在线（127.0.0.1:13337，可自动拉起）。

手工要点：
1. **确认架构**：fat binary 需拆分 \`lipo -thin arm64 fat.bin -output arm64.bin\`
2. **Objective-C/Swift**：关注 \`objc_msgSend\` 调用与方法名
3. **动态调试**：macOS 用 lldb；iOS 需砸壳 ipa + frida（Windows 上建议传 Kali/macOS 虚拟机）`);
    return;
  }

  // 复用二进制求解闭环（IDA 采集 → AI 求解 → 验证 → 经验）
  addLog('info', '[2/3] 交给 IDA MCP 驱动的二进制求解闭环...');
  await autoSolveBinaryFlag('MACHO');
  addLog('info', '[3/3] Mach-O 流程完成');
}

// Lua 字节码分析：抽取字节/常量/字符串 → AI 求解（对齐 PYC 的做法）
// 旧实现只打印一段"用 unluac" 的指引文字，AI 完全不参与。现改为：
//   用 python 扫描 .luac 里的明文串/长 hex/base64/大整数（常量表通常明文），喂给 AI 还原。
async function analyzeLua() {
  addSolveNote('文件', `开始分析 Lua 字节码：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', '开始 Lua 字节码 (.luac) 分析流程');
  addLog('info', '========================================');

  // [1/3] 字节/字符串/常量抽取（纯 Python 扫描，不依赖 unluac）
  addLog('info', '[1/3] 扫描字节/常量/字符串...');
  let version = '未知';
  let scan = '';
  try {
    const py = [
      'import sys,re',
      'data=open(sys.argv[1],"rb").read()',
      'print("SIZE", len(data))',
      'hdr=data[:4]',
      'if len(hdr)>=4 and hdr[0]==0x1b:',
      '    print("LUAC_MAGIC ok ver=%d.%d"%(hdr[3],hdr[4]) if len(hdr)>4 else "LUAC_MAGIC ok")',
      'txt=data.decode("latin-1")',
      'for m in sorted(set(re.findall(r"[ -~]{4,}", txt)), key=len, reverse=True)[:120]:',
      '    print("STR", m[:200])',
      'for m in sorted(set(re.findall(r"\\b[0-9a-fA-F]{24,}\\b", txt)), key=len, reverse=True)[:20]:',
      '    print("HEX", m[:200])',
      'for m in sorted(set(re.findall(r"\\b[A-Za-z0-9+/]{20,}={0,2}\\b", txt)), key=len, reverse=True)[:20]:',
      '    print("B64", m[:200])'
    ].join('\n');
    const r = await window.electronAPI.runToolArgs(['python', '-c', py, state.currentFile]);
    if (r && r.success && r.stdout) {
      scan = String(r.stdout);
      const vm = scan.match(/ver=(\d+\.\d+)/);
      if (vm) version = vm[1];
      const ok = /LUAC_MAGIC ok/.test(scan);
      addLog(ok ? 'success' : 'warning', ok ? `✅ 识别为 Lua 字节码（版本 ${version}）` : '未识别到标准 luac 头（可能是自定义/混淆字节码）');
    } else {
      addLog('warning', 'Lua 扫描未返回输出: ' + ((r && r.error) || '未知'));
    }
  } catch (e) {
    addLog('warning', 'Lua 扫描异常: ' + e.message);
  }
  if (scan) await caseAddEvidence('luac_scan', 'Lua 字节码扫描', scan.slice(0, 6000), 'txt');

  // [2/3] AI 求解（无有效数据则短路，避免臆测）
  const hasData = scan && /^(STR|HEX|B64) /m.test(scan);
  if (!hasData) {
    addLog('warning', '未提取到有效常量/字符串，AI 求解跳过（避免臆测）');
    addSystemMessage(`**Lua 字节码分析**：未从 ${state.fileInfo ? state.fileInfo.fileName : '文件'} 提取到有效字符串/常量。

手工要点：
1. **确认 Lua 版本**：文件头第 5 字节（0x51=5.1 / 0x52=5.2 / 0x53=5.3 / 0x54=5.4）
2. **反编译**：\`java -jar unluac_2015.jar file.luac > out.lua\`（版本要对）；5.3/5.4 也可 \`luac -l\`
3. 遇自定义 VM/字节码混淆时先还原 opcode 映射表`);
    return;
  }

  addLog('info', '[2/3] 调用 AI 还原算法并求 flag...');
  const knowledge = await prefetchKnowledge(scan, 'LUAC');
  const prompt = `我在解一道 CTF Lua 字节码（.luac）逆向题。已扫描出**明文串/长hex/base64/常量**，请据此还原算法并求出 flag。

文件：${state.fileInfo ? state.fileInfo.fileName : state.currentFile}
Lua 版本：${version}

## 扫描结果（STR=明文串 / HEX=长hex / B64=疑似base64）
\`\`\`
${scan.slice(0, 8000)}
\`\`\`
${knowledge}

## 解题要点
- Lua 常量表通常是明文：flag 校验常用 字符串比较 / 逐字节变换 / XOR / base64（含自定义字符表）。
- 若为自定义 VM/字节码混淆：先还原 opcode 映射，再按解释执行反推。
- 需要时用 \`run_python\` 实际跑一遍验证。

**输出契约（务必遵守）：**
1. 得出 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附验证契约：${VERIFY_CONTRACT}
3. 多个候选：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 末尾 \`[EXPERIENCE]每条一行,最多5条[/EXPERIENCE]\`
不要臆造；拿不准就写"待人工验证"。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      buildSystemPrompt()
    );
    endStreamMessage();
    addLog('info', `AI 求解完成，耗时 ${((Date.now() - startTime) / 1000).toFixed(1)} 秒`);
    if (result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(Lua)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      // [3/3] 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      addLog('info', '[3/3] 本地复现验证...');
      const { verifiedFlags: vf, flags } = await finalizeSolve(result.text, { source: 'lua' });
      addSystemMessage(`**🌙 Lua 字节码分析结果**

${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`);
      return;
    }
    if (result.aborted || /已取消/.test(result.error || '')) { addLog('info', 'Lua AI 求解已停止'); return; }
    addLog('warning', 'AI 求解未返回内容: ' + (result.error || '未知'));
  } catch (err) {
    try { endStreamMessage(); } catch (e) {}
    addLog('error', 'Lua AI 求解异常: ' + err.message);
  } finally {
    state.aiBusy = false;
  }
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

    // 关键：设备"在线"≠"包管理器就绪"。模拟器刚开机时 system_server 尚未注册
    // package 服务，此时 install 会秒失败 —— `cmd: Can't find service: package`
    // （CrackMe_1_3 实战触发）。安装前先轮询 `service check package`，直到 found。
    {
      let pkgReady = false;
      const deadline = Date.now() + 60000; // 最长等 60s（Android 冷启动偏慢）
      let waited = 0;
      while (Date.now() < deadline) {
        try {
          const chk = await window.electronAPI.adbCommand('shell service check package');
          const o = `${(chk && chk.stdout) || ''}${(chk && chk.stderr) || ''}`;
          if (/found/i.test(o) && !/not found/i.test(o)) { pkgReady = true; break; }
        } catch (e) { /* 继续等 */ }
        if (waited === 0) addLog('info', '等待模拟器 package 服务就绪...');
        await new Promise(r => setTimeout(r, 2000));
        waited += 2;
      }
      if (!pkgReady) {
        addLog('warning', '模拟器 package 服务在 60s 内未就绪（系统可能仍在启动），继续尝试安装...');
      } else if (waited > 0) {
        addLog('info', `模拟器 package 服务已就绪（等待 ${waited}s）`);
      }
    }

    // 安装APK（-r 覆盖安装；-t 允许 testOnly 包——CTF 题 APK 常带此标记，
    // 缺它会 INSTALL_FAILED_TEST_ONLY 秒失败）。
    // install 对"服务未就绪/冷启动未就绪/管道中断"等瞬时错误做重试（最多 4 次，间隔递增）。
    let result = null, out = '', installOk = false;
    for (let attempt = 1; attempt <= 4; attempt++) {
      addLog('info', attempt === 1 ? '正在安装APK...' : `重试安装APK（第${attempt}次）...`);
      result = await window.electronAPI.adbCommand(`install -r -t "${state.currentFile}"`);
      out = `${(result && result.stdout) || ''}\n${(result && result.stderr) || ''}`;
      installOk = /Success/i.test(out) && !/Failure|Missing APK file|no devices\/emulators found/i.test(out);
      if (installOk) break;
      // 瞬时失败类型（值得重试）：
      //  - 服务未就绪/管道中断：Can't find service / Failure calling service / Broken pipe / offline
      //  - 冷启动期通用安装失败：adb 输出 `Failed to install <path>:`（原因常为空），
      //    这是模拟器刚开机、installd/dexopt 尚未就绪的典型症状（本题 03:51 复现）。
      //    确定性错误（INSTALL_FAILED_TEST_ONLY / 签名 / NO_CERTIFICATE 等）不重试。
      const definitive = /INSTALL_FAILED_TEST_ONLY|INSTALL_PARSE_FAILED|INSTALL_FAILED_UPDATE_INCOMPATIBLE|NO_CERTIFICATE|signatures do not match|INSTALL_FAILED_INSUFFICIENT_STORAGE|INSTALL_FAILED_ALREADY_EXISTS\b(?!.*-r)/i.test(out);
      const transient = !definitive && (
        /Can't find service|Failure calling service|Broken pipe|device offline|device not found|closed|error: closed/i.test(out)
        || /Failed to install/i.test(out)   // 冷启动期通用失败（含原因为空）
      );
      if (!transient || attempt === 4) break;
      addLog('warning', `安装瞬时失败（${out.trim().slice(0, 160) || '模拟器冷启动未就绪'}），重建 adb 连接后重试`);
      // 重试前重建 adb：重连设备 + 重设到 port。主进程 adb-command 内部还会在检测到
      // 版本不匹配时 kill-server/start-server，双保险确保 daemon 属于当前客户端。
      // 冷启动场景等待更久（installd/dexopt 就绪需要时间）。
      await new Promise(r => setTimeout(r, 3000 + attempt * 4000));
      await window.electronAPI.adbCommand(`connect 127.0.0.1:${adbPort}`);
      // 重新确认 package 服务（daemon 重建后服务引用可能需重新解析）
      try { await window.electronAPI.adbCommand('shell service check package'); } catch (e) { /* 忽略 */ }
    }

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
      // 重新转发并探活：daemon 重建会丢 forward，光有进程不代表端口可达
      await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);
      let ok = false;
      for (let i = 0; i < 4; i++) {
        try { const pr = await window.electronAPI.checkPort(`http://127.0.0.1:${fridaPort}/`); ok = !!(pr && pr.listening); } catch (e) { ok = false; }
        if (ok) break;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      if (ok) {
        addLog('success', `Frida 服务已在运行，复用（端口: ${fridaPort}）`);
        setMcpStatus('frida', true);
        return true;
      }
      addLog('info', 'frida-server 进程在但端口不可达，重新启动...');
      // 落到下面走"杀残留→重启"逻辑
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

    // 设置端口转发（一次即可；重复调用无意义）
    await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);

    // 验证：进程在跑 + 端口真的可达。
    // 不能只看 `ps | grep frida`——adb daemon 被 nox_adb 顶掉重建时 forward 会丢失，
    // 此时进程还在但 127.0.0.1:27042 已不可达（实战中导致动态阶段被整段跳过）。
    const psResult = await window.electronAPI.adbCommand('shell "ps | grep frida"');
    const procAlive = psResult.success && /frida-server/.test(psResult.stdout || '');
    let reachable = false;
    for (let i = 0; i < 5 && procAlive; i++) {
      try {
        const pr = await window.electronAPI.checkPort(`http://127.0.0.1:${fridaPort}/`);
        reachable = !!(pr && pr.listening);
      } catch (e) { reachable = false; }
      if (reachable) break;
      // forward 可能因 daemon 重建丢失：重新转发后再探
      await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    if (procAlive && reachable) {
      addLog('success', `✅ Frida服务已启动 (端口: ${fridaPort})`);
      setMcpStatus('frida', true);
      return true;
    } else if (procAlive && !reachable) {
      addLog('warning', `frida-server 进程在运行，但 ${fridaPort} 端口不可达（端口转发可能失效）`);
      setMcpStatus('frida', false);
      return false;
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

  // 1. 枚举函数（IDA MCP 工具名/参数随版本变化，逐个试到可用）
  // 实测 ida-pro-mcp v1.0.0：真实工具是 list_funcs（参数 {queries:{filter,count}}）与
  // func_query；旧代码用的 export_funcs {}(缺 addrs 报错) / list_functions(不存在) 全部失败，
  // 导致 fnText 为空 → 一个函数都反编译不了（本题「未取到反编译结果」的真因）。
  let fnText = '';
  for (const [tool, args] of [
    // 分页版本：list_funcs 默认 count=100，只取一页会漏掉大量函数（SO 常上千个函数）
    ['list_funcs', { paged: true }],
    ['func_query', { queries: {} }],
    ['list_functions', { paged: true }],                   // 旧/其他实现兼容
    ['export_funcs', { addrs: [] }],                       // 万不得已（通常为空）
    ['survey_binary', {}]                                  // 最后兜底：至少给元数据/函数名
  ]) {
    try {
      const r = args && args.paged
        ? await window.electronAPI.idaMcpCallPaged(tool, {})
        : await window.electronAPI.idaMcpCall(tool, args);
      if (r && r.success && r.result) {
        const txt = typeof r.result === 'string' ? r.result : JSON.stringify(r.result);
        // 判定"拿到了函数清单"：出现 sub_/Java_/函数名或 addr+name 结构
        if (/sub_[0-9A-Fa-f]+|Java_[A-Za-z0-9_]+|"name"\s*:|0x[0-9a-f]{4,}\s+\S/.test(txt)) {
          fnText = txt; addLog('info', `IDA 函数清单来源: ${tool}`); break;
        }
        if (!fnText) fnText = txt; // 先留个底，继续试更好的
      }
    } catch (e) { /* 换下一个工具名 */ }
  }
  if (fnText) intel.exports = fnText.slice(0, 4000);

  // 2. 挑要反编译的函数：
  //    (a) JNI 导出（Java_…）——最高优先
  //    (b) 语义名（encrypt/decrypt/check/verify/key/flag/crypt/sign/hash/stage…）
  //    (c) 剥离符号后的 sub_XXXX：无法靠名字，改为**多取一批**（真逻辑常在里面），
  //        并在第(3)步按"反编译后是否含常量比较/循环XOR/查表/memcmp"二次筛选。
  const jniNames = [...new Set((fnText.match(/Java_[A-Za-z0-9_]+/g) || []))].slice(0, 12);
  const semantic = [...new Set((fnText.match(/\b[A-Za-z_][A-Za-z0-9_]*(?:encrypt|decrypt|cipher|check|verify|key|flag|crypt|sign|hash|stage|init|load|jni)[A-Za-z0-9_]*\b/gi) || []))].slice(0, 10);
  // sub_XXXX / FUN_xxx（IDA 对无符号函数的默认命名）最多取前 40 个，供行为筛选
  const subs = [...new Set((fnText.match(/\b(?:sub|FUN|j_|nullsub)_[0-9A-Fa-f]+\b/g) || []))].slice(0, 40);
  const ordered = [...jniNames, ...semantic, ...subs].filter((v, i, a) => v && a.indexOf(v) === i);
  intel.jniFuncs = [...jniNames, ...semantic].filter((v, i, a) => a.indexOf(v) === i);

  // 行为特征：反编译文本里出现下列任一项 → 该函数值得保留（真算法/校验函数几乎必中一条）
  const BEHAVIOR = [
    /0x9[eE]3779[bB]9/,       // TEA/XTEA 魔数
    // 大常量：排除裸地址（sub_/loc_/函数地址多为 0x401000 这类 6-7 位、或等于本函数内的 loc），
    // 只认 8 位以上且**带异或/比较语义**的常量，避免"人人命中"把名额占满。
    /(?:==|!=|\^|&|\|)\s*0x[0-9a-fA-F]{8,}/,
    /0x[0-9a-fA-F]{12,}/,      // 更长常量（64 位模数/密钥片段）
    /\^|<<|>>/,                // 位运算（异或/移位，流密码/哈希特征）
    /memcmp|strcmp|strncmp|Arrays|equals/i,
    /for\s*\(|while\s*\(/,     // 存在循环
    /\[[^\]]+\]\s*[;=]/,       // 数组下标读写（查表）
    /sbox|Sbox|RC4|MD5|SHA|AES|DES|TEA|ChaCha|Salsa/i,
  ];

  // 3. 逐个反编译：先按 ordered 走，边反编译边按行为打分；
  //    分两个上限：保底 15 个（够写进上下文）+ 硬上限 28 个（防爆上下文）。
  //    优先级函数（JNI/语义名）一律保留并占用名额；无名 sub_* 命中行为特征保留。
  //    单个函数上限 12000 字符（之前 6×6000 会漏掉/截断真正承载算法的 sub_）。
  const MIN_KEEP = 15, MAX_KEEP = 28;
  const decompiledNames = new Set();
  let behavioralKept = 0;
  let decompileErrors = 0;
  for (const name of ordered) {
    if (intel.decompiled.length >= MAX_KEEP) break;
    if (decompiledNames.has(name)) continue;
    decompiledNames.add(name);
    try {
      // 注意：必须用 window.electronAPI（大写 API）。曾误写为 electronApi → 每次调用
      // 都抛 TypeError 并被下面的 catch 静默吞掉 → 一个函数都反编译不了（本题「未取到
      // 反编译结果」的真因：IDA 明明连上了、get_bytes/list_globals 都成功，唯独代码为空）。
      const r = await window.electronAPI.idaMcpCall('decompile', { address: name });
      if (r && r.success && r.result) {
        const code = typeof r.result === 'string' ? r.result : JSON.stringify(r.result);
        // 行为打分：sub_*/无符号函数只有在命中行为特征时才保留；JNI 导出与语义名无条件保留。
        const isPriority = jniNames.includes(name) || semantic.includes(name);
        const hits = BEHAVIOR.filter(re => re.test(code)).length;
        // 优先函数 / 命中≥2 / (未达保底数时命中≥1) 都保留
        const keep = isPriority || hits >= 2 || (intel.decompiled.length < MIN_KEEP && hits >= 1);
        if (keep) {
          intel.decompiled.push({ name, code: code.slice(0, 12000), raw: r.result, hits });
          if (!isPriority) behavioralKept++;
          addLog('info', `IDA 已反编译: ${name}（${code.length} 字符, 行为特征 ${hits}）`);
        }
      }
    } catch (e) {
      // 不再静默：把前 3 个失败原因记到日志，避免"IDA 连上了却 0 反编译"这类问题被吞掉无从排查
      decompileErrors++;
      if (decompileErrors <= 3) addLog('warning', `IDA 反编译失败(${name}): ${e && e.message ? e.message : e}`);
    }
  }
  if (!intel.decompiled.length && ordered.length) {
    addLog('warning', `IDA 反编译 0 个函数（尝试 ${ordered.length} 个，失败 ${decompileErrors} 个）——请检查 IDA MCP 的 decompile 工具是否可用`);
  }
  if (behavioralKept) addLog('success', `IDA 采集：额外按行为特征保留 ${behavioralKept} 个无名函数(sub_*)`);

  // 3b. 采集被引用的全局数据表（关键！）
  //     SO 里的密钥常量 / 密文表 / S 盒 / ChaCha 常量 通常放在 .data/.rodata 全局数组里，
  //     只给反编译代码、不给常量表 → AI 永远还原不出算法（本类题"动态失败+静态缺数据"的典型）。
  //     复用 PE 流程同款逻辑：从反编译结果的 refs 取被引用地址 → list_globals 匹配 → get_bytes 取值。
  try {
    // 被引用地址有两个来源，取并集（raw.refs 常缺失，故必须再从反编译文本里抠）：
    //  (1) raw.refs（IDA MCP decompile 返回的引用列表）
    //  (2) 反编译文本中的符号名 —— off_XXX/byte_XXX/dword_XXX/qword_XXX/unk_XXX/&xxx 等
    //      （IDA 伪代码里全局数组几乎都以这类名字出现；抠出名字后交给 IDA 按名解析地址）
    const refAddrs = idaCollectRefAddrs(intel.decompiled.map(d => ({ refs: (d && d.raw && d.raw.refs) || [] })));
    const refNames = new Set();
    for (const d of intel.decompiled) {
      const m = String(d.code || '').match(/\b(?:off|byte|word|dword|qword|unk|flt|dbl|stru|algn)_[0-9A-Fa-f]{4,}\b/g) || [];
      for (const s of m) refNames.add(s);
    }
    // 分页拿全量：strip 过的 so 常上千个全局符号，默认 100 条会漏掉真正的大表
    const gRes = await window.electronAPI.idaMcpCallPaged('list_globals', {});
    const globals = (gRes && gRes.success && Array.isArray(gRes.result)) ? gRes.result : [];
    if (refAddrs.size || refNames.size || globals.length) {
      const byAddr = globals
        .map(g => ({ addr: String((g && g.addr) || ''), name: String((g && g.name) || ''), val: parseInt((g && g.addr) || '', 16) }))
        .filter(g => Number.isFinite(g.val))
        .sort((a, b) => a.val - b.val);
      const wanted = [];
      for (let i = 0; i < byAddr.length; i++) {
        const g = byAddr[i];
        const hitByAddr = refAddrs.has(g.addr.toLowerCase());
        const hitByName = refNames.has(g.name);
        if (!hitByAddr && !hitByName) continue;
        const next = byAddr[i + 1];
        let size = next ? next.val - g.val : 256;
        // 大表（VM 字节码/密文表/S盒）常 >8KB：上限放宽到 64KB（超过则截，而非一刀切退 256）
        if (!(size > 0)) size = 256;
        else if (size > 65536) size = 65536;
        wanted.push({ addr: g.addr, name: g.name, size });
      }
      if (wanted.length) {
        const bRes = await window.electronAPI.idaMcpCall('get_bytes', {
          regions: wanted.map(w => ({ addr: w.addr, size: w.size }))
        });
        if (bRes && bRes.success && Array.isArray(bRes.result)) {
          intel.globals = bRes.result.map((r, i) => ({
            name: (wanted[i] && wanted[i].name) || (r && r.addr) || 'global',
            addr: (r && r.addr) || (wanted[i] && wanted[i].addr) || '',
            data: (r && r.data) || ''
          }));
          addLog('success', `✅ 已读取 ${intel.globals.length} 个 SO 全局数据表: ${intel.globals.map(g => g.name).join(', ')}`);
        }
      }
      // 兜底：若 refs 没带出任何地址，至少把全部全局符号名+地址列出（AI 可据此判断哪个像常量表）
      if (!intel.globals && globals.length) {
        intel.globalsList = globals.slice(0, 40).map(g => `${(g && g.addr) || '?'}  ${(g && g.name) || ''}`).join('\n');
        addLog('info', `IDA 全局符号: ${globals.length} 个（已列前 40）`);
      }
    }
    // 段级兜底：完全无 refs / 无符号时（剥离 so），直接 dump .data/.rodata 段数据，
      // 保证"密钥/密文/常量表"这类数据一定进上下文。用 survey_binary 取段信息。
    if (!intel.globals || !intel.globals.length) {
      try {
        const sv = await window.electronAPI.idaMcpCall('survey_binary', {});
        const svText = sv && sv.success ? (typeof sv.result === 'string' ? sv.result : JSON.stringify(sv.result)) : '';
        // 从段信息里解析 (name, start, end/ size)：兼容 "name ... 0xSTART ... 0xEND/size" 多种排版
        const segs = [];
        const re = /\b(\.?(?:rodata|data|bss|data\.rel|rodata\.rel))\b[^\n]*?(0x[0-9a-fA-F]{6,})[^\n]*?(0x[0-9a-fA-F]{4,}|0x[0-9a-fA-F]{6,})?/g;
        let mm;
        while ((mm = re.exec(svText)) !== null) {
          const start = parseInt(mm[2], 16);
          let size = mm[3] ? parseInt(mm[3], 16) : 0;
          if (size && size < start) size = size; // 若第三段是 end 地址则按 end-start
          else if (mm[3] && parseInt(mm[3], 16) > start) size = parseInt(mm[3], 16) - start;
          if (!size || size <= 0) size = 65536;
          size = Math.min(size, 65536);       // 单段最多 64KB，防爆
          segs.push({ name: mm[1], start, size });
        }
        if (segs.length) {
          const regions = segs.slice(0, 4).map(s => ({ addr: '0x' + s.start.toString(16), size: s.size }));
          const bRes = await window.electronAPI.idaMcpCall('get_bytes', { regions });
          if (bRes && bRes.success && Array.isArray(bRes.result)) {
            intel.segments = bRes.result.map((r, i) => ({
              name: (segs[i] && segs[i].name) || 'seg',
              addr: (r && r.addr) || (segs[i] && '0x' + segs[i].start.toString(16)) || '',
              data: (r && r.data) || ''
            })).filter(g => g.data);
            if (intel.segments.length) addLog('success', `✅ 已 dump ${intel.segments.length} 个数据段(.rodata/.data)兜底`);
          }
        }
      } catch (e) { /* 段兜底失败不阻塞 */ }
    }
  } catch (e) { /* 采集失败不阻塞 */ }

  // 4. 搜关键字符串（flag/key/密文常量；含 crypto 特征：nonce/iv/salt/chacha/tea 等）
  try {
    const rs = await window.electronAPI.idaMcpCall('find_strings', { pattern: 'flag|ctf|key|secret|nonce|salt|cipher|chacha|salsa|aes|des|rc4|tea|sign|[0-9a-fA-F]{32,}' });
    if (rs && rs.success && rs.result) {
      // find_regex 返回 {n, matches:[{addr,string}]}；渲染成 `addr  string` 列表，
      // 比整段 JSON 更省 token、也便于 AI 直接引用。其他形态兜底字符串化。
      const r = rs.result;
      let rendered;
      if (r && Array.isArray(r.matches)) {
        rendered = r.matches.map(m => `${(m && m.addr) || '?'}  ${(m && (m.string || m.text)) || ''}`).join('\n');
      } else if (Array.isArray(r)) {
        rendered = r.map(m => (m && (m.string || m.text)) ? `${(m && m.addr) || '?'}  ${m.string || m.text}` : String(m)).join('\n');
      } else {
        rendered = typeof r === 'string' ? r : JSON.stringify(r);
      }
      intel.strings = rendered.slice(0, 3000);
      const cnt = r && Array.isArray(r.matches) ? r.matches.length : (Array.isArray(r) ? r.length : 0);
      addLog('info', `IDA 关键字符串: ${cnt} 条命中`);
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
// ========== Java 系（DEX / JAR / .class）统一 AI 求解（JEB 优先） ==========
// 背景：旧 analyzeDEX / analyzeJava 各只有 ~20 行，只"启动 jadx"就结束 —— AI 完全不参与，
// 没有验证闭环、没有经验沉淀、没有题库预取。而用户实际用的是 JEB（MCP 已全套接好：
// get_all_classes / get_class_decompiled_code / get_manifest）。现统一为：JEB 采集 → 预取题库
// → AI 求解 → finalizeSolve 三件套。JEB 不可用时降级为"启动 jadx + 明确指引"（不假装已解）。
async function analyzeJavaLike(fileType, fileLabel) {
  const label = fileLabel || fileType || 'Java';
  clearMcpCache();   // 防止上一个文件的类列表/反编译残留污染本次分析
  addSolveNote('文件', `开始分析 ${label}：${state.fileInfo ? state.fileInfo.fileName : '未知'}`);
  addLog('info', `开始 ${label} 分析流程（JEB 优先 + AI 求解）`);
  addLog('info', '========================================');

  // [1/4] JEB 采集：类列表 + 关键类反编译
  addLog('info', '[1/4] 通过 JEB MCP 采集类列表与关键类反编译...');
  let classes = null;
  try {
    const r = await window.electronAPI.jebMcpCall('get_all_classes', [state.currentFile]);
    if (r && r.success && Array.isArray(r.result)) {
      classes = r.result;
      mcpCache.classes = r.result;
      addLog('success', `✅ 已获取 ${classes.length} 个类`);
    } else {
      addLog('warning', 'JEB 未返回类列表: ' + ((r && r.error) || '未知'));
    }
  } catch (e) {
    addLog('warning', 'JEB get_all_classes 失败: ' + e.message);
  }

  if (!classes || !classes.length) {
    // 降级链：JEB MCP 不可用 → jadx **命令行**反编译出源码 → 交给 AI 求解。
    // ⚠️ 旧实现只 `launchTool('jadx')` 打开 GUI 然后 return，等于"AI 求解跳过"——
    // 实测批量里 10+ 道 JAR/APK 题因此 30 秒内草草结束（JEB 超时 → 直接放弃）。
    addLog('warning', 'JEB MCP 未取得类列表，降级为 jadx 命令行反编译 + AI 求解');
    try {
      const jadxPath = (state.config && state.config.tools && state.config.tools.jadx) || '';
      if (jadxPath) {
        const outDir = (state.caseDir || (state.appPaths && state.appPaths.userData) || '.') + '/jadx_out';
        addLog('info', `[jadx] 反编译到 ${outDir} ...`);
        const jr = await window.electronAPI.runToolArgs([jadxPath, '-d', outDir, '--no-res', state.currentFile], { timeout: 300000 });
        if (jr && jr.success) {
          // 收集 .java 源码（限制总量，避免撑爆上下文）
          let code = '';
          try {
            // 无 glob API：用 grep-in-dir 列出所有 class 声明所在文件（返回 "file:line: text" 字符串数组）
            const gr = await window.electronAPI.grepInDir(outDir, '^\\s*(public\\s+)?(final\\s+)?class\\s+\\w+');
            const files = [];
            if (gr && gr.success && Array.isArray(gr.hits)) {
              for (const h of gr.hits) {
                const f = String(h).split(':')[0];
                if (f && f.toLowerCase().endsWith('.java') && !files.includes(f)) files.push(f);
              }
            }
            const picked = files.slice(0, 40);
            for (const f of picked) {
              const rf = await window.electronAPI.readFile(f);
              if (rf && rf.success) {
                code += `\n// ==== ${String(f).split(/[\\/]/).pop()} ====\n` + String(rf.content || '').slice(0, 6000);
                if (code.length > 60000) break;
              }
            }
          } catch (e) { /* 收集失败则只用 stdout */ }
          if (!code && jr.stdout) code = String(jr.stdout).slice(0, 30000);
          if (code.trim()) {
            addLog('success', `[jadx] 已获取 ${code.length} 字符源码，交给 AI 分析`);
            const prompt = `以下是 JADX 反编译出的 Java 源码（题目：${label}）。请找出 flag 的生成/校验逻辑并求解。\n\n\`\`\`java\n${code.slice(0, 60000)}\n\`\`\`\n\n输出契约：\n1. 得到 flag 单独一行 \`[FLAG]flag内容[/FLAG]\`\n2. 附 \`${VERIFY_CONTRACT}\`（工具会本地复现）\n3. 做不出要写清卡在哪一步、已排除哪些路线`;
            beginStreamMessage();
            const res = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
            endStreamMessage();
            if (res && res.success && res.text) {
              state.lastAiText = res.text;
              await finalizeSolve(res.text, { source: 'ai-jadx' });
              const vf = ((state.findings && state.findings.flags) || []).filter(f => f.verified);
              if (vf.length) { addLog('success', `[jadx] ✅ 解出已验证 flag: ${vf[0].flag}`); return; }
            }
            addLog('warning', '[jadx] AI 未产出已验证 flag');
            return;
          }
        }
        addLog('warning', '[jadx] 反编译失败或无源码输出');
      }
    } catch (e) { addLog('warning', '[jadx] 降级流程异常: ' + e.message); }

    // ── 第三条路（40 题实测「Java逆向解密」补）：裸 .class 常量池摘要 → AI 求解 ──
    // JEB 拉不起、jadx 对单 .class 无输出时，主进程直接解析 .class 二进制
    // （类名/字符串常量/方法签名/字节码 hex），足够 AI 还原简单校验逻辑。
    if (/\.class$/i.test(String(state.currentFile || '')) && window.electronAPI.classFileSummary) {
      try {
        const cr = await window.electronAPI.classFileSummary(state.currentFile);
        if (cr && cr.success && cr.summary) {
          const sum = cr.summary;
          addLog('success', `[.class] 常量池摘要已生成（${sum.constantsParsed} 项常量，${(sum.methods || []).length} 个方法），交 AI 分析`);
          try { await caseAddEvidence('class_summary', '.class 常量池摘要', JSON.stringify(sum, null, 2), 'json'); } catch (e) { }
          const prompt = `以下是 Java .class 文件的常量池摘要（JEB/JADX 均不可用，由工具直接解析字节码格式得到）。\n`
            + `类: ${sum.thisClass || '?'}（继承 ${sum.superClass || '?'}，Java ${sum.version}）\n`
            + `\n## 字符串常量（重点：输入提示/比较目标/变换表线索）\n${(sum.strings || []).map(s => '- ' + s).join('\n').slice(0, 8000)}\n`
            + `\n## 字段\n${(sum.fields || []).map(f => `${f.name} : ${f.desc}`).join('\n').slice(0, 2000)}\n`
            + `\n## 方法（codeHex 为 JVM 字节码，可用 run_python 搭 capstone/手工译码；简单校验也能直接读）\n${(sum.methods || []).map(m => `${m.name}${m.desc}${m.codeHex ? '\n  code: ' + m.codeHex : ''}`).join('\n\n').slice(0, 24000)}\n`
            + `\n请还原 flag 的生成/校验逻辑并求解。\n输出契约：\n1. 得到 flag 单独一行 \`[FLAG]flag内容[/FLAG]\`\n2. 给出 \`${VERIFY_CONTRACT}\`（工具会本地复现）\n3. 做不出来说明卡在哪一步、已排除哪些路。`;
          beginStreamMessage();
          const res = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
          endStreamMessage();
          if (res && res.success && res.text) {
            state.lastAiText = res.text;
            await finalizeSolve(res.text, { source: 'ai-class-summary' });
            const vf = ((state.findings && state.findings.flags) || []).filter(f => f.verified);
            if (vf.length) { addLog('success', `[.class] ✅ 解出已验证 flag: ${vf[0].flag}`); return; }
            addLog('warning', '[.class] 常量池路线未产出已验证 flag');
          }
          return;   // 已尽力（JEB/jadx/常量池三条路都走过），不再弹 GUI
        }
      } catch (e) { addLog('warning', '[.class] 常量池兜底异常: ' + e.message); }
    }

    // 最后兜底：打开 jadx GUI 供人工
    addSystemMessage(`**${label} 分析：JEB/JADX 均不可用**

未能通过 JEB MCP 采集类列表，jadx 命令行反编译也未产出源码。

请检查设置中的 tools.jeb / tools.jadx 路径。`);
    try { await window.electronAPI.launchTool('jadx', state.currentFile); } catch (e) { /* 忽略 */ }
    return;
  }

  // [2/4] 挑选并反编译关键类（应用自身包优先 + 加解密/校验语义加权）
  const pkgGuess = (classes.find(c => /^L(?!java|android|androidx|kotlin|javax)/.test(String(c))) || '').replace(/^L/, '').replace(/;.*$/, '').split('/').slice(0, 2).join('.');
  const keyClasses = selectKeyClasses(classes, pkgGuess, null, 12);
  addLog('info', `挑选 ${keyClasses.length} 个关键类进行反编译: ${keyClasses.map(c => String(c).split('/').pop()).join(', ')}`);
  const codes = [];
  for (const cls of keyClasses) {
    try {
      const clsResult = await window.electronAPI.jebMcpCall('get_class_decompiled_code', [state.currentFile, cls]);
      if (clsResult && clsResult.success && clsResult.result) {
        codes.push({ class: cls, code: clsResult.result });
        mcpCache.otherClasses[cls] = clsResult.result;
        addLog('success', `✅ 已反编译: ${String(cls).split('/').pop()}`);
      }
    } catch (e) { /* 忽略单个类失败 */ }
  }
  if (!codes.length) {
    addLog('warning', '关键类反编译均为空，AI 求解跳过（避免臆测）');
    addSystemMessage(`**${label} 分析**：JEB 返回了 ${classes.length} 个类，但关键类反编译为空。可手动在 JEB 中查看或重试。`);
    return;
  }
  await caseAddEvidence('jeb_classes', '类反编译', codes.map(c => `// ==== ${c.class} ====\n${c.code}`).join('\n\n'), 'java');

  // [3/4] AI 求解（内联题库攻略）
  addLog('info', '[3/4] 调用 AI 分析并求解 flag...');
  const knowledge = await prefetchKnowledge(
    [pkgGuess, ...codes.map(c => c.code)].join('\n'), fileType || 'JAR', [pkgGuess].filter(Boolean));
  const codeText = codes.map(c => `\n### ${c.class}\n${String(c.code).substring(0, 5000)}`).join('\n');
  const prompt = `我在解一道 CTF ${label} 逆向题（Java 字节码）。以下是通过 JEB 反编译得到的关键类代码，请还原算法并求出 flag。

文件：${state.fileInfo ? state.fileInfo.fileName : state.currentFile}
推断包名：${pkgGuess || '未知'}
类总数：${classes.length}，已反编译关键类 ${codes.length} 个。

## 关键类反编译代码
${codeText}
${knowledge}

## 解题要点
- 先找校验/比较点（\`equals\`/\`compareTo\`/\`Arrays.equals\`/自定义 check），反推输入约束。
- 常见：Base64（含自定义字符表）、AES/DES（注意 ECB/CBC 与 IV 编码）、XOR、逐字节变换、哈希比对。
- 密文/密钥多在字符串常量或 byte[] 数组里；自定义字符表要看 \`Base64.decode\` 的替代实现。
- 需要时用 \`run_python\` 实际跑一遍验证（不要只靠脑算）。

**输出契约（务必遵守）：**
1. 得出 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附验证契约：${VERIFY_CONTRACT}
3. 多个候选：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 末尾 \`[EXPERIENCE]每条一行,最多5条[/EXPERIENCE]\`
不要臆造；拿不准就写"待人工验证"。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      buildSystemPrompt()
    );
    endStreamMessage();
    addLog('info', `AI 求解完成，耗时 ${((Date.now() - startTime) / 1000).toFixed(1)} 秒`);

    if (result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(Java)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      // [4/4] 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      addLog('info', '[4/4] 本地复现验证...');
      const { verifiedFlags: vf, flags } = await finalizeSolve(result.text, { source: 'jeb-java' });
      addSystemMessage(`**☕ ${label} 分析结果**

${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`);
      return;
    }
    if (result.aborted || /已取消/.test(result.error || '')) { addLog('info', `${label} AI 求解已停止`); return; }
    addLog('warning', 'AI 求解未返回内容: ' + (result.error || '未知'));
    addSystemMessage(`**${label} 反编译完成**，但 AI 求解未返回内容。类反编译已存入证据目录，可重试。`);
  } catch (err) {
    try { endStreamMessage(); } catch (e) {}
    addLog('error', `${label} AI 求解异常: ` + err.message);
  } finally {
    state.aiBusy = false;
  }
}

async function analyzeDEX() {
  // DEX 单文件：走 JEB 统一求解（不再只启动 jadx）
  await analyzeJavaLike('DEX', 'DEX');
}

// PYC分析（多后端 + AI 求解闭环）
// 背景：CTF 的 .pyc 版本很杂（3.8~3.13），用户配置的单个 pycdc 对高版本常直接报
// "Bad MAGIC!" 失败（实测 Python 3.12）；旧实现只跑 pycdc、失败就打一行 error 就结束，
// 既不回退也不交给 AI —— 等于 PYC 题目完全无解。现改为：
//   1) 主进程多后端回退（pycdc → xdis/pydisasm → 原生 marshal+dis → 纯字节串扫描）
//   2) 把反汇编/常量/字符串**喂给 AI** 做算法还原（对齐 PE/ELF 的求解流程）
//   3) 走验证闭环：AI 给 [VERIFY] 契约 → 本地 Python 复现 → 命中标 ✅已验证
async function analyzePYC() {
  addLog('info', '执行PYC分析流程（多后端反汇编 + AI 求解）...');
  addLog('info', '========================================');

  // 1. 多后端反汇编/常量提取（pycdc 失败自动回退，不再"一次失败就结束"）
  addLog('info', '[1/3] 反汇编与常量提取（pycdc → xdis → marshal → 字节串扫描）...');
  let dec = null;
  try {
    dec = await window.electronAPI.pycDecompile(state.currentFile);
  } catch (e) {
    addLog('warning', 'pyc 反汇编调用异常: ' + e.message);
  }

  if (!dec || !dec.success) {
    addLog('error', 'PYC 反汇编失败: ' + ((dec && dec.error) || '未知原因'));
    addSystemMessage(`**PYC 反汇编失败**\n\n${(dec && dec.error) || '未知原因'}\n\n` +
      `可尝试：在设置中配置 **pycdc** 路径；或确认本机已装 Python（内置助手会回退到 marshal 反汇编/字节串扫描）。`);
    return;
  }

  const backendInfo = (dec.backends || []).join(' | ');
  addLog('success', `PYC 反汇编成功（后端：${backendInfo || '未知'}）`);
  const meta = dec.meta || '';
  const disasm = dec.disasm || '';
  const consts = dec.consts || '';
  const strings = dec.strings || '';
  addLog('info', `反汇编 ${disasm.split('\n').length} 行，常量 ${consts.split('\n').filter(Boolean).length} 条，字符串 ${strings.split('\n').filter(Boolean).length} 条`);

  // 落盘证据（供 WP 引用与复盘）
  await caseAddEvidence('pyc_disasm', 'PYC 反汇编', `# META\n${meta}\n\n# DISASM\n${disasm}`, 'txt');
  if (consts) await caseAddEvidence('pyc_consts', 'PYC 常量', consts, 'txt');
  if (strings) await caseAddEvidence('pyc_strings', 'PYC 字符串', strings, 'txt');

  // 2. 交给 AI 做算法还原（PYC 的关键信息都在反汇编/常量里，不需要外部工具）
  addLog('info', '[2/3] 调用 AI 还原算法并求 flag...');
  const pyVersion = (meta.match(/PYVER\s+(\S+)/) || [])[1] || '未知';
  // 自动预取：从反汇编/常量/字符串里探测特征词（marshal/renpy/pickle/xor…）检索知识库，内联攻略
  const knowledge = await prefetchKnowledge([disasm, consts, strings].join('\n'), 'PYC');

  const prompt = `我在解一道 CTF Python 字节码（.pyc）逆向题。已用反汇编工具提取出**反汇编 + 全部常量 + 字符串**，请据此还原算法并求出 flag。

文件：${state.fileInfo ? state.fileInfo.fileName : state.currentFile}
字节码版本：Python ${pyVersion}

## 反汇编（co_code，含各子函数）
\`\`\`
${disasm.slice(0, 12000)}
\`\`\`
${consts ? `\n## 常量表（co_consts，**密钥/密文/数值常量都在这里，务必逐条检查**）\n\`\`\`\n${consts.slice(0, 4000)}\n\`\`\`` : ''}
${strings ? `\n## 原始字节串扫描（含明文串/base64/hex/大整数）\n\`\`\`\n${strings.slice(0, 3000)}\n\`\`\`` : ''}
${knowledge}

## 解题要点
- Python 字节码常只需**读常量 + 读逻辑**即可还原，不需要动态运行：
  - 常见套路：base64 解密 → 单字节 XOR / RC4 / 自定义查表 / 逐字节变换 → 与目标常量比较。
  - 看 \`decrypt_flag\` 之类子函数的 \`LOAD_CONST\`/\`BINARY_OP\`/\`LOAD_ATTR\`：还原出算法与密钥（如 \`xor_key=199\`、\`base64.b64decode\`）。
  - 密文通常就是常量表里那条长 base64/hex 串。
- 需要时用 \`run_python\` **实际跑一遍**验证（不要只靠脑算）。
- 打印函数名/常量名提示：\`co_names\`、\`co_consts\` 已在上方给出。

**输出契约（务必遵守）：**
1. 得出 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附验证契约：${VERIFY_CONTRACT}
   - 例：{"algo":"xor","key":"199","key_encoding":"ascii","ciphertext":"<base64或hex>","encoding":"base64","expected":"flag"}（若先 base64 再 xor，可用自定义 code 字段）
3. 多个候选：[HYPOTHESES][{...},{...}][/HYPOTHESES]
4. 末尾 [EXPERIENCE]每条一行,最多5条[/EXPERIENCE]
不要臆造；拿不准就写"待人工验证"。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      buildSystemPrompt()
    );
    endStreamMessage();
    addLog('info', `AI 求解完成，耗时 ${((Date.now() - startTime) / 1000).toFixed(1)} 秒`);

    if (result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(PYC)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      // 3. 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      addLog('info', '[3/3] 本地复现验证...');
      const { verifiedFlags: vf, flags } = await finalizeSolve(result.text, { source: 'pyc' });
      addSystemMessage(`**🐍 PYC 分析结果**（后端：${backendInfo || '未知'}）

${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`);
      return;
    }
    if (result.aborted || /已取消/.test(result.error || '')) {
      addLog('info', 'PYC AI 求解已停止');
      return;
    }
    addLog('warning', 'AI 求解未返回内容: ' + (result.error || '未知'));
    addSystemMessage('**PYC 反汇编已完成**，但 AI 求解未返回内容。反汇编/常量已存入证据目录，可手动分析或重试。');
  } catch (err) {
    try { endStreamMessage(); } catch (e) {}
    addLog('error', 'PYC AI 求解异常: ' + err.message);
  } finally {
    state.aiBusy = false;
  }
}

// BIN/固件分析 - 使用Kali（Kali 不可用时回退本地采集）
//
// 实测（firmware 题）：Kali SSH 握手超时 × 4 条命令 → file/binwalk/strings 全部返回 null，
// AI 只收到四个"（无输出）"，213 秒后放弃。但"读字节、找可打印字符串、找高熵块"这些
// 根本不需要 Kali——本地 Node 就能做。这里补一个确定性兜底，保证 AI 至少拿到**真实数据**。
async function localFirmwareProbe(filePath) {
  const r = { bytes: null, magic: '', strings: '', entropy: '', note: '' };
  try {
    // 走现有的 runToolArgs（preload 已暴露），用本机 Python 做字节级采集。
    // 不新增 IPC：这条路径只依赖 python3 标准库（无第三方包），任何装了 Python 的机器都能跑。
    const py = [
      'import sys, math, json',
      'p = sys.argv[1]',
      'raw = open(p, "rb").read()',
      'out = {}',
      'out["bytes"] = len(raw)',
      'out["magic"] = " ".join("%02x" % b for b in raw[:16])',
      '# 可打印字符串（>=6 连续），优先挑像线索的',
      'seen = []',
      'cur = bytearray(); start = 0',
      'for i, c in enumerate(raw):',
      '    if 0x20 <= c <= 0x7e:',
      '        if not cur: start = i',
      '        cur.append(c)',
      '    else:',
      '        if len(cur) >= 6: seen.append((start, bytes(cur).decode("latin-1")))',
      '        cur = bytearray()',
      '    if len(seen) > 4000: break',
      'if len(cur) >= 6: seen.append((start, bytes(cur).decode("latin-1")))',
      'def sc(x):',
      '    s = len(x[1])',
      '    if any(k in x[1].lower() for k in ("flag","ctf","key","pass","secret","cipher","encrypt","decrypt","aes","des","rc4","sm4","rsa")): s += 1000',
      '    return s',
      'seen.sort(key=sc, reverse=True)',
      'out["strings"] = "\\n".join("@0x%x %s" % (o, s[:160]) for o, s in seen[:120])',
      '# 高熵块：256 字节窗口，抽样至多 512 个',
      'blocks = []',
      'W = 256',
      'step = max(W, len(raw)//512)',
      'for off in range(0, max(0, len(raw)-W+1), step):',
      '    seg = raw[off:off+W]',
      '    cnt = [0]*256',
      '    for b in seg: cnt[b] += 1',
      '    H = 0.0',
      '    for c in cnt:',
      '        if c:',
      '            q = c/W; H -= q*math.log2(q)',
      '    if H > 7.2: blocks.append("@0x%x H=%.2f" % (off, H))',
      '    if len(blocks) >= 24: break',
      'out["entropy"] = "\\n".join(blocks) if blocks else "（无高熵块）"',
      // 用固定标记包裹：strings 里可能含换行/任意字符，直接 print(json) 会被
      // 上游的缓冲/编码截断（实测会只剩 "SIZE 4063744"）。标记 + JSON 便于稳定解析。
      'print("__FWPROBE__" + json.dumps(out) + "__ENDFW__")',
    ].join('\n');
    const tmp = `${state.appPaths.userData || '.'}/fwprobe_${Date.now().toString(36)}.py`;
    await window.electronAPI.writeFile(tmp, py);
    const rr = await window.electronAPI.runToolArgs(['python', tmp, filePath]);
    const txt = String((rr && rr.stdout) || '');
    const mm = txt.match(/__FWPROBE__([\s\S]*?)__ENDFW__/);
    if (!mm) { r.note = 'Python 输出中未找到采集结果标记'; return r; }
    const j = JSON.parse(mm[1]);
    r.bytes = j.bytes;
    r.magic = j.magic || '';
    r.strings = j.strings || '';
    r.entropy = j.entropy || '';
    if (!r.bytes) r.note = 'Python 未返回字节数';
  } catch (e) {
    r.note = '本地采集异常: ' + e.message;
  }
  return r;
}

// PCAP 分析：纯二进制流量走本地解析（不启动 Burp）；含 HTTP 时才走 Burp 历史。
// 为什么分开：样本（plutochat）是 31337 端口上的二进制协议、http=0，
// 强行拉 Burp 只会白等 150s 且拿不到任何有用数据。
async function analyzePcapFile(filePath, opts) {
  const o = opts || {};
  addLog('info', `[流量] 解析 pcap：${filePath}`);
  let r = null;
  try {
    r = await window.electronAPI.trafficExtract({ path: filePath, protocol: 'auto', max_flows: 20 });
  } catch (e) {
    addLog('warning', '[流量] 解析失败: ' + e.message);
  }
  if (!r || !r.success) {
    addLog('error', '[流量] 无法解析: ' + ((r && r.error) || '未知错误'));
    addSystemMessage(`**❌ 流量解析失败**\n\n${(r && r.error) || '未知错误'}`);
    return;
  }
  addLog('success', `✅ pcap 解析完成：packets=${r.packets} flows=${r.flows} http=${r.http}${r.outPath ? `（完整结果: ${r.outPath}）` : ''}`);
  await caseAddEvidence('pcap_flows', 'pcap 流量解析', String(r.result || ''), 'txt')
    .catch(() => null);

  if (!o.useBurp) {
    addSystemMessage(`**📦 流量已解析（二进制协议）**\n\n共 ${r.packets} 包 / ${r.flows} 条流，HTTP 流 ${r.http} 条。\n已交给 AI 分析。`);
  } else {
    addSystemMessage(`**🌐 流量含 HTTP**\n\n共 ${r.packets} 包 / ${r.flows} 条流。尝试读取 Burp 历史补充上下文...`);
  }

  const prompt = `我在解一道 CTF 流量分析题，已用工具解析抓包。

文件路径：${filePath}
${o.useBurp ? '（该抓包含 HTTP 流量；如需代理侧上下文可用 burp_get_history 查询）' : '（该抓包是二进制协议，没有 HTTP；不要当 Web 题处理）'}

## 解析结果
${String(r.result || '').slice(0, 12000)}

## 你的任务
1. 从每条流的 hex 预览里识别协议结构（长度前缀/魔数/字段边界）；
2. 写 run_python 脚本解析载荷、还原被传输的数据；
3. 明确说明每一步的证据（偏移/字节），不要凭猜；
4. 输出契约：flag 单独一行 \`[FLAG]flag内容[/FLAG]\`，并附 \`${VERIFY_CONTRACT}\`。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const result = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
    endStreamMessage();
    if (result && result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(流量)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 3000));
      await finalizeSolve(result.text, { source: 'pcap' });
      addSystemMessage(`**🎯 流量分析结果**\n\n${result.text.slice(0, 4000)}`);
    } else {
      addLog('warning', '[流量] AI 未返回内容: ' + ((result && result.error) || '未知'));
    }
  } catch (e) {
    try { endStreamMessage(); } catch (e2) { }
    addLog('error', '[流量] AI 分析异常: ' + e.message);
  } finally {
    state.aiBusy = false;
  }
}

// 容器/文件系统（squashfs/cramfs/ubifs/jffs2/ext…）：本地优先。
// 本机 binwalk 损坏、Kali 常不可达，所以这里只做纯本地的 magic/strings/熵采集，
// 并把"本地兜底不能解包"的能力边界写进 AI 上下文，而不是先去打 3 条 SSH 超时。
async function analyzeBinContainer(filePath) {
  addLog('info', `[容器] 本地分析文件系统镜像：${filePath}`);
  const probe = await localFirmwareProbe(filePath);
  if (!probe || probe.bytes == null) {
    addLog('error', '[容器] 本地采集失败: ' + ((probe && probe.note) || '未知'));
    addSystemMessage(`**❌ 容器分析失败**\n\n${(probe && probe.note) || '本地采集不可用'}`);
    return;
  }
  addLog('success', `[容器] 本地采集完成：${probe.bytes} 字节，magic=${probe.magic}`);
  await caseAddEvidence('firmware_probe', '容器本地采集（magic/strings/熵）',
    `magic: ${probe.magic}\n\nstrings:\n${probe.strings || '（无）'}\n\nentropy:\n${probe.entropy || '（无）'}`, 'txt')
    .catch(() => null);

  const prompt = `我在解一道 CTF 固件/文件系统镜像题，工具已在本地完成字节级采集。

文件路径：${filePath}
大小：${probe.bytes} 字节
头部 16 字节：${probe.magic}

## 本地采集（magic / strings / 高熵块）
### strings
${String(probe.strings || '（未找到 ≥6 字节的可打印字符串）').slice(0, 6000)}

### 高熵块（>7.2/8，通常是压缩/加密/内嵌文件）
${String(probe.entropy || '（无）').slice(0, 3000)}

## 能力边界（必须如实说明）
本地兜底**只能给 magic/strings/熵，不能解包**（本机 binwalk 不可用、Kali 未连接时不要假装解包成功）。
若需要解包：优先写 \`run_python\` 按已知文件系统格式解析，或用远程 \`remote_exec({host:"kali", command:"binwalk -e ..."})\`（失败会返回 REMOTE_* 前缀）。

## 你的任务
1. 按 magic 判定文件系统/容器类型；
2. 从 strings 里找 flag/密钥/提示；
3. 需要结构解析时写 run_python（先小范围验证，再全量）；
4. 输出契约：flag 单独一行 \`[FLAG]flag内容[/FLAG]\`，并附 \`${VERIFY_CONTRACT}\`。`;

  state.aiBusy = true;
  beginStreamMessage();
  try {
    const result = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
    endStreamMessage();
    if (result && result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(容器)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 3000));
      await finalizeSolve(result.text, { source: 'container' });
      addSystemMessage(`**🎯 容器分析结果**\n\n${result.text.slice(0, 4000)}`);
    } else {
      addLog('warning', '[容器] AI 未返回内容: ' + ((result && result.error) || '未知'));
    }
  } catch (e) {
    try { endStreamMessage(); } catch (e2) { }
    addLog('error', '[容器] AI 分析异常: ' + e.message);
  } finally {
    state.aiBusy = false;
  }
}

async function analyzeBIN() {
  addLog('info', '执行固件分析流程（Kali 预检 → 可达才远程，否则本地兜底）...');

  // 第0步：远程预检（必须在发任何远程命令之前）。
  // 实测 Kali 不可达时，file/binwalk/strings 各 60s → 白等 3 分钟。
  // 探活结果缓存 120s（同一轮内不重复探）；探活走 checkPort，可按端口探测注入。
  const pre = await kaliPreflight();
  addLog(pre.action === 'remote' ? 'info' : 'warning', pre.log);

  let fileInfo = null, binwalkInfo = null, stringsInfo = null;
  if (pre.action === 'remote') {
    // 第2步：使用file命令检查文件类型
    addLog('info', '[2/4] 检查文件类型...');
    fileInfo = await execKaliCommand(`file ${shq(state.currentFile)}`);
    if (fileInfo) {
      addLog('info', '文件类型: ' + fileInfo.trim());
    }

    // 第3步：使用binwalk分析
    addLog('info', '[3/4] 使用binwalk分析固件...');
    binwalkInfo = await execKaliCommand(`binwalk ${shq(state.currentFile)}`);
    if (binwalkInfo) {
      addLog('info', 'binwalk分析结果:\n' + binwalkInfo);
    }

    // 第4步：提取字符串
    addLog('info', '[4/4] 提取字符串...');
    stringsInfo = await execKaliCommand(`strings ${shq(state.currentFile)} | head -50`);
    if (stringsInfo) {
      addLog('info', '提取的字符串:\n' + stringsInfo);
    }
  }

  // ===== Kali 跳过/全空 → 本地兜底采集（不能把"四个空结果"丢给 AI）=====
  let localProbe = null;
  if (!fileInfo && !binwalkInfo && !stringsInfo) {
    addLog('warning', '[固件] Kali 不可用，改用本地字节级采集（magic/strings/熵块）...');
    localProbe = await localFirmwareProbe(state.currentFile);
    if (localProbe.bytes != null) {
      addLog('success', `[固件] 本地采集完成：${localProbe.bytes} 字节，magic=${localProbe.magic}`);
      fileInfo = `本地读取 ${localProbe.bytes} 字节；头部 16 字节: ${localProbe.magic}`;
      stringsInfo = localProbe.strings || '（未找到 ≥6 字节的可打印字符串）';
      binwalkInfo = `binwalk 不可用。本地高熵块（>7.2/8，通常是压缩/加密/内嵌文件）：\n${localProbe.entropy}`;
    } else {
      addLog('error', '[固件] 本地采集也失败: ' + localProbe.note);
    }
  }
  // 预检 skip 时把能力边界写进上下文（本地兜底不能解包）
  const kaliLocalNote = pre.action === 'skip'
    ? `\n## Kali 不可达（已跳过远程命令）\n${pre.plan ? pre.plan.note : '本地兜底只能给 magic/strings/熵，不能解包。'}\n`
      + `需要解包时：写 run_python 按格式自行解析，或调用 remote_exec({host:"kali", command:"..."})（会明确返回 REMOTE_* 错误）。\n`
    : '';

  addSystemMessage(`**固件分析流程已启动（Kali模式）**

**第1步：文件类型检查**
${fileInfo ? '```\n' + fileInfo.trim() + '\n```' : '等待执行...'}

**第2步：binwalk分析**
${binwalkInfo ? '```\n' + binwalkInfo + '\n```' : '等待执行...'}

**第3步：字符串提取**
${stringsInfo ? '```\n' + stringsInfo.substring(0, 500) + '...\n```' : '等待执行...'}`);

  // ===== 第5步：把 Kali 采集结果交给 AI 求解（v1.7.4 补齐）=====
  // ⚠️ 旧实现到上面就结束了，只留一段"后续步骤"提示给用户——实测 5 道固件/.bin 题
  // 全部停在"只跑了 Kali 静态命令"，AI 从没参与。这与"AI 是解题主体"的定位直接冲突。
  const kailiCtx = [
    `## 文件信息`, fileInfo ? fileInfo.trim() : '（file 命令无输出）',
    ``, `## binwalk 分析`, binwalkInfo ? binwalkInfo.slice(0, 8000) : '（无输出）',
    ``, `## strings（前 50 行）`, stringsInfo ? stringsInfo.slice(0, 8000) : '（无输出）',
    kaliLocalNote,
  ].join('\n');

  addLog('info', '[5/5] 把 Kali 采集结果交给 AI 求解...');
  const sideFiles = (Array.isArray(state._platformFiles) ? state._platformFiles : [])
    .filter(p => String(p) !== String(state.currentFile));
  const prompt = `我正在解一道 CTF 逆向题，载体是固件/未知二进制（不是标准 PE/ELF）。

文件路径：${state.currentFile}
文件名：${(state.fileInfo && state.fileInfo.fileName) || '未知'}
大小：${(state.fileInfo && state.fileInfo.sizeFormatted) || '?'}

${kailiCtx}
${sideFiles.length ? `\n## 同包伴生文件（用 read_file 读取）\n${sideFiles.map(p => '- ' + p).join('\n')}\n` : ''}

## 你的任务
1. 从上面的信息判断这是什么（固件镜像/压缩包/编码数据/文件系统/裸二进制）；
2. 用 **bash 工具**在本地执行进一步操作（binwalk -e 解包、7z/unsquashfs 提取、` + '`python3`' + ` 解码、
   直接读偏移 hexdump 等）——你**可以直接跑命令**，不要只给"建议"；
3. 若提取出新的文件（ELF/PE/脚本/文件系统），调用 \`switch_to_next_stage\` 切换到它继续分析；
4. 若字符串/常量里已有 flag 线索，直接提取并验证；
5. 找不到就写清：已排除哪些路径、下一步需要什么工具/文件。

**输出契约：**
1. 得到 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附 \`${VERIFY_CONTRACT}\`（工具会本地复现）
3. 末尾 \`[EXPERIENCE]...[/EXPERIENCE]\``;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
    endStreamMessage();
    addLog('info', `固件 AI 求解完成，耗时 ${((Date.now() - startTime) / 1000).toFixed(1)} 秒`);
    if (result && result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(固件)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 3000));
      if (result.stageSwitch && result.stageSwitch.path) {
        const hr = await runStageHandoff(result.stageSwitch, result.text);
        if (hr.ok) return;
      }
      await finalizeSolve(result.text, { source: 'ai-firmware' });
      const vf = (state.findings ? state.findings.flags : []).filter(f => f.verified);
      addSystemMessage(`**固件分析结果**\n\n${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`` : ''}\n\n${result.text}`);
      return vf.length > 0;
    }
    addLog('warning', '固件 AI 求解未返回内容: ' + ((result && result.error) || '未知'));
    return false;
  } catch (e) {
    try { endStreamMessage(); } catch (e2) { }
    addLog('warning', '固件 AI 求解异常: ' + e.message);
    return false;
  } finally {
    state.aiBusy = false;
  }
}

// ========== Web/JS 逆向自动化（像 IDA/JEB：自动拉起 Burp/浏览器 → 连 MCP → AI 分析） ==========

// 代理历史空判断：兼容 JSON 数组/对象包装/常见空标记（供 analyzeWebJS 轮询复用）
// ⚠️ 必须把**工具错误串**也判成"空"：Burp MCP 的失败走 result.isError + content[].text，
// 主进程抛错后这条文本会以字符串形式回来；旧实现只认 "无/null/empty" 开头，
// 于是 "Field 'offset' is required ..." 被判为非空 → 流程误以为已有流量、
// 跳过拉起代理浏览器，并把报错当代理历史喂给 AI（实测 2026-10-20）。
const BURP_ERROR_RE = /^(Error:|MCP_|BURP_DOWN|Burp MCP调用失败|Tool '.*' requires extension|Field '.*' is required|Failed to |Invalid |Unknown tool)/i;
function burpHistoryLooksEmpty(t) {
  if (!t) return true;
  const s = String(t).trim();
  if (s.length < 8) return true;
  if (/^(无|null|empty|not found|没有)/i.test(s)) return true;
  if (BURP_ERROR_RE.test(s)) return true;
  try {
    const j = JSON.parse(s);
    if (Array.isArray(j)) return j.length === 0;
    if (j && typeof j === 'object') {
      // 结构化错误（{error:...} / {isError:true}）不是历史
      if (j.isError === true || (j.error != null && j.error !== false && j.error !== 0)) return true;
      for (const key of ['entries', 'history', 'data', 'messages', 'results']) {
        if (Array.isArray(j[key])) return j[key].length === 0;
      }
      return Object.keys(j).length === 0;
    }
  } catch (e) { /* 非JSON，按非空处理 */ }
  return false;
}

// 判断一条 Burp 返回是否为错误文本（供 analyzeWebJSCore 在"连接成功"判定处使用）
function burpResultIsError(t) {
  const s = String(t || '').trim();
  return BURP_ERROR_RE.test(s);
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

// 本地 HTML/JS 文件级逆向（Burp 不可用时的回退路径）。
// 与网络抓包无关：直接读文件 → 抽取内嵌 <script> → 连同原文一起交给 AI → 走 finalizeSolve。
async function analyzeLocalWebFile() {
  const file = state.currentFile;
  try {
    const rf = await window.electronAPI.readFile(file);
    if (!rf || !rf.success) {
      addLog('error', '[本地JS] 读取失败: ' + ((rf && rf.error) || '未知'));
      return false;
    }
    const raw = String(rf.content || '');
    addLog('info', `[本地JS] 已读入 ${raw.length} 字符`);

    // 提取内嵌脚本：HTML 里的 <script>...</script>，以及 .js 文件本身
    let scripts = [];
    if (/\.(js|mjs)$/i.test(file)) {
      scripts = [raw];
    } else {
      const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
      let m;
      while ((m = re.exec(raw)) !== null) {
        const body = m[1];
        if (body && body.trim().length > 40) scripts.push(body);
      }
      // 内联 script 为空时（纯外链），把整页当文本（可能内嵌在 data-* / 注释里）
      if (!scripts.length) scripts = [raw];
    }
    // 只保留最长的几段（算法通常在最大的脚本里），避免提示词爆炸
    scripts.sort((a, b) => b.length - a.length);
    const picked = scripts.slice(0, 4);
    const inline = picked.map((s, i) => `\n### 脚本 #${i + 1}（${s.length} 字符）\n\`\`\`javascript\n${s.slice(0, 30000)}\n\`\`\``).join('\n');
    addLog('info', `[本地JS] 提取 ${picked.length} 段脚本（最长 ${picked[0].length} 字符）`);

    // 明显的算法/编码线索，帮助 AI 先定位
    const clues = [];
    const clueRes = [
      [/CryptoJS|JSEncrypt|sm2|sm3|sm4|crypto\.subtle/gi, '密码库'],
      [/atob\(|btoa\(|base64/gi, 'Base64'],
      [/fromCharCode|charCodeAt|String\.fromCharCode/gi, '字符码变换'],
      [/\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*[,{]/, '常量数组'],
      [/\^=|<<|>>>/g, '位运算'],
      [/eval\(|Function\(/g, '动态执行（可能混淆）'],
    ];
    for (const [re, name] of clueRes) {
      const n = (raw.match(re) || []).length;
      if (n) clues.push(`- ${name}: ${n} 处`);
    }

    const prompt = `我在解一道 CTF JS/Web 逆向题，附件是本地文件（不需要抓包）。

文件路径：${file}
文件名：${(state.fileInfo && state.fileInfo.fileName) || ''}
大小：${(state.fileInfo && state.fileInfo.sizeFormatted) || raw.length + ' 字符'}

## 静态线索
${clues.length ? clues.join('\n') : '（无明显特征词）'}

## 文件内容（已抽取主要脚本）
${inline}

${raw.length > 120000 ? `\n⚠️ 原文共 ${raw.length} 字符，以上仅展示主要脚本。完整文件可用 read_file 读取：${file}\n` : ''}

## 你的任务
1. 定位校验逻辑（输入比较、flag 生成、按钮点击后的校验函数）；
2. 还原算法（常见：XOR/加减变换、Base64 变表、AES/DES、字符码运算、无关数学公式干扰）；
3. **必须用 run_python 实际跑一遍验证**，不要只做脑算；
4. 若逻辑被混淆（eval/Function/数组字符串化），先做常量提取与还原；
5. 拿不准就写明卡在哪、还缺什么。

**输出契约：**
1. flag 单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附验证契约：${VERIFY_CONTRACT}
3. 多个候选：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 末尾 \`[EXPERIENCE]每条一行,最多5条[/EXPERIENCE]\``;

    state.aiBusy = true;
    beginStreamMessage();
    const t0 = Date.now();
    const result = await window.electronAPI.claudeChat([{ role: 'user', content: prompt }], buildSystemPrompt());
    endStreamMessage();
    addLog('info', `[本地JS] AI 求解完成，耗时 ${((Date.now() - t0) / 1000).toFixed(1)} 秒`);

    if (result && result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(本地JS)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 3000));
      const { verifiedFlags: vf } = await finalizeSolve(result.text, { source: 'ai-local-js' });
      addSystemMessage(`**🎯 本地 JS 逆向结果**\n\n${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`\n\n` : ''}${result.text}`);
      return vf.length > 0;
    }
    addLog('warning', '[本地JS] AI 未返回内容: ' + ((result && result.error) || '未知'));
    return false;
  } catch (e) {
    try { endStreamMessage(); } catch (e2) { }
    addLog('error', '[本地JS] 异常: ' + e.message);
    return false;
  } finally {
    state.aiBusy = false;
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
    // ── 回退：本地 JS/HTML 文件不需要 Burp ──
    // 实测（equation 题）：附件就是一个 57KB 的 equation.html，算法全在内嵌 JS 里，
    // 完全可以静态解出；但旧逻辑因为 Burp 没起来就整题结束（150 秒白等）。
    // Burp 只对"需要抓包看网络请求"的题是必需的；对"文件已在本地"的题是可选的。
    const localWeb = state.currentFile && /\.(html?|js|mjs)$/i.test(state.currentFile);
    if (localWeb) {
      addLog('warning', '[Web/JS] Burp 不可用，但目标是本地文件 → 跳过抓包，直接做文件级 JS 逆向');
      addLog('warning', 'Burp 未就绪，已回退本地文件分析');
      addSystemMessage('**ℹ️ Burp 未就绪**\n\n目标是本地 HTML/JS 文件，不需要抓包——已自动切换为**文件级静态分析**。');
      return await analyzeLocalWebFile();
    }
    addLog('error', 'Burp 未就绪，Web 流量无法读取');
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
  // 自动预取：从代理历史里探测特征词（sign/token/JSEncrypt/CryptoJS/瑞数…）检索知识库，内联攻略
  const knowledge = await prefetchKnowledge(String(historyText || ''), state.fileType || 'JS');
  const prompt = `Web/JS 逆向任务。${targetUrl ? '目标: ' + targetUrl + '。' : ''}${jsFileHint}
当前 Burp 代理历史（实时数据）：
${String(historyText).substring(0, 5000)}
${knowledge}

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
      // 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags: vf } = await finalizeSolve(result.text, { source: 'ai' });
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
        // 降噪：只保留"可能是校验"的比较。实测噪音：'Cipher'=='Cipher'、'AES/CBC/...'==同串
        // （算法名自比较）、'com.nctf.hookmysecret'==''（包名，日志里几十条）、'include'=='ViewStub'
        // /'pathInterpolator'=='linearInterpolator'（框架/资源串）、'/data/user/0/...'=='/'（路径）。
        // ⚠️ 判定顺序（关键）：
        //   ① 高熵串（flag 形态/长hex/base64）→ **先**返回 true —— 这是最可能的 key/密文/flag，
        //      且"flag==flag"这种自比较正是最终校验，**不能**被 a===b 规则误杀。
        //   ② 双方都是"噪音形态"（包名/资源路径/绝对路径/算法名/框架词/含空格）→ 排除。
        //   ③ 语义词（flag/ctf/key/secret…）命中且**非噪音形态** → 打印。
        //   ④ 兜底：较长且长度相近的可打印串。
        // 教训：曾用"标识符形态"当噪音判据 → hex 串与小写词也像标识符，把真实 key 比较误杀。
        var NOISE_ALGO = /^(Cipher|AES|DES|RSA|MD5|SHA[\\-0-9]*|Hmac[A-Za-z0-9]*)$/i;
        var NOISE_WORD = /^(include|fragment|window|search|autofill|tag|merge|view|blink|display|accessibility|layout_inflater|requestFocus|ViewStub|FrameLayout|LinearLayout|ScrollView|TextView|ContentFrameLayout|changeBounds|changeTransform|changeScroll|autoTransition|fade)$/i;
        function isNoiseStr(s) {
            if (!s) return true;
            if (/\\s/.test(s)) return true;                                   // UI 文本/多行文本
            if (/^[a-z0-9_]+(\\.[a-z0-9_]+){2,}/i.test(s)) return true;       // 包名 com.a.b
            if (/^(res|assets|lib|META-INF|data|system|proc)[\\/]/i.test(s)) return true;
            if (/^\\//.test(s)) return true;                                   // 绝对路径
            if (/^android[.:]/i.test(s)) return true;
            if (NOISE_ALGO.test(s) || NOISE_WORD.test(s)) return true;
            if (/(interpolator|transition|viewstub|inflater|animator)/i.test(s)) return true;
            if (/^(change|auto)[A-Z]/.test(s)) return true;                    // Transition 属性名 changeBounds/changeClipBounds/autoTransition…
            if (/^[A-Za-z0-9]+\\/[A-Za-z0-9\\/]+$/.test(s)) return true;       // AES/CBC/...
            return false;
        }
        function isHighEntropy(s) {
            if (!s || s.length < 8) return false;
            if (/\\{/.test(s)) return true;                                    // xxx{...}
            if (/^[0-9a-fA-F]{16,}$/.test(s)) return true;                     // 长 hex
            if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s)) return true; // base64
            return false;
        }
        var SEM = /flag|ctf|key|secret|token|pass|stage/i;
        function interesting(a, b) {
            a = a || ''; b = b || '';
            if (isHighEntropy(a) || isHighEntropy(b)) return true;             // ① flag/hex/base64 → 一定打印
            if (isNoiseStr(a) && isNoiseStr(b)) return false;                  // ② 双方都是噪音形态
            if ((SEM.test(a) && !isNoiseStr(a)) || (SEM.test(b) && !isNoiseStr(b))) return true; // ③
            if (a === b) return false;                                         // 无语义常量自比较
            if (a.length >= 12 && b.length >= 12 && Math.abs(a.length - b.length) <= 2) return true; // ④
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





// 部署Frida（手动按钮）——复用自动版 startFridaServer()，
// 以获得设备就绪判定、进程复用/重启、端口转发重建、TCP 可达性验证等能力。
async function deployFrida() {
  addLog('info', '=== 部署Frida到模拟器 ===');

  try {
    // 先确认设备真正就绪（匹配 "device" 状态，避免 offline 误判）
    const port = (state.config.emulator && state.config.emulator.adb_port) || 62025;
    const device = `127.0.0.1:${port}`;
    await window.electronAPI.adbCommand(`connect ${device}`);
    const deviceCheck = await window.electronAPI.adbCommand('devices');
    const out = (deviceCheck && deviceCheck.stdout) || '';
    const readyRe = new RegExp(device.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+device\\b');
    if (!deviceCheck.success || !readyRe.test(out)) {
      addLog('error', '模拟器未就绪，请先启动安卓9模拟器');
      return;
    }

    const ok = await startFridaServer();
    if (ok) {
      const fridaPort = (state.config.emulator && state.config.emulator.frida_port) || 27042;
      addLog('success', `Frida-server 已就绪（端口: ${fridaPort}）`);
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
    // 措辞如实：这些 key/iv/密文来自 AI 给出的 [VERIFY]/[HYPOTHESES] 契约，**未必已本地验证通过**
    // （验证失败时也会注入，靠进程内多候选枚举碰运气）。不要谎称"已验证"。
    addLog('info', '已向 Hook 注入进程内解密段（key/iv/密文来自 AI 契约，Hook 内会多候选尝试直接解出 flag）');
  }

  // 目标进程名解析：frida -n 匹配的是"进程名"（如 Hook My Secret），不是包名（com.x.y）。
  // Android 进程名常等于 App 名而非包名，直接用包名会 Failed to spawn。
  // 策略：拿 frida-ps 列表，按"包名精确/包含/末段关键词"匹配出真实进程名；
  // 匹配不到再退回前台应用(-F 由主进程处理)或人工输入。
  let target = null;
  const pkg = state.fileType === 'APK' ? await getPackageNameFromAPK() : null;
  try {
    // 同时取"应用列表(-a：含 Identifier 包名列)"与"进程列表"，两者都要比对：
    // Android 进程名常是 App 显示名（"My Application"），只有 -a 的 Identifier 才是包名。
    const psApp = await window.electronAPI.fridaPs({ apps: true });
    const psProc = await window.electronAPI.fridaPs();
    const norm = (s) => String(s || '').toLowerCase().replace(/\s+/g, '');
    const q = norm(pkg || '');
    const seg = q.split('.').pop();
    // -a 三列：PID  Name  Identifier
    const appRows = (psApp && psApp.success ? String(psApp.stdout) : '').split(/\r?\n/)
      .map(l => l.match(/^\s*(\d+)\s+(.+?)\s{2,}(\S+)\s*$/))
      .filter(Boolean)
      .map(m => ({ pid: Number(m[1]), name: m[2].trim(), identifier: m[3].trim() }));
    const procRows = (psProc && psProc.success ? String(psProc.stdout) : '').split(/\r?\n/)
      .map(l => { const m = l.match(/^\s*(\d+)\s+(.+?)\s*$/); return m ? { pid: Number(m[1]), name: m[2] } : null; })
      .filter(Boolean);
    let hit = null;
    if (q) {
      // 1) 优先用 -a 的 Identifier（包名）精确/包含匹配 → 取 App 的进程名
      hit = appRows.find(r => norm(r.identifier) === q)
        || appRows.find(r => norm(r.identifier).includes(q) || q.includes(norm(r.identifier)));
      // 2) 退回进程名匹配（含末段关键词）
      if (!hit) {
        const all = procRows.concat(appRows.map(r => ({ pid: r.pid, name: r.name })));
        const ns = norm(seg);
        hit = all.find(r => norm(r.name) === q)
          || all.find(r => norm(r.name).includes(q) || q.includes(norm(r.name)))
          || (ns.length >= 4 ? all.find(r => norm(r.name).includes(ns) || ns.includes(norm(r.name))) : null);
      }
    }
    if (hit) {
      target = hit.name;
      addLog('info', `已解析目标：包名 ${pkg || '(无)'} → 进程名 "${hit.name}" (pid ${hit.pid})`);
    } else if (pkg && appRows.length) {
      // App 未运行：交给主进程自动拉起后再 attach（见 execFridaHook 的自动拉起逻辑）
      addLog('info', `App 未在运行（包名 ${pkg}），将尝试自动启动后再附加`);
      target = pkg;
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
  // 【关键】同时自动驱动界面：否则 App 停在首页，手势/输入触发的校验代码永不执行，
  // 只能抓到启动噪音（本次实战教训：手动 Hook 只抓到 String.equals 噪音、0 条关键数据）。
  const hookPkg = (state.fileType === 'APK') ? pkg : null;
  const drivePromise = hookPkg ? (async () => {
    try {
      await sleepMs(5000);
      addLog('info', '开始自动驱动界面（与 Hook 并行，触发真实校验路径）...');
      const log = await driveAppIteratively(hookPkg, 45000);
      addLog('success', `界面驱动完成：${log.length} 个动作 → ${log.join(' | ')}`);
    } catch (e) { addLog('warning', '界面驱动失败（不影响 Hook 抓取）: ' + e.message); }
  })() : Promise.resolve();
  const hookPromise = window.electronAPI.runFridaHook(scriptToRun, target, { windowMs: 60000, hardCapMs: 600000 });
  const [result] = await Promise.all([hookPromise, drivePromise]);
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
// 日志面板 DOM 上限：批量模式一轮可产生数千行，节点无上限增长会让每次 append 的
// 重排成本线性上升（实测长会话后渲染层显著变卡）。timeline.jsonl 仍是全量记录，
// 这里只裁 DOM——超出上限时批量移除最旧的 300 行（摊销成本，不逐条删）。
const LOG_DOM_LIMIT = 1500;
const LOG_DOM_TRIM_BATCH = 300;

function addLog(type, message) {
  const logOutput = document.getElementById('category-log');
  if (!logOutput) return;

  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });

  const logLine = document.createElement('div');
  logLine.className = `log-line log-${type}`;
  logLine.innerHTML = `<span class="log-time">[${time}]</span><span class="log-text"></span>`;
  logLine.querySelector('.log-text').textContent = String(message);

  logOutput.appendChild(logLine);
  if (logOutput.children.length > LOG_DOM_LIMIT) {
    for (let i = 0; i < LOG_DOM_TRIM_BATCH && logOutput.children.length > LOG_DOM_LIMIT - LOG_DOM_TRIM_BATCH; i++) {
      logOutput.removeChild(logOutput.firstChild);
    }
  }
  followScroll(logOutput);

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
  // 用户自己发消息 → 强制回到底部（这是唯一应该强制跟随时机）
  scrollToBottomEl(chatMessages);
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
  // 系统消息（阶段汇报/工具结果）不抢滚动：用户若在翻历史就停在原处
  followScroll(chatMessages);
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

    // CTF² 平台
    set('setting-ctf2-url', mcp.ctf2);
    set('setting-ctf2-token', mcp.ctf2Token);
    set('setting-ctf2-dir', (state.config.platform && state.config.platform.downloadDir) || '');

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

// 迭代式驱动界面（通解）：每轮 dump → 界面压缩摘要 → AI 决策下一步（fast 模型，JSON）
// → 执行 → 再 dump。决策完全基于当前界面的实时数据，随题目变化，不含任何特定题目的
// 操作序列；AI 不可用或解析失败时回退到通用启发式（多语言流程词 + 占位输入）。
// 与 Hook 并行运行，让界面触发的校验代码真正执行。
async function driveAppIteratively(packageName, totalMs = 30000) {
  const deadline = Date.now() + totalMs;
  const seen = new Set();
  const log = [];
  const keyOf = (n) => `${n.cls}|${n.rid}|${n.text}|${n.cx},${n.cy}`;

  // 界面摘要：交互控件清单（序号供 AI 引用）+ 少量可见文本提供上下文
  const summarize = (nodes) => {
    const inter = nodes.filter(n => n.clickable || /EditText/i.test(n.cls)).slice(0, 14);
    const texts = nodes.filter(n => !n.clickable && n.text && n.text.length <= 30).slice(0, 6);
    const short = (s) => String(s || '').split('/').pop().slice(0, 22);
    // 自绘大容器候选（图案锁/画布等）：通常不可点、不在交互清单里，单独列出，
    // 否则九宫格图案锁对 AI 完全不可见，无法给出 pattern 几何参数。
    const big = nodes
      .filter(n => (n.x2 - n.x1) > 400 && (n.y2 - n.y1) > 400 && /View/i.test(n.cls)
        && !/android\.widget\.(Button|TextView|EditText|ImageView)/i.test(n.cls))
      .sort((a, b) => (b.x2 - b.x1) * (b.y2 - b.y1) - (a.x2 - a.x1) * (a.y2 - a.y1))[0];
    const list = inter.map((n, i) =>
      `${i}. ${n.cls.split('.').pop()} text="${(n.text || '').slice(0, 24)}" rid="${short(n.rid)}" @(${n.cx},${n.cy})`
    ).join('\n')
      + (big ? `\nB. 自绘大容器 bounds=(${big.x1},${big.y1})-(${big.x2},${big.y2}) center=(${big.cx},${big.cy}) 边长${big.x2 - big.x1}x${big.y2 - big.y1}（若界面是九宫格图案锁：pattern 的 center 用容器中心、step=短边/4）` : '');
    return { inter, big, list, texts: texts.map(n => `"${(n.text || '').slice(0, 24)}"`).join(' | ') };
  };

  // 执行 AI 给出的单步操作（node 查找必须用摘要清单 s.inter，序号才与提示词一致）
  async function execStep(step, inter) {
    const i = Number(step && step.i);
    const node = inter[i];
    // tap/input 必须有目标控件；pattern/swipe/back 不依赖 i
    if ((step.action === 'tap' || step.action === 'input') && !node) return false;
    if (step.action === 'tap' && node) {
      const r = await window.electronAPI.driveAppUi([{ type: 'tap', x: node.cx, y: node.cy }, { type: 'sleep', ms: 700 }]);
      log.push(`tap#${i}(${String(node.text || node.rid || 'node').slice(0, 14)})` + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    if (step.action === 'input' && node) {
      const txt = String(step.text || 'A').slice(0, 32);
      const r = await window.electronAPI.driveAppUi([
        { type: 'tap', x: node.cx, y: node.cy }, { type: 'sleep', ms: 300 },
        { type: 'text', value: txt }, { type: 'sleep', ms: 300 }]);
      log.push(`input#${i}="${txt}"` + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    if (step.action === 'pattern' && Array.isArray(step.points) && Array.isArray(step.center) && step.step) {
      const pt = (k) => [Math.round(step.center[0] + (k % 3) * step.step), Math.round(step.center[1] + Math.floor(k / 3) * step.step)];
      const r = await window.electronAPI.driveAppUi([{ type: 'swipe', points: step.points.map(pt), duration: 130 }]);
      log.push('pattern[' + step.points.join(',') + ']' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    if (step.action === 'swipe' && Array.isArray(step.from) && Array.isArray(step.to)) {
      const r = await window.electronAPI.driveAppUi([{ type: 'swipe', points: [step.from, step.to], duration: 200 }]);
      log.push('swipe' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    if (step.action === 'back') {
      const r = await window.electronAPI.adbCommand('shell input keyevent 4');
      log.push('back' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    return false;
  }

  // 通用启发式兜底：多语言流程词推进 + 占位输入；无任何题目特定序列
  async function heuristicStep(nodes) {
    const NEXT = /start|begin|submit|confirm|check|verify|next|enter|continue|login|skip|同意|开始|提交|确认|确定|校验|下一步|登录|继续|跳过|进入/i;
    const edit = nodes.find(n => /EditText/i.test(n.cls) && !seen.has('edit:' + keyOf(n)));
    if (edit) {
      seen.add('edit:' + keyOf(edit));
      const r = await window.electronAPI.driveAppUi([
        { type: 'tap', x: edit.cx, y: edit.cy }, { type: 'sleep', ms: 300 },
        { type: 'text', value: 'A' }, { type: 'sleep', ms: 300 }]);
      log.push('input(占位)' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    const btn = nodes.find(n => n.clickable && !seen.has(keyOf(n))
      && NEXT.test((n.text || '') + ' ' + String(n.rid || '').split('/').pop()));
    if (btn) {
      seen.add(keyOf(btn));
      const r = await window.electronAPI.driveAppUi([{ type: 'tap', x: btn.cx, y: btn.cy }, { type: 'sleep', ms: 900 }]);
      log.push('tap(' + String(btn.text || btn.rid || 'btn').slice(0, 14) + ')' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    const any = nodes.find(n => n.clickable && !seen.has(keyOf(n)) && (n.x2 - n.x1) < 500);
    if (any) {
      seen.add(keyOf(any));
      const r = await window.electronAPI.driveAppUi([{ type: 'tap', x: any.cx, y: any.cy }, { type: 'sleep', ms: 900 }]);
      log.push('tap(any)' + (r && r.success ? ' ok' : ' err'));
      return true;
    }
    return false;
  }

  let stall = 0, lastKey = '', lastPlanKey = '';
  while (Date.now() < deadline) {
    const nodes = await dumpUiNodes();
    if (!nodes.length) { await sleepMs(800); continue; }

    // 1) AI 决策：只看当前界面的实时数据，不同题目自然得出不同操作
    const s = summarize(nodes);
    const key = s.list + '|' + s.texts;
    if (key === lastKey) { stall++; } else { stall = 0; lastKey = key; }
    // 停滞收尾：同一界面连续多轮无变化就结束（放在 AI 调用之前，
    // 否则"执行成功但界面没变"的循环会一直烧 AI 调用到超时）
    if (stall >= 3) { log.push('stall'); break; }

    let plan = null;
    if (stall < 2) { // 界面已连着没变 → AI 大概率给出同样无效计划，直接走启发式
      try {
        const prompt = `你在用 adb 自动操作安卓设备上的 CTF 题目 App（包名 ${packageName}），目标：触发 App 内部的校验/加密逻辑（正确答案未知时用占位值，正确值由并行运行的 Frida Hook 抓取）。

当前界面可交互控件（序号即 i）：
${s.list || '(无)'}

界面可见文字：${s.texts || '(无)'}

已执行过的动作（不要原样重复）：
${log.slice(-6).join('; ') || '(无)'}

给出接下来**1 步**操作，严格输出 JSON 数组，不要解释不要 markdown：
[{"action":"tap","i":0},
 {"action":"input","i":1,"text":"占位值"},
 {"action":"pattern","points":[0,4,8],"center":[540,960],"step":120},
 {"action":"swipe","from":[x,y],"to":[x,y]},
 {"action":"back"}]
规则：
- 只能操作上面列出的控件；pattern 仅当界面明显是九宫格图案锁（多个同尺寸无文字小方块呈网格，或存在 B 容器）才允许，center/step 按 B 的 center 与边长换算成数字。
- 无法推进或不需要操作时输出 []。
- 界面与上一轮相同、已试过的动作无效时，换未试过的控件或输出 []。`;
        const res = await window.electronAPI.claudeChat(
          [{ role: 'user', content: prompt }],
          '你是安卓 UI 自动化决策器。只输出 JSON 数组，不要调用任何工具。',
          { model: String((state.config.claude && state.config.claude.fastModel) || '').trim() || undefined, maxTokens: 800 });
        if (res && res.success && res.text) {
          const m = String(res.text).match(/\[[\s\S]*\]/);
          if (m) plan = JSON.parse(m[0]);
        }
      } catch (e) { /* AI 决策失败 → 启发式兜底 */ }
    }

    // 2) 执行 AI 计划的第一步（每轮一个动作、每轮重新 dump，
    //    避免 3 步计划在界面变化后按旧坐标错点）；序号对齐摘要清单 s.inter
    if (Array.isArray(plan) && plan.length) {
      const planKey = JSON.stringify(plan);
      if (!(stall > 0 && planKey === lastPlanKey)) {
        lastPlanKey = planKey;
        if (await execStep(plan[0], s.inter)) { await sleepMs(800); continue; }
      } else {
        log.push('repeat-plan');
      }
    }

    // 3) 通用启发式兜底
    if (await heuristicStep(nodes)) continue;

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
  else if (c.iv) {
    // 没能归一成 16B：不要丢！原样带上（preamble 会再枚举 IV 候选/回退 ECB），
    // 否则 Hook 端拿不到 iv 会直接放弃（"cbc 需要 16 字节 IV，实际 0"）。
    out.iv = String(c.iv); out.iv_encoding = c.iv_encoding || '';
  }
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
var __CTF_TRIES = 0;
function emitSafe(m){ try { send(m); } catch(e){} }
function __ctfArr(bytes){ try { var a=[]; for (var i=0;i<bytes.length;i++) a.push(bytes[i]); return a; } catch(e){ return null; } }
function __ctfSlice(arr, a, b){ try { var o=[]; for (var i=a;i<b && i<arr.length;i++) o.push(arr[i]); return o; } catch(e){ return null; } }
function __ctfLooksText(s){
  try {
    if (!s || s.length < 3) return false;
    s = String(s);
    var ok = 0, tot = Math.min(s.length, 64);
    for (var i=0;i<tot;i++){ var c = s.charCodeAt(i); if ((c>=32 && c<127) || c===9 || c===10 || c===13 || c>127) ok++; }
    return (ok / tot) >= 0.8;
  } catch(e){ return false; }
}
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
    var ctB  = __ctfToBytes(__CTF_KNOWN.ct, __CTF_KNOWN.enc || 'base64');
    if (!ctB) return;
    var algo = String(__CTF_KNOWN.algo || 'aes_cbc').toLowerCase();
    // 密钥候选：主编码 + 原文 + 哈希派生（对齐 Python 侧 key_candidates），任一解出 flag 即止
    var keyCands = [];
    var k0 = __ctfToBytes(__CTF_KNOWN.key, __CTF_KNOWN.keyEnc || 'ascii');
    if (k0) keyCands.push(k0);
    var kRaw = __ctfToBytes(__CTF_KNOWN.key, 'ascii');
    if (kRaw) keyCands.push(kRaw);
    function __ctfHash(name, arr){ try { var MD = Java.use('java.security.MessageDigest').getInstance(name); return __ctfArr(MD.digest(Java.array('byte', arr))); } catch(e){ return null; } }
    if (k0) { var m5 = __ctfHash('MD5', k0); if (m5) keyCands.push(m5); var s2 = __ctfHash('SHA-256', k0); if (s2) keyCands.push(s2); }
    // IV 候选：给定(16B) → 全零 → 密文首块 → 前置IV(解 ct[16:]) → 无(ECB)
    var ivCands = [];
    var iv0 = __ctfToBytes(__CTF_KNOWN.iv, __CTF_KNOWN.ivEnc || '');
    var Z16 = []; for (var z=0; z<16; z++) Z16.push(0);
    var Z8 = []; for (var z8=0; z8<8; z8++) Z8.push(0);
    var blk = (algo.indexOf('des') >= 0 && algo.indexOf('des3') < 0) ? 8 : 16;
    var ZB = blk === 8 ? Z8 : Z16;
    if (iv0 && iv0.length === blk) ivCands.push(iv0);
    ivCands.push(null);                                   // ECB
    ivCands.push(ZB);                                     // 零 IV
    if (ctB.length > blk) { ivCands.push(__ctfSlice(ctB,0,blk)); }
    var emitted = false;
    for (var ci=0; ci<keyCands.length && !emitted; ci++) {
      var keyB = keyCands[ci];
      for (var vi=0; vi<ivCands.length && !emitted; vi++) {
        var ivB = ivCands[vi];
        var body = ctB;
        var useMode = null;
        try {
          if (algo.indexOf('ecb') >= 0) { useMode = 'AES/ECB/PKCS5Padding'; }
          else if (ivB) { useMode = (blk === 8 ? 'DES/CBC/PKCS5Padding' : 'AES/CBC/PKCS5Padding'); }
          else { useMode = (blk === 8 ? 'DES/ECB/PKCS5Padding' : 'AES/ECB/PKCS5Padding'); }
          var C = Java.use('javax.crypto.Cipher').getInstance(useMode);
          var kAlg = (blk === 8 ? 'DES' : 'AES');
          var kSpec = Java.use('javax.crypto.spec.SecretKeySpec').$new(Java.array('byte', keyB), kAlg);
          if (useMode.indexOf('CBC') >= 0) C.init(2, kSpec, Java.use('javax.crypto.spec.IvParameterSpec').$new(Java.array('byte', ivB)));
          else C.init(2, kSpec);
          var s = String(Java.use('java.lang.String').$new(C.doFinal(Java.array('byte', body))));
          // 过滤乱码：至少含可打印 ASCII 比例，避免把"错误IV"的乱码当结果刷屏
          if (__ctfLooksText(s)) {
            emitSafe('[DATA] (' + tag + ') DECRYPTED = ' + s);
            emitted = true;
            if (/NCTF\\{|flag\\{|ctf\\{/i.test(s)) { __CTF_DONE = true; emitSafe('[FLAG]' + s + '[/FLAG]'); }
          }
        } catch(e) { /* 该组合不可用，继续下一个候选 */ }
      }
    }
    if (!emitted && __CTF_TRIES <= 1) emitSafe('[!] 进程内解密未命中（key/iv/模式候选均失败）；将靠被动 hook 抓取');
  } catch(e) { emitSafe('[!] decrypt(' + tag + '): ' + e); }
}
if (typeof Java !== 'undefined' && Java.available) {
  Java.perform(function () {
    __ctfDecrypt('bootstrap');
    // 周期性重试：脚本可能稍后才拿到运行时参数（Hook 捕获）或注入的已知参数。
    // 但**不无脑刷屏**：最多重试 4 次（约 12s），且同样的 key/iv/模式不会重复打印错误。
    if (!__CTF_DONE) {
      var __ctfTick = setInterval(function () {
        __CTF_TRIES++;
        try { __ctfDecrypt('tick'); } catch(e){}
        if (__CTF_DONE || __CTF_TRIES >= 4) clearInterval(__ctfTick);
      }, 3000);
    }
  });
}
// ==== end auto-injected decryptor ====
`;
}

function buildFallbackFridaScript(packageName, crypto, targets) {
  crypto = normalizeCrypto(crypto);
  // crypto（可选）：已求解的加密参数 {key, iv, ciphertext, encoding, iv_encoding, algo}
  // 有了它，Hook 可在 App 进程内**直接解密并打印 [FLAG]**，实现"Hook 出 flag"，
  // 不依赖人工在模拟器里逐屏操作（本题外网/离线的多阶段题尤其如此）。
  // targets（可选）：从静态分析抽出的**针对性 hook 目标** {classes,natives,methods,keywords}。
  // ⚠️ 关键：兜底模板不再"只会盲扫"——它会把题目已知的类/方法/native 函数**优先 hook**，
  //    使"AI 脚本失败后的兜底"也具备针对性（否则固定盲扫大概率抓不到关键数据）。
  const c = (crypto && typeof crypto === 'object') ? crypto : {};
  const T = (targets && typeof targets === 'object') ? targets : {};
  const j = (v) => JSON.stringify(v == null ? '' : String(v));
  const jlist = (a) => JSON.stringify((Array.isArray(a) ? a : []).map(String));
  return `'use strict';
send('[*] fallback hook script loaded');
${fridaSolvePreamble(crypto)}
function hr(b){ try { var h=''; for (var i=0;i<b.length;i++){ var c=b[i]&0xff; h+=(c<16?'0':'')+c.toString(16);} return h; } catch(e){ return '<err>'; } }
function ia(a){ try { var s=[]; for(var i=0;i<a.length;i++) s.push(a[i]); return '['+s.join(',')+']'; } catch(e){ return '<err>'; } }
// ===== 针对性 hook（来自静态分析情报，优先执行）=====
var __CTF_TARGETS = { pkg: ${j(T.pkg)}, classes: ${jlist(T.classes)}, natives: ${jlist(T.natives)}, methods: ${jlist(T.methods)}, keywords: ${jlist(T.keywords)} };
send('[HIT] targets: classes=' + __CTF_TARGETS.classes.length + ' natives=' + __CTF_TARGETS.natives.join('/') + ' methods=' + __CTF_TARGETS.methods.join('/'));
// 三视图打印器：优先用 okhttp okio.ByteString（一行出 hex/base64/utf8，比手写更健壮），
// 不可用时降级到手写 hr()/utfb()。给 [B 型数据统一输出，避免漏看非可见字节。
var __BS = null; try { __BS = Java.use('com.android.okhttp.okio.ByteString'); } catch (e) { try { __BS = Java.use('okio.ByteString'); } catch (e2) {} }
function utfb(b){ try { return String(Java.use('java.lang.String').$new(b, 'UTF-8')); } catch (e) { return ''; } }
function view(tag, d){ try {
  if (__BS && __BS.of) { var z = __BS.of(d); send('[DATA] ' + tag + ' hex=' + z.hex() + ' b64=' + z.base64()); return; }
} catch (e) {} send('[DATA] ' + tag + ' hex=' + hr(d) + ' str=' + utfb(d)); }
if (Java.available) {
  Java.perform(function () {
    // 0) 【通用关键】主动 hook Java 层声明的 native 方法（含 RegisterNatives 动态注册的）。
    //    很多题（如 com.cr.myapplication.NativeBridge 的 c/ab/cd/dc）核心校验是 native 方法，
    //    但用 RegisterNatives 动态注册 → so 里没有 Java_ 导出 → "JNI 导出扫描"抓不到。
    //    这里枚举目标 App 自身包下的类，找出所有 native 方法并 hook 入参/返回，兜住这类题。
    //    注意：spawn 早期某些类尚未加载，故封装成可重入函数，多次调用直到 hook 到目标。
    var __hooked = {};
    function __scanNatives() {
      try {
        var __pkg = ${j(packageName)};
        var __seenNative = 0;
        Java.enumerateLoadedClassesSync().forEach(function (cn) {
          if (__pkg && cn.indexOf(__pkg) !== 0) return;      // 只扫 App 自身类，避开系统海量类
          if (cn.indexOf('$') >= 0) return;                   // 跳过内部类，降噪
          var cls; try { cls = Java.use(cn); } catch (e) { return; }
          var methods; try { methods = cls.class.getDeclaredMethods(); } catch (e) { return; }
          methods.forEach(function (m) {
            try {
              var mods = m.getModifiers();
              if ((mods & 0x0100) === 0) return;              // 0x0100 = native
              var mn = m.getName();
              var key = cn + '.' + mn;
              if (__hooked[key]) return;                       // 已 hook 过，避免重复
              send('[HIT] native method: ' + key + '  (' + m.toString() + ')');
              cls[mn].overloads.forEach(function (ov) {
                ov.implementation = function () {
                  var a = Array.prototype.slice.call(arguments);
                  var r;
                  try { r = ov.apply(this, arguments); } catch (e) { send('[DATA] ' + mn + ' threw ' + e); throw e; }
                  send('[DATA] native ' + key + '(' + a.map(function (x) { return x === null ? 'null' : (x.length !== undefined ? ia(x) : (x.toString ? x.toString() : String(x))); }).join(',') + ') = ' + (r === null || r === undefined ? String(r) : (r.length !== undefined ? ia(r) : String(r))));
                  return r;
                };
              });
              __hooked[key] = 1;
              __seenNative++;
            } catch (e) {}
          });
        });
        if (__seenNative) send('[HIT] native-method scan: +' + __seenNative + ' (total ' + Object.keys(__hooked).length + ')');
      } catch (e) { send('[!] native scan: ' + e); }
    }
    __scanNatives();
    // 多次重扫：捕获启动后逐步加载的类（native 类常在 Activity onCreate 后才 load）
    setTimeout(function () { Java.perform(__scanNatives); }, 2000);
    setTimeout(function () { Java.perform(__scanNatives); }, 6000);
    setTimeout(function () { Java.perform(__scanNatives); }, 12000);
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
    // 0a) 【针对性 hook】按静态分析情报，主动 hook 题目已知的类/方法（不依赖盲扫）
    try {
      __CTF_TARGETS.classes.forEach(function (cn) {
        try {
          var C = Java.use(cn);
          // 该类的所有方法里，命中"语义名"或情报里的方法名 → 优先 hook
          C.class.getDeclaredMethods().forEach(function (md) {
            try {
              var nm = md.getName();
              var want = __CTF_TARGETS.methods.indexOf(nm) >= 0 || __CTF_TARGETS.natives.indexOf(nm) >= 0
                || /check|verify|encrypt|decrypt|sign|hash|calc|validate|native/i.test(nm);
              if (!want || !C[nm]) return;
              C[nm].overloads.forEach(function (ov) {
                ov.implementation = function () {
                  var a = Array.prototype.slice.call(arguments);
                  var r = ov.apply(this, arguments);
                  send('[DATA] ' + cn + '.' + nm + '(' + a.map(function (x) { return x === null ? 'null' : (x.length !== undefined ? ia(x) : String(x)); }).join(',') + ') = ' + (r === null || r === undefined ? String(r) : (r.length !== undefined ? ia(r) : String(r))));
                  return r;
                };
              });
              send('[HIT] targeted hook ' + cn + '.' + nm);
            } catch (e) {}
          });
        } catch (e) {}
      });
    } catch (e) {}
    // 0b) 反调试 / Frida 检测 绕过（CTF 题常带；命中即替换返回值，避免 App 退出）
    try {
      var DEBUGCLASSES = ['android.os.Debug', 'android.app.Application'];
      // Debug.isDebuggerConnected -> false
      try { Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { send('[HIT] bypass Debug.isDebuggerConnected'); return false; }; } catch (e) {}
      // 常见的一些检测点（存在才改）
      try { var Sys = Java.use('java.lang.System'); if (Sys.getProperty) { var __gp = Sys.getProperty; Sys.getProperty.overload('java.lang.String').implementation = function (k) { var v = __gp.call(this, k); if (/frida|debug|xposed|magisk|hook/i.test(k)) { send('[HIT] bypass System.getProperty(' + k + ')'); return null; } return v; }; } } catch (e) {}
      // 文件检测：/proc/self/maps 里 frida 关键字读取（只能观察，无法轻易替换内核结果）
      send('[HIT] anti-debug hooks installed');
    } catch (e) {}
    // 0c) System.loadLibrary 监控 + 动态加载监控（so/DEX 加载时机，配合 attach native）
    try {
      var Sys2 = Java.use('java.lang.System');
      Sys2.loadLibrary.overload('java.lang.String').implementation = function (name) { send('[DATA] System.loadLibrary("' + name + '")'); return this.loadLibrary(name); };
    } catch (e) {}
    try {
      var DCL = Java.use('dalvik.system.DexClassLoader');
      DCL.loadClass.overload('java.lang.String').implementation = function (n) { send('[DATA] DexClassLoader.loadClass(' + n + ')'); return this.loadClass(n); };
    } catch (e) {}
    // 0c2) dlopen/dlsym 监控（native so 动态加载链，配合 attach native）
    try {
      var dlopen = Module.findExportByName('libc.so', 'dlopen');
      if (dlopen) Interceptor.attach(dlopen, { onEnter: function (a) { try { var p = Memory.readCString(a[0]); if (p && /\\.so/.test(p)) send('[DATA] dlopen ' + p); } catch (e) {} } });
      var dlsym = Module.findExportByName('libc.so', 'dlsym');
      if (dlsym) Interceptor.attach(dlsym, { onEnter: function (a) { try { var s = Memory.readCString(a[1]); if (s && /frida|anti|debug|check|inject/i.test(s)) send('[DATA] dlsym ' + s); } catch (e) {} } });
    } catch (e) {}
    // 0c3) 反调试线程阻断（pthread_create 白名单：拦截常见"反调试循环"线程，直接不创建）
    try {
      var pc = Module.findExportByName('libc.so', 'pthread_create');
      if (pc) {
        var __pc = new NativeFunction(pc, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        Interceptor.replace(pc, new NativeCallback(function (a0, a1, a2, a3) {
          try {
            var name = DebugSymbol.fromAddress(a2);
            var nm = (name && name.name) ? name.name : '';
            if (/frida|anti|detect|debug|check|inject|ptrace/i.test(nm)) { send('[HIT] blocked anti-debug thread: ' + nm); return 0; }
          } catch (e) {}
          return __pc(a0, a1, a2, a3);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
        send('[HIT] pthread_create guard installed');
      }
    } catch (e) {}
    // 0d) SSL Pinning 绕过（抓 HTTPS 流量；TrustManager + HostnameVerifier + okhttp）
    try {
      var X509TM = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustManager = Java.use('javax.net.ssl.TrustManager');
      var tm = Java.registerClass({ name: 'ctf.TrustAll', implements: [X509TM], methods: {
        checkClientTrusted: function () {}, checkServerTrusted: function () {}, getAcceptedIssuers: function () { return []; }
      }});
      var ctx = SSLContext.getInstance('TLS');
      ctx.init(null, [tm.$new()], null);
      try { SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (a, b, c) { send('[HIT] bypass SSLContext.init'); return this.init(a, [tm.$new()], c); }; } catch (e) {}
      var HV = Java.use('javax.net.ssl.HostnameVerifier');
      var hv = Java.registerClass({ name: 'ctf.HV', implements: [HV], methods: { verify: function () { return true; } } });
      try { Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(hv.$new()); } catch (e) {}
      send('[HIT] ssl-pinning bypass installed');
    } catch (e) {}
    // 0e) 打印调用栈（定位"谁调用了这个校验函数"；仅对含关键字的类名打印，降噪）
    try {
      var Throwable = Java.use('java.lang.Throwable');
      Throwable.$init.overload().implementation = function () {
        var r = this.$init();
        try {
          var st = Java.use('android.util.Log').getStackTraceString(this);
          if (/flag|check|verify|encrypt|decrypt|NativeBridge|native|crypt/i.test(st)) send('[DATA] stack: ' + st.replace(/\\n/g, ' | ').slice(0, 600));
        } catch (e) {}
        return r;
      };
    } catch (e) {}
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
    // 2b) RegisterNatives 拦截（关键！动态注册的 native 函数没有 Java_ 导出，
    //     只有在这里能拿到「方法名 → 真实实现指针」，再 attach 实现即抓到入参/返回）。
    try {
      var libart = Process.findModuleByName('libart.so');
      var rn = null;
      if (libart) {
        libart.enumerateSymbols().forEach(function (sy) {
          if (sy.name.indexOf('RegisterNatives') >= 0 && sy.name.indexOf('CheckJNI') < 0) rn = sy.address;
        });
      }
      if (rn) {
        Interceptor.attach(rn, { onEnter: function (args) {
          try {
            var cnt = args[3].toInt32();
            var methods = args[2];
            var env = Java.vm.getEnv();
            var cls = env.getClassName(args[1]);
            for (var i = 0; i < cnt; i++) {
              var mi = methods.add(i * Process.pointerSize * 3);   // JNINativeMethod{name,sig,fnPtr}
              var nm = Memory.readCString(Memory.readPointer(mi));
              var sig = Memory.readCString(Memory.readPointer(mi.add(Process.pointerSize)));
              var fn = Memory.readPointer(mi.add(Process.pointerSize * 2));
              send('[HIT] RegisterNatives ' + cls + '.' + nm + sig + ' @' + fn);
              try {
                Interceptor.attach(fn, {
                  onEnter: function (a) { this.a0 = a[0]; this.a1 = a[1]; this.a2 = a[2]; this.a3 = a[3]; send('[DATA] ' + nm + ' enter'); },
                  onLeave: function (r) { send('[DATA] ' + nm + ' return ' + r); }
                });
              } catch (e) {}
            }
          } catch (e) { send('[!] RegisterNatives parse: ' + e); }
        }});
        send('[HIT] RegisterNatives hooked');
      }
    } catch (e) {}
    // 2c) native 定位封装：导出名 / 符号(子串) / 偏移(+thumb) —— 交给 AI/脚本按需调用
    function findFunc(soName, nameOrOffset, kind) {
      try {
        var m = Process.findModuleByName(soName); if (!m) return null;
        if (kind === 'offset') { var off = parseInt(nameOrOffset, 16); return m.base.add(off); }
        if (kind === 'symbol') {
          var hit = null; m.enumerateSymbols().forEach(function (sy) { if (!hit && sy.name.indexOf(nameOrOffset) >= 0) hit = sy.address; }); return hit;
        }
        return m.findExportByName ? m.findExportByName(nameOrOffset) : Module.findExportByName(soName, nameOrOffset);
      } catch (e) { return null; }
    }
    globalThis.__ctfFindFunc = findFunc;
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
    // 3b) JCE 通杀自吐：密钥来源类 + Mac + Signature + RSA（无需追业务代码，注入即吐算法/密钥/明文）
    try {
      // 密钥/IV 构造点（比 hook Cipher.init 更早、更全）
      var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
      SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
        send('[DATA] SecretKeySpec alg=' + alg + ' keyHex=' + hr(k) + ' keyStr=' + ia(k)); return this.$init(k, alg);
      };
      try { var IVS = Java.use('javax.crypto.spec.IvParameterSpec'); IVS.$init.overload('[B').implementation = function (iv) { send('[DATA] IvParameterSpec ivHex=' + hr(iv)); return this.$init(iv); }; } catch (e) {}
      try { var DKS = Java.use('javax.crypto.spec.DESKeySpec'); DKS.$init.overload('[B').implementation = function (k) { send('[DATA] DESKeySpec keyHex=' + hr(k)); return this.$init(k); }; } catch (e) {}
      // MessageDigest.getInstance 拿算法名
      var md2 = Java.use('java.security.MessageDigest');
      try { md2.getInstance.overload('java.lang.String').implementation = function (a) { send('[HIT] MessageDigest.getInstance ' + a); return this.getInstance(a); }; } catch (e) {}
      // Mac（HMAC）
      try { var Mac = Java.use('javax.crypto.Mac'); Mac.getInstance.overload('java.lang.String').implementation = function (a) { send('[HIT] Mac algo=' + a); return this.getInstance(a); }; Mac.doFinal.overload('[B').implementation = function (d) { var r = this.doFinal(d); send('[DATA] Mac.doFinal in=' + hr(d) + ' out=' + hr(r)); return r; }; } catch (e) {}
      // Signature（数字签名/验签）
      try { var Sig = Java.use('java.security.Signature'); try { Sig.update.overload('[B', 'int', 'int').implementation = function (d, o, l) { send('[DATA] Signature.update ' + ia(d)); return this.update(d, o, l); }; } catch (e) {} try { Sig.sign.overload().implementation = function () { var r = this.sign(); send('[DATA] Signature.sign=' + hr(r)); return r; }; } catch (e) {} } catch (e) {}
      // RSA 公钥 (N,E)
      try { Java.use('java.security.spec.RSAPublicKeySpec').$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (n, e) { send('[DATA] RSA N=' + n.toString(16) + ' E=' + e.toString(16)); return this.$init(n, e); }; } catch (e) {}
      send('[HIT] JCE crypto self-leak installed');
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
    // 7) String.equals（严格降噪：高熵优先保留；包名/资源/路径/框架词排除）
    try {
      var JStr = Java.use('java.lang.String');
      var NOI_ALGO = /^(Cipher|AES|DES|RSA|MD5|SHA[\\-0-9]*|Hmac[A-Za-z0-9]*)$/i;
      var NOI_WORD = /^(include|fragment|window|search|autofill|tag|merge|view|blink|display|accessibility|layout_inflater|requestFocus|ViewStub|FrameLayout|LinearLayout|ScrollView|TextView|ContentFrameLayout)$/i;
      var isNoise = function (s) {
        if (!s) return true;
        if (/\\s/.test(s)) return true;
        if (/^[a-z0-9_]+(\\.[a-z0-9_]+){2,}/i.test(s)) return true;
        if (/^(res|assets|lib|META-INF|data|system|proc)[\\/]/i.test(s)) return true;
        if (/^\\//.test(s)) return true;
        if (/^android[.:]/i.test(s)) return true;
        if (NOI_ALGO.test(s) || NOI_WORD.test(s)) return true;
        if (/(interpolator|transition|viewstub|inflater|animator)/i.test(s)) return true;
        if (/^(change|auto)[A-Z]/.test(s)) return true;
        if (/^[A-Za-z0-9]+[\\/][A-Za-z0-9\\/]+$/.test(s)) return true;
        return false;
      };
      var isEntropy = function (s) {
        if (!s || s.length < 8) return false;
        if (/[{]/.test(s)) return true;
        if (/^[0-9a-fA-F]{16,}$/.test(s)) return true;
        if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s)) return true;
        return false;
      };
      JStr.equals.implementation = function (o) {
        var a = this.toString(); var b = o ? o.toString() : '';
        var r = this.equals(o);
        // 高熵优先（flag==flag、hex key 比较必须留）；否则双方皆噪音形态则丢弃；再判语义词
        var hit = isEntropy(a) || isEntropy(b)
          || (!(isNoise(a) && isNoise(b)) && (/flag|ctf|key|secret|token|pass|stage/i.test(a) || /flag|ctf|key|secret|token|pass|stage/i.test(b)));
        if (hit) send('[HIT] String.equals ' + r + ': "' + a + '" == "' + b + '"');
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

// 从静态分析结果中抽取"要 hook 的目标情报"（类名/方法名/native函数/包名），
// 供 fallback 模板做**针对性** hook（而非盲目通扫）。来源：类列表、AI 结论、关键类代码。
function extractHookTargets(analysisData, packageName) {
  const t = { pkg: packageName || '', classes: [], natives: [], methods: [], keywords: [] };
  const classes = (analysisData && Array.isArray(analysisData.classes)) ? analysisData.classes : [];
  const pkg = String(packageName || '');
  // 1) 题目自身包下的类优先 + 名字含语义关键词的类
  const semantic = /check|verify|encrypt|decrypt|cipher|crypt|key|flag|native|bridge|sign|hash|token|secret|util|stage|jni/i;
  const selfClasses = classes.filter(c => !pkg || String(c).indexOf(pkg) === 0);
  const picked = (selfClasses.length ? selfClasses : classes)
    .filter(c => semantic.test(String(c)) || /^[A-Z][A-Za-z0-9_]{2,}$/.test(String(c).split('/').pop() || ''));
  for (const c of picked.slice(0, 20)) t.classes.push(String(c));
  // 2) 从 AI 结论/关键类代码里抠 native 方法名与可疑方法名
  const blob = [state.lastAiText || '', mcpCache.mainCode || '', Object.values(mcpCache.otherClasses || {}).join('\n')].join('\n');
  const nativeRe = /(?:native\s+[\w\[\]<>.]+\s+|public\s+native\s+[\w\[\]<>.]+\s+)([A-Za-z_$][\w$]*)\s*\(/g;
  let m; while ((m = nativeRe.exec(blob)) !== null) if (t.natives.indexOf(m[1]) < 0) t.natives.push(m[1]);
  const methRe = /\b([A-Za-z_$][\w$]{1,30})\s*\([^)]*\)\s*\{/g;
  while ((m = methRe.exec(blob)) !== null) { const n = m[1]; if (/check|verify|encrypt|decrypt|sign|hash|calc|verify|validate/i.test(n) && t.methods.indexOf(n) < 0) t.methods.push(n); }
  // 3) 关键词（算法名），供模板里做优先 hook
  for (const kw of ['rc4', 'tea', 'xtea', 'xxtea', 'aes', 'des', '3des', 'sm4', 'chacha', 'salsa', 'xor', 'base64', 'md5', 'sha']) {
    if (new RegExp(kw, 'i').test(blob)) t.keywords.push(kw);
  }
  return t;
}

async function autoFridaStage() {
  if (state.fileType !== 'APK' || !state.currentFile) return;

  addLog('info', '========================================');
  addLog('info', '[阶段3] 动态调试自动化（Frida）');
  addLog('info', '========================================');

  // 1. 探测 frida-server（先重连设备并重新转发：daemon 被顶替时 forward 会丢失）
  const fridaPort = (state.config && state.config.emulator && state.config.emulator.frida_port) || 27042;
  let online = false;
  try {
    const adbPort = (state.config.emulator && state.config.emulator.adb_port) || 62025;
    await window.electronAPI.adbCommand(`connect 127.0.0.1:${adbPort}`);
    await window.electronAPI.adbCommand(`forward tcp:${fridaPort} tcp:${fridaPort}`);
  } catch (e) { /* 忽略，下面探活仍会判定 */ }
  try {
    const probe = await window.electronAPI.checkPort(`http://127.0.0.1:${fridaPort}/`);
    online = !!(probe && probe.listening);
  } catch (e) { online = false; }
  if (!online) {
    addLog('info', `Frida 未在线（127.0.0.1:${fridaPort} 不可达），跳过动态调试自动化；可启动模拟器+frida-server 后点"运行Hook"手动执行`);
    return;
  }

  // 1b. Frida 能力自检：端口通不代表枚举可用。某些 frida-server 版本在与旧版模拟器
  //     （如 Nox Android 9）组合时，会抛
  //     `NullPointerException: queryIntentActivities on null`——导致 frida-ps / -f / -n / -F 全失败。
  //     但 **按 PID attach（frida -p <PID>，PID 用 adb pidof/ps 取）走的是另一条路径，实测可用**。
  //     因此这里不再"判死刑"，只在枚举失败时**提示已切换到 PID 模式**，动态阶段照常继续。
  let fridaCompat = true;
  try {
    const ps = await window.electronAPI.fridaPs();
    const psText = JSON.stringify(ps || {});
    if (/queryIntentActivities|NullPointerException|unable to communicate|major versions match/i.test(psText)) {
      fridaCompat = false;
      addLog('info', 'Frida 进程枚举不可用（queryIntentActivities NPE）——已自动切换为「按 PID 附加」模式（adb 取 PID），动态阶段继续。');
      addSystemMessage('**ℹ️ Frida 枚举不可用，已切换 PID 模式**\n\n`frida-ps` / `-f` / `-n` 走的是会 NPE 的枚举路径（frida + 本模拟器的已知 quirk）。\n本工具已改为用 **adb 取 PID → `frida -p <PID>` 附加**，该路径实测正常，动态调试阶段继续执行。\n\n> 若想彻底根治（让枚举也能用），可把 frida 与 frida-server 一并降到与模拟器匹配的版本并重启 server。');
    }
  } catch (e) { /* 探活失败不阻断，交给后续 spawn 回退处理 */ }

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
  let vres = await validateAndRepairFridaScript(script);
  // 校验失败：让 AI 带着"具体错误"**反复重生成**（最多 2 轮），每轮都带全题目情报——
  // 绝不轻易退化成"固定模板"。语法笔误（少 '+'/括号）是 AI 长脚本的高频问题，重生成命中率高。
  for (let round = 1; round <= 2 && !vres.ok; round++) {
    addLog('info', `AI 脚本语法校验未通过（${String(vres.error || '').slice(0, 80)}），第 ${round}/2 轮带错误重新生成...`);
    try {
      const retry = await window.electronAPI.claudeChat(
        [{ role: 'user', content: genPrompt + `\n\n注意：你上一次输出的脚本**无法通过语法校验**，错误是：\n  ${String(vres.error || '').slice(0, 200)}\n请重新输出一个**语法绝对正确、完整可运行**的脚本：仔细检查每一处字符串拼接（该有 '+' 的地方别漏）、括号/花括号配对完整、方括号与引号成对、正则里的 '/' 已转义。宁可精简也不要漏写符号。只输出一个 [FRIDA_SCRIPT] 块。` }],
        '你是 Frida 动态插桩专家。只输出一个 [FRIDA_SCRIPT] 块。不要调用任何工具。',
        { model: String((state.config && state.config.claude && state.config.claude.fastModel) || '').trim() || undefined, maxTokens: 16384 });
      const sm2 = retry && retry.success ? String(retry.text || '').match(/\[FRIDA_SCRIPT\]([\s\S]+?)\[\/FRIDA_SCRIPT\]/) : null;
      if (sm2) {
        const cand = sm2[1].replace(/^```(?:javascript|js)?\s*/i, '').replace(/```\s*$/, '').trim();
        const v2 = await validateAndRepairFridaScript(cand);
        if (v2.ok) { vres = v2; addLog('success', `脚本已按错误信息重新生成并通过校验（第 ${round} 轮）`); break; }
        vres = v2; // 记录最新错误供下一轮
      }
    } catch (e) { addLog('warning', '重生成异常: ' + e.message); }
  }
  const cryptoParams = pickCryptoParams();
  // ⚠️ analysisData 是 analyzeAPK 的局部变量，本函数（autoFridaStage）拿不到：
  // 直接引用会抛 "analysisData is not defined"，把整个 APK 解题流程吞掉
  //（实测：2 道 APK 题都因此报 exception 中断）。这里按可用的全局状态重建最小对象。
  const fridaAnalysisCtx = {
    packageName: packageName || null,
    classes: (mcpCache && Array.isArray(mcpCache.classes)) ? mcpCache.classes : [],
    manifest: (mcpCache && mcpCache.manifest) || null,
  };
  const hookTargets = extractHookTargets(fridaAnalysisCtx, packageName);
  if (!vres.ok) {
    // 语法失败 → 已经不在此处直接落"固定模板"了：上面的重试循环已带错误+情报重生成多次。
    // 仅当所有重试都失败，才用"情报增强版"兜底模板（会优先 hook 题目已知的类/方法/native）。
    addLog('warning', 'AI Hook 脚本多次重生成仍语法失败（' + vres.error + '）；改用**情报增强版**内置模板（按题目已知目标针对性 hook）');
    script = buildFallbackFridaScript(packageName, cryptoParams, hookTargets);
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

  // 4. 拉起 APP 并注入 Hook，同时**并行驱动界面**（关键：否则 App 停在首页，
  //    手势/输入框触发的校验代码永不执行，Hook 抓到的全是启动噪音）。
  //    枚举可用 → 用 spawn -f（能在启动期就挂上 hook）；
  //    枚举不可用（NPE）→ -f 必然失败，直接用 adb 拉起 + 按 PID attach（省掉一次注定失败的往返）。
  let hookTarget = 'spawn:' + packageName;
  if (!fridaCompat) {
    addLog('info', `枚举不可用：改用「adb 拉起 + 按 PID attach」模式执行 Hook（目标 ${packageName}）`);
    try {
      await window.electronAPI.adbCommand(`shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`);
      await sleepMs(2500);
    } catch (e) { /* 拉起失败仍可让主进程再兜底 */ }
    hookTarget = packageName;
  }
  addLog('info', `注入 Hook 到 ${hookTarget}，同时自动驱动界面（抓取约 25s）...`);

  // 4a. 迭代式驱动界面（每轮 dump→操作→再dump），与 Hook 并行；
  //     让界面触发的校验代码真正执行（否则 App 停在首页，Hook 只抓到启动噪音）。
  const drivePromise = (async () => {
    try {
      await sleepMs(5000); // 等 App 完成启动 + hook 安装
      addLog('info', '开始自动驱动界面（AI 逐屏决策：读界面控件→决定操作→触发校验）...');
      const log = await driveAppIteratively(packageName, 45000);
      addLog('success', `界面驱动完成：${log.length} 个动作 → ${log.join(' | ')}`);
    } catch (e) {
      addLog('warning', '界面驱动失败（不影响 Hook 抓取）: ' + e.message);
    }
  })();

  // 4b. 同时执行 Frida Hook（阻塞至命中/超时）
  // 抓取窗口必须长于 UI 驱动（5s 启动 + 30s 驱动），否则等校验真正发生时窗口已关闭。
  // 用滚动窗口：每来一条数据就续 60s，持续有数据就一直抓；连续 60s 无数据才收尾。
  const hookPromise = window.electronAPI.runFridaHook(script, hookTarget, { windowMs: 60000, hardCapMs: 600000 });

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
  // 关键：Frida 输出常达数万字符，前几千行多是启动噪音。更重要的是**分级**：
  //   · 高价值行（[DATA]/[FLAG]/flag 形态/加解密实参/SP 读写）**全部保留**，不参与任何截断；
  //   · 噪音行（[HIT] 命中痕迹，常达上百条）单独限量，避免把真证据挤出窗口。
  // 教训：此前把 [HIT] 与真证据混在一个池子里再 `slice(-120)`，而噪音多在真证据**之后** →
  //   尾部 120 条几乎全是噪音，真证据被整段丢弃（只以 [DATA]/普通输出形式出现的 flag 就此漏掉）。
  const allLines = String(output).split(/\r?\n/);
  const HIT_LINE = /^\s*\[HIT\]/i;
  const highLines = allLines.filter(l => l.trim() && !HIT_LINE.test(l) &&
    /\[DATA\]|\[FLAG\]|NCTF\{|flag\{|ctf\{|Arrays\.equals|Cipher\.|SP\.|putString|putBoolean/i.test(l));
  const hitLines = allLines.filter(l => HIT_LINE.test(l));
  const HIT_KEEP = 40;                                   // 噪音行限量保留（够定位、不淹没证据）
  const hitKept = hitLines.length > HIT_KEEP
    ? [`（[HIT] 命中痕迹共 ${hitLines.length} 条，仅保留末尾 ${HIT_KEEP} 条作为线索）`, ...hitLines.slice(-HIT_KEEP)]
    : hitLines;
  const keptLines = [...highLines, ...hitKept];
  const outputSummary = keptLines.length
    ? `（原始 ${allLines.length} 行 → 保留高价值 ${highLines.length} 条 + [HIT] 线索 ${Math.min(hitLines.length, HIT_KEEP)}/${hitLines.length} 条）\n` + keptLines.join('\n')
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
      '你是CTF逆向解题专家。结合动态抓取数据给出 flag。不要调用任何工具。' + experienceSection()
    );
    endStreamMessage();
    if (result.success && result.text) {
      state.lastAiText = result.text;
      // 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags: vf } = await finalizeSolve(result.text, { source: 'frida', noteSection: 'Flag(动态)' });
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
  // 内容命中筛查结果（APK 路径填充，selectKeyClasses 读取）——不清会跨文件泄漏，
  // 把上一题的"高价值类"强行置顶到本题的类选择里。
  state._keyClassesByContent = null;
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

  // 自动预取：本题固定清单禁止调工具，故先按已采集代码/包名检索知识库并内联攻略
  const knowledge = await prefetchKnowledge(
    [analysisData.manifest, analysisData.packageName, mainClass, analysisData.mainActivityCode,
     (analysisData.otherClassesCode || []).map(c => c.code).join('\n')].join('\n'),
    state.fileType || 'APK', [analysisData.packageName].filter(Boolean));

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
${knowledge}

请直接分析上面的代码，找出：
1. 加密算法是什么
2. flag的生成或验证逻辑
3. 直接给出flag

注意：不要调用任何工具，直接基于上面的代码分析。

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，必须附验证数据（工具会本地复现）：
   \`${VERIFY_CONTRACT}\`
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
      `你是CTF逆向解题专家。请直接分析代码并给出flag。直接基于提供的代码分析，不要调用任何工具。\n解题学习闭环（强制）：回答最后必须输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条、每条200字内[/EXPERIENCE]（确无新收获则写"无新增经验"），工具会自动写入经验库，下次同类题优先复用、避免重复踩坑。` + experienceSection()
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

      // 验证闭环 + 失败时本地枚举兜底 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags, flags } = await finalizeSolve(result.text, { source: 'ai' });

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

  // 多阶段接力：上一层（如 APK 解包/壳解出）的结论摘要
  const stageBlock = state.stageContext
    ? `\n## ⚙️ 前序阶段上下文（本题是多阶段题目，第 ${state.stageDepth} 层）\n${String(state.stageContext).slice(0, 4000)}\n⚠️ 上面的结论来自上一层文件（已分析完），当前文件是它解出的下一阶段。请在已有结论基础上继续，不要重复上一层工作。\n`
    : '';

  const deepPrompt = `我正在解一道 CTF APK 题，静态固定清单分析未能得出 flag。请你**使用工具**自主深入分析并求出 flag。
${stageBlock}
文件路径：${state.currentFile}
包名：${pkg || '未知'}
主Activity：${mainClass || '未知'}

## 已获取的类列表（完整，供你挑目标类反编译）
${classesList}
${mcpCache.nativeIntel && mcpCache.nativeIntel.decompiled.length ? `
## IDA 已反编译的 native 函数（直接用，勿重复反编译）
${mcpCache.nativeIntel.decompiled.map(d => `### ${d.name}\n\`\`\`c\n${d.code}\n\`\`\``).join('\n\n')}
${mcpCache.nativeIntel.strings ? `\n## IDA 关键字符串\n${mcpCache.nativeIntel.strings}` : ''}
${mcpCache.nativeIntel.globals && mcpCache.nativeIntel.globals.length ? `\n## SO 全局数据表（被反编译函数引用的常量表，逐字节 hex；密钥/密文/S盒常在此）\n${mcpCache.nativeIntel.globals.map(g => `### ${g.name} @ ${g.addr}\n${g.data}`).join('\n')}` : ''}${mcpCache.nativeIntel.segments && mcpCache.nativeIntel.segments.length ? `\n## SO 数据段 dump（.rodata/.data 全段 hex，用于兜底取常量；量大，按需解析）\n${mcpCache.nativeIntel.segments.map(g => `### ${g.name} @ ${g.addr}\n${String(g.data).slice(0, 6000)}`).join('\n')}` : ''}${mcpCache.nativeIntel.globalsList ? `\n## SO 全局符号清单\n${mcpCache.nativeIntel.globalsList}` : ''}` : ''}

## 你必须**严格按 4 个阶段推进**（每阶段先产出证据，再进下一阶段；不要跳步臆测）
> 若上文未提供某项数据（nativeIntel 为空 / 类列表不全），**先自己调工具补齐再继续**。

**阶段① 收集（把"代码+数据"喂全，缺一不可）**
- 校验逻辑定位：\`jeb_get_all_classes\` 拿全类清单 → 对**混淆类**（N0/d、C/h、K0/a 这类单字母包/类）
  以及**名字含 check/verify/encrypt/key/stage/Util/Encoder** 的类，\`jeb_get_class_decompiled\` 逐个反编译；
  Activity 只是 UI，真逻辑在别的类。
- 常量数据：读 \`strings.xml\` / \`resources.arsc\`（\`bash\`/\`read_file\`）、\`SharedPreferences\` 键名。
- **native SO（关键，最易漏）**：若含 \`lib/*.so\` 且校验在 native，**必须**采到：
  - 目标函数**反编译代码**（\`ida_decompile\`：JNI 入口 + 它调用的 sub_* ）；
  - 函数**引用的常量表**（\`ida_list_globals\`（自动分页）+ \`ida_get_bytes\`，密钥/密文/S盒/VM字节码都在 .data/.rodata）；
  - 关键字符串（\`ida_find_strings\`：flag/key/nonce/salt）。
  - ⚠️ **只给代码不给常量表 = 数学上无解**：算法认得出，但 key/密文拿不到，算不出 flag。

**阶段② 定位算法（只定性，不急求 flag）**
- 在反编译代码里认出**算法特征**：TEA 魔数 \`0x9E3779B9\`、RC4 双 S 盒、AES S 盒、XOR 流、
  自定义查表/VM（跳转表 + 取指解释器）。写清：算法名 + 关键地址（函数/RVA）+ 输入输出形态。

**阶段③ 写求解脚本并本地验证**
- 用 \`run_python\` 实现还原，**正反双向**验证（反推 key 后，正向加密要能对回目标密文常量）。
- 需要爆破/约束/符号执行时用 Z3 / angr / Unicorn（见 ctf-reverse-tooling 技能）。
- 如果识别为**分组密码/自定义 S 盒 AES 变体/微指令 VM 加密**：**不要硬逆**——写出正向加密模拟器，
  用 \`enc(候选明文)==目标密文\` 验证（块密码双射，正演验证=反演且简单得多）；有格式/字典就正向枚举。
  符号求解一次只解 1 个块、S 盒用常量数组 Select；单脚本超时就拆成多个短脚本。
- **脚本必须真跑**，把输出贴出来；不要只给"我认为应该是"。
- ⚠️ **多候选密文（变种题陷阱）**：native so 里常有多组常量（如 C++ 静态初始化一个
  \`std::array<std::string,N>\`，或 .rodata 里多条 hex）。**不要取第一条就下结论**——要先确认
  **校验函数实际引用的是哪条**（看引用它的函数、或哪条与 key/nonce 同处一个初始化块）。
  工具会在本地复现后**自动枚举全部候选**并用 IDA xrefs 判定"被校验函数引用的那条"（自动裁决）；
  你应在证据里写明：用的密文地址/符号 + 引用它的函数名。若工具告警"未能判定权威"，再回 IDA 看。

**阶段④ 出结论**
- 有把握才给 flag；证据不足就明确写"待人工验证 + 还缺什么"，**不要猜**。

**阶段④' 多阶段题目（壳/多阶段 APK）——解出新文件就接力**
- 若解出/提取出一个**新的可执行文件**（脱壳后的 DEX、解密出的内嵌 APK/so/payload 等，写出到磁盘
  且能识别出 DEX/ELF/MZ 头），或发现当前样本只是壳/loader 而真逻辑在另一文件里，
  **直接调用 \`switch_to_next_stage\`**（path=新文件绝对路径, reason=判定理由, carried=要传下去的关键结论）。
  工具会关闭当前反编译进程、保留你的结论、以新文件重建上下文并自动继续。层数上限 3，同一文件勿重复接力。

**输出契约（必须遵守）：**
1. 得到 flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 必须附验证数据（工具会本地复现）：
   \`${VERIFY_CONTRACT}\`
3. 多个候选组合：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 回答最后输出 \`[EXPERIENCE]...[/EXPERIENCE]\`（每条一行，最多5条）
不要臆造工具结果；工具失败时换一条路径继续，不要重复同一失败写法。

**⚠️ 收工门槛（实测教训：上一轮 50 秒就收工、零验证数据，等于白跑）**
在给出最终回答前，自检以下三条，**任一不满足就不许收工，继续调用工具**：
1. 你**至少真正跑过一次**能产出 flag 的脚本（run_python/bash），并把真实输出贴出来；
   只"阅读代码后推断"不算解出。
2. 若已定位算法/密钥，必须给出 \`[VERIFY]\` 契约（哪怕 expected 只是 flag 前缀）；
   给不出说明你还没真正验证过，继续分析。
3. 若确实做不出来，必须写清**卡在哪一步**：
   - 缺什么数据（哪个函数/表/偏移没拿到）
   - 已排除哪些路线（算法×参数组合）
   - 下一步该试什么
   只写"未找到 flag"会被判为无效结论。`;

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

      // ── 多阶段接力（APK 版）：AI 请求切换新阶段文件 ──
      if (result.stageSwitch && result.stageSwitch.path) {
        addLog('info', `[阶段接力] 收到 AI 接力请求 → ${result.stageSwitch.path}`);
        const hr = await runStageHandoff(result.stageSwitch, result.text);
        if (hr.ok) return true;
        addLog('warning', '[阶段接力] 未切换（' + hr.note + '），按当前阶段正常收尾');
      }

      // 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      await finalizeSolve(result.text, { source: 'ai-deep' });

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
      `你是CTF逆向解题专家。请使用工具分析代码并找出flag。最多调用5次工具，找到flag后立即停止。当前文件: ${state.fileInfo.fileName}` + experienceSection()
    );

    if (result.success && result.text) {
      addLog('success', '========================================');
      addLog('success', '详细分析完成！');
      addLog('success', '========================================');

      state.lastAiText = result.text;
      addSolveNote('求解结果(详细)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      // 详细分析同样走验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags: dvf, flags: dflags } = await finalizeSolve(result.text, { source: 'ai-detail' });

      const resultMsg = `**🔍 详细分析结果**

**文件**: ${state.fileInfo.fileName}
**包名**: ${analysisData.packageName || '未知'}
${dvf.length ? `**Flag（✅已验证）**: \`${dvf[0].flag}\`` : (dflags.length ? `**Flag（⚠️未验证）**: \`${dflags[0]}\`` : '')}

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
  // ⚠️ IDA 刚连上时自动分析可能尚未完成 → list_functions 只返回 2~3 个函数
  //（Disguise 实测：初次采集只得 sub_413CB0/sub_413CD0/sub_414060 三个，导致后续
  //  "选主体函数/读常量表"全部落空）。函数数过少时等待重试，给 IDA 分析时间。
  try {
    // 插件 list_funcs 默认 count=100 → 必须分页拿全量（否则函数表残缺，
    // 函数选择/按地址读表/缺口计算全部建立在截断表上）。
    let funcsResult = await window.electronAPI.idaMcpCallPaged('list_functions', { queries: {} });
    let funcs = (funcsResult && Array.isArray(funcsResult.result)) ? funcsResult.result : [];
    for (let retry = 0; retry < 4 && funcs.length < 8; retry++) {
      addLog('info', `函数列表仅 ${funcs.length} 个（IDA 可能仍在自动分析），等待 5s 后重试…`);
      await new Promise(r => setTimeout(r, 5000));
      const r2 = await window.electronAPI.idaMcpCallPaged('list_functions', { queries: {} });
      const f2 = (r2 && Array.isArray(r2.result)) ? r2.result : [];
      if (f2.length > funcs.length) { funcs = f2; funcsResult = r2; }
    }
    // 落界校验：这些地址真的属于当前文件吗？
    // 实测（QuiZow）IDA 会话串台时返回的 100 个函数里有 62 个落在目标所有 section 之外，
    // 只校验"数组非空"就记 ✅，会让别人的库一路以成功状态进入提示词与证据落盘。
    if (funcs.length) {
      try {
        const im = await window.electronAPI.fileImageMap(state.currentFile);
        if (im && im.success && im.map) {
          const { kept, dropped } = filterFunctionsInImage(funcs, im.map);
          if (dropped.length) {
            addLog('warning', `[IDA] 越界地址 ${dropped.length}/${funcs.length} 个不在映像内`
              + `（ImageBase=0x${im.map.imageBase.toString(16)}, SizeOfImage=0x${im.map.sizeOfImage.toString(16)}），判定为串台，已剔除`);
            const sample = dropped.slice(0, 3).map(f => {
              const a = (f && (f.address != null ? f.address : f.addr)) || '?';
              return String(a);
            }).join(', ');
            addLog('warning', `[IDA] 越界样例: ${sample}`);
            funcs = kept;
          }
        }
      } catch (e) { /* 映像解析失败不阻塞，但也不再声称"地址已验证" */ }
    }

    if (funcsResult && funcsResult.success) {
      analysisData.functions = funcs;
      addLog('success', `✅ 已获取函数列表（${funcs.length} 个${funcsResult.paged ? '，分页' : ''}）`);

      // 识别关键函数（语义加权：加解密/编解码/校验/VM 派发等，避免漏掉 vm_operad 这类核心函数）
      if (funcs.length) {
        const keyFuncs = selectKeyFunctions(funcs, 10);
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
    // 强制通道：入口/对话框过程及其 1 跳 callee 先入队，**不占 6 个名额**
    let forced = [];
    try {
      forced = await collectForcedFuncs(analysisData.functions, window.electronAPI.idaMcpCall, 12);
      if (forced.length) addLog('info', `[采集] 强制加入入口/Dialog 邻接函数: ${forced.join(', ')}`);
    } catch (e) { addLog('warning', '[采集] 强制函数通道失败（不阻塞）: ' + e.message); }

    const picked = selectKeyFunctions(analysisData.functions, 6);
    const seenNames = new Set();
    const keyFuncs = [];
    for (const f of [...forced, ...picked]) {
      const n = String((f && f.name) || f || '');
      if (!n || seenNames.has(n)) continue;
      seenNames.add(n);
      keyFuncs.push(f);
    }
    // thunk 兜底（加壳/混淆 PE 实测）：若入选者多为 j_xxx 跳转桩（说明函数表被 ILT 噪声占满），
    // 追加"体积最大的 sub_* 主体函数"——真逻辑在这些无语义命名的函数里（Disguise：sub_415D00/sub_411401）。
    const nameOfF = f => String((f && f.name) || f || '');
    // ⚠️ IDA MCP 的 size 是 **hex 字符串**（"0x21b"），用 parseInt(v,10) 会得到 0 →
    // 所有函数都被误判为 thunk（size<=8），"按体积选主体"完全失效（Disguise 实测）。
    // 必须识别 0x 前缀并按 16 进制解析。
    const sizeOfF = f => {
      const raw = (f && (f.size ?? f.length));
      if (raw == null || raw === '') return -1;
      const s = String(raw).trim();
      const v = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10);
      return Number.isFinite(v) ? v : -1;
    };
    const pickedThunkCount = keyFuncs.filter(f => /^j_/i.test(nameOfF(f)) || (sizeOfF(f) >= 0 && sizeOfF(f) <= 12)).length;
    if (pickedThunkCount >= Math.ceil(keyFuncs.length / 2)) {
      // ⚠️ 不能只认 sub_*：not-baby-parallelism 的题目逻辑是普通命名（如 main/函数指针回调），
      // 用 sub_* 过滤会得到 0 个候选，AI 仍然拿不到主体。
      // 改为"所有非库函数按体积降序"——体积大 = 逻辑多，这是跨编译器的通用判据。
      const libNoise = /^(printf|scanf|malloc|calloc|realloc|free|memcpy|memmove|memset|strlen|strcmp|strcpy|strcat|puts|putchar|exit|abort|rand|srand|getopt|__|_IO_|_ZNS|_ZNSt|_ZSt)/;
      const bodyCands = analysisData.functions
        .filter(f => {
          const n = nameOfF(f);
          return n && !libNoise.test(n) && !/^j_/i.test(n) && sizeOfF(f) > 12;
        })
        .sort((a, b) => sizeOfF(b) - sizeOfF(a))
        .slice(0, 10)
        .map(nameOfF);
      const have = new Set(keyFuncs.map(nameOfF));
      const extra = bodyCands.filter(n => !have.has(n));
      addLog('info', `[采集] 入选函数多为 thunk 桩（${pickedThunkCount}/${keyFuncs.length}），追加 ${extra.length} 个体积最大的主体函数`);
      for (const n of extra) keyFuncs.push(n);
    }

    // 单函数上限 60000（"轮函数不截断"），同时受全局预算约束：
    // 6 个 30000 字符的函数各放宽 60000 会撑爆上下文，必须按入选顺序累加并降级。
    let funcBudgetLeft = MAX_TOTAL_FUNC_CHARS;
    let funcBudgetCompressed = 0;
    for (const func of keyFuncs) {
      try {
        const funcName = (func && typeof func === 'object') ? String(func.name || '') : String(func || '');
        if (!funcName || funcName === '[object Object]') continue;
        const funcResult = await window.electronAPI.idaMcpCall('decompile', { address: funcName });
        const rawCode = idaPickCode(funcResult && funcResult.result);
        if (rawCode) {
          let code = rawCode;
          if (rawCode.length > funcBudgetLeft) {
            // 超预算：降级为 head/tail 片段，且分配量不超过剩余预算（总长才能真的 ≤ 预算）
            const allot = Math.max(0, Math.min(3000, funcBudgetLeft));
            if (allot < 500) {
              // 预算耗尽：该函数完全进不了上下文，同样计入"被预算压缩"
              funcBudgetCompressed++;
              addLog('info', `[采集] ${funcName} 跳过（函数预算已用尽）`);
              continue;
            }
            code = buildFuncBody(funcName, rawCode, allot);
            funcBudgetCompressed++;
            addLog('info', `[采集] ${funcName} 超出函数预算，降级为 head/tail 片段（${allot} 字符）`);
          } else if (rawCode.length > MAX_SINGLE_FUNC_CHARS) {
            code = buildFuncBody(funcName, rawCode, MAX_SINGLE_FUNC_CHARS);
          }
          funcBudgetLeft -= code.length;
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
    if (funcBudgetCompressed) addLog('info', `[采集] 函数预算 ${MAX_TOTAL_FUNC_CHARS} 字符，压缩 ${funcBudgetCompressed} 个`);
  }

  // 5. 读取反编译里引用到的全局数据表
  //    VM 字节码 / 密文表 / S 盒 / 密钥常量通常放在全局数组里，只给代码 AI 无法还原。
  //    2.exe 的 src_（0x403040，114 个 int32）就是 VM 程序本体，缺它必解不出。
  //    ⚠️ 关键表常是 dword 数组（lane 布局），符号名未必是 global；旧实现只把 refs 与
  //    list_globals 的名字求交集，cnbragon 只命中 1 个 thunk。改为**按地址**收集。
  try {
    const im = await window.electronAPI.fileImageMap(state.currentFile);
    const imageMap = (im && im.success && im.map) ? im.map : null;
    let globals = [];
    try {
      // list_globals 只用于补名字（分页拿全量；插件默认 100 条）
      const gRes = await window.electronAPI.idaMcpCallPaged('list_globals', {});
      globals = (gRes && gRes.success && Array.isArray(gRes.result)) ? gRes.result : [];
    } catch (e) { /* 无 IDA 时按文本地址照常读 */ }
    const nameToAddr = new Map();
    for (const g of globals) {
      if (g && g.name && g.addr) nameToAddr.set(String(g.name), String(g.addr));
    }

    const texts = [analysisData.mainCode]
      .concat(analysisData.otherFunctions.map(f => f.code))
      .filter(Boolean);
    let regions = collectGlobalRegions(texts, imageMap, { resolver: (n) => nameToAddr.get(n) || '' });

    // 反向补充：list_globals 里名字/地址命中 refAddrs 的条目（refs 是 IDA 直接给出的地址）
    const refAddrs = idaCollectRefAddrs([
      { refs: analysisData.mainRefs },
      ...analysisData.otherFunctions.map(f => ({ refs: f.refs }))
    ]);
    const have = new Set(regions.map(r => r.addr.toLowerCase()));
    if (refAddrs.size) {
      const byAddr = globals
        .map(g => ({ addr: String((g && g.addr) || ''), name: String((g && g.name) || ''), val: parseInt((g && g.addr) || '', 16) }))
        .filter(g => Number.isFinite(g.val))
        .sort((a, b) => a.val - b.val);
      for (let i = 0; i < byAddr.length; i++) {
        const g = byAddr[i];
        if (!refAddrs.has(g.addr.toLowerCase()) || have.has(g.addr.toLowerCase())) continue;
        const next = byAddr[i + 1];
        let size = next ? next.val - g.val : 256;
        if (!(size > 0)) size = 256;
        else if (size > 65536) size = 65536;
        regions.push({ addr: g.addr, size, stride: 0, referrers: [g.name].filter(Boolean) });
        have.add(g.addr.toLowerCase());
      }
    }
    regions = regions.slice(0, 24);

    if (regions.length) {
      const bRes = await window.electronAPI.idaMcpCall('get_bytes', {
        regions: regions.map(w => ({ addr: w.addr, size: w.size }))
      });
      if (bRes && bRes.success && Array.isArray(bRes.result)) {
        analysisData.globals = bRes.result.map((r, i) => {
          const want = regions[i] || {};
          const hex = String((r && r.data) || '');
          const raw = hex.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
          // 渲染层没有 Node Buffer（实测：Buffer.from 在浏览器上下文 ReferenceError，
          // 整个全局数据表读取被 catch 吞掉 → 指纹扫描拿不到 S 盒/常量表）。
          const bytes = hexToUint8Array(raw);
          const stride = want.stride || (bytes.length ? probeStride(bytes, 0, bytes.length) : 0);
          return {
            name: (want.referrers && want.referrers[0]) || (r && r.addr) || 'global',
            addr: (r && r.addr) || want.addr || '',
            size: want.size || 0,
            stride,
            referrers: want.referrers || [],
            data: hex
          };
        });
        addLog('success', `✅ 已按地址读取 ${analysisData.globals.length} 个全局数据表`
          + `（stride/referrers 已标注）: ${analysisData.globals.map(g => g.name).join(', ')}`);
      }
    } else {
      addLog('info', '未发现需要读取的全局数据表');
    }
  } catch (e) {
    addLog('warning', '读取全局数据失败: ' + e.message);
  }

  // 5.5 可执行节缺口 + 续块（函数表没覆盖到的代码不能被当死代码）
  try {
    const im = await window.electronAPI.fileImageMap(state.currentFile);
    const imageMap = (im && im.success && im.map) ? im.map : null;
    const fnWithBodies = (analysisData.functions || []).map(f => {
      const name = String((f && f.name) || '');
      const body = name === analysisData.mainName ? analysisData.mainCode
        : (analysisData.otherFunctions.find(x => x.name === name) || {}).code;
      return Object.assign({}, f, body ? { code: body } : {});
    });
    const gapInfo = computeExecGaps(fnWithBodies, imageMap, {});
    analysisData.execGaps = gapInfo;
    addLog('info', gapInfo.log);

    const targets = [];
    for (const g of gapInfo.gaps.slice(0, 8)) targets.push({ addr: g.addr, source: 'gap' });
    for (const c of gapInfo.continuation.slice(0, 8)) targets.push({ addr: c.addr, source: 'jmp-target' });

    const blocks = [];
    let insnBudget = 400;
    for (const t of targets) {
      if (insnBudget <= 0) break;
      const n = Math.min(64, insnBudget);
      try {
        const d = await window.electronAPI.idaMcpCall('disasm', { addr: t.addr, max_instructions: n, offset: 0 });
        const text = (d && d.success) ? (typeof d.result === 'string' ? d.result : JSON.stringify(d.result)) : '';
        if (!text) continue;
        blocks.push(`### ${t.addr}（来源: ${t.source}）\n\`\`\`\n${text.slice(0, 4000)}\n\`\`\``);
        insnBudget -= n;
      } catch (e) { /* 单段反汇编失败不阻塞 */ }
    }
    analysisData.execFlowText = blocks.length
      ? `## 间接流/续块（不得当死代码）\n以下地址不在任何函数内，可能由间接跳转/VM 尾声到达；**不得**因为"不在函数表里"就当死代码或填充物。\n\n`
        + blocks.join('\n\n')
        + (gapInfo.continuation.length
          ? `\n\n⚠️ 续块标记（continuation-missing）：${gapInfo.continuation.map(c => `${c.from} → ${c.addr}`).join('、')}`
          : '')
      : '';
  } catch (e) {
    addLog('warning', '[缺口] 计算失败（不阻塞）: ' + e.message);
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

  // 阶段1.7：算法指纹扫描（代码层确定性识别）——直接读文件字节，不依赖 IDA 引用关系。
  // 实测教训：AI 每次都往 AES 猜、啃 VM handler 烧 500+ 秒，而二进制里本有确定性证据
  // （S 盒/FK/CK/轮结构）。这里先把"工具已识别的算法"摆到 AI 面前，强引导其走标准解密路线。
  let algHintText = '';
  try {
    const sc = await window.electronAPI.scanCryptoFingerprints(state.currentFile);
    // 存到全局状态：负面断言反证（runNegativeAssertionCheck）在别的作用域，只能读 state。
    state.lastAlgScan = (sc && sc.success) ? sc : null;
    if (sc && sc.success && Array.isArray(sc.summary) && sc.summary.length) {
      analysisData.algScan = sc;
      const lines = sc.summary.map(s =>
        `- 【${s.algo}】置信度 ${s.confidence}\n    证据：${s.evidence}\n    建议：${s.note}`);
      algHintText = `\n## ⚙️ 工具已确定性识别的算法指纹（读文件字节扫描得出，**优先采信**）\n${lines.join('\n')}\n`;
      // 载荷（下一层载体）命中 → 本层是 loader：必须"先提取下一层再分析它"，否则会误报 decoy 收工。
      // payloads 覆盖 PE/ELF/DEX 多格式 × 多编码（单字节/周期/滚动 XOR、Base64/Hex 文本等）；
      // 旧版只看 embeddedPE（仅 PE 子集），这里改为 payloads 并兼容 embeddedPE。
      // ⚠️ type==='table'（Base64/Base91 变表）是**算法数据**，不是可执行载荷：
      //    实测有两道题因此被误判成 loader，AI 放着 high 置信度的 AES 不逆、去 dump 不存在的 payload。
      const pl = ((Array.isArray(sc.payloads) && sc.payloads.length) ? sc.payloads
        : (Array.isArray(sc.embeddedPE) ? sc.embeddedPE : []))
        .filter(x => x && x.type !== 'table');
      if (pl.length) {
        const p0 = pl[0];
        const enc = p0.encode || {};
        const kindName = p0.type === 'pe' ? 'PE' : p0.type === 'elf' ? 'ELF' : p0.type === 'dex' ? 'DEX' : '载荷';
        const encDesc = enc.kind === 'none' ? '明文'
          : enc.kind === 'xor' ? `XOR 0x${(enc.key >>> 0).toString(16)}`
          : enc.kind === 'add' ? `ADD 0x${(enc.key >>> 0).toString(16)}`
          : enc.kind === 'periodic-xor' ? `${enc.period} 字节周期 XOR`
          : enc.kind === 'rolling-xor' ? '滚动 XOR'
          : enc.kind === 'rolling-add' ? '滚动 ADD'
          : enc.kind === 'base64' ? 'Base64 文本' : enc.kind === 'hex' ? 'Hex 文本' : enc.kind;
        algHintText += `\n### 🚫 硬性约束：本层是 loader，**禁止在本层下结论**\n`
          + `扫描器已在文件字节里**确定性定位**出一个编码存储的 ${kindName} 载荷（${encDesc}，见上"内嵌 ${kindName}"结论，含可直接运行的提取脚本）。\n`
          + `**第一步必须是把下一层提取出来**（按上面给的 offset/编码参数解码 → 写出文件 → 确认头部魔数正确）；\n`
          + `然后对**新文件**重新扫描算法指纹并分析。\n`
          + `**严禁**因为"在本层搜不到明文 MZ/ELF 头 / 找不到第二载体"就断定"真 flag 不在此文件"、或把编码后的载荷当成数据填充物——\n`
          + `实测教训：那样会直接收工、报出第一层的诱饵（如 "This is a fake flag"）当成答案。\n`;
        addLog('success', `[算法扫描] 载荷命中：${kindName} @0x${p0.offset.toString(16)} stride=${enc.stride || 1} ${encDesc}（本层为 loader）`);
      }
      if (sc.highEntropy && sc.highEntropy.length) {
        algHintText += `\n### 疑似 key/密文常量（高熵块，供参考）\n${sc.highEntropy.map(h => `- @${h.offset} (${h.len}B) ${h.hex}`).join('\n')}\n`;
      }
      addLog('success', `[算法扫描] ${sc.summary.map(s => s.algo + '(' + s.confidence + ')').join(', ')}`);
      try { await caseAddEvidence('crypto_scan', '算法指纹扫描结果', JSON.stringify(sc, null, 2), 'json'); } catch (e) {}
    } else {
      // 零指纹只说明"扫描器没认出来"，不说明"一定是壳"。
      // 实测（CrackMe2）真实算法是 MD5、K 表就在本层、没有任何内嵌载荷，
      // 旧文案却断言"算法在下一层"，把 AI 推向了错误方向。
      const scAny = state.lastAlgScan || {};
      const hasPayloadNow = (Array.isArray(scAny.payloads) && scAny.payloads.length > 0)
        || (Array.isArray(scAny.embeddedPE) && scAny.embeddedPE.length > 0);
      if (hasPayloadNow) {
        addLog('info', '[算法扫描] 未发现算法指纹，但本层存在内嵌载荷 → 先提取下一层');
        algHintText = `\n## ⚙️ 算法指纹扫描：**未发现任何算法常量**\n`
          + `本层**确有内嵌载荷**（见下方载荷列表）：算法可能在下一层。请先提取，再对**新文件**重跑扫描。\n`;
      } else {
        addLog('info', '[算法扫描] 未发现算法指纹（本层无内嵌载荷，优先在本层找自实现算法/轮常量）');
        algHintText = `\n## ⚙️ 算法指纹扫描：**未发现任何算法常量**\n`
          + `这不等于"是壳"：可能是**自实现算法**、**常量布局非常规**（表被拆分/加花、按非标准步长或 lane 交错存放）、`
          + `或算法写在其它函数里。本层**没有内嵌载荷**。\n`
          + `建议优先在本层找逐字节比较/位运算循环与内联常量表；不要仅凭"扫描无命中"就断定存在下一层。\n`;
      }
    }
  } catch (e) { addLog('warning', '[算法扫描] 失败（不阻塞）: ' + e.message); }

  // 阶段1.8（Phase 4.1）：工具自动提取载荷并接力——不再等 AI 主动喊 switch_to_next_stage。
  // 理由：多阶段题的"提取下一层"是确定性操作（offset/编码参数都已由扫描给出），
  // 让 AI 花 5~10 次工具调用去写脚本纯属浪费；工具直接做，失败才交回 AI。
  //
  // ⚠️ 判据必须区分两类 summary（实测踩坑）：
  //   · **载荷定位结论**（"内嵌 PE/ELF/DEX（…已定位）"）——这是"我在哪"，**不是**"本层算法"；
  //   · **算法指纹结论**（SM4/AES/自定义分组密码/TEA…）——这是"本层在做什么"。
  //   旧判据用 `confidence==='high'` 统一判断，导致"内嵌 PE/high"被当成算法指纹，
  //   于是在**每一道 loader 题**上都打印"本层同时命中了算法指纹，不自动接力"——整个自动接力形同虚设。
  const PAYLOAD_SUMMARY_RE = /内嵌\s*(PE|ELF|DEX|载荷)|编码存储/i;
  try {
    const sc0 = analysisData.algScan;
    const sums = (sc0 && Array.isArray(sc0.summary)) ? sc0.summary : [];
    const algoSignals = sums.filter(s => !PAYLOAD_SUMMARY_RE.test(String(s.algo || ''))
      && (s.confidence === 'high' || s.confidence === 'medium'));
    const hasStrongAlgo = algoSignals.length > 0;
    const hasPayload = !!(sc0 && (((sc0.payloads || []).filter(x => x && x.type !== 'table')).length || (sc0.embeddedPE || []).length));
    if (hasPayload && !hasStrongAlgo && state.stageDepth < STAGE_MAX_DEPTH) {
      // ⚠️ 不能加 `!state._inStageHandoff`：重新接力的新阶段**也是**在 handoff 上下文里跑的，
      //    加了这个条件等于"多层题只能自动剥一层"（实测 Disguise 三层结构会停在 stage2）。
      //    防循环靠 runStageHandoff 里的 stageVisitedMd5 去重 + STAGE_MAX_DEPTH 上限，不靠这个标志。
      const ah = await tryAutoHandoffByPayload(state.currentFile, sc0);
      if (ah && ah.took) {
        // 接力内部已递归跑完新阶段的完整求解，直接结束本层
        addLog('success', `[自动接力] 已切换并完成下一阶段分析（${ah.path}）`);
        return;
      }
    } else if (hasPayload && hasStrongAlgo) {
      // 本层既有载荷又有真实算法：可能是"带上层数据的多阶段"或"算法就在壳里"，交 AI 判断
      addLog('info', `[自动接力] 本层同时命中算法指纹（${algoSignals.map(s => s.algo).join(',')}），判定为主逻辑层，不自动接力`);
    }
  } catch (e) { addLog('warning', '[自动接力] 失败（不阻塞，交回 AI）: ' + e.message); }

  // 阶段1.9（自主求解）：若扫描器已生成"SM4 变体全组合解密脚本"，**工具直接跑它**。
  // 为什么：实测 Disguise stage2，AI 拿到全部常量后仍在字节序/块内排列上耗了 300+ 秒、59 次工具调用
  // 仍未解出；而工具生成的脚本枚举全部组合只需 ~2 秒。这类"有限组合穷举"就该由工具做。
  try {
    const sc1 = analysisData.algScan;
    const caList = ((sc1 && sc1.fingerprints) || []).map(f => f.constantAnalysis).filter(Boolean);
    const ca = caList.find(c => c && c.decryptScript && c.decryptScript.script);
    if (ca) {
      addLog('info', '[自主求解] 检测到 SM4 变体结构，工具自动运行全组合解密脚本…');
      const baseDir = state.caseDir || (await getScriptsDir());
      const scriptsBase = state.caseDir ? `${state.caseDir}/scripts` : baseDir;
      const pyPath = `${scriptsBase}/auto_sm4_variant.py`;
      try { await window.electronAPI.ensureDir(scriptsBase); } catch (e) {}
      await window.electronAPI.writeFile(pyPath, ca.decryptScript.script);
      const rr = await window.electronAPI.runToolArgs(['python', pyPath, state.currentFile]);
      const outTxt = ((rr.stdout || '') + (rr.stderr ? '\n' + rr.stderr : '')).trim();
      if (outTxt) await caseAddEvidence('auto_decrypt', '自动解密脚本输出', outTxt.slice(0, 20000), 'log');
      const fm = outTxt.match(/(?:FLAG:\s*)(\S[^\r\n]*)/);
      if (fm && fm[1]) {
        const flag = fm[1].trim();
        addLog('success', `[自主求解] ✅ 自动脚本解出 flag：${flag}`);
        recordFlag(flag, 'auto-sm4-script', true);
        addSolveNote('自主求解', `工具自动生成的解密脚本命中：${flag}`);
        addSystemMessage(`**🎯 工具自动解出 flag**\n\n\`${flag}\`\n\n（由工具生成的 SM4 变体全组合枚举脚本直接跑出，未经 AI 猜测）\n\n\`\`\`\n${outTxt.slice(-1500)}\n\`\`\``);
        return;   // 已解出，无需再烧 AI 预算
      }
      // 未命中：必须明确"这不等于算法认错"——脚本只覆盖 SM4 骨架，换骨架就不适用。
      // 同时把"已尝试过什么"记进上下文，避免 AI 重复跑同一套枚举（浪费预算）。
      addLog('info', `[自主求解] SM4 骨架脚本未命中（**不代表算法认错**），交回 AI。输出尾部：${outTxt.slice(-300).replace(/\s+/g, ' ')}`);
      addSolveNote('自主求解', 'SM4 骨架脚本未命中 → 需按实际轮结构（可能是 AES/其它）另写实现');
      state._autoSm4Tried = {
        script: pyPath,
        ctCandidates: (ca.decryptScript.ciphertextCandidates || []).map(x => x.offset),
        summary: outTxt.slice(-500),
      };
    }
  } catch (e) { addLog('warning', '[自主求解] 自动脚本执行失败（不阻塞）: ' + e.message); }

  // 阶段2：AI初步分析
  // ⚠️ 若本层已确认是 loader（有载荷但无算法），**跳过**"静态一次性分析（禁止调用工具）"阶段：
  //    该阶段的系统提示明确禁止调工具，AI 只能输出"需要更多数据/请用户提供 stage2"——
  //    实测（Disguise 2026-10-17）这正是它给出"请用户提供 stage2"白烧一轮的原因。
  //    这种题的下一步是**执行**（提取下一层），直接进 Tool-Use 深挖。
  {
    const scL = analysisData.algScan;
    const sumsL = (scL && Array.isArray(scL.summary)) ? scL.summary : [];
    const PAYLOAD_RE_L = /内嵌\s*(PE|ELF|DEX|载荷)|编码存储/i;
    const hasAlgoL = sumsL.some(s => !PAYLOAD_RE_L.test(String(s.algo || ''))
      && (s.confidence === 'high' || s.confidence === 'medium'));
    const hasPayloadL = !!(scL && (((scL.payloads || []).filter(x => x && x.type !== 'table')).length || (scL.embeddedPE || []).length));
    if (hasPayloadL && !hasAlgoL) {
      addLog('info', '[阶段2] 本层是 loader（有载荷、无算法）→ 跳过静态分析，直接进入 Tool-Use 深挖（可执行提取）');
      try { await toolUseDeepSolveBinary(analysisData, fileType); } catch (e) {
        addLog('warning', '[阶段2] Tool-Use 深挖异常（不阻塞）: ' + e.message);
      }
      return;
    }
  }
  addLog('info', '========================================');
  addLog('info', '[阶段2] AI初步分析');
  addLog('info', '========================================');
  addLog('info', '准备构建分析提示...');

  try {

    // 构建其他函数的代码（采集阶段已按 buildFuncBody 截断/预算；此处不再二次硬切，
    // 否则"省略"标记后面的 tail 会被再次切掉，且偏移区间与实际内容不再对应）
    let otherFuncsText = '';
    if (analysisData.otherFunctions && analysisData.otherFunctions.length > 0) {
      otherFuncsText = '\n## 其他关键函数\n';
      for (const func of analysisData.otherFunctions) {
        otherFuncsText += `\n### ${func.name}\n${func.code ? String(func.code) : '暂无'}\n`;
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

    // 安全地转换字符串列表（find_regex -> {n,matches:[{addr,string}]}，渲染成 addr string 列表）
    let stringsText = '暂无';
    try {
      if (analysisData.strings) {
        const s = analysisData.strings;
        if (s && Array.isArray(s.matches)) {
          stringsText = s.matches.map(m => `${(m && m.addr) || '?'}  ${(m && (m.string || m.text)) || ''}`).join('\n').substring(0, 2000);
        } else if (Array.isArray(s)) {
          stringsText = s.map(m => (m && (m.string || m.text)) ? `${(m && m.addr) || '?'}  ${m.string || m.text}` : String(m)).join('\n').substring(0, 2000);
        } else {
          stringsText = JSON.stringify(s).substring(0, 2000);
        }
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

    // ── 花指令主动探测（关键：不能用词匹配，必须从二进制本身量测）──
    // 教训（Matr1x 实测）：prefetchKnowledge 的 haystack 是反编译文本，
    // 其中永远不会出现"花指令 / sp-analysis"这类 IDA 界面状态词，
    // 所以靠 POOL/FEATURES 词表永远命中不了 → AI 从不知道有 junk_repair 这个工具。
    // 现在改成：直接扫二进制，量"跳转目标非对齐"数量，命中就强制注入知识库 + 工具指引。
    let junkProbe = null, junkSection = '';
    try {
      if (window.electronAPI && window.electronAPI.junkProbe && state.currentFile) {
        const jp = await window.electronAPI.junkProbe(state.currentFile);
        if (jp && jp.success && jp.probed) {
          junkProbe = jp;
          const featBits = Object.entries(jp.features || {}).filter(([k, v]) => v && !/^EXCL_/.test(k));
          addLog(jp.suspicious ? 'warning' : 'info',
            `[花指令探测] 跳转目标非对齐 ${jp.badTargets}/${jp.insnCount}（${jp.badRatio}%）` +
            (featBits.length ? ' 特征: ' + featBits.map(([k, v]) => `${k}=${v}`).join(', ') : '') +
            (jp.suspicious ? '  ⚠ 高度可疑' : ''));
          if (jp.suspicious) {
            junkSection = `
## ⚠ 花指令检测：本题高度可疑（必须处理）

工具已对二进制本身做完静态量测（**不是**靠反编译文本猜）：

| 指标 | 值 |
|---|---|
| 代码区 | [0x${jp.start.toString(16)}, 0x${jp.end.toString(16)}) = ${jp.size} 字节 |
| 解码指令数 | ${jp.insnCount} |
| **跳转目标不落在指令边界上** | **${jp.badTargets}**（占 ${jp.badRatio}%） |
| 不可解码字节 | ${jp.undecodable} |
| 可自动修补 | ${jp.patchable} 处 |
| 仅报告（需人工） | ${jp.reportOnly} 处 |
${featBits.length ? '| 命中的花指令特征 | ' + featBits.map(([k, v]) => `${k}×${v}`).join('、') + ' |' : ''}

**这意味着**：IDA 当前的指令边界是错的，你看到的反编译结果（含 push ebp/mov ebp,esp 之后的
一切）都可能错位。**不要**基于当前反编译结果推算法，那样会得到错乱的表达式。

## 🚫 硬性禁令（违反会得到错误答案）

1. **禁止自己写脚本 nop 花指令**。实测：手工按"看起来像垃圾"的区间 nop
   会让后续指令重新错位（不可解码 4→7、覆盖率不升反降）。
   正确做法是只 nop **跳转指令本身**（等长 NOP，字节偏移不变）—— 这正是 junk_repair 做的事。
2. **禁止在调用 junk_repair 之前下任何算法结论**。当前反编译文本本身是坏的：
   它会把 \`mov eax, imm32\` 的立即数当成独立指令、把常量表达式拆错，
   任何基于它的"算法识别"都会得到假结论。
3. **禁止调用 ida_dbg / 动态调试来"绕过"** —— 动态调试是修完之后用来验证的手段，
   不是替代静态修复的捷径（目标是 32 位 ELF，本机调试器不兼容）。

## ✅ 必须按此顺序（前两步未完成不得进入分析）

\`\`\`
步骤 1（必做）：junk_repair({ path: "${state.currentFile}", dryRun: true })
              → 看特征清单（11 类）、每条的证据、可修补数

步骤 2（必做）：junk_repair({ path: "${state.currentFile}" })
              → 生成 ${state.currentFile.replace(/\.[^.]*$/, '')}_repaired 文件（只 nop 跳转本身，字节偏移不变）

步骤 3（必做）：ida_open_file({ path: "<步骤2 输出的 _repaired 路径>", new_database: true })
              → 让 IDA 在新实例里重新分析修复后的二进制。**这一步不能跳**：
                当前 IDB 是按错位字节流建的，不重开就永远是坏伪代码。

步骤 4：在**新实例**上重新做：ida_list_functions → ida_decompile
        → 这时再推算法（矩阵/轮函数/常量表都会清晰可读）

⚠ **怎么判读修补效果（重要，别被百分比骗）**：
修补后**函数数会变多**（原本被花指令切碎的函数被重新连成完整函数）。
此时"反编译成功率"这类**百分比反而可能下降**，因为分母里多了原本根本识别不出来的复杂函数。
实测 Matr1x：函数 54→90、可反编译 35→50，但成功率 87.5%→65.8%——**这不是变差**。
**该看的是"能反编译出可读伪代码的函数绝对数"是否增加，以及 junk_repair 返回的
「非对齐跳转下降百分比」**。绝不要因为成功率下降就说"修补有害"然后回去自己 nop。

步骤 5（可选）：若仍有函数反编译失败，junk_scan({ path, mode: "boundary" })
              → 看不可达区间与强制对齐点
\`\`\`

**为什么步骤 2 必须由 junk_repair 做，而不是你自己写脚本**：
花指令的判据是"跳转目标落在指令边界之外"，只有重跑解码模型才能定位；
凭肉眼挑"看起来像垃圾"的字节段去 nop，会把跳转目标本身也清掉，后续指令重新错位。
junk_repair 只把**跳转指令那 2/5 个字节**换成等长 NOP——跳转消失了、目标处的指令保持原样，
所以字节偏移和可执行语义都不变（实测修补后程序仍能正常运行、输出不变）。
`;
          }
        }
      }
    } catch (e) { addLog('warning', '[花指令探测] 失败（不阻塞）: ' + e.message); }

    // 自动预取：本题固定清单禁止调工具，故先按已采集代码/字符串检索知识库并内联攻略
    // 花指令命中时把"花指令"关键词追加进检索词（否则 haystack 里没有这个词）
    const prefetchExtra = junkProbe && junkProbe.suspicious ? ['花指令', 'junk code', '反编译失败'] : [];
    const knowledge = await prefetchKnowledge(
      [functionsText, stringsText, mainCodeText, otherFuncsText, globalsText].join('\n'),
      fileType, prefetchExtra);

    const analysisPrompt = `我正在分析一个CTF ${fileType}题目。

文件路径：${state.currentFile}
${algHintText}${junkSection}
以下是通过IDA MCP获取的分析数据：

## 函数列表
${functionsText}

## 关键字符串
${stringsText}

## 入口函数（${analysisData.mainName || 'main'}）反编译代码
${mainCodeText}
${otherFuncsText}
${globalsText}
${knowledge}

请直接分析上面的代码，找出：
1. 加密算法是什么
2. flag的生成或验证逻辑
3. 直接给出flag

${junkSection ? `**本段允许（且强烈建议）调用工具**：已检测到花指令，先用 junk_repair 修复二进制再分析。
修复前基于错位反编译推算法，只会得到错乱的表达式。` : '注意：不要调用任何工具，直接基于上面的代码分析。'}

**输出契约（必须遵守）：**
1. 得到 flag 时：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 若能给出算法+密钥+密文，必须附验证数据（工具会本地复现）：
   \`${VERIFY_CONTRACT}\`
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
      `你是CTF逆向解题专家。请直接分析代码并给出flag。不要调用任何工具，直接基于提供的代码分析。\n解题学习闭环（强制）：回答最后必须输出 [EXPERIENCE]每条一行，格式"题型特征→关键套路/踩过的坑→下次怎么做"，最多5条、每条200字内[/EXPERIENCE]（确无新收获则写"无新增经验"），工具会自动写入经验库，下次同类题优先复用、避免重复踩坑。` + experienceSection()
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

      // 验证闭环 + 失败时本地枚举兜底 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags, flags } = await finalizeSolve(result.text, { source: 'ai' });

      const resultMsg = `**🎯 自动求解结果**

**文件**: ${state.fileInfo.fileName}
**类型**: ${fileType}
${verifiedFlags.length ? `**Flag（✅已验证）**: \`${verifiedFlags[0].flag}\`` : (flags.length ? `**Flag（⚠️未验证）**: \`${flags[0]}\`` : '')}

${result.text}`;

      addSystemMessage(resultMsg);

      // 阶段2.5（二进制）：静态一次性分析未出已验证 flag 时，进入 Tool-Use 深挖
      // （与 APK 流程对齐：让 AI 自主调 ida_decompile/find_strings/get_xrefs/run_python 继续求解）。
      const stillNoVerified = !((state.findings ? state.findings.flags : []) || []).some(f => f.verified);
      if (stillNoVerified) {
        await toolUseDeepSolveBinary(analysisData, fileType);
      }
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

// PE/ELF 的 Tool-Use 深挖（与 APK 的 toolUseDeepSolve 对齐）：
// 静态一次性分析未出已验证 flag 时，把 IDA MCP / run_python 等工具交给 AI 自主驱动，
// 让它在"收集→定位→写脚本→验证"里继续推进，而不是卡住即止。
async function toolUseDeepSolveBinary(analysisData, fileType) {
  addLog('info', '========================================');
  addLog('info', '[阶段2.5] Tool-Use 深度求解（AI 自主调用 IDA/脚本）');
  addLog('info', '========================================');

  const fnSummary = analysisData.functions
    ? (typeof analysisData.functions === 'string' ? analysisData.functions : JSON.stringify(analysisData.functions)).slice(0, 4000)
    : '（未获取）';
  // 平台手包伴生文件（flag.out/input.bin/README 等）：AI 的 run_python/bash 可直接用绝对路径访问。
  // 多文件题优化（not-baby-parallelism 四轮实测）：文本类伴生文件**内容直接内联**进提示词，
  // 省掉 AI 每轮"重新发现+read_file+凭记忆复述"的重复劳动（此前同一文件被推演 5 遍）。
  const sideFiles = (Array.isArray(state._platformFiles) ? state._platformFiles : [])
    .filter(p => String(p) !== String(state.currentFile));
  const TEXT_EXT = /\.(txt|out|md|json|log|csv|py|c|cpp|h|js|html|xml|yaml|yml|ini|cfg)$/i;
  let sideFilesBlock = '';
  if (sideFiles.length) {
    const parts = [];
    const inlined = [];
    for (const p of sideFiles) {
      let inlinedThis = false;
      try {
        const st = await window.electronAPI.getFileInfo(p).catch(() => null);
        const sz = st && st.success ? st.size : 0;
        if (sz <= 8192 && (TEXT_EXT.test(p) || sz === 0)) {
          const rf = await window.electronAPI.readFile(p);
          if (rf && rf.success) {
            parts.push(`### ${p}（内容已内联）\n\`\`\`\n${String(rf.content).slice(0, 6000)}\n\`\`\``);
            inlined.push(p.split('\\').pop());
            inlinedThis = true;
          }
        }
      } catch (e) { /* 读失败按未内联处理 */ }
      if (!inlinedThis) parts.push(`- ${p}（二进制/大文件，用 read_file 或 run_python 处理）`);
    }
    sideFilesBlock = `\n## 同包伴生文件（${sideFiles.length} 个${inlined.length ? `，其中 ${inlined.length} 个已内联全文` : ''}）\n${parts.join('\n')}\n⚠️ 输入样例/输出样例/说明文档往往就是解题钥匙——上面对象已给出，**不要凭记忆推演，直接用**。\n`;
  }
  // 平台题目描述（含官方用法说明，如 "Run with pppp -n ..."）：此前被丢弃，AI 每轮都在猜参数语义
  //
  // 额外：描述里常直接规定 flag 的**形态**（"提取完整邮箱即为 flag"、"flag 是 32 位 md5"、
  // "答案为 base64 解码后的字符串"）。这类句子是最高价值的检索目标——实测（相册）题目明确说
  // "提取完整邮箱即为 flag"，AI 却只拿 flag{test} 去试 UI，从未在二进制里搜邮箱正则。
  // 这里把描述里能识别的形态抽成清单，要求 AI 按该形态去搜。
  const descRaw = String(state._platformChallengeDesc || '');
  const shapeRules = [
    [/邮箱|e-?mail/i, '邮箱地址 → 在字符串/常量里搜 `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}`，包成 flag{邮箱}'],
    [/md5|32\s*位/i, 'MD5/32 位十六进制 → 搜 32 位 hex 串，或对候选明文做 md5'],
    [/base64/i, 'Base64 → 对可疑串做 base64 解码（注意自定义字符表）'],
    [/二维码|qr/i, '二维码 → 从图片/资源里解码 QR'],
    [/十六进制|hex/i, '十六进制串 → 尝试 hex 解码'],
    [/异或|xor/i, 'XOR → 找单字节/循环 key 做反演'],
    [/手机号|电话/i, '手机号 → 搜 1[3-9]\\d{9} 形态'],
    [/邮箱|account|账号/i, '账号类 → 搜资源文件/字符串里的账号字段'],
  ];
  const shapes = [...new Set(shapeRules.filter(([re]) => re.test(descRaw)).map(([, s]) => s))];
  // 包装指令：题面明确要求"包成 xxx{...}"时，把模板记下来。
  // 实测（CrackMe3）：「请包上 flag{} 提交」这句话存在，但旧的 8 条 shapeRules
  // 只认数据形态（邮箱/md5/base64…），完全匹配不到"包装指令"，
  // 于是算出的 771535 因不是 flag{...} 形态被静默丢弃。
  const wrapDirective = parseWrapDirective(descRaw);
  if (wrapDirective) {
    state._platformWrapTemplate = wrapDirective.template;
    addLog('info', `[平台] 检测到包装指令 → ${wrapDirective.template}（依据：${wrapDirective.evidence.slice(0, 40)}）`);
  }
  const wrapHint = wrapDirective
    ? `\n### 🎯 题面规定了答案的外壳——最终答案必须按此包装\n`
      + `模板：\`${wrapDirective.template}\`（把裸值代入 %s，例如 ${applyWrap('你的结果', wrapDirective.template)}）\n`
      + `要求：先求出**裸值**（口令/序列号/字符串），再用该模板包装后提交；`
      + `不要因为"它看起来不像 flag"就丢弃一个已复现成功的值。\n`
    : '';
  const platDesc = state._platformChallengeDesc
    ? `\n## 题目描述（平台官方，含运行用法）\n${String(state._platformChallengeDesc).slice(0, 2000)}\n`
      + wrapHint
      + (shapes.length
        ? `\n### ⚠️ 描述里规定了 flag 的形态——按此定向检索，不要只猜常见 flag 格式\n${shapes.map(s => '- ' + s).join('\n')}\n`
          + '提示：先在全文件/资源/字符串里按上述形态**正则搜索**（用 run_python 直接读字节扫），\n'
          + '找到候选后再验证它是否能被程序逻辑复现；不要先假定 flag 是 `flag{...}` 形态去试。\n'
        : '')
    : '';
  // 成长闭环③：本题历史失败档案注入——已排除的路先摆出来，AI 优先换路而非重蹈覆辙
  const failHint = state._platformChallenge ? await failureHintSection(state._platformChallenge.name) : '';
  // Phase 3.3：本题**已排除的候选组合**（来自上一轮本地枚举的失败归因）——避免重复烧预算
  let excludedHint = '';
  try {
    const ex = await loadExcludedPaths();
    if (ex) {
      excludedHint = `\n## ⛔ 本题已排除的候选（上一轮本地枚举实测失败，**不要再重复尝试**）\n${ex}\n`
        + `若仍要重试其中某条，必须先说明它与上次的本质差异（否则纯属浪费预算）。\n`;
    }
  } catch (e) { /* 忽略 */ }
  // 多阶段接力：上一阶段的结论摘要（壳/packer 题的 stage1 发现）注入本轮提示词
  const stageBlock = state.stageContext
    ? `\n## ⚙️ 前序阶段上下文（本题是多阶段题目，第 ${state.stageDepth} 层）\n${String(state.stageContext).slice(0, 4000)}\n⚠️ 上面的结论来自上一层文件（已分析完），当前文件是它解出的下一阶段。请**在已有结论基础上继续**，不要重复上一层的工作。\n`
    : '';
  // 算法指纹扫描（若采集阶段未跑或未存，这里补一次）——强引导 AI 走标准解密路线
  let algHint = '';
  try {
    let sc = analysisData && analysisData.algScan;
    if (!sc && state.currentFile) sc = await window.electronAPI.scanCryptoFingerprints(state.currentFile);
    if (sc && sc.success) state.lastAlgScan = sc;   // 供跨作用域的反证使用
    if (sc && sc.success && Array.isArray(sc.summary) && sc.summary.length) {
      const lines = sc.summary.map(s => `- 【${s.algo}】置信度 ${s.confidence}｜证据：${s.evidence}｜建议：${s.note}`);
      // 硬约束触发：high 置信度判定，或发现了 256 项双射 S 盒（= 确定存在分组密码，只是常量被改）
      // 载荷（下一层载体）命中：payloads 覆盖 PE/ELF/DEX；兼容旧 embeddedPE
      const plDeep = ((Array.isArray(sc.payloads) && sc.payloads.length) ? sc.payloads
        : (Array.isArray(sc.embeddedPE) ? sc.embeddedPE : []))
        .filter(x => x && x.type !== 'table');   // 编码表是算法数据，不是"下一层载荷"
      const hasEmbedPE = plDeep.length > 0;
      const hardTrigger = sc.summary.some(s => s.confidence === 'high' || /自定义分组密码/.test(s.algo));
      // 三态（勿合并，否则低置信度命中也会被套上"必须先走标准框架"的强约束）：
      //   载荷命中 → 本层是 loader，先提取下一层
      //   hard 判定 → 必须先走标准解密框架
      //   仅低置信度 → 不加硬约束（证据不足，避免误导）
      let constraint = '';
      if (hasEmbedPE) {
        const p0 = plDeep[0], enc = p0.encode || {};
        const kindName = p0.type === 'pe' ? 'PE' : p0.type === 'elf' ? 'ELF' : p0.type === 'dex' ? 'DEX' : '载荷';
        const encDesc = enc.kind === 'none' ? '明文' : enc.kind === 'xor' ? `XOR 0x${(enc.key >>> 0).toString(16)}`
          : enc.kind === 'add' ? `ADD 0x${(enc.key >>> 0).toString(16)}`
          : enc.kind === 'periodic-xor' ? `${enc.period} 字节周期 XOR`
          : enc.kind === 'rolling-xor' ? '滚动 XOR' : enc.kind === 'rolling-add' ? '滚动 ADD'
          : enc.kind === 'base64' ? 'Base64 文本' : enc.kind === 'hex' ? 'Hex 文本' : enc.kind;
        constraint = `**🚫 最高优先级：本层是 loader/壳，下一层已在上面给出（含提取脚本）**
扫描器已在文件字节里**确定性定位**出一个编码存储的 ${kindName} 载荷（${encDesc}，@0x${p0.offset.toString(16)}）。**首要动作**就是按上面的脚本把它提取出来
（解码 → 写出文件 → 确认头部魔数正确），然后对**新文件**重新扫描算法并分析。
**禁止**：因为本层搜不到明文 MZ/ELF 头/找不到第二载体，就宣称"真 flag 不在此文件"或把编码载荷当填充物——
实测那样会把第一层诱饵（如 "This is a fake flag"）当成答案收工。
多阶段题必须 \`switch_to_next_stage\` 接力到提取出的新文件，而不是在当前层硬啃。\n`;
      } else if (hardTrigger) {
        constraint = `**⚠️ 硬性顺序约束**：上面存在 **high 置信度算法判定**，或**已确认一个 256 项双射 S 盒**（= 该程序一定含分组密码，只是常量被改）。
→ **必须先用对应算法的标准解密框架完成验证**（SM4：32 轮 + 轮密钥逆序 rk[31-i] + 块内字节反序 [3][2][1][0]，常量换成题目表；
   AES/自定义：按 SubBytes/ShiftRows/MixColumns 结构照抄）。\n`
          + `只有在标准路线确实全部失败（并说明尝试了什么、报错是什么）之后，**才允许**进入"逐条 opcode 手撕 VM"的路线。
**禁止无视本判定直接开始啃 VM 字节码或写通用 VM 解释器**（实测：那样会烧掉 500+ 秒仍无结果）。\n`;
      }
      algHint = `\n## ⚙️ 工具已确定性识别的算法指纹（读文件字节扫描，**优先采信**）
${lines.join('\n')}
${constraint}`;
      addLog('info', `[算法扫描] 注入深度求解提示：${sc.summary.map(s => s.algo).join(', ')}`);
    } else if (sc && sc.success) {
      // 零指纹只说明"扫描器没认出来"。是否有下一层，要看**有没有内嵌载荷**，而不是看有没有常量。
      const scZero = state.lastAlgScan || sc || {};
      const hasPayloadZero = (Array.isArray(scZero.payloads) && scZero.payloads.length > 0)
        || (Array.isArray(scZero.embeddedPE) && scZero.embeddedPE.length > 0);
      if (hasPayloadZero) {
        algHint = `\n## ⚙️ 工具已确定性扫描算法指纹：**本层未发现任何算法常量，但本层有内嵌载荷**
含义：算法可能在载荷解出的下一层。
**下一步**：按载荷列表把下一层 dump 出来，对**新文件**重新扫描；不要在本层反复找不存在的加解密逻辑。\n`;
        addLog('info', '[算法扫描] 本层零指纹但有载荷 → 提示 AI 先提取下一层');
      } else {
        algHint = `\n## ⚙️ 工具已确定性扫描算法指纹：**本层未发现任何算法常量**
这不等于"本层是壳"。真实原因可能是：
① **自实现算法**（S 盒被换成自生成表、或根本不用 S 盒）；
② **使用非常规常量布局**（例如 K 表被拆分/加花、只有轮常量没有 S 盒/IV，或表项按非标准步长交错存放）；
③ 算法写在别的函数/别的模块里。
**本层没有内嵌载荷**，因此"去下一层找"这条路不成立。
**下一步**：优先在本层找逐字节比较、位运算循环、内联常量表；用 \`ida_get_bytes\` 直接读可疑区域自查。
只有在确实找到"释放/解密下一层"的代码后，才去 dump 新文件。\n`;
        addLog('info', '[算法扫描] 本层零指纹且无载荷 → 提示 AI 在本层找自实现算法/轮常量');
      }
    }
  } catch (e) { /* 扫描失败不阻塞 */ }

  // SMC 特征 + 摘要目标存在性（只读文件字节）。两者都必须给**双向出口**：
  //   · 有 W+X 节 ≠ 必须动态调试（CrackMe2 的 .WProtec 存在，但算法静态可判）
  //   · 没有摘要目标时，不要做 MD5(候选)==目标 爆破
  let smcBlock = '';
  let hashBlock = '';
  try {
    const im = await window.electronAPI.fileImageMap(state.currentFile);
    const smcHash = await window.electronAPI.analyzeSmc(state.currentFile);
    if (smcHash && smcHash.success) {
      const smc = smcHash.smc || {};
      if (smc.hasSignal) {
        smcBlock = `\n## SMC/自修改特征
${smc.summary}
**先走静态/离线路线**（直接反汇编该节、读解包后字节、离线模拟）；只有在静态路线拿不到解包后字节时，
才走动态。动态的正确顺序（**不是**直接 start 然后单步）：
1. 静态定位**解密循环**（写该节的循环）与它的**结束地址**——这一步必须静态完成
2. \`ida_dbg(start)\` → 在解密循环**结束后**的那条指令 \`bp_add\` → \`continue\` 等命中
3. 命中后用 \`ida_dbg_mem read\` 把解密后的整节 dump 出来
4. 对 **dump 出来的新字节**重新反编译/扫描算法——不要继续在密文上纠缠

⚠️ **W+X ≠ 必须动态调试**；W+X 节存在但算法可静态判定时（如常量/结构已经明确），不要为了"看一眼运行时"烧预算。
⚠️ 若 ret 目标不是调用方压入的返回地址，按间接分支继续执行，**不得判定函数返回**；必须报告总指令数与最后 8 条 PC。\n`;
      } else {
        smcBlock = `\n## SMC/自修改特征\n未发现自修改特征（无 W+X 节、代码节不可写、无可疑导入）。**不建议动态调试**，按静态路线推进。\n`;
      }
      // 动态调试的决策顺序必须写清楚，否则 AI 会在 GUI 题上盲目 run_to 挂死。
      smcBlock += `\n## 动态调试决策顺序（GUI/ELF 通用）

### 🚧 入场条件：静态没跑完，不要启动调试器
**动态调试是取证手段，不是探索手段。** 它只回答"这个值运行时是多少"，
不回答"这段代码在干什么"——后者反编译更便宜、更可复现。
四条全满足才允许 \`ida_dbg(action:"start")\`：
1. **有函数清单**（\`list_funcs\` 已调用）
2. **候选函数说得清职责**（读输入 / 做变换 / 比对 / 解壳）
3. **写得出调试假设**：断点地址 + 命中后读哪个表达式 + 期望值 + 判定方式
4. **有办法把流程逼到那里**：入口断点 / 输入触发 / 定时触发 / 改 IP

写不出第 3 条 → 回反编译。知识库：\`wiki_read("reverse/method_static_first_dynamic.md")\`。

**先问：不动态能不能拿到答案？**
1. **离线模拟优先**：校验若是纯计算（不依赖 GetTickCount/文件/网络），用静态映射 + Unicorn（py_eval）直接跑，最省预算。
2. **GUI 对话框题**：校验只在按钮点击（WM_COMMAND）时执行，程序启动后阻塞在消息循环，
   \`run_to(校验地址)\` **永远等不到**——实测 8 轮 continue，IP 全程停在系统 DLL。
   - 32 位目标（WOW64）：**优先用内存改写法，不要依赖窗口消息**。跨位数下
     \`WM_SETTEXT\` 会返回 1 但 \`GetWindowText\` 读不回、\`SetFocus\` 失败、UIA 也找不到
     CreateWindowEx 创建的经典控件。可靠做法是：
     \`status\` 确认 STATE=-1 → 在**读取输入的那条指令**下断点 → \`continue\` 命中 →
     \`ida_dbg_mem(write, 地址=输入缓冲区, data=你的候选)\` → \`continue\` 看校验分支。
     \`dbg_read/dbg_write\` 走调试器后端，**不受位数影响**（实测 32 位目标读写字节精确一致）。
   - 64 位目标：可先用 \`gui_input(list_only:true)\` 看控件，再
     \`gui_input(text, submit:true)\`；自绘 UI / Qt / 游戏引擎不适用。
3. **无交互程序（ELF/控制台）**：可直接 \`run_to\`；ELF 用
   \`ida_dbg(start, mode:"remote", remote_host:"<kali ip>")\`。
4. **本地启动报 Failed to start debugger / START_RC=0**：两种原因分开处理。
   - \`START_RC=-1\`：先 \`ida_dbg(action:"clear_remote")\` —— IDA 的远程调试配置全局持久，
     残留的 host/pass/port 会让本地 start_process 失败。
   - \`START_RC=0\`（启动被取消）：进程选项里 target 路径为空或残留了上一次远程调试的
     Linux 路径。工具已自动回落到 IDA 当前加载的文件；若仍失败，先 \`clear_remote\` 再 start。

### 断点选址优先级（别乱下）
| 优先级 | 位置 | 理由 |
|---|---|---|
| 高 | 变换函数入口/出口 | 各断一次即得"输入原值→输出值"整段映射 |
| 高 | memcmp/strcmp 调用点 | 直接看到"期望 vs 实际" |
| 中 | 解密循环内部 | 只在需要轮密钥/中间态时 |
| 避免 | 消息循环 / sleep / CRT 初始化 | 断在这里等于没断 |

### 窗口期：断点"设了却不命中"的首要原因
目标启动后可能立刻跑完关键逻辑，调试器还没来得及下断点。三种应对：
入口先下断再 continue / 选有 sleep 或等输入的目标 / start 后立刻 suspend。

### 一次命中的取数清单（不要来回单步几十次）
寄存器（含 IP/SP）+ 函数参数（x64 RCX/RDX/R8/R9；x86 [esp+4..]；ARM64 X0..X3）
+ 关键内存（入参缓冲区、全局密文、常量表）+ 调用栈。
单条指令的语义反编译已经给了，动态只用来取运行时值。

### 拿到值必须离线复算
运行时值 → 用自己的脚本对同样输入做同样变换 → 逐字节比对。
不等时依次查：断点位置（变换前/后）→ 栈帧偏移 → 字节序/宽度 → 调用约定。

### 调试状态机（必须先看 STATE 再动手）
\`ida_dbg(action:"status")\` 返回 \`state\`：**-1=已暂停（可单步/run_to/写内存）**、
0=无进程、1=运行中（step/写内存必然失败）、2=已退出。
\`continue\`/\`run_to\` 是异步投递，工具已自动轮询到真正停下再返回：
- 返回 \`stopped:true\` → 可以紧接着 step / regs / mem_read；
- 返回 \`state:1\` + \`stopped:false\` → 进程在跑（GUI 程序通常在等输入）。
  用 \`ida_dbg(action:"suspend")\` 停下，或 \`gui_input\` 喂输入后等断点。
- 返回 \`state:2\` → 进程已退出，需要重新 \`start\`。

### 本地（PE / win32）与远程（ELF / linux_server）的关键差异
| | 本地 win32 | 远程 linux |
|---|---|---|
| start 后 | 自动停在入口（STATE=-1），可直接单步 | **不停**，进程直接跑（STATE=1），工具已自动 suspend |
| 调试器名 | \`load_debugger("win32", False)\` | \`load_debugger("linux", True)\`（**不是 gdb**） |
| 服务端 | 无 | Kali 上跑 IDA 自带 \`dbgsrv/linux_server\`，**不是 gdbserver** |
| 启动命令 | — | \`setsid linux_server -P<密码> & \`（\`-P\` 必须紧贴密码；\`setsid\` 防 SSH 断开被杀） |
| 断点 | 静态地址即可 | **PIE 必须用重定位后的地址**：\`start\` 返回的 \`symbols\` 里取 main 等地址 |
| 断点 API | 均可 | 用 \`idaapi.add_bpt\`（\`dbg_add_bp\` 转发 ida_idd，对远程段恒 False） |

远程调试用例实测（11/11 通过）：编译带符号的 PIE → 下载 → linux_server 监听 23946 →
\`start(mode:"remote")\` → suspend → 读重定位符号（IMAGEBASE 0x555555554000）→
\`idaapi.add_bpt(main)\` → continue 命中 → step_over → continue 命中 check → 读写内存。
**关键时序**：目标若启动后立刻跑关键逻辑，调试器来不及下断点。要么让目标先 sleep 留窗口，
要么先按入口地址下断再 continue。

### 常见假故障（不要误判成"工具不可用"）
- \`dbg_step_over\` 报 Failed 但 IP 确实变了 → IDA 9 异步返回值问题，工具已用 IP 变化兜底。
- \`load_debugger("linux") 返回 False\` → 很可能连到了**仍加载 PE 的旧 IDA 实例**。
  确认只跑一个 IDA，且打开的数据库是 ELF。
- 连上后立刻 \`Closing connection\` + \`read_regs => -1\` → 目标已退出（如聊天客户端连不上服务端），
  换一个会驻留的样本验证链路。
- Kali 的 shell 是 zsh：未匹配的 glob 会报 \`no matches found\` 并中止整条命令，
  通配符命令放到 \`sh -c '...'\` 里。
\n`;
      const h = smcHash.hash || {};
      if (!h.hasTarget) {
        hashBlock = `\n## 摘要目标\n文件内无 32 位 hex 摘要目标 → MD5 可能用于 KDF/掩码派生，不要做 MD5(候选)==目标 爆破。\n`;
      }
    }
  } catch (e) { /* 特征采集失败不阻塞 */ }

  const prompt = `我在解一道 CTF ${fileType || '二进制'} 题，静态固定清单分析未得出 flag。请**使用工具**自主深入分析并求出 flag。
${algHint}${platDesc}${failHint}${excludedHint}${stageBlock}
${state._autoSm4Tried ? `\n## ⚠️ 工具已替你试过的路线（不要原样重复）
工具已按 SM4 骨架跑过全组合枚举脚本（${state._autoSm4Tried.script}），未命中。
已覆盖：密文候选 ${state._autoSm4Tried.ctCandidates.join('、')} × 全部 FK 候选 × key 候选 × 16 种字节序/状态组合 × 3 种块内排列。
这不代表算法认错——**很可能实际结构不是 SM4 骨架**（如 AES 的 SubBytes/ShiftRows/MixColumns），
或密文/key 不在工具假设的位置。请换一条路线，而不是再跑一遍同样的枚举。
` : ''}
文件路径：${state.currentFile}
## 已获取的函数列表（节选）
${fnSummary}
${analysisData.mainCode ? `\n## 入口函数反编译\n\`\`\`c\n${buildFuncBody(analysisData.mainName || 'main', analysisData.mainCode, 12000)}\n\`\`\`` : ''}
${analysisData.otherFunctions && analysisData.otherFunctions.length ? `\n## 已反编译的其它函数\n${analysisData.otherFunctions.map(f => `### ${f.name}\n\`\`\`c\n${f.code}\n\`\`\``).join('\n\n')}` : ''}
${analysisData.strings ? `\n## 关键字符串\n${typeof analysisData.strings === 'string' ? analysisData.strings.slice(0, 2000) : JSON.stringify(analysisData.strings).slice(0, 2000)}` : ''}
${analysisData.execFlowText || ''}
${smcBlock}${hashBlock}
${sideFilesBlock}

## 你必须严格按 4 阶段推进（每阶段先出证据）

0) **⚡ 先做确定性扫描（省最多预算，务必第一步做）**
   在反编译任何函数之前，先调用 \`scan_crypto\`（参数 path=当前文件绝对路径）。它直接读字节，**不依赖 IDA**，
   一次性告诉你：
   - 已知算法常量（SM4 FK/S 盒、AES、SM3、TEA、CRC32…）
   - **自定义分组密码的常量差分**（S 盒与标准表关系、轮常量表位置与精确差分、FK 候选、字节序线索）
   - **编码存储的内嵌载荷**（XOR/ADD/旋转/Base64/Hex/ELF/DEX/shellcode，含提取配方）
   - 高熵常量块（疑似 key/密文）
   ⚠️ 这些是**确定性结论**，优先采信，别再用反编译去反复验证同一件事。
   - 若报告了内嵌载荷 → 调 \`extract_payload\`（不传参数即自动用最佳候选）提取下一层，再对**新文件**重新 \`scan_crypto\`。
   - 若报告「自定义 S 盒 + SM4 形态轮常量表」→ 调 \`gen_sm4_solver\` 拿到可跑脚本（覆盖标准 SM4 与常见魔改），
     先跑它；**未命中不代表算法认错**（可能其实是 AES 骨架）。
   - 分析过程中**任何时刻**都可以重新调用（例如换到提取出的新文件、或怀疑前面的结论）。

① **收集（代码+数据缺一不可）**：用 \`ida_decompile\` 反编译入口与关键函数；**务必**用
   \`ida_get_bytes\`（读任意地址原始字节，hex+ASCII）+ \`ida_list_globals\`（**自动分页**，默认每页 500 条；需要更多用 offset/count 翻页）取出被引用的**常量表/vtable 内容**
   （密钥/密文/S盒/VM字节码/函数指针表都在 .data/.rodata）；
   用 \`ida_find_strings\` 搜 flag/key/密文特征串。⚠️ **只给代码不给常量表 = 无解**。
   （IDA MCP 未连接时，用 run_python 配 capstone/pefile 手工解析。）
   📄 **伴生文本文件（.txt/.out/README 等）直接用 \`read_file\` 读全文**——不要凭部分信息反复猜测其内容
   （实测教训：flag.out 的 51 个数字被 AI 凭记忆推演了 3 遍，全是重复劳动）。
② **定位算法**：认出算法特征（TEA 魔数 0x9E3779B9 / RC4 双 S 盒 / AES S 盒 / XOR 流 / 自定义 VM/查表），
   写清算法名 + 关键地址 + 输入输出形态。
②' **VM/加壳题：先"认算法"再动手，别一头扎进 opcode（血泪教训）**：
   若看到"取指-译码-执行"循环（while(1){ op=code[pc]; switch(op){...} } + 一大块内存当寄存器），
   **VM 只是外壳**。**严禁**逐条反编译所有 opcode handler 去手工还原语义（实测 Disguise：反编译 13 个
   handler、烧掉 500+ 秒，最后仍卡在"怎么写模拟器"）。
   **正确顺序（省 10 倍预算）**：
   a) 先把 VM 用到的**常量表全读出来**（'ida_get_bytes' 按 VA 直接读 S 盒/FK/CK/密钥/密文，别手算 offset）；
   b) **逐项对照标准算法**：S 盒 256 字节（首字节 0xD6/8E…）；系统参数 FK 'a3b1bac6 56aa3350 677d9197 b27022dc'
      （出现即 **SM4**）；轮常量 CK 表；16 字节种子密钥 → 32 轮密钥；轮函数形如 'X ^ X ^ X ^ rk'（SM4 特征）
      或 SubBytes/ShiftRows/MixColumns（AES 特征）；
   c) **认出后直接套标准解密框架**（结构照抄，常量/轮密钥顺序换成题目的）——不要写通用 VM 解释器。
   d) 若确实认不出标准算法：**才**退化为"写 VM 解释器正向执行 + 逐块反演"，且**先跑通 1 个块**再扩到全部。
   ⚠️ 魔改题常见三坑：轮密钥逆序 'rk[31-i]'、块内最后字节反序 '[3][2][1][0]'、常量被换（此时库函数解出乱码）。
③ **写脚本本地验证**：用 run_python 实现还原，正反双向验证（反推 key 后正向加密对回目标常量）；
   需要约束/符号执行/模拟执行时用 Z3 / angr / Unicorn。
③'' **分组密码 / VM·AES 变体题（重要！别硬逆）**：若发现"16 字节输入 → 16 字节输出 + 多轮结构 +
   S 盒查表 + 密钥常量"（典型：自定义 S 盒的 AES 变体、微指令 VM 解释器加密），**不要试图手工反演/硬逆
   加密过程**（会烧光预算）：
   - 首选**正向验证**：写出/复用正向加密模拟器（VM 解释器或 AES 结构），然后用
     'enc(候选明文) == 目标密文' 做验证。**块密码是双射，"正演验证"与"反演"等价，且简单得多**。
   - 有已知格式（xmctf{/flag{/dice{…）或字典 → 直接正向枚举候选、逐一验证。
   - 若必须符号求解：**一次只解 1 个块（16 字节）**，且 S 盒查表用**常量数组 Select**而不是逐项 If 链；
     分段多次短脚本 > 一次巨型脚本（单次 run_python 超时了就先拆小）。
   - 反演顺序：若确认是标准轮结构（SubBytes/ShiftRows/MixColumns/AddRoundKey），可把自定义 S 盒换成逆 S 盒，
     其余用标准 AES 解密框架。
   ⚠️ 若 run_python 报"超时"，那是**算得久不是方法错**——按提示缩小搜索空间或拆分，不要换方法重头再来。
   ⚠️ **RVA→文件偏移不要手算**（如 0xfa00+(va-0x421000) 这种）——极易错且会让你反复重跑同一脚本直到卡死。
      正确做法：用 pefile.PE(path).get_offset_from_rva(rva) 或 pe.get_memory_mapped_image()[va]（按虚拟地址索引）；
      读常量表优先用 ida_get_bytes(address)（IDA 已加载，直接按 VA 读，无需换算）。
   ⚠️ **同一脚本不要重复跑 3 次以上**——拿不到结果说明方法有问题，先看报错原文定位根因，别换写法重试。
③' **运行型题目路径（重要！）**：若程序**没有**静态校验逻辑，而是"输入→处理→输出"的工具型程序
   （判断特征：getopt 命令行参数 / ifstream+ofstream / 线程池 / 计时输出；题目描述给出运行用法），
   先做 **10 秒分诊**（决定走哪条路，判错方向全盘皆输）：
   **伴生 .out/.txt 若全是纯数字 → 测两问**：① 首值是否可打印 ASCII（如 chr(100)='d'）？
   ② 反编译中变换循环是否从下标 1 开始（即**元素 0 永不被更新**）？
   **两问都中 = 数据变换型**：flag 就是程序当时的输入，被确定性变换写进输出文件——
   **不要运行程序，直接反演输出**：利用已知明文（dice{/flag{/ctf{ 前缀 + 元素0 不变）推出算子
   （逐位测 xor/add(减)/mul(整除) 哪个能出可打印字符），算子洗牌顺序不用预测 glibc rand——
   3!=6 种排列暴力 + "全元素可打印 ASCII"约束即可锁定；按程序循环结构逆向走一遍，chr 拼接出 flag。
   ⚠️ 多线程/semaphore/std::thread 只是**执行机制**，别烧预算逆向 _State_impl vtable/嵌套 invoke 链
   ——变换语义从"调用 sem_wait 的 lambda 函数体"找，或干脆用已知明文绕过。
   **分诊不中（输出与 flag 无字符关联）= 真运行型**：flag 在运行行为里（特定输入的输出/种子复现随机序列），
   才走 WSL（\`wsl --status\` 检测）/Unicorn/qiling 运行路线。
④ **结论**：有把握才给 flag；证据不足就写明"待人工验证 + 还缺什么"，不要猜。
④' **多阶段题目（壳/packer）——解出新文件就接力**：若你在本阶段解出/提取出一个**新的可执行文件**（壳解出的 stage2.exe、解密出的内嵌 PE/DEX/payload、从资源段 dump 的二进制等，写出到磁盘且能识别出
   MZ/ELF/DEX 头），**不要试图在当前进程里硬啃它**（IDA/JEB 单实例、当前数据库绑的是旧文件）——
   直接调用 \`switch_to_next_stage\`（参数 path=新文件绝对路径, reason=判定理由, carried=你要传下去的关键结论）。
   工具会：关闭当前反编译进程 → 保留你的结论 → 以新文件重建分析上下文并自动继续。
   ⚠️ 同一文件不要重复接力；不确定是否真有下一阶段时不要调用（层数上限 3）。
   ⚠️ 若当前文件本身是 decoy（如校验表解出 "This is a fake flag"、程序是壳/loader），**必须**找真载体接力，
   而不是报告"这是假 flag"就收工。

## 动态调试/流量/远程工具（仅在证据需要时使用）

- \`ida_open_file({path:"<绝对路径>"})\`：让 IDA 在新实例里打开并重新分析该二进制，
  **之后所有 ida_* 调用自动路由到新实例**。花指令修复（junk_repair）后必须用它重开文件，
  否则读到的仍是按旧错位边界解析的伪代码。加 \`new_database:true\` 强制丢弃旧 .i64 重建。
- \`ida_list_globals({filter:"key"})\`：列出全局符号（**自动分页**，每页 500 条直到 next_offset=null）。
  需要更多时用 \`{offset:500, count:500}\` 手动翻页；不要假定第一页就是全部。
- \`ida_disasm({address:"0x401000", max_instructions:64})\`：反汇编任意地址（含不在函数表里的代码/间接跳转目标）。
- \`ida_dbg({action:"start"})\` → \`ida_dbg({action:"bp_add", addrs:["0x401000"]})\` → \`ida_dbg({action:"continue"})\`
  → \`ida_dbg({action:"regs"})\` / \`ida_dbg({action:"regs_named", regs:"RAX,RBX"})\`；
  退出用 \`ida_dbg({action:"exit"})\`，断点列表 \`{action:"bp_list"}\`。

### ⭐ 运行期探测（混淆题首选，比读伪代码可靠）

**当反编译出来的代码读不懂、或怀疑静态结论不可信时，不要硬读——直接量运行期行为。**

- **代码被切成很多段、中间是 \`jmp rax\`（分段 dispatch / VM 保护）时，先走这两步**：
  \`emu_trace({binary:"/tmp/chall", start:"0x401006", mode:"function"})\`
  → Unicorn 真跑目标，记录**每个间接跳转实际去了哪里**。摘要里
  \`IND 0x401138 -> 2 targets: v=0x2 0x4011BF(x1)\` 就是「段号 2 → 段地址 0x4011BF」。
  轨迹 JSON 同时含全部控制流边与执行区间；动态链接目标别用 mode=entry（入口是 ld.so）。
  \`ida_apply_trace({trace:"<轨迹对象或 JSON 路径>"})\`
  → 把轨迹回填成 create_insn + add_cref + add_func，各段立刻连成一片，反编译器就能读了。
  回填后每段还能单独 \`ida_decompile\`，逐段还原语义比读一整坨 switch 快。
  仍断段就再来一次并加 \`code_ranges:true\`。
- \`ida_dbg({action:"snapshot_diff", regions:[{addr:"0x13200",size:216}], mode:"until_return"})\`
  **反推"这段代码把数据改成了什么"**。跑完当前函数，前后各拍一次内存快照并**就地差分**，
  返回逐字节变化清单（offset / before / after）。混淆 handler 的置换/变换语义直接可见。
  mode：\`until_return\`（整个函数，最常用）/ \`single_step\`（单条指令）/ \`until_addr\`（需 target）/
  \`manual\`+\`once\`（先拍 before，中途做别的事，再出差分）。
- \`ida_dbg({action:"force_continue", set:[{reg:"eax",value:1}], then:"continue", repeat:6, bp_addr:"0x46bd"})\`
  **让被混淆提前打断的循环跑满**。在断点处强制改寄存器再继续，repeat 控制次数。
  典型场景：校验函数本该循环 N 次，但被 \`test eax,eax; je exit\` 提前退出，只抓到第一组常量。
- \`ida_dbg({action:"global_reads", func:"sub_4638"})\`
  **判断函数只校验一行还是一整块**。统计它引用了哪些全局元素、步长多少。
  若元素数 < 一行宽度 ⇒ 该函数只处理一行，调用方在循环里喂多次 ⇒ 还有 N 组常量没抓，回头找调用方。
- \`angr_solve({binary:"/tmp/chall", find:["0x5B90"], avoid:["0x5BB9"], main:"0x4EDF", hooks:[{addr:"0x39E3"}]})\`
  **算法读不出但知道成功分支时，让符号执行反求输入**。生成脚本后用 run_python / remote_exec 跑。
  两个硬前提：① 必须 \`call_state\` 从主函数起（\`entry_state\` 会卡在 \`__libc_start_main\` 耗尽 state）；
  ② 间接跳转点必须写进 \`hooks\`（否则 angr 顺函数指针把常量表当代码解码，报 IR decoding error）。
  带参数启动：\`ida_dbg({action:"start", path:"", args:"-d", cwd:"..."})\`（path 空串 = 调试 IDA 当前已加载的库）。

### ⭐ 算法已读出时：先判断"可逆"，别急着上符号执行

把校验循环的伪代码拿到手后，**先看循环体只用了哪些运算**：

| 循环体里的操作 | 是否可以倒着算 |
|---|---|
| \`x ^= y\` | 可以（自己就是逆运算） |
| \`x = ~x\` | 可以（自逆） |
| \`x = rol(x,1)\` / \`(x<<1)\\|\` 最高位 | 可以（改 ror / 最低位回填） |
| \`x += y\` / \`x -= y\` | 可以（反过来减 / 加） |
| 双变量交换 \`t=x; x=y; y+=t\` | 可以（**逆序**把每条语句倒着撤） |
| \`x &= mask\` / \`x \\|= y\` / \`x *= k\` / 查表 / S-box | **不可以**（信息丢失或非线性） |

**只要全是前四行那类操作，就不要上 Z3/angr**：从目标值出发，把每轮操作**逆序**执行一遍，
几千轮也只是几毫秒。这是最省时也最可靠的路。

做法（三步，务必都做）：
1. 把读出的语义写成正向函数 \`f(X, Y)\`；
2. 用 \`emu_trace\` 的 \`regs.rax/regs.rdx\`（就是函数返回值）与 \`f(...)\` 对拍，
   **确认模型与真实程序一致**——这一步能挡住绝大多数"抄错常量/看错方向"的错误；
3. 写逆函数 \`g(目标)\` 逐轮回退，得到输入后打包成字节再跑一次真实程序验证。

只有在出现 \`& | *\`、查表、S-box 这类**不可逆**操作时，才转去 \`angr_solve\`。
先问一句"这个循环能不能倒着走"，往往能省掉几百秒的符号执行。
- \`ida_dbg_mem({action:"read", regions:[{addr:"0x401000", size:32}]})\`：读内存（返回带空格的 hex）；
  \`ida_dbg_mem({action:"write", regions:[{addr:"0x401000", data:"9090"}]})\`：写内存。
- \`remote_exec({host:"kali", command:"binwalk -e fw.bin"})\`：远程执行（local 也可）。
  失败返回 \`REMOTE_TIMEOUT/REMOTE_AUTH/REMOTE_REFUSED/REMOTE_UNCONFIGURED\` 前缀，**都是错误**，不要当成成功空输出。
- \`traffic_extract({path:"x.pcap", protocol:"auto"})\`：解析抓包（每流端口/包数/字节数/熵/hex 预览）。
  http=0 表示二进制协议，不要当 Web 流量处理。

⏱ **预算纪律（必读）**：本轮你共有约 **60 次工具调用**（充足，但别挥霍）。
- 收集阶段（反编译/读伴生文件/常量）：目标 **15 次内**完成。
- 第 **16 次起：进入执行**——写还原/模拟/反演脚本（run_python），**用实验代替继续读代码**；
  脚本报错就修脚本再跑（这算执行，不算收集）。
- 第 **55 次起（冲刺）**：无论状态如何，停止一切新分析，把已有发现落地为最终脚本或结论。

**输出契约：**
1. flag：单独一行 \`[FLAG]flag内容[/FLAG]\`
2. 附 \`${VERIFY_CONTRACT}\`
3. 多个候选：\`[HYPOTHESES][{...},{...}][/HYPOTHESES]\`
4. 末尾 \`[EXPERIENCE]每条一行,最多5条[/EXPERIENCE]\`
不要臆造工具结果；工具失败时换一条路径继续。`;

  try {
    state.aiBusy = true;
    beginStreamMessage();
    const startTime = Date.now();
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: prompt }],
      buildSystemPrompt()
    );
    endStreamMessage();
    addLog('info', `Tool-Use 深度求解完成，耗时 ${((Date.now() - startTime) / 1000).toFixed(1)} 秒`);

    if (result.success && result.text) {
      state.lastAiText = result.text;
      addSolveNote('求解结果(Tool-Use)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));

      // ── 多阶段接力：AI 请求切换到新阶段文件（壳/packer 题）──
      // 由本层承载切换（kill 旧进程 + 保留结论 + analyzeFile 新文件 + 递归 autoAnalyze）。
      if (result.stageSwitch && result.stageSwitch.path) {
        addLog('info', `[阶段接力] 收到 AI 接力请求 → ${result.stageSwitch.path}`);
        const r = await runStageHandoff(result.stageSwitch, result.text);
        if (r.ok) return true;   // 新阶段（含其内部递归）已跑完
        addLog('warning', '[阶段接力] 未切换（' + r.note + '），按当前阶段正常收尾');
      }

      // 验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const fin = await finalizeSolve(result.text, { source: 'ai-deep' });
      const vf = (state.findings ? state.findings.flags : []).filter(f => f.verified);

      // ── Phase 2：负面断言被推翻 → 用证据强制 AI 再走一轮（不靠它自觉）──
      // 实测教训（Disguise）：AI 说"文件内无第二载体"就直接收工。工具已用扫描数据反驳；
      // 这里把反驳当作**新一轮输入**再次调用 AI，而不是只在 UI 上提示一句。
      //
      // v1.7.4 扩展：**验证失败也要重试**。实测 6 道题"有契约但本地复现失败"，
      // 根因多是 AI 的 expected 写错（猜的前缀与实际不符）或参数差一点；
      // finalizeSolve 已把真实解密输出拼成 retryPrompt，此前却没有消费方 → 白丢证据。
      //
      // rank 5：重试改成**循环**（最多 2 轮）。旧实现只跑一轮且把第二次 finalizeSolve
      // 的返回值直接丢掉——第二轮生成的定向提示（中间值类型/机器码结论）没有任何消费方，
      // 实测（CrackMe3）日志出现了「已生成定向下一步提示」却不再有第三次调用。
      const MAX_RETRY_ROUNDS = 2;
      let retryFin = fin;
      let retryText = result.text;
      let retryRefuted = fin && fin.refuted;
      for (let round = 1; round <= MAX_RETRY_ROUNDS; round++) {
        const vfNow = (state.findings ? state.findings.flags : []).filter(f => f.verified);
        const canRetry = retryFin && retryFin.retryPrompt && !vfNow.length
          && ((retryRefuted && retryRefuted.length) || (retryFin.vr && retryFin.vr.failureFeedback)
            || retryFin.intermediateTyped || retryFin.machineCodeNote || retryFin.enumFeedback);
        if (!canRetry) break;
        const reason = (retryRefuted && retryRefuted.length)
          ? (round === 1 ? '负面断言遭推翻' : `负面断言遭推翻（第 ${round} 轮）`)
          : (retryFin.enumFeedback
            ? (round === 1 ? '本地枚举候选全部无效（缺密文/空输出）' : `本地枚举候选全部无效（第 ${round} 轮）`)
            : (round === 1 ? '验证失败（附真实解密输出）' : `验证失败（第 ${round} 轮）`));
        addLog('warning', `[重试] 第 ${round} 轮：追加一轮 AI（${reason}，强制基于证据修正）`);
        const retryMessages = [
          { role: 'user', content: prompt },
          { role: 'assistant', content: String(retryText || '').slice(0, 20000) },
          { role: 'user', content: retryFin.retryPrompt + '\n\n请直接执行上述动作；不要重复之前的否定结论。' },
        ];
        let r2 = null;
        try {
          r2 = await window.electronAPI.claudeChat(retryMessages, buildSystemPrompt());
        } catch (e) {
          addLog('warning', `[重试] 第 ${round} 轮调用失败（不阻塞）: ${e.message}`);
          break;
        }
        if (!(r2 && r2.success && r2.text)) break;
        state.lastAiText = r2.text;
        addSolveNote(`求解结果(修正重试${round > 1 ? ' ' + round : ''})`, String(r2.text).replace(/\s+/g, ' ').trim().slice(0, 3000));
        addLog('info', `[重试] 第 ${round} 轮定向提示已消费`);
        // 重试里若又请求接力，同样处理
        if (r2.stageSwitch && r2.stageSwitch.path) {
          const hr = await runStageHandoff(r2.stageSwitch, r2.text);
          if (hr.ok) return true;
        }
        // 必须接住返回值：下一轮的 retryPrompt 来自这里
        retryFin = await finalizeSolve(r2.text, { source: round === 1 ? 'ai-deep-retry' : 'ai-deep-retry-' + round });
        retryText = r2.text;
        retryRefuted = retryFin && retryFin.refuted;
        const vf2 = (state.findings ? state.findings.flags : []).filter(f => f.verified);
        if (vf2.length) {
          addSystemMessage(`**🎯 Tool-Use 深度求解结果（证据回灌后重试）**\n\n**Flag（✅已验证）**: \`${vf2[0].flag}\`\n\n${r2.text}`);
          return true;
        }
        if (round === MAX_RETRY_ROUNDS) addLog('info', `[重试] 已达上限（${MAX_RETRY_ROUNDS} 轮）`);
      }
      {
        const vf2 = (state.findings ? state.findings.flags : []).filter(f => f.verified);
        addSystemMessage(`**🎯 Tool-Use 深度求解结果**\n\n${vf2.length ? `**Flag（✅已验证）**: \`${vf2[0].flag}\`` : ''}\n\n${retryText}`);
        return vf2.length > 0;
      }

      addSystemMessage(`**🎯 Tool-Use 深度求解结果**\n\n${vf.length ? `**Flag（✅已验证）**: \`${vf[0].flag}\`` : ''}\n\n${result.text}`);
      return vf.length > 0;
    }
    if (result.aborted || /已取消/.test(result.error || '')) { addLog('info', 'Tool-Use 深度求解已停止'); return false; }
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
      `你是CTF逆向解题专家。请使用工具分析代码并找出flag。最多调用5次工具，找到flag后立即停止。当前文件: ${state.fileInfo.fileName}` + experienceSection()
    );

    if (result.success && result.text) {
      addLog('success', '========================================');
      addLog('success', '详细分析完成！');
      addLog('success', '========================================');

      state.lastAiText = result.text;
      addSolveNote('求解结果(详细)', String(result.text).replace(/\s+/g, ' ').trim().slice(0, 4000));
      // 详细分析同样走验证闭环 + 解题成功则经验自动入库（统一走 finalizeSolve 三件套）
      const { verifiedFlags: dvf, flags: dflags } = await finalizeSolve(result.text, { source: 'ai-detail' });

      const resultMsg = `**🔍 详细分析结果**

**文件**: ${state.fileInfo.fileName}
**类型**: ${fileType}
${dvf.length ? `**Flag（✅已验证）**: \`${dvf[0].flag}\`` : (dflags.length ? `**Flag（⚠️未验证）**: \`${dflags[0]}\`` : '')}

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

// 从经验库文本里挑选与"当前题"最相关的条目注入系统提示。
// 旧实现只取末 15 行 —— 失败题教训/早期高价值经验会被淹没。改为：
//   1) 按当前题特征（文件类型关键词 + 已识别的算法/包名）命中打分；
//   2) 命中优先，其次补齐"最近 N 条"（保证上下文新鲜）；
//   3) 去重、限总条数，避免撑爆 token。
function selectRelevantExperience(expText, findings) {
  // 结构化检索（借鉴 openclaude memdir）：按"当前题的特征词"给经验条目打分，
  // 只注入命中的 top 几条（≤600 字符），而不是把整个经验库塞进提示词。
  // 兼容两种格式：旧自由文本行 与 新 [technique]/[pitfall] + applies_to/Rule/Why/How。
  const kws = [];
  const ft = (state.fileType || '').toUpperCase();
  if (ft) kws.push(ft);
  if (/APK|DEX/i.test(ft)) kws.push('APK', 'so', 'native', 'JEB', 'Frida', 'smali', 'SharedPreferences');
  else if (/PE|ELF|EXE|BIN/i.test(ft)) kws.push('native', 'IDA', 'PE', 'ELF', 'VM', '常量表');

  // 用最近一次扫描结论做特征词（骨架/S 盒关系/存放形态）
  const scan = state.lastAlgScan || null;
  if (scan) {
    for (const s of (scan.summary || [])) {
      const a = String(s.algo || '');
      if (a) kws.push(a);
      for (const m of a.match(/(SM4|AES|DES|Blowfish|TEA|RC4|Base64|Base91|VM)/gi) || []) kws.push(m);
    }
    for (const f of (scan.fingerprints || [])) {
      if (f.stride > 1) kws.push('dword', 'stride');
      if (f.constantAnalysis) {
        const rel = f.constantAnalysis.sboxRelation;
        if (rel && rel.relatedTo) kws.push(rel.relatedTo);
        kws.push('S盒', 'sbox', '常量');
      }
    }
    for (const pl of (scan.payloads || [])) {
      kws.push(pl.type === 'pe' ? 'loader' : String(pl.type || ''));
      if (pl.encode && pl.encode.kind) kws.push('XOR', '编码');
    }
  }

  const pkg = (state.findings && state.findings.meta && state.findings.meta.packageName) || '';
  if (pkg) kws.push(pkg);
  for (const a of (findings && findings.algorithms) || []) {
    const x = (a && a.text) || String(a);
    if (x) kws.push(x.slice(0, 20));
  }

  // 调用主进程的结构化检索（失败则退回本地的宽松匹配，保证不会因 IPC 故障丢经验）
  try {
    const api = window.electronAPI;
    if (api && api.experienceRank) {
      // 同步接口不可用时用缓存结果；这里优先用同步实现（见下方 localRank）
    }
  } catch (e) { /* 忽略 */ }
  return localRankExperience(expText, kws);
}

// 与 electron/agent-runtime.js: rankExperience 同算法的渲染层实现
// （渲染层不能 require 主进程模块；两边由 test_agent_runtime.js 的同组断言守住一致性）
function localRankExperience(expText, keywords) {
  const limit = 6, maxChars = 600;
  const kws = (keywords || []).map(k => String(k).toLowerCase()).filter(Boolean);
  const lines = String(expText || '').split('\n').filter(l => /^\s*-/.test(l));
  const items = [];
  lines.forEach((raw, idx) => {
    const m = raw.trim().match(/^-\s*\[(\w+)\]\s*(.*)$/);
    let kind = 'legacy', tags = [], rule = raw.trim(), why = '', how = '';
    if (m && /^(technique|pitfall|layout|tool-usage|fact)$/i.test(m[1])) {
      kind = m[1].toLowerCase();
      const body = m[2];
      const tm = body.match(/applies_to\s*=\s*([^|]+)/i);
      if (tm) tags = tm[1].split(/[,，\s]+/).filter(Boolean);
      rule = (body.match(/Rule:\s*(.+?)(?=\||$)/i) || [])[1] || body;
      why = (body.match(/Why:\s*(.+?)(?=\||$)/i) || [])[1] || '';
      how = (body.match(/How:\s*(.+?)(?=\||$)/i) || [])[1] || '';
    } else {
      rule = raw.trim().replace(/^-\s*(\[[^\]]+\]\s*)?/, '');
    }
    const hay = (raw + ' ' + tags.join(' ')).toLowerCase();
    const hits = kws.reduce((n, k) => n + (hay.includes(k) ? 1 : 0), 0);
    if (!hits) return;                       // 零命中不注入（否则等于把经验库全塞进提示词）
    items.push({ kind, tags, rule: rule.trim(), why: why.trim(), how: how.trim(), hits, idx });
  });
  items.sort((a, b) => (b.hits - a.hits) || (b.idx - a.idx));
  const out = [];
  let used = 0;
  for (const e of items.slice(0, limit)) {
    let text;
    if (e.kind === 'legacy') text = '- ' + e.rule;
    else {
      text = '- [' + e.kind + '] ' + e.rule;
      if (e.why) text += '\n  为什么：' + e.why;
      if (e.how) text += '\n  怎么做：' + e.how;
    }
    if (used + text.length > maxChars) break;
    out.push(text); used += text.length;
  }
  return out.join('\n');
}

// 构建系统提示（连接状态取真实探测结果，不夸大）
function buildSystemPrompt() {
  const mc = state.mcpStatus;
  const st = (ok) => (ok ? '已连接' : '未连接');
  const skillsIndex = state.skills.length
    ? `\n## 可用技能（用 read_skill 工具读取全文）\n${state.skills.map(s => `- ${s.name}：${s.description}`).join('\n')}\n`
    : '';
  // 知识库注入：优先提示"先读全局索引 AI-SEARCH-INDEX"，再列页面清单。
  // 注意：逆向条目库(reverse/)有 40+ 篇，只靠 wiki_search 命中即可，不必逐条列名
  //（逐条列名会白白吃掉上下文，且文件名长、对定位无帮助）。只列"手法页"清单。
  const wikiPages = state.wikiPages || [];
  const revCount = wikiPages.filter(p => String(p.rel || '').startsWith('reverse/')).length;
  // reverse/ 下的方法篇（不是某道题的 writeup）必须**点名**，否则 AI 只看到"40+ 篇题库"，
  // 不会想到里面还有方法论页——这是"写了却用不上"的典型。
  const METHOD_PAGES = [
    'reverse/method_static_first_dynamic.md',
    'reverse/method_junk_code.md',
    'reverse/method_runtime_challenges.md',
    'reverse/method_parallel_scan_inversion.md',
    'reverse/method_excel_formula_verifier.md',
    'reverse/method_short_ciphertext_triage.md',
    'reverse/method_gm_crypto.md',
    'reverse/method_pe_loader_vm_obfuscation.md',
  ].filter(rel => wikiPages.some(p => p.rel === rel));
  const methodList = METHOD_PAGES.length
    ? `\n**方法论专页（reverse/ 下，不是题库）**：\n${METHOD_PAGES.map(r => '- ' + r).join('\n')}\n`
    : '';
  const wikiIndex = wikiPages.length
    ? `\n## 知识库 Wiki（解题前先检索）\n**首选**：\`wiki_read(path=AI-SEARCH-INDEX.md)\` 读全局检索索引（按技术标签定位资源）；速查用 \`wiki_read(path=PAYLOAD-CHEATSHEET.md)\`。\n手法页（用 wiki_search 按关键词检索 / wiki_read 读整页）：\n${wikiPages.filter(p => !String(p.rel || '').startsWith('reverse/')).map(p => `- ${p.rel}`).join('\n')}\n${methodList}${revCount ? `另有**历年逆向题条目库 ${revCount} 篇**（含 attack_chain 解法链 / reasoning_chain 思维链 / failed_attempts 避坑）：用题目特征词（算法名/混淆方式/工具/大赛名）\`wiki_search\` 检索，或先读 \`reverse/_INDEX.md\` 看总表。\n` : ''}遇到具体手法/踩坑（Frida 进程内解密、native 常量反演、IV 编码坑、多阶段 APK）先 wiki_search 检索，命中即 wiki_read 取完整片段。\n需要**动不起来/静态读不动**时，先读 \`reverse/method_static_first_dynamic.md\`（动态调试入场条件），再决定是否启动调试器。\n`
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
- 浏览器 MCP：${st(mc.browser)} - 网页搜索/内容抓取
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
7. 给出验证数据：${VERIFY_CONTRACT}，工具会本地复现验证；custom 需附 "code":"def decrypt(data,key): 完整函数"；JS逆向还原的加密函数用 node_js：附 "code":"function decrypt(input){...}"（返回字符串或Uint8Array）和 "input":"抓到的参数原文"
8. 有多个候选（算法/字节序/密钥变体）时：[HYPOTHESES][{...},{...}][/HYPOTHESES]，工具会本地枚举
9. 解题学习闭环（每次解题强制遵守）：
   - 解题前：先读上方「历史经验速查」，同类场景直接复用已验证套路与避坑点；需要完整方法论时用 read_skill 加载对应技能（ctf-reverse-binary / ctf-reverse-android / ctf-jsreverse 等）；遇到具体手法/踩坑（Frida 进程内解密、native 常量反演 key、IV 编码坑、多阶段 APK 停在首页等）先用 wiki_search 检索知识库，命中即 wiki_read 取完整代码片段。禁止无视知识库从零摸索
   - 解题中：严格按知识库流程执行，知识库已记录的坑（如 VM 题必须连常量表一起采集、mingw 入口是 _main、IV 编码不能借用 key 的编码）不得重踩
   - 解题后（无论成功失败）：回答最后输出 [EXPERIENCE]经验块[/EXPERIENCE]，工具自动写入经验库。**格式（支持多步攻击链）**：
     · 每条经验一行起头，**用 → 串联成"多步攻击链/思维链"**（特征→关键步骤→坑→下次怎么做），例如：
       "APK多阶段题→反查常量串定位校验类→native 反演 key→AES 解 flag→坑:IV 单独按 base64 解"
     · 也可写"失败教训"（哪条路走不通、为什么、下次直接换哪条）——失败教训往往比成功更有价值
     · 最多 5 条，每条 ≤300 字；确无新收获写"无新增经验"
${skillsIndex}${wikiIndex}${experienceSection()}${(state.findings && ((state.findings.flags || []).length || (state.findings.algorithms || []).length)) ? `\n## 本题已收集的结论（勿重复劳动/勿推翻已验证项）\n${(state.findings.flags || []).map(f => `- Flag: ${f.flag}${f.verified ? '（✅已验证）' : '（⚠️未验证）'}`).join('\n')}\n${(state.findings.algorithms || []).length ? `- 已识别算法: ${state.findings.algorithms.map(a => (a && a.text) || a).join('; ')}` : ''}\n` : ''}

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

// Kali 远程预检（决策在 electron/kali-preflight.js，纯函数可单测）。
// 只测远程预检阶段耗时；skip 之后的 localFirmwareProbe 会 spawn Python，不计入。
// 探活缓存 120s，避免同一轮里反复握手。
const KALI_PREFLIGHT_TTL = 120000;
let _kaliProbeCache = { at: 0, reachable: false };

// 决策逻辑在主进程（electron/kali-preflight.js），渲染层只传事实、消费结论。
async function decideKaliPreflight(input) {
  try {
    const r = await window.electronAPI.kaliPreflightDecide(input);
    if (r && r.success) return r.decision;
  } catch (e) { /* 回退到最小本地判定 */ }
  return input && input.reachable
    ? { action: 'remote', log: '[Kali] 可达 → 远程命令' }
    : { action: 'skip', log: `[Kali] ${(input && input.port) || 22}/TIMEOUT → 跳过远程命令，使用本地兜底` };
}

async function decideKaliRemotePlan(input) {
  try {
    const r = await window.electronAPI.kaliRemotePlan(input);
    if (r && r.success) return r.plan;
  } catch (e) { /* 回退 */ }
  return input && input.reachable
    ? { reachable: true, commands: ['file', 'binwalk', 'strings'], note: '' }
    : { reachable: false, commands: [], note: '本地兜底只能给 magic/strings/熵，不能解包。' };
}

async function kaliPreflight() {
  const cfg = (state.config && state.config.kali) || {};
  const host = String(cfg.sshHost || '').trim();
  const port = Number(cfg.sshPort) || 22;
  const age = _kaliProbeCache.at ? (Date.now() - _kaliProbeCache.at) : null;

  let reachable = _kaliProbeCache.reachable;
  // 缓存过期或无缓存 → 探活（TCP 端口级；失败不抛）
  if (!host) {
    reachable = false;
  } else if (age == null || age >= KALI_PREFLIGHT_TTL) {
    try {
      const p = await window.electronAPI.checkPort(`http://${host}:${port}`);
      reachable = !!(p && p.listening);
    } catch (e) {
      reachable = false;
    }
    _kaliProbeCache = { at: Date.now(), reachable };
  }

  if (!host) {
    return { action: 'skip', log: `[Kali] ${port}/TIMEOUT → 跳过远程命令，使用本地兜底（未配置 sshHost）`, plan: await decideKaliRemotePlan({ reachable: false }) };
  }
  const d = await decideKaliPreflight({ reachable, cacheAgeMs: age, ttlMs: KALI_PREFLIGHT_TTL, host, port });
  d.plan = await decideKaliRemotePlan({ reachable: d.action === 'remote', capabilities: state._capabilities });
  return d;
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
//
// 诱饵（decoy）过滤：多阶段题**普遍**在某一层埋假 flag 诱导（实测 Disguise 第一层的校验表
// 解出 "This is a fake flag"，工具却把"中间值命中"当成 ✅ 记下来，看起来像"解出来了"）。
// 真 flag 不会是这种自曝身份的串——按形态直接剔除，避免"假成功"污染结论与经验库。
const DECOY_FLAG_RE = /(fake|decoy|dummy|placeholder|not[\s_-]*(the[\s_-]*)?real|try[\s_-]*again|wrong[\s_-]*flag|假\s*flag|这不是|诱饵)/i;
function isDecoyFlag(s) {
  return DECOY_FLAG_RE.test(String(s || ''));
}
// 常见哈希的"退化输入"摘要：空串/全零/单字符等，说明输入根本没取到，不是解出 flag。
// 实测（findKey）：工具算出 `d41d8cd98f00b204e9800998ecf8427e` 并当成 flag 提交，
// 而那是**空字符串的 MD5**——真实含义是"待哈希的输入为空"。
const DEGENERATE_DIGESTS = new Set([
  'd41d8cd98f00b204e9800998ecf8427e',   // md5("")
  'da39a3ee5e6b4b0d3255bfef95601890afd80709', // sha1("")
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // sha256("")
  '00000000000000000000000000000000',
  '0cc175b9c0f1b6a831c399e269772661',   // md5("a")
  '900150983cd24fb0d6963f7d28e17f72',   // md5("abc") —— 常被用作占位
]);

function isDegenerateDigest(s) {
  const t = String(s || '').toLowerCase();
  // 同时接受 flag{...} 包裹的形态
  const inner = (t.match(/\{([^}]+)\}/) || [, t])[1];
  return DEGENERATE_DIGESTS.has(inner.trim());
}

// ===== 本地枚举纪律（纯函数；与 electron/verify-discipline.js 语义一致） =====
// 只要存在假设就必须执行：与 vr 是否为 null 无关（无 [VERIFY] 时 vr=null）。
function shouldRunHypotheses(vr, hypothesisCount) {
  return Number(hypothesisCount) > 0;
}

const CIPHERTEXT_ALGOS_RE = /^(aes|des|3des|blowfish|sm4|rc4|tea|xtea|xxtea|chacha|salsa|camellia|twofish|present|aria|base64|hex)/i;

// 仅三种 invalid：(a) 算法需密文但密文为空；(b) 输入非空输出为空；(c) 退化摘要输出。
// 无 key 的合法变换（algo=custom/node_js 且带 code）必须放行。
function validateCandidateAttempt(a) {
  const att = a || {};
  const algo = String(att.algo || '').trim();
  const ct = String(att.ciphertext == null ? '' : att.ciphertext).trim();
  const out = String(att.output == null ? '' : att.output).trim();
  if (CIPHERTEXT_ALGOS_RE.test(algo) && !ct) {
    return { ok: false, reason: `algo=${algo} 需要密文，但 ciphertext 为空` };
  }
  if (ct && !out) return { ok: false, reason: '输入非空但输出为空（解密/变换未真正执行）' };
  if (out && isDegenerateDigest(out)) return { ok: false, reason: `输出是退化摘要 ${out}（说明输入没取到）` };
  return { ok: true, reason: '' };
}

// 结构化尝试记录（algo/key/ct/错误/结论）
function recordAttemptRecord(a, result) {
  const att = a || {};
  const r = result || {};
  return {
    algo: String(att.algo || ''),
    key: att.key == null ? '' : String(att.key),
    key_encoding: String(att.key_encoding || ''),
    ciphertext_len: String(att.ciphertext == null ? '' : att.ciphertext).replace(/\s+/g, '').length,
    error: r.error == null ? '' : String(r.error),
    output_len: String(r.output == null ? '' : r.output).length,
    valid: r.valid === undefined ? true : !!r.valid,
    hit: !!r.hit,
    reason: r.reason == null ? '' : String(r.reason),
    ts: new Date().toISOString(),
  };
}

function looksLikeFlag(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s || s.length < 5 || s.length > 300) return false;
  if (isDecoyFlag(s)) return false;                       // 诱饵串不进 flag 库
  if (isDegenerateDigest(s)) return false;                // 退化哈希（空输入）不是 flag
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

// 登记"裸答案"（口令/序列号/裸字符串）——**不经** looksLikeFlag 过滤。
// 为什么需要（CrackMe3）：AI 第一轮就给出并自证了 771535（本地复现 sum==0x2979），
// recordFlag 因它不是 `xxx{...}` 形态直接 return，最终 flags 为空、整题记为未解出。
// 但"不是 flag 形态"不等于"不是答案"——平台题面常常要求答题者自己包壳。
// 是否可信由 verified 标记承担，绝不在这里默认标 verified。
function recordAnswer(value, opts = {}) {
  if (!state.findings) return;
  const v = String(value == null ? '' : value).trim();
  if (!v || v.length < 2 || v.length > 200) return;
  // 已经是 flag 形态的走 recordFlag，不重复记
  if (looksLikeFlag(v)) { recordFlag(v, opts.source || 'ai', !!opts.verified); return; }
  if (!Array.isArray(state.findings.answers)) state.findings.answers = [];
  const existing = state.findings.answers.find(a => a.value === v);
  if (existing) {
    if (opts.verified) existing.verified = true;
    if (opts.source && !String(existing.source).includes(opts.source)) existing.source += ',' + opts.source;
    if (opts.evidence) existing.evidence = opts.evidence;
  } else {
    state.findings.answers.push({
      value: v,
      verified: !!opts.verified,
      source: opts.source || 'ai',
      evidence: opts.evidence || '',
      ts: new Date().toISOString(),
    });
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

// [VERIFY] 契约里 algo 的**唯一权威清单**。
// 教训：此前 5 处提示词各写一份、内容漂移，其中有的漏了 chacha20 → 求解器也没实现，
// 导致"契约承诺支持但本地复现报 unknown algo"。此处集中一份，且必须与 buildSolvePython
// 里的分支保持同步（新增算法：改这里 + 加求解器分支，两处一起改）。
const VERIFY_ALGOS = 'rc4|tea|xtea|xxtea|xor|aes_ecb|aes_cbc|des_ecb|des_cbc|des3_ecb|sm4_ecb|sm4_cbc|sm3|chacha20|salsa20|base64|base64_custom|node_js|custom';
// 完整契约示例（含 iv/code 等可选字段说明），供各提示词统一插值。
const VERIFY_CONTRACT = `[VERIFY]{"algo":"${VERIFY_ALGOS}","key":"密钥","key_encoding":"ascii|hex","ciphertext":"密文","encoding":"hex|base64|ascii","expected":"flag或前缀","iv":"(aes_cbc/des_cbc/chacha20 需要；chacha20 的 iv 可为 12B nonce 或 16B=nonce12+counter4)","iv_encoding":"ascii|hex|base64","counter":"(chacha20 可选，counter 初值；不给则自动枚举)","code":"(custom/node_js 需要)完整函数"}[/VERIFY]`;

function buildSolvePython(attempts) {
  // 契约走 base64 内嵌：AI 的 custom code 可能含 ''' / 反斜杠等，任何引号方案都会碎
  const payload = utf8ToBase64(JSON.stringify(attempts));
  return `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auto-generated by ctf-tool: verify / hypotheses enumeration
import base64, json, re, struct, sys

ATTEMPTS = json.loads(base64.b64decode("${payload}").decode("utf-8"))
_hit_seen = set()   # 全局 [HIT] 去重（多 key 候选中同一 flag 只报一次）

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
    # k 既可能是字节串（循环异或），也可能是"单字节密钥"的整数（pyc 题里 xor_key=199 极常见，
    # 且 AI 常把 199 写成字符串）。
    try:
        if isinstance(k, (bytes, bytearray)):
            kb = bytes(k)
        else:
            s = str(k).strip()
            if re.fullmatch(r"\\d+", s):          # 十进制整数 → 单字节
                kb = bytes([int(s) & 0xff])
            elif re.fullmatch(r"0x[0-9a-fA-F]+", s):
                kb = bytes([int(s, 16) & 0xff])
            else:
                kb = s.encode("latin-1", "replace")
    except Exception:
        kb = b""
    if not kb:
        return d
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(d))

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

def _sm4_cbc_raw(d, k, mode, iv):
    """CBC 单次解密（供 dec_cbc_multi 复用，签名与 dec_aes/dec_des 一致）。
    注意 gmssl 各版本 crypt_cbc 签名不同：本机新版只接受 (iv, input_data)，无 pkcs7_unpadding 参数
    → 不能传该 kwarg（传了会 TypeError 导致全部候选失败）。"""
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    c = CryptSM4(); c.set_key(k, SM4_DECRYPT)
    try:
        return bytes(c.crypt_cbc(bytes(iv), bytes(d)))
    except TypeError:
        # 老版本带 pkcs7_unpadding 形参时，显式关闭自动去填充（避免非 PKCS7 密文被误剥）
        return bytes(c.crypt_cbc(bytes(iv), bytes(d), pkcs7_unpadding=False))

def dec_sm4_cbc(d, k, ivb):
    """SM4-CBC：复用通用多候选逻辑（全零IV/密文首块/前置IV + 回退 ECB），按 _pt_score 择优。
    旧实现有两个真 bug：(1) 判据 "isprintable 占比>=0.9" 对 printable() 返回的 hex 恒真
    → 永远只试第一个 IV，兜底候选是死代码；(2) 全候选失败时返回原密文 → run_one 里
    _pt_score 对含 flag 形态的密文给 4 分 → 报出"输入当 flag"的假 [HIT]。"""
    return dec_cbc_multi(d, k, ivb, _sm4_cbc_raw, 16, ecbfn=lambda dd, kk, m: dec_sm4(dd, kk))

def dec_sm3(d, k=None):
    """SM3 是哈希（不可逆），不能"解密"。此处返回 None 表示"该 algo 不产出明文"——
    run_one 见到 None 会走 ERR 分支，绝不把它塞进 [HIT]（旧实现返回摘要/原数据，
    会把 64 位 hex 摘要或输入的 flag 串当 flag 上报，是明确的假阳性通道）。"""
    return None

def dec_chacha20(d, k, nonce, counter=0, variant="chacha20"):
    """ChaCha20 stream cipher. nonce: 12B (IETF, 32-bit counter) or 8B (original, 64-bit counter).
    counter: initial block counter (many CTF binaries start at 1, not 0!) — handled via seek(64*counter)."""
    from Crypto.Cipher import ChaCha20
    c = ChaCha20.new(key=k, nonce=nonce)
    if counter:
        c.seek(64 * int(counter))
    return c.decrypt(d)

def dec_chacha20_try(d, k, ivb, explicit_ctr=None):
    """枚举 counter/大小端候选：CTF 里 counter 编码极易搞错（本题 iv=nonce12+counter4，
    counter 是大端 1；但若按小端读会变成 16777216）。这里把所有合理候选都试一遍，
    返回第一个解出可打印/flag 形态的结果；都不行则返回第一个候选。"""
    cands = []
    nonce = ivb
    ctrs = []
    if explicit_ctr is not None:
        ctrs = [int(explicit_ctr)]
    elif ivb and len(ivb) == 16:
        nonce = ivb[:12]
        ctrs = [int.from_bytes(ivb[12:16], "big"), int.from_bytes(ivb[12:16], "little"), 0, 1]
    elif ivb and len(ivb) == 12:
        ctrs = [0, 1]
    elif ivb and len(ivb) == 8:
        ctrs = [0, 1]
    else:
        ctrs = [0, 1]
    seen = set()
    for ctr in ctrs:
        if ctr in seen:
            continue
        seen.add(ctr)
        try:
            out = dec_chacha20(d, k, nonce, ctr)
            cands.append(out)
            if FLAG_RE.search(out):
                return out
            t = printable(out)
            if t.startswith("flag{") or t.startswith("ctf{"):
                return out
        except Exception:
            pass
    return cands[0] if cands else b""

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
        # 协议封装明文常带控制字符头尾（如 \x03\x11+len 用户名）：只剥首尾控制符，
        # 主体可打印即返回可读文本——否则整段回退 hex，flag 就被埋进 hex 里没人认得。
        CTRL = bytes(range(0, 9)) + bytes(range(11, 13)) + bytes(range(14, 32))
        core = t.strip(CTRL.decode("latin-1"))
        if core and all(ch.isprintable() or ch in "\\r\\n\\t" for ch in core):
            return core
        if all(ch.isprintable() or ch in "\\r\\n\\t" for ch in t):
            return t
    except Exception:
        pass
    return b.hex()

def _to_bytes_out(x):
    """把解密函数返回值统一成 bytes。AI 的 custom decrypt 常返回 str / list[int] / bytearray。"""
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("latin-1", "replace")
    if isinstance(x, (list, tuple)):
        try:
            return bytes([int(v) & 0xff for v in x])
        except Exception:
            return None
    return str(x).encode("latin-1", "replace")

def _unpad(b):
    """剥掉 PKCS#5/#7 尾部填充（1~16 且末 n 字节都等于 n），让"带填充的正确明文"
    在打分时不被误判为不可打印（否则 ECB 候选会因尾部 0x05 得 0 分而输给错误候选）。"""
    if not b:
        return b
    n = b[-1]
    if 1 <= n <= 16 and len(b) >= n and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b

def _pt_score(b):
    """给一个解密结果打分，用于在"多候选"里挑最像 flag 的那个（4=flag 形态，0=不可打印）。
    注意：CBC 用错 IV 时**只有第 1 块被打乱**，第 2 块起仍是正确明文（flag 常跨块出现），
    因此不能要求"整段全可打印"，否则会把"错 IV 但含 flag"的候选误判为 0 分丢弃。
    故：先在原始字节上找 flag 形态（最高优先），再用"可打印比例"给一般结果打分。"""
    if not b:
        return 0
    ub = _unpad(b)
    if FLAG_RE.search(ub):
        return 4
    try:
        t = ub.decode("utf-8", "replace")
    except Exception:
        return 0
    tot = len(t)
    if tot == 0:
        return 0
    ok = sum(1 for ch in t if ch.isprintable() or ch in "\\r\\n\\t")
    if (ok / tot) < 0.85:
        return 0
    if "{" in t and "}" in t:
        return 3
    if any(x in t.lower() for x in ("flag", "ctf", "key=", "secret")):
        return 2
    return 1

def key_candidates(spec, ke):
    """密钥候选：显式编码解出的字节 + 原文 lating-1 + AES 长度兜底(md5/sha256/零填充)。
    解决"AI 给的 key 不是 16/24/32 字节（如口令）"导致 AES 直接抛错的情况。"""
    import hashlib
    out = []
    try:
        base = to_bytes(spec or "", ke)
    except Exception:
        base = b""
    if base:
        out.append(base)
    try:
        raw = str(spec).encode("latin-1", "replace")
    except Exception:
        raw = b""
    if raw and raw not in out:
        out.append(raw)
    # 单字节整数密钥：pyc/简单题里 xor_key=199 很常见，AI 常直接写成 "199"。
    # 此时真正参与异或的是**一个字节 0xC7**，而非 b"199" —— 必须补上这个候选。
    try:
        sv = str(spec).strip()
        if re.fullmatch(r"\\d+", sv) and 0 <= int(sv) <= 255:
            b1 = bytes([int(sv)])
            if b1 not in out:
                out.append(b1)
        elif re.fullmatch(r"0x[0-9a-fA-F]{1,2}", sv):
            b1 = bytes([int(sv, 16)])
            if b1 not in out:
                out.append(b1)
    except Exception:
        pass
    src = base or raw
    if src:
        try:
            out.append(hashlib.md5(src).digest())
        except Exception:
            pass
        try:
            out.append(hashlib.sha256(src).digest()[:32])
        except Exception:
            pass
        if len(src) < 16:
            out.append(src + b"\\x00" * (16 - len(src)))
    seen = set()
    uniq = []
    for b in out:
        if b and b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq

def dec_cbc_multi(d, k, ivb, decfn, block, ecbfn=None):
    """CBC 多候选解密：IV 缺失/给错时枚举 全零IV / 密文首块当IV / 前置IV(解 d[block:] 用 d[:block])；
    CBC 全失败再回退 ECB。返回得分最高的明文（flag 形态优先），全失败返回 b""。
    解决"契约没给 iv（或给了非块长）→ 单个契约必然无命中"的通用坑。"""
    best = None
    bestsc = -1
    cands = []
    if ivb and len(ivb) == block:
        cands.append((ivb, d))
    cands.append((b"\\x00" * block, d))
    if len(d) > block:
        cands.append((d[:block], d))
        cands.append((d[:block], d[block:]))       # 前置IV 模式：密文 = IV || body
    if len(d) >= 2 * block:
        cands.append((d[-block:], d))
    for iv, dd in cands:
        try:
            out = decfn(dd, k, "cbc", iv)
        except Exception:
            continue
        sc = _pt_score(out)
        if sc > bestsc:
            bestsc = sc
            best = out
        if sc >= 4:
            return out
    if ecbfn:
        try:
            out = ecbfn(d, k, "ecb")
            sc = _pt_score(out)
            if sc > bestsc:
                bestsc = sc
                best = out
        except Exception:
            pass
    return best if best is not None else b""

def dec_aes_cbc_multi(d, k, ivb):
    return dec_cbc_multi(d, k, ivb, dec_aes, 16, ecbfn=dec_aes)

def dec_des_cbc_multi(d, k, ivb):
    return dec_cbc_multi(d, k, ivb, dec_des, 8, ecbfn=dec_des)

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
        kcands = key_candidates(keyspec, ke) or [b""]
        for k in kcands:
            try:
                if algo == "custom":
                    ns = {}
                    exec(a["code"], ns)
                    fn = ns.get("decrypt") or ns.get("custom_decrypt") or ns.get("solve") or ns.get("decrypt_flag")
                    if fn is None:
                        raise RuntimeError("code 未定义 decrypt 函数（找过 decrypt/custom_decrypt/solve/decrypt_flag）")
                    # 调用形态自适应（AI 写法五花八门，参数个数不一致是本地复现失败的头号原因）：
                    #   ①decrypt(target) 单参（数据变换/置换类题的标准写法）
                    #   ②decrypt(ct_bytes, key_bytes) 二参 bytes
                    #   ③decrypt(raw_ct_str, raw_key_str) 二参原文（函数内部自己 base64/hex 解码）
                    #   ④decrypt(ct_bytes, key=keyspec) 关键字参
                    # 全部失败才报错；用 inspect 判形参个数优先尝试最可能形态，减少无效异常噪音。
                    raw_ct = a.get("ciphertext", "")
                    raw_key = "" if keyspec is None else str(keyspec)
                    import inspect as _inspect
                    try:
                        arity = len(_inspect.signature(fn).parameters)
                    except Exception:
                        arity = None
                    order = []
                    if arity == 1:
                        order = [("raw", raw_ct, None), ("bytes", ct, None)]
                    else:
                        order = [
                            ("raw2", raw_ct, raw_key),
                            ("bytes2", ct, k),
                            ("raw1", raw_ct, None),
                            ("bytes1", ct, None),
                            ("kw", ct, keyspec),
                        ]
                    out = None
                    last_err = None
                    for tag, d1, d2 in order:
                        try:
                            if d2 is None:
                                out = fn(d1)
                            elif tag == "kw":
                                out = fn(d1, key=d2)
                            else:
                                out = fn(d1, d2)
                            break
                        except TypeError as e:
                            last_err = e
                            continue
                    if out is None and last_err is not None:
                        raise last_err
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
                    # IV 用独立编码（iv_encoding），默认自适应；关键：**IV 缺失/给错时不直接失败**，
                    # 而是枚举 IV 候选（全零/密文首块/前置IV）并回退 ECB —— 否则"单契约缺 iv"必然无命中。
                    out = dec_aes_cbc_multi(ct, k, iv_bytes(a))
                elif algo == "des_ecb":
                    out = dec_des(ct, k, "ecb")
                elif algo == "des_cbc":
                    out = dec_des_cbc_multi(ct, k, iv_bytes(a))
                elif algo == "des3_ecb":
                    out = dec_des3(ct, k)
                elif algo == "sm4_ecb":
                    out = dec_sm4(ct, k)
                elif algo == "sm4_cbc":
                    out = dec_sm4_cbc(ct, k, iv_bytes(a))
                elif algo == "sm3":
                    out = dec_sm3(ct, k)
                elif algo in ("chacha20", "chacha20_ietf", "chacha20_original", "salsa20"):
                    # ChaCha20：key 32B，nonce 12B(IETF)/8B(original)。
                    # iv 字段可能给 12B nonce，或 16B「nonce(12B)+counter(4B)」（本项目约定）。
                    # counter 初值常非 0（本题=1）且大小端易错 → 交给 dec_chacha20_try 枚举候选。
                    ivb = iv_bytes(a)
                    ctr = a.get("counter")
                    out = dec_chacha20_try(ct, k, ivb, ctr)
                elif algo == "base64":
                    out = dec_b64(ct)
                elif algo == "base64_custom":
                    out = dec_b64(ct, a.get("table"))
                elif algo == "node_js":
                    out = dec_node_js(a.get("code", ""), a.get("input", a.get("ciphertext", "")))
                else:
                    outs.append((ke, "unknown algo " + algo)); break
            except Exception as e:
                # 结构化失败归因（Phase 3）：把"哪一步、什么错"显式打出，便于工具汇总回灌给 AI，
                # 而不是让 AI 自己去读 traceback 猜。
                _fail_reason = type(e).__name__ + ": " + str(e)[:160]
                outs.append((ke, "ERR: " + _fail_reason))
                print("[FAIL] attempt=%d algo=%s keyenc=%s stage=decrypt reason=%s" % (i, algo, ke, _fail_reason.replace("\\n", " ")))
                continue
            # 归一化：AI 的 custom decrypt 常返回 str（甚至 list[int]/None），
            # 而下游 printable/FLAG_RE 都按 bytes 处理 —— 必须先转 bytes，否则直接崩。
            out = _to_bytes_out(out)
            if out is None:
                outs.append((ke, "ERR: decrypt 返回不可用类型")); continue
            pt = printable(out)
            outs.append((ke, pt))
            m = FLAG_RE.search(out)
            # expected 匹配分级（AI 常把 expected 截断成 flag 前缀，如只给 "dice{P4ra..."）：
            #   完全相等 / 解密结果包含 expected / expected 包含解密结果（AI 截断了明文一侧）
            # → 都算命中；命中值优先取 FLAG_RE 完整匹配，其次取解密结果全文（完整 flag 比截断前缀有价值）。
            exp_hit = False
            if exp:
                ptl = pt.lower()
                if exp in ptl or (ptl and ptl in exp):
                    exp_hit = True
            # ⚠️ 命中判据（v1.7.4 修正）：
            #   旧实现要求 _pt_score(out) >= 4，而 _pt_score 只在"已知 flag 前缀"或"含 {}"时给
            #   4 分/3 分——一道题的 flag 若不是常见前缀（如 ae s{...}、或纯文本答案），
            #   即使解对了也只得 1 分 → 被判定"契约无命中"，实测 6 道题卡在这里。
            #   现在补一档：**高可打印比例（≥0.95）且长度≥8** 也算命中候选（但仍标 low confidence，
            #   交给下游 finalizeSolve 用 looksLikeFlag 复核 + 平台提交验证）。
            _ps = _pt_score(out)
            _pt_ratio = 0.0
            try:
                _txt = _unpad(out).decode("utf-8", "replace")
                if _txt:
                    _pt_ratio = sum(1 for ch in _txt if ch.isprintable() or ch in "\\r\\n\\t") / len(_txt)
            except Exception:
                _pt_ratio = 0.0
            _is_texty = bool(out) and len(_unpad(out)) >= 8 and _pt_ratio >= 0.95
            hit = exp_hit or bool(m) or _ps >= 4 or (_is_texty and _ps >= 1)
            if hit:
                if m:
                    fl = m.group(0).decode("utf-8", "ignore")
                elif exp_hit and len(pt) >= len(exp):
                    fl = pt.strip()
                elif _is_texty and not exp_hit:
                    # 无 expected 但解出高可打印文本 → 用明文本身（下游复核）
                    fl = _unpad(out).decode("utf-8", "replace").strip()
                else:
                    fl = exp
                # 去重：同一 attempt 内多个 key 候选常解出**同一个** flag（如 key "199" 的
                # ascii/int 两个候选），只打印一次，避免下游把重复 [HIT] 当多个候选。
                if fl not in _hit_seen:
                    _hit_seen.add(fl)
                    print("[HIT] attempt=%d keyenc=%s algo=%s flag=%s" % (i, ke, algo, fl))
            else:
                # 结构化"解密成功但没出 flag"（Phase 3 归因）：区分可打印/乱码/空，
                # 便于工具判断是"算法对但 key/iv 错"还是"算法本身选错"。
                if not out:
                    _st = "empty"
                elif _pt_score(out) == 0:
                    _st = "garbage"
                else:
                    _st = "no-flag"
                print("[MISS] attempt=%d algo=%s keyenc=%s stage=verify result=%s preview=%s"
                      % (i, algo, ke, _st, pt[:80].replace("\\n", " ")))
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
  // getScriptsDir() 已经返回 .../scripts，不能再拼 /scripts（否则生成 scripts/scripts/）。
  const scriptsBase = state.caseDir ? `${state.caseDir}/scripts` : await getScriptsDir();
  const scriptPath = `${scriptsBase}/solve_enum_${Date.now().toString(36)}.py`;
  await window.electronAPI.ensureDir(scriptsBase);
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

// ============ 多候选密文交叉校验 ============
// 背景（实战教训）：native so 里常存在**多组**加密常量（如本题 sub_24C40 初始化的是
// std::array<std::string,8> —— 8 条 hex 串）。若只取"第一条"就当密文，遇到"变种题"
// （密文被换过、key/nonce 不变）会算出**自洽但版本不对**的 flag：
//   encrypt(候选flag) == 该密文  ✔ 但那条密文根本不是 App 真正比对的那条。
// 因此这里从 native intel 里抽全部 hex 常量作为候选，与 AI 给的密文并列，让本地求解
// 逐个尝试并报告"哪些候选能出 flag"，由 AI/人工按"是否被校验函数引用"定案。
function extractNativeCandidates(intel) {
  intel = intel || {};
  const blobs = [];
  // 1) 全局数据表（get_bytes 的 data 字段是 "0x.. 0x.." 形式；带 addr）
  for (const g of (intel.globals || [])) {
    const hex = String(g.data || '').replace(/0x|\s+/g, '');
    if (hex) blobs.push({ src: `global:${g.name || g.addr}`, hex, addr: g.addr || '', name: g.name || '' });
  }
  // 2) 数据段 dump（addr 是段起始，一般不是常量精确地址，仅作兜底来源）
  for (const s of (intel.segments || [])) {
    const hex = String(s.data || '').replace(/0x|\s+/g, '');
    if (hex) blobs.push({ src: `segment:${s.name || s.addr}`, hex, addr: s.addr || '', name: s.name || '' });
  }
  // 3) 关键字符串里的 hex 长串（渲染形如 "0xADDR  HEX..."，解析出 addr）
  for (const line of String(intel.strings || '').split('\n')) {
    const m = line.match(/^\s*(0x[0-9a-fA-F]+)\s+([0-9a-fA-F]{32,})/);
    if (m) blobs.push({ src: `string@${m[1]}`, hex: m[2], addr: m[1], name: '' });
    else {
      const m2 = line.match(/([0-9a-fA-F]{32,})/);
      if (m2) blobs.push({ src: 'string', hex: m2[1], addr: '', name: '' });
    }
  }
  // 4) 反编译代码里出现的"长 hex 字符串字面量"（C++ 静态初始化常见；无 addr，靠 xref 名称间接定位）
  for (const d of (intel.decompiled || [])) {
    const code = String(d.code || '');
    for (const m of code.matchAll(/"([0-9a-fA-F]{32,})"/g)) blobs.push({ src: `code:${d.name}`, hex: m[1], addr: '', name: '' });
  }
  // 归一化：只保留偶数长度、长度像"密文/常量"的十六进制串（16B~128B 最像密文/密钥），去重
  const out = [];
  const seen = new Set();
  for (const b of blobs) {
    const hex = b.hex.toLowerCase();
    if (hex.length % 2 !== 0) continue;
    const bytes = hex.length / 2;
    // 只收 16~128 字节：太短不像密文，太长多半是整段 .rodata（当密文试没意义且拖慢）
    if (bytes < 16 || bytes > 128) continue;
    const key = hex.slice(0, 24) + ':' + hex.length;   // 去重键（前 12 字节 + 长度）
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ src: b.src, hex, addr: b.addr || '', name: b.name || '' });
    if (out.length >= 24) break;                       // 上限，防爆（24 组够覆盖"多常量"场景）
  }
  return out;
}

// 按需反编译一个函数（不在预采集集合里时）；结果缓存 + 全局上限，失败静默。
// budget：{ n } 可变计数器，防止候选多时触发过多 decompile 调用。
async function probeFnCode(name, cache, budget) {
  if (!name) return '';
  if (cache.has(name)) return cache.get(name);
  if (budget && budget.n <= 0) return '';
  let code = '';
  try {
    if (budget) budget.n--;
    const r = await window.electronAPI.idaMcpCall('decompile', { address: name });
    if (r && r.success && r.result) code = typeof r.result === 'string' ? r.result : (r.result.code || JSON.stringify(r.result));
  } catch (e) { /* 忽略 */ }
  cache.set(name, code || '');
  return code || '';
}

// 尝试用 IDA trace_data_flow 判断"常量地址是否流向某个比较点"（更强的判据，可用则加分）。
// 该工具在部分 ida-pro-mcp 版本存在；不存在/参数不符时静默跳过返回 0。
// 收紧策略：结果必须非空、且不是"未找到/无流"类回应，避免给所有候选都加同样分而失去区分度。
async function probeDataFlow(addr, cmpFnNames) {
  if (!addr) return { ok: false, score: 0, note: '' };
  try {
    const r = await window.electronAPI.idaMcpCall('trace_data_flow', { addr });
    if (!r || !r.success || !r.result) return { ok: false, score: 0, note: '' };
    const txt = (typeof r.result === 'string' ? r.result : JSON.stringify(r.result)).trim();
    if (!txt || txt.length < 8) return { ok: false, score: 0, note: '' };
    // "无流/未找到/空结果"类回应 → 不加分（否则每个候选都 +2，裁决退化）
    if (/no\s*flow|not\s*found|no\s*path|empty|none\b|未找到|无数据|无流向|null/i.test(txt)) return { ok: false, score: 0, note: '' };
    // 路径里出现"已知比较函数名" → 最强信号
    if (cmpFnNames.some(n => n && txt.includes(n))) return { ok: true, score: 4, note: 'trace_data_flow→比较函数' };
    // 命中比较/解密调用（且文本确实描述了路径，非泛化空话）
    if (/memcmp|strcmp|compare|equals/i.test(txt) && /decrypt|cipher|chacha|tea|rc4|aes|expand|key/i.test(txt)) {
      return { ok: true, score: 3, note: 'trace_data_flow→比较+解密' };
    }
    return { ok: true, score: 0, note: '' };
  } catch (e) { return { ok: false, score: 0, note: '' }; }
}

// ============ 自动裁决"权威密文"（哪条被校验函数真正引用）============
// 思路（在有 IDA MCP 时可用，纯静态启发式、失败即静默降级）：
//   对每个带地址的候选常量，查 IDA xrefs_to → 找出"引用它的函数"；
//   若该引用函数（在预采集集合里，或**按需反编译**后）代码含比较语义
//   （memcmp/strcmp/==/Arrays.equals，或对解密结果做逐字节比较），则该候选极可能是"真校验用的那条"。
//   叠加两类加分：候选符号名出现在比较类函数文本中；trace_data_flow 显示常量流向比较点。
// 返回按可信度降序的候选列表，每项附 { refFns:[], score, authoritative:bool, why:[] }。
async function rankCandidatesByXref(cands, intel) {
  intel = intel || {};
  if (!Array.isArray(cands) || !cands.length) return cands || [];
  // 已反编译函数名集合 + 各函数代码（用于判断"引用它的函数是否做比较"）
  const decMap = new Map();
  for (const d of (intel.decompiled || [])) decMap.set(String(d.name || ''), String(d.code || ''));
  const fnCache = new Map();  // 按需反编译缓存（含 decMap 命中）
  for (const [n, c] of decMap) fnCache.set(n, c);
  const CMP_RE = /memcmp|strcmp|strncmp|Arrays\s*\.?\s*equals|\.equals\s*\(|==|!=/;
  const refCache = new Map();  // addr -> xrefs
  const decBudget = { n: 16 };  // 按需 decompile 总上限（覆盖"引用函数不在预采集集合"的情形）
  let queried = 0;
  for (const k of cands) {
    let score = 0;
    const refFns = [];
    const why = [];
    const addr = String(k.addr || '').trim();
    if (addr && queried < 12) {                 // 最多查 12 个，控成本
      try {
        if (!refCache.has(addr)) {
          const r = await window.electronAPI.idaMcpCall('xrefs_to', { addrs: [addr] });
          refCache.set(addr, (r && r.success && r.result) || null);
        }
        const xr = refCache.get(addr);
        // 归一化各种返回形态：
        //   [{addr, xrefs:[...]}]（实测 ida-pro-mcp）/ {addr, xrefs:[...]} / {addrs:[...]} / 直接 xrefs:[...]
        let list = [];
        if (Array.isArray(xr)) list = xr;
        else if (xr && Array.isArray(xr.addrs)) list = xr.addrs;
        else if (xr && Array.isArray(xr.xrefs)) list = [xr];
        else if (xr && typeof xr === 'object') list = [xr];
        for (const item of list) {
          const xrefs = (item && item.xrefs) || [];
          for (const x of xrefs) {
            // fn 可能是对象 {name}、字符串(函数名)，或 xref 自带 name/func_name
            let fnName = '';
            if (x && typeof x.fn === 'string') fnName = x.fn;
            else if (x && x.fn && x.fn.name) fnName = x.fn.name;
            else if (x && (x.name || x.func_name)) fnName = x.name || x.func_name;
            if (!fnName) continue;
            refFns.push(fnName);
            // 引用它的函数代码：优先预采集，其次**按需反编译**（更强覆盖，不再局限于 28 个）
            let code = fnCache.get(fnName);
            if (code === undefined) code = await probeFnCode(fnName, fnCache, decBudget);
            if (code) {
              score += 3;                                    // 引用函数可读到代码
              if (CMP_RE.test(code)) { score += 3; why.push(`${fnName} 含比较语义`); }
            }
          }
        }
        queried++;
      } catch (e) { /* xref 失败不影响主流程 */ }
    }
    k.refFns = [...new Set(refFns)];
    k.why = why;
    k.score = score;
  }
  // 符号名出现在"比较类函数"文本里 → 加分（无 addr 的候选也能受益）
  const cmpText = [...fnCache.values()].filter(c => CMP_RE.test(String(c))).join('\n');
  for (const k of cands) {
    if (k.name && cmpText.includes(k.name)) { k.score = (k.score || 0) + 2; (k.why = k.why || []).push('符号名出现在比较函数'); }
    if (k.addr && cmpText.includes(String(k.addr).toLowerCase())) { k.score = (k.score || 0) + 2; (k.why = k.why || []).push('地址出现在比较函数'); }
  }
  // 最强判据：trace_data_flow（可用时）—— 常量地址是否流向比较点。
  // 仅对"已有 xref 命中"的候选查（无引用的候选没必要查），且总量限 6 次，控成本。
  const cmpFnNames = [...fnCache.keys()].filter(n => CMP_RE.test(String(fnCache.get(n) || '')));
  let dfBudget = 6;
  for (const k of cands) {
    if (!k.addr || !(k.refFns && k.refFns.length)) continue;
    if (dfBudget <= 0) break;
    dfBudget--;
    const df = await probeDataFlow(k.addr, cmpFnNames);
    if (df.ok && df.score > 0) { k.score = (k.score || 0) + df.score; (k.why = k.why || []).push(df.note); k.dataFlow = true; }
  }
  cands.sort((a, b) => (b.score || 0) - (a.score || 0));
  // 只有"最高分明显领先"时才标 authoritative（避免误判）：
  //  - 必须真有 xref（refFns 非空）或强名命中，不能只靠弱加分
  //  - 且分数需比第二名至少高 2 分（拉开差距），同分则不裁决（降级为告警）
  const top = cands[0];
  const second = cands[1];
  const topScore = (top && top.score) || 0;
  const hasRealRef = top && ((top.refFns && top.refFns.length) || (top.name && top.name.length));
  if (top && topScore >= 3 && hasRealRef && (cands.length === 1 || topScore - ((second && second.score) || 0) >= 2)) {
    top.authoritative = true;
  }
  return cands;
}


// 交叉校验：把"AI 给的密文"与"so 里抽到的候选密文"并列，用同一 key/iv/algo 逐个尝试，
// 报告每个候选能否解出 flag 形态结果。返回 { aiHit, nativeHits:[{src,hex,flag}], tried }
async function crossCheckCandidates(contract) {
  const c = contract || {};
  const flagRe = /^(?:flag|ctf|nctf|nssctf|sctf|dasctf|hgame|iscc|sictf|moectf|hnctf|bjdctf|gwht|picoctf|cyberpeace)\{/i;
  const intel = (mcpCache && mcpCache.nativeIntel) || {};
  let cands = extractNativeCandidates(intel);
  if (!cands.length) return { tried: 0, nativeHits: [], aiHit: null };
  // 用 IDA xrefs 给候选打分，标出"最像被校验函数引用的那条"（失败静默降级）
  try { cands = await rankCandidatesByXref(cands, intel); } catch (e) { /* 降级：保持原顺序 */ }

  const base = {
    algo: c.algo, key: c.key, key_encoding: c.key_encoding,
    encoding: c.encoding || 'hex', iv: c.iv, iv_encoding: c.iv_encoding, counter: c.counter,
  };
  // 构造 attempts：每个候选密文一份（AI 原密文也一起，便于对比）
  const attempts = [];
  const aiCt = String(c.ciphertext || '').replace(/0x|\s+/g, '').toLowerCase();
  attempts.push(Object.assign({}, base, { ciphertext: c.ciphertext, _src: 'AI' }));
  for (const k of cands) {
    if (k.hex === aiCt) continue;
    attempts.push(Object.assign({}, base, { ciphertext: k.hex, _src: k.src, _nativeHex: k.hex, _score: k.score || 0, _auth: !!k.authoritative, _refFns: k.refFns || [], _why: k.why || [] }));
  }
  if (attempts.length <= 1) return { tried: 0, nativeHits: [], aiHit: null };

  addLog('info', `[交叉校验] 从 so 抽到 ${cands.length} 组候选常量，连同 AI 密文共 ${attempts.length} 组，逐一出解...`);
  const r = await runContractScript(attempts);
  // runContractScript 只回 hits；为归因到具体候选，这里再解析 [HIT] 行的 attempt 序号
  const nativeHits = [];
  let aiHit = null;
  const re = /\[HIT\]\s*attempt=(\d+)[^\n]*?flag=([^\r\n]+)/gi;
  let m;
  while ((m = re.exec(r.output)) !== null) {
    const idx = Number(m[1]);
    const flag = m[2].trim();
    const a = attempts[idx] || {};
    if (a._src === 'AI') { aiHit = flag; continue; }
    // 只认 flag 形态
    if (flagRe.test(flag)) nativeHits.push({ src: a._src, hex: (a._nativeHex || '').slice(0, 32) + '…', flag, score: a._score || 0, authoritative: !!a._auth, refFns: a._refFns || [], why: a._why || [] });
  }
  // 每个候选（含未出 flag 的）带分排序，供裁决：authoritative 优先
  nativeHits.sort((a, b) => (b.authoritative - a.authoritative) || (b.score - a.score));
  // 若"被校验函数引用(authoritative)"的那条能出 flag，则它即权威答案
  const authHit = nativeHits.find(h => h.authoritative) || null;
  return { tried: attempts.length, nativeHits, aiHit, authHit, ranked: cands.map(k => ({ src: k.src, score: k.score || 0, authoritative: !!k.authoritative, refFns: k.refFns || [], why: k.why || [] })) };
}

// 【统一入口】验证闭环 + 失败自动枚举 + flag 登记（此前 7 处复制粘贴，语义已漂移：
//   有的用 `if (!vr)` 门控 recordFlag、有的无条件登记，源码字符串也各不相同）。
// 统一语义：先按 source 登记 AI 抽到的 flag（未验证，去重），再跑本地复现；复现失败
// 自动合成候选枚举；返回 { vr, flags, verifiedFlags } 供调用方拼结果消息。
async function verifyAndRecord(aiText, opts = {}) {
  const source = opts.source || 'ai';
  const noteSection = opts.noteSection || 'Flag';
  const flags = extractFlags(aiText);
  // 先登记（未验证）。runVerification 内部也会登记，但那是"有契约时"才走的分支；
  // 无契约时必须在此登记，否则 flag 会丢失。recordFlag 自带去重，重复登记无害。
  flags.forEach(f => recordFlag(f, source, false));
  const vr = await runVerification(aiText);
  // augmentSynth：走到这里说明契约已经失败（!vr.verified），
  // 此时即使 AI 给过 [HYPOTHESES]，也要追加工具合成的维度（P1）。
  // ⚠️ 门控不能写成 `if (vr && !vr.verified)`：没有 [VERIFY] 时 runVerification 返回 null，
  // 假设永远不会在本地执行（"最终轮没有任何契约被本地执行"的根因）。
  // 判定抽到 electron/verify-discipline.js（纯函数），与 vr 是否为 null 无关。
  const hypotheses = parseHypotheses(aiText);
  const synthCount = Array.isArray(vr && vr.contracts) ? vr.contracts.length : 0;
  if (shouldRunHypotheses(vr, hypotheses.length + synthCount)) {
    if (!vr) addLog('info', `[本地枚举] 无 [VERIFY] 但仍执行 ${hypotheses.length || synthCount} 组假设`);
    await runHypotheses(aiText, {
      synthFrom: (vr && vr.contracts) || state.lastVerifyContracts || undefined,
      augmentSynth: !!(vr && !vr.verified),
    });
  }

  // ── 契约驱动的"裸答案"判定（rank 5）──
  // 记 verified 的条件必须同时成立，绝不把"顺手给的 key"标成已验证：
  //   ① 值 V 出现在 extractFlags(aiText) 里（AI 明确把它当答案提出，含 [FLAG]V[/FLAG]）；
  //   ② 存在契约 c 使 String(c.key).trim() === V；
  //   ③ 该契约的本地复现产生了命中（vr.hits.length > 0）。
  // 实测（CrackMe3）：V=771535、c.key=771535、契约复现出 shellcode → 三条全中。
  //
  // ── 近失升级（40 题实测新增）──
  // ④ byHit：V 逐字出现在本地复现命中（vr.hits）里——AI 声明的答案被工具自己跑出来；
  // ⑤ byOutput：V 出现在复现的原始输出里（len≥6 且不是任何契约的密文本身，
  //    防"密文回显"假阳性）。equation 类（z3 直接解出 flag 但契约没建）靠这条救回。
  try {
    const hits = (vr && Array.isArray(vr.hits)) ? vr.hits : [];
    const contracts = (vr && Array.isArray(vr.contracts)) ? vr.contracts : [];
    const rawOut = String((vr && vr.rawOutput) || '');
    if (flags.length) {
      for (const v of flags) {
        const t = String(v || '').trim();
        if (!t) continue;
        const byKey = contracts.some(c => c && String(c.key == null ? '' : c.key).trim() === t);
        const byHit = hits.some(h => h != null && String(h).trim() === t);
        const byOutput = t.length >= 6 && rawOut.includes(t)
          && !rawOut.includes('keyenc=' + t)   // 编码标签（base64/hex…）不算答案证据
          && !contracts.some(c => c && String(c.ciphertext == null ? '' : c.ciphertext).replace(/\s+/g, '').trim() === t.replace(/\s+/g, ''));
        const okVerified = (byKey || byHit || byOutput) && (hits.length > 0 || byOutput);
        if (okVerified) {
          const why = byKey ? '契约 key 匹配' : (byHit ? '答案=本地复现命中值' : '答案出现在本地复现输出');
          recordAnswer(t, {
            source: byKey ? 'verify-contract-key' : (byHit ? 'verify-hit-match' : 'verify-output-match'),
            verified: true,
            evidence: `${why}（${t}，复现输出 ${rawOut.length} 字符/命中 ${hits.length} 条）`,
          });
          addLog('success', `[验证闭环] 裸答案 ${t} 经本地复现确认（${why}）`);
        } else {
          recordAnswer(t, { source: source, verified: false });
        }
      }
    }
    // 契约里出现但 AI 没在 [FLAG] 里明确提出的 key：只登记为未验证候选
    for (const c of contracts) {
      if (!c || c.key == null) continue;
      const k = String(c.key).trim();
      if (!k) continue;
      if (flags.some(f => String(f || '').trim() === k)) continue;
      recordAnswer(k, { source: 'verify-contract-key(unstated)', verified: false });
    }
  } catch (e) { addLog('warning', '[验证闭环] 裸答案判定异常（已隔离）: ' + e.message); }

  flags.forEach(f => addSolveNote(noteSection, f));
  const verifiedFlags = (state.findings ? state.findings.flags : []).filter(f => f.verified);
  return { vr, flags, verifiedFlags };
}

// 【统一入口·三件套】验证闭环 → 失败自动枚举 → 登记 flag → **解题成功则经验自动入库**。
// 为什么收口：此前"verifyAndRecord + harvestExperience"这两步在 9 个求解流程里各写一遍，
// 于是反复出现"某条路径只验证不收割经验""某条路径压根没接"（v1.3.11/v1.3.12 两轮补漏）。
// 现固定为单一入口 —— 新增任何求解流程只调本函数即可，杜绝再漏（见 SSOT §9）。
// 返回 { vr, flags, verifiedFlags }，供调用方拼结果消息。
// ========== 解题成长闭环：失败计数 → 复盘证伪 → 经验自净 ==========
// 目标（用户要求）：不是"人工喂知识"，而是工具根据每次解题自己成长——
//   ① 同题反复失败 → 记录每次的"方向结论"，下次自动带着"已排除的路"重试；
//   ② 解出后复盘 → 对比失败结论与成功路径，**证伪并删除污染经验**（经验库只增不删会让错误经验永远毒害未来题）。

// 失败档案：{ challengeKey: [{ts, note, source}] }，持久化到 userData/failures.json
function failureLogPath() {
  return (state.appPaths && state.appPaths.userData ? state.appPaths.userData : '') + '/failures.json';
}
function loadFailureLog() {
  if (state._failureLog) return state._failureLog;
  try {
    const p = failureLogPath();
    if (p && window.electronAPI.readFileSync) { /* 渲染层无同步读，走异步入口 */ }
  } catch (e) {}
  state._failureLog = state._failureLog || {};
  return state._failureLog;
}
async function loadFailureLogAsync() {
  if (state._failureLog) return state._failureLog;
  try {
    const rf = await window.electronAPI.readFile(failureLogPath());
    if (rf && rf.success) state._failureLog = JSON.parse(rf.content || '{}');
    else state._failureLog = {};
  } catch (e) { state._failureLog = {}; }
  return state._failureLog;
}
async function saveFailureLog() {
  try {
    await window.electronAPI.writeFile(failureLogPath(), JSON.stringify(state._failureLog || {}, null, 2));
  } catch (e) { /* 落盘失败不阻塞 */ }
}
function challengeKeyOf(name) {
  return String(name || state.fileInfo && state.fileInfo.fileName || 'unknown').toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5]+/g, '_').slice(0, 60);
}

// 失败时记录：本题这轮的"方向结论"（从 AI 文本提炼首条掌握度/推断，限 200 字）
async function recordFailure(challengeName, aiText, note) {
  const log = await loadFailureLogAsync();
  const key = challengeKeyOf(challengeName);
  log[key] = log[key] || [];
  // 提炼本轮"走了哪条路"：优先取「当前推断」段，退而取首 200 字
  let dir = '';
  const m = String(aiText || '').match(/当前推断及置信度[:：]?\s*([\s\S]{0,200})/);
  if (m) dir = m[1].replace(/\s+/g, ' ').trim();
  else dir = String(aiText || '').replace(/\s+/g, ' ').trim().slice(0, 200);
  log[key].push({ ts: new Date().toISOString(), dir: dir || note || '（无结论）', note: note || '' });
  if (log[key].length > 6) log[key] = log[key].slice(-6);   // 每题最多留 6 条失败记录
  state._failureLog = log;
  await saveFailureLog();
  const n = log[key].length;
  addLog('warning', `[成长] ${challengeName} 第 ${n} 次未解出，方向已存档${n >= 2 ? '（下次自动注入已排除的路）' : ''}`);
  return n;
}

// 解出后复盘：对比本题的失败记录与成功路径，让 AI 证伪旧结论 → 删除被证伪的经验条目
async function postSolveReview(challengeName, successText) {
  const log = await loadFailureLogAsync();
  const key = challengeKeyOf(challengeName);
  const fails = log[key] || [];
  if (!fails.length) return 0;   // 一次就解出 → 无失败可复盘
  addLog('info', `[成长] ${challengeName} 曾失败 ${fails.length} 次，开始复盘：对比失败方向与成功路径…`);
  const failLines = fails.map((f, i) => `${i + 1}. [${f.ts.slice(0, 10)}] ${f.dir}`).join('\n');
  const reviewPrompt = `我在解 CTF 题「${challengeName}」时经历了 ${fails.length} 次失败后最终解出。

## 每次失败时的方向结论（已存档）
${failLines}

## 最终成功路径
${String(successText || '').replace(/\s+/g, ' ').slice(0, 2500)}

## 复盘任务（只做证伪，不写新经验）
对照成功路径，逐条判断上面的失败结论：
- 哪条是**方向性错误**（不只是信息不足，而是方法/认知本身错了，例如把数据格式读错、猜错算法结构）？
- 这些错误结论是否可能已作为"经验"沉淀进经验库，毒害未来的同类题？

**输出契约（务必遵守）：**
1. 逐条判定：结论 N = 方向错误 / 仅信息不足
2. 对"方向错误"的每条：给出一行 \`[KILL]错误经验的特征文字（尽量取经验库里可能存在的原句片段，10~40字）[/KILL]\`
3. 最后 \`[LESSON]一句话：下次遇到同类题，第一步应该做什么（≤120字）[/LESSON]\`
不要展开新分析。`;

  try {
    state.aiBusy = true;
    const result = await window.electronAPI.claudeChat(
      [{ role: 'user', content: reviewPrompt }],
      '你是CTF逆向复盘专家。只做失败证伪，输出严格按契约。不要调用任何工具。'
    );
    if (!result || !result.success || !result.text) { addLog('warning', '[成长] 复盘 AI 未返回内容'); return 0; }
    // 1) 提取 [LESSON] → 入经验库（这是"从失败中长出来"的真经验）
    const lesson = (result.text.match(/\[LESSON\]([\s\S]*?)\[\/LESSON\]/i) || [])[1];
    if (lesson && lesson.trim()) {
      const line = `- [${new Date().toISOString().slice(0, 10)}] 复盘「${challengeName}」▶ ${lesson.trim().replace(/\s+/g, ' ').slice(0, 300)}`;
      await writeExperienceEntries([line]);
    }
    // 2) 提取 [KILL] → 从 experience.md 删除匹配的污染条目
    const kills = [...result.text.matchAll(/\[KILL\]([\s\S]*?)\[\/KILL\]/gi)].map(m => experienceKey(m[1].trim()));
    let killed = 0;
    if (kills.length) {
      const expPath = `${state.appPaths.userData}/experience.md`;
      const rf = await window.electronAPI.readFile(expPath);
      if (rf && rf.success) {
        const kept = [];
        for (const l of String(rf.content).split('\n')) {
          if (!l.trim().startsWith('- [')) { kept.push(l); continue; }
          const k = experienceKey(l);
          if (kills.some(kk => kk && (k === kk || experienceSimilar(k, kk)))) { killed++; continue; }  // 证伪 → 移除
          kept.push(l);
        }
        if (killed) {
          await window.electronAPI.writeFile(expPath, kept.join('\n'));
          state.experience = kept.join('\n');
        }
      }
    }
    // 3) 清掉本题失败档案（已复盘完毕）
    delete log[key];
    state._failureLog = log;
    await saveFailureLog();
    addLog('success', `[成长] 复盘完成：判定方向性错误 ${kills.length} 项，清除污染经验 ${killed} 条${lesson ? '，新增复盘教训 1 条' : ''}`);
    addSystemMessage(`**🧬 复盘完成（${challengeName}）**\n\n失败 ${fails.length} 次的方向已逐一证伪：清除污染经验 **${killed} 条**，沉淀复盘教训 1 条。\n\n> ${lesson ? lesson.trim().slice(0, 200) : '（无）'}\n\n经验库已自净——同类题下次不会再被错误结论误导。`);
    return killed;
  } catch (e) {
    addLog('warning', '[成长] 复盘异常: ' + e.message);
    return 0;
  } finally {
    state.aiBusy = false;
  }
}

// 失败注入：拉题前查本题失败档案，≥1 次失败就把"已排除的路"注入提示词（让 AI 换路而非重蹈）
async function failureHintSection(challengeName) {
  const log = await loadFailureLogAsync();
  const key = challengeKeyOf(challengeName);
  const fails = log[key] || [];
  if (!fails.length) return '';
  const lines = fails.map((f, i) => `${i + 1}. [第${i + 1}次尝试] ${f.dir}`).join('\n');
  return `\n\n## ⚠️ 本题历史失败记录（${fails.length} 次，**这些路已走过且未解出**）\n${lines}\n**请优先换一条与上述不同的路线**；若必须重走其中一条，先说明这次与上次的本质差异。\n（另：可主动搜索该题的公开题解（题名+赛事名）对照正解方向——站在题解肩上比盲目重试高效。）\n`;
}

async function finalizeSolve(aiText, opts = {}) {
  // 枚举反馈属"本轮 runHypotheses"的产物：入口先清，防止上一题/上一次调用的反馈
  // 残留到本题（runHypotheses 在下方 verifyAndRecord 里才会重新填充）。
  state.lastEnumFeedback = '';
  // 三件事（反证 / 验证 / 经验收割）互相独立：任一抛错都不能把 AI 已产出的结果整体吞掉。
  // 实测事故：runNegativeAssertionCheck 里一个 ReferenceError 让 autoSolveBinaryFlag 直接跳到
  // catch，AI 那段正确的"本层是 loader、需提取 stage2"结论被丢弃，还跳过了后续 Tool-Use 深挖。
  // 故此处逐步降级：失败只记日志，继续下一步。
  let neg = { refuted: [], retryPrompt: '' };
  try {
    neg = await runNegativeAssertionCheck(aiText, opts);
  } catch (e) { addLog('warning', '[反证] 异常（已隔离，不阻塞求解）: ' + e.message); }

  let vr = null, flags = [], verifiedFlags = [];
  // run_python 的产物由主进程登记在 evidence/artifacts.jsonl（主进程不写 findings.json，
  // 那是渲染层整份覆盖写的）。这里逐条转成 findings.evidence，避免产物从取证链里消失。
  try {
    const ar = await window.electronAPI.caseArtifacts();
    if (ar && ar.success && Array.isArray(ar.artifacts) && ar.artifacts.length) {
      const seen = new Set((state.findings && state.findings.evidence ? state.findings.evidence : [])
        .map(e => `${e.kind}|${e.path || e.file || ''}`));
      let added = 0;
      for (const a of ar.artifacts) {
        const k = `run_python_artifact|${a.path || ''}`;
        if (seen.has(k)) continue;
        seen.add(k);
        // 文件内容不重复落盘（已在 scripts/ 里），只登记指针
        state.findings.evidence.push({
          kind: 'run_python_artifact',
          label: `run_python 产物 ${a.rel || a.path}`,
          file: a.path,
          size: a.size,
          ts: a.ts || new Date().toISOString(),
        });
        added++;
      }
      if (added) { await persistFindings(); addLog('info', `[产物] 登记 ${added} 个 run_python 产物到 findings.evidence`); }
    }
  } catch (e) { addLog('warning', '[产物] 登记异常（已隔离）: ' + e.message); }
  try {
    const r = await verifyAndRecord(aiText, opts);
    vr = r.vr; flags = r.flags || []; verifiedFlags = r.verifiedFlags || [];
  } catch (e) { addLog('warning', '[验证闭环] 异常（已隔离，不阻塞求解）: ' + e.message); }

  try {
    await harvestExperience(aiText, { autoSave: verifiedFlags.length > 0 });
  } catch (e) { addLog('warning', '[经验] 收割异常（已隔离）: ' + e.message); }

  if (neg && neg.refuted.length && !verifiedFlags.length) {
    return { vr, flags, verifiedFlags, refuted: neg.refuted, retryPrompt: neg.retryPrompt };
  }

  // ===== 中间值命中 → 告诉 AI「这个值是什么类型、下一步该做什么」=====
  // 实测（CrackMe，四道闸上线后）：本地复现命中 `55a54008ad1ba589aa210d2629c1df41`，
  // 工具只记录"命中中间值/密钥，非 flag"，然后重试 17 秒就结束——因为 AI
  // 完全不知道这个 32 位 hex 意味着什么。它不是"再解一层"的密文，而是 md5(某输入)，
  // 正确的下一步是「爆破/字典匹配」，不是「换算法再解」。
  // 这类"形态可判、动作可定"的中间值在 CTF 里极常见，工具应当直接给出下一步。
  if (!verifiedFlags.length && vr && Array.isArray(vr.hits) && vr.hits.length) {
    // ── 命中"可打印明文"时先做自动外壳尝试（P0.4b）──
    // 实测（reverse3）：本地复现命中 `{i_l0ve_you}`，只差 `flag` 前缀就是答案；
    // 实测（新年快乐）：命中 `HappyNewYear!`；实测（Crackme7）：命中 `THISiSsERIALnUMBER`。
    // 这三道都被记为"只命中中间值"而失败——工具明明拿到了近乎完整的答案，
    // 却因为不是 `flag{...}` 形态而不认。这里直接尝试常见外壳，命中即记为已验证。
    if (wrapPrintableHit(vr.hits)) {
      verifiedFlags = (state.findings ? state.findings.flags : []).filter(f => f.verified);
      if (verifiedFlags.length) {
        addLog('success', `[验证闭环] 可打印明文加常见外壳后命中 flag：${verifiedFlags[0].flag}`);
        return { vr, flags, verifiedFlags, wrappedFromPrintable: true };
      }
    }
    // ── 机器码优先于通用 hex 分类（rank 5）──
    // 实测（CrackMe3）：AI 用自定义 RC4 变体解出 `83ec18b0 65b16388 ... c3 90 90`——
    // 那是一段完整 x86 函数（sub esp,0x18 … ret nop nop），算法和 key 都对，
    // 拿到的只是**代码层**。而 classifyIntermediateValues 会把同一段字节判成
    // "128 字节的十六进制数据 → 当作下一层的 ciphertext 继续解"，方向完全相反。
    // 机器码是更强的确定性结论，必须先判它，并且即使没有 failureFeedback 也要返回提示。
    let dlEarly = { count: 0, sample: '' };
    try { dlEarly = findDecodedLayer(vr.rawOutput || '') || dlEarly; } catch (e) { /* 忽略 */ }
    if (dlEarly.count > 0) {
      const mc = [
        '⛔ 工具从你的解密输出里识别出了可执行机器码（' + dlEarly.count + ' 处）。',
        '样本：`' + String(dlEarly.sample || '').slice(0, 120) + '`',
        '这说明**你的算法和密钥是对的**，但解出来的不是明文，而是**下一层代码**。',
        '因此**不要换算法、不要换 key**。正确动作：',
        '① 把该字节按 hex 写盘为新文件（run_python: bytes.fromhex(...) → open(...,"wb")）；',
        '② 读文件头确认魔数（MZ/ELF/或确认为裸 shellcode）；',
        '③ 用 switch_to_next_stage 接力到新文件，或直接用 capstone/unicorn 分析它。',
      ].join('\n');
      addLog('info', '[验证闭环] 机器码结论优先于通用 hex 分类');
      return { vr, flags, verifiedFlags, retryPrompt: mc, machineCodeNote: mc };
    }

    const typed = classifyIntermediateValues(vr.hits);
    if (typed.length) {
      // ── P2：先自动推进，而不是只把"这是 MD5"丢回给 AI ──
      // 实测：AI 拿到"可能是 md5"之后基本不会主动去爆破，整题就卡在这一步。
      // 能确定性推进的先做掉（爆破/解码），成功就等于直接拿到下一层输入。
      let advanced = [];
      try {
        advanced = await autoAdvanceIntermediates(vr.hits);
      } catch (e) {
        addLog('warning', '[中间值] 自动推进异常（已隔离）: ' + e.message);
      }
      const solvedByAdvance = advanced.filter(a => a.ok);
      if (solvedByAdvance.length) {
        // 解出的明文**只有本身已是 flag 形态**才直接记为已验证。
        // 不能把 md5("admin")="admin" 这种口令自动包成 flag{admin} 并标 verified：
        // 那是"未经验证的猜测"冒充确定结论，会污染正确率统计（实测已有此类误报）。
        // 其余明文一律当作「下一层输入」交回 AI，由它决定是否加外壳再 [VERIFY]。
        const plaintexts = solvedByAdvance
          .map(a => String(a.plaintext || '').trim())
          .filter(Boolean);
        for (const p of plaintexts) {
          if (looksLikeFlag(p) && !isDecoyFlag(p) && !isDegenerateDigest(p)) {
            recordFlag(p, 'intermediate-advance', true);
          }
        }
        const nowVerified = (state.findings ? state.findings.flags : []).filter(f => f.verified);
        if (nowVerified.length) {
          addLog('success', `[中间值] 自动推进得到 flag 形态明文：${nowVerified[0].flag}`);
          return { vr, flags, verifiedFlags: nowVerified, advancedFromIntermediate: advanced };
        }
        // 解出了明文但不是 flag 形态 → 把它作为「下一层输入」交给 AI，别再让它重算这一步
        const advLines = solvedByAdvance.map(a =>
          `- \`${a.value}\`（${a.kind}）→ ${a.action} 得到明文 \`${a.plaintext}\`（${a.note}）`).join('\n');
        const retry = [
          '工具已经**自动完成**了中间值的下一步转换，结果如下：',
          '',
          advLines,
          '',
          '请**直接使用这些明文**继续往下分析，不要重复爆破/解码：',
          '· 若某个明文像密钥/口令 → 用它解下一层；',
          '· 若像注册码/校验值 → 在程序里搜它被比较的位置；',
          '· 若它本身接近答案但形态不对 → 按题目要求加外壳后用 [VERIFY] 复验。',
          '',
          '拿到下一层结果后，必须输出 [VERIFY]（新的算法/密钥/密文）或 [FLAG]。',
        ].join('\n');
        addLog('info', `[中间值] 自动推进得到明文（${solvedByAdvance.map(a => a.kind).join('/')}），已交给 AI 继续`);
        return { vr, flags, verifiedFlags, retryPrompt: retry, intermediateTyped: typed, advancedFromIntermediate: advanced };
      }

      const failedAdv = advanced.filter(a => !a.ok);
      const retry = [
        '本地验证**成功复现了你的计算**，但解出的值不是 flag 形态的明文。工具已识别出它们的类型：',
        '',
        ...typed.map(t => `- \`${t.value}\` → **${t.kind}**：${t.next}`),
        ...(failedAdv.length ? [
          '',
          '工具已尝试自动推进但**未命中**（这不代表方向错误，只说明当前字典不够）：',
          ...failedAdv.map(a => `- \`${a.value}\`（${a.kind}）${a.action}：${a.note}`),
        ] : []),
        '',
        '请按上面的「下一步」直接执行，不要重复已经验证过的这一步：',
        '· 若是哈希（MD5/SHA）→ 用 run_python 做字典/短串爆破；**优先用程序内出现过的字符串常量**作字典（工具通用字典没命中时，答案通常就在文件里）',
        '· 若是密钥/IV → 用它去解**下一层**（找另一段密文，或对当前输入再跑一次解密）；',
        '· 若是 UUID/路径/URL 形态 → 在二进制与资源里搜同样的串，找引用它的校验逻辑；',
        '· 若已是可打印明文 → 它可能就是 flag 本体，按题目要求加外壳（如 flag{...}）后用 [VERIFY] 复验。',
        '',
        '拿到下一层结果后，必须输出 [VERIFY]（新的算法/密钥/密文）或 [FLAG]。',
      ].join('\n');
      addLog('info', `[验证闭环] 命中中间值并识别类型 ${typed.map(t => t.kind).join('/')}，已生成定向下一步提示`);
      return { vr, flags, verifiedFlags, retryPrompt: retry, intermediateTyped: typed, advancedFromIntermediate: advanced };
    }
  }

  // ===== 验证失败 → 生成"基于真实输出"的修正提示 =====
  // 这是"举一反三"的核心：AI 不是因为算法不会而失败，而是因为**它看不到自己的假设错在哪**。
  // 把本地复现的真实结果（报错/解出什么/差在哪）回灌，让它带着证据修正，而不是重头再来。
  if (!verifiedFlags.length && vr && vr.failureFeedback) {
    // 先判定"解出来的是不是机器码"：这会彻底改变重试指令的方向。
    const dl = findDecodedLayer(vr.rawOutput || '');
    const decodedNote = dl.count ? [
      '',
      '⛔ **重要：工具从你的解密输出里识别出了可执行机器码**（' + dl.count + ' 处）。',
      '样本：`' + dl.sample + '`',
      '这说明**你的算法和密钥是对的**，但解出来的不是明文，而是**自解密/自解压的下一层代码**。',
      '因此**不要换算法、不要换 key**。正确动作：',
      '1. 用同样的参数，把解密结果**完整写出到磁盘**（run_python 里 open(...,"wb").write(pt)）；',
      '2. 读出前 16 字节确认头部（4D 5A = PE / 7F 45 4C 46 = ELF / 64 65 78 0A = DEX）；',
      '3. 调 `switch_to_next_stage`（path=新文件绝对路径）接力到下一层；',
      '4. 若那段代码不是完整 PE/ELF 而是裸函数，就用 capstone/unicorn 反汇编或模拟它，找出它对输入做的变换。',
      '',
    ].join('\n') : '';
    const retry = [
      '本地验证已跑完，**但你的 [VERIFY] 契约没有命中**。以下工具实测到的真实结果：',
      '',
      vr.failureFeedback,
      decodedNote,
      '请据此判断属于哪种情况，并给出修正后的方案：',
      '1. **expected 写错了**（最常见）：你猜的 flag 前缀与实际不符。以上面的"解出但不匹配"里的**真实明文**为准，',
      '   重新确认这才是 flag（或它的前一层），并给出正确的 expected。',
      '2. **脚本有 bug**：按报错行修代码（除零/越界/索引/None），**不要因为崩溃就换算法**。',
      '3. **参数形态错**：key 长度/编码/IV 不对，或密文偏移取错。',
      '4. **算法族错**：若全部是 garbage，说明算法选错，换算法族而不是换 key。',
      '',
      `契约中的 expected 当前是：${(vr.contracts || []).map(c => JSON.stringify(c.expected || '')).join('、')}`,
      '如果真实明文确实是 flag，直接输出 [FLAG]真实明文[/FLAG] + 对应的 [VERIFY]（expected 用真实明文）。',
    ].join('\n');
    addLog('info', '[验证闭环] 已生成修正提示（' + retry.length + ' 字符），将随结果回传触发重试'
      + (dl.count ? `；检测到解出机器码 ${dl.count} 处 → 重试指令已改为"接力下一层"` : ''));
    state.lastEnumFeedback = '';   // 已有更强的契约失败证据，枚举反馈不再需要
    return { vr, flags, verifiedFlags, retryPrompt: retry, decodedLayer: dl.count };
  }
  // 枚举全灭的定向反馈：没有 vr 失败证据时也值得让 AI 修一轮（缺密文/输出为空是可修的）
  const enumFb = String(state.lastEnumFeedback || '');
  if (enumFb && !verifiedFlags.length) {
    state.lastEnumFeedback = '';
    return { vr, flags, verifiedFlags, retryPrompt: enumFb, enumFeedback: true };
  }
  return { vr, flags, verifiedFlags };
}

// 可打印明文 → 尝试常见外壳，命中即记为已验证 flag。
// 判据保守：只对"整段都是可打印 ASCII、长度 4~120、不含空白换行"的值尝试，
// 避免把一段描述性文本误当答案。外壳只试 CTF 里确定存在的几种。
//
// ⚠️ 必须排除"纯十六进制串"：实测（CrackMe）中间值 `CBAADEB0A8ABAEB1B4B7BABDC0C3C6C9`
// 全是大写 hex，字面上确实"可打印"，但它是一段**字节数据**，不是明文答案。
// 把它包成 flag{...} 提交只会在平台上多一次错误记录，还会污染"已验证"状态。
// 判据：整串只由 0-9A-Fa-f 组成且长度 ≥16 → 视为 hex 数据，不做外壳尝试
// （这类值由 classifyIntermediateValues 按"hex 数据"给出下一步，语义更准）。
// 返回是否至少命中一个。
function wrapPrintableHit(hits) {
  let any = false;
  for (const raw of (Array.isArray(hits) ? hits : []).slice(0, 6)) {
    const v = String(raw == null ? '' : raw).trim();
    if (v.length < 4 || v.length > 120) continue;
    // 必须整段可打印、无空白（有空白的多半是句子/描述）
    if (!/^[\x21-\x7e]+$/.test(v)) continue;
    // 纯 hex 串是字节数据，不是明文（详见上方注释）
    if (/^[0-9a-fA-F]{16,}$/.test(v)) continue;
    // 已经是 flag 形态（由 lookFlag 处理），跳过
    if (looksLikeFlag(v)) continue;
    const candidates = [];
    // 已带花括号：{xxx} → flag{xxx}
    if (/^\{[^{}]+\}$/.test(v)) candidates.push('flag' + v);
    // 裸明文 → flag{明文}
    candidates.push('flag{' + v + '}');
    for (const c of candidates) {
      if (looksLikeFlag(c)) {
        recordFlag(c, 'printable-wrap', true);
        addSolveNote('明文外壳命中', `${v} → ${c}`);
        any = true;
        break;
      }
    }
  }
  return any;
}

// P2：把中间值"形态可判 → 动作可定"的那部分直接执行掉（爆破/解码）。
// 目标文件路径可提供，用于把文件内字符串常量并入字典（CTF 的 key 几乎都在文件里）。
async function autoAdvanceIntermediates(hits) {
  if (!Array.isArray(hits) || !hits.length) return [];
  if (!window.electronAPI || !window.electronAPI.advanceIntermediates) return [];
  const filePath = (state.fileInfo && state.fileInfo.filePath) || state.currentFile || '';
  const r = await window.electronAPI.advanceIntermediates(hits, filePath);
  if (!r || !r.success) {
    if (r && r.error) addLog('warning', '[中间值] 自动推进失败: ' + r.error);
    return [];
  }
  const results = Array.isArray(r.results) ? r.results : [];
  for (const a of results) {
    if (a.ok) addLog('info', `[中间值] ${a.kind} ${a.action} 命中：${a.value.slice(0, 32)}… → ${String(a.plaintext).slice(0, 80)}（${a.note}）`);
  }
  return results;
}

// 识别"中间值"的形态并给出下一步动作。
// 设计原则：只认**值的形态本身**能确定的类型，不猜题目。
// 例：32 位 hex 且是合法 md5 → "可能是 md5(某输入)"，下一步是爆破/字典；
//     但这只是"可能"——所以 next 里必须同时给出"若不是哈希该怎么办"的退路。
function classifyIntermediateValues(hits) {
  const out = [];
  const seen = new Set();
  const push = (value, kind, next) => {
    const k = value + '|' + kind;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ value, kind, next });
  };
  for (const raw of (Array.isArray(hits) ? hits : []).slice(0, 8)) {
    const v = String(raw == null ? '' : raw).trim();
    if (!v || v.length < 4) continue;
    const hex = /^(0x)?[0-9a-fA-F]+$/.test(v);
    const hexLen = hex ? v.replace(/^0x/i, '').length : 0;
    if (hex && hexLen === 32) {
      push(v, '32 位十六进制（MD5 长度）',
        '最可能是 **md5(某段输入)**：用 run_python 对「题面提示词 + 常见弱口令 + 程序里的字符串常量」做字典/短串爆破；'
        + '若爆破无果，它也可能是**未被加密的原始密钥/标识**，直接用于下一层解密或搜索引用');
    } else if (hex && hexLen === 40) {
      push(v, '40 位十六进制（SHA1 长度）', '可能是 **sha1(输入)**：同样先字典/短串爆破；也可能是原始字节的 hex 表示');
    } else if (hex && hexLen === 64) {
      push(v, '64 位十六进制（SHA256 长度）', '可能是 **sha256(输入)**：字典爆破；或原始 32 字节密钥/摘要');
    } else if (hex && hexLen >= 8 && hexLen % 2 === 0) {
      push(v, `${hexLen / 2} 字节的十六进制数据`, '原始字节：尝试按 ASCII/UTF-16 解码看是否可打印；若是密文，用它作为下一层的 ciphertext 继续解');
    } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
      push(v, 'UUID 形态', '通常是**题目生成的标识/注册码**：在二进制与资源里搜同样的格式或生成逻辑，找到它被校验的位置');
    } else if (/^https?:\/\//i.test(v)) {
      push(v, 'URL', '在二进制/资源里搜该 URL 或域名片段，定位与之关联的校验或下载逻辑');
    } else if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(v) && v.length % 4 === 0) {
      push(v, 'Base64 形态', '先 base64 解码看是否得到可打印明文；解不出就把它当下一层的输入');
    } else if (/^[\x20-\x7e]{6,}$/.test(v)) {
      push(v, '可打印明文', '它可能就是 flag 本体（若题目要求包裹则加 `flag{...}`），或是一段密钥/提示：'
        + '先用 [VERIFY] 复验这个明文，再判断是否需要再解一层');
    }
  }
  return out;
}

// ========== 负面断言反证（Phase 2）==========
// 为什么需要（Disguise 实测）：AI 说"文件内无第二可执行载体，真 flag 不在此文件"，工具**直接采信**，
// 于是收工报了个诱饵。事实是 stage2 就在 .data 里，只是被编码存储、明文搜 MZ 搜不到。
// 原则：**AI 的否定性结论必须被数据验证**，工具不能只是被动采信。
//
// 结构：每条规则 = { id, detect(文本) -> bool, verify(ctx) -> 反驳文本|null, retryPrompt }
//   · detect：识别"AI 在断言不存在某物"
//   · verify：用确定性数据（扫描结果、文件字节）验证该断言是否成立；成立返回 null，不成立返回证据
//   · 验证器只允许报**确定性事实**（偏移/长度/魔数），不给模糊判断 → 避免用猜测反驳猜测。
function buildNegativeAssertionRules() {
  return [
    {
      id: 'no-second-carrier',
      // 断言"没有第二载体/内嵌文件/下一层"，或"上一层缺下一层数据我无法继续"
      detect: (t) => /(无|没有|不存在|未发现|找不到|搜不到|missing|no)\s*[^。\n]{0,24}(第二|另一个|内嵌|嵌入|下一层|second|embedded|next[- ]stage|另一个可执行|可执行载体|PE\s*载荷)/i.test(t)
        || /(真\s*flag\s*(不在|不在此)|flag\s*不在此文件|not\s+in\s+this\s+file)/i.test(t)
        // "stage2 未提供 / 没有 stage2 的内容 / 缺 stage2" → 同样属于"以为拿不到下一层"
        || /(stage\s*\d+|下一层|下一阶段)[^。\n]{0,20}(未|没有|无法|缺|missing|not\s+provided|not\s+available)/i.test(t),
      verify: (ctx) => {
        const sc = ctx.algScan || {};
        const pl = Array.isArray(sc.payloads) ? sc.payloads : (Array.isArray(sc.embeddedPE) ? sc.embeddedPE : []);
        if (!pl.length) return null;   // 确实没有 → 断言成立，不反驳
        const p = pl[0];
        const e = p.encode || {};
        const typeName = p.type === 'pe' ? 'PE' : p.type === 'elf' ? 'ELF' : p.type === 'dex' ? 'DEX' : '载荷';
        const how = e.kind === 'none' ? '明文'
          : e.kind === 'xor' ? `XOR 0x${(e.key >>> 0).toString(16)}`
          : e.kind === 'add' ? `ADD 0x${(e.key >>> 0).toString(16)}`
          : e.kind === 'periodic-xor' ? `${e.period} 字节周期 XOR`
          : e.kind === 'rolling-xor' ? '滚动 XOR' : e.kind === 'rolling-add' ? '滚动 ADD'
          : e.kind === 'base64' ? 'Base64 文本' : e.kind === 'hex' ? 'Hex 文本' : e.kind;
        return `**你的结论"没有第二载体"被工具数据推翻**：扫描器在文件偏移 **0x${p.offset.toString(16)}** 处`
          + `确定性定位到一个**编码存储的 ${typeName} 载荷**（${how}，步长 ${e.stride || 1}`
          + (p.length ? `，长度 ${p.length} 字节` : '')
          + `）。它之所以"搜不到"，是因为 ${typeName} 头被编码掩盖了——不是不存在。`
          + `\n下一步：按扫描结论里的提取脚本解码写出该文件，对**新文件**重新分析；不要在本层下"真 flag 不在此文件"的结论。`;
      },
      // 反驳后要求 AI 重做的具体动作（工具无法代替 AI 完成"分析下一层"，但能强制它先提取）
      retryPrompt: (ctx) => {
        const sc = ctx.algScan || {};
        const pl = Array.isArray(sc.payloads) ? sc.payloads : [];
        const p = pl[0];
        if (!p) return null;
        return `⛔ 复核：你刚才断言"没有第二载体/真 flag 不在此文件"，但工具的字节扫描在 0x${p.offset.toString(16)} 找到了编码后的 ${p.type.toUpperCase()} 载荷。`
          + `请**立即按提取脚本解码出该文件**（run_python），确认其头部魔数后，用 switch_to_next_stage 接力到新文件继续；不要就此收工。`;
      },
    },
    {
      id: 'delegates-to-user',
      // 断言"需要用户提供 / 请把 stage2 发我 / 需要人工提取"——把可自动完成的活推给人。
      // 实测（Disguise）：AI 正确判断"本层是 loader、缺 stage2"，但结论是"请用户提供 stage2"，
      // 而工具**本可以自己提取**。这类"正确的诊断 + 错误的行动"最难被人工发现，必须拦下。
      detect: (t) => /(请|需要|麻烦|建议)\s*(用户|你|人工|手动)\s*[^。\n]{0,24}(提供|给出|上传|提取|dump|发|补)/i.test(t)
        || /(需要|待)\s*(人工|用户)\s*(提供|提取|介入|处理)/i.test(t)
        || /(stage2|下一层|内嵌文件|payload)\s*(未|没有|无法)\s*(提供|获取|提取)/i.test(t),
      verify: (ctx) => {
        const sc = ctx.algScan || {};
        const pl = Array.isArray(sc.payloads) ? sc.payloads : (Array.isArray(sc.embeddedPE) ? sc.embeddedPE : []);
        if (!pl.length) return null;          // 没有载荷 → 确实需要人工，不反驳
        const p = pl[0], e = p.encode || {};
        const how = e.kind === 'none' ? '明文'
          : e.kind === 'xor' ? `XOR 0x${(e.key >>> 0).toString(16)}`
          : e.kind === 'add' ? `ADD 0x${(e.key >>> 0).toString(16)}`
          : e.kind === 'periodic-xor' ? `${e.period} 字节周期 XOR`
          : e.kind === 'rolling-xor' ? '滚动 XOR' : e.kind === 'rolling-add' ? '滚动 ADD'
          : e.kind === 'base64' ? 'Base64 文本' : e.kind === 'hex' ? 'Hex 文本' : e.kind;
        return `**这个结论把工具能做的事推给了用户**：下一层载荷的提取是**纯确定性操作**，`
          + `扫描器已给出全部参数（偏移 0x${p.offset.toString(16)}、${how}`
          + (p.length ? `、长度 ${p.length}` : '') + `），不需要人工提供。`
          + `\n正确做法：直接用 run_python 按参数解码并写出文件（工具也会自动接力），然后分析新文件。`;
      },
      retryPrompt: (ctx) => {
        const sc = ctx.algScan || {};
        const pl = Array.isArray(sc.payloads) ? sc.payloads : [];
        const p = pl[0];
        if (!p) return null;
        return `⛔ 复核：你把"提取下一层"推给了用户，但这是确定性操作。`
          + `请**自己用 run_python** 按偏移 0x${p.offset.toString(16)} / ${p.encode.kind} 参数解码并写出文件，`
          + `校验 MZ/ELF 魔数后继续分析；不要要求用户提供。`;
      },
    },
    {
      id: 'no-crypto',
      // 断言"没有加密/没有算法/是明文"
      detect: (t) => /(没有|无|不含|未使用|不存在|no)\s*[^。\n]{0,16}(加密|算法|密码|crypto|encrypt|cipher)/i.test(t)
        && !/(可能|疑似|或许|不确定|待确认)/.test(t),
      verify: (ctx) => {
        const sc = ctx.algScan || {};
        const strong = (sc.summary || []).filter(s => s.confidence === 'high' || s.confidence === 'medium');
        if (!strong.length) return null;
        return `**你的结论"没有加密/算法"被工具数据推翻**：扫描器从文件字节里确定性识别到 `
          + strong.map(s => `${s.algo}（${s.confidence}）`).join('、')
          + `。证据：${strong[0].evidence}`;
      },
      retryPrompt: (ctx) => {
        const sc = ctx.algScan || {};
        const strong = (sc.summary || []).find(s => s.confidence === 'high');
        if (!strong) return null;
        return `⛔ 复核：你断言"没有加密算法"，但扫描器识别到 ${strong.algo}（high）。请按该算法的标准框架验证，不要断言"无加密"。`;
      },
    },
    {
      id: 'no-decoding',
      // 断言"没有解密/解码逻辑"
      detect: (t) => /(没有|无|不存在|未发现|no)\s*[^。\n]{0,16}(解密|解码|脱壳|decrypt|unpack|decod)/i.test(t),
      verify: (ctx) => {
        const sc = ctx.algScan || {};
        const pl = Array.isArray(sc.payloads) ? sc.payloads : [];
        if (!pl.length) return null;
        const p = pl[0], e = p.encode || {};
        if (!e.kind || e.kind === 'none') return null;
        return `**你的结论"没有解密/解码逻辑"被工具数据推翻**：文件偏移 0x${p.offset.toString(16)} 处的 ${p.type.toUpperCase()} 载荷`
          + `就是被编码存储的（${e.kind}${e.key != null ? ` key=0x${(e.key >>> 0).toString(16)}` : ''}）。编码本身就是解码逻辑的产物。`;
      },
      retryPrompt: () => `⛔ 复核：你断言"没有解码逻辑"，但工具找到了编码存储的载荷。请先解码提取，再看它的解码程序逻辑。`,
    },
    {
      id: 'no-vm',
      // 断言"没有 VM / 不是 VM"
      detect: (t) => /(没有|无|不是|并非|no)\s*[^。\n]{0,8}(VM|虚拟机|解释器|字节码)/i.test(t),
      verify: (ctx) => {
        // VM 无法从静态字节可靠判定 → 只在**已确认分组密码 S 盒**时反驳（那种题几乎都套 VM 外壳）
        const sc = ctx.algScan || {};
        const cb = (sc.summary || []).find(s => /自定义分组密码/.test(s.algo) && s.confidence === 'high');
        if (!cb) return null;
        return `**"没有 VM"这个结论不可靠**：扫描器已确认存在 256 项双射 S 盒（自定义分组密码）。`
          + `实测同类题（Disguise）的 VM 只是**外壳**，真正的算法是魔改 SM4——不要因为"找不到 VM"就放弃，`
          + `也不要因为"找到了 VM"就去硬逆它。优先按分组密码结构验证。`;
      },
      retryPrompt: () => `⛔ 复核：你断言"没有 VM"，但已确认存在分组密码。请改为验证分组密码结构（S盒/轮函数/轮密钥），而不是纠结 VM 存不存在。`,
    },
  ];
}

// 对 AI 的最终文本跑一遍负面断言反证。返回 { refuted: [{id, evidence}], retryPrompt }
// 注意：一次只反证**前两条**，避免把提示词撑爆；且只反证有确定性证据的。
function checkNegativeAssertions(aiText, ctx) {
  const text = String(aiText || '');
  if (!text) return { refuted: [], retryPrompt: '' };
  const rules = buildNegativeAssertionRules();
  const refuted = [];
  const prompts = [];
  // xref 闸门状态只取 `unreferenced` 作为"表未被引用"的证据；
  // `unverified`（x64/ELF 的 RIP-relative 未解析到）不得用于反证，否则会把真表说成库数据。
  const ctx2 = Object.assign({}, ctx || {});
  ctx2.refutedTables = (((ctx || {}).algScan || {}).fingerprints || [])
    .filter(f => f && f.xref && f.xref.status === 'referenced');
  ctx2.downgradedTables = (((ctx || {}).algScan || {}).fingerprints || [])
    .filter(f => f && f.xref && f.xref.status === 'unreferenced');
  for (const rule of rules) {
    if (refuted.length >= 2) break;
    let hit = false;
    try { hit = rule.detect(text); } catch (e) { continue; }
    if (!hit) continue;
    let evidence = null;
    try { evidence = rule.verify(ctx2); } catch (e) { evidence = null; }
    if (!evidence) continue;   // 断言成立（或无确定性证据）→ 不反驳
    refuted.push({ id: rule.id, evidence });
    try {
      const rp = rule.retryPrompt ? rule.retryPrompt(ctx2) : null;
      if (rp) prompts.push(rp);
    } catch (e) { /* 忽略 */ }
  }
  return { refuted, retryPrompt: prompts.join('\n\n') };
}

// 执行反证：把证据落盘 + 记日志 + 返回是否被推翻（供调用方决定是否追加一轮 AI）
// ⚠️ algScan 必须由调用方显式传入：`analysisData` 是 autoSolveBinaryFlag 的**局部变量**，
//    本函数在另一作用域（且会被多个求解流程调用），引用它会抛 ReferenceError 并吞掉整轮 AI 结果。
//    实测代价：Disguise 那轮 AI 已经给出了正确的"本层是 loader、需提取 stage2"结论，却因这个异常被丢弃。
async function runNegativeAssertionCheck(aiText, opts = {}) {
  const algScan = opts.algScan || (state.lastAlgScan || null);
  if (!algScan) return { refuted: [], retryPrompt: '' };   // 无扫描数据 → 无从反证，直接放行
  const ctx = { algScan };
  const r = checkNegativeAssertions(aiText, ctx);
  if (!r.refuted.length) return r;
  addLog('warning', `[反证] AI 的负面结论被数据推翻 ${r.refuted.length} 条：${r.refuted.map(x => x.id).join(', ')}`);
  addSolveNote('负面断言反证', r.refuted.map(x => `[${x.id}] ${x.evidence.replace(/\s+/g, ' ').slice(0, 200)}`).join(' || '));
  try { await caseAddEvidence('negative_assertion', '负面断言反证', r.refuted.map(x => `## ${x.id}\n${x.evidence}`).join('\n\n---\n\n'), 'md'); } catch (e) {}
  addSystemMessage(`**🔍 负面断言反证**\n\nAI 的否定性结论被工具数据推翻：\n\n${r.refuted.map(x => x.evidence).join('\n\n')}`);
  return r;
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

  // 命中值分三类（诱饵必须单独识别，否则"命中 fake flag"会被当成验证通过 = 假成功）：
  //   flagHits = 真 flag 形态；decoyHits = 诱饵串（fake/decoy/假flag）
  const flagHits = r.hits.filter(h => looksLikeFlag(h));
  const decoyHits = r.hits.filter(h => !looksLikeFlag(h) && isDecoyFlag(h));
  const verified = flagHits.length > 0;
  // 命中是 flag → 标同值 flag 为已验证
  flagHits.forEach(h => recordFlag(h, 'verify', true));
  // 命中不是 flag（中间值/key）但复现成功 → 把契约 expected 对应的 flag 一并标验证？
  // 不能：中间值复现不等于 flag 被验证。故仅当存在 flag 形态命中时才标验证。
  const note = flagHits.length
    ? `本地复现通过（flag）：${flagHits.join(', ')}`
    : (decoyHits.length
      ? `本地复现只命中**诱饵**（非真 flag）：${decoyHits.join(', ')} —— 当前层是 decoy，真 flag 在下一层载体`
      : (r.hits.length ? `本地复现通过（命中中间值/密钥，非 flag）：${r.hits.join(', ')}` : `本地复现失败（${contracts.length} 个契约无命中）`));
  addSolveNote('验证', note);
  addLog(flagHits.length ? 'success' : (decoyHits.length ? 'warning' : (r.hits.length ? 'info' : 'warning')), `[验证闭环] ${note}`);

  // ===== 多候选密文交叉校验（防"变种题"陷阱）=====
  // 即使本地复现"通过"了，也要确认用的是 so 里**真正被校验**的那条密文，而不是随便一条。
  // 条件：AI 用了密文 + native intel 里抽到 >=2 组候选常量。此时把候选都跑一遍看哪些能出 flag，
  // 并用 IDA xrefs 判定"哪条被校验函数引用" → 尝试自动裁决（无法判定时降级为告警）。
  let cross = null, verdict = null;
  try {
    const hasNativeIntel = mcpCache && mcpCache.nativeIntel &&
      ((mcpCache.nativeIntel.globals || []).length || (mcpCache.nativeIntel.segments || []).length ||
       (mcpCache.nativeIntel.decompiled || []).length);
    const c0 = contracts.find(c => c && c.ciphertext && c.key && (c.algo !== 'custom' && c.algo !== 'node_js'));
    if (hasNativeIntel && c0) {
      cross = await crossCheckCandidates(c0);
      const aiFlag = (flagHits[0] || '').trim();
      if (cross && cross.nativeHits && cross.nativeHits.length) {
        const others = cross.nativeHits.filter(h => (h.flag || '').trim() !== aiFlag);
        const authHit = cross.authHit;
        if (authHit) {
          // ✅ 自动裁决：找到了"被校验函数引用"的那条候选，且它能出 flag
          const authFlag = (authHit.flag || '').trim();
          if (authFlag && authFlag !== aiFlag) {
            // 权威密文解出的 flag 与 AI 不同 → 以权威为准，并把 AI 原答案降级为未验证
            if (state.findings && Array.isArray(state.findings.flags)) {
              const prev = state.findings.flags.find(f => f.flag === aiFlag);
              if (prev) { prev.verified = false; if (!String(prev.source).includes('superseded')) prev.source += ',superseded'; persistFindings(); }
            }
            recordFlag(authFlag, 'native-authoritative', true);
            flagHits.length = 0; flagHits.push(authFlag);
            const whyTxt = (authHit.why && authHit.why.length) ? '（依据：' + authHit.why.join('；') + '）' : '（依据 IDA xrefs：被引用函数含比较语义）';
            const msg = `✅ 自动裁决：以「被校验函数引用的密文」为权威\n` +
              `  • 权威候选 [${authHit.src}]${authHit.refFns && authHit.refFns.length ? ' 被 ' + authHit.refFns.join(', ') + ' 引用' : ''}\n` +
              `    ct=${authHit.hex} → ${authFlag}\n` +
              `  • AI 原答案（已降级为候选）：${aiFlag || '(无)'}\n` +
              `${whyTxt}，score=${authHit.score}`;
            addLog('success', '[交叉校验] ' + msg.replace(/\n/g, ' '));
            addSolveNote('交叉校验裁决', msg.replace(/\n/g, ' '));
            addSystemMessage(`**🧭 多候选密文自动裁决**\n\n${msg}`);
            verdict = { authoritative: authFlag, source: authHit.src, refFns: authHit.refFns || [], why: authHit.why || [], replacedAI: !!aiFlag };
          } else {
            addLog('success', `[交叉校验] AI 用的密文与「被校验函数引用的候选」一致 ✓（${authHit.src}）`);
            verdict = { authoritative: authFlag || aiFlag, source: authHit.src, refFns: authHit.refFns || [], why: authHit.why || [], replacedAI: false };
          }
        } else if (others.length) {
          // 无法自动判定权威（xref 没查到明确引用）→ 保持告警，交人工/AI 复核
          const msg = `⚠️ 检测到 ${others.length} 条 so 候选密文也能解出 flag（与 AI 给的不同）：\n` +
            others.map(h => `  • [${h.src}]${h.refFns && h.refFns.length ? ' 被 ' + h.refFns.join(', ') + ' 引用' : ''} score=${h.score || 0} → ${h.flag}`).join('\n') +
            `\nAI 用的是：${aiFlag || '(无)'}\n未能从 xref 明确判定权威密文，请回 IDA 看 xrefs_to 密文地址后定案。`;
          addLog('warning', '[交叉校验] ' + msg.replace(/\n/g, ' '));
          addSolveNote('交叉校验告警', msg.replace(/\n/g, ' '));
          addSystemMessage(`**⚠️ 多候选密文交叉校验**\n\n${msg}\n\n（工具已枚举 so 内全部候选常量，非仅第一条）`);
          others.forEach(h => recordFlag(h.flag, 'native-candidate', false));
        }
      } else if (cross && cross.tried) {
        addLog('info', `[交叉校验] 已试 ${cross.tried} 组候选，仅 AI 密文出 flag（其余为噪声/密钥表）`);
      }
    }
  } catch (e) { /* 交叉校验失败不阻断主流程 */ }

  // ===== 失败回灌：把"真实解密输出"交回 AI，让它修正假设 =====
  // 为什么需要：实测 6 道题"有契约但本地复现失败"——根因不是算法错，而是 AI 的
  // expected 写错了（抄了猜测的前缀/只写了一半），或参数形态差一点。
  // 但旧流程只打一行"契约无命中"就把结果丢掉，AI 下一轮完全不知道自己错在哪。
  // 这里把每个候选的真实解出结果（前 200 字符）拼成结构化反馈，作为附加字段返回，
  // 由调用方决定是否用它触发一轮"基于证据的修正"。
  let failureFeedback = '';
  if (!flagHits.length && contracts.length) {
    const outText = String(r.output || '');
    const fails = [...outText.matchAll(/\[FAIL\] attempt=(\d+) algo=(\S+) keyenc=(\S+) stage=(\S+) reason=([^\r\n]*)/g)]
      .slice(0, 8).map(m => `  · 尝试#${m[1]} ${m[2]}/${m[3]} → 报错 ${m[5].slice(0, 100)}`);
    const misses = [...outText.matchAll(/\[MISS\] attempt=(\d+) algo=(\S+) keyenc=(\S+) stage=(\S+) result=(\S+) preview=([^\r\n]*)/g)]
      .slice(0, 8).map(m => `  · 尝试#${m[1]} ${m[2]}/${m[3]} → ${m[5]}（前 80 字符：${m[6].slice(0, 80)}）`);
    const outs = [...outText.matchAll(/\[OUT\] attempt=(\d+) keyenc=(\S+): ([^\r\n]*)/g)]
      .slice(0, 6).map(m => `  · 尝试#${m[1]} /${m[2]} → ${m[3].slice(0, 120)}`);
    const parts = [];
    if (fails.length) parts.push('**脚本报错**：\n' + fails.join('\n'));
    if (misses.length) parts.push('**解出但不匹配**：\n' + misses.join('\n'));
    if (outs.length) parts.push('**原始输出**：\n' + outs.join('\n'));
    if (parts.length) {
      failureFeedback = '本地复现的真实结果如下（你的 expected 可能与之不符）：\n' + parts.join('\n\n');
      addLog('info', '[验证闭环] 已提取失败证据（将回灌给 AI）: ' + failureFeedback.length + ' 字符');
    }
  }

  return { verified: flagHits.length > 0, intermediateVerified: verified, hits: r.hits, flagHits, cross, verdict, contracts, failureFeedback, rawOutput: String(r.output || '') };
}

// 【举一反三】AI 没给 [HYPOTHESES] 契约时，工具**自己合成**候选矩阵，而不是只打一句
// "未找到 [HYPOTHESES] 契约"就放弃（正是"单契约复现失败后原地卡死"的根因）。
// 依据已解析的 [VERIFY] 契约（key/iv/ciphertext/algo），枚举 CTF 中最常见的歧义维度：
//   · 密钥编码：ascii / hex / base64
//   · 模式：CBC / ECB
//   · IV：给的 / 全零 / 密文首块 / 前置IV（CBC 侧在 Python solver 内自动枚举）
//   · 算法族兜底：algo 给了 aes_cbc 时一并试 aes_ecb / des_cbc / rc4 / xor 等
//   · 附加：RSA 小指数、base64 直接解等"零 key"尝试
// 全部交给同一份本地求解器跑，命中即记为已验证 flag。
function synthesizeHypotheses(contracts) {
  // 只要求「有 key」即可尝试枚举：密文可以来自 AI 的契约，也可以由工具从扫描结果里补。
  // 旧实现硬性要求 c.ciphertext，实测（CrackMe2/CrackMe3 的 P1 复验）AI 的契约常常是
  // {algo, key, expected} 而**不写 ciphertext** —— 于是合成器直接返回空，
  // "举一反三"在最需要它的场景（契约失败）完全没有生效。
  const all = (Array.isArray(contracts) ? contracts : []).filter(c => c && (c.key || c.ciphertext));
  if (!all.length) return [];
  const withCt = all.filter(c => c && c.ciphertext);
  const noCt = all.filter(c => c && !c.ciphertext);
  const base = withCt.length ? withCt : noCt;
  const hexLike = (s) => /^[0-9a-fA-F]+$/.test(String(s || '')) && String(s).length % 2 === 0;
  const b64Like = (s) => /^[A-Za-z0-9+/]+={0,2}$/.test(String(s || '')) && String(s).length % 4 === 0;
  const dims = [];
  // 密文候选：AI 给的那条 + 扫描器从二进制抽到的全部十六进制常量。
  // 为什么需要：实测多道题的失败根因是"AI 抄错了密文"——它从反编译里挑了一条看起来像的，
  // 而真正被校验函数引用的那条在别处。工具已有确定性扫描结果（state.lastAlgScan 的
  // highEntropy / 常量命中），把它们一并喂进枚举，等于让工具替 AI 试遍所有候选。
  const scannedCts = [];
  try {
    const sc = state.lastAlgScan || {};
    const pushHex = (h) => {
      const v = String(h || '').replace(/[^0-9a-fA-F]/g, '');
      if (v.length >= 16 && v.length % 2 === 0 && v.length <= 512) scannedCts.push(v);
    };
    (sc.highEntropy || []).forEach(h => pushHex(h.hex));
    (sc.summary || []).forEach(s => {
      const m = String(s.evidence || '').match(/\b[0-9a-fA-F]{16,}\b/g);
      if (m) m.forEach(pushHex);
    });
  } catch (e) { /* 扫描结果不可用则只用 AI 给的 */ }
  // 没有 AI 密文时，扫描候选就是唯一来源：多取几条（仍设上限，避免候选爆炸）。
  const hasAiCt = base.some(c => c.ciphertext);
  // AI 没给密文、扫描结果也没有 → 无法枚举（没有待解密的数据），明确返回空而不是造空尝试。
  if (!hasAiCt && !scannedCts.length) return [];
  const scannedLimit = hasAiCt ? 4 : 10;
  const ctCandidates = [...new Set([].concat(
    base.map(c => String(c.ciphertext || '')),
    scannedCts.slice(0, scannedLimit)
  ).filter(Boolean))].slice(0, hasAiCt ? 5 : 12);

  for (const c of base.slice(0, 6)) {
    const algo = String(c.algo || '').toLowerCase();
    const variants = [algo];
    // 算法族扩展：同一份 key/密文常能换个模式/同族算法解出
    if (/aes_cbc/.test(algo)) variants.push('aes_ecb');
    if (/aes_ecb/.test(algo)) variants.push('aes_cbc');
    if (/des_cbc/.test(algo)) variants.push('des_ecb');
    if (/des_ecb/.test(algo)) variants.push('des_cbc');
    if (/chacha/.test(algo)) variants.push('chacha20_ietf', 'chacha20_original');
    if (/^[a-z0-9_]*_cbc$/.test(algo)) variants.push(algo.replace('_cbc', '_ecb'));
    if (/^[a-z0-9_]*_ecb$/.test(algo)) variants.push(algo.replace('_ecb', '_cbc'));
    // TEA 族：字节序是最常见的失败点。AI 常只给 algo=tea，而数据可能是大端存放。
    // Python solver 通过 attempt 的 `variant` 字段选择解包格式（见 buildSolvePython 的
    // dec_tea/dec_xtea/dec_xxtea 调用），所以这里展开成两档 variant 而不是改 algo 名。
    // 非 TEA 算法必须保留一个占位（null），否则下面的 for 循环会因空数组而不产生任何尝试。
    const isTea = /tea/.test(algo);
    const teaVariantCands = isTea
      ? [...new Set([c.variant, 'le32', 'be32'].filter(Boolean))]
      : [c.variant || null];
    // 密钥编码候选：AI 声明的优先，但**不盲信**——密钥形态像 hex/base64 时一并试，
    // 因为 AI 常把 hex 密钥标成 ascii（反之亦然），这是"单契约必然失败"的高频根因。
    const declared = c.key_encoding ? [c.key_encoding] : [];
    const guessed = [];
    if (hexLike(c.key)) guessed.push('hex');
    if (b64Like(c.key)) guessed.push('base64');
    guessed.push('ascii', 'hex', 'base64');
    const keyEncs = [...new Set(declared.concat(guessed))];
    // IV 候选：声明的 / 全零 / 密文首块。CBC 类最常见失败点是"IV 其实是全零"或"IV 就是密文首块"。
    // 这三者靠 Python solver 内部的 iv 枚举也能覆盖一部分，但显式列出能让归因更准确
    // （失败时能区分"IV 错"和"算法错"）。
    const ivCands = [];
    if (c.iv) ivCands.push(String(c.iv));
    ivCands.push('', '0000000000000000');
    for (const ivv of [...new Set(ivCands)]) {
      for (const ke of keyEncs) {
        for (const a of variants) {
          for (const tv of teaVariantCands) {
            for (const ct of ctCandidates) {
              dims.push(Object.assign({}, c, {
                algo: a, key_encoding: ke, iv: ivv, ciphertext: ct,
                ...(tv ? { variant: tv } : {}),
              }));
            }
          }
        }
      }
    }
  }
  // 去重（algo+key_encoding+key+iv+variant+密文前缀 相同视为同一尝试）
  // ⚠️ variant 必须进键：TEA 族的 le32/be32 是两组不同尝试，漏掉会被误合并成一组。
  const seen = new Set();
  const out = [];
  for (const d of dims) {
    const k = [d.algo, d.key_encoding, String(d.key || ''), String(d.iv || ''), String(d.variant || ''), String(d.ciphertext || '').slice(0, 32)].join('|');
    if (seen.has(k)) continue;
    seen.add(k); out.push(d);
    if (out.length >= 40) break;
  }
  return out;
}

// 判定一段"明文"是否其实是可执行机器码（自解密/自解压的下一层）。
// 实测（CrackMe3）：AI 用自定义 RC4 变体解出 `83ec18b0 65b16388 ... c3 90 90`，
// 那是一段完整的 x86 函数（sub esp,0x18 … ret nop nop）——密钥和算法都对，
// 拿到的只是**代码层**。旧归因把它算作"可打印但无 flag → 换算法族"，方向完全相反。
//
// 判据全部来自字节形态本身（不引入题目特定知识）：
//   · printable() 会把不可打印字节渲染成 hex → 预览几乎全为 hex 数字
//   · 长度足够（≥16 字节）才有"像代码"的意义
//   · 命中常见 x86/x64 序言（push ebp; mov ebp,esp / sub esp,N / 48 89 e5）或收尾（ret / int3/nop 填充）
function looksLikeMachineCode(s) {
  const t = String(s || '').replace(/[\s.]/g, '').toLowerCase();
  if (t.length < 32) return false;
  if (!/^[0-9a-f]+$/.test(t)) return false;
  const head = t.slice(0, 64);
  const tail = t.slice(-24);
  const prologue = /(^|.*?)(55(89|8b)e5|55(89|8b)ec|83ec[0-9a-f]{2}|4883ec[0-9a-f]{2}|48(89|8b)e5)/;
  const epilogue = /(c3|c2[0-9a-f]{4})/;
  const padding = /90{4,}|cc{4,}/;
  const hasPro = prologue.test(head);
  const hasEpi = epilogue.test(tail) || epilogue.test(head);
  const hasPad = padding.test(head) || padding.test(tail);
  return (hasPro && hasEpi) || (hasPro && hasPad) || (hasEpi && hasPad);
}

// 从求解脚本输出中提取"解出的代码层"证据（预览行 / 原始输出行）
function findDecodedLayer(outputText) {
  const text = String(outputText || '');
  const previews = [...text.matchAll(/\[MISS\][^\r\n]*result=no-flag[^\r\n]*preview=([^\r\n]*)/g)]
    .map(m => m[1]);
  const outs = [...text.matchAll(/\[OUT\] attempt=\d+ keyenc=\S+: ([^\r\n]*)/g)].map(m => m[1]);
  const hits = outs.filter(looksLikeMachineCode).concat(previews.filter(looksLikeMachineCode));
  return { count: hits.length, sample: hits[0] ? hits[0].slice(0, 120) : '' };
}

// 解析求解脚本的结构化失败输出 → 归因摘要（Phase 3）
// 目的：把"30 个脚本都失败"变成"22 个算法选错（garbage）、5 个 key 错（no-flag）、3 个报错（TypeError）"，
// 让 AI 下一步有方向，而不是重头再来。
function attributeFailure(output, attempts) {
  const text = String(output || '');
  const fails = [];     // [{attempt, algo, keyenc, stage, reason}]
  const misses = [];    // [{attempt, algo, keyenc, result, preview}]
  let m;
  const reF = /\[FAIL\]\s*attempt=(\d+)\s+algo=(\S+)\s+keyenc=(\S+)\s+stage=(\S+)\s+reason=([^\r\n]*)/gi;
  while ((m = reF.exec(text)) !== null) {
    fails.push({ attempt: +m[1], algo: m[2], keyenc: m[3], stage: m[4], reason: m[5].trim() });
  }
  const reM = /\[MISS\]\s*attempt=(\d+)\s+algo=(\S+)\s+keyenc=(\S+)\s+stage=(\S+)\s+result=(\S+)\s+preview=([^\r\n]*)/gi;
  while ((m = reM.exec(text)) !== null) {
    misses.push({ attempt: +m[1], algo: m[2], keyenc: m[3], stage: m[4], result: m[5], preview: m[6].trim() });
  }
  const total = Array.isArray(attempts) ? attempts.length : 0;
  const errFails = fails.filter(f => /^decrypt$/.test(f.stage));
  const garbage = misses.filter(x => x.result === 'garbage').length;
  const empty = misses.filter(x => x.result === 'empty').length;
  const noFlag = misses.filter(x => x.result === 'no-flag').length;
  const algoSet = [...new Set(misses.map(x => x.algo).concat(fails.map(f => f.algo)))];

  // ── "解出来的其实是机器码/结构化数据，不是明文"判定 ──
  // 详见 looksLikeMachineCode 的说明：形态判定优先于"换算法"归因。
  const dl = findDecodedLayer(text);
  const decodedLayer = dl.count;

  // 归因结论：给出"最可能是什么错了"的判断（仅基于结构化输出，不猜测）
  const hints = [];
  if (errFails.length) {
    const byReason = {};
    for (const f of errFails) { const k = f.reason.split(':')[0]; byReason[k] = (byReason[k] || 0) + 1; }
    // 区分两类：
    //   · **代码缺陷**（ZeroDivision/Index/Key/Type/Attribute/Name/UnboundLocal）——
    //     AI 生成的脚本本身写错了，应该修代码，不是换算法。
    //     实测（not-baby-parallelism）：`post//src if post%src==0`，src=0 直接崩。
    //   · **参数形态不匹配**（ValueError，如 key 长度 8 字节、IV 非 16 字节）——
    //     算法可能对，是喂进去的参数不对。
    const codeBugs = errFails.filter(f => /ZeroDivisionError|IndexError|KeyError|TypeError|AttributeError|NameError|UnboundLocal/.test(f.reason));
    const paramErrs = errFails.filter(f => !codeBugs.includes(f));
    if (codeBugs.length) {
      const kinds = [...new Set(codeBugs.map(f => f.reason.split(':')[0]))];
      hints.push(`AI 生成的脚本有 Python 运行时缺陷 ${codeBugs.length} 次（${kinds.join(', ')}）→ **先修代码再重试**：`
        + '检查除零/越界/空列表索引；对 `a/b`、`a%b` 先判 b!=0；对 `arr[i]` 先判边界；'
        + '不要因为脚本崩溃就判定算法错。');
    }
    if (paramErrs.length) {
      const kinds = [...new Set(paramErrs.map(f => f.reason.split(':')[0]))];
      hints.push(`解密阶段报错 ${paramErrs.length} 次（${kinds.join(', ')}）→ 多为参数形态不匹配（key 长度/编码/函数签名），不是算法错`);
    }
  }
  if (decodedLayer) {
    // 这条必须排在 garbage/no-flag 之前：解出机器码说明"解密本身成功了"，
    // 若还按"换算法"去提示，AI 会把唯一正确的密钥丢掉重来。
    hints.push(`解出的内容是**可执行机器码**（${decodedLayer} 处，样本：${dl.sample}）→ `
      + '**解密参数是对的，这不是明文层，而是自解密/自解压的下一层代码**。'
      + '正确动作：把这段字节**写盘为新文件**（如 stage_next.bin / .exe），确认 MZ/ELF 头后调用 `switch_to_next_stage` 接力；'
      + '不要换算法、不要换 key，也不要把它当乱码丢弃。');
  }
  if (garbage > 0) hints.push(`解出乱码 ${garbage} 次 → 算法或 key/iv 选错（若全部乱码，优先换算法族而不是换 key）`);
  if (empty > 0) hints.push(`解出空串 ${empty} 次 → 密文/偏移取错，或该候选不是这条数据`);
  if (noFlag > 0 && !decodedLayer) hints.push(`解出可打印但无 flag ${noFlag} 次 → 可能是中间值层（还需再解一层）或 key 正确但算法模式（ECB/CBC/轮序）错`);
  if (noFlag > 0 && decodedLayer) hints.push(`另有 ${noFlag} 次解出可打印文本但无 flag → 与上面的机器码对照，判断哪条是数据层、哪条是代码层`);
  if (!fails.length && !misses.length && total) hints.push('脚本未输出结构化归因（旧模板或执行异常）');
  return {
    total, fails, misses,
    summary: { errFails: errFails.length, garbage, empty, noFlag, algos: algoSet, decodedLayer },
    decodedLayer,
    hints,
    text: hints.length ? hints.join('\n') : '（无可用归因）',
  };
}

// Phase 3.3：把"已排除的路"持久化到本题 CASE，下次注入提示词（避免重复烧预算）
function excludedPathKey() { return state.caseDir ? `${state.caseDir}/excluded_paths.json` : ''; }
async function saveExcludedPaths(entries) {
  const key = excludedPathKey();
  if (!key || !Array.isArray(entries) || !entries.length) return;
  try {
    const rf = await window.electronAPI.readFile(key);
    let cur = [];
    if (rf && rf.success) { try { cur = JSON.parse(rf.content || '[]'); } catch (e) { cur = []; } }
    const seen = new Set(cur.map(x => `${x.algo}|${x.keyenc}|${x.reason}`));
    for (const e of entries) {
      const k = `${e.algo}|${e.keyenc}|${e.reason}`;
      if (!seen.has(k)) { cur.push({ ...e, ts: new Date().toISOString() }); seen.add(k); }
    }
    await window.electronAPI.writeFile(key, JSON.stringify(cur.slice(-40), null, 2));
  } catch (e) { /* 落盘失败不阻塞 */ }
}
async function loadExcludedPaths() {
  const key = excludedPathKey();
  if (!key) return '';
  try {
    const rf = await window.electronAPI.readFile(key);
    if (!rf || !rf.success) return '';
    const arr = JSON.parse(rf.content || '[]');
    if (!Array.isArray(arr) || !arr.length) return '';
    const uniq = [];
    const seen = new Set();
    for (const x of arr) {
      const k = `${x.algo}|${x.keyenc}|${x.reason}`;
      if (seen.has(k)) continue;
      seen.add(k); uniq.push(x);
    }
    return uniq.slice(-12).map(x => `- ${x.algo}（key 编码 ${x.keyenc}）：${x.reason}`).join('\n');
  } catch (e) { return ''; }
}

// Phase 3.3：按**信息增益**给候选排序（不是随机顺序，也不是全并行）。
// 依据：① 工具已识别的算法（high 置信度）优先；② 短 key 优先（计算快、常见）；
//      ③ 常见编码（hex/ascii）优先；④ 已排除的组合降权到末尾（仍保留一次机会，但最后试）。
// 这比"全并行"更实用：脚本是单进程顺序执行，真正省时间的是"先试最可能成功的"。
function rankAttempts(attempts, opts = {}) {
  if (!Array.isArray(attempts)) return [];
  const known = (opts.knownAlgos || []).map(a => String(a).toLowerCase());
  const excluded = opts.excluded || new Set();
  const score = (a) => {
    let s = 0;
    const algo = String(a.algo || '').toLowerCase();
    const ke = String(a.key_encoding || 'ascii').toLowerCase();
    const key = String(a.key == null ? '' : a.key);
    // 工具识别出的算法：高优先级
    if (known.some(k => k && (algo.includes(k) || k.includes(algo)))) s += 100;
    // 标准算法族略优先于 custom（custom 依赖 AI 的代码质量）
    if (algo === 'custom' || algo === 'node_js') s -= 10;
    // 常见 key 编码
    if (ke === 'hex') s += 8;
    else if (ke === 'ascii') s += 6;
    else if (ke === 'base64') s += 2;
    // 常见 key 长度（8/16/24/32 字节）
    const kl = key.length;
    if ([8, 16, 24, 32].includes(kl)) s += 5;
    // 无 expected 的候选优先级略低（AI 自己也不确定）
    if (!a.expected) s -= 3;
    if (!a.ciphertext) s -= 20;
    // 已排除组合：降到末尾（仍试，但最后）
    const ek = `${algo}|${ke}`;
    if (excluded.has(ek)) s -= 200;
    return s;
  };
  return attempts
    .map((a, i) => ({ a, i, s: score(a) }))
    .sort((x, y) => (y.s - x.s) || (x.i - y.i))
    .map(x => x.a);
}

// 本地枚举：解析 [HYPOTHESES] → 并行尝试全部组合 → 命中即记
async function runHypotheses(aiText, opts = {}) {
  state.lastEnumFeedback = '';   // 每次枚举重置；仅"全部候选无效"时填充（finalizeSolve 拼进 retryPrompt）
  let attempts = Array.isArray(aiText) ? aiText : parseHypotheses(aiText);
  if (!attempts.length && Array.isArray(opts.synthFrom)) {
    // 无 [HYPOTHESES] 契约 → 工具自行合成候选矩阵（举一反三，避免原地卡死）
    attempts = synthesizeHypotheses(opts.synthFrom);
    if (attempts.length) addLog('info', `[本地枚举] AI 未给 [HYPOTHESES]，工具自动合成 ${attempts.length} 组候选（算法/编码/模式变体）...`);
  } else if (attempts.length && Array.isArray(opts.synthFrom) && opts.augmentSynth) {
    // ── P1：AI 给了 HYPOTHESES，但**已确认这些假设全部失败**时，追加工具合成维度 ──
    // 为什么需要：AI 的候选往往在同一组假设里打转（同样的 key/编码，只换顺序）。
    // 工具合成会补上它想不到的维度：全零 IV、扫描器抽到的其他密文、TEA 字节序。
    // 只在 augmentSynth 显式要求时追加（由"契约已失败"的调用方设置），
    // 避免在 AI 首次给假设时就把候选池撑爆。
    const synth = synthesizeHypotheses(opts.synthFrom);
    if (synth.length) {
      const seen = new Set(attempts.map(a => [a.algo, a.key_encoding, a.key, a.iv, a.variant, String(a.ciphertext || '').slice(0, 32)].join('|')));
      let added = 0;
      for (const s of synth) {
        const k = [s.algo, s.key_encoding, s.key, s.iv, s.variant, String(s.ciphertext || '').slice(0, 32)].join('|');
        if (seen.has(k)) continue;
        seen.add(k); attempts.push(s); added++;
      }
      if (added) addLog('info', `[本地枚举] AI 的假设已失败，工具追加 ${added} 组补充维度（IV/密文候选/字节序）`);
    }
  }
  if (!attempts.length) {
    addLog('warning', '[本地枚举] 无可枚举候选（AI 未给 [HYPOTHESES]，且缺少可合成的密文契约）');
    return null;
  }
  // Phase 3.3：剪掉"上次已排除"的候选（同 algo+keyenc+密文前缀 且已知失败原因）
  const excluded = await loadExcludedPaths();
  if (excluded && attempts.length > 4) {
    // 只做提示，不硬剪（AI 可能这轮换了 key/密文，硬剪会误伤）；真正的剪枝信息在下方注入
    addLog('info', '[本地枚举] 已加载本题历史排除路径（将随结果一并回灌）');
  }
  const cap = opts.synthFrom ? 24 : 16;
  if (attempts.length > cap) attempts = attempts.slice(0, cap);
  // Phase 3.3：按信息增益排序（工具识别的算法优先、已排除组合降权到末尾）
  try {
    // 同样只能读 state（本函数在多个求解流程里被调用，没有 analysisData 入参）
    const knownAlgos = ((state.lastAlgScan && state.lastAlgScan.summary) || [])
      .filter(s => (s.confidence === 'high' || s.confidence === 'medium')
        && !/内嵌\s*(PE|ELF|DEX|载荷)|编码存储/i.test(String(s.algo || '')))   // 排除"载荷定位"类结论
      .map(s => s.algo);
    const exSet = new Set();
    if (excluded) {
      for (const line of String(excluded).split('\n')) {
        const m = line.match(/^-\s*(\S+)（key 编码 (\S+)）/);
        if (m) exSet.add(`${m[1].toLowerCase()}|${m[2].toLowerCase()}`);
      }
    }
    attempts = rankAttempts(attempts, { knownAlgos, excluded: exSet });
    if (knownAlgos.length) addLog('info', `[本地枚举] 已按信息增益排序（优先：${knownAlgos.join('/')}）`);
  } catch (e) { /* 排序失败不阻塞 */ }
  addLog('info', `[本地枚举] ${attempts.length} 个候选组合（算法/密钥/字节序）...`);
  // 逐条做形态校验：只有三种 invalid（需密文却空 / 输入非空输出空 / 退化摘要）。
  // 无 key 无密文的合法变换必须放行（synthesizeHypotheses 明确允许无 ciphertext）。
  const attemptRecords = [];
  attempts = attempts.filter(a => {
    const v = validateCandidateAttempt(a);
    if (!v.ok) {
      addLog('warning', `[本地枚举] 候选无效: ${v.reason}`);
      attemptRecords.push(recordAttemptRecord(a, { valid: false, reason: v.reason }));
      return false;
    }
    return true;
  });
  if (!attempts.length) {
    // 定向反馈（40 题实测：17 连"候选无效"后直接放弃，AI 永远不知道缺哪个维度）。
    // 聚合无效原因，交由 finalizeSolve 拼进 retryPrompt 驱动重试。
    const cat = { noCt: 0, emptyOut: 0, degenerate: 0 };
    for (const rec of attemptRecords) {
      const r = String((rec && rec.reason) || '');
      if (/需要密文/.test(r)) cat.noCt++;
      else if (/输出为空/.test(r)) cat.emptyOut++;
      else if (/退化摘要/.test(r)) cat.degenerate++;
    }
    const advice = [];
    if (cat.noCt) advice.push(`- ${cat.noCt} 组候选缺少真实密文（ciphertext 为空）：请从代码/数据里取出被校验的密文常量（附地址或偏移），再给 [VERIFY] 契约。没有密文的"解密"无法本地复现。`);
    if (cat.emptyOut) advice.push(`- ${cat.emptyOut} 组候选"输入非空但输出为空"：解密函数没真正执行（多半是 key/密文配错或算法族错），请核对 key 来源与密文的对应关系。`);
    if (cat.degenerate) advice.push(`- ${cat.degenerate} 组输出是退化摘要（空输入的哈希）：说明输入没取到，请检查密文偏移/长度。`);
    state.lastEnumFeedback = [
      `本地枚举的 ${attemptRecords.length} 组候选全部无效，未能复现。失败原因汇总：`,
      ...advice,
      '请基于以上修正：给出带真实密文的 [VERIFY]，或明确说明为何拿不到密文（例如目标值是运行时生成）。',
    ].join('\n');
    addLog('warning', '[本地枚举] 全部候选均被形态校验判为无效，未执行本地复现（已生成定向修正提示）');
    state.lastAttemptRecords = attemptRecords;
    return null;
  }
  const r = await runContractScript(attempts);
  for (const a of attempts) {
    attemptRecords.push(recordAttemptRecord(a, { valid: true, hit: false }));
  }
  state.lastAttemptRecords = attemptRecords;
  if (r.output) caseAddEvidence('hypotheses', '假设枚举输出', r.output, 'log');

  // Phase 3.2：结构化归因（失败也有信息量）
  const attr = attributeFailure(r.output, attempts);
  if (attr.total > 1) {
    addLog('info', `[归因] ${attr.text.replace(/\n/g, ' | ')}`);
    addSolveNote('失败归因', attr.text.replace(/\n/g, ' ').slice(0, 500));
    // 把失败候选登记为"已排除路"（供下一轮提示词，避免重跑）
    const excludedEntries = [];
    for (const f of attr.fails.slice(0, 8)) {
      const a = attempts[f.attempt] || {};
      excludedEntries.push({ algo: f.algo, keyenc: f.keyenc, reason: `${f.stage} 报错 ${f.reason.slice(0, 60)}`, key: String(a.key || '').slice(0, 32) });
    }
    for (const x of attr.misses.filter(x => x.result === 'garbage').slice(0, 8)) {
      const a = attempts[x.attempt] || {};
      excludedEntries.push({ algo: x.algo, keyenc: x.keyenc, reason: '解出乱码（算法/key/iv 不符）', key: String(a.key || '').slice(0, 32) });
    }
    if (excludedEntries.length) await saveExcludedPaths(excludedEntries);
  }

  // 区分三类命中（举一反三：多阶段题普遍在第一层埋诱饵，把诱饵当"✅命中"= 假成功收工）：
  //   · 真 flag 形态 → 确认成功
  //   · 诱饵串（fake/decoy/假flag…）→ 只提示"这是诱饵，继续找真载体"，绝不报成功
  //   · 其它（key/中间值）→ 复现成功但非 flag
  const flagHits = r.hits.filter(h => looksLikeFlag(h));
  const decoyHits = r.hits.filter(h => !looksLikeFlag(h) && isDecoyFlag(h));
  const midHits = r.hits.filter(h => !looksLikeFlag(h) && !isDecoyFlag(h));
  if (flagHits.length) {
    flagHits.forEach(h => recordFlag(h, 'hypotheses', true));
    addSolveNote('本地枚举命中', flagHits.join(', '));
    addLog('success', `[本地枚举] ✅ 命中: ${flagHits.join(', ')}`);
    addSystemMessage(`**🎯 本地枚举命中**\n\n${flagHits.map(h => `\`${h}\``).join('\n\n')}\n\n（算法/密钥/字节序组合由 AI 假设 + 本地并行验证得出）`);
    return { verified: true, hits: flagHits, attribution: attr, excluded };
  }
  if (decoyHits.length) {
    addSolveNote('本地枚举', `命中诱饵（非真 flag）：${decoyHits.join(', ')}`);
    addLog('warning', `[本地枚举] ⚠️ 命中的是**诱饵**（如 fake/假flag）：${decoyHits.join(', ')} —— 本题该层是 decoy，真 flag 在下一层载体里`);
    addSystemMessage(`**⚠️ 本地枚举只命中了"诱饵"**\n\n${decoyHits.map(h => `\`${h}\``).join('\n\n')}\n\n这类串自曝身份（fake/假flag），**不是真 flag**。说明当前层是**诱饵层/壳**——请找出并提取下一层载体（内嵌 PE/解密后的文件）后继续，不要就此收工。`);
    return { verified: false, hits: [], decoy: decoyHits, attribution: attr, excluded };
  }
  if (midHits.length) {
    addLog('info', `[本地枚举] 命中中间值/密钥（非 flag）：${midHits.join(', ')}`);
    return { verified: false, hits: [], mid: midHits, attribution: attr, excluded };
  }
  addLog(opts.quiet ? 'info' : 'warning', '[本地枚举] 全部候选未命中，输出已存入证据目录');
  return { verified: false, hits: [], attribution: attr, excluded };
}

// 经验去重键：剥离「- [日期] 」前缀与全部标点/空白后比对。
// 关键修复：旧实现按"整行字符串"比对，同一条经验换个日期就成了"新行"→ 必然重复入库。
function experienceKey(s) {
  return String(s || '')
    .replace(/^-?\s*\[\d{4}-\d{2}-\d{2}\]\s*/, '')
    .toLowerCase()
    .replace(/[\s\-_*•·▶→,，。;；:：、|/\\()（）\[\]【】"'“”‘’`]+/g, '')
    .trim();
}

// 判两条经验是否"实为同一条"（措辞微调 / 补半句 / 顺序调换）：
//   · Jaccard 相似度 ≥0.78（措辞级微调、顺序调换）
//   · 或短的那条是长的那条的**完整子串**（只是补了半句，且短条足够长以免误判）
// 阈值经真实样本校准：真重复 jac 落在 0.815~0.944 或为完整子串；而"套路相同但确是不同的题"
// 最高 jac=0.744 且不构成子串 → 以 0.78 居中切分，两侧各留 ~0.035 余量，不误合并不同题。
function experienceSimilar(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  const short = a.length <= b.length ? a : b;
  const long = a.length <= b.length ? b : a;
  if (short.length >= 12 && long.includes(short)) return true;   // 完整子串 = 补了半句
  const bigrams = (s) => { const out = new Set(); for (let i = 0; i < s.length - 1; i++) out.add(s.slice(i, i + 2)); return out; };
  const A = bigrams(a), B = bigrams(b);
  if (!A.size || !B.size) return false;
  let inter = 0; for (const x of A) if (B.has(x)) inter++;
  const union = A.size + B.size - inter;
  return union > 0 && (inter / union) >= 0.78;
}

// 把经验条目写入 experience.md（首建补表头 → 逐条追加 → 更新内存 → 按上限修剪）。
// 抽成单一入口，供"解题成功自动入库"与「保存」手动入库共用，避免两处各写一遍。
async function writeExperienceEntries(lines) {
  if (!state.appPaths || !Array.isArray(lines) || !lines.length) return 0;
  const expPath = `${state.appPaths.userData}/experience.md`;
  const rf = await window.electronAPI.readFile(expPath);
  if (!rf || !rf.success) {
    await window.electronAPI.writeFile(expPath, '# 解题经验库（reverse-skill 进化层：AI 解题前自动速查）\n\n');
  }
  let n = 0;
  for (const line of lines) {
    const r = await window.electronAPI.appendFile(expPath, line + '\n');
    if (r && r.success) { state.experience += line + '\n'; n++; }
  }
  if (n) await pruneExperience();
  return n;
}

// 解题学习闭环：从 AI 回答中收割 [EXPERIENCE]...[/EXPERIENCE] 经验块，供下次解题自动速查。
// 支持"多步攻击链"：一条经验若含 `→` 分隔的步骤（或子行以 ·/数字开头）→ 存为
//   一条"链式"经验（特征▶步骤1▶步骤2▶…▶坑），而非拆成互不相关的单行；单行经验保持兼容。
// 入库策略：解题成功（opts.autoSave=true，调用方已确认有已验证 flag）→ **自动入库**；
//   否则仅暂存，等用户发送「保存」再入库。两条路径都做内容级去重（与日期无关）。
async function harvestExperience(aiText, opts = {}) {
  try {
    const text = String(aiText || '');
    const m = text.match(/\[(?:EXPERIENCE|经验)\]([\s\S]*?)\[\/(?:EXPERIENCE|经验)\]/i);
    if (!m || !state.appPaths) return 0;
    // 先按"顶层条目"分组：以 -/*/数字 开头的行是条目起点；其后续不带标记的行视为该条目的续行（步骤）
    const groups = [];
    for (const raw of m[1].split('\n')) {
      const l = raw.replace(/\s+$/, '');
      const isStart = /^\s*([-*•]+|\d+[.、)])\s+/.test(l) || (l.trim() && !/^\s/.test(l) && groups.length === 0);
      if (isStart) groups.push([l.trim()]);
      else if (l.trim() && groups.length) groups[groups.length - 1].push(l.trim());
    }
    const norm = (s) => s.replace(/^[-*•]+\s*/, '').replace(/^\d+[.、)]?\s*/, '').replace(/^[-*•]+\s*/, '').trim();
    const entries = [];
    for (const g of groups) {
      // 把该条的续行合并（用 ▶ 连接），并把正文里已有的 '→' 统一成 '▶'，形成"攻击链"
      let body = g.map(norm).filter(Boolean).join(' ▶ ');
      body = body.replace(/\s*→\s*/g, ' ▶ ').replace(/\s*▶\s*(▶\s*)+/g, ' ▶ ').trim();
      if (!body || /^(无|无新增经验|无新增|none)$/i.test(body) || body.length <= 4) continue;
      entries.push(body.slice(0, 400));
    }
    if (!entries.length) return 0;

    // 内容级去重：把"已入库"与"已暂存"的经验都归一成键，逐条比对（精确匹配 + 近似匹配）
    if (!Array.isArray(state.pendingExperience)) state.pendingExperience = [];
    const existing = [];
    for (const l of String(state.experience || '').split('\n')) { const k = experienceKey(l); if (k) existing.push(k); }
    for (const l of state.pendingExperience) { const k = experienceKey(l); if (k) existing.push(k); }
    const fresh = [];
    for (const body of entries.slice(0, 5)) {
      const key = experienceKey(body);
      if (!key) continue;
      if (existing.some(k => k === key || experienceSimilar(k, key))) continue;
      existing.push(key);
      fresh.push(`- [${new Date().toISOString().slice(0, 10)}] ${body}`);
    }
    if (!fresh.length) {
      addLog('info', '本题经验与经验库/暂存区重复，未新增（去重：与日期无关的内容比对）');
      return 0;
    }

    if (opts.autoSave) {
      // 解题成功 → 直接入库（无需人工发「保存」）
      // 同时把**本题更早阶段已暂存**的经验一并入库：那些暂存来自同一次解题的前序 AI 调用
      // （如阶段2 初步分析暂存、阶段2.5 Tool-Use 才解出 flag），它们在收到本次成功信号时
      // 已确认"属于一道已解出的题"，应一并沉淀；否则会滞留内存、关应用即丢。
      const pendingNow = Array.isArray(state.pendingExperience) ? state.pendingExperience.slice() : [];
      // 防御性去重：writeExperienceEntries 自身不判重，这里按内容键（含近似）合并去重，避免重复行。
      const allFresh = [];
      const seenKeys = [];
      for (const line of [...fresh, ...pendingNow]) {
        const k = experienceKey(line);
        if (!k || seenKeys.some(x => x === k || experienceSimilar(x, k))) continue;
        seenKeys.push(k);
        allFresh.push(line);
      }
      const n = await writeExperienceEntries(allFresh);
      if (n) {
        allFresh.forEach(l => addSolveNote('经验', l.replace(/^- \[[^\]]+\] /, '').slice(0, 200)));
        addLog('success', `✅ 解题成功，自动沉淀 ${n} 条新经验（含前序暂存 ${pendingNow.length} 条，已入库，内容级去重）`);
        addSystemMessage(`**🧠 经验已自动入库（${n} 条）**\n\n${allFresh.map(l => '> ' + l.replace(/^- \[[^\]]+\] /, '')).join('\n\n')}\n\n下次同类题自动注入速查（无需手动保存）。`);
      }
      state.pendingExperience = [];
      return n;
    }
    // 未确认解题成功 → 仅暂存，用户发「保存」才写入
    for (const line of fresh) {
      state.pendingExperience.push(line);
      addSolveNote('经验(待保存)', line.replace(/^- \[[^\]]+\] /, '').slice(0, 200));
    }
    addLog('info', `本题提炼出 ${fresh.length} 条经验（已暂存，未入库）。需要沉淀时发送「保存」写进经验库`);
    addSystemMessage(`**💾 经验已暂存（未入库）**\n\n${fresh.map(l => '> ' + l.replace(/^- \[[^\]]+\] /, '')).join('\n\n')}\n\n未确认解题成功：发送 **保存** 后才写入经验库（experience.md）。`);
    return fresh.length;
  } catch (e) {
    addLog('warning', '经验暂存失败: ' + e.message);
    return 0;
  }
}

// 经验注入段：把与"当前题特征"最相关的历史经验拼成系统提示片段。
// 供 buildSystemPrompt 与各求解流程（含原本写死 system prompt 的 APK/PE 路径）共用，
// 解决"经验存了却从不被复用"的问题。
function experienceSection() {
  if (!state.experience) return '';
  const picked = selectRelevantExperience(state.experience, state.findings);
  if (!picked) return '';
  return `\n\n## 历史经验速查（此前解题沉淀：同类场景优先复用、勿重踩已记录的坑）\n${picked}`;
}

// 自动预取知识库攻略：从本题已采集的代码/字符串里抽取"算法/工具/混淆"特征词，
// 主动调用 wiki_search 检索历年题条目库 + 手法专题页，把最相关的摘要内联进提示词。
// 为什么必须内联：APK/PE 两条"固定清单"主路径在提示词里**明令禁止调用工具**，
// 若不预先取好，AI 既看不到题库也无权查 → 43 篇题库页 + frida/firmware 手法页形同虚设。
async function prefetchKnowledge(haystack, fileType, extra = []) {
  try {
    const api = window.electronAPI;
    if (!api || !api.wikiSearch) return '';
    const hay = String(haystack || '').toLowerCase();
    // 可在题面代码/字符串里探测到的特征词（算法族/工具/混淆/语言/平台）
    const POOL = ['rc4', 'tea', 'xtea', 'xxtea', 'aes', 'des', '3des', 'sm4', 'sm3', 'chacha20', 'chacha', 'salsa20',
      'twofish', 'blowfish', 'idea', 'base64', 'md5', 'sha256', 'sha1', 'rsa', 'xor', 'rot13', 'caesar', 'crc32',
      's-box', 'sbox', 'whitebox', '白盒', 'dfa', 'ollvm', 'vm', 'upx', 'frida', 'registernatives', 'jni', 'smali',
      'realm', 'macho', 'pyc', 'marshal', 'cuda', 'ptx', 'riscv', 'qemu', '固件', 'firmware', 'unidbg', 'angr',
      'unicorn', 'z3', '反调试', 'ptrace', 'hook', 'native',
      // Python/字节码类
      'pickle', 'renpy', 'rpyc', 'cython', 'pyinstaller', 'co_code', 'pydisasm',
      // Java/Android 字节码类（DEX/JAR/class）
      'jadx', 'dex2jar', 'smali', 'classloader', 'sharedpreferences', 'jni', 'il2cpp', 'unity',
      // Lua 字节码类
      'luac', 'unluac', 'luaopcode',
      // Web/JS 逆向类
      'jsencrypt', 'cryptojs', 'sign', 'token', 'x-bogus', 'a_bogus', '_0x', 'sm2', 'sm3', 'wasm', 'jsvmp', '瑞数',
      // 动态调试类：命中即把「先静态取数、锁定函数再定向调试」的方法论拉进提示词。
      // 不补这些词的话，新方法论页只能靠 AI"主动想起来"去查——实测等于没写。
      '动态调试', '调试', '断点', '单步', 'smc', '自修改', '反调试', 'ptrace', 'isdebuggerpresent',
      'self-modifying', '自解码', '解密后执行', 'virtualprotect', 'mprotect', '运行时解密',
      // 花指令类：反编译失败时 AI 应当主动想到 junk_scan
      '花指令', 'junk', 'sp-analysis', '反编译失败', '指令错位', '解码错位', '栈平衡',
      'opaque predicate', '不透明谓词', '互补跳转', '垃圾代码',
      'gui', 'dialogbox', 'winmain', '消息循环', '窗口', 'crackme',
      'tickcount', 'getsystemtime', '时间相关', '环境检测'];
    const hits = POOL.filter(t => hay.includes(t));
    // ── 按"常量/结构特征"反查算法（关键增强）──
    // 教训（Disguise 实测）：魔改/VM 化的标准算法题，代码里**没有算法名字面量**（无 "sm4"/"aes"），
    // 只有 S 盒常量、FK/CK、轮结构。旧逻辑只按字面量选检索词 → 检索词退化为 "native"，
    // AI 每次都往 AES 猜，国密方法页完全没被用上。
    // 实测踩坑（两版都失败过，务必看清数据在 haystack 里的真实形态）：
    //  ①数据表经 bytesToInt32LE 渲染成 **每 4 字节打包的有符号 int32**（如 [-18247466, ...]），
    //    所以"单字节十进制"（214/142）和"无符号十进制"（2746333894）都**永远匹配不上**；
    //  ②IDA get_bytes 兜底 / SO 数据段是**空格分隔 hex**（`d6 90 e9`），而 hex 直读是连续 hex（`d690e9`）
    //    → 两种 hex 形态都要覆盖（上一版删了空格形态，造成对 hex-dump 的回归）。
    // 结论：常量特征必须用「hex 双形态 + 4 字节小端 int32（含负数）」三种写法。
    const FEATURES = [
      // SM4：S 盒首 4 字节 / FK 系统参数（0xA3B1BAC6 小端 c6bab1a3 = -1548633402）
      [/d6[\s,]{0,2}90[\s,]{0,2}e9|d690e9|8e[\s,]{0,2}2f[\s,]{0,2}03|a3b1bac6|56aa3350|677d9197|b27022dc|-1548633402|-1422884016|1751077783|-1297079588/,
       'sm4 国密 非平衡feistel 轮函数 s盒 32轮'],
      // SM3 IV 7380166F 小端 6f168073 = 1863254131
      [/7380166f|4914b2b9|1863254131|1226093241|1937774191/, 'sm3 国密 哈希 长度扩展'],
      // AES S 盒 637C777B 小端 7b777c63 = 2071956579
      [/63[\s,]{0,2}7c[\s,]{0,2}77|637c777b|2071956579/, 'aes s盒 密钥扩展'],
      [/9e3779b9|2654435769|61c88647|-1640531527|1640531527/, 'tea xtea xxtea delta'],
      [/428a2f98|6a09e667|1116352408|1779033703/, 'sha256'],
      [/67452301|efcdab89|1732584193|-272785855/, 'md5'],
      // 结构特征（魔改题靠这些也适用）
      [/virtualalloc|sizeofimage/i, 'pe加载器 内嵌pe 手工映射'],
      [/opcode|\bdispatch\b|取指|解释器|轮函数/i, 'vm 虚拟机 opcode 分组密码 魔改算法识别'],
      // 大常量表 = S 盒候选（64 个 int32 ≈ 256 字节 S 盒；也接受 256 项的大表）
      [/共 (64|128|256) 个/, 's盒 分组密码 sm4 aes 查表'],
      [/分组密码|16 字节块|每 16 字节|轮密钥|round.?key/i, '分组密码 魔改sm4 轮密钥 sm4 aes'],
      // ── 动态调试信号（命中即把「先静态取数、锁定函数再定向调试」的方法论拉进提示词）──
      // 这些特征意味着"静态读不动 / 必须拿运行时值"，正是该动态调试的题。
      // 之前特征表完全没有这一类，导致新方法论页自动预取 0 命中（实测 5/5 落榜）。
      [/virtualprotect|mprotect|page_execute_readwrite|self-?modif|自修改|自解码|解密后执行|smc\b/i,
       '动态调试 静态先行 断点 smc 自修改代码 窗口期'],
      [/isdebuggerpresent|checkremotedebuggerpresent|ntqueryinformationprocess|ptrace|tracerpid|反调试|antidebug/i,
       '动态调试 静态先行 断点 反调试 窗口期'],
      [/dialogboxparam|winmain|wndproc|wm_command|消息循环|getdlgitemtext|对话框/i,
       '动态调试 静态先行 断点 gui 窗口期 32位 改内存'],
      [/gettickcount|getsystemtime|queryperformancecounter|time\(null\)|rand\(\)/i,
       '动态调试 静态先行 断点 窗口期'],
      // ── 花指令信号（命中即把"去花指令"方法论与 junk_scan/junk_patch 拉进提示词）──
      // 关注"反编译失败/代码段异常"这一类症状，而不是某个具体助记符。
      [/sp-analysis|无法反编译|反编译失败|伪代码.{0,6}(错乱|异常|乱)|函数边界|花指令|junk|指令错位|解码错位/i,
       '花指令 junk code 反编译失败 指令错位 栈平衡 互补跳转 不透明谓词'],
    ];
    // 特征反查词放最前（最高优先），其次算法/工具字面量命中，最后文件类型词
    const feats = [];
    for (const [re, terms] of FEATURES) { if (re.test(hay)) feats.push(terms); }
    // 兜底：haystack 里有大块 int32 常量表（数据段高度疑似 crypto 表），且没有其他特征 → 提示分组密码方向
    if (!feats.length && /int32\[\] = \[/.test(hay) && /共 \d{2,} 个/.test(hay)) {
      feats.push('s盒 分组密码 sm4 aes 查表 魔改');
    }
    const ft = String(fileType || '').toUpperCase();
    if (/APK/.test(ft)) hits.unshift('apk');
    else if (/DEX/.test(ft)) hits.unshift('apk', 'dex');
    else if (/JAR|JAVA|CLASS/.test(ft)) hits.unshift('java', 'jadx');
    else if (/PE|ELF|EXE|BIN/.test(ft)) hits.push('native');
    else if (/PYC/.test(ft)) hits.push('python');
    else if (/MACHO/.test(ft)) hits.push('macho');
    else if (/LUAC|LUA/.test(ft)) hits.push('lua');
    else if (/JS|HTML/.test(ft)) hits.push('js 逆向', 'sign');
    // 词级去重：多条特征命中会产出 N 个高度重叠的词串（实测一轮命中 4 条
    // "动态调试 静态先行 断点 …"），整串去重挡不住 → 检索词膨胀、同一方法论页
    // 重复占满结果（该轮提示词被灌到 111KB）。按单词去重后取前 12 个词；
    // 组装顺序 extra → 类型词 → 特征词：短而准的类型词（native/java…）不会被
    // 长特征词串挤出去重窗口。
    const rawTerms = [...extra, ...hits, ...feats].map(s => String(s).trim()).filter(Boolean);
    const seenW = new Set();
    const words = [];
    for (const t of rawTerms) {
      for (const w of t.split(/\s+/)) {
        const k = w.trim();
        if (k && !seenW.has(k)) { seenW.add(k); words.push(k); }
      }
    }
    const terms = words.slice(0, 12);
    if (!terms.length) terms.push(ft || 'reverse');
    const r = await api.wikiSearch(terms.join(' '), 4);
    if (!r || !r.success || !r.result || /未找到与/.test(r.result)) return '';
    addLog('info', `[知识库] 已按本题特征自动检索：${terms.join(' ')}`);
    return `\n\n## 相关知识库攻略（工具已按本题特征自动检索命中，**直接参考，勿重复摸索已记录的路**）\n${r.result}`;
  } catch (e) {
    return '';
  }
}

// 「保存」指令：把暂存的解题经验写入 experience.md（手动入库路径，与自动入库共用写入器）
async function flushPendingExperience() {
  try {
    if (!Array.isArray(state.pendingExperience)) state.pendingExperience = [];
    if (!state.pendingExperience.length) {
      addSystemMessage('**当前没有待保存的经验**\n\n（解题成功的经验已**自动入库**；仅未确认成功时提炼的经验需要发送「保存」写入。）');
      return;
    }
    if (!state.appPaths) return;
    const n = await writeExperienceEntries(state.pendingExperience.slice());
    state.pendingExperience = [];
    if (n) {
      addLog('success', `✅ 已按指令保存 ${n} 条经验进知识库，下次解题自动速查（避坑复用）`);
      addSystemMessage(`**✅ 经验已入库（${n} 条）**\n\n暂存经验已写入 experience.md，下次解题自动注入速查。`);
    }
  } catch (e) {
    addLog('error', '经验保存失败: ' + e.message);
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
    if (isDecoyFlag(v) || isDecoyFlag(inner)) return true; // 诱饵（fake/decoy/假flag）不是 flag
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

// ========== 函数体截断与预算 ==========
// 为什么必须显式传 maxChars：规则若按"函数特征"隐式放宽（例如轮函数给 60000），
// 14552 字符的函数根本不会截断，而"必须含省略标记"的验收就永远失败；
// 反过来 6 个函数各放宽 60000 又没有总预算，会直接撑爆上下文。
const MAX_SINGLE_FUNC_CHARS = 60000;
const MAX_TOTAL_FUNC_CHARS = 120000;

function buildFuncBody(name, code, maxChars) {
  const s = String(code == null ? '' : code);
  const n = Number(maxChars);
  if (!Number.isFinite(n) || n <= 0 || s.length <= n) return s;
  // head 60% / tail 40%；标记本身另算，调用方预算按返回值长度累减
  const headLen = Math.floor(n * 0.6);
  const tailLen = Math.max(0, n - headLen);
  const a = headLen;
  const b = s.length - tailLen;
  const omitted = Math.max(0, b - a);
  const marker = `\n… 省略 ${omitted} 字符（原偏移 ${a}..${b}），需要全文请调 ida_decompile(function_name="${name}") …\n`;
  addLog('info', `[采集] ${name} 截断 head/tail（省略 ${omitted} @${a}..${b}，maxChars=${n}）`);
  return s.slice(0, headLen) + marker + (tailLen ? s.slice(b) : '');
}

// ========== 按地址读全局表（不依赖 list_globals 的名字交集） ==========
// 旧实现只把 raw.refs 与 list_globals 的名字求交集（cnbragon 只命中 1 个 thunk）。
// 关键表是 dword 数组（lane 布局），名字未必是 global —— 必须能从反编译文本里
// 抽地址/符号，再按地址读。
function parseAddrValue(v) {
  if (typeof v === 'number') return v;
  const s = String(v == null ? '' : v).trim();
  if (!/^(0x)?[0-9a-fA-F]+$/.test(s)) return NaN;
  return parseInt(s.replace(/^0x/i, ''), 16);
}

function collectGlobalRegions(decompileTexts, imageMap, opts) {
  const o = opts || {};
  const texts = Array.isArray(decompileTexts) ? decompileTexts : [decompileTexts];
  const resolver = typeof o.resolver === 'function' ? o.resolver : (typeof opts === 'function' ? opts : null);
  // 渲染层没有 Buffer：用鸭子类型判断"可按字节索引的缓冲"（Uint8Array/Buffer 均通过）。
  // probeStride 只用 buf.length 与 buf[i]，两种类型都兼容。
  const buf = o.buf && typeof o.buf === 'object' && typeof o.buf.length === 'number'
    && typeof o.buf[0] === 'number' ? o.buf : null;

  const hits = new Map();   // addr -> Set(referrer)
  const add = (addr, who) => {
    if (!Number.isFinite(addr) || addr <= 0) return;
    if (!hits.has(addr)) hits.set(addr, new Set());
    if (who) hits.get(addr).add(String(who));
  };

  for (const t of texts) {
    const text = String(t == null ? '' : t);
    // 0x... 绝对地址（过滤明显不是数据地址的：小于 0x1000 的常量）
    for (const m of text.matchAll(/\b0x([0-9a-fA-F]{4,})\b/g)) {
      const v = parseInt(m[1], 16);
      if (v >= 0x1000) add(v, '');
    }
    // off_/byte_/dword_/qword_/unk_ 符号名 → resolver
    for (const m of text.matchAll(/\b((?:off|byte|word|dword|qword|unk|flt|dbl|stru|algn)_[0-9A-Fa-f]{4,})\b/g)) {
      if (!resolver) continue;
      const v = parseAddrValue(resolver(m[1]));
      add(v, m[1]);
    }
  }

  // 只保留落在非可执行节（PE !X、ELF !(PF_X)）的地址
  const keep = [];
  for (const [addr, refs] of hits) {
    if (!imageMap || !Array.isArray(imageMap.sections)) continue;
    const abs = (s) => (imageMap.vaIsAbsolute ? s.va : (imageMap.imageBase || 0) + s.va);
    for (const s of imageMap.sections) {
      const start = abs(s);
      const size = s.vsize || s.rawSize || 0;
      if (!(size > 0) || addr < start || addr >= start + size) continue;
      const executable = s.executable === true;
      if (executable) break;
      keep.push({ addr, refs });
      break;
    }
  }

  keep.sort((x, y) => x.addr - y.addr);
  const regions = [];
  for (const k of keep) {
    const last = regions[regions.length - 1];
    // "相邻"：间隔 <= 8 字节视为同一张表（lane 布局的 dword 数组是 4 字节步长）
    if (last && k.addr - (last.addr + last.size) <= 8) {
      last.size = Math.min(65536, k.addr + 16 - last.addr);
      k.refs.forEach(r => last.referrers.add(r));
      continue;
    }
    regions.push({ addr: k.addr, size: 16, referrers: new Set(k.refs) });
  }

  return regions.map(r => ({
    addr: '0x' + r.addr.toString(16),
    size: Math.min(r.size, 65536),
    stride: buf ? probeStride(buf, r.addr, r.size) : 0,
    referrers: [...r.referrers].filter(Boolean).slice(0, 8),
  }));
}

// hex 字符串 → Uint8Array（渲染层无 Buffer 时的安全替代；奇数长度截尾）
function hexToUint8Array(hex) {
  const clean = String(hex == null ? '' : hex).replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
  const n = clean.length >> 1;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// 表项步长探测：1/2/4 三档，统计"跨步重复率高且高位恒零"的那一档。
function probeStride(buf, addr, size) {
  const n = Math.min(size, 256);
  if (!buf || addr + n > buf.length || n < 8) return 0;
  let best = 1, bestScore = -1;
  for (const stride of [1, 2, 4]) {
    if (n < stride * 4) continue;
    const seen = new Set();
    let highZero = 0, total = 0;
    for (let off = 0; off + stride <= n; off += stride) {
      const v = buf[addr + off];
      seen.add(v);
      for (let k = 1; k < stride; k++) { total++; if (buf[addr + off + k] === 0) highZero++; }
    }
    // 跨步重复越少、高位零越多 → 越像该步长的表
    const score = (seen.size / Math.max(1, n / stride)) * 0.5 + (total ? highZero / total : 0) * 0.5;
    if (score > bestScore) { bestScore = score; best = stride; }
  }
  return best;
}

// ========== 可执行节缺口（函数表没覆盖到的代码） ==========
// 只在**代码节**内计算：PE 取 .text 且 X 且 !W；ELF 取 PF_X 且 !PF_W。
// 显式排除 W+X 节（如加壳程序的 .WProtec：va=0x42f000、约 117KB、无任何函数，
// 按"所有可执行节"会产生大量伪缺口）与 .rsrc/.reloc。
const EXEC_GAP_MAX = 4096;
const EXEC_GAP_TOTAL = 32;

function computeExecGaps(functions, imageMap, opts) {
  const o = opts || {};
  const maxGap = Number(o.maxGap) > 0 ? Number(o.maxGap) : EXEC_GAP_MAX;
  const maxTotal = Number(o.maxTotal) > 0 ? Number(o.maxTotal) : EXEC_GAP_TOTAL;
  const out = { gaps: [], continuation: [], log: '' };
  if (!imageMap || !Array.isArray(imageMap.sections) || !imageMap.sections.length) {
    out.log = '[缺口] 无节表信息，跳过缺口计算';
    return out;
  }

  const isCode = (s) => {
    if (imageMap.format === 'pe') {
      if (s.executable !== true || s.writable === true) return false;
      if (/^\.(rsrc|reloc)$/i.test(String(s.name || ''))) return false;
      return /^\.text$/i.test(String(s.name || ''));
    }
    return s.executable === true && s.writable !== true;
  };

  const abs = (s) => (imageMap.vaIsAbsolute ? s.va : (imageMap.imageBase || 0) + s.va);
  const covers = [];
  for (const s of imageMap.sections) {
    if (!isCode(s)) continue;
    const start = abs(s);
    const size = s.vsize || s.rawSize || 0;
    if (size > 0) covers.push({ start, end: start + size, name: s.name });
  }
  if (!covers.length) {
    out.log = '[缺口] 未找到代码节（PE .text X!W / ELF PF_X!PF_W）';
    return out;
  }

  const fnRanges = [];
  for (const f of (functions || [])) {
    const a = parseAddrValue(f && (f.address != null ? f.address : (f.addr != null ? f.addr : f.start)));
    if (!Number.isFinite(a) || a <= 0) continue;
    const sz = parseAddrValue(f && (f.size != null ? f.size : (f.length != null ? f.length : 0))) || 0;
    fnRanges.push({ start: a, end: a + Math.max(sz, 1) });
  }
  fnRanges.sort((x, y) => x.start - y.start);

  for (const c of covers) {
    let cursor = c.start;
    const inSec = fnRanges.filter(r => r.end > c.start && r.start < c.end);
    for (const r of inSec) {
      if (r.start > cursor) pushGap(out, cursor, Math.min(r.start, c.end), maxGap, maxTotal);
      if (r.end > cursor) cursor = r.end;
      if (out.gaps.length >= maxTotal) break;
    }
    if (cursor < c.end) pushGap(out, cursor, c.end, maxGap, maxTotal);
    if (out.gaps.length >= maxTotal) break;
  }

  // 续块：反编译体以无条件 jmp <函数外> 结尾 → 该目标不在任何函数内，必须单独反汇编
  for (const f of (functions || [])) {
    const code = String((f && (f.code || f.body)) || '');
    if (!code) continue;
    // 末尾的 `}` 是函数收尾，不算"最后一条指令"
    const lines = code.trim().split(/\r?\n/).map(s => s.trim()).filter(s => s && s !== '}' && s !== '};');
    const lastLine = lines.length ? lines[lines.length - 1] : '';
    const m = lastLine.match(/^jmp\s+(?:near\s+)?(?:loc_|sub_)?(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b/);
    if (!m) continue;
    const target = parseAddrValue(/^0x/i.test(m[1]) ? m[1] : '0x' + m[1]);
    if (!Number.isFinite(target)) continue;
    const selfStart = parseAddrValue(f.address != null ? f.address : f.addr);
    const selfSize = parseAddrValue(f.size != null ? f.size : f.length) || 0;
    const insideSelf = Number.isFinite(selfStart) && target >= selfStart && target < selfStart + selfSize;
    const insideAny = fnRanges.some(r => target >= r.start && target < r.end);
    if (insideSelf || insideAny) continue;
    out.continuation.push({
      addr: '0x' + target.toString(16),
      from: String(f.name || (f && (f.address || f.addr)) || ''),
      reason: 'continuation-missing',
    });
    if (out.continuation.length >= 16) break;
  }

  out.log = `[缺口] 代码节 ${covers.length} 个，函数 ${fnRanges.length} 个，缺口 ${out.gaps.length} 段`
    + `（单段上限 ${maxGap}B，总数上限 ${maxTotal}），续块 ${out.continuation.length} 个`;
  return out;
}

function pushGap(out, start, end, maxGap, maxTotal) {
  let s = start;
  while (s < end && out.gaps.length < maxTotal) {
    const len = Math.min(maxGap, end - s);
    out.gaps.push({
      addr: '0x' + s.toString(16),
      size: len,
      truncated: len < (end - s),
    });
    s += len;
  }
}

// 反编译入口函数。入口名随工具链而异（mingw→_main、MSVC→main/_WinMainCRTStartup），
// 逐个候选尝试，命中「有代码」即返回；全失败时退回函数表里形如 main 的符号。
async function decompileEntryFunction(functionList) {
  // ⚠️ 顺序很重要：`start`/`_start` 是 CRT 启动桩（只调 __libc_start_main 后转 main），
  // 反编译它得到的是 508 字符的汇编壳，题目逻辑完全看不到。
  // 实测（not-baby-parallelism）：只反编译到 start → AI 拿不到任何题目函数。
  // 因此把真正的用户入口（main/_main/wmain…）排在前面，CRT 桩放最后兜底。
  const candidates = ['main', '_main', '__main', 'wmain', '_wmain', 'WinMain', '_WinMain@16'];
  if (Array.isArray(functionList)) {
    // 从函数表里找所有"像用户入口"的名字（含 main 但排除 CRT/运行时）
    for (const f of functionList) {
      const n = String((f && f.name) || '');
      if (!n) continue;
      if (/^_*(win)?main(@\d+)?$/i.test(n) && !candidates.includes(n)) candidates.push(n);
    }
  }
  // 最后才考虑 CRT 启动桩
  candidates.push('_WinMainCRTStartup', '__tmainCRTStartup', '_mainCRTStartup', 'start', '_start');

  for (const name of candidates) {
    try {
      const r = await window.electronAPI.idaMcpCall('decompile', { address: name });
      if (r && r.success) {
        const code = idaPickCode(r.result);
        // CRT 桩内容极短且只剩 __libc_start_main 调用时，继续找下一个候选
        if (code) {
          const looksLikeCrtStub = /__libc_start_main|__scrt_common_main/i.test(code) && code.length < 900;
          if (looksLikeCrtStub) continue;
          return { name, code, raw: r.result };
        }
      }
    } catch (e) {
      // 换下一个候选名
    }
  }
  // 所有候选都失败 → 退回"体积最大的非库函数"作为主体
  if (Array.isArray(functionList) && functionList.length) {
    const sizeOf = f => {
      const raw = (f && (f.size ?? f.length));
      if (raw == null || raw === '') return -1;
      const s = String(raw).trim();
      const v = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10);
      return Number.isFinite(v) ? v : -1;
    };
    const noise = /^(printf|scanf|malloc|free|memcpy|memset|strlen|strcmp|__|_IO_|printf|puts|exit|abort|rand|srand|getopt)/i;
    const best = functionList
      .filter(f => {
        const n = String((f && f.name) || '');
        return n && !noise.test(n) && sizeOf(f) > 0;
      })
      .sort((a, b) => sizeOf(b) - sizeOf(a))[0];
    if (best) {
      const n = String(best.name || best);
      try {
        const r = await window.electronAPI.idaMcpCall('decompile', { address: n });
        if (r && r.success) {
          const code = idaPickCode(r.result);
          if (code) return { name: n + '（体积最大的非库函数，入口未识别）', code, raw: r.result };
        }
      } catch (e) { }
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
  // IDA MCP 的 size 是 hex 字符串（"0x21b"）；parseInt(v,10) 会得 0 → 全体误判为 thunk。
  const sizeOf = f => {
    const raw = (f && (f.size ?? f.length));
    if (raw == null || raw === '') return -1;
    const s = String(raw).trim();
    const v = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10);
    return Number.isFinite(v) ? v : -1;
  };
  // 工具链/CRT 噪声：命名看着像加解密（__decode_pointer / ____w64_mingwthr_add_key_dtor
  // 含 decode、key），其实是运行时支撑代码，必须压权重，否则会把真正的题目函数挤出名额。
  const runtimeNoise = /mingw|_w64|w64|mingwthr|tls|tmain|crtstartup|_pre_c|exception|_lock|_unlock|atexit|_onexit|cxa|__gcc|security_cookie|findpesection|section_writable|invalidparameter|__dyn|__runtime|__main(_|$)|_p\.\d|pointer|_dtor|_ctor|__gnu|__mingw/i;
  // 跳转桩（ILT thunk）：加壳/混淆 PE 的函数列表里 90%+ 是 5 字节 j_xxx 桩，
  // 真主体是 sub_xxxx 这种"有实际体积"的函数。实测（Disguise stage2）：固定清单全被
  // thunk 占满 → AI 拿不到 sub_415D00/sub_411401 主体 → 报"只有 thunk 无实际逻辑、无解"。
  const isThunk = (n, sz) => (/^j_/i.test(n) || /^nullsub/i.test(n)) || (sz >= 0 && sz <= 12);
  const score = (n, sz) => {
    let s = 0;
    if (/encrypt|decrypt|encode|decode|crypt|cipher|flag|key|check|verify|hash|digest|md5|sha\d?|base64|rc4|tea|aes|sm4/i.test(n)) s += 4;
    if (/vm_|operad|operand|opcode|bytecode|dispatch|handler|interp|exec|eval|table|scramble|obfuscat|translat|transform/i.test(n)) s += 3;
    if (/^_*(win)?main(_?crtstartup)?(@\d+)?$/i.test(n) || /^_?start$/i.test(n)) s += 2;
    // 对话框/窗口过程是**校验逻辑最常见的落点**（按钮点击 → 校验）。
    // 实测：30 个 sub_*(0x150) + DialogFunc(0xa9) 时，+3 仍全被 sub_* 挤出 top10；
    // 必须 +5 才能让 DialogFunc 进入（sub_*=4 分，DialogFunc=5 分）。
    if (/(DialogFunc|DlgProc|DialogProc|WndProc|WinProc|WindowProc|MainWndProc)$/i.test(n)) s += 5;
    if (runtimeNoise.test(n)) s -= 5;
    // thunk/极小函数：重罚（几乎不会被选中），让真正的主体函数浮上来
    if (isThunk(n, sz)) s -= 100;
    // sub_xxxx 这类无语义命名但"有体积"的函数：给基础分（它们才是题目逻辑所在）
    else if (/^sub_[0-9a-f]+$/i.test(n)) {
      s += 2;
      if (sz >= 200) s += 2;        // 体积大的更可能是核心
      else if (sz >= 60) s += 1;
    }
    return s;
  };
  return funcs
    .slice()
    .filter(f => nameOf(f) && nameOf(f) !== '[object Object]')
    .map(f => ({ f, s: score(nameOf(f), sizeOf(f)) }))
    .sort((a, b) => b.s - a.s)
    .slice(0, max)
    .map(x => x.f);
}

// 强制通道：入口函数与对话框过程相邻的 1 跳 callee 必须进采集集，不占 selectKeyFunctions 的 6 个名额。
// 为什么额外调 callees：`_collect_decompile_refs` 只收 cot_obj（数据/对象）引用，不含函数调用，
// 所以从 decompile 的 refs 里拿不到 callee；必须显式调插件的 callees 工具。
async function collectForcedFuncs(funcList, callMcp, limit = 12) {
  if (!Array.isArray(funcList) || !funcList.length) return [];
  const max = limit || 12;
  const nameOf = f => String((f && f.name) || f || '');
  const entryRe = /^_*(win)?main(@\d+)?$/i;
  const dlgRe = /(DialogFunc|DlgProc|DialogProc|WndProc|WinProc|WindowProc|MainWndProc)$/i;
  const byName = new Map();
  for (const f of funcList) {
    const n = nameOf(f);
    if (n && n !== '[object Object]') byName.set(n, f);
  }

  const seeds = [...byName.keys()].filter(n => entryRe.test(n) || dlgRe.test(n)).slice(0, 8);
  if (!seeds.length) return [];

  // 名字 -> 地址：callees 需要地址；没有地址时退回名字（插件 addrs 也接受符号名）
  const addrOf = (n) => {
    const f = byName.get(n);
    const a = f && (f.address != null ? f.address : (f.addr != null ? f.addr : f.start));
    return a == null || a === '' ? n : String(a);
  };

  const forced = [];
  const seen = new Set();
  const push = (n) => {
    const s = String(n == null ? '' : n).trim();
    if (!s || s === '[object Object]' || seen.has(s)) return;
    seen.add(s);
    forced.push(s);
  };

  for (const seed of seeds) {
    push(seed);
    if (typeof callMcp !== 'function') continue;
    try {
      const r = await callMcp('callees', { addrs: [addrOf(seed)] });
      const data = r && r.success !== undefined ? r.result : r;
      const arr = Array.isArray(data) ? data : [];
      for (const item of arr) {
        const callees = Array.isArray(item && item.callees) ? item.callees
          : (Array.isArray(item && item.calls) ? item.calls : []);
        for (const c of callees) {
          if (typeof c === 'string') { push(c); continue; }
          if (c && typeof c === 'object') {
            push(c.name || c.func || c.addr || c.address);
            // 有名有址时把地址也补进来（按名反编译可能失败）
            if (c.name && (c.addr || c.address)) push(String(c.addr || c.address));
          }
        }
      }
    } catch (e) { /* 单个入口取 callee 失败不影响其余 */ }
    if (forced.length >= max) break;
  }
  return forced.slice(0, max);
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

// 会话恢复（D1）：读取最近一次会话日志，把清洗后的历史接回对话。
// 主进程已剥离未完成的 tool_use / 孤立 tool_result（不清洗直接回放会被 API 400），
// 并在末尾注入"从上次中断处继续"。这里只负责接回内存状态并给用户可见反馈。
async function resumeLastSession() {
  try {
    const api = window.electronAPI;
    if (!api || !api.sessionsList) { addLog('warning', '当前版本不支持会话恢复'); return; }
    const list = await api.sessionsList();
    if (!list || !list.success) { addLog('error', '读取会话列表失败: ' + ((list && list.error) || '未知')); return; }
    const sessions = (list.sessions || []).filter(s => s.size > 0);
    if (!sessions.length) { addSystemMessage('**没有可恢复的会话**\n\n当前还没有已保存的 AI 对话记录。'); return; }
    const latest = sessions[0];
    const loaded = await api.sessionLoad(latest.id);
    if (!loaded || !loaded.success) { addLog('error', '读取会话失败: ' + ((loaded && loaded.error) || '未知')); return; }
    const messages = loaded.messages || [];
    if (!messages.length) { addSystemMessage('**该会话没有可恢复的内容**'); return; }

    // 接回内存历史（主进程下次调用会带上它继续）
    state.chatHistory = messages.slice();
    addSystemMessage(
      '**已恢复会话** ' + latest.id + '\n\n'
      + '- 原始记录 ' + loaded.rawCount + ' 条，清洗后 ' + loaded.cleanedCount + ' 条'
      + '（已移除未完成的工具调用，避免接口报错）\n'
      + '- 直接发送任意消息即可从中断处继续。'
    );
    addLog('success', '已恢复会话 ' + latest.id);
  } catch (e) {
    addLog('error', '恢复会话异常: ' + e.message);
  }
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

// 日志化 IDA 调试能力（判定在主进程 electron/ida-debug-capability.js，渲染层只消费结论）。
// 旧实现用关键词数组过滤 tools/list，'ea'/'ip'/'start' 几乎命中所有静态工具，
// 打出"检测到 44 个调试相关工具"的错误结论。
// 两个连接路径（connectIdaMcpWithWait / connectIdaMcp）都必须走这一个函数。
function logIdaDebugCapability(cap) {
  try {
    if (!cap) {
      addLog('info', '[IDA调试能力] 未取得工具列表，无法判断是否支持动态调试');
      return;
    }
    addLog(cap.enabled ? 'success' : 'info', cap.log || '[IDA调试能力] 结论缺失');
    if (cap.enabled) {
      addLog('info', '[IDA调试能力] 扩展已启用但调试器未启动（仅工具可见）');
    }
  } catch (e) {
    addLog('info', '[IDA调试能力] 检测异常: ' + e.message);
  }
}

function detectIdaDebugCapability(toolsResult) {
  // 兼容两种入参：主进程返回体 {tools, debugCapability} 或裸能力对象
  const cap = toolsResult && toolsResult.debugCapability ? toolsResult.debugCapability : toolsResult;
  logIdaDebugCapability(cap);
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
          detectIdaDebugCapability(toolsResult);
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
        detectIdaDebugCapability(toolsResult);
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

// 测试 CTF² 平台连接：先保存设置（拿到地址/Token），再 whoami 探活 + 列工具
async function testCtf2Connection() {
  const btn = document.getElementById('btn-test-ctf2');
  if (btn) btn.disabled = true;
  addLog('info', '正在测试 CTF² 平台连接...');
  try {
    await saveSettings({ keepOpen: true });
    const probe = await window.electronAPI.ctf2Probe();
    if (probe && probe.success) {
      addLog('success', '✅ CTF² 平台连接成功');
      let toolNames = [];
      try { const t = await window.electronAPI.ctf2Tools(); if (t && t.success) toolNames = (t.tools || []).map(x => x.name); } catch (e) {}
      addSystemMessage(`**CTF² 平台连接成功**\n\n账号信息：\n\`\`\`\n${JSON.stringify(probe.me, null, 2).slice(0, 800)}\n\`\`\`\n\n可用工具（${toolNames.length}）：${toolNames.join(', ') || '（未取到）'}`);
    } else {
      addLog('error', 'CTF² 平台连接失败: ' + ((probe && probe.error) || '未知'));
      addSystemMessage(`**CTF² 平台连接失败**\n\n${(probe && probe.error) || '未知'}\n\n请确认：① 设置页填了 Token（平台「凭证」页创建）；② 地址为 https://ctf2.dasctf.com/api/ai/v1/mcp。`);
    }
  } catch (err) {
    addLog('error', 'CTF² 平台连接测试异常: ' + err.message);
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

  // CTF² 平台
  const ctf2Url = val('setting-ctf2-url');
  const ctf2Token = val('setting-ctf2-token');
  if (ctf2Url !== null) newConfig.mcp.ctf2 = ctf2Url;
  if (ctf2Token !== null) newConfig.mcp.ctf2Token = ctf2Token;
  newConfig.platform = newConfig.platform || {};
  const ctf2Dir = val('setting-ctf2-dir');
  if (ctf2Dir !== null) newConfig.platform.downloadDir = ctf2Dir;

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
