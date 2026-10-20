# CTF-RE-TOOL 历史更新日志（归档）

> v1.3.4 及更早版本的更新记录。最新变更见 [README 更新日志](README.md#更新日志)。

---

### v1.3.4 (2026-10-09) — 知识库扩充 + 固件逆向 + 开源发布
- **知识库技能 8→11**：新增 `ctf-reverse-tooling`（Z3/angr/Unicorn 自动化求解 + 迷宫题）、`ctf-reverse-langs`（Python 字节码/Go/Rust/Lua 语言特定逆向）、`ctf-iot-firmware`（固件提取/解包/QEMU 仿真）
- **知识库 Wiki**：`wiki/` 可检索手法页（`wiki_list`/`wiki_search`/`wiki_read`），系统提示只注入页面索引；内置 Frida 专题 + 固件解包/仿真专题
- **Hook 进程内解密直接出 flag**：把已求解的 key/iv/密文注入 Hook 脚本，运行时捕获明文，绕过关卡直接解出；滚动窗口抓取（每来数据续 60s，绝对上限 10min）
- **命令注入收口**：新增参数化执行原语 `run-tool-args`（argv 数组，无 shell 解析）、纯 Node `zip-list`/`grep-in-dir`，渲染层不再拼接 PowerShell/cmd 命令字符串
- **文件 IPC 边界**：`write-file`/`read-file`/`ensure-dir`/`append-file` 加写入根约束（userData/应用目录/临时目录/CASE 目录），并屏蔽读取工具自身凭据配置
- **Electron 加固**：`webPreferences` 启用 `sandbox`，拦截 `will-navigate` 与 `setWindowOpenHandler`（外部链接一律交系统浏览器）
- **界面**：暖白简约主题；键盘焦点环（`:focus-visible`）+ 减少动效支持；移除说明书弹窗
- **打包**：electron-builder 输出便携单文件 `CTF-RE-TOOL.exe`（含应用图标）
- **仓库卫生**：`node_modules`/`HANDOFF.md`/`.zcode` 计划/一次性调试脚本取消入库，重写 `.gitignore`

### v1.3.3 (2026-09-12) — 第四轮复审（自动化流程专项）
- P0：processUserMessage 的 hasWord 在声明前使用（TDZ），英文消息含 "script" 一词即静默崩溃 → 提升至函数顶部
- P1：analyzeWebJS 全程占锁（轮询阶段此前不加锁，可并发双流程造成流错乱）；两个轮询循环可通过再点发送键中止（flowAbortRequested）
- P1：Burp 传输探测双重 initialize（严格 Streamable 服务器会拒绝导致误判回落 SSE）→ 复用 burpHttpEnsureSession
- P2：tools/call 超时不再重试（防非幂等重复执行）；SSE 连接失败路径补 waiter 清理；JS 文件读证失败不再中断流程；AI 空结果单列提示；experience.md 表头判断修正（read-file 返回 {success:false} 而非抛异常）
- 知识库：ctf-dispatch 分流表补 Web/JS/加密参数 → ctf-jsreverse 路由 + 下一步菜单模式 + 经验库优先原则

### v1.3.2 (2026-09-12) — Web/JS 逆向全自动工作流
- **像 IDA/JEB 一样自动拉起工具链**：说"分析这个站的加密参数"即触发——自动探测 Burp（9876）→ 未运行自动启动 MCP_Burp.bat 并轮询就绪（150s）→ 自动连 MCP → 无流量自动拉起**走 Burp 代理的隔离浏览器**（Chrome/Edge 自动探测 + 独立 user-data-dir 保证代理生效 + 忽略证书告警）→ 后台轮询等流量（90s）→ AI 接手按 ctf-jsreverse 五阶段分析
- 新增 IPC：burp-probe（TCP 快探）/ open-proxy-browser（代理浏览器）；新增 web 配置组（浏览器路径/Burp 代理端口，设置页可视化）
- .js/.mjs/.html 拖入即走 Web 流程（JS 原文自动存 evidence）；`burp 启动` 现在启动后自动连接 MCP
- 逻辑单测：路由正则触发/不触发用例、历史空判断（结构化 JSON 检测，10 用例）、浏览器候选探测

### v1.3.1 (2026-09-12) — Burp MCP 实装完成
- 本地 Burp 2025.11.2 全链路实装官方 MCP Server 扩展（burp-suite v1.1.2）：jar 下载 → mcp_user_options.json 免 GUI 自动加载（MCP_Burp.bat 追加 --config-file）→ GUI 勾选 Loaded/Enabled/历史免审批
- 客户端重写为双传输自适应（auto：先 Streamable HTTP 社区扩展，失败转经典 SSE 官方扩展）；SSE 端点路径多候选（/sse 与 /）；notification 不占 pending 超时；URL 变更自动重置传输探测
- 实测：9876 监听 ✓、initialize/tools/list 握手 ✓、27 个工具全部发现（get_proxy_http_history / send_http2_request / get_scanner_issues / Repeater / Collaborator / 编解码）
- 参数适配单测 6 场景全过；tools.burp 默认启动器改为 MCP_Burp.bat

### v1.3.0 (2026-09-12)
Burp MCP 集成 + JS 逆向能力（工作思路参考 reverse-skill 与 hello_js_reverse_skill，择优吸收）：
- Burp MCP 客户端（逻辑名映射：history/message + 任意工具透传），MCP 栅格/工具区/聊天命令三处入口；.bat/.vbs 启动器支持
- 新增 ctf-jsreverse 技能：五阶段流程、路径A算法追踪四板斧、路径B环境伪装、JSVMP/瑞数/obfuscator 判型、案例坑库
- 验证闭环支持 node_js 契约：AI 还原的 JS 函数本地 node 复现（修复 argv 取参 bug 并端到端实测）
- 全局经验库：解题成功**自动入库**（内容级去重）/ `经验 <内容>` 手动回写 / `查经验` 查看 / 自动注入 AI 系统提示（近15条）
- 参考来源：[reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT）

### v1.2.2 (2026-09-12)
第三轮复审（CSS/UI 层 + 知识库技术细节）：
- P1：Frida 输出面板换行丢失+长 hex 行被裁剪（补 pre-wrap/break-all）；日志长 token 同样裁剪；聊天气泡长 base64/哈希撑破面板 + 行内 code 无样式
- P2：流式光标闪烁动画；"分析结果"tab 标题/段落/flag 候选排版（此前被全局 margin 归零挤压）；说明书 help-note 提示框样式；移除分析 tab 双层嵌套 padding；MainActivity 识别支持 activity-alias；自动求解中止提示优化；findings.json 串行化写队列防并发交错
- 知识库：SM4 描述修正（非平衡 Feistel）；7 个 SKILL.md 机器校验（frontmatter/代码围栏闭合/交叉引用/乱码）全部通过；密码学常量与反调试偏移逐项人工复核

### v1.2.1 (2026-09-12)
系统性架构+知识库复审（独立代理交叉审查）修复：
- P0：PE/ELF"详细分析"传入空对象导致 `otherFunctions.length` TypeError，Tool-Use 深度分析必挂
- P1：CSP 使内联 onclick 失效（清空日志按钮同时会折叠面板）；解密模板中 xxtea 实现错误（TEA 风格轮函数，解出乱码）改为正确 MX 算法；`[VERIFY]`/`[HYPOTHESES]` 契约解析遇 custom 代码中的 `}`/`]` 截断（改匹配闭合标签）；Python 求解器契约改 base64 内嵌（三引号守护本就无效）
- P2：验证命中只标命中 flag；AI 中止显示为提示而非错误；聊天路由 pe/tea/md5/crc 等改词边界（"open/steal"不再误触发）；移除 data-collapse 死代码；grep 默认根目录对齐工作目录；browser_search/open 从占位接为真实调用；流式重试不再造成文本重复；PYC 魔数收紧（校验第 2 字节 0x0D）；移除无效 defaultFilter；kali 启动失败如实报错；Frida 17 API 兼容 shim 内置到全部模板；设置页新增"测试AI连接"；安装 APK 前设备就绪轮询
- 知识库：ctf-crypto-identify 契约算法清单与求解器实现对齐；ctf-frida-dynamic 补充 Frida 17+ API 变更说明

### v1.2.0 (2026-09-11)
- Agent Skills 引擎：7 个内置中文方法论 skill（写题解/Android/二进制/算法识别/反调试/Frida/调度），AI 经 `read_skill` 按需加载，用户可自装
- CASE 证据体系：每题独立目录（evidence/scripts/timeline.jsonl/findings.json），MCP 采集物自动落盘
- 验证闭环：`[VERIFY]` 契约 → 自动生成 Python 本地复现 → flag 标注 ✅已验证/⚠️未验证
- 本地枚举：`[HYPOTHESES]` 契约 → 组合枚举一键跑完（TEA/XTEA/XXTEA/RSA字节序/密钥编码歧义等），验证失败自动触发
- WP 双轨：模板轨升级为 findings 驱动（证据清单+验证状态自动填充）；AI 轨（`aiwp`）按 ctf-writeup 技能产出提交级题解，失败自动回退
- 参考 [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)（MIT）与 [anthropics/skills](https://github.com/anthropics/skills) 的 SKILL.md 组织方式

### v1.1.0 (2026-09-11)
**缺陷修复**
- 修复 JEB MCP 一键启动读取错误配置键（`mcp.jeb` → `mcp.jebMcpScript`）的问题
- 修复聊天/日志/Frida 输出的 HTML 注入（XSS）漏洞
- 修复 MainActivity 误识别：现在精确解析 Manifest 中的 LAUNCHER activity
- 修复 APK 自动分析结果虚假成功提示：每步真实汇报 ✅/❌
- 修复 PYC 魔数只认旧版本、`.zip` 一律当 APK、kali-stop-vm 空 vmx 等问题
- 修复设置保存丢失 nox_path/mcp/kali 配置段、WP 保存后脚本类型错乱等问题

**健壮性与体验**
- AI 回复 SSE 流式输出 + 发送按钮一键停止
- JEB/IDA MCP 连接改为就绪轮询；模拟器等待不再固定 60 秒
- 429/5xx 指数退避重试；`max_tokens` 可在设置中调整（默认 8192）
- `saveScript` 实现系统保存对话框；聊天工具栏按钮接线；新增"分析结果"标签页
- 设置页新增 AI 接口 / MCP 地址 / Kali SSH / 输出目录 配置
- 硬编码路径与端口（frida 27042、ADB 62025、scripts 目录、VS Code、JEB MCP 脚本）全部进配置

**解题能力扩展**
- 文件分流新增：JAR/.class（jadx）、.NET（dnSpy/ilspycmd 指引）、Unity IL2CPP（Il2CppDumper 指引）、Lua 字节码（unluac）、Mach-O 指引
- 解密模板新增：SM4、3DES、自定义码表 Base64、RSA（小指数/factordb/Wiener/共模）、Z3、angr
- 新增 Windows PE 反调试绕过 Frida 脚本、smali 重打包签名批处理脚本
- RC4 动态脚本参数化（模块名/RVA 弹窗输入，不再硬编码 2.exe）
- WP 报告增强：多格式 flag 提取（flag/ctf/NSSCTF/SCTF…）、关键结论区块、真实连接状态
- flag 统一提取函数，支持 `[FLAG]...[/FLAG]` 输出契约

**安全加固**
- adb/frida/launch-tool/vmrun 全部改为 spawn 参数数组，消除命令注入面
- Kali SSH 改用 ssh2 库（原 sshpass 方案在 Windows 不可用）；密码不再写死在源码
- `shell.openExternal` 仅允许 http/https；新增 CSP；FontAwesome 加 SRI
- 工具输出统一 8000 字符截断（IPC 与 AI 上下文双重保护）

### v1.0.0 (2026-07-23)
- 初始版本发布
- 支持文件拖入和自动识别
- 集成 IDA、DIE、JEB、jadx、UPX、apktool、pycdc 等工具
- Frida Hook 脚本生成（基于ctf-agent模板）
- Python 解密脚本生成（支持多种算法）
- 反调试绕过脚本生成（支持多种绕过技术）
- 响应式窗口布局

### v1.4.0 (2026-10-14) — 修复 Frida Hook 证据被噪音淹没 / 降噪失效 / 经验跨阶段丢失

审查两次真实运行日志（一次 APK 自动解题、一次 Frida Hook）发现三个真实缺陷，全部修复。

**一、Frida 输出"真证据被噪音挤出 AI 结论窗口"（高危，可能漏 flag）**

Hook 输出回灌 AI 前，旧逻辑把 `[DATA]`/`[FLAG]` 真证据与 `[HIT]` 噪音**混在一个池子**里再 `slice(-120)`。而噪音（可达上百条）通常出现在真证据**之后** → 尾部 120 条几乎全是噪音，**真证据被整段丢弃**。
本次实测复现：131 条关键行里 2 条真证据 + 129 条噪音，`slice(-120)` 后**真证据 0 条保留**。
（这次 flag 没丢，是因为另有一条独立逻辑直接收割 `[FLAG]` 行兜底；但若 flag 只以 `[DATA]`/普通解密输出形式出现，就会彻底漏掉。）

**修复**：改为**分级保留** —— 高价值行（`[DATA]`/`[FLAG]`/flag 形态/加解密实参/SP 读写）**全部保留、不参与截断**；仅对 `[HIT]` 噪音限量（保留末尾 40 条作线索）。实测：真证据 ✅必留。

**二、Frida `String.equals` 降噪形同虚设（129 条 `[HIT]` 全是误报）**

两条根因：
- 关键词正则 `/flag|ctf|key|secret|token|pass|stage/i` **命中了应用包名本身** —— 本题包名 `com.nctf.hookmysecret` 同时含 `ctf` 与 `secret`，导致每条涉及包名的比较都被判"有意义"而刷屏；
- 兜底规则"两串 ≥6 字且长度差 ≤2"太松，把 `include==ViewStub`、`pathInterpolator==linearInterpolator`、`res/*.xml` 等框架/资源串全部放行。

**修复**：改为"**高熵优先 + 噪音形态黑名单**"——① 高熵串（flag 形态/长 hex/base64）**先**保留（`flag==flag` 这种最终校验不能被误杀）；② 双方均为噪音形态（包名/资源/绝对路径/算法名/框架词）排除；③ 语义词命中且非噪音形态才打印。修复前后对比：**129 条噪音 → 0 条**（降噪 100%），5 个正例（flag、hex key、password 对）全部保留。

**三、经验"跨阶段丢失"（前序暂存的经验永远进不了库）**

一次 APK 解题里，阶段2（初步分析）AI 产出的经验被"暂存"，阶段2.5（Tool-Use）解出 flag 后**只入库了它自己那条** —— 阶段2 那条滞留在内存 `pendingExperience`，既不入库、也不持久化（关应用即丢）。且该暂存区从不随换题清空，会跨题残留。

**修复**：① 换题（加载新文件）时清空 `pendingExperience`；② 解题成功时把**本题前序暂存的全部经验**一并入库（含防御性去重）。实测：阶段2 暂存 1 条 + 阶段2.5 成功 1 条 → 库内 2 条、暂存清空、重复幂等。

> 回归：修复项 #1 真证据必留 ✅ ｜ #2 降噪 128/128 且正例 5/5 ✅ ｜ #3 经验接管与幂等 ✅ ｜ 原有回归（经验流 6/6、相似度 5/5、finalizeSolve 契约 2/2、求解路径审计 10/10）无回退 ｜ `node --check` 全过。

### v1.3.14 (2026-10-14) — 当日汇总

> 本条目汇总 **2026-10-14 当天**的全部更新（原按里程碑分为 v1.3.6 ~ v1.3.14 多次提交，现合并为一个版本）。

**解题结构根治**
- **"三件套"收口**：把"验证闭环 + 经验沉淀"从散落 9 处的两步复制粘贴，收口为单一入口 `finalizeSolve(text, {source})` —— 内含「验证闭环 → 失败自动枚举 → 登记 flag → 解题成功则经验自动入库」，从结构上杜绝"修一处漏一处"。
- **5 类"只指路"入口改为真正解题**：`.dex` / `.jar` / `.class` / Mach-O / `.luac` 此前只启动外部工具或打印指引（AI 不参与），现全部接入 AI 求解闭环 —— DEX/JAR 走 **JEB 优先**（不可用降级 jadx）、Mach-O 走 IDA、`.luac` 走字节/常量抽取。分流表 12/12 均路由到真实求解器。
- **修复跨文件 MCP 缓存泄漏**：`analyzeJavaLike` 未清缓存、`state._keyClassesByContent` 从不重置 → 连解多题时上一题数据会串进本题提示词/类选择；现随 `clearMcpCache()` 一并清理。

**经验与知识库"真正帮到解题"**
- **经验自动入库 + 真去重**：解题成功即写入（无需手动「保存」）；去重从"按整行含日期比对（换日必重复）"改为**与日期无关的内容级去重**（精确 + 二元组相似度≥0.78 + 子串判定）。经验注入补全到所有求解路径。
- **修复题库 meta 解析 bug**：`wiki_search` 解析 YAML 的 `m` 标志令 `$` 匹配行尾，导致**列表写法**的 `attack_chain`/`failed_attempts` 被解析为空 —— 43 篇题库仅 13 篇解法链可用。修复后 **13 → 38 篇**，检索摘要升级为 **要点 + 解法链 + 避坑**。
- **主路径自动预取**：新增 `prefetchKnowledge()`，调用 AI 前按题面特征词检索题库并把攻略内联进提示词（已覆盖 APK/PE/ELF、PYC、Web/JS、DEX/JAR、Lua）。

**PYC 逆向从"无解"到可用**
- 多后端自动回退：**pycdc → xdis/pydisasm → 原生 marshal+dis → 纯字节串扫描**（永不空手）；内置零依赖助手 `electron/pyc_decompile.py`。
- 求解器兼容 `xor` **单字节整数密钥**（`xor_key=199`）、`custom` 返回 `str`/`list[int]` 归一化。

**验证闭环与动态 Hook 通用性**
- **修复 IDA 采集 0 反编译（最严重）**：`window.electronApi` 拼写错被空 catch 吞掉，实测反编译 **0 → 19 个**。
- 验证闭环不再"没契约就放弃"：`synthesizeHypotheses()` 自合成候选矩阵（≤24 组）。
- AES/DES-CBC **缺 IV/错 IV** 不再必然失败（枚举全零/首块/前置 IV + 回退 ECB）；口令 key 自动派生（MD5/SHA-256/零填充）。
- 多候选密文**交叉校验 + 自动裁决**（IDA `xrefs_to` 判"哪条被校验函数引用"），防"变种题"陷阱。
- 动态 Hook：修复"抓到输出却报 0 条关键数据"、手动 Hook 自动驱动界面、枚举失败改按 PID attach、`String.equals` 降噪。

**重构引入问题的修复**
- v1.3.9：验证闭环 7 处复制粘贴收敛为 `verifyAndRecord()`（纯重构）。
- v1.3.10：修复该重构遗漏 —— `autoSolveFlag`/`autoSolveBinaryFlag` 只解构 `verifiedFlags` 却引用裸 `flags`，导致 `ReferenceError: flags is not defined`。

### v1.3.5 (2026-10-13) — 结构化知识库 + 解题成功率优化
- **知识库重构为「结构化 + RAG 友好」**：新增全局检索索引 `AI-SEARCH-INDEX.md` 与速查表 `PAYLOAD-CHEATSHEET.md`
- **历年逆向题条目库**：新增 `wiki/reverse/`，**43 篇**纯逆向题（从 132 候选筛选、剔除 PWN/杂项），每题带 `attack_chain`（解法链）/`reasoning_chain`（思维链）/`failed_attempts`（避坑）等 YAML meta
- **修复结构化检索失效**：`wiki_search` 此前只解析 `---` front matter，而条目库把 meta 放在 ` ```yaml ` 围栏里，导致 tags/attack_chain 加权**完全失效**；现兼容两种写法，并新增 `vuln_type`/`contest`/`difficulty` 加权；命中片段优先展示 `one_liner`+`attack_chain` 且保留原文大小写（防止把大小写敏感的 flag 小写化）
- **系统提示瘦身**：不再逐条列出 43 篇逆向条目路径（交给 `wiki_search` 检索），每次请求省约 1.5k tokens
- **Frida 能力增强**：吸收两大开源 Frida Hook 项目精华——RegisterNatives 拦截、JCE 通杀自吐、SSL pinning 绕过（Java+native）、脱壳、反检测；兜底模板注入题目情报做针对性 Hook（不再是固定模板）
- **AI 解题流程优化**：APK/PE/ELF 深度求解改为四阶段流水线提示词；AI 脚本语法错自动重新生成 2 轮
- **环境自愈**：frida client/server 版本一致性自检、双 adb 互杀重连、装 APK 前 package 服务就绪轮询、GUI 窗口可见性修复（IDA/JEB/Nox）
- **Frida 枚举失败自动降级为按 PID 附加**：某些模拟器（如 Nox Android9）上 `frida-ps`/`-f`/`-n`/`-F` 会抛 `queryIntentActivities NullPointerException`（**即使 client=server 版本完全一致**，是枚举路径本身的 quirk）——旧逻辑据此判"Frida 不可用"并跳过整个动态阶段。现改为 `adb pidof/ps` 取 PID → `frida -p <PID>` 附加（实测该路径正常），动态阶段继续
- **隐私与安全**：移除源码/文档中硬编码的私有 AI 中转地址（Base URL 默认留空，未配置时明确报错）；`git-filter-repo` 抹除历史中的私有域名与本机路径；清理构建残留与一次性调试脚本
- **发现并修复**：`wikiSearch` 结构化 meta 解析失效（见上）；`baseUrl` 为空时由 `Invalid URL` 改为明确的中文配置提示


> v1.3.4 及更早版本见 [CHANGELOG-ARCHIVE.md](CHANGELOG-ARCHIVE.md)。
