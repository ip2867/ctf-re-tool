# CTF-RE-TOOL 优化与完善计划（第三轮）

> 依据：[FINAL-REPORT.md](./FINAL-REPORT.md)（本轮题库中段 6 道 + rank 6 复测 2 道）+ [CHALLENGE-LOG.md](./CHALLENGE-LOG.md)（逐题）+ [OPTIMIZATION-PLAN-V3.md](./OPTIMIZATION-PLAN-V3.md)（rank 1–6 工单与验收细节）。
> 原则不变：AI 是解题主体，工具提供确定性证据与可执行操作；所有改动必须是通用机制，不针对任何题名。

## 一、已完成（本轮，不需要再做）

| rank | 机制 | 文件 | 测试 | 实战验证 |
|---|---|---|---|---|
| 1 | 去重闸改为地址目标指纹 | `electron/script-dedup.js` | 24 + 68 | ✅ 6 题中多次出现"无地址指纹 → B 层不判定"的正确退让 |
| 2 | 工具结果可信性（失败必须失败） | `electron/tool-result.js` | 65 + 19 + 64 | ✅ 全量回归绿 |
| 3 | IDA 会话身份 + 映像落界 | `electron/binary-map.js` | 40 + 46 | ✅ 6 题 6 次正确重载，无跨题串台 |
| 4 | 平台题目契约贯穿 | `src/js/app.js` | 35 | ✅ level1 正确识别 `flag{}` 包装指令 |
| 5 | 末公里候选闭环（契约驱动 verified） | `src/js/app.js` | 45 | ✅ xxor 首次把验证失败转成成功 |
| 6 | 指纹扫描（MD5 K / lane 变表 / 中性措辞） | `electron/crypto-detect.js` | 32 + 15 | ✅ CrackMe2 报 `MD5(high)`、cnbragon 报 `自定义分组密码(high)`；两题仍未解出（模型侧） |

全量：`node tests/run_all.js` → 单元测试 **49/49**、回归题集通过、exit 0。

## 一之二、2026-10-20 修复与真实联调（已完成）

在 rank 1–6 之上，针对工作流复核暴露的契约级缺口与工具链可用性做了 6 项修复，并完成 4 条真实联调。

### 修复项

| # | 缺陷 | 修法 | 回归用例 |
|---|---|---|---|
| 1 | Burp `get_proxy_http_history` 的 `count`/`offset` 都是必填，`adaptBurpArgs` 只改名 `max→count`，缺 `offset` → 整条 history 报错 | `adaptBurpArgs` 按 schema 的 `required` 补中性初值（数字 0 / 字符串空 / 数组空 / 布尔 false），只补缺不覆盖 | `test_protocol_contracts.js` [1] |
| 2 | MCP `result.isError` 未透传：`requires extension`、`Field 'offset' is required` 这类失败被当成功文本交给 AI | 新增 `mcpResultIsError`/`mcpErrorText`，接入 IDA 与 Burp 两个客户端 | 同上 [2] |
| 3 | `sshExec` 忽略退出码：命令失败仍返回 `success:true` + 空 stdout | `stream.on('close', (code, signal))` 透传真实退出码；`remote_exec` 消费它 | 同上 [3] |
| 4 | `file-capability.js` 用 4 字节 `head` 全等比较 2 字节的 `'1F8B'`，gzip 头永远判不出 | 改用 `startsWith` | 同上 [4] |
| 5 | `detect-file-type` 产出 `WASM`，但 `autoAnalyze` 的 switch 没有对应 case → 落进未知类型提示 | 新增 `case 'WASM'` 走本地探测 | 同上 [5] |
| 6 | Burp 返回的错误串被 `burpHistoryLooksEmpty` 判成"有流量" → 跳过拉起浏览器 + 把报错喂给 AI | 新增错误前缀识别（`Error:` / `BURP_DOWN` / `requires extension` / `Field '...' is required` 等）+ 结构化 `isError` 识别 | 同上 [6] |
| 7 | IDA 9 异步调试器：`idaapi.step_over()` 投递成功却返回 False，插件报 `Failed to step over`，而 IP 实际已前进 | 新增 `rescueStepFailure`：单步失败后读 IP，确实变化即判成功 | `test_ida_dynamic.js` [4] |
| 8 | 调试能力白名单必须与 `buildDbgCall` 产出严格一致，否则又变成"宣称了 AI 调不到的能力" | 白名单收敛为 15 个已包装工具 | `test_ida_dbg_wiring.js` [7] |

### 真实联调结果（全部 PASS）

| 链路 | 证据 |
|---|---|
| **Burp offset** | 同一活服务上三态对比：`{max:5}` → 服务器拒绝未知键；旧适配 `{count:5}` → `Field 'offset' is required`；新适配 `{count:5,offset:0}` → 返回真实 `GET / HTTP/1.1` 历史 |
| **IDA 动态调试** | 不带 `?ext=dbg` 时 62 个工具、dbg_* = **0**；带上后 82 个工具、dbg_* = **20**。`dbg_start` 返回 `{started:true, ip:"0x77d2a6b0"}`；`dbg_regs` 返回真实寄存器；单步后 IP `0x77d284cc → 0x4012d1`；`dbg_read@0x4012d3` 读出 `6aff68c0504000689c1f400064a10000`；`dbg_add_bp(0x4012d0)` → `dbg_bps` 可见 → `dbg_run_to` 命中；`dbg_exit` 正常 |
| **Kali SSH** | 修正凭据后 `uname -a` 返回 Kali 6.12.38；`binwalk 2.4.3` / `file` / `strings` / `python3` 均可用；失败命令返回退出码 2 并被 `classifyRemoteError` 判为 `REMOTE_REFUSED` |
| **Kali 端到端** | 按能力分诊：ELF→static、gzip→extract、squashfs→extract、裸 .bin→local-probe、pcap→traffic。把样本传到 Kali 后 `file`/`binwalk`/`strings` 全部 code=0 并返回真实输出 |

全量：`node tests/run_all.js` → 单元测试 **71/71**、回归题集通过、exit 0。

**凭据修正**：`config.json` 的 `kali.sshUser/sshPass` 由占位值 `kali/kali` 改为本机实际账号（连接验证通过后写入，密码不回显）。

**上一轮遗留的两项也已验证**：
- P1 契约自动枚举 → 演进为 rank 5 的"契约驱动 verified + 重试循环"，本轮 xxor 实测转成功
- P2 中间值自动推进 → 已落地（`electron/intermediate-advance.js`，17 项单测 + 3 项 E2E）

## 二、本轮新发现的两个通用缺陷（优先级最高）

这两条不是从计划里推出来的，是真实运行暴露的，且都可复现、都是纯形态判据。

### P0-A — 包装去重壳（`[WUSTCTF2020]level1`）

**现象**：平台描述要求 `flag{}`，AI 给的值已经是 `ctf2020{d9-dE6-20c}`，工具套成 `flag{ctf2020{d9-dE6-20c}}` → `accepted:false`。

**根因**：`applyWrap(value, tpl)` 只做字符串填充，不检查值是否已有 `<word>{...}` 外层壳。

**改法**（通用）：
1. 套壳前判断值是否匹配 `^[A-Za-z0-9_!-]{1,24}\{([\s\S]*)\}$`；
2. 若匹配且外层词 **不等于** 目标前缀，且内层非空 → 先剥一层再套；
3. 若外层词等于目标前缀 → 视为已包装，不重复套；
4. 剥壳后仍不合法（内层含嵌套 `{`）→ 保留原值并记日志，交 AI 判断。

**验收**：
- 单测：`ctf2020{x}` + `flag{%s}` → `flag{x}`；`flag{x}` + `flag{%s}` → `flag{x}`；`{x}` + `flag{%s}` → `flag{x}`；`a{b{c}}` → 保持原值并给出日志
- 真实重跑 `[WUSTCTF2020]level1`，平台返回 `accepted:true`

### P0-B — flag 形态合理性校验（`[MRCTF2020]Xor`）

**现象**：AI 给 `CTF{UA^SSQ@VC_L\OB~[q}`，本地脚本确实输出该串 → 契约复现通过 → 标 verified → 提交被拒。

**根因**：rank 5 的契约驱动 verified 只证明"脚本输出 === 契约值"，不证明"这个值语义上是 flag"。前半段控制符说明异或没解完。

**改法**（通用，不依赖题面）：
1. verified 前统计 flag 体字符集：控制字符（<0x20）、`\ ^ ~ | \`` 及非可打印 Unicode 的占比；
2. 占比 > 0 **且** 题面未声明这些符号合法 → 降级为"中间值"，记 `[验证闭环] 形态不合理，降级为中间值`，不进提交候选；
3. 同时把"疑似未完成的编码"证据回灌给 AI（走现有 retryPrompt 通道）。

**边界（必须遵守）**：不能按"常见 flag 字符集"硬编码白名单——很多题允许 `!@#$%`。判据只针对**控制字符与转义类符号**，并且题面声明优先。

**验收**：
- 单测：`CTF{a\b}` → 降级；`flag{re_is_great!}` → 不降级；`flag{0046af1b...}` → 不降级
- 用 `[MRCTF2020]Xor` 重跑，日志出现降级且不再提交该值

## 三、下一轮优先级

### P1 — MD5 目标串自动定位（rank 6 的直接后续）

**数据**：CrackMe2 已能识别 `MD5(high)`（K 64/64），但 607 秒（总耗时；Tool-Use 阶段 579.4/323.2）内 AI 没把"用户名/序列号校验"的目标串找全。

**现状**：工具告诉 AI "这是 MD5"，但没告诉它"和什么比、比多少字节"。

**改法**（通用）：
1. 命中 `MD5-K`/`MD5-IV` 时，在文件里扫描**32 位 hex 字面量**与**16 字节高熵常量**，作为"疑似摘要目标"列出（带偏移与所在节）；
2. 若同时存在用户输入读取点（`scanf`/`fgets`/`GetWindowText`/`read` 等字符串常量）→ 生成"输入 → MD5 → 比较"的候选组合；
3. 把目标串列表写进 scan summary，明确告诉 AI "要爆破的是哪几个值"。

**验收**：CrackMe2 重跑时，scan summary 中出现疑似摘要目标串；AI 的脚本直接对这串爆破（而非自己再找一遍）。

### P2 — 单题预算按形态分层

**数据**：本轮 6 道平均 59s，但 CrackMe2 跑到 607 秒（总耗时；Tool-Use 阶段 579.4/323.2）、cnbragon 349 秒（总耗时；Tool-Use 阶段 579.4/323.2）仍无产出。

**现状**：一刀切的 60 轮 / 12 分钟。简单题浪费预算，难题预算不够。

**改法**（通用）：
1. 工具侧给出"题面复杂度信号"（文件大小、函数数量、是否含 VM 特征、是否有指纹）；
2. 信号 = 简单（有明确指纹 + 文件 < 1MB）→ 8 分钟；中等 → 15 分钟；复杂（无指纹 + 大文件/VM）→ 25 分钟；
3. 预算只做上限，不强制消耗——简单题解出即停。

**验收**：`tea`（有指纹）不被拖到 8 分钟以上；CrackMe2 拿到 25 分钟预算后能跑完爆破。

### P3 — 零指纹时的定向检索建议（rank 6 的措辞延伸）

**数据**：本轮 6 道里 4 道是零指纹，其中 3 道仍解出（usualCrypt/xxor/rc4）。说明零指纹很常见。

**现状**：中性措辞已经做到（不再说"是壳"），但只有"建议在本层找"，没有**具体检索方向**。

**改法**（通用）：按"文件里实际存在什么"给方向，而不是泛泛而谈：
- 有 32 位 hex 字面量 → 优先查哈希比较
- 有 Base64 字符表 → 查自定义 Base64（usualCrypt 就是这类）
- 有循环 + 逐字节比较 → 查编码/异或
- 有大常量数组 + 少指令 → 查 VM/查表

**验收**：rc4（零指纹但有 KSA 循环）重跑时，提示词里出现"循环 + 逐字节置换 → 优先查 RC4/自定义流密码"这类**由数据推导**的方向。

### P4 — 人工干预兜底（BLOCKER.md）

**数据**：本轮 2 道 rank 6 复测题（CrackMe2/cnbragon）消耗 956 秒仍无产出，人工无法快速接手。

**改法**：工具放弃时生成 `cases/<md5>/BLOCKER.md`：
```
## 已完成的步骤（带数据）
## 当前卡点（具体地址/函数/缺什么）
## 下一步建议（具体动作）
```
内容全部来自已有的 scan/IDA/验证记录，不新增探测。

**验收**：CrackMe2 失败后能产出含"MD5 K 表 @0xb2f、目标串候选、已试过的爆破范围"的 BLOCKER.md。

## 四、实施顺序

```
P0-A 包装去重壳        ← 直接吃一道现成的 accepted:false
P0-B flag 形态校验     ← 同上，防污染正确率
P1   MD5 目标串定位    ← rank 6 的直接后续
P2   预算分层          ← 让 P1/P3 有机会跑完
P3   零指纹定向建议    ← 纯提示词，成本最低
P4   BLOCKER.md        ← 最后一道
```

## 五、验收标准

| 项 | 验收 |
|---|---|
| P0-A | 单测 4 条；`[WUSTCTF2020]level1` 重跑 `accepted:true` |
| P0-B | 单测 3 条；`[MRCTF2020]Xor` 重跑出现降级日志且该值不被提交 |
| P1 | CrackMe2 scan summary 列出疑似摘要目标；AI 直接对其爆破 |
| P2 | 简单题 ≤ 8 分钟收口；复杂题有 ≥ 25 分钟预算 |
| P3 | rc4 这类零指纹题得到由数据推导的检索方向 |
| P4 | 任一道失败题产出可执行的 BLOCKER.md |

每项都要求：`node tests/run_all.js` exit 0 + 同一批题的前后对比。

## 六、底线

- 所有改动通用，不写题目特判、不写题名/路径/flag
- 形态判据优先"数据自身结构"，其次"题面声明"，最后才是经验默认值
- 解不出也必须留下可执行的卡点说明，保证人工可接手
- 未本地验证通过的 flag 不提交（避免污染正确率）——P0-B 正是为了加强这条
