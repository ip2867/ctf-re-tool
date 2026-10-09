---
name: ctf-jsreverse
description: Web JS 逆向方法论：加密参数定位、路径A算法追踪、路径B环境伪装、JSVMP/瑞数/obfuscator 判型、Burp 联动抓包分析。遇到 sign/token/X-Bogus 等加密参数或 JS 混淆还原任务时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# JS 逆向五阶段工作流（Observe → Capture → Rebuild → Verify → Document）

## 硬约束清单（开工前逐项确认）

- [ ] 目标与授权范围明确（CTF 题/自有系统/授权测试）
- [ ] 抓包通道就绪：浏览器代理指向 Burp（默认 127.0.0.1:8080），已触发目标请求
- [ ] 判型完成（见下"判型速查"），已声明走路径 A 还是路径 B
- [ ] 本地有 Node.js（复现/补环境必需）

## 五阶段流程

### 1. 观察 Observe
- 用 `burp_get_history` 搜代理历史，锁定带加密参数的请求（query/body 里的 `sign/token/signature/_signature/X-Bogus/a_bogus/data` 等）
- 记录：参数名、所在请求 URL、参数长度与字符集（纯 hex→可能是 md5/sha；带 `==`→base64；超长混合→AES/自定义+编码）

### 2. 捕获 Capture
- 从响应/历史中提取对应 JS 文件 URL，`burp_get_message` 取 JS 原文
- JS 内搜关键词（命中率排序）：`encrypt/decrypt/sign/Signature/SecretKey/CryptoJS/JSEncrypt/aes/des/md5/sha/base64/fromCharCode/charCodeAt`
- DevTools 手法：Sources 面板搜索 → XHR 断点（发起请求处回溯调用栈）→ DOM 断点 → `JSON.stringify` Hook（参数常在此被序列化加密）
- Hook 模板：`JSON.parse = new Proxy(JSON.parse, {apply(t,c,a){console.log('parse',a[0]);return Reflect.apply(t,c,a)}})`
- **自动化优先：用 `browser_js` 工具注入 Hook，无需人工开 DevTools**：
  - 观察：`browser_js(url=目标页, hookScript=Hook代码, resultExpr='window.__ctfCaptured||"无"', waitMs=5000)` — 注入后自动收集 console 输出与结果表达式
  - Hook 加密函数示例：`hookScript` 里覆写目标函数，把入参/出参 push 到 `window.__ctfCaptured=[]`，`resultExpr` 取回
  - 复现：直接在页面上下文调它的加密函数（如 `hookScript='window.__r=encrypt("test")'`，`resultExpr='window.__r'`），等效"抠出算法"但零翻译成本

### 3. 复现 Rebuild（先判型，再选路径）
**判型速查：**
| 特征 | 判型 | 默认路径 |
|---|---|---|
| 大量 `_0x` 前缀 + 字符串数组表 | obfuscator.io 混淆 | 路径A（四板斧） |
| 控制流扁平 switch-dispatcher / 大跳表 | JSVMP 或控制流混淆 | 小混淆走A，真 VMP 走B |
| 412 状态码 / Cookie 反复跳转 / 首页 JS 自解密 | 瑞数 | 路径B（sdenv 思路） |
| 参数在 WebView/Native 生成 | 混合 | B + Frida(见 ctf-reverse-android) |

**路径 A：算法追踪（四板斧，成本从低到高）**
1. **搜索还原**：直接读懂加密函数（多数 CTF/小站到此结束）
2. **Hook 插桩**：Frida/DevTools Hook `CryptoJS.AES.encrypt`、`Object.keys`、自实现类，打印入参出参
3. **日志插桩**：在关键函数出入口插 `console.log(JSON.stringify(arguments))`
4. **源码级插桩**：AST（babel）给每个函数调用插日志，跑一遍拿完整数据流 → 按日志重写算法

**路径 B：环境伪装（加密逻辑强依赖浏览器环境时）**
1. 把目标 JS 原样拉到 Node：`jsdom`/`vm` 沙箱 + 补 `window/document/navigator/location`
2. 浏览器采集真实环境对象 JSON → 与 Node 侧 diff → 逐个补丁（经验：缺啥报啥，报 `TypeError: Cannot read properties of undefined (reading 'x')` 就补 `x`）
3. 反检测浏览器兜底：Camoufox（C++ 引擎级指纹伪装）动态跑，导出环境
4. 补环境产物本身即"解密函数"：`function decrypt(input){...}`

### 4. 验证 Verify（本工具自动完成）
把还原函数按契约交出，工具本地跑 node 复现：
```
[VERIFY]{"algo":"node_js","key":"","ciphertext":"","encoding":"ascii","input":"<抓到的加密参数原文/明文输入>","expected":"<抓到的密文或期望输出>","code":"function decrypt(input){ ... return 密文字符串或Uint8Array; }"}[/VERIFY]
```
- `input` 喂明文，`expected` 喂抓包里的密文 → 工具比对是否复现成功
- 多个候选实现/密钥 → `[HYPOTHESES][{"algo":"node_js","code":"...","input":"...","expected":"..."}, ...][/HYPOTHESES]`

### 5. 记录 Document
- 关键结论 `经验 <一句话>` 入全局经验库（下次自动速查）
- `aiwp` 生成提交级题解；证据自动落 CASE 目录

## 案例坑库（命中特征直接套方案）

| 站点/特征 | 方案 | 关键坑 |
|---|---|---|
| TikTok `X-Bogus`/webmssdk | jsdom 环境伪装 | cacheOpts 配置错一点签名就变 |
| 抖音 `a_bogus`/byted_acrawler | jsdom + XHR 拦截器 | ttwid 必须从真浏览器导出，无法纯生成 |
| 瑞数 RS6 / 412 挑战 | sdenv（纯 Node 原生模块编译）| 别硬抠算法，环境伪装性价比高 10 倍 |
| obfuscator.io（`_0x` 前缀）| 通用四板斧 | 先还原字符串数组表（代码解密函数通常在底部 IIFE）|
| AES-GCM + JSVMP | 路径B 子进程桥接 | VMP 里手抠算法不如把 VM 整个跑起来 |

## 原则

- **别跟混淆较劲**：能 Hook 拿结果就不要读混淆码；能补环境跑原码就不要人肉翻译 VMP
- 每阶段产出一个证据（请求 URL、JS 文件、函数地址/行号、Hook 输出）落到 CASE
- 还原出的函数先 `Verify` 再宣称成功——抓包密文对不上就是没还原完
