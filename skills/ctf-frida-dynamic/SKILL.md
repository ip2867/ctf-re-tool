---
name: ctf-frida-dynamic
description: Frida 动态分析：按目标选 Hook 点（Java加密库/字符串比较/Native函数/内存），拿到静态拿不到的运行时密钥与密文；并让 Hook 在进程内直接解密出 flag。需要动态数据或"抓得到却出不了 flag"时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# Frida 动态取证

## 环境

- Windows PE：`frida -n 目标.exe -l hook.js`（本机）
- Android：`frida -H 127.0.0.1:27042 -n 包名 -l hook.js`；本工具"运行Hook"按钮抓 20 秒输出
- 免 root/gadget：`frida -f 包名`（spawn 模式，能 Hook 到 Application.onCreate 之前的逻辑）；若 spawn 失败则回退 attach（见"常见坑"）
- **先自检**：`frida-ps -H 127.0.0.1:27042`。能列进程 = 环境 OK；报 `queryIntentActivities` NPE 或 `major versions match` = client/server 版本不一致，两端对齐同一版本

## Hook 点选择树

```
要拿什么？
├── 加密密钥/IV → Cipher.init / SecretKeySpec 构造 / EVP_CipherInit(native)
├── 加密前后数据 → Cipher.doFinal / 自定义 encrypt 函数 onEnter+onLeave
├── 比较点(输入对不对) → String.equals / strcmp / memcmp
├── 哈希/签名 → MessageDigest.digest / Mac.doFinal / Signature.sign / HMAC
├── 编解码 → Base64.decode/encode
├── 配置/密文常量 → SharedPreferences.getString / 资源读取 / .rodata 内存扫描
├── native 动态注册校验 → RegisterNatives（见下，无 Java_ 导出时的唯一入口）
└── 未知地址函数 → Interceptor.attach(基址+RVA)，x64: RCX RDX R8 R9，x86: 栈
```

> **JCE 通杀自吐**：不必逐个追业务类，直接在 JCA/JCE 标准层挂 hook 就能吐出「算法名+密钥+IV+明文+密文」——
> 绝大多数 App（含混淆/加固）最终都走 `javax.crypto.*` / `java.security.*`。挂全这几个即通杀：
> `Cipher.init/doFinal`（列全 7 个 init、6 个 doFinal 重载）、`MessageDigest.getInstance/update/digest`、
> `Mac.getInstance/doFinal`、`Signature.update/sign`、`SecretKeySpec`/`DESKeySpec`/`IvParameterSpec` 构造、`RSAPublicKeySpec(N,E)`。
> 判断加/解密方向：`Cipher.init` 的 opmode（1=ENCRYPT / 2=DECRYPT）。
> RSA 私钥坑：`arguments[1]` 若是 `OpenSSLRSAPrivateKey`，`getEncoded()` 会抛异常，先 `JSON.stringify` 判类名跳过。

## native 函数定位（四种，按稳定性）

| 方式 | 写法 | 场景 |
|---|---|---|
| 导出名 | `Module.findExportByName(so, name)` | 有导出的 `Java_*` / 自定义导出 |
| 符号表 | `Process.findModuleByName(so).enumerateSymbols()` + 子串过滤 | libart/libc、C++ mangled、静态 so |
| 地址偏移 | `Module.findBaseAddress(so).add(offset)`（**ARM32/Thumb 要 +1**）| IDA 里拿到 RVA，无符号 |
| inline | `Interceptor.attach(任意地址)` | 任意函数（含非导出） |

```javascript
// 主动调用 so 内函数（不依赖 App 触发）
var f = new NativeFunction(Module.findBaseAddress("libx.so").add(0x1234), 'pointer', ['pointer']);
var arg = Memory.alloc(32); arg.writeUtf8String("test");
console.log(hexdump(f(arg), { length: 64 }));
```

> **RegisterNatives（关键）**：加固/动态注册的 native 函数**没有 `Java_` 导出**，只能在 `libart.so` 的
> `RegisterNatives` 处拦截，遍历 `JNINativeMethod{name, sig, fnPtr}`（结构体步长 `pointerSize*3`），
> 从 `fnPtr` 直接 attach 真实实现——这是这类题唯一的 native 入口。
> 另可用「JNIEnv 函数表 vtable 偏移」hook `GetStringUTFChars`(169)/`NewStringUTF`(167) 抓 Java↔Native 字符串。

## 反检测绕过（逆向加固题常需）

- **反 Frida 字符串检测**：hook `libc` 的 `strstr/strcmp`，命中 `frida/gum-js-loop/gmain/gdbus/linjector/27042/tmp` → `retval.replace(0)`。
- **反调试线程**：`Interceptor.replace(pthread_create)`，对回调名含 `detect/frida/anti/debug/check` 的线程直接返回 0（不创建）。
- **自实现 syscall 绕过 libc**：扫 `svc` 机器码（arm64 `01 00 00 D4` / arm `00 00 00 EF`）找 open(56/5) 等系统调用点。
- **SSL Pinning**：Java 层造万能 `X509TrustManager` 并劫持 `SSLContext.init`，再逐层 hook `okhttp3.CertificatePinner.check`、`conscrypt.TrustManagerImpl.verifyChain`、`WebViewClient.onReceivedSslError`；native 兜底 hook `libssl` 的 `SSL_read/SSL_write`（r0capture 原理）。

## 脱壳（内存扫描 DEX）

内存扫 DEX 魔数 `64 65 78 0a 30 ?? ?? 00`（`dex\n035`），校验 `+0x3C` 的 `string_ids_off == 0x70`、`+0x20` 读出的 `file_size`，dump 出来交给 jadx。
现成工具：`frida-dexdump -U -f <pkg>`（整体加固）/ BlackDex（免 root）。

## 实用片段

> **Frida 17+ API 变更**：v17 移除了 `Module.findExportByName / getExportByName / findBaseAddress` 静态方法。
> 兼容写法（旧版跳过，新版重建）：
>
> ```javascript
> if (typeof Module.findExportByName !== 'function') {
>     Module.findExportByName = function (modName, expName) {
>         if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(expName) : null; }
>         return Module.getGlobalExportByName ? Module.getGlobalExportByName(expName) : null;
>     };
> }
> if (typeof Module.findBaseAddress !== 'function') {
>     Module.findBaseAddress = function (name) { var m = Process.findModuleByName(name); return m ? m.base : null; };
> }
> ```
>
> 本工具生成的模板已内置此 shim；自己手写脚本时建议照抄。

### Java：一把梭拿加密参数

```javascript
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log("[Cipher.init] mode=" + (mode===1?"ENCRYPT":"DECRYPT") +
            " algo=" + this.getAlgorithm());
        console.log("  key bytes=" + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var r = this.doFinal(input);
        console.log("[doFinal] in=" + bytesToHex(input) + "\n  out=" + bytesToHex(r));
        return r;
    };
    function bytesToHex(b){if(!b)return"null";var h=[];for(var i=0;i<b.length;i++)h.push(("0"+(b[i]&0xFF).toString(16)).slice(-2));return h.join("");}
});
```

### Native：按 RVA Hook + 读缓冲区

```javascript
var base = Module.findBaseAddress("目标.so或.exe");
var fn = base.add(0x1A40); // IDA地址 - ImageBase
Interceptor.attach(fn, {
    onEnter: function(args) {
        this.buf = args[1]; this.len = args[2].toInt32();
        console.log("[fn] arg1=" + hexdump(this.buf, {length: Math.min(this.len,64)}));
    },
    onLeave: function(ret) {
        console.log("[fn] out=" + hexdump(this.buf, {length: Math.min(this.len,64)}));
    }
});
```

### 内存搜索常量密文

```javascript
Memory.scan(base, size, "aa bb cc dd", {
    onMatch: function(addr, size) { console.log("found at " + addr); },
    onComplete: function() {}
});
```

## 进阶：让 Hook 自己解出 flag（而非只打印日志）

被动 Hook 只能看到"发生过什么"，出不了 flag。让它自己完成最后一步：
- **进程内解密**：脚本头部注入解密器，拿到 key/iv/密文就在 App 进程内 `Cipher.doFinal`，命中即 `send('[FLAG]...')`。完整模板见知识库 `wiki/frida/in-process-decrypt.md`（用 `wiki_search 'frida 解密'` 检索）。
- **运行时兜底**：hook `Cipher.init` 捕获真实 key/IV（16 字节）写回，脚本周期重试解密。
- **密钥来源**：校验在 native 时，从常量数组反演密钥并**正逆互校**（`wiki/frida/native-key-inversion.md`）。
- **编码自适应**：key/IV 的编码互相独立，IV 不能借用 key 的编码；按 hex/base64/ascii 枚举取 16 字节（`wiki/frida/param-encoding.md`）。
- **多阶段 APK**：App 停在首页时校验代码不执行，需主动驱动界面或用 App API 注入状态跳关（`wiki/frida/android-multistage.md`）。

> 本项目工具已把上述逻辑内置：阶段3 会向 Hook 注入"进程内解密段"，并从输出直接收割 `[FLAG]`。

## 常见坑

- **frida client/server 版本必须一致（最常见、最致命）**：PC 端 frida 客户端 与 设备端 frida-server
  **版本要完全一致**（大/次版本）。不一致时连 `frida-ps` 都失败，报
  `java.lang.NullPointerException: ... queryIntentActivities(...) on null`
  或 `unable to communicate with remote frida-server; please ensure that major versions match`，
  此时 spawn/attach 全部失败。
  **解决：两者对齐到同一版本（推荐都 16.7.19）**，并**把 server 覆盖到工具实际使用的路径
  `/data/local/tmp/frida-server`**（只放别名如 `frida-server-16` 无效——工具仍用主路径旧文件）。
  实测：**client/server 一致时 16/16 与 17/17 都能正常 `frida-ps`+`spawn`**；不一致必崩。
  判断法：跑 `frida-ps -H 127.0.0.1:27042` —— 能列进程=OK，报上述错=版本不匹配（非脚本问题）。
- **spawn 失败要回退 attach**：`frida -f 包名` 某些环境（旧 ROM / 版本不匹配 / 无 launcher 解析）
  会 `Failed to spawn`。此时改用：先 `adb shell monkey -p 包名 -c android.intent.category.LAUNCHER 1`
  拉起 App，再 `frida -H ... -n 进程名 -l hook.js`（attach），多数场景等价可用（本工具已内置自动回退）。
- Hook `String.equals` 不过滤 → 日志爆炸刷屏；过滤 `length()>4` 且非系统调用
- 不要 Hook `java.util.Objects.equals` 之类超热方法 → 每次比较都进，会把 Frida agent 打崩（实测 `Bad access due to protection failure`）；优先 hook 低频的 `Cipher.init`
- 解密报 `Incorrect IV length (16 required)` → IV 被按错误编码解（如明文被当 base64）；key/IV 编码互相独立，见 `wiki/frida/param-encoding.md`
- `overload` 不匹配直接异常 → 先 `.overloads.forEach` 打印真实签名再选
- spawn 模式启动太早 Java 还没就绪，且 `ActivityThread.currentApplication()` 可能为 null → 包在 `Java.perform` 里，取 context 用 `setInterval` 轮询重试
- `SharedPreferences` 编辑器是内部类 → `Java.use('android.app.SharedPreferencesImpl$EditorImpl')`，写成 `.EditorImpl` 会 undefined
- 打印 byte[] 不要直接 toString → 用 bytesToHex

## 结果回填约定

Hook 拿到 key/密文后，把它们代入 `[VERIFY]{...}` 契约让工具本地复现验证，而不是只贴日志。
契约里带上 `key_encoding` / `iv_encoding` / `encoding`，避免编码二义导致复现失败。
