# Hook 进程内解密直接出 flag

> 适用：CTF 逆向题里，"抓得到密文但出不了 flag"——Hook 只被动打印日志，没人拿密钥去解密。
> 来源：某多阶段 APK 实战验证（2026-10，包名与 flag 已脱敏）。

## 核心思想

被动 Hook 只能看到"发生过什么"；要出 flag，得让 **Hook 自己完成最后一步解密**。

在 Frida 脚本头部注入一段"解密器"：只要手上有 `key / iv / ciphertext`（不管是静态求出来的，还是运行时 hook 到的），就在 App 进程内调 `Cipher.doFinal` 解密，命中 flag 形态就 `send('[FLAG]...[/FLAG]')`，由工具侧直接收割落库。

关键点：**在目标进程内解密**，天然复用 App 自己的 crypto provider，绕开"导出的密文拿到本机解、环境/填充/Provider 不一致"的坑。

## 注入模板（已验证可运行）

```javascript
// ==== ctf-tool: in-process flag decryptor ====
var __CTF_KNOWN = { key:'<静态/动态求得的key，hex或原文>', keyEnc:'hex',
                    iv:'<求得的IV>', ivEnc:'hex',
                    ct:'<抓到的密文，hex 或 base64>',
                    enc:'base64', algo:'aes_cbc' };
var __CTF_DONE = false;

function __ctfToBytes(s, enc){
  if (s == null) return null; s = String(s);
  if (enc === 'hex')    { var o=[]; for (var i=0;i<s.length;i+=2) o.push(parseInt(s.substr(i,2),16)); return o; }
  if (enc === 'base64') { var B=Java.use('android.util.Base64'); var b=B.decode(s,2); var a=[]; for (var k=0;k<b.length;k++) a.push(b[k]); return a; }
  var sb = Java.use('java.lang.String').$new(s).getBytes('UTF-8'); var a2=[]; for (var m=0;m<sb.length;m++) a2.push(sb[m]); return a2;
}

function __ctfDecrypt(tag){
  if (__CTF_DONE) return;
  if (!__CTF_KNOWN.key || !__CTF_KNOWN.ct) return;
  try {
    var keyB = __ctfToBytes(__CTF_KNOWN.key, __CTF_KNOWN.keyEnc || 'ascii');
    var ctB  = __ctfToBytes(__CTF_KNOWN.ct,  __CTF_KNOWN.enc    || 'base64');
    if (!keyB || !ctB) return;
    var algo = String(__CTF_KNOWN.algo || 'aes_cbc').toLowerCase();
    var mode = algo.indexOf('ecb') >= 0 ? 'AES/ECB/PKCS5Padding' : 'AES/CBC/PKCS5Padding';
    var C = Java.use('javax.crypto.Cipher').getInstance(mode);
    var kSpec = Java.use('javax.crypto.spec.SecretKeySpec').$new(Java.array('byte', keyB), 'AES');
    var ivB = __ctfToBytes(__CTF_KNOWN.iv, __CTF_KNOWN.ivEnc || '');
    if (mode.indexOf('CBC') >= 0) {
      if (!ivB || ivB.length !== 16) { send('[!] cbc 需要 16 字节 IV，实际 ' + (ivB ? ivB.length : 0)); return; }
      C.init(2, kSpec, Java.use('javax.crypto.spec.IvParameterSpec').$new(Java.array('byte', ivB)));
    } else { C.init(2, kSpec); }
    var s = String(Java.use('java.lang.String').$new(C.doFinal(Java.array('byte', ctB))));
    send('[DATA] (' + tag + ') DECRYPTED = ' + s);
    if (/XXX\{|flag\{|ctf\{/i.test(s)) { __CTF_DONE = true; send('[FLAG]' + s + '[/FLAG]'); }
  } catch(e) { send('[!] decrypt(' + tag + '): ' + e); }
}

Java.perform(function(){
  __ctfDecrypt('bootstrap');
  // 关键：脚本可能稍后才拿到运行时参数（hook 捕获）→ 周期重试
  if (!__CTF_DONE) setInterval(function(){ try{ __ctfDecrypt('tick'); }catch(e){} }, 3000);
});
```

## 运行时兜底：hook 到密钥就自动解密

静态求不出 key/iv 时，用 `Cipher.init` 捕获运行时真实值，写回 `__CTF_KNOWN` → 下次重试即解出：

```javascript
var Cipher = Java.use('javax.crypto.Cipher');
Cipher.init.overloads.forEach(function(ov){
  ov.implementation = function(){
    var a = Array.prototype.slice.call(arguments);
    try { if (a[1] && a[1].getEncoded) { var kb=a[1].getEncoded();
      if (kb && kb.length === 16) __CTF_KNOWN.key = __hex(kb); } } catch(e){}
    try { if (a[2] && a[2].getIV) { var ib=a[2].getIV();
      if (ib && ib.length === 16) __CTF_KNOWN.iv = __hex(ib); } } catch(e){}
    return ov.apply(this, arguments);
  };
});
```

另有更直接的一路：`Cipher.doFinal` 的**明文入参**若本身就是 flag 形态，直接 `send('[FLAG]...')`，连解密都不用。

## 工具侧收割

Hook 输出里的 `[FLAG]...[/FLAG]` 直接用正则提取 → `recordFlag(f, 'frida-flag', true)`（去重后），不依赖 AI 复述：

```javascript
const directFlags = (output.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/gi) || [])
  .map(s => (s.match(/\[FLAG\]\s*([^\[\]\r\n]+?)\s*\[\/FLAG\]/i) || [])[1])
  .filter(v => v && looksLikeFlag(v));
[...new Set(directFlags)].forEach(f => recordFlag(f, 'frida-flag', true));
```

## 避坑

- **别把注入段重复拼两次**：内置兜底脚本本身已含该段，外部再拼一次会重复解密、重复打印 `[FLAG]`。用 `!/__CTF_KNOWN/.test(script)` 作去重标记。
- **函数名加前缀**（如 `__ctf*`）：避免与 AI 生成脚本里的同名辅助函数（`toBytes` 等）冲突。
- **不要 Hook `java.util.Objects.equals` 这类超热方法**：每次字符串比较都进，极易把 Frida agent 打崩（本会话实测 "Bad access due to protection failure"）。优先 hook 低频的 `Cipher.init`。
- **spawn 早期 `ActivityThread.currentApplication()` 可能是 null**：用 `setInterval` 重试拿 context，别只取一次。

## 关联

- 密钥怎么来 → `frida/native-key-inversion.md`
- 编码/IV 长度坑 → `frida/param-encoding.md`
- 多阶段 APK 整体套路 → `frida/android-multistage.md`
