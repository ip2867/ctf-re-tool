---
title: Frida 进阶：native 定位 / RegisterNatives / JCE 自吐 / 反检测 / 脱壳
category: dynamic
vuln_type: [reverse, android, native]
tags: [frida, RegisterNatives, native四定位, JCE自吐, 反调试, SSL pinning, 脱壳]
difficulty: hard
one_liner: native 无 Java_ 导出时靠 RegisterNatives 拦截；JCE 层通杀自吐密钥明文；反检测/SSL/脱壳一页全
keywords: [RegisterNatives, JNINativeMethod, 动态注册, Cipher, SecretKeySpec, 反frida, SSL pinning, dex dump, OLLVM]
---

# Frida 进阶：native 定位 / RegisterNatives / JCE 自吐 / 反检测 / 脱壳

> 适用：native 校验题、加固/反调试题、需要"抓密钥/明文但不知从何下手"时。
> 来源：吸收 `wa1ki0g/Script-For-FridaHook`、`laozig/frdia-hook` 两大项目精华 + 实战验证。
> 配套：本工具阶段3 内置 Hook 模板已含以下大部分片段，可作参考实现。

## 0. 三视图打印器（所有 [B 型数据都用它）

```javascript
// 优先 okio.ByteString（一行出 hex/base64，非可见字节也稳），失败降级手写
var BS = null; try { BS = Java.use('com.android.okhttp.okio.ByteString'); } catch(e) { try { BS = Java.use('okio.ByteString'); } catch(e2){} }
function view(tag, b){ try { if (BS && BS.of){ var z = BS.of(b); console.log(tag, 'hex=' + z.hex(), 'b64=' + z.base64()); return; } } catch(e){}
  var h=''; for (var i=0;i<b.length;i++){ var c=b[i]&0xff; h+=(c<16?'0':'')+c.toString(16);} console.log(tag, 'hex=' + h); }
```

## 1. native 函数四种定位

```javascript
// (a) 导出名
Interceptor.attach(Module.findExportByName("libx.so", "Java_com_a_b_c"), {
  onEnter: function(a){ try { console.log('arg1 str:', a[2].readCString()); } catch(e){} },
  onLeave: function(r){ console.log('ret:', r); /* r.replace(ptr(0x1)) 改返回 */ }
});
// (b) 符号表（libart/libc、mangled）
var hit=null; Process.findModuleByName("libart.so").enumerateSymbols().forEach(function(sy){
  if (sy.name.indexOf("RegisterNatives")>=0 && sy.name.indexOf("CheckJNI")<0) hit=sy.address; });
// (c) 偏移（ARM32/Thumb +1，ARM64 不加）
var addr = Module.findBaseAddress("libx.so").add(0x1234);   // 若 thumb 则 0x1234+1
// (d) inline：直接 attach 任意地址
```

## 2. RegisterNatives 拦截（无 Java_ 导出时的唯一入口）

```javascript
var libart = Process.findModuleByName("libart.so");
var rn=null; libart.enumerateSymbols().forEach(function(sy){
  if (sy.name.indexOf("RegisterNatives")>=0 && sy.name.indexOf("CheckJNI")<0) rn=sy.address; });
Interceptor.attach(rn, { onEnter: function(args){
  var cnt=args[3].toInt32(), methods=args[2], env=Java.vm.getEnv();
  var cls=env.getClassName(args[1]);
  for (var i=0;i<cnt;i++){
    var mi = methods.add(i * Process.pointerSize * 3);          // JNINativeMethod{name,sig,fnPtr}
    var nm = Memory.readCString(Memory.readPointer(mi));
    var sig= Memory.readCString(Memory.readPointer(mi.add(Process.pointerSize)));
    var fn = Memory.readPointer(mi.add(Process.pointerSize*2));
    console.log("[RN]", cls + "." + nm + sig, "->", fn);
    Interceptor.attach(fn, { onEnter:function(a){ /* a[1]=JNIEnv a[2]=jobject/this a[3..]=参数 */ },
                             onLeave:function(r){ /* JNI 返 jstring 时可用 env.newStringUtf 改 */ } });
  }
}});
```

## 3. JCE 通杀自吐（不追业务代码吐算法/密钥/明文）

```javascript
var Cipher = Java.use('javax.crypto.Cipher');
Cipher.init.overloads.forEach(function(ov){ ov.implementation = function(){
  var a=[].slice.call(arguments);
  try { if (a[1] && a[1].getEncoded) console.log('[key]', this.getAlgorithm(), view('', a[1].getEncoded())); } catch(e){}
  try { if (a[2] && a[2].getIV) console.log('[iv]', view('', a[2].getIV())); } catch(e){}
  return ov.apply(this, arguments); }; });
Cipher.doFinal.overloads.forEach(function(ov){ ov.implementation = function(){
  var a=[].slice.call(arguments); var r=ov.apply(this,arguments);
  console.log('[doFinal]', this.getAlgorithm(), 'in=', view('',a[0]), 'out=', view('',r)); return r; }; });
// 密钥来源更早：SecretKeySpec / DESKeySpec / IvParameterSpec 的 $init
Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B','java.lang.String').implementation=function(k,alg){ console.log('SKS', alg, view('',k)); return this.$init(k,alg); };
// HMAC / 签名
Java.use('javax.crypto.Mac').doFinal.overload('[B').implementation=function(d){ var r=this.doFinal(d); view('Mac in',d); view('Mac out',r); return r; };
Java.use('java.security.Signature').sign.overload().implementation=function(){ var r=this.sign(); view('sign',r); return r; };
// RSA N/E
Java.use('java.security.spec.RSAPublicKeySpec').$init.overload('java.math.BigInteger','java.math.BigInteger')
  .implementation=function(n,e){ console.log('RSA N=',n.toString(16),'E=',e.toString(16)); return this.$init(n,e); };
```

## 4. 反检测绕过

```javascript
// (a) 反 Frida 字符串检测
["strstr","strcmp"].forEach(function(fn){ var p=Module.findExportByName("libc.so",fn); if(!p) return;
  Interceptor.attach(p,{ onEnter:function(a){ var s=a[1].readCString();
    if (s && /frida|gum-js-loop|gmain|gdbus|linjector|27042|\/tmp/.test(s)) this.hit=true; },
    onLeave:function(r){ if(this.hit) r.replace(0); } }); });
// (b) 反调试线程阻断
var pc=Module.findExportByName("libc.so","pthread_create");
if (pc){ var orig=new NativeFunction(pc,'int',['pointer','pointer','pointer','pointer']);
  Interceptor.replace(pc, new NativeCallback(function(a0,a1,a2,a3){
    try { var nm=DebugSymbol.fromAddress(a2).name||''; if(/detect|frida|anti|debug|check/i.test(nm)) return 0; } catch(e){}
    return orig(a0,a1,a2,a3); }, 'int', ['pointer','pointer','pointer','pointer'])); }
```

## 5. SSL Pinning 绕过（抓 HTTPS）

```javascript
var X509=Java.use('javax.net.ssl.X509TrustManager'), SSL=Java.use('javax.net.ssl.SSLContext');
var TM=Java.registerClass({ name:'ctf.TM', implements:[X509], methods:{
  checkClientTrusted:function(){}, checkServerTrusted:function(){}, getAcceptedIssuers:function(){ return []; } }});
var tms=[TM.$new()];
SSL.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
  .implementation=function(km,tm,sr){ return this.init(km,tms,sr); };
try { Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String','java.util.List').implementation=function(){}; } catch(e){}
try { Java.use('com.android.org.conscrypt.TrustManagerImpl').verifyChain.implementation=function(u){ return u; }; } catch(e){}
```
> 最高强度 pinning：直接 hook native `libssl` 的 `SSL_read`/`SSL_write`（r0capture 原理，绕过所有上层校验）。

## 6. 脱壳（内存扫 DEX）

```javascript
Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function(m){ /* dex\n035 魔数 */
  if (m.address.add(0x3C).readUInt() === 0x70) {                 // string_ids_off==0x70 校验
    var size = m.address.add(0x20).readUInt();                    // file_size
    /* 写文件 dump */ } });
```
或用现成 `frida-dexdump -U -f <pkg>`。

## 7. 调用栈定位（谁调了这个函数）

```javascript
console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
// native:
console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
```

## 关联
- 进程内解密出 flag → `in-process-decrypt.md`
- native 常量反演 key → `native-key-inversion.md`
- key/IV 编码坑 → `param-encoding.md`
- 环境排障 → `environment-troubleshooting.md`
