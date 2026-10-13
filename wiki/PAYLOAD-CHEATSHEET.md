# PAYLOAD / 套路速查表（逆向专用）

> 从逆向专项知识与历年题中提炼的**高频套路 + 可复用脚本片段**。做题直接查，不用翻长文。
> 每条标注**适用场景 + 关键代码**。深度原理见对应 wiki 页。

---

## 一、算法识别（看常量/结构认算法）

| 特征 | 算法 | 关键点 |
|---|---|---|
| 魔数 `0x9E3779B9` | **TEA/XTEA** | 32 轮，`sum += delta`；XTEA 改密钥索引 |
| 双 S 盒 + KSA/PRGA | **RC4** | `S[i]=i; KSA 乱序; PRGA 异或` |
| `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476` | **MD5** | 初始向量 |
| `6A09E667 BB67AE85...` | **SHA-256** | 初始 hash |
| 256 字节固定表 + 行列置换 | **AES S盒/MixColumns** | `AES_PRECOMP_TE` |
| 逐字节 `^` 固定/滚动 key | **XOR 流** | key 可能单字节/循环/PRNG 生成 |
| 大 switch + 状态变量 | **OLLVM 平坦化** | deflat / 语义恢复 |
| 跳转表 + 取指循环 | **自定义 VM** | 还原 opcode 映射表 |

## 二、native 常量反演 key（正逆互校）

```python
# 反演：从密文/目标常量反推 key 或输入；必须"正向加密对回目标"才算成功
def forward(x):  """按 IDA 反编译的算式实现"""
    ...
def inverse(target):  """反推"""
    ...
# 自检：forward(inverse(target)) == target 才敢用
assert forward(inverse(cipher)) == cipher
```
> 详：`wiki/frida/native-key-inversion.md`

## 三、Frida Native 方法 Hook（RegisterNatives 题）

```javascript
// 动态注册的 native（无 Java_ 导出）→ 拦 RegisterNatives 拿真实实现
var rn = null; Process.findModuleByName('libart.so').enumerateSymbols().forEach(function(s){
  if (s.name.indexOf('RegisterNatives')>=0 && s.name.indexOf('CheckJNI')<0) rn = s.address; });
Interceptor.attach(rn, { onEnter: function(a){
  var cnt=a[3].toInt32(), m=a[2];
  for (var i=0;i<cnt;i++){ var mi=m.add(i*Process.pointerSize*3);
    var nm=Memory.readCString(Memory.readPointer(mi));
    var fn=Memory.readPointer(mi.add(Process.pointerSize*2));
    Interceptor.attach(fn,{ onEnter:function(x){}, onLeave:function(r){} });
    console.log('[RN]', nm, fn); } }});
```
> 详：`wiki/frida/advanced-native-and-jce.md`

## 四、JCE 一把梭（抓密钥/明文，不追业务代码）

```javascript
Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B','java.lang.String')
  .implementation=function(k,alg){ console.log('key',alg,hex(k)); return this.$init(k,alg); };
Java.use('javax.crypto.Cipher').doFinal.overloads.forEach(function(ov){ ov.implementation=function(){
  var a=[].slice.call(arguments), r=ov.apply(this,arguments);
  console.log('doFinal in=',hex(a[0]),'out=',hex(r)); return r; }; });
```

## 五、Frida 环境自检（必做）

```bash
frida-ps -H 127.0.0.1:27042          # 能列进程=OK
# 报 queryIntentActivities NPE / major versions match = client/server 版本不一致 → 两端对齐(16.7.19)
```

## 六、IDA MCP 数据采集（缺常量表=无解）

```
反编译入口 + 关键函数 → 取引用常量表：list_globals + get_bytes（密钥/密文/S盒在 .data/.rodata）
搜字符串：find_strings(pattern="flag|key|nonce|salt")
```

## 七、VM/字节码题（还原 opcode）

```python
# 从 .data dump 出字节码数组 + opcode 映射表；写解释器逐条执行
prog = [...]            # dump 的程序数组
for pc in range(0, len(prog)):
    op = prog[pc] & 0xff
    if op == 0x01: ...  # 按 IDA switch 分支还原每个 op 语义
```

## 八、自动化求解选型

| 场景 | 工具 |
|---|---|
| 逐字节独立校验 | 暴力枚举 |
| 跨位依赖 / 约束方程 | **Z3** |
| 分支多静态读不动 | **angr**（给 find/avoid 地址）|
| 自写 VM / 只想跑一小段 | **Unicorn** |
| 迷宫/状态机 | BFS/DFS |
> 详：`read_skill ctf-reverse-tooling`

## 九、常见坑速查

| 坑 | 解 |
|---|---|
| 反编译 `Not found: 'main'` | mingw 入口是 `_main`；按候选名重试 |
| 函数列表全是 CRT 噪声 | `_add_key_dtor` 等是运行时噪声，降权 |
| native 无 Java_ 符号 | RegisterNatives 动态注册（§三）|
| IV 长度报错 | key/IV 编码互相独立，别借用（`param-encoding.md`）|
| 反调试致退出 | §反调试绕过（`advanced-native-and-jce.md`）|
| 抓包 0 数据 | 版本不一致 / App 停首页 / Hook 点错（`environment-troubleshooting.md`）|
