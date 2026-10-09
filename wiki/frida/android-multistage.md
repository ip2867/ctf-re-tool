# Android 多阶段校验题（Hook 视角）

> 适用：APK 分多关（手势 → 输入 → 最终校验），flag 只在最后一关的加密里出现；
> 典型表现"Hook 抓到的全是启动噪音、0 条关键数据"。
> 来源：某多阶段 APK（Stage1 手势 / Stage2 native / Stage3 AES）实战验证，包名与 flag 已脱敏。

## 题目结构（本类题的通用骨架）

```
PatternActivity(手势, SHA-256 比常量)  →  Stage2Activity(native encryptStage2 比 int[])
        →  Stage3Activity(AES/CBC 比密文)  →  SuccessActivity
```

数据流：`SharedPreferences` 存中间态（`stage1Passed/stage2Passed/stage2Key`），
`SQLite`（SQLiteOpenHelper.onCreate）常藏密码学常量（本题是 Stage3 的 **IV**）。

## 定位关键代码（R8 混淆下）

包名被压成单字母（`N0`、`C`、`K0`、`M0`），Activity 只是壳。**按"字符串常量"反查**最快：

```bash
# 在 apktool 产物里搜关键常量，直接定位承载校验的类
findstr /S /I /M /C:"stage3_iv" /C:"stage2Key" /C:"<密文/常量片段的特征串>" smali\*.smali
```

- 校验回调（`OnClickListener`）→ 本题 `N0/d`
- 常量类（`fill-array-data` 的 int[]）→ 本题 `K0/a`
- `SQLiteOpenHelper`（DB 初始化常量）→ 本题 `M0/a`

`strings.xml` 里的 `XXX{...}` 类占位多为**干扰项/提示**，别直接当 flag。

## 最大坑：App 停在首页，校验代码永不执行

spawn 后如果不操作界面，App 停在手势页，Stage2/3 的加密根本不会跑 → Hook 只看到启动噪音。

**两条应对：**

1. **主动驱动界面**（本项目 `driveAppIteratively`：dump→操作→再 dump 逐屏推进）。
   手势盘穷举候选 `[[0,1,2,4,8], [0,3,6,7,8], [0,4,8], ...]`，输入框先填占位值触发分支。
2. **直接注入状态 + 跳关**（用 App 自己的 API，最干净）：

```javascript
Java.perform(function(){
  var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var sp = ctx.getSharedPreferences('challenge_state', 0);
  var ed = sp.edit();
  ed.putBoolean('stage1Passed', true);
  ed.putBoolean('stage2Passed', true);
  ed.putString('stage2Key', '<反演出的key>');
  ed.apply();
  Java.scheduleOnMainThread(function(){
    var it = Java.use('android.content.Intent').$new(ctx,
      Java.use('com.example.target.ui.Stage3Activity').class);
    it.addFlags(0x10000000); ctx.startActivity(it);
  });
});
```

读 DB 常量（IV）也走应用自己的 helper，不依赖 root：

```javascript
var helper = Java.use('M0.a').$new(ctx);
var cur = helper.getReadableDatabase()
  .rawQuery('SELECT v FROM app_cfg WHERE k = ?', Java.array('java.lang.String', ['stage3_iv']));
      if (cur.moveToFirst()) send('[DATA] stage3_iv = ' + cur.getString(0));  // -> <base64 编码的 IV，需按 base64 解码>
```

## 推荐进攻顺序

1. 静态：定位校验类、常量类、DB helper（按常量串搜 smali）。
2. 静态能解就在静态解（native 反演 key → AES 解 flag），最快最稳。
3. 静态拿不全 → Hook 补：在进程内解密（见 `in-process-decrypt.md`），key 用反演（`native-key-inversion.md`），IV 从 DB 读。
4. 需要触发真实流程时，再上"注入状态跳关 + 主动解密"。

## 避坑清单

- **不要**指望被动 Hook 自动出 flag；flag 在最后一关，必须主动推进到那儿或直接解密。
- **手势/输入的正确值未知**时不要死磕 UI 穷举；优先从 `SHA-256 常量`反查手势（本题 `0,1,2,4,8`）、从 native 反演输入。
- `SharedPreferencesImpl$EditorImpl` 是**内部类**，`Java.use('android.app.SharedPreferencesImpl$EditorImpl')`；写成 `SharedPreferencesImpl.EditorImpl` 会 undefined。
- spawn 早期 `currentApplication()` 可能为 null → 轮询重试。

## 关联

- 进程内解密出 flag → `frida/in-process-decrypt.md`
- native 常量反演密钥 → `frida/native-key-inversion.md`
- IV/key 编码坑 → `frida/param-encoding.md`
