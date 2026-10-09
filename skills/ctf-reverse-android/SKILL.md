---
name: ctf-reverse-android
description: Android/APK 逆向解题方法论：查壳脱壳、Java层/Native层分析、IL2CPP、反调试、Frida 动态取密钥。拿到 APK 题目或分析含 SO 的 APK 时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# Android 逆向解题方法（APK）

## 流程总览

```
APK → 查壳 → (有壳:脱壳) → Java层分析(JEB MCP 优先，软件自动拉起)
    → 找到关键类/方法 → (native? → 提取SO → IDA)
    → 静态定位算法 → Frida 动态验证 → 还原解密 → flag
```

## 0. 首选路径：JEB MCP（软件会自动拉起）

- APK 静态分析**优先调用 JEB 工具**：`jeb_get_manifest` → `jeb_get_all_classes` / `jeb_get_exported_activities` → `jeb_get_class_decompiled` / `jeb_get_method_decompiled`
- **JEB MCP 插件未运行≠不可用**：软件检测到 16161 端口不通时会自动启动 JEB、加载 `scripts/MCP.py` 并打开目标 APK（首次约 1~2 分钟），就绪后自动重试原工具调用。所以直接调用即可，不要因为"未连接"就绕开 JEB
- 标准顺序：manifest（找 LAUNCHER activity）→ 全部类列表（找可疑类名：Encoder/Check/Util，以及**拼写诱饵类**如 `MainActlvity` 与真 `MainActivity` 仅差字母）→ 反编译可疑类方法 → 拿到密文/密钥/比较逻辑 → 用 run_python 写脚本逆推
- 只有自动拉起也失败（JEB 未安装、scripts/MCP.py 缺失）才退回 run_python + androguard 本地分析

## 1. 查壳与脱壳

- 判断加固：DIE 查壳；特征字符串（360/腾讯乐固/爱加密/娜迦/百度/梆梆）在 Manifest 或 so 名中
- 脱壳手段（按成本从低到高）：
  1. **Frida dump DEX**：hook `DexClassLoader`/`ClassLoader.loadClass` 或搜内存 `dex\n035` 魔数 dump
  2. **BlackDex**（免 root 可用）、**FRIDA-DEXDump**
  3. 内存搜索法：`frida -H ... -n 目标 -l dump.js`，扫描 `0x64 0x65 0x78 0x0a 0x30 0x33 0x35`

## 2. Java 层分析要点

- 搜关键词：`flag`、`encrypt`、`decrypt`、`check`、`verify`、`password`、`Base64`、`SecretKey`
- 常见套路：
  - 输入 → `MessageDigest`（MD5/SHA）比对 → 无解需碰撞或截断比较
  - 输入 → `Cipher.doFinal`（AES/DES/RC4）→ 与常量密文比对 → **Hook `Cipher.init` 拿 key+iv，Hook `doFinal` 拿密文**
  - 输入 → native 方法（`public native String check(String)`）→ 转 SO 分析
  - 字符串混淆（`new String(byte[], charset)` / 异或）→ 逆推码表
- **MainActivity 定位**：找 `android.intent.category.LAUNCHER` 对应 activity，不是 Manifest 第一个 `android:name`

## 3. Native 层（SO）分析

- JNI 函数命名：`Java_包名_类名_方法名`；动态注册时找 `RegisterNatives`
- 常见保护：`JNI_OnLoad` 里反调试/字符串加密；OLLVM 控制流平坦化（用 deflat / 语义恢复）
- IDA 打开 SO 后先看 exports → JNI 函数 → 交叉引用到算法
- so 中识别算法同二进制逆向（见 ctf-crypto-identify skill）

## 4. Unity IL2CPP

- 特征：`libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat`
- 流程：**Il2CppDumper**（输入两个文件）→ 得 dummy.dll（所有 C# 类/方法名）+ script.py（IDA 符号）→ IDA 加载符号后按方法名定位
- 加密常在 C# 层调 native 或 `System.Security.Cryptography`

## 5. Frida 动态取证（本工具默认环境）

- 环境：Nox Android 9（ADB 62025），frida-server 27042
- 高价值 Hook 点（按命中率排序）：
  1. `javax.crypto.Cipher.init/doFinal` → 密钥、IV、密文一次拿全
  2. `java.lang.String.equals` → 比较点即 flag 校验点
  3. `android.util.Base64.decode/encode`
  4. `libc.so` 的 `strcmp/strstr/memcmp`（native 比较）
  5. 自定义 JNI 导出函数（onEnter 读 args，onLeave 读 retval）
- 注意：hook `equals` 时过滤空串避免日志爆炸

## 6. 输出契约

分析完成后按工具约定输出：
- `[FLAG]flag{...}[/FLAG]`（有把握时）
- `[VERIFY]{"algo":"rc4","key":"...","ciphertext":"hex或base64","encoding":"hex","expected":"..."}[/VERIFY]`（供工具自动复现）
- `[HYPOTHESES][{...},{...}][/HYPOTHESES]`（多个候选算法/密钥/字节序组合，供本地枚举）
