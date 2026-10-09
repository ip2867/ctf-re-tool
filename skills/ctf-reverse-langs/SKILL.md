---
name: ctf-reverse-langs
description: 语言特定逆向：Python 字节码（.pyc/PyInstaller/PyArmor）、Go（gopclntab/GoReSym）、Rust（符号/demangle/panic）、Lua（.luac/unluac/魔数版本）。拿到非 C/C++ 编译产物（.pyc/.exe 但像 Python、Go/Rust 二进制、.luac）时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# 语言特定逆向（Python / Go / Rust / Lua）

## 判型速查（先认语言，再选工具）

| 特征 | 语言 | 入口 |
|---|---|---|
| `.pyc/.pyo` 魔数；或 exe 里含 `python3x.dll`、`_MEIPASS`、`pyi-` | Python | 见 §1 |
| 大量 `gopclntab` / `runtime.main` / `Go build ID`；字符串含 `main.main` | Go | §2 |
| 字符串含 `core::panicking` / `rustc` / `std::io`；符号被 mangled（`_ZN...`） | Rust | §3 |
| `.luac` 文件头 `\x1bLua`；或内嵌 Lua 5.x VM | Lua | §4 |
| `.exe` 但 DIE 显示 PyInstaller/Nuitka/cx_Freeze | Python 打包 | §1 |

## 1. Python 字节码

**版本识别（关键，版本不对反编译必错）**：`.pyc` 前 4 字节 = magic（前 2 字节）+ 后 4 字节 = 可选时间戳/哈希。用 `python -c "import importlib.util; print(importlib.util.MAGIC_NUMBER)"` 或对魔数表。

**常规 .pyc**：
1. `pycdc xx.pyc`（本工具已集成）→ 反编译成 Python 源；失败则 `pycdas xx.pyc` 看字节码
2. 反编译不全时，读字节码：`LOAD_CONST/LOAD_FAST/BINARY_ADD/CALL_FUNCTION` 栈机语义，对照 [dis 文档]
3. 直接 import 跑：版本匹配时 `python -c "import xx"` 可执行（注意别真跑恶意代码）

**PyInstaller 打包（.exe）**：
1. 解包：`pyinstxtractor.py target.exe`（或用本工具 zip-list 找 `PYZ-00.pyz`）
2. 得到 `.pyc`（通常缺 magic，需按目标 Python 版本补前 4+8 字节头）
3. 再走 pycdc 反编译；主逻辑在 `target.exe_extracted/` 下的同名 `.pyc`（**不是** `PYZ` 里的库）

**PyArmor 混淆**：
- 特征：`pyarmor_runtime`、`__pyarmor__` 调用、代码被拆成 `__pyarmor_bcc_` 块
- 思路：找 `pyarmor_runtime.pyd/so`，Hook `__pyarmor__` 函数拿**解密后的原始字节码**（运行时会解出真实 co_code）；或用内存 dump 出还原的 code object
- 别硬解混淆算法，动态 dump 更稳

**常见坑**：magic 不匹配导致 pycdc 输出乱码；`exec/compile` 动态执行的字符串要多跟一层；`marshal.loads` 的数据段单独 dump。

## 2. Go 逆向

**符号识别（Go 的福音——默认不 strip 保留全部函数名）**：
1. **GoReSym**（首选）：`GoReSym -t target` 恢复函数名/类型 → 生成 IDA/Ghidra 可导入的符号文件
2. **IDA + golang_loader_assist / GoReSym 插件**：自动识别 `gopclntab`，恢复 `main.xxx` 函数名
3. 恢复后**直接搜 `main.main`、`main.check`、`main.encrypt`**，Go 函数名是明文，可读性远超 C

**关键结构**：
- `gopclntab`：函数地址→名字映射表（strip 后仍常在）；Go 1.18+ 偏移有变，工具版本要够新
- 字符串：Go 字符串是 `{ptr, len}` 结构，不是 C 的 null 结尾；IDA 里搜字符串后注意取 len 字节
- 切片 slice = `{ptr, len, cap}`；map 是 hash 表

**本工具配合**：Go 二进制用 `strings` + IDA；`main.check` 找到后按 ctf-reverse-binary 的静态套路还原算法。

**常见坑**：Go 1.20+ 的 `gopclntab` 布局变化导致老插件的函数名恢复失败→换新版 GoReSym；Go 的接口调用是间接寻址（interface 的 itab），交叉引用定位不到，要靠运行时类型断言点。

## 3. Rust 逆向

**符号**：Rust 符号名 mangled（`_ZN4main5check17h...E`）。用 `rustfilt` 或 `c++filt` demangle：
```
rustfilt < symbols.txt        # 或 IDA 插件 rust-demangle
```
demangle 后是 `main::check`、`core::str::...`，可读性恢复。

**特征与套路**：
- 字符串是 `&str`（ptr+len）或 `String`（ptr+len+cap），**不是 null 结尾**
- panic 路径：`core::panicking::panic_fmt`，输入错误常走 `panicked at 'assertion failed'` → 反推校验条件在 panic 调用点上方
- `Result`/`Option` 的分支判断：`is_ok/is_some` 后 `unwrap`，校验逻辑在 unwrap 之前的 match
- 大量内联：Rust release 把小函数内联进 main，反编译会很大→按字符串交叉引用切入

**常见坑**：Rust 字符是 **UTF-8**，`char` 4 字节；`wrapper` 类型零开销但反编译有噪声；iterator 链（`.map().filter().collect()`）展开成复杂循环，按语义理解而非逐指令。

## 4. Lua

**判型**：`.luac` 头 `\x1bLua` + 版本字节（`0x51`=5.1、`0x53`=5.3、`0x54`=5.4，**版本必须匹配**）。

**反编译**：
1. **unluac**：`java -jar unluac.jar xx.luac > xx.lua`（5.0~5.3）
2. **luadec**：按版本编译对应分支（5.1/5.4 各不同）
3. **LuaJIT**：特征 `\x1bLJ`，字节码是 LuaJIT 专有格式 → `luajit-decompiler`（LJD），或用 luajit 的 `-bl` dump

**加密 Lua（游戏/加固常见）**：
- 特征：加载时先 `xxtea_decrypt`/异或解密出字节码再 `loadstring`
- 思路：Hook `lua_load`/`luaL_loadbuffer`，在真正加载前 dump 出**解密后的字节码**；或在 `loadstring` 参数处断下

**常见坑**：版本字节不看导致 unluac 报错；LuaJIT 用不了 unluac；`string.dump` 出来的字节码可能是 strip 过的（去掉了调试信息，变量名丢失）。

## 输出契约

- 反编译/还原的算法 → `[VERIFY]`（`algo:"custom"` + 完整 Python 脚本），或 `[HYPOTHESES]` 枚举
- Python 题可直接给解密脚本；Go/Rust 若算法已还原，给等价 Python 复现脚本核对
- 语言判型结论写进过程记录（`read_skill` 命中本 skill 时，正文说明"判为 X 语言，走 §N"）
