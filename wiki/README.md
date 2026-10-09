# CTF 逆向知识库（Wiki）

> 本目录是工具的**可检索知识库**：AI 通过 `wiki_search`（按关键词找页）和 `wiki_read`（读整页）调用。
> 与 `skills/` 的分工：`skills/` 是"方法论/工作流"，`wiki/` 是"具体手法 + 验证过的代码片段 + 踩坑"。
> 新增页时，把条目补进本文件，AI 的索引会自动更新。

## frida/（动态 Hook）

| 页面 | 一句话 | 何时读 |
|---|---|---|
| [in-process-decrypt.md](frida/in-process-decrypt.md) | 让 Hook 在 App 进程内自己解密，直接打印 `[FLAG]` | 抓得到密文但出不了 flag；要"Hook 出 flag" |
| [native-key-inversion.md](frida/native-key-inversion.md) | 从 native 常量反演密钥（正逆互校） | 校验在 .so，Java 只见 `native int[] f(String)` + int[] 常量比较 |
| [param-encoding.md](frida/param-encoding.md) | key/IV/密文编码与 IV 长度坑的自适应处理 | 报 `Incorrect IV length` / `Incorrect padding` / 解出乱码 |
| [android-multistage.md](frida/android-multistage.md) | 多阶段 APK 的定位与推进（含"停在首页"大坑） | 多关 APK；Hook 只抓到启动噪音 |

## firmware/（固件解包与仿真）

| 页面 | 一句话 | 何时读 |
|---|---|---|
| [unpack-and-emulate.md](firmware/unpack-and-emulate.md) | 固件解包（squashfs/jffs2/ubi/initramfs）+ QEMU 仿真实操与踩坑 | 拿到固件 .bin；binwalk 提取卡在中间层；要跑起来 |

## 使用约定

- **解题前**：`wiki_search` 关键词（如 `frida 解密`、`IV 长度`、`native 反演`、`多阶段`）。
- **命中后**：`wiki_read` 读整页，按里面的代码片段改参数直接用。
- **解题后**：有新手法/新坑，写进对应页或新建页，并在本索引登记。
