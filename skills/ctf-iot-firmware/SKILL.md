---
name: ctf-iot-firmware
description: IoT/路由器固件逆向：binwalk 提取、squashfs/ubifs/jffs2 文件系统识别与解包、init/NVRAM/启动脚本定位后门与硬编码口令、架构识别、QEMU 仿真运行、常见 CTF 固件题为型。拿到 .bin/固件镜像/路由器 dump/无扩展名大文件时使用。
license: MIT
metadata:
  user-invocable: "true"
---

# IoT / 路由器固件逆向

## 适用与判断

拿到 `.bin`、无扩展名大文件、`*_fw`、`flash.bin`、OTA 包、设备 dump，或题面提到"路由器/摄像头/IoT/PLC/固件"时用本技能。
本质：**一个容器套娃**——固件镜像里含引导头 + 一个或多个文件系统；目标通常在文件系统里（后门脚本、硬编码口令、加密程序）。

## 0. 通用流程（先扫后提，再钻进去）

```
固件 → file/strings 初始侦察 → binwalk 扫签名 → binwalk -e 提取
     → 得到文件系统镜像(常需二次提取) → 解包出 rootfs
     → 找 /etc /init.d /usr/bin 关键脚本 → 定位后门/口令/加密逻辑
     → 架构识别 → IDA 分析二进制 / 或 QEMU 仿真跑起来
```

## 1. 初始侦察（别急着 binwalk）

```bash
file firmware.bin                 # 有些直接报 "Squashfs filesystem" / "u-boot legacy uImage"
strings -n 8 firmware.bin | head -100    # 找内核版本、厂商名、busybox 版本、明显文件名
xxd firmware.bin | head -20               # 看魔数：squashfs=hsqs、uboot=0x27051956、jffs2=0x1985(小端)
```
- **魔数速记**：`hsqs`(正序)=squashfs 小端；`sqsh`=squashfs 大端；`\x27\x05\x19\x56`=u-boot uImage；gzip `1f8b`、xz `fd377a585a00`、7z、LZMA `5d0000`
- 文件里可能有**多个**文件系统与内核，别只提第一个

## 2. binwalk 提取

```bash
binwalk firmware.bin                 # 只扫，列出偏移+类型+大小
binwalk -e firmware.bin              # 提取（输出到 _firmware.bin.extracted/）
binwalk -Me firmware.bin             # 递归提取（含压缩包内的）
binwalk -E firmware.bin              # 熵图：识别加密/压缩段（高熵平坦=可能加密）
```
- **binwalk v3（Rust 重写）注意**：v3 **不再内置提取器**，`-e` 行为与 v2 不同、需要外部工具（unsquashfs/7z 等）在 PATH 里；若 v3 提取不出，换 v2（`pip install binwalk==2.3.4`）或手动按偏移 dd 出来再解
- 提取后常见剩余物：`.squashfs`（**需二次提取**，见下）、`.cpio`、`.gzip`、`.lzma`、`.dtb`
- 熵图一段平坦高熵 = 加密或已压缩，binwalk 认不出签名 → 需先脱壳/解密（见 §6）

## 3. 文件系统解包（最容易卡住的一步）

| 类型 | 识别 | 解包命令 |
|---|---|---|
| **squashfs** | 魔数 `hsqs`/`sqsh`，binwalk 提取后留 `.squashfs` | `unsquashfs -d rootfs file.squashfs`；新版固件（squashfs 4.0 变体/非标准压缩）用 **sasquatch** 或 `unsquashfs -comp <comp>` |
| **JFFS2** | 魔数 `0x1985`；NAND/NOR 常见 | `jefferson -d out file.jffs2` 或 `jffs2extract`；挂载用 `modprobe mtdram` + `mount -t jffs2` |
| **UBIFS/UBI** | `UBI#` 魔数 | `ubireader_extract_images` → `ubireader_extract_files`（ubireader-ng 包） |
| **cramfs** | 魔数 `0x28cd3d45` | `cramfsck -x rootfs file.cramfs` 或 `binwalk -e` |
| **ext2/3/4** | `file` 报 ext filesystem | `mount -o loop` 或 `debugfs` |
| **initramfs/cpio** | gzip 解开后是 ASCII `cpio` | `(cd rootfs && cpio -idmv < ../initramfs.cpio)` |
| **tar/tgz** | `file` 报 tar/gzip | `tar xf` |
| **yaffs2** | 裸 NAND dump | `unyaffs` / `yaffs2utils` |

```bash
# 万能兜底：先看是什么
file file.squashfs
binwalk file.squashfs          # squashfs 有时也含嵌套
# squashfs 解不开的常见原因：非默认压缩(lzma/xz/lzo/zstd) → 试 -comp 参数
unsquashfs -s file.squashfs    # 显示压缩算法/版本，据此选参数
```

**二次提取坑**（FreeBuf 案例1）：binwalk 提到 `120200.squashfs` 就停了，因为它本身是个 squashfs 文件（不是"压缩包"，binwalk 不自动解文件系统）——必须用 `unsquashfs` 再解一次才得到 `rootfs/`。

## 4. rootfs 里找目标（固件题的高频落点）

解出 `rootfs/` 后，按这个顺序翻：

1. **`/etc/init.d/`、`/etc/rc.d/`、`/etc/inittab`、`/etc/profile`**：启动脚本，后门常藏在这（`telnetd -l /bin/sh`、监听端口、硬编码口令）
2. **`/etc/passwd`、`/etc/shadow`**：找非 root 的异常账号、默认口令（shadow 里 `$1$`=MD5-crypt，`$6$`=SHA512-crypt，可 hashcat 爆破）
3. **`/etc/config/`、`/etc/nvram*`、`/etc/*.conf`**：NVRAM/配置，出厂默认口令常在
4. **`/usr/bin`、`/usr/sbin`、`/bin`、`/sbin`**：二进制程序；找与题面相关的自定义程序名（backdoor/demo/agent/xxx_server）
5. **`/etc_ro`、`/rom`、`/mnt/`、`/home/`**：厂商自定义目录；PLC 类题常在 `/home/<厂商>/`（FreeBuf 案例2：`/home/` 下有 `FuncDll/NandFlash/Process`）
6. **web 目录**（`/www`、`/web`、`/usr/share/web`）：Web 管理界面，找 CGI 里的命令注入/改包逻辑
7. **`strings` 全局扫敏感词**：`grep -rniE "flag|passwd|password|secret|key|admin|backdoor|debug" rootfs/etc rootfs/usr`

**FreeBuf 案例2 的坑（务必记）**：搜 `rootPasswd`、`passWd.c` 在 Strings 视图和 hex/内存里都找不到——因为它们是 **symbol（符号名）不是字符串**。要 `View → Open subviews → Names` 里找（或 Shift+F4 打开符号表）。**字符串搜不到时，立刻换 Names 视图**。

## 5. 架构识别（决定能否仿真/用哪个 IDA 处理器）

```bash
file rootfs/usr/bin/backdoor        # ELF 32-bit LSB shared object, ARM, EABI5 ...
readelf -h rootfs/usr/bin/backdoor  # Machine: ARM / MIPS / AArch64
```
- `ARM, EABI5, 32-bit` → IDA 用 ARM Little-endian（**注意**：可能是 Thumb，函数开头 LSB=1 或地址末位为奇数）
- `MIPS, 32-bit` → 路由器最常见；大端(big-endian)路由器上常见 **MIPS BE**
- `AArch64`/`x86-64` → 64 位，现代设备
- 静态链接的 busybox/程序符号全无 → 用 IDA FLIRT 签名或 Ghidra 的自动识别

**UPX 脱壳**（FreeBuf 案例1）：`backdoor` 被 UPX 加壳（DIE 或 `strings | grep UPX` 可见），先 `upx -d backdoor` 再入 IDA，否则反编译是壳代码。
`apt install upx-ucl`；部分变种被改过 UPX 头 → 用 `upx -d --force` 或手动解。

## 6. 加密/未知段处理

- binwalk 熵图高熵平坦且无签名 → 可能整段加密：找**解密逻辑**（bootloader 或首段程序里的 AES/RC4/自定义异或），提取 key 后解密再 binwalk
- 已知变体的 squashfs（非标准压缩/魔数被改）：`unsquashfs -comp lzma|xz|lzo|zstd`；魔数被改则按偏移手动 `dd` 出来再看
- 固件头的校验和/CRC 有时也是题目（改完要重算）

## 7. QEMU 仿真（把固件跑起来）

**为什么仿真**：动态观察真实行为、让加密程序自解密、或跑 CGI 看处理逻辑。

**方案 A：firmadyne / FAT（全系统仿真，自动）**
```bash
# firmadyne 自动识别架构+生成 qemu 启动脚本
sudo ./sources/extractor/extractor.py -b <brand> -sql 127.0.0.1 -np -nk firmware.bin images
./scripts/getArch.sh ./images/1.tar.gz
./scripts/makeImage.sh 1
./scripts/inferNetwork.sh 1
./scripts/run.sh 1          # 起 qemu
```
- 常失败：内核版本与 QEMU 不匹配、NVRAM 缺失导致启动卡住 → 用 FAT（firmware-analysis-toolkit）包装，或手动补 NVRAM

**方案 B：user-mode QEMU（只跑单个程序，最实用）**
```bash
# MIPS 大端程序：用 qemu-mips（BE）；小端用 qemu-mipsel
# 需要把程序依赖的库放到 arm/mips 的 sysroot 里
cp $(which qemu-mips-static) ./rootfs/usr/bin/
sudo chroot ./rootfs ./usr/bin/qemu-mips-static -L ./ ./bin/target
# ARM: qemu-arm-static -L . ./bin/target
# 带参数/输入：
sudo chroot ./rootfs ./usr/bin/qemu-arm-static -L . ./bin/check "input"
```
- `-L .` 指定动态库搜索根（否则报 `No such file or directory`——其实是找不到 ld.so）
- 静态编译的 busybox/程序：直接 `qemu-arm-static ./target` 即可

**方案 C：直接跑题目程序（最简单，很多 CTF 题适用）**
```bash
# 纯算法题：程序只是读输入算结果，不需要整个系统
qemu-arm ./target                    # 交叉架构直接跑
qemu-arm ./target arg1 arg2
# 交互输入：echo "input" | qemu-arm ./target  或  printf 'a\nb\n' | qemu-arm ./target
```
**注意**：`qemu-arm`（动态）需宿主有对应 `arm-linux-gnueabi` 的 ld 与 libc；没有就用 `-static` 版本 + `-L`。**架构/字节序选错**（MIPS BE 用了 el）会直接 `Invalid ELF image` 或段错误——先 `readelf -h` 确认。

**方案 D：只提取加密函数，不走 QEMU** —— 若程序是"读输入→算法→比较"，直接按 ctf-reverse-binary 静态还原 + Unicorn 模拟单段（见 ctf-reverse-tooling），比整套仿真快。

## 8. 常见固件题类型 → 落点

| 题型 | 特征 | 落点 |
|---|---|---|
| 后门程序/远程地址 | 题问"后门连接的 IP:端口" | init 脚本/二进制里 strings 找 IP + 端口号（FreeBuf 案例1）|
| 硬编码口令 | 题问"厂商默认密码/root 密码" | `/etc/shadow` 爆破 或 二进制 Names 视图找 `passwd` 符号（案例2）|
| 配置校验 | 固件里含校验算法 | 提取算法 → Z3/爆破 |
| 加密固件解密 | 固件头/段加密 | 先逆解密逻辑拿 key，再解全镜像 |
| CGI/Web 逻辑 | 固件带 httpd + www | 分析 CGI 程序，找命令注入/参数校验 |
| 迷宫/规则 | 少见但存在 | 转 ctf-reverse-tooling |

## 9. 输出契约

- 提取出的可疑脚本/二进制路径、硬编码凭据、算法 → 作为证据落 CASE
- 口令/算法还原 → `[VERIFY]`（custom + Python 脚本）或 `[HYPOTHESES]`
- 仿真成功的启动命令记进过程（下次同固件直接复用）
- flag：`[FLAG]xxx[/FLAG]`

## 工具速查（本工具环境）

| 用途 | 工具 |
|---|---|
| 扫描/提取 | `binwalk`（v2/v3）、`file`、`strings`、`xxd`、`dd` |
| squashfs | `unsquashfs`、`sasquatch`（非标准压缩）|
| jffs2/ubi/cramfs/yaffs | `jefferson`、`ubireader`、`cramfsck`、`unyaffs` |
| 脱壳 | `upx -d`、DIE |
| 静态分析 | IDA（Strings **和** Names 两个视图）、Ghidra |
| 仿真 | `qemu-arm/mips/mipsel(-static)`、`firmadyne`、FAT |
| 口令爆破 | `hashcat`（`$1$`→mode 500，`$6$`→mode 1800）、`john` |
