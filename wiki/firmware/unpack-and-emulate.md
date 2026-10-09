# 固件解包与仿真实操（踩坑版）

> 配合 `ctf-iot-firmware` 技能使用。本页只放**能直接抄的命令**和**真会卡住的坑**。

## 1. binwalk 提取后"卡在中间层"

**症状**：`binwalk -e fw.bin` 跑完，目录里只有 `120200.squashfs` / `xxx.cpio` / `yyy.gz`，没有 `rootfs/`。

**原因**：binwalk 只**按签名切分**出内嵌文件，**不会解文件系统**（squashfs 是文件系统不是压缩包）。切出来的 `.squashfs` 必须自己再解。

```bash
unsquashfs -s 120200.squashfs        # 先看压缩算法/版本，决定参数
unsquashfs -d rootfs 120200.squashfs # 默认解
# 若报 "unsupported compression" / "Can't find a valid SQUASHFS superblock"：
unsquashfs -comp lzma -d rootfs 120200.squashfs    # 固件常用 lzma
unsquashfs -comp xz   -d rootfs 120200.squashfs
# 老/魔改 squashfs（4.0 变体、vendor 改过）→ sasquatch
sasquatch -d rootfs 120200.squashfs
```

**兜底**：`unsquashfs` 全试完还不行 → `dd if=120200.squashfs of=part.bin bs=1 skip=<偏移>` 手动定界，或直接上 `binwalk -Me`（递归）再试。

## 2. 熵图判加密

```bash
binwalk -E fw.bin            # 生成熵图 PNG
```
- 一段**平坦高熵**（接近 1.0 且很长）= 加密数据或已压缩数据
- 若该段前有解密代码 → 先去逆解密拿 key，解完再 `binwalk` 才不会漏
- 全文件都高熵 → 整个镜像被加密（少见，通常带头部明文）

## 3. squashfs 之外的常见文件系统

```bash
# JFFS2（NAND/NOR，魔数 0x1985）
jefferson -d rootfs file.jffs2

# UBI/UBIFS（魔数 "UBI#"）
ubireader_extract_images fw.bin         # 先抽 UBI 卷
ubireader_extract_files -o out ubi.img  # 再抽文件

# cramfs（魔数 0x28cd3d45）
cramfsck -x rootfs file.cramfs

# initramfs/cpio（gzip 解开后是 ASCII "070701"）
mkdir rootfs && cd rootfs && cpio -idmv < ../initramfs.cpio

# yaffs2（裸 NAND dump）
unyaffs nand.bin
```

## 4. QEMU 仿真：三种粒度

### 粒度 A：直接跑单个程序（CTF 最常用）
```bash
readelf -h ./target | grep Machine     # 先确认架构 + 字节序
# ARM 32：
qemu-arm ./target
# MIPS 小端（路由常见）：
qemu-mipsel ./target
# MIPS 大端：
qemu-mips ./target
# 需要动态库但宿主没有 → 用 static 版 + chroot 到 rootfs
cp /usr/bin/qemu-arm-static ./rootfs/
sudo chroot ./rootfs ./qemu-arm-static -L . ./bin/target
```
**坑**：`No such file or directory` 通常**不是**程序不存在，而是**找不到对应架构的 ld.so / 动态库** → 加 `-L <rootfs路径>` 或换 `-static` 版。

### 粒度 B：chroot + qemu-user 跑整套用户态
```bash
sudo apt install qemu-user-static binfmt-support
cp $(which qemu-arm-static) ./rootfs/usr/bin/
sudo chroot ./rootfs /usr/bin/qemu-arm-static -L . /bin/sh
# 进入后用固件自己的 busybox/sh 跑它的启动脚本
```

### 粒度 C：全系统仿真（firmadyne / FAT）
```bash
# FAT = firmware-analysis-toolkit，封装了 firmadyne
sudo ./fat.py firmware.bin
# 它会：识别架构 → 提取 → 造镜像 → 起 qemu → 尝试推断网络/登录
```
**常见失败与对策**：
| 症状 | 原因 | 对策 |
|---|---|---|
| 内核 panic / 起不来 | 内核与 QEMU 不匹配 | 换 FAT 的内核，或手动指定 `-kernel` |
| 卡在解压 rootfs | 非标准压缩 | 先手动 `unsquashfs` 解出再喂给仿真 |
| 起来但网络不通 | NVRAM 缺失/网卡配置不对 | 补 NVRAM（很多固件启动时读 `nvram` 变量）|
| 服务不监听 | 依赖硬件线程/看门狗 | user-mode 单独跑那个二进制更实际 |

## 5. rootfs 找目标的命令清单（抄了就用）

```bash
# 启动脚本里的后门/监听
grep -rniE "telnetd|nc |/bin/sh|listen|backdoor|debug" rootfs/etc/init.d rootfs/etc/rc* 2>/dev/null

# 全局敏感词
grep -rniE "flag\{|password|passwd|secret|admin|root:" rootfs/ 2>/dev/null | head -50

# /etc/shadow 口令格式 → 爆破模式
grep -E '^\w+:' rootfs/etc/shadow
#   $1$ = MD5-crypt  → hashcat -m 500
#   $5$ = SHA256-crypt → hashcat -m 7400
#   $6$ = SHA512-crypt → hashcat -m 1800
#   明文/空 = 直接就是口令

# 找厂商自定义二进制（非 busybox/standard）
find rootfs -type f -exec file {} \; 2>/dev/null | grep -iE "ELF.*(ARM|MIPS|AArch64)"
```

## 6. 两个真实的卡点（FreeBuf 案例沉淀）

1. **二次提取**：binwalk 出来 `.squashfs` 后必须 `unsquashfs` 再解一次，别以为 binwalk 一步到位。
2. **符号 ≠ 字符串**：搜 `rootPasswd` / `passWd.c` 这类**符号名**，在 `Strings` 视图和内存 hex 里都找不到——它们不是字符串常量，是**编译期符号**。要打开 IDA 的 **`View → Open subviews → Names`**（Shift+F4）在符号表里找。**字符串搜不到，立刻换 Names 视图**。
