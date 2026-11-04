'use strict';
// RISC-V / 跨架构固件的**动态取值**脚本生成器（纯函数）。
//
// 为什么需要（实测 qwb2026 firmware）：fw_b.bin 是 RISC-V32 固件，
// 它在启动时把 .text 的 SM3 原地变换成派生材料，只在内存里存在、不落盘。
// 静态读只能拿到变换**前**的值（.selfhash），必须跟到函数返回点取变换**后**的缓冲区。
//
// 实测可行链路（Kali）：
//   1. qemu-riscv32 -g <port> ./fw_b.bin   ← 起单步调试桩
//   2. gdb-multiarch + set architecture riscv:rv32 + target remote
//   3. break *<返回地址>; continue
//   4. info registers <buf_reg>; x/Nxb $<buf_reg>
//
// 关键环境事实（实测）：
//   · Kali 上 qemu-riscv32 / qemu-riscv64 / gdb-multiarch **都已安装**
//   · **capstone 是 4.0.0，不支持 RISC-V**（CS_ARCH_RISCV 从 5.0 才有）→ 反汇编必须用 gdb-multiarch
//   · 宿主 objdump 也不带 RISC-V 后端 → 同样用 gdb-multiarch
//
// 本模块只生成**脚本**，不自己执行：执行交给 remote_exec（host=kali），
// 这样不引入 SSH 依赖，也便于 AI 看到中间过程。

/**
 * 生成"反汇编找调用点"的 bash 脚本。
 * 用 gdb-multiarch 反汇编整段 .text，grep 出 `jal <目标>`，并打印其后几行（含返回地址）。
 *
 * @param {object} o { remoteDir, binName, target, textStart, textEnd }
 */
function buildFindCallSiteScript(o) {
  const d = o.remoteDir || '/tmp/fwprobe';
  const bin = o.binName || 'firmware.bin';
  const tgt = o.target || '0x10818';
  const ts = o.textStart || '0x100b4';
  const te = o.textEnd || '0x1090e';
  return `#!/bin/bash
# 由 ctf-tool 生成：在 RISC-V 固件里找"谁调用了 ${tgt}"
set -u
cd ${d} || exit 2
echo "=== 反汇编 ${ts}..${te}，找 jal ${tgt} ==="
gdb-multiarch -q -batch -nx \\
  -ex "set architecture riscv:rv32" \\
  -ex "file ${bin}" \\
  -ex "disassemble /r ${ts},${te}" 2>/dev/null > /tmp/fwprobe_disasm.txt
# 先把反汇编落到临时文件再处理：管道里 awk 拿不到"后面几行"（流式读，NR+k 还没到）
awk -v t="${tgt}" '
  { a[NR] = $0 }
  END {
    found = 0
    for (i = 1; i <= NR; i++) {
      if (a[i] ~ /jal/ && index(a[i], t) > 0) {
        found++
        print "调用点: " a[i]
        print "  之后的指令（第一行就是返回地址）:"
        for (k = 1; k <= 4 && (i + k) <= NR; k++) print "   " a[i + k]
        print ""
      }
    }
    if (!found) print "（未找到对 " t " 的 jal 调用 —— 可能不是 jal 而是 jalr/间接调用）"
  }
' /tmp/fwprobe_disasm.txt
echo "=== 静态反汇编完 ==="
`;
}

/**
 * 生成"起 qemu + gdb 断点 + 读缓冲区"的 bash 脚本。
 *
 * @param {object} o {
 *   remoteDir, binName, port=1234,
 *   breakAddr,         // 断点地址（通常是 0x10818 的返回点）
 *   bufReg='s2',       // 缓冲区指针所在的寄存器
 *   readBytes=32,      // 读多少字节
 *   cmpAddr,           // 可选：对照地址（如 .selfhash），一起 dump
 *   extraCmds=[]       // 可选：额外 gdb 命令
 * }
 */
function buildRiscvProbeScript(o) {
  const d = o.remoteDir || '/tmp/fwprobe';
  const bin = o.binName || 'firmware.bin';
  const port = Number(o.port) || 1234;
  const brk = o.breakAddr || '0x103fc';
  const reg = o.bufReg || 's2';
  const n = Number(o.readBytes) || 32;
  const cmp = o.cmpAddr || '';
  const extra = Array.isArray(o.extraCmds) ? o.extraCmds : [];

  const gdbEx = [
    '-ex "set architecture riscv:rv32"',
    `-ex "file ${bin}"`,
    `-ex "target remote :${port}"`,
    `-ex "break *${brk}"`,
    '-ex "continue"',
    `-ex "printf \\"=== HIT ${brk} ===\\\\n\\""`,
    `-ex "info registers ${reg} pc ra sp"`,
    // ⚠️ gdb 的寄存器引用要写成 $s2，但这段最终在 bash 双引号里执行 ——
    // 不转义的话 bash 会先把 $s2 当自己的变量展开（配合 set -u 直接报"未绑定的变量"）。
    // 实测踩过：必须写成 \$s2，让 bash 原样传给 gdb。
    `-ex "printf \\"=== buffer @ \\$${reg} (${n} bytes) ===\\\\n\\""`,
    `-ex "x/${n}xb \\$${reg}"`,
    ...(cmp ? [`-ex "printf \\"=== compare @ ${cmp} ===\\\\n\\""`, `-ex "x/${n}xb ${cmp}"`] : []),
    ...extra.map((c) => `-ex "${c}"`),
    '-ex "detach"',
    '-ex "quit"',
  ].join(' \\\n    ');

  return `#!/bin/bash
# 由 ctf-tool 生成：用 qemu + gdb 在 RISC-V 固件里断点读派生材料
#
# 为什么必须动态取：这类固件在启动时把常量原地变换，变换结果只在内存里，
# 静态读 .selfhash 只能拿到变换前的值。
set -u
cd ${d} || exit 2

PORT=${port}
BIN=${bin}

# 端口占用检查（避免上一次的 qemu 还活着）
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":\${PORT} "; then
  echo "[warn] 端口 \${PORT} 已被占用，尝试清理旧 qemu"
  pkill -f "qemu-riscv32 -g \${PORT}" 2>/dev/null || true
  sleep 1
fi

# 起 qemu（-g 让它等待 gdb 连接，不立即执行）
qemu-riscv32 -g "\${PORT}" "./\${BIN}" >/tmp/fwprobe_qemu.log 2>&1 &
QEMU_PID=$!
sleep 1.5

if ! kill -0 "\${QEMU_PID}" 2>/dev/null; then
  echo "[error] qemu 没起来，日志："
  cat /tmp/fwprobe_qemu.log
  exit 3
fi

echo "=== qemu-riscv32 pid=\${QEMU_PID} listening on :\${PORT} ==="

gdb-multiarch -q -batch -nx \\
    ${gdbEx}

RC=$?
kill "\${QEMU_PID}" 2>/dev/null || true
wait "\${QEMU_PID}" 2>/dev/null || true

echo "=== qemu 侧输出 ==="
cat /tmp/fwprobe_qemu.log 2>/dev/null
exit \${RC}
`;
}

/**
 * 从 gdb 的 `x/32xb` 输出里解析出字节串。
 * 形如：`0x2b2abbc0:\t0xdd\t0x97\t0xcb ...`
 *
 * ⚠️ 必须按「连续地址块」切分：一次输出里可能有多个不同地址的 dump
 * （缓冲区 + cmpAddr 对照段），全揉成一串会把两段拼在一起（实测踩过：
 * 32 字节缓冲区 + 32 字节对照 → 解析出 64 字节的错误结果）。
 *
 * @param {string} text
 * @param {object} [opts] { maxBlocks } 返回前几个块
 * @returns {{blocks:Array<{addr:string,bytes:number[],hex:string}>, hex:string, bytes:number[], addr:string}}
 */
function parseGdbXOutput(text, opts) {
  const o = opts || {};
  const lines = String(text || '').split('\n');
  const blocks = [];
  let cur = null;
  const flush = () => {
    if (cur && cur.bytes.length) blocks.push(cur);
    cur = null;
  };
  for (const l of lines) {
    const m = l.match(/^\s*(0x[0-9a-f]+):\s*(.+)$/i);
    if (!m) {
      // 遇到非 dump 行就结束当前块（例如 "=== compare ===" 分隔）
      if (cur) flush();
      continue;
    }
    const addr = m[1].toLowerCase();
    // 地址不连续 → 新块（gdb 每行 8/16 字节，间距 8/16）
    if (cur) {
      const prevEnd = parseInt(cur.addr, 16) + cur.bytes.length;
      if (parseInt(addr, 16) !== prevEnd) flush();
    }
    if (!cur) cur = { addr, bytes: [] };
    const hexBytes = m[2].match(/0x[0-9a-f]{1,2}\b/gi) || [];
    for (const h of hexBytes) cur.bytes.push(parseInt(h, 16) & 0xff);
  }
  flush();
  const limit = Number(o.maxBlocks) > 0 ? Number(o.maxBlocks) : blocks.length;
  const picked = blocks.slice(0, limit).map((b) => ({
    addr: b.addr,
    bytes: b.bytes,
    hex: Buffer.from(b.bytes).toString('hex'),
  }));
  const first = picked[0] || { addr: '', bytes: [], hex: '' };
  return { blocks: picked, hex: first.hex, bytes: first.bytes, addr: first.addr };
}

module.exports = { buildFindCallSiteScript, buildRiscvProbeScript, parseGdbXOutput };
