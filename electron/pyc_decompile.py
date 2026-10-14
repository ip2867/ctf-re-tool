#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PYC 反汇编/常量提取助手（多后端、抗高版本、零第三方依赖也能出结果）。

用法:  python pyc_decompile.py <target.pyc>
输出:  分区文本（### META/SOURCE/DISASM/CONSTS/STRINGS ###），供主进程按区解析。

设计动机：CTF 里 .pyc 版本很杂（3.8~3.13），用户配置的单个 pycdc 对高版本常直接报
"Bad MAGIC!" 而失败（实测：Python 3.12 的 .pyc）。本助手给出"尽力而为"的多层回退：
  1) xdis / pydisasm（若已安装）—— 跨版本反汇编 + 常量表
  2) 原生 marshal.loads + dis   —— 当运行版本与 pyc 版本一致时最完整（含递归常量）
  3) 纯字节串扫描               —— 永远可用：可打印串 / GBK 中文 / 长 hex / base64 / 大整数

即使 1、2 全不可用，第 3 层也能给出足够线索（如本题的 base64 密文 + xor 密钥）。
"""
import sys, os, re, marshal, dis, io, subprocess, importlib.util

# 常见 CPython magic（前两字节小端）→ 版本。取主要版本即可，够用。
_MAGIC = {
    3310: "3.4", 3320: "3.5", 3330: "3.5", 3340: "3.5", 3350: "3.6", 3351: "3.6",
    3360: "3.6", 3361: "3.6", 3370: "3.6", 3371: "3.6", 3372: "3.6", 3373: "3.6",
    3375: "3.6", 3376: "3.6", 3377: "3.6", 3378: "3.6", 3379: "3.7", 3390: "3.7",
    3391: "3.7", 3392: "3.7", 3393: "3.7", 3394: "3.7", 3400: "3.8", 3401: "3.8",
    3410: "3.8", 3411: "3.8", 3412: "3.8", 3413: "3.8", 3420: "3.9", 3421: "3.9",
    3422: "3.9", 3423: "3.9", 3424: "3.9", 3425: "3.9", 3430: "3.10", 3431: "3.10",
    3432: "3.10", 3433: "3.10", 3434: "3.10", 3435: "3.10", 3436: "3.10", 3437: "3.10",
    3438: "3.10", 3439: "3.10", 3450: "3.11", 3451: "3.11", 3452: "3.11", 3453: "3.11",
    3454: "3.11", 3455: "3.11", 3456: "3.11", 3495: "3.10", 3500: "3.11", 3530: "3.12",
    3531: "3.12", 3550: "3.13", 3560: "3.13",
}

_TEXT = re.compile(rb"[\x20-\x7e]{4,}")
_B64 = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(rb"[0-9a-fA-F]{16,}")


def detect_version(mv):
    if mv in _MAGIC:
        return _MAGIC[mv]
    # 运行版本自身
    try:
        cur = int.from_bytes(importlib.util.MAGIC_NUMBER[0:2], "little")
        if cur == mv:
            return "%d.%d" % (sys.version_info[0], sys.version_info[1])
    except Exception:
        pass
    # xdis 兜底（有大全表）
    try:
        from xdis.magics import magics
        v = magics.get(bytes([mv & 0xFF, (mv >> 8) & 0xFF]))
        if v:
            return str(v)
    except Exception:
        pass
    return "unknown"


def raw_strings(data):
    """第3层：纯字节串扫描（无依赖，永远可用）。"""
    found = []
    # ASCII 可打印段
    for m in _TEXT.finditer(data):
        found.append(m.group(0).decode("latin-1"))
    # 中文（GBK/UTF-8）段：整段尝试解码
    for enc in ("gbk", "utf-8"):
        try:
            t = data.decode(enc, "ignore")
        except Exception:
            continue
        for m in re.finditer(r"[\u4e00-\u9fff][\u4e00-\u9fff\uff00-\uffef，。！？：、\x20-\x7e]{1,40}", t):
            found.append(("[" + enc + "] " + m.group(0)).strip())
    # 长 hex / base64（常是密钥/密文）
    for rex, tag in ((_HEX, "HEX"), (_B64, "B64")):
        for m in rex.finditer(data):
            found.append(tag + " " + m.group(0).decode("latin-1"))
    # 去重保序
    seen, out = set(), []
    for s in found:
        s = s.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def dump_code(code, indent=0, acc=None):
    """递归 dump 代码对象：反汇编 + 常量。返回常量/名称聚合。"""
    if acc is None:
        acc = {"consts": [], "names": [], "dis": []}
    pad = "  " * indent
    acc["names"].extend([str(n) for n in getattr(code, "co_names", ())])
    buf = io.StringIO()
    try:
        dis.dis(code, file=buf)
    except Exception as e:
        buf.write("(dis failed: %s)\n" % e)
    acc["dis"].append(pad + "== %s(args=%s) ==\n" % (getattr(code, "co_name", "?"),
                                                     list(getattr(code, "co_varnames", ())[:getattr(code, "co_argcount", 0)]))
                      + "\n".join(pad + ln for ln in buf.getvalue().splitlines()))
    for c in getattr(code, "co_consts", ()):
        if hasattr(c, "co_code"):
            acc["consts"].append((pad + "subcode", getattr(c, "co_name", "?")))
            dump_code(c, indent + 1, acc)
        else:
            acc["consts"].append((pad + type(c).__name__, repr(c)))
    return acc


def walk_consts(code, indent=0, acc=None):
    """只递归收集常量/名称（不反汇编）——用于已有 xdis 反汇编时补一份结构化常量表。"""
    if acc is None:
        acc = {"consts": [], "names": []}
    pad = "  " * indent
    acc["names"].extend([str(n) for n in getattr(code, "co_names", ())])
    for c in getattr(code, "co_consts", ()):
        if hasattr(c, "co_code"):
            acc["consts"].append((pad + "subcode", getattr(c, "co_name", "?")))
            walk_consts(c, indent + 1, acc)
        else:
            acc["consts"].append((pad + type(c).__name__, repr(c)))
    return acc


def main():
    if len(sys.argv) < 2:
        print("### META ###\nERR no-input")
        return 2
    path = sys.argv[1]
    if not os.path.exists(path):
        print("### META ###\nERR not-found %s" % path)
        return 2
    data = open(path, "rb").read()

    print("### META ###")
    print("SIZE %d" % len(data))
    if len(data) >= 4:
        mv = int.from_bytes(data[0:2], "little")
        print("MAGIC %s" % data[0:2].hex())
        print("MAGIC_U16 %d" % mv)
        print("PYVER %s" % detect_version(mv))
    print("RUNPY %d.%d.%d" % sys.version_info[:3])

    # 层1：xdis / pydisasm（跨版本反汇编）
    print("### DISASM ###")
    did = False
    try:
        r = subprocess.run([sys.executable, "-m", "xdis.bin.pydisasm", path],
                           capture_output=True, text=True, timeout=60, errors="replace")
        if r.returncode == 0 and len((r.stdout or "").strip()) > 40:
            print("# backend: xdis/pydisasm")
            print(r.stdout)
            did = True
    except Exception:
        pass
    # 层2（补充）：只要本机 Python 能 marshal 加载，就额外做一次**结构化常量表**
    #       （xdis 的输出把常量混在反汇编里，单列一份 CONSTS 让 AI 一眼扫密钥/密文更省力）
    code = None
    for hdr in (16, 12, 8, 0):
        try:
            code = marshal.loads(data[hdr:])
            break
        except Exception:
            code = None
    if code is not None:
        if not did:
            print("# backend: marshal+dis (header=%d)" % hdr)
            acc = dump_code(code)
            for block in acc["dis"]:
                print(block)
            did = True
        else:
            acc = walk_consts(code)
        print("### CONSTS ###")
        for t, v in acc["consts"]:
            print("%s %s" % (t, v))
        if acc["names"]:
            print("# NAMES: " + ", ".join(sorted(set(acc["names"]))))
    else:
        if not did:
            print("(marshal 失败：pyc 版本与本机 Python 不一致；见下方 STRINGS)")

    # 层3：纯字节串扫描（永远执行，作为补充/兜底）
    print("### STRINGS ###")
    for s in raw_strings(data):
        print(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
