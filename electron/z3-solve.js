'use strict';

/**
 * z3-solve.js — 符号求解工具
 *
 * 设计：AI 只写「约束代码」（声明符号变量 + s.add(...)），本模块用模板包装成
 * 完整的 z3 求解脚本，交给 run_python 的管道执行，返回结构化 JSON。
 *
 * 为什么这样设计：
 * 1. z3 求解是确定性的：给定约束，sat/unsat/model 可验证。
 * 2. 手写 z3 脚本易踩坑：import 位置、unsat 时 model() 抛异常、退出码 0 但无输出。
 *    模板统一处理这些。
 * 3. 结构化输出（JSON）让 AI 直接可读：status + model + summary。
 *
 * 约束脚本约定（工具自动补全的部分不要重复写）：
 *   - 已提供：from z3 import *、s = Solver()
 *   - 需要写：符号变量声明 + s.add(约束)
 */

/**
 * 构建完整求解脚本
 *
 * @param {string} constraints - AI 写的约束代码
 * @param {object} opts - {timeout}
 * @returns {string} 完整 Python 脚本
 */
function buildZ3SolveScript(constraints, opts) {
  opts = opts || {};
  const timeoutSec = Number(opts.timeout) > 0 ? Number(opts.timeout) : 30;
  const timeoutMs = Math.round(timeoutSec * 1000);

  // 用 base64 传约束代码，杜绝三引号 / 反斜杠 / 缩进 逃逸问题
  const b64 = Buffer.from(String(constraints), 'utf8').toString('base64');

  return `# ─── z3_solve 自动生成的求解脚本（勿手改）───
import sys, json, base64, traceback

try:
    from z3 import *
except ImportError:
    print(json.dumps({
        "status": "error",
        "error": "z3 未安装。请执行 pip install z3-solver 后重试。"
    }, ensure_ascii=False))
    sys.exit(0)

RESULT = {"status": "unknown", "model": {}, "summary": ""}

# 1) 预置执行环境：把 z3 的全部符号（BitVec/Solver/sat/...）注入命名空间
_g = {"__name__": "__main__"}
_g.update({k: v for k, v in globals().items() if not k.startswith("__")})
_g['s'] = Solver()

# 1b) 常用别名：z3 官方是 RotateLeft/RotateRight/LShR（驼峰），
#     但逆题里手写约束时习惯写 rotl/rotr/lshr。这里补上小写别名，
#     避免 AI 写 rotl() 时撞 NameError 白跑一轮。
_g['rotl'] = RotateLeft
_g['rotr'] = RotateRight
_g['lshr'] = LShR
_g['ashr'] = lambda v, n: v >> n
_g['rol'] = RotateLeft
_g['ror'] = RotateRight
_g['zext'] = ZeroExt
_g['sext'] = SignExt
_g['extract'] = Extract

def _bswap8(v):
    return Concat(Extract(7, 0, v), Extract(15, 8, v),
                  Extract(23, 16, v), Extract(31, 24, v))
_g['bswap32'] = _bswap8

# 1c) 查表辅助：把 256 字节常量表变成 z3 表达式（平衡 If 树）。
#     ⚠️ 比较必须用 ULT（无符号）。写 If(v < K, A, B) 时 z3 按有符号比较，
#     索引 >= 0x80 会被当成负数 → 前一半条目全部查错，
#     表现是"明明有解却报 unsat"（实测 128/256 项错）。这是本项目踩过的坑。
def _lookup_expr(var, table, width=8):
    """table: list[(index, value)]，按 index 升序。返回 z3 表达式。"""
    if len(table) == 1:
        return BitVecVal(table[0][1], width)
    mid = len(table) // 2
    return If(ULT(var, BitVecVal(table[mid][0], width)),
              _lookup_expr(var, table[:mid], width),
              _lookup_expr(var, table[mid:], width))
_g['lookup_expr'] = _lookup_expr

_code = base64.b64decode("${b64}").decode("utf-8")

# 2) 执行约束代码
try:
    exec(compile(_code, "<constraints>", "exec"), _g)
except Exception as e:
    print(json.dumps({
        "status": "error",
        "error": "约束代码执行失败: " + str(e),
        "traceback": traceback.format_exc()[-1500:]
    }, ensure_ascii=False))
    sys.exit(0)

s = _g.get("s")
if s is None:
    print(json.dumps({"status": "error", "error": "约束代码里找不到 Solver 实例 s"}, ensure_ascii=False))
    sys.exit(0)

# 3) 求解
try:
    s.set("timeout", ${timeoutMs})
    res = s.check()
    if res == sat:
        m = s.model()
        RESULT["status"] = "sat"
        parts = []
        for decl in m.decls():
            try:
                val = m[decl]
                if hasattr(val, "as_long"):
                    iv = val.as_long()
                    RESULT["model"][str(decl)] = iv
                    if 0 <= iv <= 0xFF:
                        ch = chr(iv) if 32 <= iv < 127 else "."
                        parts.append("%s=%#x(%s)" % (decl, iv, ch))
                    else:
                        parts.append("%s=%#x" % (decl, iv))
                elif hasattr(val, "is_true") and hasattr(val, "is_false"):
                    bv = bool(val.is_true())
                    RESULT["model"][str(decl)] = bv
                    parts.append("%s=%s" % (decl, bv))
                else:
                    RESULT["model"][str(decl)] = str(val)
                    parts.append("%s=%s" % (decl, val))
            except Exception:
                RESULT["model"][str(decl)] = "<unprintable>"
        RESULT["summary"] = ", ".join(parts)
    elif res == unsat:
        RESULT["status"] = "unsat"
        RESULT["summary"] = "约束组无解（检查推导是否自相矛盾）"
    else:
        RESULT["status"] = "unknown"
        RESULT["summary"] = "求解器返回 unknown（超时或不支持的片段）"
except Exception as e:
    RESULT["status"] = "error"
    RESULT["error"] = str(e)
    RESULT["traceback"] = traceback.format_exc()[-1500:]

# 4) 额外：把字节型 model 拼成字符串，便于直接看 flag
try:
    if RESULT["status"] == "sat":
        byte_entries = [(k, v) for k, v in RESULT["model"].items()
                        if isinstance(v, int) and 0 <= v <= 0xFF]
        if len(byte_entries) >= 2:
            # 按变量名里的数字后缀排序（f0,f1,...,f12 自然序）
            import re as _re
            def _key(kv):
                k = kv[0]
                m2 = _re.search(r"(\\d+)$", k)
                return (int(m2.group(1)) if m2 else 10**9, k)
            byte_entries.sort(key=_key)
            bs = bytes(v for _, v in byte_entries)
            RESULT["as_bytes_hex"] = bs.hex()
            RESULT["as_text"] = "".join(chr(b) if 32 <= b < 127 else "." for b in bs)
except Exception:
    pass

print(json.dumps(RESULT, ensure_ascii=False, default=str))
`;
}

module.exports = { buildZ3SolveScript };
