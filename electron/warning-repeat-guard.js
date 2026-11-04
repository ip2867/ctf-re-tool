'use strict';
// 「同一类告警反复出现」的升级器。
//
// 为什么需要（真实事故 elfstudy，2026-10-31）：
//   `[IDA] 越界地址 44/159 个不在映像内` 与 `[花指令探测] 0.52% 高度可疑`
//   各出现了 **6 次**（03:09 / 03:12 / 03:48 / 04:11 / 04:14 / 04:25）。
//   每一次 AI 重开分析都重新踩同一个坑，因为它把「又看到这条警告」当成
//   「环境还没准备好」，而不是「上次的修复没生效，该换前提」。
//
// 现有的 FailureLoopGuard 只管**工具调用失败**（按 tool+errorCategory 计数），
// 管不到这种情况：那些工具调用全都"成功"了，告警是日志级的。
//
// 本模块的做法：
//   1. 把 warning/error 日志文本归一成"告警类别"（去掉数字/地址/路径等易变部分）
//   2. 同类第 2 次 → 产出 advisory（提醒比较前后两次，别重试）
//   3. 同类第 3 次 → tripped，调用方应**强制换前提**（而不是再试一次）

/** 把一条日志归一成稳定的类别键 */
function normalizeWarningKey(text) {
  let s = String(text == null ? '' : text);
  // 去掉方括号前缀里的具体值（保留标签）
  s = s.replace(/\[\s*([^\]]*?)\s*\]/g, (m, inner) => {
    // 保留形如 [IDA] / [花指令探测] 的标签，但把内部的数字/地址抹掉
    return '[' + inner.replace(/0x[0-9a-f]+/gi, '0x?').replace(/\d+/g, '?') + ']';
  });
  // 抹掉地址、数字、路径
  s = s.replace(/0x[0-9a-f]+/gi, '0x?');
  s = s.replace(/\d+(\.\d+)?/g, '?');
  s = s.replace(/[A-Za-z]:\\[^\s，。；]*/g, '<path>');
  // ⚠️ 去掉**尾部括号里的补充信息**：同一个告警常有两种写法——
  //   `[IDA] 越界地址 44/159 个不在映像内（ImageBase=0x0, SizeOfImage=0x1b330）`
  //   `[IDA] 越界地址 43/43 个不在映像内`
  // 它们是同一类问题，若不归一就会各算一份计数，导致"6 次重复"检测不出来
  // （实测 elfstudy 的时间线里两种写法都有）。
  s = s.replace(/\s*[（(][^（()）]*[)）]\s*$/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  // 只取前 120 字符作为键（后面的细节不值钱）
  return s.slice(0, 120);
}

class WarningRepeatGuard {
  /**
   * @param {object} opts { adviseAt=2, tripAt=3, maxKeys=200 }
   */
  constructor(opts) {
    const o = opts || {};
    this.adviseAt = Number(o.adviseAt) > 0 ? Number(o.adviseAt) : 2;
    this.tripAt = Number(o.tripAt) > 0 ? Number(o.tripAt) : 3;
    this.maxKeys = Number(o.maxKeys) > 0 ? Number(o.maxKeys) : 200;
    this.counts = new Map();     // key -> {n, sample, firstTs}
    this.advisories = [];
    this.tripped = new Set();    // 已升级过的 key，避免重复刷屏
  }

  /**
   * 记录一条日志。只对 warning / error 生效。
   * @param {string} level
   * @param {string} text
   * @returns {{repeat:number, key:string, advisory?:string, tripped?:boolean}}
   */
  record(level, text) {
    const lv = String(level || '').toLowerCase();
    if (lv !== 'warning' && lv !== 'error') return { repeat: 0, key: '' };
    const key = normalizeWarningKey(text);
    if (!key) return { repeat: 0, key: '' };

    let ent = this.counts.get(key);
    if (!ent) {
      if (this.counts.size >= this.maxKeys) {
        // 容量保护：删掉最早的一批，避免无限增长
        const firstKey = this.counts.keys().next().value;
        this.counts.delete(firstKey);
      }
      ent = { n: 0, sample: String(text).slice(0, 300), firstTs: Date.now() };
      this.counts.set(key, ent);
    }
    ent.n++;

    const repeat = ent.n;
    if (repeat >= this.tripAt && !this.tripped.has(key)) {
      this.tripped.add(key);
      const advisory = `### ⛔ 同一告警已出现 ${repeat} 次，停止重试\n`
        + `这条告警在本次会话中已重复 ${repeat} 次：\n\`${ent.sample}\`\n\n`
        + `**重复出现 = 上次的处理没有生效**。不要再"重开分析/再试一次"——\n`
        + `请按以下顺序换前提：\n`
        + `1. **判断这是不是"结果"而不是"原因"**：告警描述的现象（跳转非对齐、函数越界、\n`
        + `   反编译错位）往往由更上游的问题引起（IDA 基址错、函数表坏、逻辑不在函数里）。\n`
        + `2. **换一类工具取证**：不要继续在同一个表象上做修补。用 elf_anomaly / scan_crypto /\n`
        + `   strings+xrefs / blob_decrypt 从另一个角度拿确定性事实。\n`
        + `3. **明确写出"当前假设已排除"**，并说明排除了什么证据。\n`
        + `4. 若确实是环境问题（如 IDA 实例串台），用 ida_open_file 重开 + new_database=true\n`
        + `   重建 IDB，而不是对着旧库反复操作。`;
      this.advisories.push(advisory);
      return { repeat, key, advisory, tripped: true };
    }
    if (repeat === this.adviseAt) {
      const advisory = `⚠ 同类告警第 ${repeat} 次出现（${key.slice(0, 60)}…）。`
        + `再出现一次将要求换前提——先检查上一次的处理是否真的生效了。`;
      this.advisories.push(advisory);
      return { repeat, key, advisory };
    }
    return { repeat, key };
  }

  takeAdvisories() {
    const out = this.advisories.slice();
    this.advisories.length = 0;
    return out;
  }

  /** 供测试/诊断：返回重复次数 ≥2 的告警清单 */
  topRepeats(min = 2) {
    return [...this.counts.entries()]
      .filter(([, v]) => v.n >= min)
      .map(([k, v]) => ({ key: k, count: v.n, sample: v.sample }))
      .sort((a, b) => b.count - a.count);
  }

  reset() {
    this.counts.clear();
    this.advisories.length = 0;
    this.tripped.clear();
  }
}

module.exports = { WarningRepeatGuard, normalizeWarningKey };
