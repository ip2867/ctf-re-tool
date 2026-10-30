// 多文件选择回归（select-file multi + 材料摘要）
//
// 用户需求：
//   "这里打开时，可以添加多个文件，交给ai去利用"
//   "要给ai加一个读取多个文件，然后去分析哪一些是提示，哪一些是做题要求反汇编的能力"
//
// 对应改动：
//   ① select-file 支持 multiSelections，多选返回数组
//   ② 多选后先 file_digest 摘要全部材料，再挑主文件深入分析
//   ③ 非主文件登记为伴生材料，AI 可 read_file 取全文
//   ④ 消息里给多个路径时全部返回，不替 AI 挑
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const mainSrc = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const preSrc = fs.readFileSync(path.join(ROOT, 'electron', 'preload.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'src', 'js', 'app.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, m, d) => {
  if (c) { pass++; console.log('  OK   ' + m); }
  else { fail++; console.log('  FAIL ' + m + (d ? '  -> ' + d : '')); }
};

console.log('[1] 对话框支持多选');
{
  ok(/multiSelections/.test(mainSrc), 'showOpenDialog 带 multiSelections');
  ok(/wantMulti/.test(mainSrc), '有 multi 开关');
  ok(/wantMulti \? result\.filePaths : result\.filePaths\[0\]/.test(mainSrc),
    '多选返回数组、单选返回字符串（向后兼容）');
  // 过滤器里应当包含题目材料的常见类型（不只是可执行）
  ok(/docx/.test(mainSrc) && /pdf/.test(mainSrc), '文件过滤器含 docx/pdf 等材料类型');
  ok(/sys/.test(mainSrc), '过滤器含 .sys（驱动题）');
}

console.log('\n[2] preload 透传 multi 与 fileDigest');
{
  ok(/selectFile:\s*\(filters, multi\)/.test(preSrc), 'selectFile 接受 multi 参数');
  ok(/fileDigest:/.test(preSrc), 'preload 暴露 fileDigest');
  ok(/file-digest/.test(mainSrc), 'main 有 file-digest handler');
}

console.log('\n[3] 渲染层：多选 → 摘要全部 → 挑主文件');
{
  ok(/handleSelectFile/.test(appSrc), '有 handleSelectFile');
  ok(/selectFile\(null, true\)/.test(appSrc), '调用时开启多选');
  ok(/Array\.isArray\(picked\)/.test(appSrc), '兼容数组返回');
  ok(/fileDigest\(paths\)/.test(appSrc), '多选后调用 fileDigest');
  // 必须把材料内容放进对话（直接给 AI 看题面）
  ok(/已读入 .* 个材料/.test(appSrc), '把材料内容作为系统消息注入');
  ok(/先判断哪些是题面/.test(appSrc), '明确要求 AI 自己判断哪个是题面');
  // 主文件按"二进制优先、文档垫底"挑
  ok(/it\.kind === 'binary'\) s \+= 20/.test(appSrc), '二进制优先');
  ok(/\['docx', 'xlsx', 'pptx', 'pdf'\]\.includes\(it\.kind\)\) s -= 10/.test(appSrc),
    '文档垫底');
  // 非主文件要登记成伴生材料
  ok(/_platformFiles = others/.test(appSrc), '伴生材料登记到 _platformFiles');
}

console.log('\n[4] 消息里多个路径：全部返回，不替 AI 挑');
{
  ok(/existingFiles/.test(mainSrc), '收集所有存在的文件路径');
  ok(/files: existingFiles\.length \? existingFiles : \[hit\.p\]/.test(mainSrc),
    '返回 files 数组而非单一路径');
  ok(/siblings:/.test(mainSrc), '同时返回同目录其它文件');
}

console.log('\n[5] 真实场景模拟：驱动 + docx 题面');
{
  // 用测试内构造的文件验证"挑主文件"的排序规则
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ctfmulti-'));
  const drv = path.join(TMP, 'DancingKeys.sys');
  const doc = path.join(TMP, '题面（必须给出）.docx');
  const txt = path.join(TMP, 'note.txt');
  // .sys：PE 头 + 填充
  fs.writeFileSync(drv, Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(4096, 0x90)]));
  fs.writeFileSync(doc, 'fake docx');
  fs.writeFileSync(txt, 'flag 格式 bytectf{...}');

  const { digestMany } = require(path.join(ROOT, 'electron', 'file-digest.js'));
  const r = digestMany([drv, doc, txt], { skipArtifacts: false });
  ok(r.items.length === 3, '3 个都参与摘要', String(r.items.length));

  // 复刻渲染层的排序规则，验证 .sys 排第一
  const score = (it) => {
    const n = String(it.name || '').toLowerCase();
    let s = 0;
    if (it.kind === 'binary') s += 20;
    else if (it.kind === 'text') s += 8;
    else if (it.kind === 'archive') s += 4;
    else if (['docx', 'xlsx', 'pptx', 'pdf'].includes(it.kind)) s -= 10;
    else if (it.kind === 'image') s -= 6;
    if (/\.(apk|exe|dll|sys|elf|so|out|bin|pyc|dex|wasm)$/.test(n)) s += 10;
    if (/\.(txt|md|docx?|pdf|png|jpg)$/.test(n)) s -= 5;
    return s;
  };
  const ranked = r.items.filter(i => i.ok).sort((a, b) => score(b) - score(a));
  ok(ranked[0].name === 'DancingKeys.sys', '主分析目标挑中 .sys', ranked[0].name);
  ok(ranked.some(x => x.name === 'note.txt'), 'note.txt 也在材料里（不丢信息）');

  fs.rmSync(TMP, { recursive: true, force: true });
}

console.log('\n[6] 单文件仍走原路径（不能因多选改动破坏原有流程）');
{
  ok(/if \(paths\.length === 1\) \{[\s\S]{0,80}await analyzeFile\(paths\[0\]\)/.test(appSrc),
    '单选仍直接 analyzeFile');
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
