// 载荷提取脚本生成器的测试入口。
//
// ⚠️ 这个文件以前是"从 app.js 抽源码"跑测试：
//     const src = fs.readFileSync('src/js/app.js');
//     const body = src.slice(start, end);   // 抽出 buildPayloadExtractPython
//     new Function(...)(body)
//   后果：**测的根本不是生产代码**。渲染层那份即使和主进程不一致也测不出来，
//   而主进程当时压根没有这个函数（extract_payload 100% 抛 ReferenceError），
//   测试却全绿——这正是那个 bug 能潜伏一整轮的原因。
//
// 现在实现只有一份（electron/payload-extract.js），测试直接 require 它。
module.exports = require('../electron/payload-extract.js');
