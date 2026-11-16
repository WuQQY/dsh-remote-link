/**
 * HTTP 小工具：插件里到处都是「回一段 JSON」，抽出来免得每处各写一遍。
 *
 * 不引宿主内部包：插件的 `import` 只有 node: 与自己的文件，跨版本才不会被别人的重构带崩。
 */

/** 回一段 JSON，带上该有的头。`no-store` 是刻意：这些都是本机实时状态。 */
export function sendJson(res, status, payload) {
  const text = JSON.stringify(payload);
  try {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(text),
    });
    res.end(text);
  } catch { /* 客户端已经断开 */ }
}

/** 读请求体（限长），解析成 JSON；失败回 undefined。 */
export function readJsonBody(req, limit = 64 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    const done = (value) => resolve(value);
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { req.destroy(); done(undefined); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return done(undefined);
      try { done(JSON.parse(raw)); } catch { done(undefined); }
    });
    req.on('error', () => done(undefined));
  });
}

/** 回一段 HTML（登录页用）。 */
export function sendHtml(res, status, html) {
  try {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(html),
    });
    res.end(html);
  } catch { /* 已断开 */ }
}
