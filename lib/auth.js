/**
 * 登录门（网页端）：手机号 + 验证码。
 *
 * 关于「用 DeepSeek 账号登录」：DeepSeek 并**没有**对第三方开放手机号+验证码的登录接口，
 * 硬接等于伪造身份、而且要把你的账号密码喂给一个自建服务。这里做的是**同样的形式**、
 * 但不依赖任何第三方：手机号由你指定，验证码由三种通道之一产生。
 *
 *   通道一 totp（默认，推荐）：验证器 App（Authenticator / 1Password / iOS 密码）里
 *                              每 30 秒变一次的 6 位数字。**人在外面也能用**，不花钱、
 *                              不需要短信、不依赖电脑屏幕。第一次跑会把密钥（二维码 +
 *                              otpauth:// 链接）打印在电脑终端里，扫一次以后永久有效。
 *   通道二 console           ：验证码打印在电脑终端里。适合你就在电脑旁边。
 *
 * 共同规则：只认配置里的那一个手机号；验证码一次性、5 分钟有效（TOTP 是 30 秒窗口 ±1）；
 * 同 IP 限流；错太多次作废；登录态是 HMAC 签名的 HttpOnly cookie，30 天。
 */
import { createHmac, randomInt, timingSafeEqual, randomBytes } from 'node:crypto';
import { currentCode, generateSecret, locateStep, otpauthUrl, secondsRemaining, verifyCode } from './totp.js';
import { sendHtml } from './http.js';

const CODE_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_SENDS_PER_HOUR = 8;
const MAX_TRIES = 8;
/** 错满 MAX_TRIES 后的锁定期；过了这段时间计数自动清零（见 verify 里的衰减）。 */
const RETRY_LOCK_MS = 60 * 1000;
const SESSION_DAYS = 30;

const COOKIE = 'dshlink_sid';

function hmac(key, text) {
  return createHmac('sha256', key).update(text).digest('base64url');
}

function equal(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

/** 抹掉中间四位：日志与界面回显都不出现完整号码。 */
export function maskPhone(phone) {
  const s = String(phone || '');
  return s.length >= 7 ? `${s.slice(0, 3)}****${s.slice(-4)}` : s;
}

function consoleSender(log) {
  return async (phone, code) => {
    log('');
    log('==================== 登录验证码 ====================');
    log(`  手机号  ${maskPhone(phone)}`);
    log(`  验证码  ${code}    （5 分钟内有效，只能用一次）`);
    log('====================================================');
    log('');
    return { ok: true };
  };
}

export function createAuth(options) {
  const state = options.state;
  const log = options.log || ((m) => console.log(m));
  const phone = String(options.phone || state.loginPhone || '').trim();
  const channel = String(options.channel || state.loginChannel || 'totp');
  if (!/^1[3-9]\d{9}$/.test(phone)) {
    throw new Error('还没配置登录手机号：请在 DSH 设置 → 远程链接 中填写，或在插件配置里指定');
  }
  if (!['totp', 'console'].includes(channel)) {
    throw new Error(`不认识的验证码通道：${channel}（可选 totp / console）`);
  }
  state.loginPhone = phone;
  state.loginChannel = channel;

  // ── TOTP 密钥：第一次生成，之后一直复用（手机上的验证器已经加过它） ──────────
  const totpIsNew = !state.totpSecret;
  if (totpIsNew) state.totpSecret = generateSecret();
  const totpSecret = state.totpSecret;

  // ── 会话签名密钥 ────────────────────────────────────────────────────────
  if (!state.loginSecret) state.loginSecret = randomBytes(32).toString('base64url');
  const secret = Buffer.from(state.loginSecret, 'base64url');

  const send = consoleSender(log);

  const pending = new Map(); // 手机号 → { code, expiresAt }
  const limits = new Map();  // key = stable local bridge identity / phone; 不信任客户端的转发 IP 头
  const lastUsedSteps = new Set(); // 成功使用过的 TOTP 时间片，防止同一动态码重放
  const replayKey = (step) => `${phone}:${step}`;
  /**
   * 已被「退出」作废的会话 id。
   *
   * 会话本身是无状态 HMAC 签名，签名有效就永久有效 —— 那样「退出」只能清掉浏览器那一侧
   * 的 cookie，服务端其实还认。这里补一张吊销名单：退出时把 jti 记进来，之后同一个 cookie
   * 再来就不放行。名单只在内存里（重启即清空），这与「关掉 DSH 就等于全部下线」是一致的。
   */
  const revoked = new Set();

  const issueSession = () => {
    const issuedAt = Date.now();
    const expiresAt = issuedAt + SESSION_DAYS * 86400e3;
    const jti = randomBytes(9).toString('base64url');
    const body = Buffer.from(JSON.stringify({ sub: phone, issuedAt, expiresAt, jti })).toString('base64url');
    return `v1.${body}.${hmac(secret, body)}`;
  };

  const verifySession = (value) => {
    const parts = String(value || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    const [, body, sig] = parts;
    if (!equal(sig, hmac(secret, body))) return null;
    let payload;
    try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return null; }
    if (payload?.sub !== phone) return null;
    if (!(payload.expiresAt > Date.now())) return null;
    if (payload.jti && revoked.has(payload.jti)) return null;
    return payload;
  };

  /**
   * 作废某一枚会话（退出时用）。返回是否真的吊销了。
   *
   * 必须先验签再吊销：`/__logout` 在登录检查之前处理，任何访客都能带着自造的 cookie 打进来。
   * 若这里只 base64url 解出 jti 就加进名单，攻击者无需签名密钥即可：
   *   · 伪造任意 jti 灌满 200 条上限，把真实要吊销的 jti 冲出去（吊销名单 FIFO 淘汰）；
   *   · 若已知某枚合法 cookie 的 jti，直接让受害者会话失效。
   * 签名算法与 verifySession 保持一致，验不过就不碰名单。
   */
  const revokeSession = (value) => {
    const parts = String(value || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return false;
    const [, body, sig] = parts;
    if (!equal(sig, hmac(secret, body))) return false;
    try {
      const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (!payload?.jti || payload?.sub !== phone) return false;
      revoked.add(payload.jti);
      // 只留最近 200 条，避免长期运行无限增长
      if (revoked.size > 200) revoked.delete(revoked.values().next().value);
      return true;
    } catch { return false; }
  };

    const safeNext = (value) => {
      if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return '/';
      if (/[\\\u0000-\u0020]/.test(value)) return '/';
      try {
        const parsed = new URL(value, 'https://dsh.local');
        if (parsed.origin !== 'https://dsh.local') return '/';
      } catch { return '/'; }
      return value;
    };

  const cookieOf = (req) => {
    for (const seg of String(req.headers.cookie || '').split(';')) {
      const at = seg.indexOf('=');
      if (at === -1) continue;
      if (seg.slice(0, at).trim() === COOKIE) return seg.slice(at + 1).trim();
    }
    return '';
  };

  const clientIp = (req) => {
    // 桥接本身只监听回环，外部头都由客户端控制，不能拿来做限流键。
    // 以手机号为主键，附带 socket 地址作为未来多实例宿主的区分；当前桥接通常都是 127.0.0.1。
    return `${phone}|${String(req.socket?.remoteAddress || 'local')}`;
  };

  function limitOf(ip) {
    let entry = limits.get(ip);
    if (!entry) { entry = { sends: [], tries: 0, lastSendAt: 0, lastTryAt: 0 }; limits.set(ip, entry); }
    return entry;
  }

  function json(res, status, body) {
    const text = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
    res.end(text);
  }

  async function readBody(req, max = 8 * 1024) {
    return new Promise((resolve) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > max) { req.destroy(); resolve({}); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); }
      });
      req.on('error', () => resolve({}));
    });
  }

  /** 首次启动时把 TOTP 密钥交给用户：终端里打印 otpauth 链接 + 二维码 + 当前验证码。 */
  async function announceTotp(showQr) {
    const url = otpauthUrl({ secret: totpSecret, account: `${maskPhone(phone)}@dsh` });
    log('');
    log('=========== 一次性设置：把登录器加进手机（只做这一次）===========');
    log('  手机装任意验证器 App，都行：');
    log('    · iOS 自带「密码」App → 密码 → ＋ → 扫二维码');
    log('    · Google Authenticator / 微软 Authenticator / 1Password / Authy');
    log('');
    if (typeof showQr === 'function') {
      log('  用手机相机或验证器 App 扫下面这个码：');
      log('');
      try { await showQr(url); } catch { /* 二维码失败就退回手输 */ }
    }
    log('');
    log('  扫不了码，就手输这串密钥（大写字母数字，空格不算）：');
    log(`     ${totpSecret}`);
    log('');
    log('  或者在自己的电脑上打开这条 otpauth 链接导入：');
    log(`     ${url}`);
    log('');
    log(`  现在手机上的 6 位数字应该是：${currentCode(totpSecret)}（${secondsRemaining()} 秒后变）`);
    log('  加好之后，以后任何时候打开网页，看一眼手机就能登录，不用发短信、不用在电脑旁边。');
    log('  这串密钥只存在本机 ~/.dsh/remote-link.json —— 别截图发给别人。');
    log('============================================================');
    log('');
  }

  /**
   * 处理一条请求：返回 'pass' 放行给 DSH，返回 'handled' 表示已经答完。
   */
  async function handle(req, res, url) {
    // 退出必须放在「已登录就放行」之前：否则带 cookie 的 /__logout 会被当成普通请求转给 DSH。
    if (req.method === 'POST' && url.pathname === '/__logout') {
      // 先吊销服务端这一枚，再清浏览器 cookie —— 只清 cookie 的话，
      // 已经泄露出去的那份 cookie 还能继续用（签名是无状态的）。
      revokeSession(cookieOf(req));
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'set-cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
      });
      res.end(JSON.stringify({ ok: true }));
      return 'handled';
    }

    if (verifySession(cookieOf(req))) return 'pass';

    if (req.method === 'GET' && (url.pathname === '/__login' || url.pathname === '/__login/')) {
      const html = loginPage({
        channel,
        maskedPhone: maskPhone(phone),
        next: url.searchParams.get('next') || '/',
        seconds: secondsRemaining(),
        // 只给「时间」，绝不给这个时间片对应的码 —— 给了码，登录门就等于没有。
        serverTime: Date.now(),
      });
      sendHtml(res, 200, html);
      return 'handled';
    }

    // TOTP 不需要发码；console 才需要
    if (req.method === 'POST' && url.pathname === '/__login/send') {
      if (channel === 'totp') {
        return json(res, 400, { ok: false, error: '这个部署用的是验证器 App 的 6 位动态码，不需要「获取验证码」' }), 'handled';
      }
      const ip = clientIp(req);
      const entry = limitOf(ip);
      const now = Date.now();
      entry.sends = entry.sends.filter((t) => now - t < 3600e3);
      if (now - entry.lastSendAt < RESEND_COOLDOWN_MS) {
        return json(res, 429, { ok: false, error: `请等 ${Math.ceil((RESEND_COOLDOWN_MS - (now - entry.lastSendAt)) / 1000)} 秒再发` }), 'handled';
      }
      if (entry.sends.length >= MAX_SENDS_PER_HOUR) {
        return json(res, 429, { ok: false, error: '这一小时发得太多了，过一会儿再试' }), 'handled';
      }
      const code = String(randomInt(0, 1000000)).padStart(6, '0');
      try {
        await send(phone, code);
      } catch (error) {
        log(`发码失败：${error.message}`);
        return json(res, 500, { ok: false, error: error.message }), 'handled';
      }
      pending.set(phone, { code, expiresAt: now + CODE_TTL_MS });
      entry.sends.push(now);
      entry.lastSendAt = now;
      entry.tries = 0;
      return json(res, 200, { ok: true, channel, maskedPhone: maskPhone(phone) }), 'handled';
    }

    if (req.method === 'POST' && url.pathname === '/__login/verify') {
      const ip = clientIp(req);
      const entry = limitOf(ip);
      const body = await readBody(req);
      const given = String(body?.code || '').replace(/\s/g, '');
      const at = Date.now();

      // 试错计数按时间衰减：锁定期 60 秒，过了就把计数清零。
      // 不衰减的话，TOTP 通道没有「重新发码」可点，8 次之后就永久 429 ——
      // 用户只能重启插件才能再登，而文案还写着「等一分钟」，等于把人锁在门外。
      if (entry.tries > 0 && at - (entry.lastTryAt || 0) > RETRY_LOCK_MS) {
        entry.tries = 0;
      }
      if (entry.tries >= MAX_TRIES) {
        const wait = Math.ceil((RETRY_LOCK_MS - (at - (entry.lastTryAt || 0))) / 1000);
        return json(res, 429, { ok: false, error: `错太多次了，请等 ${wait > 0 ? wait : 1} 秒后再试` }), 'handled';
      }
      entry.tries += 1;
      entry.lastTryAt = at;

      let ok = false;
      if (channel === 'totp') {
        const step = Math.floor(Date.now() / 1000 / 30);
        const key = replayKey(step);
        ok = verifyCode(totpSecret, given);
        if (ok && lastUsedSteps.has(key)) ok = false;
        if (ok) lastUsedSteps.add(key);
        for (const old of lastUsedSteps) if (Number(old.split(':').at(-1)) < step - 3) lastUsedSteps.delete(old);
      } else {
        const record = pending.get(phone);
        if (!record || !(record.expiresAt > Date.now())) {
          return json(res, 400, { ok: false, error: '验证码已过期，请重新获取' }), 'handled';
        }
        ok = equal(given, record.code);
        if (ok) pending.delete(phone);
      }
      if (!ok) {
        // 失败原因要分开说：把「密钥不一样」也说成「时钟不准」，用户会一直去调时间。
        let error = channel === 'totp' ? '动态码不对' : '验证码不对';
        if (channel === 'totp') {
          const located = locateStep(totpSecret, given);
          if (!located.matched) {
            // 前后 5 分钟里一个都对不上 = 手上这串码不是这把密钥算出来的
            error = '动态码和这台电脑对不上：你手机验证器里的那个条目，可能还是旧的密钥。'
              + '请在电脑上重新打开设置 → 远程链接 → 显示认证器，用新的码重新扫一次（旧条目先删掉）。';
          } else if (Math.abs(located.deltaSteps) >= 2) {
            const secs = Math.abs(located.deltaSteps) * 30;
            error = `动态码对，但时间差了约 ${secs} 秒（手机快了/慢了）。`
              + '把手机「设置 → 通用 → 日期与时间」里的「自动设置」打开，再试。';
          } else {
            // ±1 片内本应通过，走到这里说明是被重放保护挡了
            error = '这个动态码刚用过一次，等它刷新（约 30 秒）再用新码。';
          }
        }
        return json(res, 401, { ok: false, error }), 'handled';
      }

      entry.tries = 0;
      const next = safeNext(body?.next);
      // 「关掉网页就等于断开」在 cookie 这一层做不到：HttpOnly + Max-Age 的 cookie
      // 关标签页不会消失，浏览器也没有可靠的「页面已关闭」信号。所以把选择权交给用户：
      //   remember=false（默认）= 会话 cookie（不写 Max-Age），关掉浏览器就没了；
      //   remember=true       = 记 30 天，下次直接进。
      // 默认选前者，正好符合「下次进来要重新连」的期望。
      const remember = body?.remember === true;
      const maxAge = remember ? `; Max-Age=${SESSION_DAYS * 86400}` : '';
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'set-cookie': `${COOKIE}=${issueSession()}; Path=/; HttpOnly; SameSite=Lax${maxAge}`,
      });
      res.end(JSON.stringify({ ok: true, next, remember }));
      return 'handled';
    }

    // API 请求不能跳 HTML 登录页：客户端会把 303 跟成登录页，然后在解析 JSON 时产生误导性错误。
    // 浏览器导航才使用 303，交互页面仍保留原地址便于登录后返回。
    if (String(url.pathname || '').startsWith('/api/')) {
      return json(res, 401, { ok: false, error: { code: 'login-required', message: '请先登录这台电脑' } }), 'handled';
    }
    const target = url.pathname + (url.search || '');
    res.writeHead(303, { 'cache-control': 'no-store', location: `/__login?next=${encodeURIComponent(target)}` });
    res.end();
    return 'handled';
  }

  return {
    handle,
    verifySession,
    revokeSession,
    cookieName: COOKIE,
    phone,
    channel,
    issueSession,
    announceTotp,
    totpIsNew,
    totpSecret,
  };
}

/** 登录页：深色、单列、窄屏铺满；纯静态，无外部依赖。 */
function loginPage({ channel, maskedPhone, next, seconds, serverTime = Date.now() }) {
  const safeNext = JSON.stringify(next).replace(/</g, '\\u003c');
  const totp = channel === 'totp';
  const hint = totp
    ? '打开手机上的验证器 App（Google Authenticator / 微软 / 1Password / iOS 密码），填它显示的 6 位数字'
    : channel === 'console'
      ? '验证码会打印在电脑的终端窗口里'
      : '验证码会通过短信发到这个号码';
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#151517">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>登录 · DeepSeek Harness</title>
<style>
  :root{color-scheme:dark;--bg:#151517;--panel:#1c1c1f;--line:#2a2a2f;--fg:#e8e8ea;--muted:#8b8b93;--accent:#4d6bfe;--error:#ff6b6b;--ok:#37d67a}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif;
       display:flex;align-items:center;justify-content:center;padding:24px;padding-bottom:calc(24px + env(safe-area-inset-bottom))}
  .card{width:100%;max-width:380px}
  .logo{display:flex;align-items:center;gap:10px;margin-bottom:28px}
  .mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#4d6bfe,#7a5cff);display:grid;place-items:center;font-weight:700;font-size:17px}
  h1{font-size:20px;margin:0 0 6px;font-weight:600}
  p.sub{margin:0 0 24px;color:var(--muted);font-size:13px}
  label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
  .row{display:flex;gap:8px}
  input{width:100%;background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--fg);
        font-size:16px;padding:13px 14px;outline:none;transition:border-color .15s}
  input:focus{border-color:var(--accent)}
  input::placeholder{color:#5c5c66}
  .field{margin-bottom:16px}
  button{font:inherit;cursor:pointer;border:none;border-radius:10px;padding:13px 16px;transition:opacity .15s}
  button:disabled{opacity:.45;cursor:default}
  .primary{width:100%;background:var(--accent);color:#fff;font-weight:600}
  .ghost{background:var(--panel);border:1px solid var(--line);color:var(--fg);white-space:nowrap;min-width:112px}
  .msg{min-height:20px;font-size:13px;margin:14px 0 0}
  .msg.err{color:var(--error)} .msg.ok{color:var(--ok)}
  .foot{margin-top:26px;color:#5c5c66;font-size:12px;line-height:1.7}
  .locked{margin-top:18px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:#18181b;color:var(--muted);font-size:12.5px;line-height:1.6}
  .timer{color:#5c5c66;font-size:12px;margin-top:6px;min-height:16px}
  .clock{color:#7d7d88;font-size:11.5px;margin-top:2px}
  .clock span{font-variant-numeric:tabular-nums;color:#a8a8b3}
  .remember{display:flex;align-items:flex-start;gap:8px;margin:2px 0 0;color:var(--muted);font-size:12.5px;line-height:1.5;cursor:pointer}
  .remember input{margin:2px 0 0;width:15px;height:15px;flex:none;accent-color:var(--accent)}
</style>
</head>
<body>
  <div class="card">
    <div class="logo"><div class="mark">D</div><strong>DeepSeek Harness</strong></div>
    <h1>登录这台电脑</h1>
    <p class="sub">手机号只是这台电脑的登录标签，不会连接 DeepSeek 账号；用已绑定的验证器动态码验证身份。</p>

    <div class="field">
      <label>手机号</label>
      <input id="phone" value="${maskedPhone}" readonly>
    </div>

    <div class="field">
      <label>${totp ? '验证器动态码' : '验证码'}</label>
      <div class="row">
        <input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6 位数字">
        ${totp ? '' : '<button id="send" class="ghost" type="button">获取验证码</button>'}
      </div>
      ${totp ? `<div id="timer" class="timer">当前码 ${seconds} 秒后刷新</div>
      <div class="clock">电脑此刻 <span id="clock">--:--:--</span>　（和手机时间差超过 30 秒就会登录失败）</div>` : ''}
    </div>

    <button id="go" class="primary" type="button">登录</button>
    <label class="remember"><input id="remember" type="checkbox"> 在这台手机上记住我 30 天（默认不勾：关掉网页就要重新登录）</label>
    <div id="msg" class="msg"></div>

    <div class="locked">${hint}。这里不是 DeepSeek 官方账号登录：手机号只是本机配置的标签，验证码由你自己的验证器/短信通道提供。手机不在身边就登不进来。</div>
    <div class="foot">只有这台电脑开着 DSH 时才能登录；电脑关掉，链接就失效。</div>
  </div>

<script>
const NEXT = ${safeNext};
const TOTP = ${totp};
const $ = (id) => document.getElementById(id);
const msg = (text, cls) => { $('msg').textContent = text || ''; $('msg').className = 'msg ' + (cls || ''); };

${totp ? `let left = ${seconds};
setInterval(() => {
  left -= 1;
  if (left <= 0) left = 30;
  const t = $('timer');
  if (t) t.textContent = '当前码 ' + left + ' 秒后刷新';
}, 1000);

// 电脑的实时时钟：让你能把它和手机时间直接对一眼。
// 只报时间，不报这个时间片算出的码 —— 报码等于把登录门拆了。
(function () {
  let skew = 0;
  try { skew = ${serverTime} - Date.now(); } catch (e) { skew = 0; }
  const pad = (n) => String(n).padStart(2, '0');
  const tick = () => {
    const d = new Date(Date.now() + skew);
    const el = $('clock');
    if (el) el.textContent = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  };
  tick();
  setInterval(tick, 1000);
})();` : `let sendTimer = null;
$('send').onclick = async () => {
  $('send').disabled = true;
  msg('正在发送…');
  try {
    const res = await fetch('/__login/send', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) throw new Error(data.error || ('发送失败 HTTP ' + res.status));
    msg('验证码已发出', 'ok');
    let n = 60;
    sendTimer = setInterval(() => {
      n -= 1; $('send').textContent = n + 's';
      if (n <= 0) { clearInterval(sendTimer); $('send').disabled = false; $('send').textContent = '重新获取'; }
    }, 1000);
    $('send').textContent = n + 's';
    $('code').focus();
  } catch (error) {
    msg(error.message, 'err');
    $('send').disabled = false;
  }
};`}

$('go').onclick = async () => {
  const code = $('code').value.trim();
  if (!/^\\d{6}$/.test(code)) { msg('请填 6 位数字', 'err'); return; }
  $('go').disabled = true;
  msg('正在验证…');
  try {
    const res = await fetch('/__login/verify', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, next: NEXT, remember: $('remember').checked === true }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) throw new Error(data.error || ('验证失败 HTTP ' + res.status));
    msg('登录成功，正在进入…', 'ok');
    location.replace(data.next || '/');
  } catch (error) {
    msg(error.message, 'err');
    $('go').disabled = false;
  }
};

$('code').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('go').click(); });
${totp ? "$('code').focus();" : ''}
</script>
</body>
</html>`;
}
