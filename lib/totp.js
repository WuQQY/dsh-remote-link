/**
 * TOTP（时间型一次性口令）—— 标准 RFC 6238，和 Google Authenticator / 微软 Authenticator /
 * 1Password / iOS 自带「密码」App 全部兼容。
 *
 * 为什么登录门要这个：如果你人在外面、电脑在家里，验证码打在电脑终端里你是看不到的。
 * TOTP 是由手机自己算出来的 6 位数字，不依赖任何发信通道，也不用花钱买短信。
 *
 * 只要第一次在电脑上把密钥（otpauth:// 链接或二维码）加进手机的验证器 App，
 * 以后任何时候打开网页，掏出手机看一眼 6 位数字就能登录。
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

/** 20 字节随机 → base32（不带 padding，验证器 App 通用格式）。 */
export function generateSecret(bytes = 20) {
  const raw = randomBytes(bytes);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function decodeSecret(secret) {
  const clean = String(secret).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 某个时间片（step）上的 6 位码。 */
export function codeAt(secret, step) {
  const key = decodeSecret(secret);
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(step / 0x100000000), 0);
  counter.writeUInt32BE(step >>> 0, 4);
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/** 当前码（给测试和「本机也能看到」用）。 */
export function currentCode(secret, now = Date.now()) {
  return codeAt(secret, Math.floor(now / 1000 / STEP_SECONDS));
}

/**
 * 诊断用：这个 6 位码对应本机时间轴上的第几个时间片？
 *
 * 用途是**把「码不对」拆成两种完全不同的原因**：
 *   · 手机时钟偏了 → 它给出的码属于相邻的时间片（±1、±2…），能算出来；
 *   · 密钥不是同一把 → 本机时间轴前后好几片里**一个都匹配不上**。
 * 以前这两种情况都只报「动态码不对（注意手机时钟要准）」，把密钥不一致也推给时钟，
 * 结果用户去调时间，越调越远。
 *
 * @returns {{ matched: boolean, deltaSteps: number|null }}
 */
export function locateStep(secret, given, now = Date.now()) {
  const text = String(given || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(text)) return { matched: false, deltaSteps: null };
  const step = Math.floor(now / 1000 / STEP_SECONDS);
  // 扫 ±10 片（±5 分钟）：再远就不是时钟问题了，是密钥或输入错误。
  for (let delta = -10; delta <= 10; delta += 1) {
    const expected = codeAt(secret, step + delta);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(text))) {
      return { matched: true, deltaSteps: delta };
    }
  }
  return { matched: false, deltaSteps: null };
}

/**
 * 校验。允许前后各一个时间片（±30 秒），容忍手机和电脑的时钟差；
 * 再宽就等于削弱强度了，所以只给 ±1。
 */
export function verifyCode(secret, given, now = Date.now()) {
  const text = String(given || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(text)) return false;
  const step = Math.floor(now / 1000 / STEP_SECONDS);
  for (const delta of [0, -1, 1]) {
    const expected = codeAt(secret, step + delta);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(text))) return true;
  }
  return false;
}

/** 剩余有效秒数（登录页上可以显示「还有 N 秒」）。 */
export function secondsRemaining(now = Date.now()) {
  return STEP_SECONDS - (Math.floor(now / 1000) % STEP_SECONDS);
}

/** 验证器 App 认的 otpauth:// 链接。 */
export function otpauthUrl({ secret, account, issuer = 'DeepSeek Harness' }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}
