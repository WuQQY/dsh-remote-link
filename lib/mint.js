/**
 * 生成 DSH 自己的「浏览器会话」cookie。
 *
 * 为什么要造它：DSH 的 Web 服务每个请求都要一枚按 authority（`127.0.0.1:<port>`）签名
 * 的 cookie，外部域名拿不到、也伪造不了。桥接进程在本机、拿得到签名密钥，所以由它
 * 替外部请求现铸一枚，手机浏览器里一个字都不用带。
 *
 * 密钥来源：优先用宿主给的 `credentials` 记录 `client-connection/browser-session`；
 * 拿不到才退回读 `~/.dsh/.credentials.yaml`（老宿主 / 单独跑脚本时）。
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** 从 base64url 文本解出 32 字节签名密钥。 */
export function decodeSecret(text) {
  const raw = String(text || '').trim();
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error('签名密钥格式不对（应为 base64url）');
  const buf = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (buf.length !== 32) throw new Error(`签名密钥长度异常：${buf.length} 字节（应为 32）`);
  return buf;
}

/**
 * 宿主侧取密钥：`credentials.readRecord('client-connection/browser-session')`。
 * 记录形如 `{ kind: 'grant', payload: { version: 1, secret: '…' } }`。
 */
export async function readSecretFromHost(ctx) {
  const credentials = typeof ctx?.get === 'function' ? ctx.get('credentials') : null;
  if (!credentials || typeof credentials.readRecord !== 'function') return null;
  const record = await credentials.readRecord('client-connection/browser-session');
  const secret = record?.payload?.secret;
  if (typeof secret !== 'string' || secret.length === 0) return null;
  return decodeSecret(secret);
}

/**
 * 退路：直接读 DSH 自己的凭据文件（`$DSH_HOME/.credentials.yaml`）。
 *
 * 只在宿主没有 `credentials` 服务时用（老版本、或单独跑脚本）。读的是**本机文件本身**，
 * 不外发、不留副本；拿不到就回 null，由调用方按「不可用」处理，不猜测、不伪造。
 */
export function readSecretFromFile(path) {
  const file = path || join(process.env.DSH_HOME || join(homedir(), '.dsh'), '.credentials.yaml');
  let raw = '';
  try { raw = readFileSync(file, 'utf8'); } catch { return null; }
  const hit = /client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/.exec(raw);
  if (!hit) return null;
  try { return decodeSecret(hit[1]); } catch { return null; }
}

export const COOKIE_PREFIX = 'dsh-auth-';/** cookie 名按 authority 派生，与服务端一致。 */
export function cookieName(authority) {
  return COOKIE_PREFIX + b64url(createHash('sha256').update(authority).digest());
}

/** 为某个 authority（形如 `127.0.0.1:51585`）铸 cookie。 */
export function mintCookie(authority, { secret, days = 30 } = {}) {
  if (!Buffer.isBuffer(secret)) throw new Error('需要 32 字节的签名密钥');
  const issuedAt = Date.now();
  const expiresAt = issuedAt + days * 24 * 60 * 60 * 1000;
  const body = b64url(Buffer.from(JSON.stringify({ version: 1, authority, issuedAt, expiresAt }), 'utf8'));
  const sig = b64url(createHmac('sha256', secret).update(body).digest());
  return { name: cookieName(authority), value: `v1.${body}.${sig}`, expiresAt };
}

/**
 * 校验一枚 DSH 浏览器会话 cookie 是否有效。
 *
 * 注意：**设置接口不用它当门禁** —— 那层用的是 `lib/routes.js` 的 `localOnly`
 * （回环 + Host 字面量 + 无转发头 + 无 `x-dsh-via`）。这里保留它是给诊断/自检用，
 * 别误以为它有守卫作用。
 */
export function verifyCookie(cookieHeader, authority, secret, now = Date.now()) {
  if (!Buffer.isBuffer(secret)) return false;
  const want = cookieName(authority);
  let value = '';
  for (const segment of String(cookieHeader || '').split(';')) {
    const at = segment.indexOf('=');
    if (at === -1) continue;
    if (segment.slice(0, at).trim() === want) { value = segment.slice(at + 1).trim(); break; }
  }
  if (!value) return false;
  const parts = value.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return false;
  const [, body, sig] = parts;
  const expected = b64url(createHmac('sha256', secret).update(body).digest());
  // 定长比较：字符串 `!==` 会在第一个不同字节处短路，理论上可被计时侧信道利用。
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return false; }
  if (payload?.authority !== authority) return false;
  if (!(payload.expiresAt > now)) return false;
  return true;
}
