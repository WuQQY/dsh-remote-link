/**
 * 对浏览器可见的那部分设置接口（小路由 `/api/remote-link/*`）。
 *
 * 为什么这些接口要单独挂在 webServer 上：界面那一半跑在浏览器里，它要读开关状态、
 * 点按钮开/关、拿二维码，只能走 HTTP。而这些接口一旦开出去，就等于「谁能拨到这个端口
 * 谁就能开隧道」——所以每一个都过 `localOnly`：只认本机回环、同源、无转发头的请求。
 * 从隧道进来的请求带着登录门补的 cookie 也过不了这一关（它们本来也不该改开关）。
 */
import { sendJson, readJsonBody } from './http.js';

const PREFIX = '/api/remote-link';

/**
 * @param {object} hooks
 * @param {() => object} hooks.status         当前状态快照
 * @param {() => Promise<object>} hooks.enable   开隧道
 * @param {() => Promise<object>} hooks.disable  关隧道
 * @param {() => object} hooks.pairing         二维码与密钥（仅本机可见）
 * @param {(body: object) => Promise<object>} hooks.configure 改配置（手机号/通道/监听）
 */
export function createRoutes(hooks) {
  /** 本机回环 + 同源 + 无代理头；与移动插件那条 control-plane 同一套判据。 */
  function localOnly(req) {
    const socket = req?.socket || req?.connection;
    const address = String(socket?.remoteAddress || '').replace(/^\[|\]$/g, '');
    const loopback = /^127\./.test(address) || address === '::1' || /^::ffff:127\./.test(address);
    if (!loopback) return false;
    const headers = req.headers && typeof req.headers === 'object' ? req.headers : {};
    for (const [name, value] of Object.entries(headers)) {
      if (/^(?:forwarded$|x-forwarded-|x-real-ip$|via$|x-dsh-via$|true-client-ip$|cf-connecting-ip$)/i.test(name) && String(value || '').trim()) return false;
    }
    // Host 不能是任意域名：DNS rebinding 时 socket 仍是回环、Origin 与 Host 也会相等。
    // 只接受 localhost / IP 字面量，域名一律拒绝；这与 DSH 的 webAccessHostTrusted 判据一致。
    const host = headers.host;
    if (typeof host !== 'string' || !host) return false;
    let hostname = '';
    try { hostname = new URL(`http://${host}`).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return false; }
    const isIpLiteral = hostname === 'localhost' || hostname === '::1'
      || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(hostname)
      || /^[0-9a-f:]+$/i.test(hostname) && hostname.includes(':');
    if (!isIpLiteral) return false;
    if (String(headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') return false;
    const origin = headers.origin;
    if (typeof origin === 'string' && origin) {
      try { if (new URL(origin).host !== host) return false; } catch { return false; }
    }
    return true;
  }

  const deny = (res) => sendJson(res, 403, { ok: false, error: { code: 'local_only', message: '这个操作只允许在本机 DSH 里点' } });

  /** 一条路由：路径后缀 + 允许的方法 + handler。 */
  const table = [
    ['/status', 'GET', async (_req, res) => sendJson(res, 200, { ok: true, ...hooks.status() })],
    // `?reveal=1` 才回长期密钥：默认只给二维码，避免有人截个设置页就把第二因子拿走
    ['/pairing', 'GET', async (req, res) => {
      const url = new URL(req.url || '/', 'http://local.invalid');
      const reveal = url.searchParams.get('reveal') === '1';
      sendJson(res, 200, { ok: true, ...hooks.pairing({ reveal }) });
    }],
    ['/enable', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks.enable()) })],
    // 只开桥接（局域网直连）：没有隧道客户端时也能用，出门就断
    ['/enable-lan', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks['enable-lan']()) })],
    // 两条入口一起起：桥接 + 隧道，界面据此自动推荐走哪条
    ['/enable-both', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks['enable-both']()) })],
    ['/disable', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks.disable()) })],
    // 手机端主动断开：只掐掉当前这条登录态，不动隧道（用户可能还在别的设备上用）
    ['/logout', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks.logout()) })],
    // 注销所有设备：轮换登录签名密钥，已登录的 30 天 cookie 立刻失效
    ['/signout-all', 'POST', async (_req, res) => sendJson(res, 200, { ok: true, ...(await hooks.signoutAll()) })],
    ['/configure', 'POST', async (req, res) => {      const body = await readJsonBody(req, 16 * 1024);
      if (!body || typeof body !== 'object') return sendJson(res, 400, { ok: false, error: { code: 'bad-request', message: '需要 JSON' } });
      try {
        return sendJson(res, 200, { ok: true, ...(await hooks.configure(body)) });
      } catch (error) {
        return sendJson(res, 400, { ok: false, error: { code: 'bad-request', message: String(error?.message || error) } });
      }
    }],
  ];

  return table.map(([suffix, method, handler]) => ({
    kind: 'exact',
    path: `${PREFIX}${suffix}`,
    handler: async (req, res) => {
      if (!localOnly(req)) return deny(res);
      if (String(req.method || 'GET').toUpperCase() !== method) {
        return sendJson(res, 405, { ok: false, error: { code: 'method-not-allowed', message: `只支持 ${method}` } });
      }
      try {
        await handler(req, res);
      } catch (error) {
        sendJson(res, 500, { ok: false, error: { code: 'internal', message: String(error?.message || error) } });
      }
    },
  }));
}

export { PREFIX };
