/**
 * 回环桥接：把外部（手机）请求安全地转给本机 DSH web 服务。
 *
 * 为什么需要它：DSH 的 Web 服务只绑 `127.0.0.1`，而且每个请求都要一枚**按 authority
 * 签名**的浏览器会话 cookie；外部域名既连不到、也拿不出这枚 cookie。桥接跑在同一台机器上，
 * 所以它能做到两件事，而这两件事外部谁做都不对：
 *
 *   1. 用宿主给的签名密钥现铸一枚 `127.0.0.1:<port>` 的 cookie，替外部请求带上；
 *   2. 把 Host 改写成回环那一份、丢掉 Origin，让 DSH 的 Host/Origin 围栏认下这条请求。
 *
 * 访问控制由 `lib/auth.js` 的登录门负责：桥接自己不判断身份，只认「登录门放行与否」。
 * 登录门返回非 `pass` 的请求，一律由登录门答完（登录页 / 401 / 303），不进转发。
 *
 * 同时转发 WebSocket（`/api/remote.mux`）：对话流、工具实时输出、审批卡片全靠它，
 * 少了这条链路，手机上只能看历史、不能干活。
 */
import http from 'node:http';
import net from 'node:net';
import { mintCookie } from './mint.js';

const VIA_HEADER = 'x-dsh-via';
const VIA_TUNNEL = 'tunnel';

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length',
]);

/**
 * @param {object} opts
 * @param {number} opts.targetPort   本机 DSH web 端口
 * @param {Buffer} opts.secret       DSH 浏览器会话签名密钥（32 字节）
 * @param {object} opts.auth         登录门（`lib/auth.js` 的返回值）
 * @param {number} [opts.listenPort] 监听端口，0 = 让系统挑
 * @param {string} [opts.listenHost] 监听地址，默认 0.0.0.0（局域网可用；公网仍必须经隧道）
 * @param {(message: string) => void} [opts.log]
 */
export function createBridge(opts) {
  const targetPort = Number(opts.targetPort);
  if (!Number.isInteger(targetPort) || targetPort <= 0) throw new Error('桥接需要有效的 DSH 端口');
  const targetHost = '127.0.0.1';
  const upstreamAuthority = `${targetHost}:${targetPort}`;
  const auth = opts.auth;
  if (!auth) throw new Error('桥接需要登录门（没有它等于把 DSH 裸奔到公网）');

  // cookie 只为「替外部请求说话」用；30 天与 DSH 自己的 cookieMaxAgeDays 一致
  const cookie = mintCookie(upstreamAuthority, { secret: opts.secret });
  const cookieHeader = `${cookie.name}=${cookie.value}`;

  const log = opts.log || (() => {});
  const live = new Set();

  /** 外部请求 → 上游头：删逐跳头与来源标记，改 Host，补 cookie。 */
  function upstreamHeaders(incoming) {
    const out = {};
    for (const [key, value] of Object.entries(incoming)) {
      if (value === undefined) continue;
      if (HOP_BY_HOP.has(key)) continue;
      if (key === 'origin' || key === 'referer' || key === 'sec-fetch-site' || key === 'host' || key === 'cookie' || key === VIA_HEADER) continue;
      out[key] = value;
    }
    out.host = upstreamAuthority;
    out.cookie = cookieHeader;
    out[VIA_HEADER] = VIA_TUNNEL;
    return out;
  }

  function forwardRequest(req, res) {
    const up = http.request(
      { hostname: targetHost, port: targetPort, method: req.method, path: req.url, headers: upstreamHeaders(req.headers) },
      (ures) => {
        const headers = {};
        for (const [key, value] of Object.entries(ures.headers)) {
          // content-length 不是逐跳头：丢了它每一发响应都退化成 chunked，
          // 手机侧判断「这个文件收完了没有」就没了依据。
          if (!HOP_BY_HOP.has(key) || key === 'content-length') headers[key] = value;
          // 上游不会发 set-cookie（会话 cookie 由我们代持），万一发了也不能冲掉登录态
          if (key === 'set-cookie') delete headers[key];
        }
        res.writeHead(ures.statusCode || 502, headers);
        if (typeof res.flushHeaders === 'function') res.flushHeaders();
        ures.pipe(res);
      },
    );
    up.on('error', (error) => {
      log(`转发失败：${error.message}`);
      try {
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(`upstream error: ${error.message}`);
      } catch { /* 手机侧已断开 */ }
    });
    // 手机走了就把上游这条请求一起拆掉，否则宿主那边的流订阅永远等不到收尾
    res.on('close', () => {
      if (!res.writableEnded) { try { up.destroy(); } catch { /* 已断开 */ } }
    });
    if (req.method === 'GET' || req.method === 'HEAD') up.end();
    else req.pipe(up);
  }

  /** 升级请求按 rawHeaders 逐条搬：握手要靠 connection/upgrade，不能走逐跳头过滤。 */
  function upgradeHead(req) {
    // origin / referer / sec-fetch-site 必须和 HTTP 那条一样丢掉：
    // 浏览器经隧道打开时 WS 会带 `Origin: https://xxx.trycloudflare.com`，
    // 而 DSH 的 Host/Origin 一致性检查会把它判成跨源 → 403，手机上就是一直「重新连接中」。
    const skip = new Set(['host', 'cookie', 'origin', 'referer', 'sec-fetch-site', VIA_HEADER]);
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      const key = String(req.rawHeaders[i]).toLowerCase();
      if (skip.has(key)) continue;
      lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    lines.push(`Host: ${upstreamAuthority}`);
    lines.push(`Cookie: ${cookieHeader}`);
    lines.push(`${VIA_HEADER}: ${VIA_TUNNEL}`);
    return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1');
  }

  function forwardUpgrade(req, socket, head) {
    // TCP keepalive 必须开：quick tunnel 两端的 NAT/边缘在连接「静默」一段时间后
    // 会直接丢状态，客户端看到的就是 1006 异常关闭 —— 界面上就是「重新连接中」。
    // 30 秒探一次，比 WebSocket 层的心跳更靠底层，不干扰协议的 ping/pong。
    try {
      socket.setKeepAlive(true, 30000);
      socket.setNoDelay(true);
    } catch { /* 部分平台不支持，忽略 */ }
    const upstream = net.connect({ host: targetHost, port: targetPort });
    try {
      upstream.setKeepAlive(true, 30000);
      upstream.setNoDelay(true);
    } catch { /* 同上 */ }
    live.add(socket);
    live.add(upstream);
    const drop = () => {
      live.delete(socket);
      live.delete(upstream);
      socket.destroy();
      upstream.destroy();
    };
    socket.on('error', drop);
    upstream.on('error', drop);
    socket.on('close', drop);
    upstream.on('close', drop);
    upstream.on('connect', () => {
      upstream.write(upgradeHead(req));
      if (head && head.length > 0) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
  }

  /** 从 Cookie 头里取登录态（桥接只认自己那枚，不解析别的）。 */
  function sessionOf(req) {
    for (const segment of String(req.headers.cookie || '').split(';')) {
      const at = segment.indexOf('=');
      if (at === -1) continue;
      if (segment.slice(0, at).trim() === auth.cookieName) return segment.slice(at + 1).trim();
    }
    return '';
  }

  /**
   * 最近进来的是些什么客户端（只留内存，最多 12 条）。
   * 用途：手机上连不上时，能一眼看出「请求到底有没有到」以及「是浏览器还是脚本」——
   * User-Agent 里 iPhone / Android / Windows 分得很清楚，比 ping 隧道域名有用得多。
   */
  const recent = [];
  /** 每条客户端记录的序号，用来让界面判断「有没有新请求进来」。 */
  let clientSeq = 0;

  /** 内部把 IPv4 映射段也算成本机（Node 在双栈下会给出 ::ffff:127.0.0.1）。 */
  function isLoopbackPeer(peer) {
    const ip = String(peer || '').replace(/^\[|\]$/g, '');
    return /^127\./.test(ip) || ip === '::1' || /^::ffff:127\./.test(ip);
  }

  /** Tailscale CGNAT 段 100.64.0.0/10 —— 它不是局域网，只是另一个虚拟网段。 */
  function isTailscalePeer(peer) {
    const ip = String(peer || '').replace(/^\[|\]$/g, '').replace(/^::ffff:/, '');
    return /^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip) || /^fd7a:115c:a1e0:/i.test(ip);
  }

  /**
   * 判定这条请求从哪条路进来。
   *
   * 关键难点：frpc（自建中继）和 cloudflared（Cloudflare）**都是从 127.0.0.1 转进来的**，
   * 光看 socket 地址分不出谁是谁 —— 之前就因此把中继流量误标成「公网隧道（Cloudflare）」，
   * 用户看到状态码里的延迟数字，容易误以为是公网隧道的锅。
   *
   * 所以改成看**本地监听端口**：中继走独立端口（`opts.relayPort`），
   * 其他回环来源才归到 Cloudflare。这样界面说的是实话。
   */
  function viaOf(req) {
    const peer = req.socket?.remoteAddress;
    const localPort = Number(req.socket?.localPort) || 0;
    if (isLoopbackPeer(peer)) {
      // 中继端口进来的 → relay；其余回环（含 cloudflared）→ tunnel
      if (opts.relayPort && localPort === Number(opts.relayPort)) return 'relay';
      return 'tunnel';
    }
    if (isTailscalePeer(peer)) return 'tailscale';
    return 'lan';
  }

  function noteClient(req, kind) {
    const ua = String(req.headers['user-agent'] || '').slice(0, 200);
    const via = viaOf(req);
    clientSeq += 1;
    recent.push({
      seq: clientSeq,
      at: Date.now(),
      method: req.method,
      path: String(req.url || '/').split('?')[0].slice(0, 80),
      kind,
      via,
      ua,
    });
    while (recent.length > 12) recent.shift();
  }

  const server = http.createServer(handleRequest);

  // ── 中继专用监听口 ────────────────────────────────────────────────────────
  //
  // frpc 和 cloudflared 都从 127.0.0.1 转进来，光看 socket 地址分不出是谁。
  // 于是让 frpc 连一个**独立端口**（默认 bridgePort+1）：那个口进来的就是「自建中继」，
  // 其余回环来源才是 Cloudflare。这样界面和客户端记录说的都是实话。
  let relayServer = null;
  let relayPort = Number(opts.relayPort) || 0;
  if (opts.relayPort) {
    relayServer = http.createServer(handleRequest);
    relayServer.requestTimeout = 0;
    relayServer.headersTimeout = 0;
    relayServer.timeout = 0;
    relayServer.keepAliveTimeout = 0;
  }

  async function handleRequest(req, res) {
    const url = new URL(req.url || '/', 'http://bridge.invalid');

    // `/__ping`：状态条用来量往返延迟的极轻接口。
    // 它必须**在登录门之后**才能答（否则等于给外人一个探测口），
    // 但又要足够便宜 —— 所以放在鉴权后、转发前，直接回一个空 JSON。
    const isPing = url.pathname === '/__ping';
    if (!isPing) {
      // 设置接口的本机探测不算「客户端」，否则每 3 秒刷新会把真实记录挤掉
      if (!String(url.pathname).startsWith('/api/remote-link/')) noteClient(req, 'http');
    }
    try {
      const verdict = await auth.handle(req, res, url);
      if (verdict !== 'pass') return;
    } catch (error) {
      log(`登录门异常：${error.message}`);
      try {
        if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('login gate error');
      } catch { /* 已断开 */ }
      return;
    }
    if (isPing) {
      const via = viaOf(req);
      const clientIp = String(req.headers['cf-connecting-ip'] || '').split(',')[0].trim();
      let sameEgress = false;
      if (clientIp && typeof opts.publicIp === 'function') {
        try {
          const own = await opts.publicIp();
          // 只有两边都是 IPv4 时比较才有意义
          const bothV4 = /^\d+\.\d+\.\d+\.\d+$/.test(own) && /^\d+\.\d+\.\d+\.\d+$/.test(clientIp);
          sameEgress = bothV4 && own === clientIp;
        } catch { sameEgress = false; }
      }
      const payload = JSON.stringify({
        ok: true,
        t: Date.now(),
        via,
        // home 只对「真局域网」成立。Tailscale 的 100.x 不算 —— 它可能正在绕地球。
        home: via === 'lan' || sameEgress,
        sameEgress,
        lanUrls: opts.lanUrls ? opts.lanUrls() : [],
        // Tailscale 实际走的是直连还是中继，由 shell 侧的 tsPath() 提供；
        // 这里回 null 表示「不知道」，前端就不会瞎标“局域网”。
        tsPath: opts.tsPath ? await opts.tsPath() : null,
      });
      // 实测结论：经 frp（tcpMux）时，**小响应会被攒到 2 秒才发**——
      // 133 字节的响应固定 2240ms，而同一通道 44KB 的首页只要 120ms。
      // 这是 frp 多路复用器对小包做合并超时导致的，不是网络慢。
      // 做法：把响应填充到一个 TCP 段以上，让它立刻出队。填充内容无意义，只占位。
      const pad = 1200;
      const body = payload.length >= pad
        ? payload
        : payload.slice(0, -1) + `,"_pad":"${'x'.repeat(pad - payload.length)}"}`;
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'content-length': Buffer.byteLength(body),
        'connection': 'keep-alive',
        'x-accel-buffering': 'no',
      });
      try { res.socket?.setNoDelay(true); } catch { /* 平台不支持就算了 */ }
      res.end(body);
      return;
    }
    forwardRequest(req, res);
  }

  /** 两个监听口共用同一个升级处理。 */
  function handleUpgrade(req, socket, head) {
    noteClient(req, 'websocket');
    // WebSocket 不跑页面，只认登录 cookie；没登录直接断，不给它跳转的机会
    const token = sessionOf(req);
    const ok = token !== '' && auth.verifySession(token) !== null;
    if (!ok) {
      socket.write('HTTP/1.1 401 Unauthorized\r\ncontent-type: text/plain\r\ncontent-length: 13\r\n\r\nlogin required');
      socket.destroy();
      return;
    }
    // 第三个参数必须传下去：有的客户端会在握手包之后立刻跟一段数据，
    // 丢掉它等于吞掉首批帧（表现为「连上了但收不到东西」）。
    forwardUpgrade(req, socket, head);
  }

  server.on('upgrade', handleUpgrade);
  if (relayServer) relayServer.on('upgrade', handleUpgrade);

  // SSE / 长任务不能被默认超时掐掉。
  // keepAliveTimeout 默认 5 秒：经隧道进来的连接若刚好被判定成「空闲 keep-alive」，
  // 会被当成可回收连接直接断掉（浏览器侧看到的就是 1006 异常关闭、界面转「重新连接中」）。
  server.requestTimeout = 0;
  server.headersTimeout = 0;
  server.timeout = 0;
  server.keepAliveTimeout = 0;

  return {
    cookieName: cookie.name,
    upstreamAuthority,
    /** 最近进来的客户端（只读快照，给设置页和排查用）。 */
    recentClients: () => recent.map((item) => ({ ...item })),
    /** 当前活着的长连接条数（WebSocket 被掐断时界面要能看出来）。 */
    liveCount: () => live.size / 2,
    /** 此刻在线的客户端数（按最近 20 秒内有过请求的去重 UA + 出口判定）。 */
    activeCount() {
      const now = Date.now();
      const seen = new Set();
      for (const item of recent) {
        if (now - item.at > 20000) continue;
        seen.add(`${item.ua}|${item.via}`);
      }
      return seen.size;
    },
    /** @returns {Promise<{ port: number, host: string, relayPort?: number }>} */
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(Number(opts.listenPort || 0), opts.listenHost || '0.0.0.0', async () => {
          server.removeListener('error', reject);
          const address = server.address();
          const boundPort = typeof address === 'object' && address ? address.port : 0;
          let boundRelay = 0;
          if (relayServer) {
            try {
              await new Promise((res2, rej2) => {
                relayServer.once('error', rej2);
                relayServer.listen(Number(opts.relayPort), '127.0.0.1', () => {
                  relayServer.removeListener('error', rej2);
                  res2();
                });
              });
              const a2 = relayServer.address();
              boundRelay = typeof a2 === 'object' && a2 ? a2.port : 0;
            } catch (error) {
              // 中继口起不来不该拖垮主桥接：记一笔，标记为不可用
              log(`中继监听口启动失败：${error.message}`);
              relayPort = 0;
            }
          }
          resolve({
            port: boundPort,
            host: opts.listenHost || '127.0.0.1',
            relayPort: boundRelay,
          });
        });
      });
    },
    /** 中继专用口（frpc 连这个，界面据此显示“自建中继”）。0 = 没起来。 */
    relayPortOf: () => relayPort,
    close() {
      for (const socket of live) socket.destroy();
      live.clear();
      server.close();
      try { relayServer?.close(); } catch { /* 已关 */ }
    },
  };
}
