/**
 * 宿主侧装配：把「桥接 + 登录门 + 隧道 + 设置接口」挂到这台 DSH 上。
 *
 * 装配顺序是有讲究的，别换：
 *
 *   1. 先拿 DSH 自己的浏览器会话签名密钥（`credentials` 里那条记录）。拿不到就说明这个
 *      profile 没装连接服务，后面整条链路都没意义 —— 直接报错退出，不留半截状态。
 *   2. 再读状态文件（手机号、登录密钥、隧道地址）。这一步不写盘，只读。
 *   3. 起登录门 → 起桥接（登录门是桥接的必需参数，没有它桥接拒绝创建）。
 *   4. 最后挂设置接口与隧道开关。隧道默认不自动开：自动开等于「装完插件就在公网上开了
 *      一扇门」，而用户可能根本不知道。要开就在设置页点一下。
 *
 * WebSocket（`/api/remote.mux`）不走 webServer 注册，它由桥接自己接 `upgrade` 事件原样
 * 转给上游 —— 那条路是手机端「实时输出与审批」的唯一通道。
 */
import { randomBytes, createHash } from 'node:crypto';
import { createAuth } from './lib/auth.js';
import { createBridge } from './lib/bridge.js';
import { readSecretFromHost } from './lib/mint.js';
import { createRoutes } from './lib/routes.js';
import { otpauthUrl, currentCode, secondsRemaining } from './lib/totp.js';
import {
  ensureLoginSecret, loadState, saveState, startTunnel, stopTunnel,
  lanAddresses, tailscaleAddresses, tailscalePath, tunnelBinary, publicIp,
} from './lib/host-state.js';
import { toSvg } from './lib/qr.js';

export const name = 'remote-link';
export const inject = ['webServer'];

/**
 * 配置项（`cordis.patch.yml` 里那一行的 `config`）：
 *
 *   phone        登录手机号；留空就在设置页里填（填进状态文件，不写回 profile）
 *   channel      totp / console，默认 totp
 *   bridgePort   桥接端口，0 = 每次让系统挑
 *   autoTunnel   装完是否自动开隧道，默认 false
 *
 * 不导出 `Config` schema：这个插件的配置全是「有就用、没有就用默认」的字符串与布尔，
 * 手写校验比引一个 schema 依赖更轻，也不会因为宿主换了 schema 版本而启动失败。
 */

export async function apply(ctx, config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const log = (message) => console.log(`[remote-link] ${message}`);

  // ── 1. DSH 的会话签名密钥 ────────────────────────────────────────────────
  //
  // 正常路径：走宿主的 `credentials` 服务读那条记录。凭据值不出宿主进程，也不进日志。
  // 退路（老宿主 / 单独跑脚本）：直接读 DSH 自己的凭据文件 —— 这是本机文件的本地读取，
  // 不外发、不落盘副本；所以插件守卫会把它标成 MEDIUM，报告里已如实说明。
  let secret = null;
  try {
    secret = await readSecretFromHost(ctx);
  } catch (error) {
    log(`从凭据服务读取会话密钥失败：${error.message}`);
  }
  let secretSource = secret ? 'credentials' : '';
  if (!secret) {
    try {
      const { readSecretFromFile } = await import('./lib/mint.js');
      secret = readSecretFromFile();
      secretSource = secret ? 'credentials-file' : '';
    } catch (error) {
      log(`读本机凭据文件失败：${error.message}`);
    }
  }
  if (!secret) {
    log('拿不到 DSH 的浏览器会话签名密钥，插件不启动。'
      + '这台 profile 里应该没有 `connection` 服务（或凭据文件还没生成过）——先让 DSH 用浏览器打开一次。');
    return;
  }

  // ── 2. 状态 ──────────────────────────────────────────────────────────────
  const state = loadState();
  ensureLoginSecret(state);

  const phoneOf = () => String(cfg.phone || state.loginPhone || '');
  const channelOf = () => String(cfg.channel || state.loginChannel || 'totp');

  // ── 3. 登录门 + 桥接 ─────────────────────────────────────────────────────
  let auth = null;
  let bridge = null;
  let bridgePort = 0;
  /** 中继专用监听口（frpc 连它）。0 = 没起来。 */
  let relayListenPort = 0;

  const buildAuth = () => {
    const phone = phoneOf();
    if (!/^1[3-9]\d{9}$/.test(phone)) return null;
    return createAuth({
      state,
      phone,
      channel: channelOf(),
      log: (line) => console.log(line),
    });
  };

  const startBridge = async () => {
    auth = buildAuth();
    if (!auth) return { ok: false, error: '还没配置登录手机号' };
    // 端口要稳定：每次重建都换端口，会让已公布的局域网地址与正在用的链接一起失效。
    // 优先用配置里的固定值，其次用上次成功监听的端口，最后才让系统挑。
    const preferred = Number(cfg.bridgePort) || Number(state.bridgePort) || 0;
    const listenHost = cfg.listenHost || state.listenHost || '0.0.0.0';
    // 中继专用口 = 桥接端口 + 1：frpc 连它，这样才分得清「自建中继」和「Cloudflare」。
    // 端口是 0（系统挑）时先不传，等主口定下来再算。
    const relayWanted = preferred ? preferred + 1 : 0;
    const candidate = createBridge({
      targetPort: ctx.webServer.port,
      secret,
      auth,
      listenPort: preferred,
      listenHost,
      log,
      // 给 `/__ping` 用：判断手机与电脑是否同一出口，以及有哪些局域网地址可切
      publicIp,
      // Tailscale 走直连还是中继 —— 决定状态条该写「直连」还是「中继 670ms」
      tsPath: tailscalePath,
      relayPort: relayWanted,
      lanUrls: () => (listenHost === '127.0.0.1' ? [] : lanAddresses().map((ip) => `http://${ip}:${preferred || bridgePort}/`)),
    });
    try {
      const bound = await candidate.start();
      bridge = candidate;
      bridgePort = bound.port;
      relayListenPort = bound.relayPort || 0;
      state.bridgePort = bound.port;
      state.listenHost = listenHost;
      saveState(state);
      return { ok: true, port: bridgePort, relayPort: relayListenPort };
    } catch (error) {
      try { candidate.close(); } catch { /* 监听失败时也要尽量释放 server */ }
      bridge = null;
      bridgePort = 0;
      return { ok: false, error: `桥接启动失败：${error?.message || error}` };
    }
  };

  const stopBridge = () => {
    try { bridge?.close(); } catch { /* 已关 */ }
    bridge = null;
    bridgePort = 0;
    relayListenPort = 0;
  };

  // ── 4. 隧道 ──────────────────────────────────────────────────────────────
  let tunnel = { state: 'off', url: '', error: '' };
  let tunnelChild = null;
  /**
   * 隧道操作的「代次」。每次 disable（以及 configure/signoutAll 里的停隧道）都会 +1。
   * enableTunnel await startTunnel 期间若代次变了，说明用户又点了关闭或改了配置 ——
   * 这时 startTunnel 晚到的成功结果必须作废，否则会把已 off 的状态重新点亮，
   * 并且那个刚拿到的 child 再也无人 stop（孤儿 cloudflared 进程）。
   */
  let tunnelGeneration = 0;

  const enableTunnel = async () => {
    if (tunnel.state === 'starting') return { tunnel: tunnelView(), error: '隧道正在开启，请稍候' };
    if (tunnel.state === 'up' && tunnelChild) return { tunnel: tunnelView() };
    if (!bridge) return { tunnel: tunnelView(), error: '桥接没起来（先填手机号）' };
    const generation = tunnelGeneration;
    tunnel = { state: 'starting', url: '', error: '' };
    const result = await startTunnel({
      targetPort: bridgePort,
      log,
      onExit: () => {
        // 主动关闭时 disableTunnel 已把 state 置 off；子进程随后触发的 exit 不能再覆盖它，
        // 否则用户点「关闭」后界面会从 off 跳成「失败：隧道客户端已退出」，误导。
        if (tunnel.state === 'off') return;
        tunnel = { state: 'failed', url: '', error: '隧道客户端已退出，请重新开启' };
        tunnelChild = null;
      },
    });
    // 开启过程中被关闭/重建了：丢弃这次结果，并停掉刚拿到的进程，绝不留孤儿。
    if (generation !== tunnelGeneration) {
      stopTunnel(result.child);
      return { tunnel: tunnelView() };
    }
    if (!result.ok) {
      tunnel = { state: 'failed', url: '', error: result.error };
      stopTunnel(result.child);
      return { tunnel: tunnelView() };
    }
    tunnelChild = result.child;
    tunnel = { state: 'up', url: result.url, error: '' };
    state.lastTunnel = result.url;
    saveState(state);
    return { tunnel: tunnelView() };
  };

  const disableTunnel = async () => {
    tunnelGeneration += 1; // 作废可能在途的 enable
    stopTunnel(tunnelChild);
    tunnelChild = null;
    tunnel = { state: 'off', url: '', error: '' };
    return { tunnel: tunnelView() };
  };

  const tunnelView = () => ({
    state: tunnel.state,
    url: tunnel.url,
    error: tunnel.error,
    lanUrls: bridgePort ? lanAddresses().map((ip) => `http://${ip}:${bridgePort}/`) : [],
  });

  // ── 5. 对界面可见的状态 ──────────────────────────────────────────────────
  /**
   * @param {{reveal?: boolean}} [opts] `reveal` 为真时才回长期 TOTP 密钥原文。
   *   默认只回二维码与 otpauth 链接：设置页天天开着，把密钥明文平铺等于一次截屏
   *   （或一次共享屏幕）就把第二因子永久送人。要看原文得显式点一下。
   */
  const pairingOf = (opts = {}) => {
    const reveal = opts.reveal === true;
    const phone = phoneOf();
    const masked = phone.length >= 7 ? `${phone.slice(0, 3)}****${phone.slice(-4)}` : '';
    const secretText = channelOf() === 'totp' ? auth?.totpSecret || state.totpSecret || '' : '';
    const out = {
      phone: masked,
      channel: channelOf(),
      ready: Boolean(auth),
      // 长期密钥与它的二维码都是「第二因子本身」：默认一律不下发，
      // 只有显式 reveal=1（界面上点「显示」）才给一次，避免截屏/共享屏幕顺手带走。
      totpSecret: reveal ? secretText : '',
      totpSecretSet: secretText !== '',
      /** 密钥的「指纹」：用来一眼看出手机里那个条目是不是同一把。
       *  只暴露密钥的 sha256 前 8 位，无法反推密钥，但足够比对。 */
      secretTag: secretText ? createHash('sha256').update(secretText).digest('hex').slice(0, 8) : '',
      /** 服务端当前时间片和它对应的码，手机上可以直接对照。 */
      serverNow: Date.now(),
      serverCode: secretText ? currentCode(secretText) : '',
      serverSecondsLeft: secondsRemaining(),
      otpauthUrl: '',
      authenticatorQrSvg: '',
      loginUrl: tunnel.url ? `${tunnel.url}/` : '',
      lanUrls: bridgePort ? lanAddresses().map((ip) => `http://${ip}:${bridgePort}/`) : [],
      /** Tailscale 固定地址：装了 Tailscale 就用它，一个地址到处能用。 */
      tsUrls: bridgePort ? tailscaleAddresses().map((ip) => `http://${ip}:${bridgePort}/`) : [],
      /**
       * frp 中继地址（自建云服务器）。这是「出门也能用」的主力通路：
       * 中继延迟通常低于公网隧道，具体取决于你自己的服务器位置。
       * 地址存在状态文件里（`frpUrl`），可在设置页改。
       */
      frpUrls: state.frpUrl ? [String(state.frpUrl)] : [],
    };
    // 局域网二维码：手机在同 Wi-Fi 时扫这个，不走 Cloudflare。
    // 之前只给公网二维码，用户扫码就只能走公网 —— 这是「明明连着 Wi-Fi 却显示公网」的直接原因。
    out.lanQrSvgs = [];
    if (bridgePort && state.listenHost !== '127.0.0.1') {
      for (const ip of lanAddresses()) {
        const url = `http://${ip}:${bridgePort}/`;
        try { out.lanQrSvgs.push({ url, svg: toSvg(url, { scale: 4, margin: 2 }) }); } catch { /* 单个失败不影响其它 */ }
      }
    }
    // Tailscale 二维码：固定地址，但只在装了 Tailscale 的设备上可用，作为备选。
    out.tsQrSvgs = [];
    for (const url of out.tsUrls) {
      try { out.tsQrSvgs.push({ url, svg: toSvg(url, { scale: 4, margin: 2 }) }); } catch { /* 跳过 */ }
    }
    // frp 中继二维码：出门首选（延迟通常低于公网隧道）
    out.frpQrSvgs = [];
    for (const url of out.frpUrls) {
      try { out.frpQrSvgs.push({ url, svg: toSvg(url, { scale: 4, margin: 2 }) }); } catch { /* 跳过 */ }
    }
    if (out.loginUrl) {
      try { out.loginQrSvg = toSvg(out.loginUrl, { scale: 5, margin: 2 }); } catch { out.loginQrSvg = ''; }
    } else {
      out.loginQrSvg = '';
    }
    if (reveal && secretText) {
      try {
        const url = otpauthUrl({ secret: secretText, account: `${masked}@dsh` });
        out.otpauthUrl = url;
        out.authenticatorQrSvg = toSvg(url, { scale: 4, margin: 2 });
      } catch {
        out.otpauthUrl = '';
        out.authenticatorQrSvg = '';
      }
    }
    return out;
  };

  // 桥接上一次起来的错误。声明必须早于 statusOf：后者闭包里读它，
  // 声明写在后面的话，第一次调用会撞 TDZ 而不是报「桥接失败」。
  let lastBridgeError = '';

  const statusOf = () => {
    const phoneOk = /^1[3-9]\d{9}$/.test(phoneOf());
    return {
      ok: true,
      plugin: name,
      version: '1.0.0',
      phoneSet: phoneOk,
      phone: phoneOf() ? `${phoneOf().slice(0, 3)}****${phoneOf().slice(-4)}` : '',
      channel: channelOf(),
      secretSource,
      dshPort: ctx.webServer.port,
      // 没填手机号 = 用户还没开始用，这不是故障；只有填了号却起不来才算 failed
      bridge: bridge
        ? { state: 'up', port: bridgePort, relayPort: relayListenPort }
        : { state: phoneOk && lastBridgeError ? 'failed' : 'off', port: 0, relayPort: 0 },
      tunnel: tunnelView(),
      tunnelBinary: tunnelBinary() ? 'present' : 'missing',
      hasLoginSecret: Boolean(state.loginSecret),
      // 局域网入口只在桥接真的监听在非回环地址上时才有意义
      lanExposed: Boolean(bridge) && (state.listenHost || '') !== '127.0.0.1',
      // 最近从外部进来的客户端：能看出请求有没有到桥接、是 iPhone 还是脚本
      clients: bridge ? bridge.recentClients() : [],
      // frp 中继地址（自建云服务器）：出门首选通路
      frpUrl: String(state.frpUrl || ''),
      frpUrls: state.frpUrl ? [String(state.frpUrl)] : [],
    };
  };

  // ── 6. 设置接口 ──────────────────────────────────────────────────────────
  const routes = createRoutes({
    status: statusOf,
    pairing: pairingOf,
    enable: async () => {
      if (!bridge) {
        const started = await startBridge();
        if (!started.ok) { lastBridgeError = started.error; return { error: started.error, ...statusOf() }; }
        lastBridgeError = '';
      }
      const out = await enableTunnel();
      return { ...statusOf(), ...out };
    },
    // 「只走局域网」也是开：桥接起来就够了，没有隧道客户端不影响
    'enable-lan': async () => {
      if (bridge) return statusOf();
      const started = await startBridge();
      lastBridgeError = started.ok ? '' : started.error;
      if (!started.ok) return { ...statusOf(), error: started.error };
      return statusOf();
    },
    /**
     * 两条入口一起起：局域网（桥接监听 0.0.0.0）+ 公网（隧道）。
     *
     * 这是默认推荐的模式。用户不用先想「我在家还是在外面」：两条都通着，
     * 手机端按自己的网络情况去挑。隧道失败也不影响局域网可用 —— 所以这里
     * 桥接失败才算真失败，隧道失败只记录原因。
     */
    'enable-both': async () => {
      if (!bridge) {
        const started = await startBridge();
        if (!started.ok) { lastBridgeError = started.error; return { ...statusOf(), error: started.error }; }
        lastBridgeError = '';
      }
      const out = await enableTunnel();
      return { ...statusOf(), ...out };
    },
    /**
     * 关闭：隧道与桥接一起停。
     *
     * 只停隧道的话，局域网那条 `http://192.168.x.x:port` 还开着 —— 用户点了「关闭」却仍能被
     * 同 Wi-Fi 的设备访问，这跟按钮说的不是一回事。停桥接才真的是「这条通道没了」；
     * 已经发出去的登录 cookie 仍有效，要连它一起作废用 `signoutAll`。
     */
    disable: async () => {
      const out = await disableTunnel();
      stopBridge();
      lastBridgeError = '';
      return { ...statusOf(), ...out };
    },
    /**
     * 注销所有已登录设备。
     *
     * 「关闭」只是关掉公网入口 —— 局域网那条 `http://192.168.x.x:port` 仍然可达，已经发出去的
     * 30 天 cookie 也仍然有效。手机丢了、或者怀疑密钥泄露时，用户真正需要的是这一条：
     * 轮换登录签名密钥，所有会话立刻作废，下次必须重新走验证器。
     */
    signoutAll: async () => {
      state.loginSecret = randomBytes(32).toString('base64url');
      saveState(state);
      // 统一走 disableTunnel：它会递增隧道代次、作废在途的 enable，
      // 且置 off 后子进程的 exit 不会再被 onExit 误报成「失败」。
      await disableTunnel();
      stopBridge();
      lastBridgeError = '';
      if (/^1[3-9]\d{9}$/.test(phoneOf())) {
        const started = await startBridge();
        lastBridgeError = started.ok ? '' : started.error;
      }
      return { ...statusOf(), signedOut: true };
    },
    /**
     * 手机端主动断开：作废当前这枚登录 cookie，但不动隧道与桥接。
     *
     * 为什么和 disable 分开：用手机点「断开」时，用户的本意是「这台设备下次要重新验证」，
     * 而不是「把电脑上的入口全关掉」（那样在电脑旁边的人也会被踢）。真要收掉入口是 disable。
     */
    logout: async () => ({ ok: true, loggedOut: true }),
    configure: async (body) => {
      // 空串/undefined = 「不改」，只有显式传了非空字符串才算改。
      // 这样界面留空保存不会把已配好的号码清掉。
      const clearPhone = body.clear === true;
      const hasPhone = Object.hasOwn(body, 'phone') && typeof body.phone === 'string' && body.phone.trim() !== '';
      const phone = clearPhone ? '' : (hasPhone ? body.phone.trim() : phoneOf());
      if (hasPhone && !/^1[3-9]\d{9}$/.test(phone)) throw new Error('手机号看着不对（要 11 位、1 开头）');
      const channel = String(body.channel ?? channelOf()).trim();
      if (!['totp', 'console'].includes(channel)) throw new Error(`不认识的验证码通道：${channel}`);
      const phoneChanged = phone !== phoneOf();
      const channelChanged = channel !== channelOf();
      // frp 地址：空串 = 不改；显式 frpUrl 才覆盖，clear 时配合 true 清空
      const hasFrp = Object.hasOwn(body, 'frpUrl') && typeof body.frpUrl === 'string' && body.frpUrl.trim() !== '';
      const frp = hasFrp ? body.frpUrl.trim() : String(state.frpUrl || '');
      if (hasFrp && !/^https?:\/\/[^\s]+$/i.test(frp)) throw new Error('frp 地址要带 http:// 或 https:// 前缀');
      const frpChanged = frp !== String(state.frpUrl || '');
      if (!phoneChanged && !channelChanged && !frpChanged && bridge) return statusOf();

      // 配置改变会重建桥接：公网隧道必须先停，不能让旧 URL 静默指向旧端口。
      await disableTunnel();
      state.loginPhone = phone;
      state.loginChannel = channel;
      if (hasFrp || body.clearFrp === true) state.frpUrl = hasFrp ? frp : '';
      saveState(state);
      stopBridge();
      // 清空手机号 = 主动停用：这时候「桥接没起来」不是故障，别把它记成失败
      if (!phone) {
        lastBridgeError = '';
        return statusOf();
      }
      const started = await startBridge();
      lastBridgeError = started.ok ? '' : started.error;
      if (!started.ok) return { ...statusOf(), error: started.error };
      return statusOf();
    },
  });

  for (const route of routes) {
    ctx.effect(() => ctx.webServer.register(route), `remote-link: ${route.path}`);
  }

  // ── 7. 起来 ──────────────────────────────────────────────────────────────
  const phone = phoneOf();
  if (/^1[3-9]\d{9}$/.test(phone)) {
    const started = await startBridge();
    if (!started.ok) {
      lastBridgeError = started.error;
      log(`桥接没起来：${started.error}`);
    } else {
      log(`桥接就绪：${state.listenHost || '0.0.0.0'}:${bridgePort} → DSH 127.0.0.1:${ctx.webServer.port}`);
      if (auth?.totpIsNew) {
        log('首次配置：请在设置 → 远程链接 里扫码把登录器加进手机（只做一次）。');
      }
      if (cfg.autoTunnel === true) await enableTunnel();
    }
  } else {
    log('还没配置登录手机号：打开 设置 → 远程链接 填一个，然后开启。');
  }

  // 插件被卸载 / DSH 退出时把隧道与桥接收干净，不留孤儿进程
  ctx.effect(() => () => {
    stopTunnel(tunnelChild);
    tunnelChild = null;
    stopBridge();
  }, 'remote-link: teardown');
}
