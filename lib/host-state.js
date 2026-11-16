/**
 * 宿主侧：状态落盘、凭据、隧道进程、桥接起停。
 *
 * 为什么宿主侧要管这些：DSH 已经把 web 服务、凭据服务、进程能力都开在宿主里了，
 * 插件挂在宿主上就能直接复用；界面那一半只读状态、只发动作，不碰文件与进程。
 */
import { spawn, execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, networkInterfaces } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_DIR = join(HERE, '..');

/** 状态文件：沿用 ~/.dsh 下的位置，卸载插件不删它（下次装回来还是同一份登录密钥）。 */
export function stateFile() {
  const home = process.env.DSH_HOME || join(homedir(), '.dsh');
  return join(home, 'remote-link.json');
}

export function loadState() {
  try {
    const raw = JSON.parse(readFileSync(stateFile(), 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch {
    return {};
  }
}

/**
 * 落盘。**只写自己那一份文件**，不碰 profile 的任何配置：
 * 这里存的是这个插件自己的运行时状态（登录密钥、隧道地址、开关），
 * 不涉及 DSH 的组合层，所以不需要走 configEditor。
 */
export function saveState(state) {
  const file = stateFile();
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
    return true;
  } catch (error) {
    // 写盘失败不能静默：调用方以为配好了，重启后手机号/密钥却不见了。
    console.error(`[remote-link] 状态文件写入失败（${file}）：${error?.message || error}`);
    return false;
  }
}

/** 首次运行生成登录签名密钥；已有就复用（否则所有设备每次重启都要重登）。 */
export function ensureLoginSecret(state) {
  if (typeof state.loginSecret === 'string' && state.loginSecret.length >= 20) return state.loginSecret;
  state.loginSecret = randomBytes(32).toString('base64url');
  saveState(state);
  return state.loginSecret;
}

/** 隧道客户端位置：包内 `bin/`，按平台挑名字。 */
export function tunnelBinary() {
  const name = process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared';
  const candidate = join(PACKAGE_DIR, 'bin', name);
  return existsSync(candidate) ? candidate : null;
}

/**
 * 起一条 quick tunnel，等它打印出 `https://xxx.trycloudflare.com` 后回地址。
 *
 * 用 quick tunnel 而不是 named tunnel 的原因：named 要先 `cloudflared tunnel login`，
 * 那是浏览器里点着授权的一套流程，放进插件里就把「双击可用」变成了「先配置」。
 * quick tunnel 的唯一代价是域名每次重启都变——对「今天要看一眼手机」这件事够用，
 * 想要固定域名的人可以把 quick tunnel 替换成自己的 named tunnel；当前插件只提供 quick tunnel。
 *
 * @returns {Promise<{ ok: true, url: string, child: import('node:child_process').ChildProcess } | { ok: false, error: string }>}
 */
export function startTunnel({ targetPort, log = () => {}, onExit = null } = {}) {
  const binary = tunnelBinary();
  if (!binary) return Promise.resolve({ ok: false, error: '包内没有隧道客户端（bin/cloudflared）' });
  return new Promise((resolve) => {
    let settled = false;
    let child;
    try {
      child = spawn(binary, ['tunnel', '--url', `http://127.0.0.1:${targetPort}`, '--no-autoupdate'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (error) {
      resolve({ ok: false, error: `隧道客户端起不来：${error.message}` });
      return;
    }
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ ...result, child });
    };
    const scan = (chunk) => {
      const text = String(chunk);
      const hit = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i.exec(text);
      if (hit) finish({ ok: true, url: hit[0] });
    };
    child.stdout?.on('data', scan);
    child.stderr?.on('data', scan);
    child.on('error', (error) => finish({ ok: false, error: `隧道客户端出错：${error.message}` }));
    child.on('exit', (code) => {
      if (!settled) finish({ ok: false, error: `隧道客户端退出（code=${code}）` });
      else log(`隧道客户端退出（code=${code}）`);
      if (typeof onExit === 'function') onExit(code);
    });
    // 20 秒还没拿到域名就判失败：再等下去用户只会以为插件卡死了
    timer = setTimeout(() => {
      finish({ ok: false, error: '隧道 20 秒内没拿到地址（可能是网络受限）' });
      if (child) stopTunnel(child);
    }, 20000);
  });
}

/** 停隧道：先礼后兵，Windows 上不杀整棵树的子进程会留在后台。 */
export function stopTunnel(child) {
  if (!child) return;
  try {
    if (process.platform === 'win32') spawn('taskkill', ['/pid', String(child.pid), '/f', '/t'], { windowsHide: true, stdio: 'ignore' });
    else child.kill('SIGTERM');
  } catch { /* 已经退出 */ }
}

/** 局域网 IPv4 候选（只挑 RFC1918 里手机真能拨到的那几段）。 */
export function lanAddresses() {
  const out = [];
  const interfaces = networkInterfaces();
  for (const list of Object.values(interfaces)) {
    for (const item of list || []) {
      if (item.family !== 'IPv4' || item.internal) continue;
      if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(item.address)) continue;
      out.push(item.address);
    }
  }
  return out;
}

/**
 * Tailscale 地址（100.64.0.0/10 的 CGNAT 段）。
 *
 * 为什么优先用它：这个地址**固定不变**，而且在家能直连、在外面走 WireGuard 打洞，
 * Tailscale 直连通常比公网隧道更快，具体取决于你的网络。
 * 更重要的是它消除了「局域网 / 公网二选一」—— 一个地址到处用。
 */
export function tailscaleAddresses() {
  const out = [];
  const interfaces = networkInterfaces();
  for (const [name, list] of Object.entries(interfaces)) {
    if (!/tailscale/i.test(name)) continue;
    for (const item of list || []) {
      if (item.family !== 'IPv4' || item.internal) continue;
      // 100.64.0.0/10：Tailscale 分配的全部落在这段里
      if (!/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(item.address)) continue;
      out.push(item.address);
    }
  }
  return out;
}

/**
 * 这条 Tailscale 链路现在到底是「直连」还是「走中继」。
 *
 * 为什么要这个：用户在 5G 下打洞失败，Tailscale 会静默退到香港中继（670ms~2s），
 * 而界面上如果还写“局域网直连”，是在骗人。这里读 `tailscale status --json`
 * 的 peer 信息，`CurAddr` 非空 = 直连；只有 `Relay` = 中继。
 *
 * 拿不到就返回 null（上层显示“未知”，绝不猜成直连）。
 */
let tsPathCache = { value: null, at: 0 };
/**
 * 探测 Tailscale 链路状态。
 *
 * 教训：Tailscale 服务停掉后，`tailscale status --json` 不会立刻报错，而是**卡到超时**
 * （这一步有固定开销）。而 `/__ping` 会等这个结果才返回，于是「测延迟」的接口
 * 自己就可能固定消耗一段时间 —— 状态条上的延迟数字会包含这个开销，未必全是网络问题。
 *
 * 所以这里两道闸：
 *   1. 先看服务是否在跑，不在就直接回 null（不做任何子进程调用）；
 *   2. 真在跑时也只给 1.5 秒超时，且结果缓存 30 秒，不让它拖慢其他请求。
 */
export async function tailscalePath() {
  const now = Date.now();
  if (tsPathCache.at && now - tsPathCache.at < 30000) return tsPathCache.value;

  // 快路径：服务没在跑就立即返回（绝大多数用户根本没装 Tailscale）
  const running = await new Promise((resolve) => {
    try {
      const child = execFile('sc.exe', ['query', 'Tailscale'], { timeout: 1200, windowsHide: true },
        (error, stdout) => resolve(!error && /RUNNING/i.test(String(stdout || ''))));
      child.on('error', () => resolve(false));
    } catch { resolve(false); }
  });
  if (!running) { tsPathCache = { value: null, at: now }; return null; }

  const bin = [
    'C:\\Program Files\\Tailscale\\tailscale.exe',
    'C:\\Program Files (x86)\\Tailscale\\tailscale.exe',
  ].find((p) => existsSync(p));
  if (!bin) { tsPathCache = { value: null, at: now }; return null; }
  try {
    const { stdout } = await execFileAsync(bin, ['status', '--json'], { timeout: 1500, windowsHide: true });
    const parsed = JSON.parse(stdout);
    const peers = Object.values(parsed?.Peer || {});
    const online = peers.filter((p) => p?.Online);
    if (!online.length) { tsPathCache = { value: 'no-peer', at: now }; return 'no-peer'; }
    const peer = online[0];
    const direct = Boolean(peer.CurAddr);
    const value = direct ? 'direct' : (peer.Relay ? `relay:${peer.Relay}` : 'relay');
    tsPathCache = { value, at: now };
    return value;
  } catch {
    tsPathCache = { value: null, at: now };
    return null;
  }
}

/**
 * 这台电脑的公网出口 IP（带 60 秒缓存）。
 *
 * 用途只有一个：判断「手机和电脑是不是从同一个出口上网」——
 * 是的话说明手机大概率在家，值得提示切换到局域网直连。
 *
 * 坑：必须强制要 IPv4。家里宽带是双栈时，Cloudflare 的 trace 会回 IPv6
 * （IPv6 形式），而手机经隧道带来的 `cf-connecting-ip` 通常是 IPv4，
 * 两者永远不可能相等 —— 结果是「明明在同一个 Wi-Fi，却一直判定不在家」。
 * 所以这里用 `--edge-ip-version` 拿不到，就退而用专门的 IPv4 探测源。
 */
let publicIpCache = { value: '', at: 0 };
export async function publicIp() {
  const now = Date.now();
  if (publicIpCache.value && now - publicIpCache.at < 60000) return publicIpCache.value;

  const onlyV4 = (text) => {
    const m = /(?:^|[^0-9.])((?:\d{1,3}\.){3}\d{1,3})(?:[^0-9.]|$)/.exec(text);
    return m ? m[1] : '';
  };

  const sources = [
    // www.cloudflare.com 在双栈下会回 IPv4，比裸 cloudflare.com 稳
    async () => {
      const t = await (await fetch('https://www.cloudflare.com/cdn-cgi/trace', { signal: AbortSignal.timeout(4000) })).text();
      const m = /^ip=(.+)$/m.exec(t);
      return m ? onlyV4(m[1]) : '';
    },
    // 明确只接受 IPv4 的源（国内可达）
    async () => onlyV4(await (await fetch('https://ipv4.icanhazip.com', { signal: AbortSignal.timeout(4000) })).text()),
    async () => onlyV4(await (await fetch('https://api.ipify.org', { signal: AbortSignal.timeout(4000) })).text()),
  ];

  for (const source of sources) {
    try {
      const value = String(await source() || '').trim();
      if (value) {
        publicIpCache = { value, at: now };
        return value;
      }
    } catch { /* 换下一个源 */ }
  }
  // 全都拿不到就返回空串：上层一律当作「不知道」，不猜、不乱提示
  publicIpCache = { value: '', at: now };
  return '';
}
