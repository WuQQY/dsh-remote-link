/**
 * 客户端那一半：设置 → 远程链接。
 *
 * 一页四块，按用户真正要做的顺序排：
 *   1. 登录方式（手机号 + 验证器通道，第一次配，配好不再动）
 *   2. 开 / 关（起桥接 + 起隧道，拿到链接；也可以只开局域网）
 *   3. 扫码（加进验证器的那个 + 手机打开链接的那个）
 *   4. 安全边界（含「注销所有设备」）
 *
 * 不写 JSX：这个文件不经构建，直接用 `React.createElement` 的别名 `h`。
 * 样式走宿主的 `--dsw-alias-*` 主题变量，明暗两套自动跟着走；类名统一 `dshrl_` 前缀。
 *
 * 两条与安全相关的界面纪律（改的时候别破坏）：
 *   · 长期 TOTP 密钥与它的二维码**默认不请求、不渲染**，必须点「显示」才要一次；
 *   · 已保存的手机号只以打码形式显示在说明里，**绝不回填进可编辑输入框** ——
 *     回填会让用户第二次点保存时拿 `138****8000` 去校验，必然报错。
 *
 * 连接状态胶囊（侧边栏底部那个圆点 + 延迟）走的是外壳官方槽
 * `sidebar.footer.action`，不再是页面里 injected 的 fixed 浮层。
 * 原因见 `ConnectionCapsule` 上面那段注释：往 React 管的容器里塞节点，重渲染就丢。
 */

window.__ModuleLoader__.load({
  id: 'dsh-remote-link',
  factory(require) {
    const {
      createElement: h,
      useCallback,
      useEffect,
      useMemo,
      useRef,
      useState,
    } = require('react');

    const NS = 'settings.remoteLink';
    // 相对路径：桌面外壳把网页挂在 `dsh-app://app/` 下，写绝对 `/api/...` 会解析到自定义协议上。
    // 页面里有 `<base href="./">`，所以相对地址在两种载体上都落到同一个源。
    const API = 'api/remote-link';

    const DICT = {
      zh: {
        nav: '远程链接',
        heading: '远程链接',
        lead: '开一条只有你能进的网页链接，在手机浏览器里接着用这台电脑的 DSH —— 同一个工作区、同一个会话，能对话、能看实时输出、能点审批、能改权限。',
      },
      en: {
        nav: 'Remote link',
        heading: 'Remote link',
        lead: "Open a link only you can enter, and continue this computer's DSH from a phone browser: same workspace, same session, with chat, live output, approvals, and permission changes.",
      },
    };

    const CSS = `
.dshrl_root{display:flex;flex-direction:column;gap:14px;width:100%;max-width:760px;box-sizing:border-box;color:var(--dsw-alias-label-primary)}
.dshrl_heading{margin:0;font-size:16px;font-weight:600;line-height:24px}
.dshrl_lead{margin:0;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary)}
.dshrl_card{box-sizing:border-box;display:flex;flex-direction:column;gap:10px;padding:12px 14px;border-radius:var(--dsw-radius-xl,12px);border:.5px solid var(--dsw-alias-settings-card-stroke);background:var(--dsw-alias-settings-card-fill)}
.dshrl_cardTitle{margin:0;font-size:14px;font-weight:600;line-height:22px}
.dshrl_note{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
.dshrl_row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.dshrl_label{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);min-width:72px}
.dshrl_input{flex:1;min-width:180px;box-sizing:border-box;padding:8px 10px;font:inherit;font-size:13px;border-radius:var(--dsw-radius-sm,8px);border:1px solid var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary)}
.dshrl_input:focus{outline:var(--dsw-focus-ring-width,2px) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:-1px}
.dshrl_select{min-width:150px;box-sizing:border-box;padding:8px 10px;font:inherit;font-size:13px;border-radius:var(--dsw-radius-sm,8px);border:1px solid var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary)}
.dshrl_btn{font:inherit;font-size:13px;line-height:18px;padding:8px 14px;border-radius:var(--dsw-radius-sm,8px);cursor:pointer;border:1px solid var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary)}
.dshrl_btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
.dshrl_btn:focus-visible{outline:var(--dsw-focus-ring-width,2px) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:1px}
.dshrl_btn:disabled{opacity:.45;cursor:default}
.dshrl_btnPrimary{border-color:transparent;background:var(--dsw-alias-state-business-primary);color:#fff}
.dshrl_btnPrimary:hover:not(:disabled){opacity:.9;background:var(--dsw-alias-state-business-primary)}
.dshrl_badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;line-height:18px;padding:3px 9px;border-radius:999px;border:.5px solid var(--dsw-alias-border-l3)}
.dshrl_dot{width:7px;height:7px;border-radius:999px;background:var(--dsw-alias-label-tertiary)}
.dshrl_dotUp{background:var(--dsw-alias-state-business-primary)}
.dshrl_dotWarn{background:var(--dsw-alias-state-warning-primary)}
.dshrl_dotErr{background:var(--dsw-alias-state-error-primary)}
.dshrl_qrBox{display:flex;gap:16px;flex-wrap:wrap}
.dshrl_qrSection{display:flex;flex-direction:column;gap:8px;padding:12px;border-radius:var(--dsw-radius-md,10px);border:.5px dashed var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1)}
.dshrl_qrCell{display:flex;flex-direction:column;gap:8px;align-items:flex-start;box-sizing:border-box;padding:12px;border-radius:var(--dsw-radius-md,10px);border:.5px solid var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1)}
.dshrl_qrTitle{margin:0;font-size:12px;font-weight:600;line-height:18px}
/* 二维码必须保持白底与静区：跟随暗色主题会扫不出来，这里刻意硬编码。 */
.dshrl_qrSvg{display:block;width:168px;height:168px;border-radius:6px;overflow:hidden;background:#fff}
.dshrl_qrSvg svg{display:block;width:100%;height:100%}
.dshrl_code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:18px;word-break:break-all;padding:8px 10px;border-radius:8px;background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l3);user-select:all}
.dshrl_link{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:18px;word-break:break-all;user-select:all;color:var(--dsw-alias-label-primary)}
.dshrl_error{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary)}
.dshrl_ok{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-state-business-primary)}
.dshrl_steps{margin:0;padding-left:18px;font-size:12px;line-height:20px;color:var(--dsw-alias-label-secondary)}
.dshrl_steps li{margin:2px 0}
.dshrl_check{margin-top:4px;padding:12px;border-radius:var(--dsw-radius-md,10px);border:1px dashed var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1);display:flex;flex-direction:column;gap:8px}
.dshrl_lanBox{margin-top:6px;padding:12px;border-radius:var(--dsw-radius-md,10px);border:1px solid var(--dsw-alias-state-business-primary);background:rgba(77,107,254,.06);display:flex;flex-direction:column;gap:8px}
.dshrl_tsBox{margin-top:6px;padding:12px;border-radius:var(--dsw-radius-md,10px);border:1.5px solid var(--dsw-alias-state-business-primary);background:rgba(55,214,122,.08);display:flex;flex-direction:column;gap:8px}
.dshrl_checkTitle{margin:0;font-size:12px;font-weight:600;line-height:18px}
.dshrl_bigCode{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:20px;font-weight:600;letter-spacing:2px;line-height:26px;color:var(--dsw-alias-state-business-primary);user-select:all}
`;

    /**
     * 胶囊自己的样式：独立一段，不跟设置页那套混在一起。
     *
     * 为什么必须分开：设置页的 `<style>` 只在设置页渲染时才有用；胶囊长在侧边栏底部，
     * 如果共用同一段 CSS，每次侧边栏渲染都会把整段设置页样式塞进那个小小的一格里
     * （`textContent` 里能看到 `.dshrl_root{...}`，既浪费也让调试时看见一堆无关文本）。
     */
    const CAPSULE_CSS = `
/* 侧边栏底部的连接状态胶囊。宽度跟着外壳那一行走，不自己定死。 */
.dshrl_cap{position:relative;display:flex;flex-direction:column;gap:6px;flex:1 1 auto;min-width:0}
.dshrl_capBtn{display:flex;align-items:center;gap:6px;width:100%;box-sizing:border-box;padding:5px 8px;font:inherit;font-size:11.5px;line-height:16px;color:var(--dsw-alias-label-secondary);background:transparent;border:none;border-radius:var(--dsw-radius-sm,8px);cursor:pointer;text-align:left}
.dshrl_capBtn:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.dshrl_capBtn:focus-visible{outline:var(--dsw-focus-ring-width,2px) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:-2px}
.dshrl_capDot{flex:none;width:7px;height:7px;border-radius:999px;background:var(--dsw-alias-label-tertiary)}
.dshrl_capDotUp{background:var(--dsw-alias-state-business-primary)}
.dshrl_capDotWarn{background:var(--dsw-alias-state-warning-primary)}
.dshrl_capDotErr{background:var(--dsw-alias-state-error-primary)}
.dshrl_capText{flex:none;white-space:nowrap}
.dshrl_capRtt{flex:none;color:var(--dsw-alias-label-tertiary);font-variant-numeric:tabular-nums}
.dshrl_capArrow{margin-left:auto;flex:none;font-size:9px;color:var(--dsw-alias-label-tertiary)}
.dshrl_capPanel{display:flex;flex-direction:column;gap:2px;padding:8px 10px;border-radius:var(--dsw-radius-sm,8px);border:.5px solid var(--dsw-alias-border-l3);background:var(--dsw-alias-bg-layer-1);font-size:11.5px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.dshrl_capRow{display:flex;justify-content:space-between;gap:8px}
.dshrl_capRow b{font-weight:500;color:var(--dsw-alias-label-primary)}
.dshrl_capNote{margin:4px 0 0;font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary)}
.dshrl_capWarn{margin:4px 0 0;font-size:11px;line-height:16px;color:var(--dsw-alias-state-warning-primary)}
.dshrl_capOut{margin-top:6px;width:100%;padding:6px 8px;font:inherit;font-size:11.5px;line-height:16px;cursor:pointer;color:var(--dsw-alias-state-error-primary);background:transparent;border:1px solid var(--dsw-alias-state-error-primary);border-radius:var(--dsw-radius-sm,8px)}
`;

    async function call(path, init) {
      const response = await fetch(`${API}${path}`, { credentials: 'same-origin', ...(init || {}) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = (body && body.error && body.error.message) || `HTTP ${response.status}`;
        const error = new Error(message);
        error.status = response.status;
        throw error;
      }
      return body;
    }

    const postJson = (path, payload) => call(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });

    /** 只保留合法的 11 位号码；其余一律当「没填」。 */
    const validPhone = (text) => /^1[3-9]\d{9}$/.test(String(text || '').trim());

    function RemoteLinkSection({ t }) {
      const [status, setStatus] = useState(null);
      const [pairing, setPairing] = useState(null);
      const [busy, setBusy] = useState('');
      const [problem, setProblem] = useState('');
      const [notice, setNotice] = useState('');
      /** 用户新输入的号码。空串 = 不改，沿用已保存的那个。 */
      const [phone, setPhone] = useState('');
      const [channel, setChannel] = useState('totp');
      /** 已保存号码的打码形态，只用于显示，不进输入框。 */
      const [savedPhone, setSavedPhone] = useState('');
      /** frp 中继地址：空串 = 不改；由用户填 https://ip:端口/ */
      const [frpInput, setFrpInput] = useState('');
      const [savedFrp, setSavedFrp] = useState('');
      /** 长期密钥与认证器二维码：默认不请求，点了才要一次。 */
      const [revealed, setRevealed] = useState(null);
      const channelTouched = useRef(false);
      const alive = useRef(true);

      const refresh = useCallback(async () => {
        try {
          const next = await call('/status');
          if (!alive.current) return;
          setStatus(next);
          setProblem('');
          setSavedPhone(typeof next.phone === 'string' ? next.phone : '');
          setSavedFrp(Array.isArray(next.frpUrls) && next.frpUrls.length ? next.frpUrls[0] : (next.frpUrl || ''));
          if (!channelTouched.current && typeof next.channel === 'string' && next.channel) setChannel(next.channel);
          // 非敏感部分：链接、局域网地址、二维码、是否已设置密钥。密钥原文不在这里拿。
          const pair = await call('/pairing');
          if (!alive.current) return;
          setPairing(pair);
        } catch (error) {
          if (alive.current) setProblem(String((error && error.message) || error));
        }
      }, []);

      useEffect(() => {
        alive.current = true;
        void refresh();
        // 页面开着的时候每 3 秒对一次状态：隧道可能在后台断、桥接端口可能变。
        const timer = setInterval(() => { if (!document.hidden) void refresh(); }, 3000);
        return () => { alive.current = false; clearInterval(timer); };
      }, [refresh]);

      const run = useCallback(async (label, action) => {
        setBusy(label);
        setProblem('');
        setNotice('');
        try {
          const next = await action();
          if (next && next.error) setProblem(String(next.error));
          await refresh();
          if (label === 'save') setNotice('已保存');
          if (label === 'signout') setNotice('已注销：所有手机都要重新过验证器');
        } catch (error) {
          setProblem(String((error && error.message) || error));
        } finally {
          setBusy('');
        }
      }, [refresh]);

      /** 保存：只发用户真输进来的号码；没输就只更新通道，不动已保存的手机号。 */
      const configure = useCallback(async () => {
        const payload = { channel };
        if (validPhone(phone)) payload.phone = phone.trim();
        if (frpInput.trim()) payload.frpUrl = frpInput.trim();
        const next = await postJson('/configure', payload);
        setPhone('');
        return next;
      }, [channel, phone, frpInput]);

      const save = () => run('save', configure);

      /**
       * 开启：如果输入框里有一个还没保存的新号码，先保存再开 ——
       * 否则服务端仍按「没有手机号」拒绝，用户看到的是莫名其妙的错误。
       */
      const enable = () => run('enable', async () => {
        if (validPhone(phone)) await configure();
        return postJson('/enable', {});
      });
      const enableLan = () => run('enable-lan', async () => {
        if (validPhone(phone)) await configure();
        return postJson('/enable-lan', {});
      });
      const disable = () => run('disable', () => postJson('/disable', {}));
      const signout = () => run('signout', () => postJson('/signout-all', {}));

      const showAuthenticator = () => run('reveal', async () => {
        const next = await call('/pairing?reveal=1');
        setRevealed({
          secret: next.totpSecret || '',
          url: next.otpauthUrl || '',
          qr: next.authenticatorQrSvg || '',
        });
        return {};
      });
      const hideAuthenticator = () => setRevealed(null);

      const tunnel = status && status.tunnel ? status.tunnel : { state: 'off', url: '', error: '', lanUrls: [] };
      const bridgeState = status && status.bridge ? status.bridge.state : 'off';
      const up = tunnel.state === 'up';
      const starting = tunnel.state === 'starting'
        || busy === 'enable' || busy === 'enable-lan' || busy === 'enable-both';
      const failed = tunnel.state === 'failed';
      const savedOk = validPhone(savedPhone) || (status && status.phoneSet === true);
      const noBinary = status && status.tunnelBinary === 'missing';
      const bridgeFailed = bridgeState === 'failed';
      const bridgeUp = bridgeState === 'up';

      const dotClass = (bridgeUp || up)
        ? 'dshrl_dot dshrl_dotUp'
        : (starting || !savedOk || bridgeFailed
          ? 'dshrl_dot dshrl_dotWarn'
          : (failed ? 'dshrl_dot dshrl_dotErr' : 'dshrl_dot'));
      /** 既没保存、输入框里也没有合法号码时才禁用开启 —— 有输入就先自动保存再开。 */
      const canEnable = savedOk || validPhone(phone);
      const stateText = !status
        ? '正在读取…'
        : busy === 'enable' || busy === 'enable-lan' || busy === 'enable-both'
          ? '正在开启…'
          : bridgeFailed
            ? '桥接没起来'
            : !savedOk
              ? '还没填手机号'
              : bridgeUp
                ? (up ? '已开启（局域网 + 中继 + Cloudflare 备用）' : '已开启（局域网 + 中继）')
                : starting
                  ? '正在开启…'
                  : failed
                    ? '桥接未开（备用隧道失败）'
                    : '已关闭';

      function qrCell(title, svg) {
        if (!svg) return null;
        return h('div', { className: 'dshrl_qrCell' },
          h('p', { className: 'dshrl_qrTitle' }, title),
          h('div', { className: 'dshrl_qrSvg', dangerouslySetInnerHTML: { __html: svg } }));
      }

      const hintText = useMemo(() => (
        validPhone(phone) ? '将替换已保存的号码' : (savedOk ? `已保存 ${savedPhone}` : '还没保存号码')
      ), [phone, savedOk, savedPhone]);

      return h('section', { className: 'dshrl_root' },
        h('style', { key: 'dshrl-style' }, CSS),

        h('div', null,
          h('h2', { className: 'dshrl_heading' }, t('heading')),
          h('p', { className: 'dshrl_lead' }, t('lead'))),

        // ── 1. 登录方式（先填号，再开）──────────────────────────────────────
        h('div', { className: 'dshrl_card' },
          h('h3', { className: 'dshrl_cardTitle' }, '1 · 登录方式'),
          h('p', { className: 'dshrl_note' },
            '手机号只是这台电脑上的登录标签，不等于 DeepSeek 账号。真正的凭据是手机验证器里那串 6 位数字 —— 它在外面也能用，不需要看电脑屏幕、不需要短信。'),
          h('div', { className: 'dshrl_row' },
            h('label', { className: 'dshrl_label', htmlFor: 'dshrl-phone' }, '手机号'),
            h('input', {
              id: 'dshrl-phone',
              className: 'dshrl_input',
              value: phone,
              inputMode: 'numeric',
              autoComplete: 'off',
              placeholder: savedOk ? `${savedPhone}（留空表示不改）` : '11 位手机号',
              onChange: (event) => setPhone(event.target.value.replace(/[^\d]/g, '').slice(0, 11)),
            })),
          h('div', { className: 'dshrl_row' },
            h('label', { className: 'dshrl_label', htmlFor: 'dshrl-channel' }, '验证码通道'),
            h('select', {
              id: 'dshrl-channel',
              className: 'dshrl_select',
              value: channel,
              onChange: (event) => { channelTouched.current = true; setChannel(event.target.value); },
            },
            h('option', { value: 'totp' }, '验证器 App（推荐）'),
            h('option', { value: 'console' }, '打印在本机终端'))),
          h('div', { className: 'dshrl_row' },
            h('label', { className: 'dshrl_label', htmlFor: 'dshrl-frp' }, '中继地址'),
            h('input', {
              id: 'dshrl-frp',
              className: 'dshrl_input',
              value: frpInput,
              placeholder: savedFrp ? `${savedFrp}（留空表示不改）` : 'https://relay.example.com:8080/',
              onChange: (event) => setFrpInput(event.target.value.trim()),
            })),
          h('p', { className: 'dshrl_note' },
            '填自建 frp 中继的公网地址。填好后设置页会多出一个「出门用这个」的二维码；留空则只有局域网入口。'),
          h('div', { className: 'dshrl_row' },
            h('button', { className: 'dshrl_btn', type: 'button', disabled: busy !== '', onClick: save },
              busy === 'save' ? '保存中…' : '保存'),
            h('span', { className: 'dshrl_note' }, hintText)),
          channel === 'console'
            ? h('p', { className: 'dshrl_note' }, '这个通道把验证码打进跑着 DSH 的那个终端窗口 —— 你不在电脑旁边就看不到它。')
            : null),

        // ── 2. 开关 ─────────────────────────────────────────────────────────
        h('div', { className: 'dshrl_card' },
          h('h3', { className: 'dshrl_cardTitle' }, '2 · 开 / 关'),
          h('div', { className: 'dshrl_row' },
            h('span', { className: 'dshrl_badge' },
              h('span', { className: dotClass, 'aria-hidden': 'true' }),
              stateText),
            status && status.dshPort
              ? h('span', { className: 'dshrl_note' }, `DSH 端口 ${status.dshPort}`)
              : null,
            bridgeUp
              ? h('span', { className: 'dshrl_note' }, `桥接 ${status.bridge.port}`)
              : null),
          h('div', { className: 'dshrl_row' },
            h('button', {
              className: 'dshrl_btn dshrl_btnPrimary',
              type: 'button',
              disabled: busy !== '' || starting || !canEnable || bridgeUp,
              onClick: enableLan,
            }, busy === 'enable-lan' ? '正在开启…' : bridgeUp ? '已开启' : '开启（局域网 + 中继）'),
            h('button', {
              className: 'dshrl_btn',
              type: 'button',
              disabled: busy !== '' || (!bridgeUp && tunnel.state !== 'starting'),
              onClick: disable,
            }, busy === 'disable' ? '正在关闭…' : '关闭并断开'),
            h('button', { className: 'dshrl_btn', type: 'button', disabled: busy !== '', onClick: () => void refresh() }, '刷新')),
          h('p', { className: 'dshrl_note' },
            '「开启」只拉起桥接；出门用的公网入口由 Windows 服务 dsh-frp 常驻（开机自启），两者合起来就是完整通路。'
            + '「关闭并断开」会收掉桥接——中继也会随即失效；已登录的设备要等会话过期，想立刻踢掉用「注销所有设备」。'),
          h('div', { className: 'dshrl_row' },
            h('button', {
              className: 'dshrl_btn',
              type: 'button',
              disabled: busy !== '' || starting || noBinary || !canEnable,
              onClick: enable,
            }, busy === 'enable' ? '正在开启…' : up ? 'Cloudflare 备用隧道已开' : '临时开 Cloudflare 备用隧道'),
            h('span', { className: 'dshrl_note' },
              '只在中继出问题时临时用；它是免费的兜底通道，延迟通常高于自建中继。')),
          !savedOk && !validPhone(phone)
            ? h('p', { className: 'dshrl_note' }, '先在上面填并保存手机号，才能开启。')
            : null,
          bridgeFailed
            ? h('p', { className: 'dshrl_error' }, '桥接没起来（端口可能被占）。重启一次 DSH，或改用「仅局域网」试试。')
            : null,
          noBinary
            ? h('p', { className: 'dshrl_error' }, '这个安装里没有隧道客户端（bin/cloudflared），所以只能走局域网。')
            : null,
          failed && tunnel.error ? h('p', { className: 'dshrl_error' }, `隧道：${tunnel.error}`) : null,
          problem ? h('p', { className: 'dshrl_error' }, problem) : null,
          notice ? h('p', { className: 'dshrl_ok' }, notice) : null),

        // ── 3. 扫码 ─────────────────────────────────────────────────────────
        // 三块二维码同处一张卡片，顺序按「用到的先后」排：
        //   ① 认证器（绑定动态验证，只做一次）—— 默认隐藏，点按钮才显示，可再隐藏
        //   ② 自建中继（出门用）—— 常显
        //   ③ 局域网（在家用）—— 常显
        // 渲染条件只看「有没有任何一块内容」，不再绑死 Cloudflare 那个码 ——
        // 之前就是因为只看 Cloudflare，一关隧道整张卡片（含中继码）全被藏掉。
        (pairing && (pairing.totpSecretSet
          || (pairing.frpQrSvgs && pairing.frpQrSvgs.length)
          || (pairing.lanQrSvgs && pairing.lanQrSvgs.length)
          || (pairing.tsQrSvgs && pairing.tsQrSvgs.length)
          || pairing.loginQrSvg))
          ? h('div', { className: 'dshrl_card' },
            h('h3', { className: 'dshrl_cardTitle' }, '3 · 扫码'),

            // ① 认证器：可隐藏。密钥与二维码都是第二因子本身，默认不摊在屏幕上。
            h('div', { className: 'dshrl_qrSection' },
              h('div', { className: 'dshrl_row' },
                h('p', { className: 'dshrl_qrTitle' }, '① 认证器二维码（绑定动态验证，只做一次）'),
                revealed
                  ? h('button', { className: 'dshrl_btn', type: 'button', onClick: hideAuthenticator }, '隐藏')
                  : h('button', {
                    className: 'dshrl_btn', type: 'button', disabled: busy !== '', onClick: showAuthenticator,
                  }, pairing.totpSecretSet ? '显示' : '还没有密钥')),
              revealed?.qr
                ? h('div', { className: 'dshrl_qrBox' },
                  qrCell('用验证器 App 扫', revealed.qr))
                : h('p', { className: 'dshrl_note' },
                  '已隐藏。密钥与它的二维码等于第二因子，设置页经常开着，平铺等于一次截屏就送人，所以默认不显示。'),
              revealed && revealed.secret
                ? h('div', { className: 'dshrl_code' }, revealed.secret)
                : null,
              revealed
                ? h('p', { className: 'dshrl_note' }, '别截图、别共享屏幕。加进验证器 App 后就不用再管这块了。')
                : null),

            // ② 自建中继：出门首选，常显
            (pairing.frpQrSvgs && pairing.frpQrSvgs.length)
              ? h('div', { className: 'dshrl_tsBox' },
                h('p', { className: 'dshrl_checkTitle' }, '② 出门用这个（自建中继，最快最稳）'),
                h('p', { className: 'dshrl_note' },
                  '流量经你自己搭建的中继服务器中转。',
                  '手机任意网络都能用，不需要装任何 App。'),
                h('div', { className: 'dshrl_qrBox' },
                  ...pairing.frpQrSvgs.map((item) => h('div', { className: 'dshrl_qrCell', key: item.url },
                    h('p', { className: 'dshrl_qrTitle' }, '用手机相机扫'),
                    h('div', { className: 'dshrl_qrSvg', dangerouslySetInnerHTML: { __html: item.svg } }),
                    h('p', { className: 'dshrl_note' }, item.url))))
              )
              : null,

            // ③ 局域网：在家用，常显
            (pairing.lanQrSvgs && pairing.lanQrSvgs.length)
              ? h('div', { className: 'dshrl_lanBox' },
                h('p', { className: 'dshrl_checkTitle' }, '③ 在家用这个（局域网，最快）'),
                h('p', { className: 'dshrl_note' },
                  '手机和电脑连同一个 Wi-Fi 时扫这个，直接连这台电脑，延迟约 3–10ms。'),
                h('div', { className: 'dshrl_qrBox' },
                  ...pairing.lanQrSvgs.map((item, index) => h('div', { className: 'dshrl_qrCell', key: item.url },
                    h('p', { className: 'dshrl_qrTitle' }, index === 0 ? '用手机相机扫' : `备用网卡 ${index + 1}`),
                    h('div', { className: 'dshrl_qrSvg', dangerouslySetInnerHTML: { __html: item.svg } }),
                    h('p', { className: 'dshrl_note' }, item.url)))),
                h('p', { className: 'dshrl_note' },
                  '局域网是明文 HTTP，只在自家 Wi-Fi 用；出门请扫上面那个自建中继。'))
              : null,

            pairing.loginUrl
              ? h('div', null,
                h('p', { className: 'dshrl_note' }, 'Cloudflare 备用隧道链接（慢，仅在自建中继出问题时临时用）：'),
                h('div', { className: 'dshrl_link' }, pairing.loginUrl))
              : null,
            h('ol', { className: 'dshrl_steps' },
              h('li', null, '先用验证器 App 扫「①」，把这个账号加进去（只做一次，之后可一直隐藏）。'),
              h('li', null, '出门扫「②」、在家扫「③」，Safari 打开后填验证器里那 6 位数字。'),
              h('li', null, '进去之后点 Safari 的分享 → 添加到主屏幕，以后点图标就用。')),

            // 自检：把「这台电脑此刻算出的码」摊开，和手机验证器一比就知道差在哪
            (pairing && pairing.totpSecretSet)
              ? h('div', { className: 'dshrl_check' },
                h('p', { className: 'dshrl_checkTitle' }, '对不上？用这里自检'),
                h('div', { className: 'dshrl_row' },
                  h('span', { className: 'dshrl_label' }, '电脑此刻的码'),
                  h('span', { className: 'dshrl_bigCode' }, pairing.serverCode || '——'),
                  h('span', { className: 'dshrl_note' }, `${pairing.serverSecondsLeft || 0} 秒后换`)),
                revealed && revealed.secret
                  ? h('p', { className: 'dshrl_note' }, `密钥指纹 ${pairing.secretTag || ''}（手机 App 里那个条目的指纹应当一致）`)
                  : null,
                h('ol', { className: 'dshrl_steps' },
                  h('li', null, '把上面这 6 位数字，和手机验证器里「同一时刻」显示的 6 位数字比。'),
                  h('li', null, h('b', null, '完全不一样'), ' → 手机里存的是旧密钥。删掉旧条目，点「显示认证器」重新扫一次。'),
                  h('li', null, h('b', null, '差一个时间片（约 30 秒错位）'), ' → 手机时间不准，打开「自动设置日期与时间」。'),
                  h('li', null, h('b', null, '一样'), ' → 那就能登录；如果还失败，多半是那个码刚用过（同一码不能重复用）。')),
                h('button', {
                  className: 'dshrl_btn', type: 'button', disabled: busy !== '',
                  onClick: async () => {
                    try {
                      const next = await call('/pairing?reveal=1');
                      setRevealed({ secret: next.totpSecret || '', url: next.otpauthUrl || '', qr: next.authenticatorQrSvg || '' });
                      await refresh();
                    } catch (error) {
                      setProblem(String((error && error.message) || error));
                    }
                  },
                }, '刷新这个码'))
              : null)
          : null,

        // ── 4. 安全边界 ─────────────────────────────────────────────────────
        h('div', { className: 'dshrl_card' },
          h('h3', { className: 'dshrl_cardTitle' }, '4 · 要知道的几件事'),
          h('ol', { className: 'dshrl_steps' },
            h('li', null, '拿到你手机（且能解锁、能打开验证器）的人就能进这台电脑。手机丢了：先「注销所有设备」，再「关闭」。'),
            h('li', null, '手机连的是这台电脑上**同一套会话**：工作区、上下文、审批都在一起，不是另开一份。'),
            h('li', null, '隧道域名每次重启都会变；域名公开可达，但别人打开只会看到登录页。'),
            h('li', null, '流量经 Cloudflare 边缘，没有端到端加密（和 ngrok / frp 一个模型），别用它处理绝密材料。'),
            h('li', null, '「关闭」会同时停掉公网隧道和局域网入口；已发出去的登录状态要等过期，要立刻作废就用「注销所有设备」。')),
          h('div', { className: 'dshrl_row' },
            h('button', {
              className: 'dshrl_btn',
              type: 'button',
              disabled: busy !== '',
              onClick: () => {
                if (typeof window !== 'undefined' && typeof window.confirm === 'function'
                  && !window.confirm('注销后所有手机都要重新过验证器才能进来，且无法撤销。确定吗？')) return;
                void signout();
              },
            }, busy === 'signout' ? '正在注销…' : '注销所有设备'))));
    }

    /**
     * 侧边栏底部的连接状态胶囊：圆点 + 延迟 + 上下箭头，点一下展开详情。
     *
     * 为什么是「注册进槽」而不是「往页面里塞一个 fixed 浮层」：
     *   · 外壳给插件留了 `sidebar.footer.action`（`kind: 'list'`，紧随设置那一行），
     *     注册进去的节点由 React 自己管，重渲染不会把它连同监听器一起丢掉；
     *   · 浮层要靠 `getBoundingClientRect` 跟着别人的位置走，那等于永远在追一个
     *     不归我们管的布局 —— 侧栏一开一合就要重算，还要自己判可见性。
     *   旧实现就是后者：ResizeObserver + MutationObserver + 防抖 + 位置跟随，
     *   全是在跟框架对抗。现在整段删掉，改由这个组件自己渲染。
     *
     * 数据从哪来：手机上只能打到桥接自己的 `/__ping`（`/api/remote-link/*` 是
     * `localOnly` 的本机接口，经桥接进来的请求会被 403）。`/__ping` 回的
     * `via` 正好是「这条请求从哪条路进来」的实话，延迟用它测也最贴近体感。
     * 桌面壳里没有这条路由，探测会 404 —— 那种情况直接标「桌面端不探测」，
     * 不假装有数据。
     *
     * 断线次数：数的是「探测连续失败」的次数，不是 WebSocket 的 close。
     * 之前那个数字来自接管 `window.WebSocket` 构造，副作用大（且和框架抢全局）；
     * 探测失败已经足够说明「这台手机现在连不上」，而且不会干扰 DSH 自己的连接。
     */
    function ConnectionCapsule({ wide, t }) {
      /** 详情面板是否展开。侧栏收窄时必须自动收起，见下面的 effect。 */
      const [open, setOpen] = useState(false);
      /**
       * 一次探测的结果快照。
       *   `supported: false` = 这条路由不存在（桌面壳），不是故障。
       *   `ok: null`         = 还没测过。
       */
      const [snap, setSnap] = useState({
        ok: null, rtt: null, hist: [], via: '', home: false, lanUrls: [],
        drops: 0, timeouts: 0, supported: true,
      });
      /** 上一次探测是否成功，用来数「断开了几次」——只在由好变坏时 +1。 */
      const prevOk = useRef(null);
      /** 卸载后别再 setState（探测是异步的，手机上切走页面很常见）。 */
      const alive = useRef(true);

      useEffect(() => {
        alive.current = true;
        let timer = null;
        let controller = null;

        const probe = async () => {
          if (typeof document !== 'undefined' && document.hidden) return;
          const started = (typeof performance !== 'undefined' && performance.now)
            ? performance.now()
            : Date.now();
          try { controller?.abort(); } catch { /* 上一次还没收尾，忽略 */ }
          controller = typeof AbortController === 'function' ? new AbortController() : null;
          const timeout = setTimeout(() => { try { controller?.abort(); } catch { /* 已结束 */ } }, 12000);
          try {
            const response = await fetch('/__ping', {
              cache: 'no-store',
              credentials: 'same-origin',
              signal: controller ? controller.signal : undefined,
            });
            clearTimeout(timeout);
            if (!alive.current) return;
            if (response.status === 404 || response.status === 405) {
              // 桌面壳里没有桥接，这条路由天然不存在：标成不支持，别显示成「已断开」
              prevOk.current = null;
              setSnap((prev) => ({ ...prev, supported: false, ok: null }));
              return;
            }
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const info = await response.json().catch(() => null);
            const now = (typeof performance !== 'undefined' && performance.now)
              ? performance.now()
              : Date.now();
            const ms = Math.max(0, Math.round(now - started));
            if (!alive.current) return;
            prevOk.current = true;
            setSnap((prev) => {
              const hist = [...prev.hist, ms].slice(-8);
              return {
                ...prev,
                supported: true,
                ok: true,
                rtt: ms,
                hist,
                via: info && typeof info.via === 'string' ? info.via : prev.via,
                home: Boolean(info && info.home === true),
                lanUrls: Array.isArray(info && info.lanUrls) ? info.lanUrls : [],
              };
            });
          } catch (error) {
            clearTimeout(timeout);
            if (!alive.current) return;
            if (error && error.name === 'AbortError') return; // 被下一次探测顶掉，不算失败
            const wasOk = prevOk.current;
            prevOk.current = false;
            setSnap((prev) => ({
              ...prev,
              ok: false,
              // 由「没坏过 / 上一次是好的」变成坏，才算断开一次；连续失败不重复加。
              // `wasOk === null` 是这一页第一次探测就失败 —— 那也是真断了一次。
              drops: wasOk === false ? prev.drops : prev.drops + 1,
              // 12 秒都没回来，单独记一笔：中继链路偶发慢和真断要分得开
              timeouts: prev.timeouts + 1,
            }));
          }
        };

        // 首帧先等连接建立，避免把 TLS 握手算进第一次延迟（老脚本踩过这个坑）
        const boot = setTimeout(() => { void probe(); }, 1200);
        timer = setInterval(() => { void probe(); }, 5000);
        return () => {
          alive.current = false;
          clearTimeout(boot);
          clearInterval(timer);
          try { controller?.abort(); } catch { /* 已结束 */ }
        };
      }, []);

      // 侧栏收起时详情必须自己收起，重新展开也不能自己弹开。
      //
      // 手机上侧栏是「抽屉」：收起时 `wide` 仍是 true（抽屉里的内容是宽的），
      // 所以拿 `wide` 判不出来。这里只用 IntersectionObserver 看**自己还在不在视野里**——
      // 收起 = 这一格被移出可视区 → 回调一次 → 把面板关掉。
      // 它不做任何布局计算，也不观察别人，和旧实现那套「位置跟随 + 全 body 监听」是两回事。
      const rootRef = useRef(null);
      useEffect(() => {
        if (!open) return undefined;
        const node = rootRef.current;
        const Observer = typeof window !== 'undefined' ? window.IntersectionObserver : undefined;
        if (!node || typeof Observer !== 'function') return undefined;
        const observer = new Observer((entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting === false) setOpen(false);
          }
        }, { threshold: 0 });
        observer.observe(node);
        return () => { observer.disconnect(); };
      }, [open]);

      const dotTone = !snap.supported
        ? 'dshrl_capDot'
        : snap.ok === null
          ? 'dshrl_capDot'
          : snap.ok
            ? 'dshrl_capDot dshrl_capDotUp'
            : 'dshrl_capDot dshrl_capDotErr';

      const stateText = !snap.supported
        ? '桌面端'
        : snap.ok === null
          ? '连接中'
          : snap.ok
            ? '已连接'
            : '已断开';

      /** 连接方式的实话：`via` 由桥接按「本地监听口」判，不是猜的。 */
      const routeText = (() => {
        if (!snap.via) return '未知';
        if (snap.via === 'relay') return '自建中继';
        if (snap.via === 'lan') return '局域网直连';
        if (snap.via === 'tailscale') return 'Tailscale';
        if (snap.via === 'tunnel') return '公网隧道（Cloudflare）';
        return snap.via;
      })();

      const histText = (() => {
        if (snap.hist.length < 2) return '';
        const min = Math.min(...snap.hist);
        const max = Math.max(...snap.hist);
        return `${min}–${max} ms`;
      })();

      const label = `${stateText}${snap.rtt !== null ? ` · ${snap.rtt}ms` : ''}`;
      const title = `${label}${snap.supported ? ` · ${routeText}` : ''}`;

      // 窄条（56 点 rail）里放不下文字：只留一颗圆点。
      // 这里不挂展开 —— 那一行只有 56 点宽，面板会把下面的设置挤出去。
      // 收起态的信息靠 `title` 与 `aria-label` 说，点开侧栏再看详情。
      if (!wide) {
        return h('div', { className: 'dshrl_cap' },
          h('style', { key: 'dshrl-capsule-style' }, CAPSULE_CSS),
          h('span', {
            className: 'dshrl_capBtn',
            style: { justifyContent: 'center', padding: '8px 0' },
            role: 'status',
            'aria-label': title,
            title,
          }, h('span', { className: dotTone, 'aria-hidden': 'true' })));
      }

      return h('div', { className: 'dshrl_cap', ref: rootRef },
        h('style', { key: 'dshrl-capsule-style' }, CAPSULE_CSS),
        h('button', {
          type: 'button',
          className: 'dshrl_capBtn',
          'aria-expanded': open ? 'true' : 'false',
          'aria-label': title,
          title,
          onClick: () => setOpen((value) => !value),
        },
        h('span', { className: dotTone, 'aria-hidden': 'true' }),
        h('span', { className: 'dshrl_capText' }, stateText),
        snap.rtt !== null ? h('span', { className: 'dshrl_capRtt' }, `${snap.rtt}ms`) : null,
        h('span', { className: 'dshrl_capArrow', 'aria-hidden': 'true' }, open ? '▼' : '▲')),

        open
          ? h('div', { className: 'dshrl_capPanel', role: 'group', 'aria-label': '连接详情' },
            h('div', { className: 'dshrl_capRow' }, h('span', null, '连接方式'), h('b', null, routeText)),
            snap.rtt !== null
              ? h('div', { className: 'dshrl_capRow' }, h('span', null, '往返延迟'), h('b', null, `${snap.rtt} ms`))
              : null,
            histText
              ? h('div', { className: 'dshrl_capRow' }, h('span', null, '最近波动'), h('b', null, histText))
              : null,
            h('div', { className: 'dshrl_capRow' }, h('span', null, '断开次数'), h('b', null, `${snap.drops} 次`)),
            snap.timeouts > 0
              ? h('div', { className: 'dshrl_capRow' }, h('span', null, '探测超时'), h('b', null, `${snap.timeouts} 次`))
              : null,
            !snap.supported
              ? h('p', { className: 'dshrl_capNote' }, '这个页面不是经桥接打开的（桌面端），没有可测的往返链路。')
              : null,
            snap.ok === false
              ? h('p', { className: 'dshrl_capWarn' }, '任务仍在电脑上继续跑，网络恢复后会自动接上。')
              : null,
            snap.home && snap.via !== 'lan' && snap.lanUrls.length > 0
              ? h('p', { className: 'dshrl_capNote' }, `同一个网络下可以直连更快：${snap.lanUrls[0]}`)
              : null,
            snap.supported
              ? h('button', {
                type: 'button',
                className: 'dshrl_capOut',
                onClick: () => {
                  // 只作废这一台设备的登录态，不动电脑那边还可能开着的其它入口
                  void fetch('/__logout', { method: 'POST', credentials: 'same-origin' })
                    .catch(() => { /* 就算失败，跳登录页也能让这台设备重新验证 */ })
                    .then(() => { location.replace('/__login'); });
                },
              }, '断开这台设备')
              : null)
          : null);
    }

    /**
     * 手机上「从左边缘往右滑」打开侧边栏；抽屉已打开时，在侧栏上往左滑收起。
     *
     * 起手区怎么定，分两种载体，这是实测出来的差别，不是猜的：
     *
     *   · **Safari 标签页**：屏幕最左那几个像素是 iOS **系统级**返回手势区，网页拦不住
     *     （`touchstart` 要么收不到，要么被系统导航接管）。所以要让开一条
     *     `SWIPE_SYSTEM_INSET` 的内缩，从它右边开始算起。
     *   · **添加到主屏（standalone）**：没有「上一页」可回，系统的边缘返回手势根本不生效
     *     （用户实测：在主屏模式下从左往右划并不会退出界面）。这时最左边是**空的**，
     *     起手区直接贴到 0，手感才跟原生抽屉一致。
     *
     * 剩下的灵敏度靠三件事：
     *   1. 起手带够宽（`0/inset` 到 `SWIPE_EDGE_END`），不用瞄准一条细线；
     *   2. 方向门槛放宽到 1.2（横向略占上风就算），距离 48px 就够；
     *   3. **滑够距离就在 `touchmove` 里立刻触发**，不等抬手 —— 这是「跟手」的关键。
     *      触发后立刻把这次手势标记为已用，抬手时不会再 toggle 第二次。
     *
     * 仍然只在「窄屏抽屉」形态下装监听：宽屏侧栏常驻，没有开合一说。
     * 仍然**不**拦 `touchmove`、不 `preventDefault`：一旦拦了浏览器就不原生滚动，
     * 误判的表现会变成「页面卡住不动」。竖向占上风的手势一律放行给页面。
     */
    /** Safari（非主屏）必须让开的系统返回手势宽度。 */
    const SWIPE_SYSTEM_INSET = 16;
    /** 起手带的外沿：从边到这儿都算「贴着左边起手」。 */
    const SWIPE_EDGE_END = 96;
    /** 横向要走够多少像素才算一次开合。 */
    const SWIPE_MIN_DX = 48;
    /** 一次手势允许的最长时间，超时当成慢拖、不响应。 */
    const SWIPE_MAX_MS = 1200;
    /** 横向 / 竖向的最小比值：横向略占上风就算划，不必严格水平。 */
    const SWIPE_DIRECTION_RATIO = 1.2;

    /** 当前是不是「添加到主屏」那种独立窗口（没有系统返回手势可以抢）。 */
    function isStandalone() {
      try {
        // iOS 的主屏模式给这个非标准属性
        if (typeof navigator !== 'undefined' && navigator.standalone === true) return true;
        if (typeof window.matchMedia !== 'function') return false;
        return window.matchMedia('(display-mode: standalone)').matches
          || window.matchMedia('(display-mode: fullscreen)').matches;
      } catch {
        return false;
      }
    }

    function installSwipeGesture(ctx) {
      if (typeof window === 'undefined' || typeof document === 'undefined') return;
      if (typeof ctx.inject !== 'function') return;
      ctx.inject(['layout'], (scope) => {
        const layout = scope.layout;
        if (!layout || typeof layout.toggleSidebar !== 'function') return;

        scope.effect(() => {
          /** 当前这次手势的起点；null = 这一次不参与（或已经触发过）。 */
          let origin = null;

          /**
           * 抽屉此刻是开还是关；`null` = 不是抽屉形态（宽屏）。
           *
           * 用外壳自己的状态标记判断，而不是自己另记一份：用户也可能点左上角按钮、
           * 点遮罩来开关，自己记的那份迟早和真实状态走岔。
           */
          const drawerState = () => {
            if (!document.querySelector('[data-sidebar-drawer]')) return null;
            return !document.querySelector('[data-sidebar-collapsed="true"]');
          };

          /**
           * 抽屉面板此刻的矩形；拿不到就返回 null。
           *
           * 关抽屉的起手判定要落在「侧栏自己那一块」上：抽屉在手机上只有 280px 宽，
           * 如果用「屏幕右半边」当条件，侧栏左半段起手就永远不响应 —— 用户的直觉却是
           * 「我在侧栏上往左划」，跟屏幕坐标系没有关系。
           */
          const drawerRect = () => {
            const panel = document.querySelector('[data-sidebar-drawer] [role="dialog"]');
            if (!panel || typeof panel.getBoundingClientRect !== 'function') return null;
            const rect = panel.getBoundingClientRect();
            if (rect.width <= 0 || rect.height <= 0) return null;
            return rect;
          };

          const onStart = (event) => {
            origin = null;
            if (!event.touches || event.touches.length !== 1) return;
            const open = drawerState();
            if (open === null) return;
            const touch = event.touches[0];
            if (!open) {
              // 抽屉关着：从左边缘起手往右滑 = 打开。
              // 主屏模式最左边是空的，贴边就行；Safari 标签页要让开系统手势区。
              const edgeStart = isStandalone() ? 0 : SWIPE_SYSTEM_INSET;
              if (touch.clientX < edgeStart || touch.clientX > SWIPE_EDGE_END) return;
              origin = { x: touch.clientX, y: touch.clientY, at: Date.now(), mode: 'open' };
              return;
            }
            // 抽屉开着：从侧栏那一块往左滑 = 关闭。起手必须在面板内（纵向也要在内），
            // 免得在下面的对话区误触。面板矩形拿不到时退回「整个视口都算」——
            // 抽屉开着的时候，往左划本来就不会撞上系统边缘手势。
            const rect = drawerRect();
            if (rect) {
              const insideX = touch.clientX >= rect.left && touch.clientX <= rect.right;
              const insideY = touch.clientY >= rect.top && touch.clientY <= rect.bottom;
              if (!insideX || !insideY) return;
            }
            origin = { x: touch.clientX, y: touch.clientY, at: Date.now(), mode: 'close' };
          };

          /**
           * 这次位移够不够触发；够就返回该往哪个方向 toggle，否则 null。
           * 开、关共用同一套方向与距离判据，只是符号相反。
           */
          const verdictOf = (start, dx, dy) => {
            if (Date.now() - start.at > SWIPE_MAX_MS) return null;
            // 竖向占上风 = 这是在滚页面，不是划侧栏
            if (Math.abs(dx) < Math.abs(dy) * SWIPE_DIRECTION_RATIO) return null;
            if (start.mode === 'open') return dx >= SWIPE_MIN_DX ? 'open' : null;
            return dx <= -SWIPE_MIN_DX ? 'close' : null;
          };

          const commit = (mode) => {
            origin = null; // 一次手势只触发一次，抬手时不会再 toggle 回来
            layout.toggleSidebar();
          };

          /**
           * 跟手的关键：滑够距离就当场触发，不等抬手。
           *
           * 抬手才触发的手感是「滑完了还得停一下」，手机上是明显的迟钝感；
           * 原生抽屉都是跟手的。这里读 `touches[0]`（手指还在屏幕上）。
           */
          const onMove = (event) => {
            if (!origin) return;
            const touch = event.touches && event.touches[0];
            if (!touch) return;
            const mode = verdictOf(origin, touch.clientX - origin.x, touch.clientY - origin.y);
            if (mode) commit(mode);
          };

          /** 抬手的兜底：极快的轻扫可能只发出一两个 move，靠这里补上。 */
          const onEnd = (event) => {
            const start = origin;
            if (!start) return;
            const touch = (event.changedTouches && event.changedTouches[0]) || null;
            if (!touch) { origin = null; return; }
            const mode = verdictOf(start, touch.clientX - start.x, touch.clientY - start.y);
            if (mode) commit(mode);
            else origin = null;
          };

          const onCancel = () => { origin = null; };

          // `passive: true`：只是旁听，不需要也不应该阻止浏览器默认行为
          document.addEventListener('touchstart', onStart, { passive: true });
          document.addEventListener('touchmove', onMove, { passive: true });
          document.addEventListener('touchend', onEnd, { passive: true });
          document.addEventListener('touchcancel', onCancel, { passive: true });
          return () => {
            document.removeEventListener('touchstart', onStart);
            document.removeEventListener('touchmove', onMove);
            document.removeEventListener('touchend', onEnd);
            document.removeEventListener('touchcancel', onCancel);
          };
        }, 'remote-link: swipe sidebar');
      });
    }

    /**
     * 让会话标题栏常显「标准模式」标签。
     *
     * 外壳原本在窄屏把它藏起来：`@container (width <= 540px) { .dscfja_label { display: none } }`。
     * 手机上宽度 390px 必然命中，所以一直看不见。这里只把这一颗标签的 display 恢复成 flex，
     * 不去动 `container-type` —— 那会连带解除这一整块里其它容器查询的效果，影响面太大。
     *
     * 代价（已实测，如实记下）：这颗标签宽 68px，会让标题可用宽度从 208px 降到 132px，
     * 可见字数从 23 字降到 14 字（长标题会更早出现省略号）。用户明确要求保留这个取舍。
     *
     * 选择器说明：外壳给这颗标签的类名是哈希化的 `dscfja_label`，其中 `label` 后缀稳定，
     * 所以用 `[class*="label"]` 限定在 `conversation.session.header.actions` 这个稳定槽内匹配，
     * 不写死哈希前缀。若将来外壳改了后缀导致失效，现象只是标签重新被隐藏，不会破坏布局。
     */
    const STANDARD_MODE_CSS = `
[data-slot="conversation.session.header.actions"] [class*="label"] {
  display: flex !important;
}
`;

    /**
     * 会话标题「发虚」的结论（已定性，勿再尝试 CSS 修法）：
     *   真机对照实验——把标题改成鲜红 + 700 加粗 + 20px，用户确认三项全部生效，
     *   但依然发虚。即 CSS 完全能作用到这些字，清晰度却改不动。
     *   结合「点开图片阅览时那一行会临时变实」（全屏层插入迫使图层重建/重新栅格化），
     *   可判定这是 iOS WebKit 对这一行的位图栅格化问题，插件 CSS 层无法修复。
     *   已放弃修复，仅保留上面的「标准模式」标签规则。
     */
    function installTitleLegibility(ctx) {
      if (typeof document === 'undefined' || !document.head) return;
      ctx.effect(() => {
        const tag = document.createElement('style');
        tag.dataset.plugin = 'dsh-remote-link';
        tag.dataset.pluginCss = 'title-legibility';
        tag.textContent = STANDARD_MODE_CSS;
        document.head.appendChild(tag);
        return () => { try { tag.remove(); } catch { /* 已摘掉 */ } };
      }, 'remote-link: standard mode label');
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        // 字典必须在这一半注册：设置页的 `label` 与页内文案都从它取，
        // 不注册的话 `t('nav')` 只会回退成键名本身，界面上就是一行 `nav`。
        ctx.effect(() => ctx.locale.register(NS, DICT), 'remote-link: locale dictionaries');
        const t = ctx.locale.bind(NS);
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'remote-link',
          order: 21,
          label: () => t('nav'),
          locale: NS,
          inject: () => ({ t }),
        }, RemoteLinkSection));
        // 侧边栏底部那颗连接胶囊：外壳给插件留的官方动作位。
        // `name` 与 `inject()` 的槽名必须是同一个字符串，改一处不报错、只会静默挂不上。
        ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({
          name: 'sidebar.footer.action',
          id: 'remote-link-status',
          order: 20,
          // 列表槽的可访问名从 label 取；给个稳定的人类可读名字，别留 id。
          label: () => t('nav'),
          locale: NS,
          inject: () => ({ t }),
        }, ConnectionCapsule));
        // 手机上从左边缘内侧右滑开侧栏 / 左滑关抽屉
        installSwipeGesture(ctx);
        // 会话标题栏常显「标准模式」标签（外壳在窄屏把它藏起来了）
        installTitleLegibility(ctx);
      },
    };
  },
});
