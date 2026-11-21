/*! Contract X-Ray page logic. MIT License.
 * Rendering is done with a tiny virtual-node helper (h -> mount) that only ever creates text nodes,
 * so on-chain strings (token names, symbols) can never inject HTML. No HTML-string sinks are used.
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.XRayApp = api;
})(typeof self !== "undefined" ? self : this, function (root) {
  "use strict";

  // ---- Voluntary tip address (the only payment-related setting on the page) -------------------
  // Must be EIP-55 checksummed; if it is empty or invalid the whole tip section stays hidden.
  const TIP_ADDRESS = "0x6E6592A226b9B8618cCb5014539B733125bc8cAd";
  const TIP_AMOUNTS = ["1", "3", "5"];

  // ---- i18n ------------------------------------------------------------------------------------
  const I18N = {
    en: {
      tagline: "See who can mint, freeze, pause, tax or upgrade a contract — before you buy, approve or sign.",
      sub: "Free · open source · runs in your browser · no sign-up, no tracking",
      chain: "Chain", address: "Contract address", scan: "Scan", scanning: "Scanning…", examples: "Try:",
      advanced: "Data source & offline mode", srcAuto: "Public RPC nodes (default)", srcWallet: "My wallet's node (no CORS issues; wallet must be on the selected chain)",
      srcCustom: "Custom RPC URL", customPh: "https://your-rpc.example", offlineTitle: "Offline: paste runtime bytecode",
      offlineHint: "Copy “Deployed Bytecode” from a block explorer. Nothing is sent anywhere.", analyze: "Analyze bytecode",
      riskLevel: { high: "HIGH RISK", medium: "MEDIUM RISK", low: "LOW RISK", "n/a": "NOT A CONTRACT" },
      score: "score", flags: "Findings", noFlags: "No findings.", control: "Who controls it", proxy: "Proxy / upgradeability",
      token: "Token", code: "Code", source: "Source verification", raw: "Raw JSON", copyJson: "Copy JSON", copied: "Copied",
      share: "Copy share link", explorer: "Open in explorer", log: "Connection log",
      owner: "Owner", ownerType: "Owner type", upgradeBy: "Upgrade authority", proxyAdmin: "Proxy admin", adminOwner: "Proxy admin owner",
      type: "Type", impl: "Implementation", beacon: "Beacon", name: "Name", symbol: "Symbol", decimals: "Decimals", supply: "Total supply (raw)",
      size: "Bytecode size", logicSize: "Logic size", codeHash: "Code hash", block: "Block", rpcUsed: "Data from", yes: "yes", no: "no",
      sourcify: { exact_match: "exact match on Sourcify", match: "partial match on Sourcify", not_found: "not on Sourcify", error: "Sourcify unreachable", skipped: "not checked" },
      safe: "Safe", timelockDelay: "Timelock delay", roleBased: "Role-based access",
      errAddr: "Enter a 0x… contract address (40 hex characters).", errChecksum: "That address has a checksum typo (mixed-case letters don't match). Re-copy it.",
      errAllRpc: "Public nodes didn't answer (browser CORS block, rate limit, or offline).",
      hints: ["Open “Data source” and choose “My wallet's node”.", "Or paste your own RPC URL.", "Or use the offline bytecode check — it needs no network."],
      errWrongChain: "Your wallet is on a different chain. Switch it to the selected chain, or use public nodes.",
      noWallet: "No browser wallet detected.", disclaimer: "Heuristic check, not an audit. No findings ≠ safe.",
      tipTitle: "Tip the author", tipText: "This tool is free and nothing is locked. If it helped you dodge a bad contract, you can tip in USDC on Base.",
      tipBtn: "Tip {n} USDC", tipCopy: "Copy address", tipLink: "Open in wallet app", tipNote: "Buttons send USDC on Base (chain 8453) through your browser wallet; you confirm everything in the wallet. A tip is a voluntary thank-you, not a purchase: no extra features or guarantees.",
      tipNoWallet: "No browser wallet here — copy the address and send USDC on the Base network from any wallet.",
      tipConfirm: "Send {n} USDC on Base to {a}?\n\nThis is a voluntary tip.", tipSwitching: "Asking your wallet to switch to Base…", tipLow: "Your wallet has {b} USDC on Base — not enough for this tip.",
      tipSent: "Sent — thank you! Transaction:", tipCancel: "Cancelled.", tipFail: "Tip failed: ", tipWrongChain: "Wallet is not on Base; nothing was sent.",
      postScanTip: "Was this useful? This tool is free; tips keep it maintained.",
    },
    zh: {
      tagline: "买币、授权、签名之前，先看清谁能增发、冻结、暂停、改税、升级这个合约。",
      sub: "免费 · 开源 · 在你的浏览器里运行 · 不注册、不追踪",
      chain: "链", address: "合约地址", scan: "扫描", scanning: "扫描中…", examples: "试试：",
      advanced: "数据源与离线模式", srcAuto: "公共 RPC 节点（默认）", srcWallet: "用我钱包的节点（不受跨域限制；钱包需切到所选的链）",
      srcCustom: "自定义 RPC 地址", customPh: "https://your-rpc.example", offlineTitle: "离线：粘贴运行时字节码",
      offlineHint: "从区块浏览器复制 “Deployed Bytecode”。不会发送到任何地方。", analyze: "分析字节码",
      riskLevel: { high: "高风险", medium: "中风险", low: "低风险", "n/a": "不是合约" },
      score: "分", flags: "发现", noFlags: "没有发现。", control: "谁在控制", proxy: "代理 / 可升级性",
      token: "代币", code: "代码", source: "源码验证", raw: "原始 JSON", copyJson: "复制 JSON", copied: "已复制",
      share: "复制分享链接", explorer: "在区块浏览器打开", log: "连接日志",
      owner: "Owner", ownerType: "Owner 类型", upgradeBy: "升级权限", proxyAdmin: "代理管理员", adminOwner: "代理管理员的 owner",
      type: "类型", impl: "实现合约", beacon: "Beacon", name: "名称", symbol: "符号", decimals: "精度", supply: "总量（原始值）",
      size: "字节码大小", logicSize: "逻辑合约大小", codeHash: "代码哈希", block: "区块", rpcUsed: "数据来自", yes: "是", no: "否",
      sourcify: { exact_match: "Sourcify 完全匹配", match: "Sourcify 部分匹配", not_found: "Sourcify 上没有", error: "Sourcify 连不上", skipped: "未检查" },
      safe: "Safe", timelockDelay: "时间锁延迟", roleBased: "基于角色的权限",
      errAddr: "请输入 0x 开头、40 位十六进制的合约地址。", errChecksum: "地址校验和不对（大小写对不上），请重新复制。",
      errAllRpc: "公共节点没有响应（可能是浏览器跨域拦截、限流或断网）。",
      hints: ["展开“数据源”，选“用我钱包的节点”。", "或者填一个你自己的 RPC 地址。", "或者用离线字节码检查，完全不需要联网。"],
      errWrongChain: "你的钱包在另一条链上。请切到所选的链，或改用公共节点。",
      noWallet: "没有检测到浏览器钱包。", disclaimer: "启发式检查，不是审计。没有发现 ≠ 安全。",
      tipTitle: "打赏作者", tipText: "这个工具免费，没有任何功能上锁。如果它帮你躲过了一个坏合约，可以用 Base 链上的 USDC 打赏。",
      tipBtn: "打赏 {n} USDC", tipCopy: "复制地址", tipLink: "在钱包 App 中打开", tipNote: "按钮通过你的浏览器钱包在 Base（链 ID 8453）上发送 USDC，每一步都由你在钱包里确认。打赏是自愿的感谢，不是购买，不附带任何额外功能或保证。",
      tipNoWallet: "这里没有浏览器钱包——复制地址，用任意钱包在 Base 网络上发送 USDC 即可。",
      tipConfirm: "在 Base 上向 {a} 发送 {n} USDC？\n\n这是自愿打赏。", tipSwitching: "正在请求钱包切换到 Base…", tipLow: "你的钱包在 Base 上只有 {b} USDC，不够这笔打赏。",
      tipSent: "已发送，谢谢！交易：", tipCancel: "已取消。", tipFail: "打赏失败：", tipWrongChain: "钱包不在 Base 上，什么都没有发送。",
      postScanTip: "有帮助吗？这个工具免费，打赏让它能持续维护。",
    },
  };

  const FLAG_INFO = {
    CURRENTLY_PAUSED: { en: ["Paused right now", "paused() returns true. Transfers or core actions are probably blocked at this moment."], zh: ["当前处于暂停状态", "paused() 返回 true，此刻转账或核心功能很可能被冻结。"] },
    EIP7702_DELEGATED: { en: ["Wallet with delegated code (EIP-7702)", "A regular wallet that delegates its behaviour to another contract. The key holder can change it at any time."], zh: ["委托了代码的钱包（EIP-7702）", "普通钱包地址把执行逻辑委托给了另一个合约，私钥持有人随时可以改。"] },
    MINIMAL_PROXY: { en: ["Clone of another contract", "An EIP-1167 clone: its logic can't be swapped. Scan the original it points to."], zh: ["另一个合约的克隆", "EIP-1167 最小代理，逻辑不能被替换。请扫描它指向的原合约。"] },
    UPGRADEABLE: { en: ["Code can be replaced", "Upgradeable proxy. Whoever controls upgrades can rewrite every rule, including balance logic. See “Who controls it”."], zh: ["代码可以被替换", "可升级代理。掌握升级权的人可以改写全部规则，包括余额逻辑。见“谁在控制”。"] },
    MINTABLE: { en: ["Can print new tokens", "A privileged account can mint new supply and dilute holders."], zh: ["可以增发", "特权账户可以增发新代币，稀释持有人。"] },
    FEE_CONTROL: { en: ["Owner can change the tax", "Buy/sell/transfer fees are owner-settable — a common honeypot pattern (sell tax raised toward 100%)."], zh: ["Owner 可以改税率", "买卖/转账手续费可由 owner 修改——常见貔貅盘手法（把卖出税调到接近 100%）。"] },
    ADMIN_SEIZE: { en: ["Can wipe or seize balances", "Functions exist that can destroy or confiscate a holder's tokens."], zh: ["可以没收或销毁余额", "存在可以销毁或没收持有人代币的函数。"] },
    BLACKLIST: { en: ["Can block specific wallets", "Blacklist / freeze / bot-list functions can stop chosen addresses from transferring."], zh: ["可以拉黑指定钱包", "黑名单/冻结/bot 名单函数可以让指定地址无法转账。"] },
    PAUSABLE: { en: ["Can be paused", "A privileged switch can halt transfers or core functions."], zh: ["可以被暂停", "特权开关可以叫停转账或核心功能。"] },
    TX_LIMITS: { en: ["Adjustable transaction limits", "Max-tx / max-wallet limits can be tightened, e.g. to block selling."], zh: ["交易限额可调", "单笔/单钱包上限可以被收紧，比如用来阻止卖出。"] },
    TRADING_SWITCH: { en: ["Trading on/off switch", "Trading is gated by a privileged account."], zh: ["交易开关", "交易由特权账户控制开启。"] },
    ADMIN_BURN: { en: ["burn(address, amount)", "May let a privileged account burn other people's tokens — check access control in the source."], zh: ["burn(address, amount)", "可能允许特权账户销毁他人的代币——请在源码里核对权限。"] },
    SELF_UPGRADE: { en: ["Upgrade entrypoint in logic", "UUPS-style upgrade functions are present — the code can be replaced."], zh: ["逻辑合约内有升级入口", "存在 UUPS 升级函数——代码可以被替换。"] },
    FEE_EXEMPTIONS: { en: ["Fee-exempt list", "Some addresses can be excluded from fees — insiders may trade tax-free."], zh: ["免税名单", "部分地址可以免手续费——内部人可能免税交易。"] },
    SINGLE_KEY_CONTROL: { en: ["One private key controls it", "The owner is a plain wallet (EOA). If that one key leaks or turns malicious, every power above can be used instantly."], zh: ["一把私钥说了算", "owner 是普通钱包（EOA）。这一把钥匙泄露或作恶，上面所有特权都能立刻被使用。"] },
    OWNERSHIP_RENOUNCED: { en: ["Ownership renounced", "owner() is the zero address. Owner-only functions are likely unusable (roles or proxies can still hold power)."], zh: ["已放弃所有权", "owner() 是零地址。仅限 owner 的函数大概率已不可用（角色系统或代理仍可能保留权力）。"] },
    SAFE_OWNED: { en: ["Owned by a multisig", "The owner is a Safe multisig, so several signers must agree."], zh: ["由多签控制", "owner 是 Safe 多签，需要多名签名人同意。"] },
    UNVERIFIED_SOURCIFY: { en: ["Source not on Sourcify", "No verified source on Sourcify. It may be verified on a block explorer — check before trusting."], zh: ["Sourcify 上没有验证源码", "Sourcify 上查不到已验证源码；区块浏览器上可能有，信任前请核对。"] },
    VERIFIED_SOURCIFY: { en: ["Source verified (Sourcify)", "The deployed bytecode matches published source on Sourcify."], zh: ["源码已验证（Sourcify）", "链上字节码与 Sourcify 上公开的源码一致。"] },
    SELFDESTRUCT_OPCODE: { en: ["SELFDESTRUCT present", "Since EIP-6780 it usually can't delete the contract, but it can still sweep ETH."], zh: ["含 SELFDESTRUCT", "EIP-6780 之后通常已无法删除合约，但仍可转走 ETH。"] },
    DELEGATECALL_OPCODE: { en: ["DELEGATECALL present", "The contract can run other code in its own context — review what it may call."], zh: ["含 DELEGATECALL", "合约可以在自身上下文里执行别的代码——请检查它会调用什么。"] },
    KNOWN_CONTRACT: { en: ["Well-known contract", "Issuer-controlled powers are expected for this kind of asset; what matters is who holds them."], zh: ["知名合约", "这类资产由发行方掌握冻结/暂停/升级权限属于预期，关键是谁持有这些权限。"] },
    OFFLINE_ONLY: { en: ["Bytecode-only check", "Who holds the powers, live paused state, proxy implementation and verification were not checked."], zh: ["仅字节码检查", "未检查权限持有人、实时暂停状态、代理实现和源码验证。"] },
    LOOKS_LIKE_PROXY: { en: ["Looks like a proxy", "The real logic lives in another contract — paste the implementation's bytecode too."], zh: ["看起来是代理", "真正的逻辑在另一个合约里——请把实现合约的字节码也贴进来。"] },
  };

  const OWNER_KIND = {
    en: { eoa: "single wallet (EOA)", "eoa-7702": "wallet with EIP-7702 code", safe: "Safe multisig", timelock: "timelock", contract: "contract (type unknown)",
      renounced: "renounced (zero address)", "role-based": "role-based access", "none-detected": "no owner() found", unknown: "unknown" },
    zh: { eoa: "单个钱包（EOA）", "eoa-7702": "带 EIP-7702 代码的钱包", safe: "Safe 多签", timelock: "时间锁", contract: "合约（类型未知）",
      renounced: "已放弃（零地址）", "role-based": "基于角色的权限", "none-detected": "未发现 owner()", unknown: "未知" },
  };

  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

  // ---- tiny virtual DOM ------------------------------------------------------------------------
  function h(tag, attrs) {
    const kids = [];
    for (let i = 2; i < arguments.length; i++) {
      const c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) { for (const x of c) if (x !== null && x !== undefined && x !== false) kids.push(x); } else kids.push(c);
    }
    return { t: tag, a: attrs || {}, c: kids.map((k) => (typeof k === "object" ? k : String(k))) };
  }
  const SAFE_ATTR = /^(class|id|title|target|rel|type|role|aria-[a-z]+|data-[a-z-]+|lang)$/;
  function safeHref(u) { return typeof u === "string" && (/^https:\/\//.test(u) || /^ethereum:0x[0-9a-fA-F]{40}@\d+\/transfer\?/.test(u) || /^[#?]/.test(u)) ? u : null; }
  function mount(v, doc) {
    doc = doc || root.document;
    if (typeof v === "string") return doc.createTextNode(v);
    const el = doc.createElement(v.t);
    for (const k of Object.keys(v.a)) {
      if (k === "href") { const u = safeHref(v.a[k]); if (u) el.setAttribute("href", u); }
      else if (SAFE_ATTR.test(k)) el.setAttribute(k, String(v.a[k]));
    }
    for (const c of v.c) el.appendChild(mount(c, doc));
    return el;
  }
  // Collect all text in a vnode tree (used by tests and for plain-text export).
  function textOf(v) { return typeof v === "string" ? v : v.c.map(textOf).join(" "); }

  const short = (a) => (a && a.length === 42 ? a.slice(0, 6) + "…" + a.slice(-4) : a);
  function fmt(s, vars) { return String(s).replace(/\{(\w+)\}/g, (_, k) => (vars && vars[k] !== undefined ? vars[k] : "")); }

  // ---- report rendering ------------------------------------------------------------------------
  function renderReport(r, lang, ctx) {
    const L = I18N[lang] || I18N.en;
    const X = ctx && ctx.XRay;
    const cfg = X && r.chain ? X.CHAINS[r.chain] : null;
    const addrLink = (a) => (cfg && a ? h("a", { href: cfg.explorer + "/address/" + a, target: "_blank", rel: "noopener" }, short(a)) : (a ? short(a) : "—"));
    const row = (k, v) => (v === null || v === undefined || v === "" ? null : h("div", { class: "kv" }, h("span", { class: "k" }, k), h("span", { class: "v" }, v)));
    const level = r.verdict.level;

    const flags = (r.flags || []).slice().sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    const flagNodes = flags.map((f) => {
      const info = FLAG_INFO[f.id] ? FLAG_INFO[f.id][lang] || FLAG_INFO[f.id].en : [f.id, ""];
      return h("li", { class: "flag sev-" + f.severity, "data-flag": f.id },
        h("div", { class: "flag-head" }, h("span", { class: "chip sev-" + f.severity }, f.severity.toUpperCase()), h("strong", null, info[0])),
        info[1] ? h("p", { class: "flag-why" }, info[1]) : null,
        h("p", { class: "flag-detail mono" }, f.detail));
    });

    const sections = [];
    if (r.control) {
      const c = r.control, K = OWNER_KIND[lang] || OWNER_KIND.en;
      sections.push(h("section", { class: "box" }, h("h3", null, L.control),
        row(L.owner, c.owner ? addrLink(c.owner) : null),
        row(L.ownerType, K[c.ownerType] || c.ownerType),
        c.safe ? row(L.safe, c.safe.threshold + " / " + c.safe.ownerCount) : null,
        c.timelockDelaySec !== undefined ? row(L.timelockDelay, c.timelockDelaySec + " s") : null,
        c.upgradeAuthorityType ? row(L.upgradeBy, K[c.upgradeAuthorityType] || c.upgradeAuthorityType) : null,
        c.proxyAdmin ? row(L.proxyAdmin, addrLink(c.proxyAdmin)) : null,
        c.proxyAdminOwner ? row(L.adminOwner, addrLink(c.proxyAdminOwner)) : null,
        row(L.roleBased, c.roleBasedAccess ? L.yes : L.no)));
    }
    if (r.proxy && r.proxy.isProxy) {
      sections.push(h("section", { class: "box" }, h("h3", null, L.proxy),
        row(L.type, r.proxy.type), row(L.impl, r.proxy.implementation ? addrLink(r.proxy.implementation) : null),
        row(L.beacon, r.proxy.beacon ? addrLink(r.proxy.beacon) : null)));
    }
    if (r.token && (r.token.name || r.token.symbol || r.token.totalSupply)) {
      sections.push(h("section", { class: "box" }, h("h3", null, L.token),
        row(L.type, r.token.standard.toUpperCase()), row(L.name, r.token.name), row(L.symbol, r.token.symbol),
        row(L.decimals, r.token.decimals), row(L.supply, r.token.totalSupply)));
    }
    if (r.code) {
      sections.push(h("section", { class: "box" }, h("h3", null, L.code),
        row(L.size, r.code.size + " B"), r.code.logicAddress ? row(L.logicSize, r.code.logicSize + " B") : null,
        row(L.codeHash, r.code.codeHash ? h("span", { class: "mono" }, r.code.codeHash.slice(0, 18) + "…") : null),
        r.source ? row(L.source, L.sourcify[r.source.sourcify] || r.source.sourcify) : null,
        row(L.block, r.block), row(L.rpcUsed, r.meta && r.meta.rpc)));
    }

    const title = r.token && (r.token.symbol || r.token.name) ? (r.token.symbol || r.token.name) : null;
    return h("article", { class: "report level-" + level.replace("/", ""), "data-level": level },
      h("header", { class: "verdict" },
        h("div", { class: "badge" }, h("span", { class: "lvl" }, L.riskLevel[level] || level), level !== "n/a" ? h("span", { class: "num" }, r.verdict.score + " " + L.score) : null),
        h("div", { class: "vtext" },
          h("div", { class: "vtitle" }, title ? h("strong", null, title) : null, r.address ? h("span", { class: "mono" }, " " + short(r.address)) : null, cfg ? h("span", { class: "muted" }, " · " + cfg.name) : null),
          r.known ? h("div", { class: "known" }, r.known.label) : null,
          h("p", { class: "summary" }, r.verdict.summary))),
      h("h3", null, L.flags + " (" + flags.length + ")"),
      flagNodes.length ? h("ul", { class: "flags" }, flagNodes) : h("p", { class: "muted" }, L.noFlags),
      h("div", { class: "grid" }, sections),
      h("p", { class: "disclaimer" }, L.disclaimer));
  }

  function renderError(kind, lang, extra) {
    const L = I18N[lang] || I18N.en;
    if (kind === "rpc") return h("div", { class: "error" }, h("p", null, h("strong", null, L.errAllRpc)), extra ? h("p", { class: "mono muted" }, extra) : null, h("ul", null, L.hints.map((x) => h("li", null, x))));
    if (kind === "wrongchain") return h("div", { class: "error" }, h("p", null, L.errWrongChain), extra ? h("p", { class: "mono muted" }, extra) : null);
    return h("div", { class: "error" }, h("p", null, extra || kind));
  }

  // ---- browser wiring ------------------------------------------------------------------------
  function init(X, doc, win) {
    const $ = (id) => doc.getElementById(id);
    let lang = "en";
    try { const saved = win.localStorage.getItem("xray-lang"); lang = saved === "zh" || saved === "en" ? saved : null; } catch (e) { lang = null; }
    if (!lang) lang = /^zh/i.test((win.navigator && win.navigator.language) || "") ? "zh" : "en";
    let lastReport = null, lastLog = [];
    const tipEnabled = X.tip.validTipAddress(TIP_ADDRESS);

    function applyLang() {
      const L = I18N[lang];
      doc.documentElement.setAttribute("lang", lang === "zh" ? "zh-CN" : "en");
      doc.querySelectorAll("[data-i18n]").forEach((el) => { const k = el.getAttribute("data-i18n"); if (typeof L[k] === "string") el.textContent = L[k]; });
      doc.querySelectorAll("[data-i18n-ph]").forEach((el) => { const k = el.getAttribute("data-i18n-ph"); if (typeof L[k] === "string") el.setAttribute("placeholder", L[k]); });
      doc.querySelectorAll("[data-lang-block]").forEach((el) => { el.hidden = el.getAttribute("data-lang-block") !== lang; });
      $("lang-toggle").textContent = lang === "zh" ? "English" : "中文";
      renderTipButtons();
      if (lastReport) show(renderReport(lastReport, lang, { XRay: X }), true);
    }
    $("lang-toggle").addEventListener("click", () => { lang = lang === "zh" ? "en" : "zh"; try { win.localStorage.setItem("xray-lang", lang); } catch (e) {} applyLang(); });

    // chain select
    const sel = $("chain");
    for (const k of Object.keys(X.CHAINS)) { const o = doc.createElement("option"); o.value = k; o.textContent = X.CHAINS[k].name; sel.appendChild(o); }
    sel.value = "base";

    function show(vnode, isReport) {
      const out = $("result");
      while (out.firstChild) out.removeChild(out.firstChild);
      out.appendChild(mount(vnode, doc));
      $("report-tools").hidden = !isReport;
      $("post-scan-tip").hidden = !(isReport && tipEnabled);
    }
    function setBusy(b) { $("scan-btn").disabled = b; $("scan-btn").textContent = I18N[lang][b ? "scanning" : "scan"]; }
    function renderLog() {
      const ul = $("rpc-log"); while (ul.firstChild) ul.removeChild(ul.firstChild);
      for (const e of lastLog) { const li = doc.createElement("li"); li.textContent = (e.ok ? "✓ " : "✗ ") + e.url + " · " + e.ms + " ms" + (e.ok ? " · " + e.calls + " calls" : " · " + e.error); ul.appendChild(li); }
    }

    function makeProvider(chain) {
      const mode = (doc.querySelector('input[name="src"]:checked') || { value: "auto" }).value;
      const log = (e) => { lastLog.push(e); renderLog(); };
      if (mode === "wallet") {
        if (!win.ethereum) throw Object.assign(new Error(I18N[lang].noWallet), { code: "NO_WALLET" });
        return X.eip1193Provider(win.ethereum, X.CHAINS[chain].id, { log });
      }
      if (mode === "custom") {
        const u = $("custom-rpc").value.trim();
        return X.httpProvider([u], { log });
      }
      return X.httpProvider(X.CHAINS[chain].rpc, { log });
    }

    async function runScan() {
      const chain = sel.value;
      const raw = $("address").value.trim();
      const chk = X.checkAddress(raw);
      if (!chk.ok) { lastReport = null; show(renderError("input", lang, chk.reason === "checksum" ? I18N[lang].errChecksum : I18N[lang].errAddr), false); return; }
      lastLog = []; renderLog(); setBusy(true);
      try {
        const provider = makeProvider(chain);
        const r = await X.scan(provider, chain, chk.address);
        lastReport = r;
        show(renderReport(r, lang, { XRay: X }), true);
        try { win.history.replaceState(null, "", "?chain=" + chain + "&address=" + chk.address); } catch (e) {}
      } catch (e) {
        lastReport = null;
        if (e && e.code === "WRONG_CHAIN") show(renderError("wrongchain", lang, e.message), false);
        else if (e && e.code === "NO_WALLET") show(renderError("input", lang, e.message), false);
        else show(renderError("rpc", lang, e && e.message), false);
        $("advanced").open = true;
      } finally { setBusy(false); }
    }
    $("scan-form").addEventListener("submit", (ev) => { ev.preventDefault(); runScan(); });
    doc.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => {
      const [c, a] = b.getAttribute("data-example").split(":"); sel.value = c; $("address").value = a; runScan();
    }));
    $("offline-btn").addEventListener("click", () => {
      try { lastReport = X.analyzeOffline($("bytecode").value); show(renderReport(lastReport, lang, { XRay: X }), true); }
      catch (e) { lastReport = null; show(renderError("input", lang, e.message), false); }
    });
    $("copy-json").addEventListener("click", () => copy(JSON.stringify(lastReport, null, 2), $("copy-json")));
    $("copy-link").addEventListener("click", () => copy(win.location.href, $("copy-link")));
    $("open-explorer").addEventListener("click", () => {
      if (lastReport && lastReport.address && X.CHAINS[lastReport.chain]) win.open(X.CHAINS[lastReport.chain].explorer + "/address/" + lastReport.address, "_blank", "noopener");
    });
    function copy(text, btn) {
      const done = () => { const old = btn.textContent; btn.textContent = I18N[lang].copied; setTimeout(() => { btn.textContent = old; }, 1200); };
      try { win.navigator.clipboard.writeText(text).then(done, () => {}); } catch (e) {}
    }

    // ---- tips ----
    $("tip").hidden = !tipEnabled;
    doc.querySelectorAll("[data-tip-link]").forEach((el) => { el.hidden = !tipEnabled; });
    function tipStatus(nodes) { const s = $("tip-status"); while (s.firstChild) s.removeChild(s.firstChild); if (nodes) s.appendChild(mount(nodes, doc)); }
    function renderTipButtons() {
      if (!tipEnabled) return;
      const L = I18N[lang];
      $("tip-address").textContent = TIP_ADDRESS;
      const box = $("tip-buttons"); while (box.firstChild) box.removeChild(box.firstChild);
      if (win.ethereum) {
        for (const n of TIP_AMOUNTS) { const b = doc.createElement("button"); b.type = "button"; b.className = "btn tipbtn"; b.textContent = fmt(L.tipBtn, { n }); b.addEventListener("click", () => sendTip(n)); box.appendChild(b); }
      } else {
        const p = doc.createElement("p"); p.className = "muted"; p.textContent = L.tipNoWallet; box.appendChild(p);
      }
      $("tip-link").setAttribute("href", X.tip.eip681(TIP_ADDRESS, X.tip.usdcUnits("1")));
    }
    $("tip-copy").addEventListener("click", () => copy(TIP_ADDRESS, $("tip-copy")));
    async function sendTip(n) {
      const L = I18N[lang], eth = win.ethereum, T = X.tip.TIP;
      if (!eth || !tipEnabled) return;
      const units = X.tip.usdcUnits(n);
      try {
        const accounts = await eth.request({ method: "eth_requestAccounts" });
        const from = accounts && accounts[0];
        if (!from) return;
        let cid = await eth.request({ method: "eth_chainId" });
        if (parseInt(cid, 16) !== T.chainId) {
          tipStatus(h("p", null, L.tipSwitching));
          try { await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: T.chainIdHex }] }); }
          catch (e) { if (e && e.code === 4902) await eth.request({ method: "wallet_addEthereumChain", params: [T.addChainParams] }); else throw e; }
          cid = await eth.request({ method: "eth_chainId" });
          if (parseInt(cid, 16) !== T.chainId) { tipStatus(h("p", null, L.tipWrongChain)); return; }
        }
        try {
          const bal = await eth.request({ method: "eth_call", params: [{ to: T.usdc, data: X.tip.balanceOfData(from) }, "latest"] });
          const have = BigInt(bal);
          if (have < units) { tipStatus(h("p", null, fmt(L.tipLow, { b: (Number(have) / 1e6).toFixed(2) }))); return; }
        } catch (e) { /* balance check is best-effort; the wallet will refuse an unfunded transfer anyway */ }
        if (!win.confirm(fmt(L.tipConfirm, { n, a: TIP_ADDRESS }))) { tipStatus(h("p", null, L.tipCancel)); return; }
        // Re-check the chain right before sending: the user may have switched networks meanwhile.
        cid = await eth.request({ method: "eth_chainId" });
        if (parseInt(cid, 16) !== T.chainId) { tipStatus(h("p", null, L.tipWrongChain)); return; }
        const hash = await eth.request({ method: "eth_sendTransaction", params: [{ from, to: T.usdc, data: X.tip.transferData(TIP_ADDRESS, units), value: "0x0" }] });
        tipStatus(h("p", null, L.tipSent + " ", h("a", { href: "https://basescan.org/tx/" + hash, target: "_blank", rel: "noopener" }, String(hash).slice(0, 14) + "…")));
      } catch (e) {
        if (e && e.code === 4001) tipStatus(h("p", null, L.tipCancel));
        else tipStatus(h("p", null, L.tipFail + ((e && e.message) || String(e))));
      }
    }

    // repo link (only when served from <user>.github.io/<repo>/)
    const m = /^([a-z0-9-]+)\.github\.io$/i.exec(win.location.hostname || "");
    const repo = (win.location.pathname || "/").split("/").filter(Boolean)[0];
    if (m && repo) { const a = $("repo-link"); a.setAttribute("href", "https://github.com/" + m[1] + "/" + repo); a.hidden = false; }

    applyLang();
    // deep link: ?chain=base&address=0x...
    try {
      const q = new win.URLSearchParams(win.location.search);
      const qa = q.get("address"), qc = q.get("chain");
      if (qc && X.CHAINS[qc]) sel.value = qc;
      if (qa && X.checkAddress(qa).ok) { $("address").value = qa; runScan(); }
    } catch (e) {}
  }

  if (root && root.document && root.XRay) {
    if (root.document.readyState === "loading") root.document.addEventListener("DOMContentLoaded", () => init(root.XRay, root.document, root));
    else init(root.XRay, root.document, root);
  }

  return { TIP_ADDRESS, TIP_AMOUNTS, I18N, FLAG_INFO, OWNER_KIND, h, mount, textOf, safeHref, renderReport, renderError, init, fmt };
});
