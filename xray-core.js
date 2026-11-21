/*! Contract X-Ray core — in-browser EVM contract risk scanner. MIT License.
 *
 * Zero dependencies. Works in the browser (<script src="xray-core.js"> -> window.XRay)
 * and in Node 18+ (require("./xray-core.js")).
 *
 * What it does: given a contract address, it reads bytecode + a handful of storage slots and
 * view functions over JSON-RPC, then reports who can change the contract and what privileged
 * switches exist (upgrade, mint, pause, blacklist, fee/tax, trading switch, seize, limits).
 * It is a heuristic static + state check, NOT an audit and NOT a trade simulation.
 *
 * Data sources (all read-only): a public JSON-RPC endpoint, the visitor's own wallet provider
 * (EIP-1193), or a custom RPC URL; plus Sourcify for source-verification status.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.XRay = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const VERSION = "1.0.0";

  // ---------------------------------------------------------------------------
  // Chains. Public endpoints are tried in order; the first one that answers wins
  // and becomes "sticky" for the rest of the scan.
  // ---------------------------------------------------------------------------
  const CHAINS = {
    base: { id: 8453, name: "Base", explorer: "https://basescan.org",
      rpc: ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"] },
    ethereum: { id: 1, name: "Ethereum", explorer: "https://etherscan.io",
      rpc: ["https://ethereum-rpc.publicnode.com", "https://ethereum.reth.rs/rpc", "https://eth.drpc.org"] },
    arbitrum: { id: 42161, name: "Arbitrum One", explorer: "https://arbiscan.io",
      rpc: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"] },
    optimism: { id: 10, name: "OP Mainnet", explorer: "https://optimistic.etherscan.io",
      rpc: ["https://mainnet.optimism.io", "https://optimism-rpc.publicnode.com"] },
    polygon: { id: 137, name: "Polygon PoS", explorer: "https://polygonscan.com",
      rpc: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com"] },
    bsc: { id: 56, name: "BNB Smart Chain", explorer: "https://bscscan.com",
      rpc: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org"] },
  };

  // Well-known contracts: informational label only, never changes the score.
  const KNOWN = {
    base: {
      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": { label: "USD Coin (USDC), issued by Circle", kind: "issuer-stablecoin" },
      "0x4200000000000000000000000000000000000006": { label: "Wrapped Ether (WETH), OP Stack predeploy", kind: "wrapper" },
    },
    ethereum: {
      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": { label: "USD Coin (USDC), issued by Circle", kind: "issuer-stablecoin" },
      "0xdac17f958d2ee523a2206206994597c13d831ec7": { label: "Tether USD (USDT), issued by Tether", kind: "issuer-stablecoin" },
      "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": { label: "Wrapped Ether (WETH9)", kind: "wrapper" },
    },
    arbitrum: { "0xaf88d065e77c8cc2239327c5edb3a432268e5831": { label: "USD Coin (native USDC), issued by Circle", kind: "issuer-stablecoin" } },
    optimism: { "0x0b2c639c533813f4aa9d7837caf62653d097ff85": { label: "USD Coin (native USDC), issued by Circle", kind: "issuer-stablecoin" } },
    polygon: { "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": { label: "USD Coin (native USDC), issued by Circle", kind: "issuer-stablecoin" } },
    bsc: { "0x55d398326f99059ff775485246999027b3197955": { label: "Binance-Peg BSC-USD (USDT)", kind: "issuer-stablecoin" } },
  };

  // ---------------------------------------------------------------------------
  // Keccak-256 (pure JS, 32-bit lanes). sponge256(bytes, 0x06) is SHA3-256, so the
  // permutation can be cross-checked against Node's crypto in the tests.
  // ---------------------------------------------------------------------------
  const RC = [
    1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648,
    32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905,
    2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
    2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648,
  ];
  const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
  const PI = new Array(25);
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);

  function keccakF(s) {
    const C = new Uint32Array(10);
    const B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const p = ((x + 4) % 5) * 2, n = ((x + 1) % 5) * 2;
        const dl = C[p] ^ ((C[n] << 1) | (C[n + 1] >>> 31));
        const dh = C[p + 1] ^ ((C[n + 1] << 1) | (C[n] >>> 31));
        for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= dl; s[2 * (x + y) + 1] ^= dh; }
      }
      for (let i = 0; i < 25; i++) {
        const lo = s[2 * i], hi = s[2 * i + 1], r = ROT[i], j = 2 * PI[i];
        if (r === 0) { B[j] = lo; B[j + 1] = hi; }
        else if (r < 32) { B[j] = (lo << r) | (hi >>> (32 - r)); B[j + 1] = (hi << r) | (lo >>> (32 - r)); }
        else if (r === 32) { B[j] = hi; B[j + 1] = lo; }
        else { const m = r - 32; B[j] = (hi << m) | (lo >>> (32 - m)); B[j + 1] = (lo << m) | (hi >>> (32 - m)); }
      }
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          const a = 2 * (x + y), b = 2 * (((x + 1) % 5) + y), c = 2 * (((x + 2) % 5) + y);
          s[a] = B[a] ^ (~B[b] & B[c]);
          s[a + 1] = B[a + 1] ^ (~B[b + 1] & B[c + 1]);
        }
      }
      s[0] ^= RC[2 * round];
      s[1] ^= RC[2 * round + 1];
    }
  }

  function sponge256(bytes, padByte) {
    const rate = 136;
    const s = new Uint32Array(50);
    const padded = new Uint8Array((Math.floor(bytes.length / rate) + 1) * rate);
    padded.set(bytes);
    padded[bytes.length] ^= padByte;
    padded[padded.length - 1] ^= 0x80;
    for (let off = 0; off < padded.length; off += rate) {
      for (let i = 0; i < rate / 4; i++) {
        const k = off + 4 * i;
        s[i] ^= padded[k] | (padded[k + 1] << 8) | (padded[k + 2] << 16) | (padded[k + 3] << 24);
      }
      keccakF(s);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[4 * i] = s[i] & 0xff; out[4 * i + 1] = (s[i] >>> 8) & 0xff;
      out[4 * i + 2] = (s[i] >>> 16) & 0xff; out[4 * i + 3] = (s[i] >>> 24) & 0xff;
    }
    return out;
  }

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const keccak256 = (input) => sponge256(typeof input === "string" ? enc.encode(input) : input, 0x01);

  // ---------------------------------------------------------------------------
  // Hex / ABI helpers
  // ---------------------------------------------------------------------------
  const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  const bytesToHex = (b) => { let s = ""; for (let i = 0; i < b.length; i++) s += HEX[b[i]]; return s; };
  function hexToBytes(hex) {
    const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
    const out = new Uint8Array(h.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
    return out;
  }
  const selectorOf = (sig) => bytesToHex(keccak256(sig).subarray(0, 4));
  const isAddr = (a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
  const ZERO = "0x0000000000000000000000000000000000000000";

  function toChecksum(addr) {
    if (!isAddr(addr)) return addr;
    const lower = addr.slice(2).toLowerCase();
    const h = bytesToHex(keccak256(lower));
    let out = "0x";
    for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
    return out;
  }
  // Mixed-case input must match its EIP-55 checksum; all-lower / all-upper is accepted as unchecked.
  function checkAddress(input) {
    const a = String(input || "").trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return { ok: false, reason: "format" };
    const body = a.slice(2);
    const mixed = body !== body.toLowerCase() && body !== body.toUpperCase();
    if (mixed && toChecksum(a) !== a) return { ok: false, reason: "checksum" };
    return { ok: true, address: toChecksum(a), checksummed: mixed };
  }

  function wordToAddress(word) {
    if (typeof word !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(word)) return null;
    if (!/^0{24}$/.test(word.slice(2, 26))) return null;
    return "0x" + word.slice(26).toLowerCase();
  }
  function decodeUint(hex) {
    if (typeof hex !== "string" || !/^0x[0-9a-fA-F]{64,}$/.test(hex)) return null;
    return BigInt("0x" + hex.slice(2, 66));
  }
  function decodeBool(hex) { const v = decodeUint(hex); return v === null ? null : v === 1n ? true : v === 0n ? false : null; }
  // Token names/symbols are attacker-controlled: keep printable ASCII only, short. Callers must still render as text.
  function cleanStr(s) { return s.replace(/[^\x20-\x7e]/g, "").trim().slice(0, 64); }
  function decodeString(hex) {
    if (typeof hex !== "string" || hex.length < 66 || !/^0x[0-9a-fA-F]*$/.test(hex)) return null;
    const b = hexToBytes(hex);
    if (b.length === 32) { let end = 0; while (end < 32 && b[end] !== 0) end++; return cleanStr(dec.decode(b.subarray(0, end))) || null; }
    try {
      const off = Number(BigInt("0x" + bytesToHex(b.subarray(0, 32))));
      if (off + 32 > b.length) return null;
      const len = Number(BigInt("0x" + bytesToHex(b.subarray(off, off + 32))));
      if (off + 32 + len > b.length || len > 1024) return null;
      return cleanStr(dec.decode(b.subarray(off + 32, off + 32 + len))) || null;
    } catch (e) { return null; }
  }
  function decodeAddressArray(hex, max) {
    max = max || 20;
    if (typeof hex !== "string" || hex.length < 130) return null;
    try {
      const b = hex.slice(2);
      const off = Number(BigInt("0x" + b.slice(0, 64))) * 2;
      if (off + 64 > b.length) return null;
      const len = Number(BigInt("0x" + b.slice(off, off + 64)));
      if (len > 1000) return null;
      const out = [];
      for (let i = 0; i < Math.min(len, max); i++) {
        const a = wordToAddress("0x" + b.slice(off + 64 + 64 * i, off + 128 + 64 * i));
        if (a) out.push(toChecksum(a));
      }
      return { count: len, items: out };
    } catch (e) { return null; }
  }

  // ---------------------------------------------------------------------------
  // Function-signature registry (selectors computed at load time — no magic hex)
  // ---------------------------------------------------------------------------
  const SIGS = {
    erc20: ["transfer(address,uint256)", "balanceOf(address)", "totalSupply()", "approve(address,uint256)",
      "allowance(address,address)", "transferFrom(address,address,uint256)"],
    erc721: ["ownerOf(uint256)", "safeTransferFrom(address,address,uint256)", "tokenURI(uint256)"],
    erc1155: ["balanceOfBatch(address[],uint256[])", "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"],
    mint: ["mint(address,uint256)", "mint(uint256)", "mintTo(address,uint256)", "mint(address,uint256,bytes)",
      "issue(uint256)", "mintFor(address,uint256)"],
    pause: ["pause()", "unpause()", "setPaused(bool)", "setPause(bool)"],
    blacklist: ["blacklist(address)", "unBlacklist(address)", "addToBlacklist(address)", "removeFromBlacklist(address)",
      "setBlacklist(address,bool)", "isBlacklisted(address)", "blacklistAddress(address,bool)", "addBlackList(address)",
      "setBot(address,bool)", "setBots(address[],bool)", "freeze(address)", "freezeAccount(address,bool)",
      "setBlacklisted(address,bool)", "updateBlacklist(address,bool)"],
    fees: ["setFee(uint256)", "setFees(uint256,uint256)", "setTaxFee(uint256)", "setBuyFee(uint256)", "setSellFee(uint256)",
      "setBuyTax(uint256)", "setSellTax(uint256)", "setTaxes(uint256,uint256)", "updateFees(uint256,uint256)",
      "setFeePercent(uint256)", "setTransferFee(uint256)", "updateBuyFees(uint256,uint256,uint256)",
      "updateSellFees(uint256,uint256,uint256)", "setTax(uint256)", "setFees(uint256,uint256,uint256,uint256)"],
    limits: ["setMaxTxAmount(uint256)", "setMaxTxPercent(uint256)", "setMaxWalletSize(uint256)", "setMaxWallet(uint256)",
      "updateMaxTxnAmount(uint256)", "updateMaxWalletAmount(uint256)", "setMaxTransactionAmount(uint256)"],
    trading: ["enableTrading()", "openTrading()", "setTradingEnabled(bool)", "startTrading()", "setTrading(bool)",
      "setTradingOpen(bool)"],
    feeExclusion: ["excludeFromFee(address)", "excludeFromFees(address,bool)", "setExcludedFromFee(address,bool)",
      "setIsFeeExempt(address,bool)"],
    upgrade: ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
    ownable: ["transferOwnership(address)", "renounceOwnership()"],
    roles: ["grantRole(bytes32,address)", "revokeRole(bytes32,address)"],
    seize: ["destroyBlackFunds(address)", "wipeFrozenAddress(address)", "seize(address,uint256)", "confiscate(address,uint256)"],
    adminBurn: ["burn(address,uint256)"],
  };
  const SEL = {};
  for (const cat of Object.keys(SIGS)) SEL[cat] = SIGS[cat].map((sig) => ({ sig, sel: selectorOf(sig) }));
  const CALL = {};
  for (const sig of ["owner()", "getOwner()", "name()", "symbol()", "decimals()", "totalSupply()", "paused()",
    "implementation()", "getThreshold()", "getOwners()", "getMinDelay()"]) CALL[sig.slice(0, sig.indexOf("("))] = "0x" + selectorOf(sig);

  const slotMinus1 = (s) => "0x" + (BigInt("0x" + bytesToHex(keccak256(s))) - 1n).toString(16).padStart(64, "0");
  const SLOTS = {
    eip1967Impl: slotMinus1("eip1967.proxy.implementation"),
    eip1967Admin: slotMinus1("eip1967.proxy.admin"),
    eip1967Beacon: slotMinus1("eip1967.proxy.beacon"),
    eip1822: "0x" + bytesToHex(keccak256("PROXIABLE")),
    zos: "0x" + bytesToHex(keccak256("org.zeppelinos.proxy.implementation")),
    slot0: "0x" + "0".repeat(64),
  };

  // ---------------------------------------------------------------------------
  // Bytecode analysis
  // ---------------------------------------------------------------------------
  function isHexCode(hex) { return typeof hex === "string" && /^0x([0-9a-fA-F]{2})*$/.test(hex); }

  function analyzeBytecode(hex) {
    const code = hexToBytes(hex || "0x");
    let end = code.length;
    if (end >= 4) { // strip trailing solc/vyper CBOR metadata: [..cbor..][len:2]
      const mlen = (code[end - 2] << 8) | code[end - 1];
      if (mlen > 0 && mlen + 2 < end && (code[end - 2 - mlen] & 0xf0) === 0xa0) end = end - 2 - mlen;
    }
    const pushes = new Set();
    const push32 = new Set();
    const ops = { selfdestruct: false, delegatecall: false, callcode: false, create2: false };
    for (let i = 0; i < end; i++) {
      const op = code[i];
      if (op >= 0x60 && op <= 0x7f) {
        const n = op - 0x5f;
        if ((n === 4 || n === 3) && i + n < code.length) {
          let v = n === 3 ? "00" : "";
          for (let k = 1; k <= n; k++) v += HEX[code[i + k]];
          pushes.add(v);
        } else if (n === 32 && i + n < code.length) {
          push32.add(bytesToHex(code.subarray(i + 1, i + 33)));
        }
        i += n;
        continue;
      }
      if (op === 0xff) ops.selfdestruct = true;
      else if (op === 0xf4) ops.delegatecall = true;
      else if (op === 0xf2) ops.callcode = true;
      else if (op === 0xf5) ops.create2 = true;
    }
    const matched = {};
    for (const cat of Object.keys(SEL)) {
      const hits = SEL[cat].filter((x) => pushes.has(x.sel)).map((x) => x.sig);
      if (hits.length) matched[cat] = hits;
    }
    const proxySlots = [];
    for (const k of ["eip1967Impl", "eip1967Beacon", "eip1822", "zos"]) if (push32.has(SLOTS[k].slice(2))) proxySlots.push(k);
    return { size: code.length, matched, ops, proxySlots };
  }

  function detectSpecialCode(hex) {
    const h = (hex || "0x").toLowerCase();
    let m = h.match(/^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/);
    if (m) return { type: "eip1167-minimal-proxy", target: "0x" + m[1] };
    m = h.match(/^0xef0100([0-9a-f]{40})$/);
    if (m) return { type: "eip7702-delegation", target: "0x" + m[1] };
    return null;
  }

  // ---------------------------------------------------------------------------
  // Providers. Each exposes batch(calls, requiredIdx) -> results[] (null = no result).
  // If any required result is missing, the endpoint counts as failed and the next one is tried,
  // so a rate-limited node can never make a contract look like an empty account.
  // ---------------------------------------------------------------------------
  function withTimeout(fetchFn, url, init, ms) {
    const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const t = setTimeout(() => ctl && ctl.abort(), ms);
    return fetchFn(url, Object.assign({}, init, ctl ? { signal: ctl.signal } : {})).finally(() => clearTimeout(t));
  }

  function mapResults(data, n) {
    const out = new Array(n).fill(null);
    if (!Array.isArray(data)) return out;
    for (const it of data) {
      if (it && Number.isInteger(it.id) && it.id >= 1 && it.id <= n && it.result !== undefined && it.result !== null) out[it.id - 1] = it.result;
    }
    return out;
  }
  const missing = (out, required) => (required || []).filter((i) => out[i] === null || out[i] === undefined);

  function httpProvider(urls, opts) {
    opts = opts || {};
    const fetchFn = opts.fetch || ((u, i) => fetch(u, i));
    const timeoutMs = opts.timeoutMs || 12000;
    const log = opts.log || function () {};
    const list = urls.filter((u) => /^https:\/\//i.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)(:|\/)/i.test(u));
    let sticky = 0;
    const state = { used: null };
    async function postJson(url, payload) {
      const r = await withTimeout(fetchFn, url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }, timeoutMs);
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }
    async function batch(calls, required) {
      if (!calls.length) return [];
      if (!list.length) throw new Error("no usable RPC URL (https:// required)");
      const payload = calls.map((c, i) => ({ jsonrpc: "2.0", id: i + 1, method: c[0], params: c[1] }));
      let lastErr = null;
      for (let k = 0; k < list.length; k++) {
        const idx = (sticky + k) % list.length;
        const url = list[idx];
        const t0 = Date.now();
        try {
          let data = await postJson(url, payload);
          if (!Array.isArray(data)) {
            // Endpoint refused the batch (or capped its size): replay as single calls, 4 at a time.
            const out = [];
            for (let i = 0; i < payload.length; i += 4) {
              const part = await Promise.all(payload.slice(i, i + 4).map((p) => postJson(url, p).catch(() => null)));
              out.push.apply(out, part);
            }
            data = out;
          }
          const out = mapResults(data, calls.length);
          const miss = missing(out, required);
          if (miss.length) throw new Error("incomplete answer (" + calls[miss[0]][0] + " missing; rate-limited?)");
          sticky = idx; state.used = url;
          log({ ok: true, url, ms: Date.now() - t0, calls: calls.length });
          return out;
        } catch (e) {
          lastErr = e;
          log({ ok: false, url, ms: Date.now() - t0, error: e && e.name === "AbortError" ? "timeout" : (e && e.message) || String(e) });
        }
      }
      throw new Error("all RPC endpoints failed (last: " + (lastErr ? (lastErr.name === "AbortError" ? "timeout" : lastErr.message) : "unknown") + ")");
    }
    return { kind: "http", batch, state, label: () => state.used || list[0] };
  }

  // The visitor's own wallet (MetaMask, Rabby, Coinbase Wallet...). No CORS involved. Read-only calls only.
  function eip1193Provider(eth, expectedChainId, opts) {
    opts = opts || {};
    const log = opts.log || function () {};
    const state = { used: "wallet provider" };
    let checked = false;
    async function batch(calls, required) {
      if (!calls.length) return [];
      const t0 = Date.now();
      if (!checked) {
        const cid = await eth.request({ method: "eth_chainId" });
        if (parseInt(cid, 16) !== expectedChainId) {
          const err = new Error("wallet is on chain " + parseInt(cid, 16) + ", expected " + expectedChainId);
          err.code = "WRONG_CHAIN"; throw err;
        }
        checked = true;
      }
      const out = await Promise.all(calls.map((c) => eth.request({ method: c[0], params: c[1] }).then((r) => (r === undefined ? null : r), () => null)));
      const miss = missing(out, required);
      if (miss.length) { log({ ok: false, url: "wallet", ms: Date.now() - t0, error: calls[miss[0]][0] + " failed" }); throw new Error("wallet provider could not answer " + calls[miss[0]][0]); }
      log({ ok: true, url: "wallet", ms: Date.now() - t0, calls: calls.length });
      return out;
    }
    return { kind: "wallet", batch, state, label: () => "wallet provider" };
  }

  const ethCall = (to, data) => ["eth_call", [{ to, data }, "latest"]];
  const getCode = (a) => ["eth_getCode", [a, "latest"]];
  const getSlot = (a, s) => ["eth_getStorageAt", [a, s, "latest"]];
  const hasCode = (c) => typeof c === "string" && c.length > 2;

  async function sourcifyStatus(chainId, address, opts) {
    opts = opts || {};
    const fetchFn = opts.fetch || ((u, i) => fetch(u, i));
    try {
      const r = await withTimeout(fetchFn, "https://sourcify.dev/server/v2/contract/" + chainId + "/" + address, { headers: { accept: "application/json" } }, opts.timeoutMs || 8000);
      if (r.status === 404) return "not_found";
      if (!r.ok) return "error";
      const j = await r.json();
      return j.match || j.runtimeMatch || "error";
    } catch (e) { return "error"; }
  }

  // ---------------------------------------------------------------------------
  // Scoring rules
  // ---------------------------------------------------------------------------
  const SEV_WEIGHT = { high: 30, medium: 12, low: 4, info: 0 };
  const DOWNGRADE = { high: "medium", medium: "low", low: "info", info: "info" };

  const RULES = [
    { id: "MINTABLE", cat: "mint", sev: "high", token: true, text: "Privileged mint function — supply can be inflated." },
    { id: "FEE_CONTROL", cat: "fees", sev: "high", text: "Owner-settable buy/sell/transfer fee — classic honeypot vector (fee can be raised toward 100%)." },
    { id: "ADMIN_SEIZE", cat: "seize", sev: "high", text: "Functions that can destroy or seize a holder's balance." },
    { id: "BLACKLIST", cat: "blacklist", sev: "medium", text: "Blacklist/freeze/bot-list functions — specific holders can be blocked from transferring." },
    { id: "PAUSABLE", cat: "pause", sev: "medium", text: "Privileged pause switch — transfers or core functions can be halted." },
    { id: "TX_LIMITS", cat: "limits", sev: "medium", text: "Owner-adjustable max-tx / max-wallet limits — can be tightened to block sells." },
    { id: "TRADING_SWITCH", cat: "trading", sev: "medium", text: "Trading enable switch — trading is gated by a privileged account." },
    { id: "ADMIN_BURN", cat: "adminBurn", sev: "medium", text: "burn(address,uint256) — may let a privileged account burn other holders' tokens (check access control)." },
    { id: "SELF_UPGRADE", cat: "upgrade", sev: "medium", text: "UUPS upgrade entrypoints in the logic contract — code can be replaced." },
    { id: "FEE_EXEMPTIONS", cat: "feeExclusion", sev: "low", text: "Fee-exemption list — insiders may trade without tax." },
  ];

  function finish(flags) {
    const score = Math.min(100, flags.reduce((s, f) => s + SEV_WEIGHT[f.severity], 0));
    const level = score >= 60 ? "high" : score >= 25 ? "medium" : "low";
    return { score, level };
  }

  const DISCLAIMER = "Heuristic static + state analysis, not an audit and not a trade simulation. Absence of flags is not a guarantee of safety.";

  // ---------------------------------------------------------------------------
  // The online scan
  // ---------------------------------------------------------------------------
  async function classifyAccounts(provider, addrs) {
    const uniq = Array.from(new Set(addrs.filter((a) => isAddr(a) && a !== ZERO)));
    const out = {};
    if (!uniq.length) return out;
    const codes = await provider.batch(uniq.map(getCode), uniq.map((_, i) => i));
    const contracts = uniq.filter((a, i) => hasCode(codes[i]) && !detectSpecialCode(codes[i]));
    uniq.forEach((a, i) => {
      const sp = hasCode(codes[i]) ? detectSpecialCode(codes[i]) : null;
      out[a] = sp && sp.type === "eip7702-delegation" ? { kind: "eoa-7702", delegate: toChecksum(sp.target) }
        : hasCode(codes[i]) ? { kind: "contract" } : { kind: "eoa" };
    });
    if (contracts.length) {
      const calls = [];
      for (const a of contracts) calls.push(ethCall(a, CALL.getThreshold), ethCall(a, CALL.getOwners), ethCall(a, CALL.getMinDelay));
      const res = await provider.batch(calls, []);
      contracts.forEach((a, i) => {
        const th = decodeUint(res[3 * i]);
        const owners = decodeAddressArray(res[3 * i + 1]);
        const delay = decodeUint(res[3 * i + 2]);
        if (th !== null && owners && owners.count > 0) out[a] = { kind: "safe", safe: { threshold: Number(th), ownerCount: owners.count, owners: owners.items } };
        else if (delay !== null) out[a] = { kind: "timelock", timelockDelaySec: Number(delay) };
      });
    }
    return out;
  }

  async function scan(provider, chain, rawAddress, opts) {
    opts = opts || {};
    const t0 = Date.now();
    const cfg = CHAINS[chain];
    if (!cfg) throw new Error("unsupported chain: " + chain);
    const chk = checkAddress(rawAddress);
    if (!chk.ok) throw new Error(chk.reason === "checksum" ? "address checksum mismatch (mixed-case typo?)" : "not a 0x… 40-hex-character address");
    const address = chk.address.toLowerCase();

    const p1Calls = [
      ["eth_blockNumber", []], getCode(address),
      getSlot(address, SLOTS.eip1967Impl), getSlot(address, SLOTS.eip1967Admin), getSlot(address, SLOTS.eip1967Beacon),
      getSlot(address, SLOTS.eip1822), getSlot(address, SLOTS.zos), getSlot(address, SLOTS.slot0),
      ethCall(address, CALL.owner), ethCall(address, CALL.getOwner), ethCall(address, CALL.name), ethCall(address, CALL.symbol),
      ethCall(address, CALL.decimals), ethCall(address, CALL.totalSupply), ethCall(address, CALL.paused),
      ["eth_getProof", [address, [], "latest"]],
    ];
    // getCode and the proxy slots are required: without them we cannot tell a contract from an empty account.
    const sourcifyP = opts.sourcify === false ? Promise.resolve("skipped") : sourcifyStatus(cfg.id, toChecksum(address), { fetch: opts.fetch });
    const p1 = await provider.batch(p1Calls, [1, 2, 3, 4, 5, 6, 7]);
    const sourcify = await sourcifyP;
    const [blockHex, code, sImpl, sAdmin, sBeacon, s1822, sZos, sSlot0, rOwner, rGetOwner, rName, rSymbol, rDecimals, rSupply, rPaused, rProof] = p1;
    const block = typeof blockHex === "string" ? parseInt(blockHex, 16) : null;
    const known = (KNOWN[chain] || {})[address] || null;
    const base = { address: toChecksum(address), chain, chainId: cfg.id, block, known };
    const meta = () => ({ tool: "Contract X-Ray", version: VERSION, generatedAt: new Date().toISOString(), durationMs: Date.now() - t0, rpc: provider.label() });

    if (!hasCode(code)) {
      return {
        ...base, kind: "eoa",
        verdict: { score: 0, level: "n/a", summary: "No contract code at this address on " + cfg.name + " (a regular wallet, or not deployed on this chain). Nothing to scan." },
        flags: [], disclaimer: DISCLAIMER, meta: meta(),
      };
    }

    const special = detectSpecialCode(code);
    const proxy = { isProxy: false, type: null, implementation: null, admin: null, beacon: null };
    let logicAddr = null;
    const implFromSlot = (w) => { const a = wordToAddress(w); return a && a !== ZERO ? a : null; };

    if (special && special.type === "eip7702-delegation") {
      proxy.isProxy = true; proxy.type = "eip7702-delegated-eoa"; proxy.implementation = special.target; logicAddr = special.target;
    } else if (special && special.type === "eip1167-minimal-proxy") {
      proxy.isProxy = true; proxy.type = "eip1167-minimal-proxy (immutable)"; proxy.implementation = special.target; logicAddr = special.target;
    } else if (implFromSlot(sImpl)) {
      logicAddr = implFromSlot(sImpl); proxy.isProxy = true; proxy.implementation = logicAddr;
      proxy.admin = implFromSlot(sAdmin);
      proxy.type = proxy.admin ? "eip1967-transparent" : "eip1967 (uups or custom)";
    } else if (implFromSlot(sBeacon)) {
      proxy.isProxy = true; proxy.type = "eip1967-beacon"; proxy.beacon = implFromSlot(sBeacon);
      const bi = await provider.batch([ethCall(proxy.beacon, CALL.implementation)], []);
      logicAddr = wordToAddress(bi[0]); proxy.implementation = logicAddr;
    } else if (implFromSlot(s1822)) {
      logicAddr = implFromSlot(s1822); proxy.isProxy = true; proxy.type = "eip1822-uups"; proxy.implementation = logicAddr;
    } else if (implFromSlot(sZos)) {
      logicAddr = implFromSlot(sZos); proxy.isProxy = true; proxy.type = "legacy-zeppelinos"; proxy.implementation = logicAddr;
    }

    const selfInfo = analyzeBytecode(code);
    if (!proxy.isProxy && selfInfo.size < 300 && selfInfo.ops.delegatecall && implFromSlot(sSlot0)) {
      logicAddr = implFromSlot(sSlot0); proxy.isProxy = true; proxy.type = "slot0-proxy (e.g. Safe)"; proxy.implementation = logicAddr;
    }

    // Phase 2: logic code + owner / admin classification
    const owner = wordToAddress(rOwner) || wordToAddress(rGetOwner);
    const p2Calls = [];
    if (logicAddr) p2Calls.push(getCode(logicAddr));
    if (proxy.admin) p2Calls.push(ethCall(proxy.admin, CALL.owner));
    const p2 = await provider.batch(p2Calls, logicAddr ? [0] : []);
    const logicCode = logicAddr ? p2[0] : null;
    const adminOwner = proxy.admin ? wordToAddress(p2[logicAddr ? 1 : 0]) : null;
    const logicInfo = logicAddr && hasCode(logicCode) ? analyzeBytecode(logicCode) : selfInfo;
    const accounts = await classifyAccounts(provider, [owner, proxy.admin, adminOwner].filter(Boolean));

    // Control model
    const roleBased = !!logicInfo.matched.roles;
    const ownerInfo = owner ? (owner === ZERO ? { kind: "renounced" } : accounts[owner] || { kind: "unknown" }) : null;
    let upgradeAuthority = null;
    if (proxy.isProxy && !/immutable/.test(proxy.type)) {
      if (proxy.type === "eip7702-delegated-eoa") upgradeAuthority = { kind: "eoa" };
      else if (proxy.admin) {
        const a = accounts[proxy.admin] || { kind: "unknown" };
        upgradeAuthority = a.kind === "contract" && adminOwner ? (accounts[adminOwner] || { kind: "unknown" }) : a;
      } else upgradeAuthority = ownerInfo && ownerInfo.kind !== "renounced" ? ownerInfo : { kind: "unknown" };
    }
    const control = {
      owner: owner ? toChecksum(owner) : null,
      ownerType: ownerInfo ? ownerInfo.kind : roleBased ? "role-based" : "none-detected",
      roleBasedAccess: roleBased,
    };
    if (ownerInfo && ownerInfo.safe) control.safe = ownerInfo.safe;
    if (ownerInfo && ownerInfo.timelockDelaySec !== undefined) control.timelockDelaySec = ownerInfo.timelockDelaySec;
    if (proxy.admin) { control.proxyAdmin = toChecksum(proxy.admin); control.proxyAdminOwner = adminOwner ? toChecksum(adminOwner) : null; }
    if (upgradeAuthority) control.upgradeAuthorityType = upgradeAuthority.kind;

    // Token metadata
    const m = logicInfo.matched;
    const standard = m.erc1155 && m.erc1155.length >= 2 ? "erc1155" : m.erc721 && m.erc721.length >= 2 ? "erc721"
      : m.erc20 && m.erc20.length >= 4 ? "erc20" : null;
    const token = standard ? {
      standard, name: decodeString(rName), symbol: decodeString(rSymbol),
      decimals: decodeUint(rDecimals) !== null ? Number(decodeUint(rDecimals)) : null,
      totalSupply: decodeUint(rSupply) !== null ? decodeUint(rSupply).toString() : null,
    } : null;

    // Flags
    const flags = [];
    const privKind = ownerInfo ? ownerInfo.kind : roleBased ? "role-based" : "unknown";
    const adjust = (sev) => {
      if (privKind === "renounced" && !roleBased && !upgradeAuthority) return { sev: "info", note: " Owner renounced and no role system detected, so likely unusable." };
      if (privKind === "safe" && ownerInfo.safe && ownerInfo.safe.threshold >= 2) return { sev: DOWNGRADE[sev], note: " Controlled by a " + ownerInfo.safe.threshold + "-of-" + ownerInfo.safe.ownerCount + " Safe." };
      if (privKind === "timelock") return { sev: DOWNGRADE[sev], note: " Behind a timelock (" + ownerInfo.timelockDelaySec + "s delay)." };
      if (privKind === "eoa" || privKind === "eoa-7702") return { sev, note: " Controlled by a single EOA key." };
      return { sev, note: "" };
    };
    const add = (id, severity, detail) => flags.push({ id, severity, detail });

    if (decodeBool(rPaused) === true) add("CURRENTLY_PAUSED", "high", "paused() returns true right now — transfers/actions are likely blocked.");
    if (proxy.isProxy) {
      if (proxy.type === "eip7702-delegated-eoa") add("EIP7702_DELEGATED", "medium", "EOA delegating its code to " + toChecksum(proxy.implementation) + " via EIP-7702; the key holder can change behaviour at any time.");
      else if (/immutable/.test(proxy.type)) add("MINIMAL_PROXY", "info", "EIP-1167 clone of " + toChecksum(proxy.implementation) + " (logic cannot be swapped).");
      else {
        const k = upgradeAuthority ? upgradeAuthority.kind : "unknown";
        const sev = k === "eoa" || k === "eoa-7702" ? "high" : k === "safe" || k === "timelock" ? "low" : "medium";
        add("UPGRADEABLE", sev, "Upgradeable proxy (" + proxy.type + "); logic at " + (proxy.implementation ? toChecksum(proxy.implementation) : "unknown") + " can be replaced by a " + k + " authority.");
      }
    }
    for (const r of RULES) {
      if (!m[r.cat]) continue;
      if (r.token && !token) continue;
      if (r.cat === "upgrade" && proxy.isProxy) continue; // already covered by UPGRADEABLE
      const a = adjust(r.sev);
      add(r.id, a.sev, r.text + " [" + m[r.cat].join(", ") + "]" + a.note);
    }
    const privilegedCount = flags.filter((f) => RULES.some((r) => r.id === f.id) && f.severity !== "info").length;
    if ((privKind === "eoa" || privKind === "eoa-7702") && privilegedCount > 0) add("SINGLE_KEY_CONTROL", "medium", "Owner " + toChecksum(owner) + " is an EOA — one leaked or malicious key controls " + privilegedCount + " privileged capability(ies).");
    if (privKind === "renounced") add("OWNERSHIP_RENOUNCED", "info", "owner() is the zero address.");
    if (privKind === "safe" && ownerInfo.safe) add("SAFE_OWNED", "info", "Owner is a Safe multisig (" + ownerInfo.safe.threshold + "-of-" + ownerInfo.safe.ownerCount + ").");
    if (sourcify === "not_found") add("UNVERIFIED_SOURCIFY", "low", "Source not verified on Sourcify (it may still be verified on a block explorer).");
    if (sourcify === "exact_match" || sourcify === "match") add("VERIFIED_SOURCIFY", "info", "Source verified on Sourcify (" + sourcify + ").");
    if (logicInfo.ops.selfdestruct) add("SELFDESTRUCT_OPCODE", "low", "SELFDESTRUCT opcode present (post EIP-6780 it can still sweep ETH).");
    if (!proxy.isProxy && logicInfo.ops.delegatecall) add("DELEGATECALL_OPCODE", "info", "DELEGATECALL present in a non-proxy contract — review what it can call.");
    if (known) add("KNOWN_CONTRACT", "info", "Well-known contract: " + known.label + "." + (known.kind === "issuer-stablecoin" ? " Issuer-controlled freeze/pause/upgrade powers are expected for this kind of asset; the question is who holds them." : ""));

    const v = finish(flags);
    const top = flags.filter((f) => f.severity === "high" || f.severity === "medium").map((f) => f.id);
    const summary = (token ? (token.symbol || token.standard.toUpperCase()) + " " : "") + (proxy.isProxy ? "proxy" : "contract") + " on " + cfg.name + ": " +
      "risk " + v.level + " (" + v.score + "/100)" + (top.length ? "; key issues: " + top.join(", ") : "; no major privileged-control red flags found") + ".";

    return {
      ...base, kind: proxy.type === "eip7702-delegated-eoa" ? "eip7702-delegated-eoa" : "contract",
      verdict: { score: v.score, level: v.level, summary },
      flags,
      proxy: { ...proxy, implementation: proxy.implementation ? toChecksum(proxy.implementation) : null,
        admin: proxy.admin ? toChecksum(proxy.admin) : null, beacon: proxy.beacon ? toChecksum(proxy.beacon) : null },
      control, token,
      code: {
        size: selfInfo.size, logicAddress: logicAddr ? toChecksum(logicAddr) : null, logicSize: logicInfo.size,
        codeHash: rProof && rProof.codeHash ? rProof.codeHash : null,
        opcodes: logicInfo.ops,
      },
      source: { sourcify },
      matchedFunctions: m,
      disclaimer: DISCLAIMER,
      meta: meta(),
    };
  }

  // ---------------------------------------------------------------------------
  // Offline mode: analyse pasted runtime bytecode. No network at all.
  // ---------------------------------------------------------------------------
  function analyzeOffline(rawHex) {
    const hex = String(rawHex || "").trim().replace(/\s+/g, "");
    const h = /^0x/i.test(hex) ? "0x" + hex.slice(2) : "0x" + hex;
    if (!isHexCode(h) || h.length <= 2) throw new Error("paste the contract's runtime bytecode as hex (0x…)");
    const special = detectSpecialCode(h);
    const info = analyzeBytecode(h);
    const flags = [];
    const add = (id, severity, detail) => flags.push({ id, severity, detail });
    add("OFFLINE_ONLY", "info", "Bytecode-only analysis: owner type, live paused state, proxy implementation and verification were NOT checked.");
    if (special && special.type === "eip1167-minimal-proxy") add("MINIMAL_PROXY", "info", "EIP-1167 clone of " + toChecksum(special.target) + " — paste that contract's bytecode instead.");
    if (special && special.type === "eip7702-delegation") add("EIP7702_DELEGATED", "medium", "EIP-7702 delegation designator to " + toChecksum(special.target) + ".");
    const looksProxy = !special && (info.proxySlots.length > 0 || (info.size < 300 && info.ops.delegatecall));
    if (looksProxy) add("LOOKS_LIKE_PROXY", "medium", "This bytecode looks like a proxy" + (info.proxySlots.length ? " (references " + info.proxySlots.join(", ") + " slot)" : "") + " — the real logic lives elsewhere; paste the implementation's bytecode too.");
    const m = info.matched;
    const standard = m.erc1155 && m.erc1155.length >= 2 ? "erc1155" : m.erc721 && m.erc721.length >= 2 ? "erc721" : m.erc20 && m.erc20.length >= 4 ? "erc20" : null;
    for (const r of RULES) {
      if (!m[r.cat]) continue;
      if (r.token && !standard) continue;
      add(r.id, r.sev, r.text + " [" + m[r.cat].join(", ") + "] Who holds this power was not checked offline.");
    }
    if (info.ops.selfdestruct) add("SELFDESTRUCT_OPCODE", "low", "SELFDESTRUCT opcode present (post EIP-6780 it can still sweep ETH).");
    if (!looksProxy && !special && info.ops.delegatecall) add("DELEGATECALL_OPCODE", "info", "DELEGATECALL present — review what it can call.");
    const v = finish(flags);
    const top = flags.filter((f) => f.severity === "high" || f.severity === "medium").map((f) => f.id);
    return {
      kind: "offline-bytecode",
      verdict: { score: v.score, level: v.level, summary: "Offline bytecode check: risk " + v.level + " (" + v.score + "/100)" + (top.length ? "; key issues: " + top.join(", ") : "; no privileged-function selectors recognised") + ". State was not checked." },
      flags,
      token: standard ? { standard } : null,
      code: { size: info.size, opcodes: info.ops, proxySlots: info.proxySlots, codeHash: "0x" + bytesToHex(keccak256(hexToBytes(h))) },
      matchedFunctions: m,
      disclaimer: DISCLAIMER,
      meta: { tool: "Contract X-Ray", version: VERSION, generatedAt: new Date().toISOString(), rpc: "none (offline)" },
    };
  }

  // ---------------------------------------------------------------------------
  // Voluntary tips (USDC on Base). Pure helpers; the page wires them to the wallet.
  // ---------------------------------------------------------------------------
  const TIP = {
    chainIdHex: "0x2105", chainId: 8453,
    usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    addChainParams: { chainId: "0x2105", chainName: "Base", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: ["https://mainnet.base.org"], blockExplorerUrls: ["https://basescan.org"] },
  };
  const BLOCKED_TIP = new Set([ZERO, "0x000000000000000000000000000000000000dead"]);
  for (const c of Object.keys(KNOWN)) for (const a of Object.keys(KNOWN[c])) BLOCKED_TIP.add(a);
  // A tip address is shown only if it is EIP-55 mixed-case-valid and not a token/zero/burn address.
  function validTipAddress(a) {
    if (!isAddr(a)) return false;
    const body = a.slice(2);
    if (body === body.toLowerCase() || body === body.toUpperCase()) return false; // require checksum casing
    if (toChecksum(a) !== a) return false;
    return !BLOCKED_TIP.has(a.toLowerCase());
  }
  const pad32 = (hexNoPrefix) => hexNoPrefix.padStart(64, "0");
  function usdcUnits(amountStr) {
    const s = String(amountStr).trim();
    if (!/^\d{1,6}(\.\d{1,6})?$/.test(s)) throw new Error("amount must be a positive number with up to 6 decimals");
    const parts = s.split(".");
    const units = BigInt(parts[0]) * 1000000n + BigInt((parts[1] || "").padEnd(6, "0"));
    if (units <= 0n) throw new Error("amount must be greater than zero");
    return units;
  }
  function transferData(to, units) {
    if (!isAddr(to)) throw new Error("bad recipient");
    return "0x" + selectorOf("transfer(address,uint256)") + pad32(to.slice(2).toLowerCase()) + pad32(BigInt(units).toString(16));
  }
  function balanceOfData(owner) { return "0x" + selectorOf("balanceOf(address)") + pad32(owner.slice(2).toLowerCase()); }
  function eip681(to, units) { return "ethereum:" + TIP.usdc + "@" + TIP.chainId + "/transfer?address=" + to + "&uint256=" + BigInt(units).toString(); }

  return {
    VERSION, CHAINS, KNOWN, SLOTS, RULES,
    scan, analyzeOffline, httpProvider, eip1193Provider, sourcifyStatus,
    checkAddress, toChecksum, isAddr,
    tip: { TIP, validTipAddress, usdcUnits, transferData, balanceOfData, eip681 },
    _t: { keccak256, sponge256, bytesToHex, hexToBytes, selectorOf, analyzeBytecode, detectSpecialCode, decodeString,
      decodeAddressArray, wordToAddress, decodeUint, mapResults },
  };
});
