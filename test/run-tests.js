// Offline test suite for Contract X-Ray (core + page logic). No network, no dependencies.
// Run: node test/run-tests.js [--expect-tip 0xYourAddress]
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DIR = path.join(__dirname, "..");
const X = require(path.join(DIR, "xray-core.js"));
const APP = require(path.join(DIR, "app.js"));
const T = X._t;

let pass = 0, fail = 0;
const ok = (cond, name, extra) => { if (cond) pass++; else { fail++; console.log("FAIL:", name, extra !== undefined ? JSON.stringify(extra, (k, v) => (typeof v === "bigint" ? v.toString() : v)) : ""); } };
const eq = (a, b, name) => ok(a === b, name, { got: a, want: b });
async function throwsAsync(fn, re, name) { try { await fn(); ok(false, name, "did not throw"); } catch (e) { ok(re.test(String(e && e.message)), name, String(e && e.message)); } }
function throws(fn, re, name) { try { fn(); ok(false, name, "did not throw"); } catch (e) { ok(re.test(String(e && e.message)), name, String(e && e.message)); } }

(async () => {
  // ---- 1. Keccak ---------------------------------------------------------------------------
  eq(T.bytesToHex(T.keccak256("")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak('')");
  eq(T.bytesToHex(T.keccak256("abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "keccak('abc')");
  for (const n of [0, 1, 55, 135, 136, 137, 271, 272, 273, 1000, 4096]) {
    const buf = crypto.randomBytes(n);
    eq(T.bytesToHex(T.sponge256(new Uint8Array(buf), 0x06)), crypto.createHash("sha3-256").update(buf).digest("hex"), "sha3 cross-check len=" + n);
  }

  // ---- 2. Selectors, slots, checksums --------------------------------------------------------
  const known = { "transfer(address,uint256)": "a9059cbb", "balanceOf(address)": "70a08231", "owner()": "8da5cb5b",
    "mint(address,uint256)": "40c10f19", "pause()": "8456cb59", "upgradeTo(address)": "3659cfe6", "getThreshold()": "e75235b8",
    "implementation()": "5c60da1b", "paused()": "5c975abb", "name()": "06fdde03", "symbol()": "95d89b41", "decimals()": "313ce567" };
  for (const [sig, s] of Object.entries(known)) eq(T.selectorOf(sig), s, "selector " + sig);
  eq(X.SLOTS.eip1967Impl, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", "EIP-1967 impl slot");
  eq(X.SLOTS.eip1967Admin, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", "EIP-1967 admin slot");
  eq(X.SLOTS.eip1967Beacon, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", "EIP-1967 beacon slot");
  eq(X.toChecksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "EIP-55 vector");
  eq(X.checkAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").ok, true, "checkAddress valid mixed");
  eq(X.checkAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").reason, "checksum", "checkAddress catches checksum typo");
  eq(X.checkAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").ok, true, "checkAddress lower ok");
  eq(X.checkAddress("0x123").reason, "format", "checkAddress format");
  eq(X.checkAddress("  0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed ").address, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "checkAddress trims + checksums");
  for (const c of Object.keys(X.KNOWN)) {
    ok(!!X.CHAINS[c], "KNOWN chain exists " + c);
    for (const a of Object.keys(X.KNOWN[c])) ok(/^0x[0-9a-f]{40}$/.test(a), "KNOWN key lowercase " + a);
  }
  for (const [k, c] of Object.entries(X.CHAINS)) ok(c.rpc.length >= 2 && c.rpc.every((u) => u.startsWith("https://")), "chain has >=2 https RPCs " + k);

  // ---- 3. Bytecode analysis -----------------------------------------------------------------
  const sel = (s) => T.selectorOf(s);
  const p4 = (s) => "63" + sel(s) + "50";
  const ERC20 = ["transfer(address,uint256)", "balanceOf(address)", "totalSupply()", "approve(address,uint256)", "allowance(address,address)", "transferFrom(address,address,uint256)"];
  const META = "a264697066735822" + "11".repeat(34) + "64736f6c6343000814" + "0033";
  const mkCode = (sigs, extra) => "0x6080604052" + sigs.map(p4).join("") + (extra || "") + "00" + META;
  const tokenLogic = mkCode([...ERC20, "mint(address,uint256)", "pause()", "unpause()", "blacklist(address)", "transferOwnership(address)", "setSellFee(uint256)"]);
  const a1 = T.analyzeBytecode(tokenLogic);
  ok(a1.matched.mint && a1.matched.pause && a1.matched.blacklist && a1.matched.fees && a1.matched.erc20.length === 6, "analyze categories", a1.matched);
  ok(!a1.ops.selfdestruct && !a1.ops.delegatecall, "no false opcode hits from metadata", a1.ops);
  ok(!T.analyzeBytecode("0x63ffffffff50" + "7f" + "ff".repeat(32) + "00").ops.selfdestruct, "0xff in PUSH data ignored");
  ok(T.analyzeBytecode("0x6000f400").ops.delegatecall, "delegatecall detected");
  const pushSlot = "7f" + X.SLOTS.eip1967Impl.slice(2);
  eq(T.analyzeBytecode("0x" + pushSlot + "54" + "f4" + "00").proxySlots[0], "eip1967Impl", "PUSH32 EIP-1967 slot recognised");
  // PUSH3 selector with leading zero byte
  const zeroSelSig = Object.values(X.RULES).length && "mint(uint256)";
  ok(T.analyzeBytecode("0x63" + sel(zeroSelSig) + "50").matched.mint, "PUSH4 mint(uint256) matched");
  eq(T.detectSpecialCode("0x363d3d373d3d3d363d73" + "ab".repeat(20) + "5af43d82803e903d91602b57fd5bf3").type, "eip1167-minimal-proxy", "detect 1167");
  eq(T.detectSpecialCode("0xef0100" + "cd".repeat(20)).type, "eip7702-delegation", "detect 7702");

  // ---- 4. ABI decoding ----------------------------------------------------------------------
  const w = (hex) => hex.replace(/^0x/, "").padStart(64, "0");
  const encStr = (s) => { const hx = Buffer.from(s).toString("hex"); return "0x" + w("20") + w(Buffer.byteLength(s).toString(16)) + (hx.padEnd(Math.ceil(hx.length / 64) * 64 || 64, "0")); };
  eq(T.decodeString(encStr("Nova Token")), "Nova Token", "decode dynamic string");
  eq(T.decodeString("0x" + Buffer.from("MKR").toString("hex").padEnd(64, "0")), "MKR", "decode bytes32 string");
  eq(T.decodeString(encStr("<img src=x onerror=alert(1)>\u0007")), "<img src=x onerror=alert(1)>", "decode strips control chars (HTML stays text, rendered via textNode)");
  eq(T.decodeString("0x" + w("ffff") + w("1")), null, "decode string bad offset -> null");
  const encAddrs = (arr) => "0x" + w("20") + w(arr.length.toString(16)) + arr.map(w).join("");
  const decArr = T.decodeAddressArray(encAddrs(["0x" + "11".repeat(20), "0x" + "22".repeat(20)]));
  ok(decArr && decArr.count === 2 && decArr.items.length === 2, "decode address[]", decArr);

  // ---- 5. Mock chain ------------------------------------------------------------------------
  const A = (n) => "0x" + n.repeat(40).slice(0, 40);
  const chain = { code: {}, slots: {}, calls: {} };
  const setCall = (to, sig, ret) => { chain.calls[to.toLowerCase() + ":0x" + sel(sig)] = ret; };
  const addrWord = (a) => "0x" + w(a.slice(2).toLowerCase());
  const uintWord = (n) => "0x" + w(BigInt(n).toString(16));

  const TOKEN = A("a"), OWNER_EOA = A("b");
  chain.code[TOKEN] = tokenLogic;
  setCall(TOKEN, "owner()", addrWord(OWNER_EOA));
  setCall(TOKEN, "name()", encStr("Rug Token")); setCall(TOKEN, "symbol()", encStr("RUG"));
  setCall(TOKEN, "decimals()", uintWord(18)); setCall(TOKEN, "totalSupply()", uintWord(10n ** 27n)); setCall(TOKEN, "paused()", uintWord(1));
  const PROXY = A("c"), LOGIC = A("d"), PADMIN = A("e"), SAFE = A("f");
  chain.code[PROXY] = "0x" + "60806040".repeat(20) + "f4" + "00";
  chain.slots[PROXY + ":" + X.SLOTS.eip1967Impl] = addrWord(LOGIC);
  chain.slots[PROXY + ":" + X.SLOTS.eip1967Admin] = addrWord(PADMIN);
  chain.code[LOGIC] = tokenLogic; chain.code[PADMIN] = mkCode(["owner()"]); chain.code[SAFE] = mkCode(["getThreshold()", "getOwners()"]);
  setCall(PADMIN, "owner()", addrWord(SAFE)); setCall(PROXY, "owner()", addrWord(SAFE));
  setCall(PROXY, "name()", encStr("Safe USD")); setCall(PROXY, "symbol()", encStr("SUSD")); setCall(PROXY, "decimals()", uintWord(6)); setCall(PROXY, "totalSupply()", uintWord(1000)); setCall(PROXY, "paused()", uintWord(0));
  setCall(SAFE, "getThreshold()", uintWord(2)); setCall(SAFE, "getOwners()", encAddrs([A("1"), A("2"), A("3")]));
  const DELEG = A("7"), DELEG_IMPL = A("8");
  chain.code[DELEG] = "0xef0100" + DELEG_IMPL.slice(2); chain.code[DELEG_IMPL] = mkCode(["execute(address,uint256,bytes)"]);
  const REN = A("9"); chain.code[REN] = tokenLogic; setCall(REN, "owner()", addrWord("0x" + "0".repeat(40)));
  const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; chain.code[USDC] = tokenLogic; setCall(USDC, "owner()", addrWord(SAFE));
  const BEACONP = A("5"), BEACON = A("6"), BLOGIC = A("4");
  chain.code[BEACONP] = "0x" + "60806040".repeat(20) + "f4" + "00"; chain.slots[BEACONP + ":" + X.SLOTS.eip1967Beacon] = addrWord(BEACON);
  chain.code[BEACON] = mkCode(["implementation()"]); setCall(BEACON, "implementation()", addrWord(BLOGIC)); chain.code[BLOGIC] = mkCode([...ERC20, "pause()"]);
  const TL = A("3"), TLTOKEN = A("2"); chain.code[TL] = mkCode(["getMinDelay()"]); setCall(TL, "getMinDelay()", uintWord(172800));
  chain.code[TLTOKEN] = tokenLogic; setCall(TLTOKEN, "owner()", addrWord(TL));

  // RPC behaviour per URL: ok | 429 | cors | incomplete | nobatch | hang
  const behaviour = {};
  const seen = [];
  function rpcAnswer(r) {
    const p0 = (r.params || [])[0], p1 = (r.params || [])[1];
    let result;
    switch (r.method) {
      case "eth_blockNumber": result = "0x3938700"; break;
      case "eth_chainId": result = "0x2105"; break;
      case "eth_getCode": result = chain.code[p0.toLowerCase()] || "0x"; break;
      case "eth_getStorageAt": result = chain.slots[p0.toLowerCase() + ":" + p1] || "0x" + "0".repeat(64); break;
      case "eth_call": { const k = p0.to.toLowerCase() + ":" + p0.data; if (!(k in chain.calls)) return { jsonrpc: "2.0", id: r.id, error: { code: 3, message: "execution reverted" } }; result = chain.calls[k]; break; }
      case "eth_getProof": result = { codeHash: "0x" + "cd".repeat(32) }; break;
      default: return { jsonrpc: "2.0", id: r.id, error: { code: -32601, message: "nope" } };
    }
    return { jsonrpc: "2.0", id: r.id, result };
  }
  const resp = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
  const mockFetch = async (url, init) => {
    url = String(url); init = init || {};
    seen.push(url);
    if (url.startsWith("https://sourcify.dev/")) return url.toLowerCase().includes(PROXY.slice(2)) ? resp(200, { match: "exact_match" }) : resp(404, {});
    const b = behaviour[url] || "ok";
    if (b === "cors") throw new TypeError("Failed to fetch");
    if (b === "429") return resp(429, { error: "rate limited" });
    if (b === "hang") return new Promise((_, rej) => { if (init.signal) init.signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))); });
    const body = JSON.parse(init.body);
    if (b === "nobatch" && Array.isArray(body)) return resp(200, { jsonrpc: "2.0", id: null, error: { code: -32600, message: "batch not supported" } });
    if (b === "incomplete" && Array.isArray(body)) return resp(200, body.map((r) => (r.method === "eth_getCode" ? { jsonrpc: "2.0", id: r.id, error: { code: -32005, message: "limit" } } : rpcAnswer(r))));
    return resp(200, Array.isArray(body) ? body.map(rpcAnswer) : rpcAnswer(body));
  };
  globalThis.fetch = mockFetch; // core default + sourcify use global fetch
  const P = (urls, o) => X.httpProvider(urls || ["https://rpc-a.test", "https://rpc-b.test"], Object.assign({ fetch: mockFetch, timeoutMs: 200 }, o || {}));
  const fl = (r, id) => r.flags.find((f) => f.id === id);

  // Scenario: EOA-owned rug token, paused
  let r = await X.scan(P(), "base", TOKEN);
  eq(r.kind, "contract", "rug: contract");
  ok(fl(r, "CURRENTLY_PAUSED") && fl(r, "MINTABLE").severity === "high" && fl(r, "FEE_CONTROL") && fl(r, "BLACKLIST") && fl(r, "SINGLE_KEY_CONTROL"), "rug: flags", r.flags.map((f) => f.id));
  eq(r.verdict.level, "high", "rug: level high"); eq(r.verdict.score, 100, "rug: score capped 100");
  eq(r.control.ownerType, "eoa", "rug: owner eoa"); eq(r.token.symbol, "RUG", "rug: symbol"); eq(r.token.totalSupply, (10n ** 27n).toString(), "rug: supply");
  eq(r.source.sourcify, "not_found", "rug: sourcify not found"); ok(fl(r, "UNVERIFIED_SOURCIFY"), "rug: unverified flag");
  eq(r.meta.rpc, "https://rpc-a.test", "rug: rpc label");

  // Scenario: transparent proxy behind a 2-of-3 Safe
  r = await X.scan(P(), "base", PROXY);
  eq(r.proxy.type, "eip1967-transparent", "proxy: type"); eq(r.control.upgradeAuthorityType, "safe", "proxy: upgrade authority safe");
  eq(fl(r, "UPGRADEABLE").severity, "low", "proxy: upgradeable low under Safe"); eq(fl(r, "MINTABLE").severity, "medium", "proxy: mint downgraded");
  ok(fl(r, "SAFE_OWNED") && fl(r, "VERIFIED_SOURCIFY"), "proxy: safe + verified flags");
  eq(r.control.safe.threshold, 2, "proxy: safe threshold"); eq(r.token.symbol, "SUSD", "proxy: token via proxy");

  // Scenario: beacon proxy
  r = await X.scan(P(), "base", BEACONP);
  eq(r.proxy.type, "eip1967-beacon", "beacon: type"); eq(r.proxy.implementation, X.toChecksum(BLOGIC), "beacon: impl resolved");
  ok(fl(r, "PAUSABLE"), "beacon: pausable from logic");

  // Scenario: timelock owner
  r = await X.scan(P(), "base", TLTOKEN);
  eq(r.control.ownerType, "timelock", "timelock: owner type"); eq(r.control.timelockDelaySec, 172800, "timelock: delay");
  eq(fl(r, "MINTABLE").severity, "medium", "timelock: downgrade");

  // Scenario: 7702, renounced, EOA, known
  r = await X.scan(P(), "base", DELEG); eq(r.kind, "eip7702-delegated-eoa", "7702 kind"); ok(fl(r, "EIP7702_DELEGATED"), "7702 flag");
  r = await X.scan(P(), "base", REN); eq(fl(r, "MINTABLE").severity, "info", "renounced: mint info"); ok(fl(r, "OWNERSHIP_RENOUNCED"), "renounced flag");
  r = await X.scan(P(), "base", A("0")); eq(r.kind, "eoa", "empty account -> eoa"); eq(r.verdict.level, "n/a", "eoa level n/a");
  r = await X.scan(P(), "base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  ok(r.known && /Circle/.test(r.known.label) && fl(r, "KNOWN_CONTRACT"), "known USDC labelled");
  r = await X.scan(P(), "ethereum", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  eq(r.known, null, "known labels are per-chain");

  // Input validation
  await throwsAsync(() => X.scan(P(), "base", "0x123"), /40-hex/, "scan rejects short address");
  await throwsAsync(() => X.scan(P(), "base", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), /checksum/, "scan rejects checksum typo");
  await throwsAsync(() => X.scan(P(), "solana", TOKEN), /unsupported chain/, "scan rejects unknown chain");

  // ---- 6. RPC robustness ----------------------------------------------------------------------
  const logs = [];
  behaviour["https://rpc-a.test"] = "429";
  r = await X.scan(P(null, { log: (e) => logs.push(e) }), "base", TOKEN);
  eq(r.meta.rpc, "https://rpc-b.test", "429 -> falls back to second endpoint");
  ok(logs.some((e) => !e.ok && /429/.test(e.error)) && logs.some((e) => e.ok), "log records failure + success", logs);
  behaviour["https://rpc-a.test"] = "cors";
  r = await X.scan(P(), "base", TOKEN); eq(r.meta.rpc, "https://rpc-b.test", "CORS failure -> fallback");
  behaviour["https://rpc-a.test"] = "incomplete";
  r = await X.scan(P(), "base", TOKEN); eq(r.kind, "contract", "incomplete getCode never reported as EOA (fallback used)"); eq(r.meta.rpc, "https://rpc-b.test", "incomplete -> fallback");
  behaviour["https://rpc-a.test"] = "hang";
  r = await X.scan(P(), "base", TOKEN); eq(r.meta.rpc, "https://rpc-b.test", "timeout -> fallback");
  behaviour["https://rpc-a.test"] = "nobatch";
  r = await X.scan(P(["https://rpc-a.test"]), "base", TOKEN); eq(r.kind, "contract", "batch refused -> single calls work"); ok(fl(r, "MINTABLE"), "single-call mode full report");
  behaviour["https://rpc-a.test"] = "incomplete"; behaviour["https://rpc-b.test"] = "incomplete";
  await throwsAsync(() => X.scan(P(), "base", TOKEN), /all RPC endpoints failed/, "all endpoints incomplete -> error, not a fake EOA verdict");
  behaviour["https://rpc-a.test"] = "cors"; behaviour["https://rpc-b.test"] = "429";
  await throwsAsync(() => X.scan(P(), "base", TOKEN), /all RPC endpoints failed/, "all endpoints down -> error");
  delete behaviour["https://rpc-a.test"]; delete behaviour["https://rpc-b.test"];
  await throwsAsync(() => X.scan(X.httpProvider(["javascript:alert(1)", "http://evil.test"], { fetch: mockFetch }), "base", TOKEN), /no usable RPC URL/, "non-https custom RPC refused");
  // sticky endpoint: after a fallback, later batches in the same scan go straight to the good node
  seen.length = 0; behaviour["https://rpc-a.test"] = "cors";
  const prov = P(); await X.scan(prov, "base", PROXY);
  const rpcHits = seen.filter((u) => u.startsWith("https://rpc-"));
  eq(rpcHits.filter((u) => u === "https://rpc-a.test").length, 1, "sticky: bad endpoint tried only once per scan");
  delete behaviour["https://rpc-a.test"];

  // ---- 7. Wallet (EIP-1193) provider -------------------------------------------------------------
  const fakeEth = (chainHex) => ({ calls: [], async request({ method, params }) { this.calls.push(method); if (method === "eth_chainId") return chainHex; const a = rpcAnswer({ id: 1, method, params }); if (a.error) { const e = new Error(a.error.message); e.code = a.error.code; throw e; } return a.result; } });
  r = await X.scan(X.eip1193Provider(fakeEth("0x2105"), 8453), "base", PROXY, { fetch: mockFetch });
  eq(r.proxy.type, "eip1967-transparent", "wallet provider: full scan works"); eq(r.meta.rpc, "wallet provider", "wallet provider label");
  try { await X.scan(X.eip1193Provider(fakeEth("0x1"), 8453), "base", TOKEN); ok(false, "wrong chain should throw"); }
  catch (e) { eq(e.code, "WRONG_CHAIN", "wallet on wrong chain -> WRONG_CHAIN"); }

  // ---- 8. Offline bytecode mode ----------------------------------------------------------------
  let o = X.analyzeOffline(tokenLogic);
  ok(o.flags.find((f) => f.id === "OFFLINE_ONLY") && o.flags.find((f) => f.id === "MINTABLE") && o.flags.find((f) => f.id === "FEE_CONTROL"), "offline: token flags", o.flags.map((f) => f.id));
  eq(o.kind, "offline-bytecode", "offline kind"); ok(/^0x[0-9a-f]{64}$/.test(o.code.codeHash), "offline code hash");
  o = X.analyzeOffline("  " + tokenLogic.slice(2) + "\n"); ok(o.flags.length > 1, "offline accepts no-0x + whitespace");
  o = X.analyzeOffline("0x363d3d373d3d3d363d73" + "ab".repeat(20) + "5af43d82803e903d91602b57fd5bf3"); ok(o.flags.find((f) => f.id === "MINIMAL_PROXY"), "offline: 1167");
  o = X.analyzeOffline("0x" + pushSlot + "54" + "f4" + "00"); ok(o.flags.find((f) => f.id === "LOOKS_LIKE_PROXY"), "offline: proxy via slot constant");
  throws(() => X.analyzeOffline("hello"), /bytecode/, "offline rejects non-hex"); throws(() => X.analyzeOffline("0x123"), /bytecode/, "offline rejects odd hex");
  throws(() => X.analyzeOffline(""), /bytecode/, "offline rejects empty");

  // ---- 9. Tips ---------------------------------------------------------------------------------
  const args = process.argv.slice(2);
  const ei = args.indexOf("--expect-tip");
  const wallets = JSON.parse(fs.readFileSync(path.join(DIR, "..", "..", "wallets.json"), "utf8"));
  const expectTip = ei >= 0 ? args[ei + 1] : wallets.evm;
  eq(APP.TIP_ADDRESS, expectTip, "TIP_ADDRESS equals the founder's registered EVM address");
  ok(X.tip.validTipAddress(APP.TIP_ADDRESS), "TIP_ADDRESS passes EIP-55 + not-a-token checks");
  ok(!X.tip.validTipAddress(APP.TIP_ADDRESS.toLowerCase()), "lowercase tip address rejected (needs checksum casing)");
  ok(!X.tip.validTipAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), "USDC contract rejected as tip address");
  ok(!X.tip.validTipAddress(""), "empty tip address rejected");
  eq(X.tip.usdcUnits("1"), 1000000n, "1 USDC = 1e6 units"); eq(X.tip.usdcUnits("0.5"), 500000n, "0.5 USDC"); eq(X.tip.usdcUnits("2.000001"), 2000001n, "6 decimals");
  throws(() => X.tip.usdcUnits("1.0000001"), /6 decimals/, "7 decimals rejected"); throws(() => X.tip.usdcUnits("0"), /greater than zero/, "zero rejected"); throws(() => X.tip.usdcUnits("-1"), /positive/, "negative rejected");
  const td = X.tip.transferData(APP.TIP_ADDRESS, 1000000n);
  eq(td, "0xa9059cbb" + "000000000000000000000000" + APP.TIP_ADDRESS.slice(2).toLowerCase() + "00000000000000000000000000000000000000000000000000000000000f4240", "transfer calldata exact");
  eq(X.tip.eip681(APP.TIP_ADDRESS, 1000000n), "ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=" + APP.TIP_ADDRESS + "&uint256=1000000", "EIP-681 link");
  eq(X.tip.TIP.usdc, X.toChecksum(USDC), "tip token is Base USDC");

  // ---- 10. Rendering (virtual DOM, no HTML strings) ----------------------------------------------
  const rug = await X.scan(P(), "base", TOKEN);
  for (const lang of ["en", "zh"]) {
    const v = APP.renderReport(rug, lang, { XRay: X });
    const txt = APP.textOf(v);
    ok(txt.includes(APP.I18N[lang].riskLevel.high), "render " + lang + ": level label");
    ok(txt.includes(APP.FLAG_INFO.MINTABLE[lang][0]), "render " + lang + ": flag title");
    ok(txt.includes("RUG"), "render " + lang + ": token symbol");
  }
  for (const id of new Set([...rug.flags.map((f) => f.id), ...X.analyzeOffline(tokenLogic).flags.map((f) => f.id)])) ok(!!APP.FLAG_INFO[id], "FLAG_INFO has " + id);
  const allIds = ["CURRENTLY_PAUSED", "EIP7702_DELEGATED", "MINIMAL_PROXY", "UPGRADEABLE", "SINGLE_KEY_CONTROL", "OWNERSHIP_RENOUNCED", "SAFE_OWNED", "UNVERIFIED_SOURCIFY", "VERIFIED_SOURCIFY", "SELFDESTRUCT_OPCODE", "DELEGATECALL_OPCODE", "KNOWN_CONTRACT", "OFFLINE_ONLY", "LOOKS_LIKE_PROXY", ...X.RULES.map((x) => x.id)];
  for (const id of allIds) ok(APP.FLAG_INFO[id] && APP.FLAG_INFO[id].en && APP.FLAG_INFO[id].zh, "FLAG_INFO en+zh " + id);
  const coreSrc = fs.readFileSync(path.join(DIR, "xray-core.js"), "utf8");
  for (const m of coreSrc.matchAll(/add\("([A-Z0-9_]+)"/g)) ok(!!APP.FLAG_INFO[m[1]], "every emitted flag has copy: " + m[1]);
  ok(Object.keys(APP.I18N.en).every((k) => k in APP.I18N.zh), "zh has every en key", Object.keys(APP.I18N.en).filter((k) => !(k in APP.I18N.zh)));
  // hostile token name stays plain text
  const evil = JSON.parse(JSON.stringify(rug)); evil.token.symbol = "<script>alert(1)</script>";
  const ev = APP.renderReport(evil, "en", { XRay: X });
  const findText = (v, s) => (typeof v === "string" ? v.includes(s) : v.c.some((c) => findText(c, s)));
  const anyTag = (v, tag) => (typeof v === "string" ? false : v.t === tag || v.c.some((c) => anyTag(c, tag)));
  ok(findText(ev, "<script>") && !anyTag(ev, "script"), "hostile symbol rendered as text only");
  eq(APP.safeHref("javascript:alert(1)"), null, "safeHref blocks javascript:"); eq(APP.safeHref("https://basescan.org/x"), "https://basescan.org/x", "safeHref allows https");
  ok(APP.textOf(APP.renderReport(X.analyzeOffline(tokenLogic), "zh", { XRay: X })).includes("仅字节码检查"), "offline report renders (zh)");
  ok(APP.textOf(APP.renderError("rpc", "en", "x")).includes(APP.I18N.en.hints[0]), "rpc error shows fallbacks");

  // ---- 11. Static checks on the page ------------------------------------------------------------
  const html = fs.readFileSync(path.join(DIR, "index.html"), "utf8");
  const appSrc = fs.readFileSync(path.join(DIR, "app.js"), "utf8");
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  for (const m of appSrc.matchAll(/\$\("([a-z-]+)"\)/g)) ok(ids.has(m[1]), "index.html has #" + m[1]);
  ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(appSrc + coreSrc), "no HTML-string sinks in JS");
  const srcs = [...html.matchAll(/<script[^>]*src="([^"]+)"/g)].map((m) => m[1]);
  ok(srcs.length === 2 && srcs.every((s) => !/^https?:|^\/\//.test(s)), "only local scripts", srcs);
  ok([...html.matchAll(/<link[^>]*>/g)].every((m) => !/href="https?:|href="\/\//.test(m[0]) || /rel="(canonical|alternate)"/.test(m[0])), "no external stylesheets/fonts (only canonical/alternate links)");
  for (const m of html.matchAll(/data-i18n="([a-zA-Z]+)"/g)) ok(typeof APP.I18N.en[m[1]] === "string" && typeof APP.I18N.zh[m[1]] === "string", "i18n key exists: " + m[1]);
  for (const m of html.matchAll(/data-example="([a-z]+):(0x[0-9a-fA-F]{40})"/g)) ok(X.CHAINS[m[1]] && X.checkAddress(m[2]).ok, "example valid " + m[1] + ":" + m[2]);
  ok(!/0x0000000000000000000000000000000000000000/.test(appSrc), "no zero address in page config");
  const readme = fs.readFileSync(path.join(DIR, "README.md"), "utf8");
  ok(readme.includes(APP.TIP_ADDRESS), "README shows the same tip address as the page");
  const addrsInReadme = [...readme.matchAll(/0x[0-9a-fA-F]{40}/g)].map((m) => m[0]);
  ok(addrsInReadme.every((a) => a === APP.TIP_ADDRESS || (X.KNOWN.base[a.toLowerCase()])), "README has no other payment-looking addresses", addrsInReadme);
  const funding = fs.readFileSync(path.join(DIR, ".github", "FUNDING.yml"), "utf8");
  ok(/custom: \["https:\/\/[a-z0-9-]+\.github\.io\/contract-xray\/#tip"\]/.test(funding), "FUNDING.yml points at the page's #tip section");
  ok(ids.has("tip"), "page has #tip anchor");
  const sitemap = fs.readFileSync(path.join(DIR, "sitemap.xml"), "utf8");
  for (const m of sitemap.matchAll(/<loc>https:\/\/[^/]+\/contract-xray\/([^<]*)<\/loc>/g)) ok(m[1] === "" || fs.existsSync(path.join(DIR, m[1])), "sitemap entry exists: /" + m[1]);
  const keyFiles = fs.readdirSync(DIR).filter((f) => /^[0-9a-f]{32}\.txt$/.test(f));
  ok(keyFiles.length === 1 && fs.readFileSync(path.join(DIR, keyFiles[0]), "utf8") === keyFiles[0].slice(0, 32), "IndexNow key file content equals its name");
  for (const g of ["guide/check-token-before-buying.html", "guide/zh-check-token.html"]) {
    const gh = fs.readFileSync(path.join(DIR, g), "utf8");
    ok(!/<script/i.test(gh), "guide has no scripts: " + g);
    ok(/href="\.\.\/"/.test(gh), "guide links back to the tool: " + g);
    ok(html.includes('href="' + g + '"'), "tool links to guide: " + g);
  }

  // ---- 12. Page wiring smoke test with a fake DOM ----------------------------------------------
  class Txt { constructor(s) { this.textContent = s; } }
  class El {
    constructor(tag, id) { this.tagName = tag; this.id = id; this.children = []; this.attrs = {}; this.listeners = {}; this.hidden = false; this._t = ""; this.value = ""; this.disabled = false; this.open = false; this.className = ""; this.type = ""; }
    get firstChild() { return this.children[0] || null; }
    appendChild(c) { this.children.push(c); return c; }
    removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); } getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    fire(t) { for (const f of this.listeners[t] || []) f({ preventDefault() {} }); }
    get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join("") : this._t; }
    set textContent(v) { this.children = []; this._t = String(v); }
  }
  function makeDoc(srcMode) {
    const store = {};
    const byId = new Proxy(store, { get: (t, k) => (typeof k === "string" ? (t[k] = t[k] || new El("div", k)) : undefined) });
    const exampleBtn = new El("button"); exampleBtn.setAttribute("data-example", "base:" + X.toChecksum(PROXY));
    const doc = {
      readyState: "complete", documentElement: new El("html"),
      getElementById: (id) => byId[id],
      createElement: (t) => new El(t), createTextNode: (s) => new Txt(s),
      querySelectorAll: (q) => (q === "[data-example]" ? [exampleBtn] : []),
      querySelector: (q) => (q.startsWith('input[name="src"]') ? { value: srcMode } : null),
    };
    return { doc, byId, exampleBtn };
  }
  const tick = () => new Promise((res) => setImmediate(res));
  async function until(fn, n) { for (let i = 0; i < (n || 200); i++) { if (fn()) return true; await tick(); } return false; }
  const sent = [];
  let walletChain = "0x1";
  const eth = {
    async request({ method, params }) {
      if (method === "eth_requestAccounts") return [A("5")];
      if (method === "eth_chainId") return walletChain;
      if (method === "wallet_switchEthereumChain") { if (params[0].chainId === "0x2105") walletChain = "0x2105"; return null; }
      if (method === "eth_call") return uintWord(5000000); // 5 USDC
      if (method === "eth_sendTransaction") { sent.push(params[0]); return "0x" + "ab".repeat(32); }
      throw new Error("unexpected " + method);
    },
  };
  const win = { localStorage: { getItem() { return null; }, setItem() {} }, navigator: { language: "zh-CN", clipboard: { writeText: async () => {} } },
    history: { replaceState() {} }, location: { hostname: "example.github.io", pathname: "/contract-xray/", search: "", href: "https://example.github.io/contract-xray/" },
    URLSearchParams, confirm: () => true, open() {}, ethereum: eth };
  const { doc, byId, exampleBtn } = makeDoc("auto");
  globalThis.fetch = mockFetch;
  APP.init(X, doc, win);
  eq(byId["tip"].hidden, false, "page: tip section visible with valid address");
  eq(byId["tip-address"].textContent, APP.TIP_ADDRESS, "page: tip address shown");
  eq(byId["tip-buttons"].children.length, 3, "page: 3 tip buttons when a wallet exists");
  ok(/打赏 1 USDC/.test(byId["tip-buttons"].children[0].textContent), "page: zh button label from navigator.language");
  eq(byId["repo-link"].getAttribute("href"), "https://github.com/example/contract-xray", "page: repo link derived from github.io URL");
  ok(byId["chain"].children.length === Object.keys(X.CHAINS).length, "page: chain options");
  exampleBtn.fire("click");
  ok(await until(() => byId["result"].children.length > 0 && !byId["scan-btn"].disabled), "page: example scan finished");
  ok(/代码可以被替换/.test(byId["result"].children[0].textContent || collect(byId["result"])), "page: report rendered into #result");
  eq(byId["report-tools"].hidden, false, "page: report tools shown"); eq(byId["post-scan-tip"].hidden, false, "page: post-scan tip nudge shown");
  function collect(el) { return el.children.map((c) => (c instanceof Txt ? c.textContent : collect(c))).join(" "); }
  // tip flow: wallet on Ethereum -> switches to Base -> sends exact USDC transfer
  byId["tip-buttons"].children[0].fire("click");
  ok(await until(() => sent.length === 1), "page: tip transaction sent");
  eq(sent[0] && sent[0].to, X.tip.TIP.usdc, "page: tip goes to the USDC contract");
  eq(sent[0] && sent[0].data, X.tip.transferData(APP.TIP_ADDRESS, 1000000n), "page: tip calldata = transfer(TIP_ADDRESS, 1 USDC)");
  eq(sent[0] && sent[0].value, "0x0", "page: no ETH value attached");
  // tip refused when the wallet will not switch to Base
  walletChain = "0x1"; const ethNoSwitch = Object.assign({}, eth, { async request(a) { if (a.method === "wallet_switchEthereumChain") return null; return eth.request(a); } });
  win.ethereum = ethNoSwitch; walletChain = "0x1";
  const d2 = makeDoc("auto"); APP.init(X, d2.doc, win);
  d2.byId["tip-buttons"].children[1].fire("click");
  await until(() => collect(d2.doc.getElementById("tip-status")).length > 0);
  eq(sent.length, 1, "page: nothing sent when the wallet stays off Base");
  // confirm() = cancel -> nothing sent
  walletChain = "0x2105"; win.ethereum = eth; win.confirm = () => false;
  const d3 = makeDoc("auto"); APP.init(X, d3.doc, win);
  d3.byId["tip-buttons"].children[0].fire("click");
  await until(() => collect(d3.doc.getElementById("tip-status")).length > 0);
  eq(sent.length, 1, "page: nothing sent when the visitor cancels");
  // no wallet -> no buttons, copy/link fallback only
  delete win.ethereum; const d4 = makeDoc("auto"); APP.init(X, d4.doc, win);
  eq(d4.byId["tip-buttons"].children.length, 1, "page: no wallet -> explanatory text instead of buttons");
  ok(/^ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453\/transfer\?address=/.test(d4.byId["tip-link"].getAttribute("href")), "page: EIP-681 wallet link set");
  // all public nodes down -> helpful error, advanced panel opened
  behaviour["https://mainnet.base.org"] = "cors"; behaviour["https://base-rpc.publicnode.com"] = "429"; behaviour["https://base.drpc.org"] = "incomplete";
  const d5 = makeDoc("auto"); APP.init(X, d5.doc, win);
  d5.byId["address"].value = X.toChecksum(TOKEN); d5.byId["scan-form"].fire("submit");
  ok(await until(() => d5.byId["advanced"].open === true, 4000), "page: RPC failure opens the data-source panel");
  ok(/钱包的节点/.test(collect(d5.byId["result"])), "page: RPC failure suggests wallet node / custom RPC / offline");
  // bad input
  const d6 = makeDoc("auto"); APP.init(X, d6.doc, win);
  d6.byId["address"].value = "0xnothex"; d6.byId["scan-form"].fire("submit");
  ok(/40 位/.test(collect(d6.byId["result"])), "page: invalid address message");

  console.log((fail ? "FAIL" : "PASS") + " " + pass + " passed, FAIL " + fail);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); console.log("FAIL (crashed)"); process.exit(1); });
