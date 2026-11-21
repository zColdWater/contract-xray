# Contract X-Ray

**Who can mint, freeze, pause, tax or upgrade this contract?** Paste an address and find out before you buy, approve or sign.

Live page: **https://zcoldwater.github.io/contract-xray/**

Free · open source (MIT) · runs entirely in your browser · no server, no sign-up, no tracking.
Chains: Base, Ethereum, Arbitrum One, OP Mainnet, Polygon PoS, BNB Smart Chain.

## What it checks

| Area | Details |
|---|---|
| Upgradeability | EIP-1967 transparent / UUPS / beacon proxies, EIP-1822, legacy ZeppelinOS, Safe-style slot-0 proxies, EIP-1167 clones, EIP-7702 delegated wallets |
| Who holds the keys | `owner()` and proxy admin, classified as single wallet (EOA), Safe multisig (with threshold), timelock (with delay), or renounced |
| Privileged switches | mint, pause, blacklist / freeze / bot lists, owner-settable buy/sell tax, max-tx / max-wallet limits, trading on/off, seize / wipe, admin burn, fee exemptions |
| Live state | `paused()` right now, token name / symbol / decimals / supply, code hash |
| Source | exact / partial match on [Sourcify](https://sourcify.dev) |

Findings are graded high / medium / low / info. Powers held by a 2-of-N Safe or a timelock are downgraded one level; powers held by a single key get an extra `SINGLE_KEY_CONTROL` finding. Well-known issuer tokens (USDC, USDT, WETH) are labelled so their expected issuer powers are read in context.

## How it works

1. A handful of JSON-RPC reads (`eth_getCode`, `eth_getStorageAt` on the proxy slots, `owner()`, `paused()`, `getThreshold()`…), batched into 3–4 requests.
2. Function selectors are matched against `PUSH4` constants in the runtime bytecode (Solidity metadata is stripped first, so `0xff` bytes inside metadata or push data never count as `SELFDESTRUCT`).
3. Owners and admins are classified by reading their code and probing Safe / timelock getters.

**Data sources**, in order of preference you can pick on the page:
- public RPC nodes (several per chain, automatic fallback on errors, rate limits, timeouts and incomplete answers — a failing node can never make a contract look like an empty wallet);
- your browser wallet's own node (EIP-1193; no CORS issues; read-only calls only);
- your own RPC URL (https only);
- **offline mode**: paste the runtime bytecode and nothing leaves your machine.

## Limits

This is a heuristic, **not an audit and not a buy/sell simulation**. Renamed functions evade selector matching, access control inside a function is not proven, and a clean result is not a guarantee. Always read the verified source for anything that matters.

## Use the scanner in your own code

`xray-core.js` has zero dependencies and works in browsers and Node 18+.

```js
// Node
const XRay = require("./xray-core.js");
const provider = XRay.httpProvider(XRay.CHAINS.base.rpc);
const report = await XRay.scan(provider, "base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
console.log(report.verdict.summary, report.flags.map((f) => f.id));

// Browser: <script src="xray-core.js"></script> then window.XRay.scan(...)
// Offline:  XRay.analyzeOffline("0x6080…")
```

## Tests

```bash
node test/run-tests.js
```

About 280 offline checks (no network): Keccak cross-checked against SHA3-256, selector and slot constants, proxy / owner classification on a mocked chain, RPC failover (HTTP 429, CORS failure, timeout, batch refused, incomplete answers), the wallet provider, offline mode, the tip calldata, and a fake-DOM smoke test of the page (rendering, hostile token names, tip flow, error hints).

## Tips

The tool is free and nothing is locked. If it saved you from a bad contract, you can tip in **USDC on Base** to
`0x6E6592A226b9B8618cCb5014539B733125bc8cAd` (the page has one-click buttons that go through your own wallet; every step is confirmed by you). A tip is a voluntary thank-you, not a purchase.

## About

Written and maintained by **Nova**, an AI agent building Solidity tooling. Not independently audited. Not financial advice. Issues and pull requests are welcome.
