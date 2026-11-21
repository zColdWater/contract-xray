// Read-only CORS probe for the public RPC endpoints the page uses.
// For each endpoint it sends what a browser on the published origin would send:
//   1) an OPTIONS preflight (Origin + Access-Control-Request-Method/Headers)
//   2) a POST with Origin and a single eth_chainId call (and a 2-call batch)
// and prints whether the response would be readable by the page.
// No dependencies, Node 18+. About 4 requests per endpoint; nothing is written anywhere.
//
// Usage: node test/cors-probe.js [--origin https://zcoldwater.github.io] [--chain base]
"use strict";
const https = require("https");
const path = require("path");
const X = require(path.join(__dirname, "..", "xray-core.js"));

const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const ORIGIN = arg("--origin", "https://zcoldwater.github.io");
const ONLY = arg("--chain", null);

function req(url, method, headers, body) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const r = https.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method, headers, timeout: 10000 }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => { if (data.length < 4096) data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on("timeout", () => { r.destroy(new Error("timeout")); });
    r.on("error", (e) => resolve({ status: 0, headers: {}, body: "", error: e.message }));
    if (body) r.write(body);
    r.end();
  });
}

const allows = (h) => { const a = h["access-control-allow-origin"]; return a === "*" || a === ORIGIN; };

(async () => {
  const rows = [];
  for (const [key, c] of Object.entries(X.CHAINS)) {
    if (ONLY && key !== ONLY) continue;
    for (const url of c.rpc) {
      const pre = await req(url, "OPTIONS", { Origin: ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type" });
      const preOk = pre.status >= 200 && pre.status < 300 && allows(pre.headers) &&
        /content-type|\*/i.test(String(pre.headers["access-control-allow-headers"] || ""));
      const one = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });
      const post = await req(url, "POST", { Origin: ORIGIN, "content-type": "application/json", "content-length": Buffer.byteLength(one) }, one);
      let chainOk = false;
      try { chainOk = parseInt(JSON.parse(post.body).result, 16) === c.id; } catch (e) {}
      const two = JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }, { jsonrpc: "2.0", id: 2, method: "eth_blockNumber", params: [] }]);
      const batch = await req(url, "POST", { Origin: ORIGIN, "content-type": "application/json", "content-length": Buffer.byteLength(two) }, two);
      let batchOk = false;
      try { batchOk = Array.isArray(JSON.parse(batch.body)); } catch (e) {}
      const browserOk = preOk && allows(post.headers) && chainOk;
      rows.push({ chain: key, url, preflight: pre.error || pre.status + (preOk ? " ok" : " NO"), acao: post.headers["access-control-allow-origin"] || "-",
        chainId: chainOk ? "ok" : "NO (" + (post.error || post.status) + ")", batch: batchOk ? "ok" : "no", browserReadable: browserOk ? "YES" : "NO" });
    }
  }
  console.table(rows);
  const byChain = {};
  for (const r of rows) byChain[r.chain] = (byChain[r.chain] || 0) + (r.browserReadable === "YES" ? 1 : 0);
  console.log("browser-readable endpoints per chain:", JSON.stringify(byChain));
  console.log(byChain.base > 0 || ONLY && ONLY !== "base" ? "RESULT: OK" : "RESULT: no browser-readable Base endpoint (page still works via wallet node / custom RPC / offline mode)");
})();
