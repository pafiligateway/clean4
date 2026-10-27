// Pafili clean-IP pool builder — installed by the panel.
// Reads .pafili/plan.json, fetches the selected country feeds, performs a real
// TLS handshake to every selected IP with the node SNI, and writes the tested
// pool for the pafili-data branch. No dependencies, no secrets, no callback.
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";

const PLAN_PATH = process.env.PAFILI_PLAN || ".pafili/plan.json";
const OUT_PATH = process.env.PAFILI_OUT || ".pafili/clean-pool.json";
const TIMEOUT_MS = Number(process.env.PAFILI_PROBE_TIMEOUT_MS || 6000);
const CONCURRENCY = Math.max(1, Math.min(64, Number(process.env.PAFILI_CONCURRENCY || 24)));
const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

function sanitizeIpv4(v) {
  const s = String(v == null ? "" : v).trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return "";
  for (let i = 1; i <= 4; i++) {
    const n = Number(m[i]);
    if (!Number.isInteger(n) || n > 255) return "";
    if (m[i].length > 1 && m[i][0] === "0") return "";
  }
  return s;
}

// Source A: one ip:port per line, optional # comment after it.
function parseLines(text, ports) {
  const allowed = Array.isArray(ports) && ports.length ? ports : TLS_PORTS;
  const out = [];
  const seen = new Set();
  for (const raw of String(text == null ? "" : text).split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line) continue;
    const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d{1,5})$/.exec(line);
    if (!m) continue;
    const ip = sanitizeIpv4(m[1]);
    const port = Number(m[2]);
    if (!ip || allowed.indexOf(port) < 0) continue;
    const k = ip + ":" + port;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push([ip, port]);
  }
  return out;
}

// Source B: one "## <flag> Country" heading per country and the IP inside a
// <code> tag on each table row. The optional risk badge is the same opt-in
// gate the panel uses (100 disables it).
function codeFromHeading(line) {
  const m = /([\u{1F1E6}-\u{1F1FF}]{2})/u.exec(String(line == null ? "" : line));
  if (!m) return null;
  let code = "";
  for (const ch of m[1]) {
    const n = ch.codePointAt(0) - 0x1F1E6;
    if (n < 0 || n > 25) return null;
    code += String.fromCharCode(65 + n);
  }
  return code;
}
function parseMarkdown(text, maxRisk) {
  const out = {};
  let current = null;
  const cap = Number.isFinite(Number(maxRisk)) ? Math.max(0, Math.min(100, Math.floor(Number(maxRisk)))) : 100;
  for (const line of String(text == null ? "" : text).split("\n")) {
    if (line.indexOf("## ") === 0) { current = codeFromHeading(line); continue; }
    if (!current) continue;
    const m = /<code>\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*<\/code>/i.exec(line);
    if (!m) continue;
    const ip = sanitizeIpv4(m[1]);
    if (!ip) continue;
    if (cap < 100) {
      const r = /badge\/-(\d{1,3})-/.exec(line);
      if (r && Number(r[1]) > cap) continue;
    }
    const arr = out[current] || (out[current] = []);
    if (!arr.some(t => t[0] === ip)) arr.push([ip, 443]);
  }
  return out;
}

async function getText(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "pafili-pool-builder" },
    signal: AbortSignal.timeout(45000),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return await res.text();
}

// A clean IP is judged by the handshake a client actually performs: TLS to
// ip:port with the node hostname as SNI. With an empty SNI the handshake alone
// is the verdict; with one, the certificate must also cover that name, because
// the generated configs verify it unless the admin turned insecure on.
function probe(ip, port, sni) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let sock = null;
    const finish = (r) => {
      if (done) return;
      done = true;
      try { if (sock) sock.destroy(); } catch (_) {}
      resolve(r);
    };
    try {
      sock = tls.connect({
        host: ip, port, servername: sni || undefined,
        rejectUnauthorized: false, timeout: TIMEOUT_MS,
      }, () => {
        const cert = sock.getPeerCertificate() || {};
        let certOk = false;
        try { certOk = !!(sni && tls.checkServerIdentity(sni, cert) === undefined); } catch (_) { certOk = false; }
        const ok = sni ? certOk : true;
        finish({ ip, port, ok, ms: Date.now() - t0, certOk, reason: ok ? "" : "sni-mismatch" });
      });
    } catch (e) {
      return finish({ ip, port, ok: false, ms: 0, certOk: false, reason: String((e && e.message) || e) });
    }
    sock.on("timeout", () => finish({ ip, port, ok: false, ms: 0, certOk: false, reason: "timeout" }));
    sock.on("error", (e) => finish({ ip, port, ok: false, ms: 0, certOk: false, reason: String((e && e.message) || e) }));
  });
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length || 1) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(runners);
  return out;
}

// Random sample per country: a 900-IP country would otherwise only ever be
// tested on the first N feed entries, every run, forever.
function sample(list, max) {
  if (list.length <= max) return list.slice();
  const copy = list.slice();
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const t = copy[i]; copy[i] = copy[j]; copy[j] = t;
  }
  return copy.slice(0, max);
}

async function main() {
  const plan = JSON.parse(fs.readFileSync(PLAN_PATH, "utf8"));
  const sni = String(plan.sni || "");
  const out = { v: 1, at: Date.now(), planAt: Number(plan.at) || 0, sni, sources: {} };
  console.log("sni:", sni || "(none)");
  for (const src of Array.isArray(plan.sources) ? plan.sources : []) {
    const id = String((src && src.id) || "");
    if (!id) continue;
    const regions = Array.isArray(src.regions) ? src.regions : [];
    const max = Math.max(1, Math.min(40, Math.floor(Number(src.max) || 20)));
    const byRegion = {};
    if (src.kind === "bestcf") {
      for (const code of regions) {
        const url = String(src.urlTemplate || "").replace("{region}", code);
        try { byRegion[code] = parseLines(await getText(url), src.ports); }
        catch (e) {
          console.error("feed " + code + " failed: " + String((e && e.message) || e));
          byRegion[code] = [];
        }
      }
    } else if (src.kind === "proxyip") {
      let all = {};
      try { all = parseMarkdown(await getText(String(src.url || "")), src.maxRisk); }
      catch (e) { console.error("feed failed: " + String((e && e.message) || e)); }
      for (const code of regions) byRegion[code] = all[code] || [];
    }
    const result = { id, kind: String(src.kind || ""), max, regions: {} };
    for (const code of regions) {
      const picked = sample(byRegion[code] || [], max);
      if (!picked.length) {
        result.regions[code] = { tested: 0, ok: 0, tuples: [], verdicts: [], reason: "no IPs in the feed" };
        console.log(code + ": no IPs");
        continue;
      }
      const probed = await mapLimit(picked, CONCURRENCY, (t) => probe(t[0], t[1], sni));
      const verdicts = probed.map(r => ({
        ip: r.ip, port: r.port, ok: !!r.ok, ms: r.ms || 0,
        certOk: !!r.certOk, reason: r.reason || "",
      }));
      const ok = verdicts.filter(v => v.ok).length;
      result.regions[code] = { tested: picked.length, ok, tuples: picked, verdicts, at: Date.now() };
      console.log(code + ": " + ok + "/" + picked.length + " ok");
    }
    out.sources[id] = result;
  }
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(out));
  const summary = Object.keys(out.sources).map(k =>
    k + "=" + Object.keys(out.sources[k].regions).length + " countries");
  console.log("wrote " + OUT_PATH + " (" + summary.join(", ") + ")");
}

main().catch((e) => { console.error(e); process.exit(1); });
