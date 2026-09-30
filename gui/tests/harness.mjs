// UI harness: serves gui/ui in headless Chrome with a stand-in for the Tauri bridge that talks
// to a real `nepomuk serve --stdio`. It drives the main flows, fails on CSP violations or page
// errors, and saves screenshots.
//
//   node gui/tests/harness.mjs <nepomuk binary> <output dir>
//
// Needs Google Chrome (CHROME env to override) and a debug build of the CLI (cheap Argon2).

import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const uiDir = resolve(here, "../ui");
const cli = resolve(process.argv[2] || resolve(here, "../../target/debug/nepomuk"));
const outDir = resolve(process.argv[3] || join(tmpdir(), "nepomuk-ui-shots"));
mkdirSync(outDir, { recursive: true });
const chrome = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const MASTER_PASS = "correct-staple-harness-master";
const JANE_PASS = "jane-uses-a-long-harness-password";

// ------------------------------------------------------------------ Demo vault

const work = mkdtempSync(join(tmpdir(), "nepomuk-ui-"));
const env = {
  ...process.env,
  NEPOMUK_CONFIG_DIR: join(work, "cfg"),
  NEPOMUK_STATE_DIR: join(work, "state"),
  NEPOMUK_INSECURE_TEST_KDF: "1",
  NEPOMUK_VAULT: join(work, "vault.nepomuk"),
};
const run = (args, extraEnv = {}, input) =>
  execFileSync(cli, ["--json", ...args], { env: { ...env, ...extraEnv }, input, cwd: work }).toString();
const m = (args, input) => run(["--identity", join(work, "cfg/master.npk"), ...args], { NEPOMUK_PASSPHRASE: MASTER_PASS }, input);

run(["init"], { NEPOMUK_PASSPHRASE: MASTER_PASS });
run(["identity", "request", "--email", "jane@example.com", "--out", join(work, "jane.request")], { NEPOMUK_PASSWORD: JANE_PASS });
m(["user", "add", join(work, "jane.request")]);
m(["mkdir", "-p", "/projects/eshop-android/signing"]);
m(["mkdir", "-p", "/infra/db"]);
m(["put", "/infra/db/prod-password"], "Sup3r-Secret-DB-Pass\n");
writeFileSync(join(work, "release.jks"), Buffer.from("fake keystore bytes"));
m(["put", "/projects/eshop-android/signing/release", "--field", "keystore=@" + join(work, "release.jks"), "--field", "key_alias=eshop-upload", "--field-prompt", "key_password"], "k3y-pass-123\n");
m(["group", "create", "android-release"]);
m(["group", "add", "android-release", "jane@example.com"]);
m(["grant", "group:android-release", "read", "/projects/eshop-android/signing"]);
m(["grant", "user:jane@example.com", "write", "/infra/db"]);
m(["revoke", "user:jane@example.com", "/infra/db"]);
const fp = JSON.parse(m(["info"])).data.master_fingerprint;
// A second vault for switching.
const vault2 = join(work, "second.nepomuk");
run(["--vault", vault2, "init", "--out", join(work, "master2.npk")], { NEPOMUK_PASSPHRASE: MASTER_PASS });

// ------------------------------------------------------------------ Bridge server

let sidecar = null;
let nextId = 1;
const pending = new Map();
const sse = new Set();
let picks = [];

function connect(args) {
  if (sidecar) sidecar.kill();
  const a = ["serve", "--stdio"];
  if (args.vault) a.push("--vault", args.vault);
  // A fresh state dir shows the trust screen first.
  sidecar = spawn(cli, a, { env: { ...env, NEPOMUK_STATE_DIR: join(work, "state-ui") }, cwd: work });
  let buf = "";
  sidecar.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      const msg = JSON.parse(line);
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      } else for (const res of sse) res.write(`data: ${JSON.stringify({ event: "nepomuk:notification", payload: msg })}\n\n`);
    }
  });
}

function call(method, params) {
  return new Promise((ok, fail) => {
    const id = nextId++;
    pending.set(id, (msg) => {
      if (!msg.error) return ok(msg.result);
      const d = msg.error.data || {};
      fail({ code: d.code || "RPC_ERROR", message: msg.error.message, details: d.details || {} });
    });
    sidecar.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

const commands = {
  async connect(a) {
    connect(a);
    const version = await call("version", {});
    return { version, vault: a.vault, project: a.project };
  },
  async disconnect() { if (sidecar) sidecar.kill(); sidecar = null; },
  rpc: (a) => call(a.method, a.params || {}),
  pick: () => picks.shift() ?? null,
  pick_save: (a) => join(work, a.defaultName),
  pick_file_b64: () => ({ name: "upload.bin", size: 4, base64: "AAECAw==" }),
  copy_secret: async (a) => { await call("node.get", { path: a.spec }); return null; },
  copy_plain: () => null,
  save_secret: (a) => join(work, a.defaultName),
};

const TAURI_SHIM = `
window.__TAURI__ = {
  core: { invoke: async (cmd, args) => {
    const r = await fetch("/__invoke", { method: "POST", body: JSON.stringify({ cmd, args }) });
    const j = await r.json();
    if (!j.ok) throw j.error;
    return j.result;
  } },
  event: { listen: async (name, cb) => {
    const es = new EventSource("/__events");
    es.onmessage = (e) => { const m = JSON.parse(e.data); if (m.event === name) cb({ payload: m.payload }); };
    return () => es.close();
  } },
};`;

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'";
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2" };

const server = createServer(async (req, res) => {
  if (req.url === "/__invoke") {
    let body = "";
    for await (const c of req) body += c;
    const { cmd, args } = JSON.parse(body);
    try {
      const result = await commands[cmd](args || {});
      res.end(JSON.stringify({ ok: true, result: result ?? null }));
    } catch (e) {
      res.end(JSON.stringify({ ok: false, error: e }));
    }
    return;
  }
  if (req.url === "/__events") {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    sse.add(res);
    req.on("close", () => sse.delete(res));
    return;
  }
  if (req.url === "/__tauri.js") {
    res.writeHead(200, { "Content-Type": "text/javascript" });
    return res.end(TAURI_SHIM);
  }
  const path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const file = join(uiDir, path);
  if (!file.startsWith(uiDir) || !existsSync(file)) {
    res.writeHead(404);
    return res.end();
  }
  let data = readFileSync(file);
  if (path === "/index.html") data = data.toString().replace('<script type="module"', '<script src="/__tauri.js"></script>\n  <script type="module"');
  res.writeHead(200, { "Content-Type": TYPES[extname(file)] || "application/octet-stream", "Content-Security-Policy": CSP });
  res.end(data);
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const url = `http://127.0.0.1:${server.address().port}/`;

// ------------------------------------------------------------------ Chrome via DevTools protocol

const port = 9300 + Math.floor(Math.random() * 500);
const browser = spawn(chrome, ["--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${join(work, "chrome")}`,
  "--no-first-run", "--window-size=1280,820", "--force-device-scale-factor=1", ...(process.env.CI ? ["--no-sandbox"] : []), "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
let chromeLog = "";
browser.stderr.on("data", (d) => { chromeLog = (chromeLog + d).slice(-4000); });
let wsUrl;
let browserExited = false;
browser.on("exit", () => { browserExited = true; });
for (let i = 0; i < 300 && !wsUrl && !browserExited; i++) {
  await new Promise((r) => setTimeout(r, 200));
  try {
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    wsUrl = targets.find((t) => t.type === "page")?.webSocketDebuggerUrl;
    if (!wsUrl && i > 10) {
      // Some headless builds start without a page.
      const created = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
      wsUrl = created.webSocketDebuggerUrl;
    }
  } catch { /* not up yet */ }
}
if (!wsUrl) {
  console.log(`Chrome did not start (${chrome})${browserExited ? " – it exited" : ""}\n${chromeLog}`);
  process.exit(1);
}
const ws = new WebSocket(wsUrl);
await new Promise((ok) => ws.addEventListener("open", ok));
let seq = 0;
const waiting = new Map();
const problems = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && waiting.has(msg.id)) {
    waiting.get(msg.id)(msg);
    waiting.delete(msg.id);
  }
  if (msg.method === "Runtime.exceptionThrown") problems.push(`exception: ${msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text}`);
  if (msg.method === "Log.entryAdded" && ["error", "warning"].includes(msg.params.entry.level)) problems.push(`${msg.params.entry.level}: ${msg.params.entry.text}`);
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") problems.push(`console: ${msg.params.args.map((a) => a.value || a.description).join(" ")}`);
});
const cdp = (method, params = {}) => new Promise((ok) => {
  const id = ++seq;
  waiting.set(id, ok);
  ws.send(JSON.stringify({ id, method, params }));
});
await cdp("Runtime.enable");
await cdp("Log.enable");
await cdp("Page.enable");
await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: process.env.THEME === "light" ? "light" : "dark" }] });
await cdp("Emulation.setDeviceMetricsOverride", { width: 1280, height: 820, deviceScaleFactor: 1, mobile: false });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const js = async (expr) => {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(`${expr}: ${r.result.exceptionDetails.exception?.description}`);
  return r.result?.result?.value;
};
async function waitFor(expr, what, ms = 8000) {
  for (let t = 0; t < ms; t += 100) {
    // The page may still be loading: an error counts as "not yet".
    if (await js(expr).catch(() => false)) return;
    await sleep(100);
  }
  const text = await js("document.body.innerText.slice(0, 600)");
  throw new Error(`timeout waiting for ${what}\n--- page ---\n${text}`);
}
const hasText = (t) => `!!document.body?.innerText.includes(${JSON.stringify(t)})`;
async function click(text, scope = "button") {
  const ok = await js(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(scope)})].find(b => b.innerText.split("\\n").some((l) => l.trim().startsWith(${JSON.stringify(text)})) && !b.disabled); if (!el) return false; el.click(); return true; })()`);
  if (!ok) throw new Error(`no enabled ${scope} "${text}"`);
  await sleep(150);
}
async function type(selector, value, index = 0) {
  await js(`(() => { const el = document.querySelectorAll(${JSON.stringify(selector)})[${index}]; el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); })()`);
}
async function shot(name) {
  await sleep(250);
  const r = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(outDir, `${name}.png`), Buffer.from(r.result.data, "base64"));
  console.log(`  screenshot ${name}.png`);
}

const steps = [];
const step = (name, fn) => steps.push([name, fn]);

step("start screen", async () => {
  await cdp("Page.navigate", { url });
  await waitFor(hasText("Open a vault"), "start screen");
  await shot("01-start");
});
step("trust the master", async () => {
  picks.push(env.NEPOMUK_VAULT);
  await click("Vault file");
  await waitFor(hasText("Verify the master"), "trust screen");
  await type("input.mono", "npk1wrongwrongwrong");
  await waitFor(hasText("Does not match"), "mismatch warning");
  await type("input.mono", fp);
  await waitFor(hasText("Matches the vault"), "match");
  await shot("02-trust");
  await click("Trust this master");
  await waitFor(hasText("Unlock"), "login");
});
step("login with the master identity", async () => {
  await click("Identity file");
  // The only identity in the default folder is preselected.
  await waitFor(hasText("master – "), "default identity preselected");
  picks.push(join(work, "jane.request"));
  await click("Choose");
  await waitFor(hasText("Use default: master"), "use-default button");
  await click("Use default: master");
  await waitFor(hasText("master – ") + " && !" + hasText("Use default"), "back to the default");
  await type("input[type=password]", MASTER_PASS);
  await shot("03-login");
  await click("Unlock");
  await waitFor("!!document.querySelector('.tree')", "secrets");
  await waitFor(hasText("projects"), "tree");
});
step("browse and reveal a record field", async () => {
  await click("release", ".tree button");
  await waitFor(hasText("key_password"), "record fields");
  await waitFor(hasText("Who has access") + " && !document.querySelector('.detail .spinner')", "access panel");
  await js(`[...document.querySelectorAll(".value")].find(v => v.innerText.includes("key_password")).querySelector("button").click()`);
  await waitFor(hasText("k3y-pass-123"), "revealed value");
  await shot("04-secret-record");
});
step("rotation badge after a revoke", async () => {
  await click("prod-password", ".tree button");
  await waitFor(hasText("Change it at its source"), "rotation notice");
  await shot("05-rotation-notice");
});
step("create a secret", async () => {
  await click("db", ".tree button");
  await click("New secret");
  await type("dialog input", "api-token", 0);
  await type("dialog input[type=password]", "tok-9876543210");
  await click("Store secret", "dialog button");
  await waitFor(hasText("Secret stored"), "stored");
  await waitFor(hasText("api-token"), "tree updated");
  await shot("06-created");
});
step("users", async () => {
  await click("Users", "nav button");
  await waitFor(hasText("jane@example.com"), "users");
  await shot("07-users");
  await js(`[...document.querySelectorAll("tr")].find(r => r.innerText.includes("jane@example.com")).querySelector("button").click()`);
  await waitFor(hasText("What jane@example.com can access"), "user access dialog");
  await shot("08-user-access");
  await click("Close", "dialog button");
});
step("groups", async () => {
  await click("Groups", "nav button");
  await waitFor(hasText("android-release"), "groups");
  await shot("09-groups");
});
step("rotation list", async () => {
  await click("Rotation", "nav button");
  await waitFor(hasText("/infra/db/prod-password"), "rotation list");
  await click("Mark rotated");
  await waitFor(hasText("Nothing to rotate"), "rotated");
});
step("activity", async () => {
  await click("Activity", "nav button");
  await waitFor(hasText("CreateNode"), "log");
  await shot("10-activity");
});
step("vault", async () => {
  await click("Vault", "nav button");
  await waitFor(hasText("Settings on this computer"), "vault view");
  await click("Verify the whole log");
  await waitFor(hasText("Verified"), "verified");
  await shot("11-vault");
});
step("lock and unlock as Jane", async () => {
  await click("Lock");
  await waitFor(hasText("Unlock") + " && " + hasText("Email and password"), "login");
  await click("Email and password");
  await type("input[type=email]", "jane@example.com");
  await type("input[type=password]", JANE_PASS);
  await click("Unlock");
  await waitFor("!!document.querySelector('.sidebar')", "shell");
  await click("Secrets", "nav button");
  await waitFor("!!document.querySelector('.tree')", "secrets");
  await waitFor(hasText("release"), "jane's tree");
  const text = await js("document.querySelector('.tree').innerText");
  if (text.includes("infra")) throw new Error("jane sees /infra");
  await shot("12-jane");
});
step("enrollment", async () => {
  await click("Lock");
  await waitFor(hasText("Request access"), "login");
  await click("Request access");
  await type("input[type=email]", "new@example.com");
  await type("input[type=password]", "short");
  await waitFor(hasText("at least 15"), "weak password feedback");
  await click("Generate passphrase");
  await waitFor(hasText("Strong enough") + " || " + hasText("Accepted"), "strong");
  await click("Save access request");
  await waitFor(hasText("Send this file to an administrator"), "request saved");
  await shot("13-enroll");
});

step("switch to another vault", async () => {
  await click("Back");
  await waitFor(hasText("Change vault"), "login with the change button");
  await click("Change vault");
  await waitFor("!!document.querySelector('dialog[open]')", "switch dialog");
  await shot("14-switch-vault");
  picks.push(vault2);
  await click("Vault file", "dialog button");
  // The second vault has a different master, not pinned yet.
  await waitFor(hasText("Verify the master"), "trust screen of the second vault");
});

let failed = false;
for (const [name, fn] of steps) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failed = true;
    console.log(`FAIL ${name}\n${e.message}`);
    await shot(`fail-${name.replace(/\W+/g, "-")}`).catch(() => {});
    break;
  }
}
const relevant = problems.filter((p) => !p.includes("favicon"));
if (relevant.length) {
  failed = true;
  console.log("page problems:\n" + relevant.join("\n"));
}
ws.close();
browser.kill();
if (sidecar) sidecar.kill();
server.close();
console.log(failed ? "UI harness FAILED" : `UI harness passed; screenshots in ${outDir}`);
process.exit(failed ? 1 : 0);
