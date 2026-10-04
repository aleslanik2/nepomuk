// nepomuk GUI: opening a vault, pinning its master, logging in and the main shell (§13).

import { invoke, rpc, listen, h, mount, toast, showError, busy, dialog, closeAllDialogs, session, fingerprint, halo, fpText, basename, settings, errorText } from "./lib.js";
import { views } from "./views.js";

const app = document.getElementById("app");

export const state = {
  conn: null, // { vault, project }
  info: null,
  me: null,
  view: "secrets",
  status: null,
  lastActivity: Date.now(),
  unlocked: false,
};

// ------------------------------------------------------------------ Start

function recent() {
  return settings.get("recent", []);
}

function remember(entry) {
  const list = recent().filter((r) => !(r.vault === entry.vault && r.project === entry.project));
  list.unshift(entry);
  settings.set("recent", list.slice(0, 6));
}

function gate(sideText, ...main) {
  return h("div", { class: "gate" },
    h("aside", { class: "gate-side" },
      h("div", { class: "stack" }, h("div", { class: "wordmark" }, h("img", { src: "icon.svg", alt: "" }), "nepomuk"), sideText),
      h("p", { class: "muted" }, "Keys never leave this computer. Every change is signed and checked by every client.")),
    h("main", { class: "gate-main" }, ...main));
}

export function renderStart(message) {
  state.unlocked = false;
  const open = async (btn, kind) => {
    const path = await busy(btn, () => invoke("pick", { kind }));
    if (path) connect(kind === "vault" ? { vault: path } : { project: path });
  };
  const list = recent();
  mount(app, gate(
    h("p", "A secrets vault that lives in a single file in git. Open the vault file, or a project folder whose .nepomuk.toml points to it."),
    h("h1", "Open a vault"),
    message ? h("div", { class: "notice seal" }, message) : null,
    h("div", { class: "choice" },
      h("button", { onClick: (e) => open(e.currentTarget, "vault") }, "Vault file", h("span", "A .nepomuk file inside the vault repository")),
      h("button", { onClick: (e) => open(e.currentTarget, "project") }, "Project folder", h("span", "Uses the vault, prefix and exec profiles from .nepomuk.toml"))),
    list.length ? h("section", { class: "stack" }, h("h3", "Recently opened"),
      h("div", { class: "recent" }, list.map((r) => h("button", { class: "quiet", onClick: () => connect(r) }, r.vault || r.project)))) : null,
    h("p", { class: "muted" },
      "New here? ",
      h("button", { class: "quiet small", onClick: () => renderEnroll() }, "Request access to a vault"))));
}

async function connect(target) {
  try {
    const res = await invoke("connect", { vault: target.vault ?? null, project: target.project ?? null });
    state.conn = target;
    remember(target);
    await afterConnect(res);
  } catch (e) {
    renderStart(errorText(e));
  }
}

const currentPath = () => state.conn?.vault || state.conn?.project || "";

/** Lets the user open a different vault file or project folder; locks the current session first. */
export async function switchVault() {
  const target = await dialog("Open a different vault", (close) => {
    const pickBtn = (kind, label, hint) => {
      const b = h("button", { onClick: async () => {
        const path = await busy(b, () => invoke("pick", { kind }));
        if (path) close(kind === "vault" ? { vault: path } : { project: path });
      } }, label, h("span", hint));
      return b;
    };
    const others = recent().filter((r) => (r.vault || r.project) !== currentPath());
    return h("div", { class: "stack" },
      currentPath() ? h("p", { class: "muted" }, "Open now: ", h("span", { class: "mono" }, currentPath())) : null,
      h("div", { class: "choice" },
        pickBtn("vault", "Vault file", "A .nepomuk file"),
        pickBtn("project", "Project folder", "A folder with .nepomuk.toml")),
      others.length ? h("div", { class: "stack" }, h("h3", "Recently opened"),
        h("div", { class: "recent" }, others.map((r) => h("button", { class: "quiet", onClick: () => close(r) }, r.vault || r.project)))) : null,
      h("div", { class: "actions end" }, h("button", { class: "quiet", onClick: () => close() }, "Cancel")));
  });
  if (!target) return;
  session.epoch += 1;
  closeAllDialogs();
  if (state.unlocked) await invoke("lock_session").catch(() => {});
  state.unlocked = false;
  state.me = null;
  state.selected = null;
  state.collapsed = null;
  state.view = "secrets";
  refs = {};
  await connect(target);
}

async function afterConnect() {
  try {
    state.info = await rpc("vault.info");
    // Trust-related notices (e.g. .nepomuk.toml naming another master) must reach the user.
    if (state.info?.warnings) state.info.warnings.forEach((w) => toast(w));
    renderLogin();
  } catch (e) {
    if (e.code === "UNTRUSTED_ROOT") renderTrust(e);
    else renderStart(errorText(e));
  }
}

// ------------------------------------------------------------------ Root of trust (§7.1)

function renderTrust(err) {
  const d = err.details || {};
  const claimed = d.claimed_fingerprint || d.new_fingerprint || d.found || "";
  const transferred = !!d.new_fingerprint;
  // A pin exists for this vault, or another pinned vault was opened from this file before:
  // this is not a first start, and the usual reason is a swapped vault file.
  const replacing = !transferred && (!!d.needs_replace || !!d.pinned);
  const input = h("input", { class: "mono", placeholder: "npk1…", autocomplete: "off", spellcheck: "false" });
  const verdict = h("div", { class: "match" });
  const confirm = h("input", { type: "checkbox" });
  const trustBtn = h("button", { class: replacing ? "danger" : "primary", type: "submit", disabled: true },
    replacing ? "Replace the pinned master" : "Trust this master");
  const check = () => {
    const v = input.value.trim();
    const ok = v && v === claimed;
    trustBtn.disabled = !ok || (replacing && !confirm.checked);
    verdict.className = `match ${v ? (ok ? "yes" : "no") : ""}`;
    verdict.textContent = v ? (ok ? "Matches the vault's master." : "Does not match the vault's master. Do not trust this vault.") : "";
  };
  input.addEventListener("input", check);
  confirm.addEventListener("change", check);
  const submit = async (ev) => {
    ev.preventDefault();
    const ok = await busy(trustBtn, () => rpc("vault.trust", { fingerprint: input.value.trim(), replace: replacing }));
    if (ok) {
      toast(replacing ? "The pinned master was replaced." : "Master fingerprint pinned.");
      afterConnect();
    }
  };
  const back = h("button", { class: replacing ? "primary" : "quiet", type: "button", onClick: () => renderStart() },
    replacing ? "Close this vault" : "Back");

  if (replacing) {
    mount(app, gate(
      h("div", { class: "stack" },
        h("p", "Pinned on this computer:"),
        d.pinned ? fingerprint(d.pinned, 72) : h("p", "—"),
        h("p", "The file now claims:"),
        claimed ? fingerprint(claimed, 72) : h("p", "No master fingerprint found.")),
      h("h1", "This is not the vault you trusted"),
      h("div", { class: "notice warn" }, d.replaces_vault_id
        ? "A different vault, with a different master, has replaced the one you opened from this place before."
        : "This vault is not signed by the master pinned on this computer, and no signed hand-over from it exists."),
      h("p", "Someone who can push to the repository may have swapped the file to make you store secrets under their key. Close the vault and ask your administrator. Replace the pin only if they announced a new vault or master and you confirmed its fingerprint over a separate channel."),
      h("form", { onSubmit: submit },
        h("label", "New fingerprint from your administrator", input),
        verdict,
        h("label", { class: "check" }, confirm, " I confirmed this fingerprint with my administrator over a separate channel"),
        h("div", { class: "actions" }, back, trustBtn))));
    back.focus();
    return;
  }

  mount(app, gate(
    h("div", { class: "stack" },
      h("p", "The vault claims this master:"),
      claimed ? fingerprint(claimed, 96) : h("p", "No master fingerprint found.")),
    h("h1", transferred ? "The master has changed" : "Verify the master"),
    h("p", transferred
      ? "The master role of this vault was transferred to a new identity. Confirm the new fingerprint with your administrator before you continue."
      : "nepomuk opens a vault only after you pin its master fingerprint. Get the fingerprint from your administrator through a separate channel and paste it here."),
    h("form", { onSubmit: submit },
      h("label", "Fingerprint from your administrator", input),
      verdict,
      h("div", { class: "actions" }, trustBtn, back))));
  input.focus();
}

// ------------------------------------------------------------------ Login

export function renderLogin(message) {
  state.unlocked = false;
  let touch = { available: false, enabled: null };
  let mode = settings.get("loginMode", "password");
  let identityPath = settings.get("identityPath", "");
  let local = { default: null, files: [] };
  const body = h("div");
  const tabs = h("div", { class: "tabs", role: "tablist" });

  const draw = () => {
    tabs.replaceChildren(
      h("button", { role: "tab", "aria-selected": mode === "password", onClick: () => { mode = "password"; draw(); } }, "Email and password"),
      h("button", { role: "tab", "aria-selected": mode === "identity", onClick: () => { mode = "identity"; draw(); } }, "Identity file"));
    const secret = h("input", { type: "password", autocomplete: "current-password", required: true });
    const submit = h("button", { class: "primary", type: "submit" }, "Unlock");
    let fields;
    if (mode === "password") {
      const email = h("input", { type: "email", value: settings.get("email", ""), autocomplete: "username", required: true });
      fields = [h("label", "Email", email), h("label", "Password", secret)];
      body._params = () => ({ email: email.value.trim(), password: secret.value });
      body._remember = () => settings.set("email", email.value.trim());
    } else {
      if (!identityPath && local.default) identityPath = local.default;
      const known = (p) => local.files.find((f) => f.path === p);
      const describe = (p) => {
        const f = known(p);
        return f ? `${f.name} – ${shortPath(p)}` : shortPath(p);
      };
      const pathLabel = h("span", { class: "mono" }, identityPath ? describe(identityPath) : "No file chosen");
      const choose = (p) => {
        identityPath = p;
        draw();
      };
      const others = local.files.filter((f) => f.path !== identityPath);
      const useDefault = local.default && identityPath !== local.default
        ? h("button", { type: "button", class: "small", onClick: () => choose(local.default) }, `Use default: ${known(local.default)?.name || basename(local.default)}`)
        : null;
      fields = [
        h("div", { class: "field-row" },
          h("label", "Identity file", pathLabel),
          h("button", { type: "button", onClick: async () => {
            const p = await invoke("pick", { kind: "identity" });
            if (p) choose(p);
          } }, "Choose…")),
        useDefault || others.length
          ? h("div", { class: "actions" },
            useDefault,
            others.filter((f) => f.path !== local.default).map((f) =>
              h("button", { type: "button", class: "small quiet", title: f.path, onClick: () => choose(f.path) }, `${f.name} – ${shortPath(f.path)}`)))
          : null,
        h("label", "Passphrase", secret),
      ];
      body._params = () => ({ identity: identityPath, password: secret.value });
      body._remember = () => settings.set("identityPath", identityPath);
    }
    settings.set("loginMode", mode);
    const remember = h("input", { type: "checkbox", checked: settings.get("rememberTouchid", false) });
    const rememberRow = touch.available && !touch.enabled
      ? h("label", { class: "check" }, remember, h("span", "Use Touch ID to unlock on this Mac"))
      : null;
    const form = h("form", { onSubmit: async (ev) => {
      ev.preventDefault();
      const params = body._params();
      if (rememberRow && remember.checked) params.remember_touchid = true;
      settings.set("rememberTouchid", remember.checked);
      if (mode === "identity" && !params.identity) return toast("Choose your identity file first.", "error");
      const res = await busy(submit, () => rpc("session.unlock", params));
      secret.value = "";
      if (res) {
        body._remember();
        state.unlocked = true;
        loadShell();
      }
    } }, fields, rememberRow, h("div", { class: "actions" }, submit));
    body.replaceChildren(form);
    if (!touch.enabled) secret.focus();
  };

  const touchBox = h("div");
  const unlockWithTouch = async (btn) => {
    const res = await busy(btn, () => rpc("session.unlock", { touchid: true }));
    if (res) {
      state.unlocked = true;
      loadShell();
    } else {
      refreshTouch();
    }
  };
  const drawTouch = () => {
    if (!touch.enabled) return mount(touchBox);
    const who = touch.enabled.kind === "email" ? touch.enabled.email : basename(touch.enabled.path);
    const btn = h("button", { class: "primary touch", onClick: () => unlockWithTouch(btn) },
      touchGlyph(), h("span", "Unlock with Touch ID"), h("small", who));
    mount(touchBox, h("div", { class: "stack" }, btn, h("p", { class: "muted" }, "Or unlock with your password:")));
    btn.focus();
  };
  const refreshTouch = async () => {
    touch = await rpc("touchid.status").catch(() => ({ available: false, enabled: null }));
    drawTouch();
    draw();
  };
  draw();
  refreshTouch();
  rpc("identity.local").then((r) => { local = r; if (mode === "identity") draw(); }).catch(() => {});

  mount(app, gate(
    h("div", { class: "stack" },
      h("p", "Master of this vault:"),
      state.info ? fingerprint(state.info.master_fingerprint, 72) : null,
      h("div", { class: "stack" },
        h("p", { class: "mono" }, currentPath()),
        h("div", h("button", { class: "small on-ink", onClick: () => switchVault() }, "Change vault")))),
    h("h1", "Unlock"),
    message ? h("div", { class: "notice seal" }, message) : null,
    touchBox,
    tabs,
    body,
    h("div", { class: "actions" },
      h("button", { class: "quiet small", onClick: () => renderEnroll() }, "Request access"),
      h("button", { class: "quiet small", onClick: () => renderNewIdentity() }, "Create an identity file"),
      h("button", { class: "quiet small", onClick: () => switchVault() }, "Open another vault"))));
}

function shortPath(p) {
  const home = (p.match(/^(\/Users\/[^/]+|\/home\/[^/]+)/) || [])[1];
  return home ? `~${p.slice(home.length)}` : p;
}

function touchGlyph() {
  // A simple fingerprint mark: concentric arcs.
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", "touch-glyph");
  for (const d of ["M6.5 9.5a5.5 5.5 0 0 1 11 0v2", "M9 10a3 3 0 0 1 6 0v3c0 2-.6 3.8-1.6 5.3", "M12 10v3.5c0 2.2-.8 4.3-2.2 5.8", "M4 8.5A8.5 8.5 0 0 1 20 9.5v2.5", "M6.5 13v1.5c0 1.6-.3 3-.9 4.2"]) {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

// ------------------------------------------------------------------ Enrollment (§4.3)

function passwordField(label, context) {
  const input = h("input", { type: "password", autocomplete: "new-password", required: true });
  const show = h("button", { type: "button", class: "small" }, "Show");
  const feedback = h("div", { class: "match" });
  let timer;
  const check = () => {
    clearTimeout(timer);
    if (!input.value) { feedback.textContent = ""; return; }
    timer = setTimeout(async () => {
      try {
        const r = await rpc("password.check", { password: input.value, context: context() });
        feedback.className = "match yes";
        feedback.textContent = r.warning ? `Accepted. ${r.warning}` : "Strong enough.";
      } catch (e) {
        feedback.className = "match no";
        feedback.textContent = errorText(e);
      }
    }, 250);
  };
  input.addEventListener("input", check);
  show.onclick = () => {
    input.type = input.type === "password" ? "text" : "password";
    show.textContent = input.type === "password" ? "Show" : "Hide";
  };
  const gen = h("button", { type: "button", class: "small", onClick: async () => {
    const r = await busy(gen, () => rpc("passgen", { words: 6 }));
    if (r) { input.value = r.passphrase; input.type = "text"; show.textContent = "Hide"; check(); }
  } }, "Generate passphrase");
  const el = h("div", { class: "stack" },
    h("label", label, h("span", { class: "hint" }, "At least 15 characters. A passphrase of six random words is easiest to remember."), input),
    h("div", { class: "actions" }, gen, show),
    feedback);
  return { el, input };
}

async function needCli() {
  // Enrollment needs no vault, only the CLI.
  if (!state.conn) await invoke("connect", { vault: null, project: null });
}

function requestResult(res, extra) {
  return h("div", { class: "card" },
    h("h3", "Send this file to an administrator"),
    h("p", { class: "mono" }, res.request),
    h("p", "When they add you, compare this fingerprint with the one they see:"),
    fingerprint(res.fingerprint, 72),
    extra);
}

function renderEnroll() {
  const email = h("input", { type: "email", required: true, autocomplete: "username" });
  const pw = passwordField("Password", () => [email.value.trim()]);
  const submit = h("button", { class: "primary", type: "submit" }, "Save access request");
  const out = h("div");
  mount(app, gate(
    h("p", "Your keys and your password are created here and never leave this computer. The request contains only public keys and your password-encrypted key."),
    h("h1", "Request access"),
    h("form", { onSubmit: async (ev) => {
      ev.preventDefault();
      await busy(submit, async () => {
        await needCli();
        const path = await invoke("pick_save", { defaultName: `${email.value.trim()}.request` });
        if (!path) return;
        const res = await rpc("identity.request", { email: email.value.trim(), password: pw.input.value, out: path });
        pw.input.value = "";
        mount(out, requestResult(res));
      });
    } }, h("label", "Work email", email), pw.el, h("div", { class: "actions" }, submit, h("button", { class: "quiet", type: "button", onClick: () => back() }, "Back"))),
    out));
}

function renderNewIdentity() {
  const name = h("input", { required: true, placeholder: "ci-eshop-android", pattern: "[A-Za-z0-9@._+-]+" });
  const pw = passwordField("Passphrase", () => [name.value.trim()]);
  const submit = h("button", { class: "primary", type: "submit" }, "Create identity file");
  const out = h("div");
  mount(app, gate(
    h("p", "An identity file holds keys protected by a passphrase – for CI pipelines, or for people who prefer a file to a password stored in the vault."),
    h("h1", "Create an identity file"),
    h("form", { onSubmit: async (ev) => {
      ev.preventDefault();
      await busy(submit, async () => {
        await needCli();
        const path = await invoke("pick_save", { defaultName: `${name.value.trim()}.npk` });
        if (!path) return;
        const res = await rpc("identity.new", { name: name.value.trim(), passphrase: pw.input.value, out: path });
        pw.input.value = "";
        mount(out, requestResult(res, h("p", { class: "muted" }, `Identity file: ${res.identity}. Keep it private; it is useless without the passphrase.`)));
      });
    } }, h("label", "Name", h("span", { class: "hint" }, "Letters, digits and @ . _ + -"), name), pw.el,
      h("div", { class: "actions" }, submit, h("button", { class: "quiet", type: "button", onClick: () => back() }, "Back"))),
    out));
}

function back() {
  if (state.info) renderLogin();
  else renderStart();
}

// ------------------------------------------------------------------ Shell

const NAV = [
  ["secrets", "Secrets"],
  ["users", "Users"],
  ["groups", "Groups"],
  ["rotation", "Rotation"],
  ["activity", "Activity"],
  ["run", "Run"],
  ["vault", "Vault"],
];

let refs = {};

export async function loadShell() {
  try {
    [state.me, state.info] = await Promise.all([rpc("whoami"), rpc("vault.info")]);
  } catch (e) {
    return handleSessionError(e);
  }
  const statusEl = h("div", { class: "status" }, h("span", { class: "dot" }), h("span", "Checking…"));
  const syncBtn = h("button", { class: "small", onClick: () => runSync(syncBtn) }, "Sync");
  const title = h("h2");
  const content = h("div", { class: "content" });
  const nav = h("nav", { "aria-label": "Sections" });
  refs = { statusEl, title, content, nav };
  mount(app, h("div", { class: "shell" },
    h("aside", { class: "sidebar" },
      h("div", { class: "vault", title: currentPath() },
        h("strong", "nepomuk"), h("small", basename(currentPath())),
        h("div", h("button", { class: "small on-ink", onClick: () => switchVault() }, "Switch vault"))),
      nav,
      h("div", { class: "me" },
        h("strong", state.me.name),
        h("span", { class: "muted" }, state.me.master ? "Master of this vault" : `${state.me.grants.length} grant${state.me.grants.length === 1 ? "" : "s"}`),
        h("button", { class: "small", onClick: () => lock("Locked.") }, "Lock"))),
    h("div", { class: "main" },
      h("header", { class: "topbar" }, title, statusEl, syncBtn),
      content)));
  show(state.view);
  refreshStatus();
  rpc("update.status").then((u) => {
    state.update = u;
    if (u.newer) refs.nav.after(h("div", { class: "update-note" }, `nepomuk ${u.latest} is available.`, h("br"), "Run ", h("code", "nepomuk upgrade")));
  }).catch(() => {});
}

export function show(view) {
  state.view = view;
  refs.nav.replaceChildren(...NAV.map(([id, label]) => {
    const count = id === "rotation" && state.info?.pending_rotation ? h("span", { class: "count" }, state.info.pending_rotation) : null;
    return h("button", { "aria-current": id === view ? "page" : false, onClick: () => show(id) }, label, count);
  }));
  refs.title.textContent = NAV.find(([id]) => id === view)[1];
  // A fresh container per navigation: a slow, stale view renders into a detached element.
  const page = h("div", { class: "view" }, h("div", { class: "spinner", "aria-label": "Loading" }));
  refs.content.replaceChildren(page);
  views[view](page, ctx).catch(handleSessionError);
}

/** What views need from the shell. */
export const ctx = {
  state,
  show,
  refreshStatus,
  /** Runs a write through the CLI, then refreshes the status and the current view. */
  async write(method, params, done) {
    const res = await rpc(method, params);
    if (res?.tasks?.length) toast(`Done. ${res.tasks.length} task(s) remain for other administrators.`);
    else if (done) toast(done);
    if (res?.warnings) res.warnings.forEach((w) => toast(w));
    state.info = await rpc("vault.info").catch(() => state.info);
    refreshStatus();
    return res;
  },
};

export async function refreshStatus(passive = false) {
  if (!refs.statusEl) return;
  try {
    // The periodic poll is not user activity: it must not keep the CLI session unlocked.
    const st = await rpc("vault.status", passive ? { passive: true } : {});
    state.status = st;
    const text = {
      "up-to-date": "Up to date",
      ahead: "Changes not pushed",
      offline: "Offline – showing the last fetched version",
      conflict: "Conflict",
    }[st.state] || st.state;
    refs.statusEl.className = `status ${st.state}`;
    refs.statusEl.replaceChildren(h("span", { class: "dot" }), h("span", `${text} · #${st.seq}`));
  } catch (e) {
    refs.statusEl.className = "status offline";
    refs.statusEl.replaceChildren(h("span", { class: "dot" }), h("span", errorText(e)));
  }
}

async function runSync(btn, resolve) {
  const res = await busy(btn, () => rpc("sync.run", resolve ? { resolve } : {}));
  if (!res) return;
  if (res.state === "conflict") return conflictDialog(res.conflicts);
  const n = res.replayed?.length || 0;
  toast(n ? `Synced ${n} pending change(s).` : "Up to date.");
  res.dropped?.forEach((d) => toast(`Dropped ${d.change}: ${d.reason}`, "error"));
  refreshStatus();
  show(state.view);
}

async function conflictDialog(conflicts) {
  const choice = await dialog("Resolve conflicts", (close) => h("div", { class: "stack" },
    h("p", "Someone else changed the same secrets while your changes were waiting to be pushed."),
    h("ul", conflicts.map((c) => h("li", h("strong", c.change), " – ", c.details?.path || c.message))),
    h("div", { class: "actions end" },
      h("button", { class: "quiet", onClick: () => close(null) }, "Decide later"),
      h("button", { onClick: () => close("theirs") }, "Keep their version"),
      h("button", { class: "primary", onClick: () => close("ours") }, "Overwrite with mine"))));
  if (choice) runSync(null, choice);
}

// ------------------------------------------------------------------ Locking (§12.2, §13)

/**
 * Locks at once: the content and every dialog go away before anything else, and answers to
 * calls still running are dropped; then the CLI forgets the identity (and is ended and
 * restarted if a long operation keeps it from answering, see `lock_session`).
 */
export async function lock(message) {
  const wasUnlocked = state.unlocked;
  session.epoch += 1;
  closeAllDialogs();
  state.unlocked = false;
  state.me = null;
  state.collapsed = null;
  refs = {};
  mount(app);
  if (wasUnlocked) await invoke("lock_session").catch(() => {});
  renderLogin(message);
}

function handleSessionError(e) {
  if (e && (e.code === "PASSWORD_REQUIRED" || e.code === "IDENTITY_DISABLED")) {
    return lock(e.code === "IDENTITY_DISABLED" ? "This identity has been disabled." : "The session is locked.");
  }
  showError(e);
}

function watchActivity() {
  const bump = () => { state.lastActivity = Date.now(); };
  ["mousemove", "keydown", "mousedown", "wheel", "touchstart"].forEach((ev) => window.addEventListener(ev, bump, { passive: true }));
  setInterval(() => {
    const idleMin = settings.get("idleMinutes", 10);
    if (state.unlocked && Date.now() - state.lastActivity > idleMin * 60_000) lock("Locked after inactivity.");
  }, 15_000);
  setInterval(() => { if (state.unlocked) refreshStatus(true); }, 60_000);
}

async function boot() {
  await listen("nepomuk:notification", (ev) => {
    const msg = ev.payload;
    if (msg.method === "session.expired" && state.unlocked) lock("Locked after inactivity.");
    if (msg.method === "vault.changed" && state.unlocked) show(state.view);
  });
  await listen("nepomuk:locked", () => { if (state.unlocked) lock("Locked because the screen was locked."); });
  await listen("nepomuk:exited", () => {
    if (state.conn) renderStart("The nepomuk process stopped. Open the vault again.");
    state.conn = null;
  });
  watchActivity();
  renderStart();
}

boot();

// Exported for views that need them.
export { halo, fpText };
