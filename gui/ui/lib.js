// Shared helpers: the bridge to the Rust backend, safe DOM building and the fingerprint halo.
// Vault data only ever reaches the page through textContent – never innerHTML.

const tauri = window.__TAURI__;

export const invoke = (cmd, args = {}) => tauri.core.invoke(cmd, args);
export const rpc = (method, params = {}) => invoke("rpc", { method, params });
export const listen = (event, cb) => tauri.event.listen(event, cb);

// ------------------------------------------------------------------ DOM

const SVG_NS = "http://www.w3.org/2000/svg";

function build(el, attrs, children) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.setAttribute("class", Array.isArray(v) ? v.filter(Boolean).join(" ") : v);
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "value" && "value" in el) el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** h("button", { class: "primary", onClick }, "Save") */
export function h(tag, attrs, ...children) {
  if (attrs instanceof Node || typeof attrs === "string" || Array.isArray(attrs)) {
    children.unshift(attrs);
    attrs = {};
  }
  return build(document.createElement(tag), attrs, children);
}

export function s(tag, attrs, ...children) {
  return build(document.createElementNS(SVG_NS, tag), attrs, children);
}

export function mount(parent, ...children) {
  parent.replaceChildren(...children.flat().filter(Boolean));
}

// ------------------------------------------------------------------ Feedback

export function toast(message, kind = "info", code) {
  const t = h("div", { class: ["toast", kind === "error" && "error"] }, message, code ? h("code", code) : null);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), kind === "error" ? 8000 : 4000);
}

export function errorText(e) {
  if (!e) return "Something went wrong.";
  if (typeof e === "string") return e;
  return e.message || JSON.stringify(e);
}

export function showError(e) {
  toast(errorText(e), "error", e && e.code);
}

/** Modal dialog; `build(close)` returns its content. Resolves with the value passed to close. */
export function dialog(title, build) {
  return new Promise((resolve) => {
    const d = h("dialog", { "aria-label": title });
    const close = (value) => {
      d.close();
      d.remove();
      resolve(value);
    };
    d.addEventListener("cancel", (ev) => {
      ev.preventDefault();
      close(undefined);
    });
    d.append(h("div", { class: "dialog-body" }, h("h2", title), build(close)));
    document.body.append(d);
    d.showModal();
    const first = d.querySelector("input, select, textarea, button.primary");
    if (first) first.focus();
  });
}

export function confirmDialog(title, message, action, danger = false) {
  return dialog(title, (close) =>
    h("div", { class: "stack" },
      h("p", message),
      h("div", { class: "actions end" },
        h("button", { class: "quiet", onClick: () => close(false) }, "Cancel"),
        h("button", { class: danger ? "danger" : "primary", onClick: () => close(true) }, action))));
}

/** Runs an async action with the button disabled; reports errors. */
export async function busy(button, fn) {
  if (button) button.disabled = true;
  try {
    return await fn();
  } catch (e) {
    showError(e);
    return undefined;
  } finally {
    if (button) button.disabled = false;
  }
}

// ------------------------------------------------------------------ Fingerprints

function hashBytes(str, n) {
  // FNV-1a over the fingerprint, stretched to n bytes – for display only, not for security.
  const out = [];
  let x = 0x811c9dc5;
  for (let i = 0; out.length < n; i++) {
    x ^= str.charCodeAt(i % str.length) + i;
    x = Math.imul(x, 0x01000193) >>> 0;
    if (i >= str.length) out.push(x & 0xff);
  }
  return out;
}

function starPath(cx, cy, r) {
  const pts = [];
  for (let i = 0; i < 10; i++) {
    const rr = i % 2 === 0 ? r : r * 0.42;
    const a = (i * Math.PI) / 5;
    pts.push(`${(cx + rr * Math.sin(a)).toFixed(2)},${(cy - rr * Math.cos(a)).toFixed(2)}`);
  }
  return `M${pts.join("L")}Z`;
}

/** Nepomuk's halo of five stars, laid out from the fingerprint: compare it at a glance. */
export function halo(fp, size = 72) {
  const b = hashBytes(fp || "?", 15);
  const svg = s("svg", { viewBox: "0 0 100 100", width: size, height: size, role: "img", "aria-label": "Fingerprint halo" });
  svg.append(s("circle", { cx: 50, cy: 50, r: 48, class: "halo-disc" }));
  svg.append(s("circle", { cx: 50, cy: 50, r: 40, class: "halo-ring" }));
  const tilt = (b[0] / 255) * 360;
  for (let k = 0; k < 5; k++) {
    const angle = ((tilt + k * 72 + (b[1 + k] / 255 - 0.5) * 36) * Math.PI) / 180;
    const radius = 14 + (b[6 + k] / 255) * 20;
    const r = 4 + (b[11 + (k % 4)] / 255) * 5;
    svg.append(s("path", { d: starPath(50 + radius * Math.sin(angle), 50 - radius * Math.cos(angle), r), class: "halo-star" }));
  }
  return svg;
}

export function fpText(fp) {
  const body = (fp || "").replace(/^npk1/, "");
  const groups = body.match(/.{1,5}/g) || [];
  return h("div", { class: "fp-text" }, h("span", "npk1"), groups.map((g) => h("span", g)));
}

export function fingerprint(fp, size) {
  return h("div", { class: "fingerprint" }, halo(fp, size), fpText(fp));
}

// ------------------------------------------------------------------ Formatting

export function when(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function bytes(n) {
  if (n === undefined || n === null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function basename(path) {
  return (path || "").split(/[\\/]/).filter(Boolean).pop() || path;
}

/** Splits a command line into arguments (quotes group words). */
export function splitArgs(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

export const settings = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem(`nepomuk.${key}`);
      return v === null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`nepomuk.${key}`, JSON.stringify(value));
    } catch {
      /* settings are a convenience */
    }
  },
};
