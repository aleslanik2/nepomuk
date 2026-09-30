// Screens of the main shell (§13).

import { invoke, rpc, h, mount, toast, busy, dialog, confirmDialog, fingerprint, when, bytes, basename, splitArgs, settings, errorText, showError } from "./lib.js";

// ------------------------------------------------------------------ Secrets

const TYPE_GLYPH = { folder: "▸", text: "•", binary: "◆", record: "≡" };

function buildTree(base, entries) {
  const root = { name: base, path: base, children: new Map(), entry: null };
  const prefix = base === "/" ? "/" : `${base}/`;
  for (const e of entries) {
    const rel = e.path.startsWith(prefix) ? e.path.slice(prefix.length) : e.path.replace(/^\//, "");
    let node = root;
    let acc = base === "/" ? "" : base;
    for (const part of rel.split("/")) {
      acc = `${acc}/${part}`;
      if (!node.children.has(part)) node.children.set(part, { name: part, path: acc, children: new Map(), entry: null });
      node = node.children.get(part);
    }
    node.entry = e;
  }
  return root;
}

function secretsView(target, ctx) {
  let data = null;
  let selected = ctx.state.selected || null;
  let filter = "";
  let users = [];
  let groups = [];
  let templates = [];
  const treeEl = h("div", { class: "tree", role: "tree" });
  const detailEl = h("div", { class: "panel detail" });

  const load = async () => {
    [data, users, groups, templates] = await Promise.all([
      rpc("node.list", { recursive: true }),
      rpc("user.list").then((r) => r.users).catch(() => []),
      rpc("group.list").then((r) => r.groups).catch(() => []),
      rpc("templates.list").then((r) => r.templates),
    ]);
    if (selected && !data.entries.some((e) => e.path === selected) && selected !== data.path) selected = null;
    drawTree();
    drawDetail();
  };

  const select = (path) => {
    selected = path;
    ctx.state.selected = path;
    drawTree();
    drawDetail();
  };

  const drawTree = () => {
    const root = buildTree(data.path, data.entries);
    const q = filter.toLowerCase();
    const visible = (n) => !q || n.path.toLowerCase().includes(q) || [...n.children.values()].some(visible);
    const item = (n, depth) => {
      if (!visible(n)) return null;
      const e = n.entry;
      const type = e ? e.type : "folder";
      const flags = [];
      if (e?.rotation_pending) flags.push(h("span", { class: "flag rot", title: "Rotate at the source" }, "rotate"));
      if (e?.expiring_soon) flags.push(h("span", { class: "flag exp", title: `Expires ${when(e.expires)}` }, "expires"));
      const btn = h("button", {
        role: "treeitem",
        "aria-selected": selected === n.path,
        onClick: () => select(n.path),
      }, h("span", { class: "glyph", "aria-hidden": "true" }, TYPE_GLYPH[type] || "•"), n.name, flags);
      btn.style.paddingLeft = `${0.75 + depth * 1}rem`;
      const kids = [...n.children.values()].sort((a, b) => {
        const fa = (a.entry?.type || "folder") === "folder" ? 0 : 1;
        const fb = (b.entry?.type || "folder") === "folder" ? 0 : 1;
        return fa - fb || a.name.localeCompare(b.name);
      });
      return h("li", btn, kids.length ? h("ul", kids.map((k) => item(k, depth + 1))) : null);
    };
    const rootItem = h("li", h("button", { role: "treeitem", "aria-selected": selected === data.path, onClick: () => select(data.path) },
      h("span", { class: "glyph", "aria-hidden": "true" }, "▸"), data.path));
    const kids = [...root.children.values()].sort((a, b) => a.name.localeCompare(b.name)).map((k) => item(k, 1));
    mount(treeEl, h("ul", rootItem, kids));
  };

  const entryFor = (path) => data.entries.find((e) => e.path === path) || (path === data.path ? { path, name: path, type: "folder" } : null);

  const drawDetail = () => {
    if (!data.entries.length && !selected) {
      mount(detailEl, h("div", { class: "empty" },
        h("h3", "Nothing here you can read"),
        h("p", "Ask an administrator for access, or create the first folder if you are the master."),
        h("button", { class: "primary", onClick: () => newFolder(data.path) }, "New folder")));
      return;
    }
    const e = selected ? entryFor(selected) : null;
    if (!e) {
      mount(detailEl, h("div", { class: "empty" }, h("h3", "Choose a folder or secret"), h("p", `${data.entries.length} items you can read.`)));
      return;
    }
    mount(detailEl, e.type === "folder" ? folderDetail(e) : secretDetail(e), accessBlock(e.path));
  };

  // ---------------------------------------------------------- Folder

  const folderDetail = (e) => {
    const children = data.entries.filter((x) => x.path.startsWith(e.path === "/" ? "/" : `${e.path}/`) && x.path.split("/").length === (e.path === "/" ? 2 : e.path.split("/").length + 1));
    return h("div", { class: "stack" },
      h("div", { class: "detail-head" }, h("div", { class: "crumbs" }, e.path), h("h2", e.name === "/" ? "Vault root" : e.name),
        h("div", { class: "facts" }, h("span", h("strong", children.length), " items"))),
      h("div", { class: "actions" },
        h("button", { class: "primary", onClick: () => newSecret(e.path) }, "New secret"),
        h("button", { onClick: () => newFolder(e.path) }, "New folder"),
        e.path !== "/" && e.path !== data.path ? h("button", { onClick: () => move(e) }, "Rename or move") : null,
        e.path !== "/" ? h("button", { onClick: () => rekey(e) }, "Rekey") : null,
        e.path !== "/" && e.path !== data.path ? h("button", { class: "danger", onClick: () => remove(e) }, "Delete") : null));
  };

  // ---------------------------------------------------------- Secret

  const valueRow = (label, spec, kind, meta, fileName) => {
    const chip = h("div", { class: ["seal-chip", kind === "binary" && "file"] },
      kind === "binary" ? `Encrypted file${meta?.size !== undefined ? `, ${bytes(meta.size)}` : ""}` : "Sealed");
    let timer;
    const reseal = () => {
      clearTimeout(timer);
      chip.className = "seal-chip";
      chip.textContent = "Sealed";
      reveal.textContent = "Reveal";
    };
    const reveal = h("button", { class: "small", onClick: async () => {
      if (chip.classList.contains("open")) return reseal();
      const r = await busy(reveal, () => rpc("node.get", { path: spec }));
      if (!r) return;
      chip.className = "seal-chip open";
      chip.textContent = r.value ?? "";
      reveal.textContent = "Hide";
      timer = setTimeout(reseal, 60_000);
    } }, "Reveal");
    const copy = h("button", { class: "small", onClick: () => busy(copy, async () => {
      await invoke("copy_secret", { spec, seconds: settings.get("clipboardSeconds", 30) });
      toast(`Copied. The clipboard is cleared in ${settings.get("clipboardSeconds", 30)} s.`);
    }) }, "Copy");
    const save = h("button", { class: "small", onClick: () => busy(save, async () => {
      const p = await invoke("save_secret", { spec, defaultName: fileName });
      if (p) toast(`Saved to ${p}`);
    }) }, "Save as file");
    const buttons = kind === "binary" ? [save] : [reveal, copy, save];
    return h("div", { class: "value" }, h("div", { class: "name" }, label), chip, h("div", { class: "actions" }, buttons));
  };

  const secretDetail = (e) => {
    const facts = [h("span", "Type ", h("strong", e.template ? `${e.type}: ${e.template}` : e.type))];
    if (e.updated) facts.push(h("span", "Changed ", h("strong", when(e.updated))));
    if (e.expires) facts.push(h("span", "Expires ", h("strong", when(e.expires))));
    let rows;
    if (e.type === "record") {
      rows = (e.fields || []).map((f) => {
        const t = e.field_types?.[f] || {};
        return valueRow(f, `${e.path}#${f}`, t.type, t, t.type === "binary" ? f : `${e.name}-${f}.txt`);
      });
    } else {
      rows = [valueRow(e.type === "binary" ? "File" : "Value", e.path, e.type, e, e.type === "binary" ? e.name : `${e.name}.txt`)];
    }
    return h("div", { class: "stack" },
      h("div", { class: "detail-head" }, h("div", { class: "crumbs" }, e.path), h("h2", e.name), h("div", { class: "facts" }, facts)),
      e.rotation_pending ? h("div", { class: "notice seal" }, "Someone who could read this secret lost access. Change it at its source, store the new value here and mark it rotated.") : null,
      e.expiring_soon ? h("div", { class: "notice warn" }, `The certificate expires ${when(e.expires)}.`) : null,
      h("section", { class: "block" }, h("div", { class: "values" }, rows)),
      h("div", { class: "actions" },
        h("button", { class: "primary", onClick: () => edit(e) }, "Replace value"),
        e.rotation_pending ? h("button", { onClick: () => markRotated(e) }, "Mark rotated") : null,
        h("button", { onClick: () => move(e) }, "Rename or move"),
        h("button", { onClick: () => rekey(e) }, "Rekey"),
        h("button", { class: "danger", onClick: () => remove(e) }, "Delete")));
  };

  // ---------------------------------------------------------- Access

  const accessBlock = (path) => {
    const wrap = h("section", { class: "block" }, h("h3", "Who has access"), h("div", { class: "spinner" }));
    rpc("access.list", { path }).then((a) => {
      const grantRows = a.grants.map((g) => h("tr",
        h("td", g.principal.replace(/^user:/, "").replace(/^group:/, "group ")),
        h("td", h("span", { class: ["tag", g.right === "admin" && "seal"] }, g.right)),
        h("td", { class: "mono" }, g.inherited ? g.on : "this item"),
        h("td", g.inherited ? null : h("button", { class: "small danger", onClick: () => revoke(g.principal, path) }, "Revoke"))));
      const who = h("select", { "aria-label": "User or group" },
        h("optgroup", { label: "Users" }, users.filter((u) => !u.disabled).map((u) => h("option", { value: `user:${u.name}` }, u.name))),
        groups.length ? h("optgroup", { label: "Groups" }, groups.map((g) => h("option", { value: `group:${g.name}` }, g.name))) : null);
      const right = h("select", { "aria-label": "Right" }, ["read", "write", "share", "admin"].map((r) => h("option", { value: r }, r)));
      const add = h("button", { onClick: () => busy(add, async () => {
        await ctx.write("grant.add", { who: who.value, right: right.value, path }, "Access granted.");
        drawDetail();
      }) }, "Grant");
      mount(wrap,
        h("h3", "Who has access"),
        h("table", h("thead", h("tr", h("th", "Who"), h("th", "Right"), h("th", "Granted on"), h("th", ""))), h("tbody", grantRows)),
        h("p", { class: "muted" }, "Effective: ", a.effective.map((x) => `${x.user} (${x.right})`).join(", ")),
        h("div", { class: "field-row" }, h("label", "Give", who), h("label", "Right", right), add));
    }).catch((e) => mount(wrap, h("h3", "Who has access"), h("p", { class: "muted" }, errorText(e))));
    return wrap;
  };

  const revoke = async (principal, path) => {
    const ok = await confirmDialog("Revoke access", `${principal} loses access to ${path}. The subtree gets new keys; secrets they could read are marked for rotation.`, "Revoke", true);
    if (!ok) return;
    try {
      const r = await ctx.write("grant.revoke", { who: principal, path }, "Access revoked.");
      if (r.rotate?.length) toast(`${r.rotate.length} secret(s) to rotate at the source.`);
      load();
    } catch (e) { showError(e); }
  };

  // ---------------------------------------------------------- Writes

  const childPath = (folder, name) => (folder === "/" ? `/${name}` : `${folder}/${name}`);

  const newFolder = async (parent) => {
    const name = await dialog("New folder", (close) => {
      const input = h("input", { required: true });
      return h("form", { onSubmit: (ev) => { ev.preventDefault(); close(input.value.trim()); } },
        h("label", `Folder in ${parent}`, input),
        h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Cancel"), h("button", { class: "primary" }, "Create folder")));
    });
    if (!name) return;
    try {
      await ctx.write("node.mkdir", { path: childPath(parent, name) }, "Folder created.");
      selected = childPath(parent, name);
      load();
    } catch (e) { showError(e); }
  };

  const secretInput = (label, value = "") => {
    const input = h("input", { type: "password", value, autocomplete: "off", spellcheck: "false", class: "mono" });
    const toggle = h("button", { type: "button", class: "small", onClick: () => {
      input.type = input.type === "password" ? "text" : "password";
      toggle.textContent = input.type === "password" ? "Show" : "Hide";
    } }, "Show");
    const gen = h("button", { type: "button", class: "small", onClick: async () => {
      const r = await busy(gen, () => rpc("passgen", { words: 6 }));
      if (r) input.value = r.passphrase;
    } }, "Generate");
    return { input, el: h("div", { class: "field-row" }, h("label", label, input), toggle, gen) };
  };

  const fileInput = (label) => {
    let file = null;
    const name = h("span", { class: "mono" }, "No file chosen");
    const pickBtn = h("button", { type: "button", onClick: async () => {
      const f = await busy(pickBtn, () => invoke("pick_file_b64"));
      if (f) { file = f; name.textContent = `${f.name} (${bytes(f.size)})`; }
    } }, "Choose file…");
    return { get: () => file, el: h("div", { class: "field-row" }, h("label", label, name), pickBtn) };
  };

  /** Form for a secret's content; returns node.put parameters or throws. */
  const contentForm = (kind, templateName, existing) => {
    if (kind === "text") {
      const v = secretInput("Value", existing?.value || "");
      return { el: v.el, params: () => ({ type: "text", value: v.input.value }) };
    }
    if (kind === "binary") {
      const f = fileInput("File");
      return { el: f.el, params: () => {
        const file = f.get();
        if (!file) throw { message: "Choose a file." };
        return { type: "binary", base64: file.base64 };
      } };
    }
    const tpl = templates.find((t) => t.name === templateName) || { name: "generic", fields: [] };
    const rows = [];
    const inputs = {};
    const fields = tpl.fields.length ? tpl.fields : Object.entries(existing?.fields || {}).map(([name, f]) => ({ name, binary: f.type === "binary" }));
    const addRow = (name, binary) => {
      const prev = existing?.fields?.[name];
      if (binary) {
        const f = fileInput(name);
        inputs[name] = () => {
          const file = f.get();
          if (file) return { type: "binary", base64: file.base64 };
          if (prev) return prev;
          throw { message: `Choose a file for ${name}.` };
        };
        rows.push(f.el);
      } else {
        const v = secretInput(name, prev?.value || "");
        inputs[name] = () => ({ type: "text", value: v.input.value });
        rows.push(v.el);
      }
    };
    fields.forEach((f) => addRow(f.name, f.binary));
    const extra = h("div", { class: "stack" });
    const newField = h("input", { placeholder: "field name" });
    const addField = () => {
      const n = newField.value.trim();
      if (n && !inputs[n]) {
        addRow(n, false);
        extra.replaceChildren(...rows);
        newField.value = "";
      }
    };
    const addBox = tpl.name === "generic"
      ? h("div", { class: "field-row" }, h("label", "Add field", newField), h("button", { type: "button", onClick: addField }, "Add text field"))
      : null;
    extra.replaceChildren(...rows);
    return { el: h("div", { class: "stack" }, extra, addBox), params: () => {
      const out = {};
      for (const [k, get] of Object.entries(inputs)) out[k] = get();
      return { type: "record", template: tpl.name, fields: out };
    } };
  };

  const newSecret = async (parent) => {
    await dialog("New secret", (close) => {
      const name = h("input", { required: true });
      const kind = h("select", h("option", { value: "text" }, "Text – a password or token"), h("option", { value: "binary" }, "File – keystore, certificate, key"),
        templates.map((t) => h("option", { value: `record:${t.name}` }, `Record – ${t.name}`)));
      const body = h("div");
      let form;
      const redraw = () => {
        const [k, t] = kind.value.split(":");
        form = contentForm(k, t);
        mount(body, form.el);
      };
      kind.addEventListener("change", redraw);
      redraw();
      const submit = h("button", { class: "primary" }, "Store secret");
      return h("form", { onSubmit: (ev) => {
        ev.preventDefault();
        busy(submit, async () => {
          const path = childPath(parent, name.value.trim());
          await ctx.write("node.put", { path, ...form.params() }, "Secret stored.");
          selected = path;
          close(true);
          load();
        });
      } }, h("label", `Name in ${parent}`, name), h("label", "Kind", kind), body,
        h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Cancel"), submit));
    });
  };

  const edit = async (e) => {
    let existing = null;
    if (e.type !== "binary") existing = await busy(null, () => rpc("node.get", { path: e.path }));
    if (e.type !== "binary" && !existing) return;
    await dialog(`Replace ${e.name}`, (close) => {
      const form = contentForm(e.type === "record" ? "record" : e.type, e.template, existing);
      existing = null;
      const submit = h("button", { class: "primary" }, "Save changes");
      return h("form", { onSubmit: (ev) => {
        ev.preventDefault();
        busy(submit, async () => {
          await ctx.write("node.put", { path: e.path, ...form.params() }, "Changes saved.");
          close(true);
          load();
        });
      } }, form.el, h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Cancel"), submit));
    });
  };

  const move = async (e) => {
    const dst = await dialog(`Rename or move ${e.name}`, (close) => {
      const input = h("input", { class: "mono", value: e.path, required: true });
      return h("form", { onSubmit: (ev) => { ev.preventDefault(); close(input.value.trim()); } },
        h("label", "New path", input),
        h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Cancel"), h("button", { class: "primary" }, "Move")));
    });
    if (!dst || dst === e.path) return;
    try {
      await ctx.write("node.mv", { src: e.path, dst }, "Moved.");
      selected = dst;
      load();
    } catch (err) { showError(err); }
  };

  const remove = async (e) => {
    const ok = await confirmDialog(`Delete ${e.name}`, e.type === "folder" ? `${e.path} and everything in it will be deleted.` : `${e.path} will be deleted. Older versions stay in git history.`, "Delete", true);
    if (!ok) return;
    try {
      await ctx.write("node.rm", { path: e.path }, "Deleted.");
      selected = null;
      load();
    } catch (err) { showError(err); }
  };

  const rekey = async (e) => {
    const ok = await confirmDialog(`Rekey ${e.name}`, "New keys for this item and everything below it. Use it after moving items or when a key may have leaked.", "Rekey");
    if (!ok) return;
    try { await ctx.write("node.rekey", { path: e.path }, "New keys issued."); } catch (err) { showError(err); }
  };

  const markRotated = async (e) => {
    try {
      await ctx.write("rotation.done", { path: e.path }, "Marked as rotated.");
      load();
    } catch (err) { showError(err); }
  };

  const search = h("input", { type: "search", placeholder: "Filter", "aria-label": "Filter secrets", onInput: (ev) => { filter = ev.target.value; drawTree(); } });
  mount(target, h("div", { class: "split" },
    h("div", { class: "panel tree-panel" }, h("div", { class: "tree-tools" }, search), treeEl),
    detailEl));
  return load();
}

// ------------------------------------------------------------------ Users

async function usersView(target, ctx) {
  const { users } = await rpc("user.list");
  const add = h("button", { class: "primary", onClick: () => addUser() }, "Add user");
  const row = (u) => h("tr",
    h("td", h("strong", u.name), " ", u.master ? h("span", { class: "tag brass" }, "master") : null, u.disabled ? h("span", { class: "tag seal" }, "disabled") : null),
    h("td", u.kind === "password" ? "Password" : "Identity file"),
    h("td", u.groups.map((g) => h("span", { class: "tag" }, g)), u.system_rights.map((r) => h("span", { class: "tag brass" }, r))),
    h("td", h("div", { class: "actions" },
      h("button", { class: "small", onClick: () => userAccess(u) }, "Access"),
      u.master || u.disabled ? null : h("button", { class: "small", onClick: () => rights(u) }, "System rights"),
      u.master ? null : h("button", { class: "small", onClick: () => replace(u) }, "Replace identity"),
      u.master || u.disabled ? null : h("button", { class: "small danger", onClick: () => offboard(u) }, "Offboard"))));

  const addUser = async () => {
    const path = await invoke("pick", { kind: "request" });
    if (!path) return;
    let req;
    try { req = await rpc("request.inspect", { path }); } catch (e) { return showError(e); }
    const ok = await dialog("Add user", (close) => h("div", { class: "stack" },
      h("p", `${req.name} asks for access with ${req.kind === "password" ? "a password" : "an identity file"}. Compare this fingerprint with them over a separate channel:`),
      fingerprint(req.fingerprint, 72),
      h("div", { class: "actions end" }, h("button", { class: "quiet", onClick: () => close(false) }, "Cancel"), h("button", { class: "primary", onClick: () => close(true) }, "Add user"))));
    if (!ok) return;
    try {
      await ctx.write("user.add", { request: req.request }, `${req.name} added.`);
      ctx.show("users");
    } catch (e) { showError(e); }
  };

  const userAccess = async (u) => {
    const a = await busy(null, () => rpc("user.access", { name: u.name }));
    if (!a) return;
    await dialog(`What ${u.name} can access`, (close) => h("div", { class: "stack" },
      a.master ? h("p", "The master can read and change everything.") : null,
      a.access.length ? h("table", h("tbody", a.access.map((x) => h("tr", h("td", { class: "mono" }, x.path), h("td", h("span", { class: "tag" }, x.right))))))
        : h("p", { class: "muted" }, "Nothing you can see."),
      h("p", { class: "muted" }, "Only folders you can read yourself are listed."),
      h("div", { class: "actions end" }, h("button", { class: "primary", onClick: () => close() }, "Close"))));
  };

  const rights = async (u) => {
    const { groups } = await rpc("group.list");
    await dialog(`System rights of ${u.name}`, (close) => {
      const right = h("select", ["users", "groups", "audit", ...groups.map((g) => `group-admin:${g.name}`)].map((r) => h("option", { value: r }, r)));
      const delegate = h("input", { type: "checkbox" });
      const grant = h("button", { class: "primary", type: "submit" }, "Grant");
      return h("form", { onSubmit: (ev) => {
        ev.preventDefault();
        busy(grant, async () => {
          await ctx.write("sysright.grant", { user: u.name, right: right.value, delegate: delegate.checked }, "Right granted.");
          close();
          ctx.show("users");
        });
      } },
        u.system_rights.length ? h("div", { class: "stack" }, h("h3", "Current"),
          h("ul", { class: "checklist" }, u.system_rights.map((r) => h("li", r, h("button", { type: "button", class: "small danger", onClick: () => busy(null, async () => {
            await ctx.write("sysright.revoke", { user: u.name, right: r.replace("+delegate", "") }, "Right revoked.");
            close();
            ctx.show("users");
          }) }, "Revoke"))))) : null,
        h("label", "Right", right),
        h("label", { class: "field-row" }, delegate, h("span", "May grant this right to others")),
        h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Close"), grant));
    });
  };

  const replace = async (u) => {
    const path = await invoke("pick", { kind: "request" });
    if (!path) return;
    let req;
    try { req = await rpc("request.inspect", { path }); } catch (e) { return showError(e); }
    const ok = await dialog(`Replace the identity of ${u.name}`, (close) => h("div", { class: "stack" },
      h("p", "Use this when someone forgot their password or lost their identity file. Their old keys stop working; grants you can re-issue are re-issued."),
      fingerprint(req.fingerprint, 72),
      h("div", { class: "actions end" }, h("button", { class: "quiet", onClick: () => close(false) }, "Cancel"), h("button", { class: "primary", onClick: () => close(true) }, "Replace identity"))));
    if (!ok) return;
    try { await ctx.write("user.replace", { name: u.name, request: req.request }, "Identity replaced."); ctx.show("users"); } catch (e) { showError(e); }
  };

  const offboard = async (u) => {
    const ok = await confirmDialog(`Offboard ${u.name}`, `${u.name} is disabled, removed from all groups and loses every grant. Affected folders get new keys. You get a checklist of secrets to change at their source.`, "Offboard", true);
    if (!ok) return;
    let r;
    try { r = await ctx.write("user.offboard", { name: u.name }); } catch (e) { return showError(e); }
    await dialog(`${u.name} was offboarded`, (close) => h("div", { class: "stack" },
      r.rotate?.length ? h("div", { class: "stack" }, h("h3", "Change these secrets at their source"),
        h("ul", { class: "checklist" }, r.rotate.map((p) => h("li", h("span", { class: "mono" }, p))))) : h("p", "No secrets need rotation."),
      r.tasks?.length ? h("div", { class: "stack" }, h("h3", "Left for other administrators"), h("ul", r.tasks.map((t) => h("li", t)))) : null,
      h("div", { class: "actions end" }, h("button", { onClick: () => { close(); ctx.show("rotation"); } }, "Open rotation list"), h("button", { class: "primary", onClick: () => close() }, "Done"))));
    ctx.show("users");
  };

  mount(target, h("div", { class: "page" },
    h("div", { class: "page-head" }, h("p", { class: "muted" }, `${users.filter((u) => !u.disabled).length} active users`), add),
    h("div", { class: "panel" }, h("table", h("thead", h("tr", h("th", "User"), h("th", "Signs in with"), h("th", "Groups and rights"), h("th", ""))), h("tbody", users.map(row))))));
}

// ------------------------------------------------------------------ Groups

async function groupsView(target, ctx) {
  const [{ groups }, { users }] = await Promise.all([rpc("group.list"), rpc("user.list")]);
  const create = h("button", { class: "primary", onClick: async () => {
    const name = await dialog("New group", (close) => {
      const input = h("input", { required: true, pattern: "[A-Za-z0-9@._+-]+" });
      return h("form", { onSubmit: (ev) => { ev.preventDefault(); close(input.value.trim()); } },
        h("label", "Name", h("span", { class: "hint" }, "Group names are visible to everyone with the vault file."), input),
        h("div", { class: "actions end" }, h("button", { type: "button", class: "quiet", onClick: () => close() }, "Cancel"), h("button", { class: "primary" }, "Create group")));
    });
    if (!name) return;
    try { await ctx.write("group.create", { name }, "Group created."); ctx.show("groups"); } catch (e) { showError(e); }
  } }, "New group");

  const card = (g) => {
    const pick = h("select", { "aria-label": "User" }, users.filter((u) => !u.disabled && !g.members.includes(u.name)).map((u) => h("option", { value: u.name }, u.name)));
    const add = h("button", { onClick: () => busy(add, async () => {
      await ctx.write("group.add", { group: g.name, user: pick.value }, "Member added.");
      ctx.show("groups");
    }) }, "Add member");
    return h("div", { class: "card" },
      h("div", { class: "page-head" }, h("h3", g.name), h("span", { class: "muted" }, `${g.grants} grant${g.grants === 1 ? "" : "s"}`)),
      h("ul", { class: "checklist" }, g.members.map((m) => h("li", h("span", m, g.admins.includes(m) ? h("span", { class: "tag brass" }, "manages") : null),
        h("button", { class: "small danger", onClick: async () => {
          const ok = await confirmDialog(`Remove ${m}`, `The group gets a new key and its folders get new keys, so ${m} cannot read anything the group can.`, "Remove", true);
          if (!ok) return;
          try { await ctx.write("group.remove", { group: g.name, user: m }, "Member removed."); ctx.show("groups"); } catch (e) { showError(e); }
        } }, "Remove")))),
      pick.options.length ? h("div", { class: "field-row" }, h("label", "Add", pick), add) : null);
  };
  mount(target, h("div", { class: "page" },
    h("div", { class: "page-head" }, h("p", { class: "muted" }, "Members hold the group key and can read everything the group can."), create),
    groups.length ? groups.map(card) : h("div", { class: "empty" }, h("p", "No groups yet."))));
}

// ------------------------------------------------------------------ Rotation

async function rotationView(target, ctx) {
  const { pending_rotation: items } = await rpc("rotation.list");
  mount(target, h("div", { class: "page" },
    h("p", "These secrets could be read by someone who has since lost access. Change each one at its source – a new certificate, a new database password – store the new value, then mark it rotated."),
    items.length ? h("ul", { class: "checklist" }, items.map((it) => {
      const btn = h("button", { class: "small", disabled: it.path === "(no access)", onClick: () => busy(btn, async () => {
        await ctx.write("rotation.done", { path: it.path }, "Marked as rotated.");
        ctx.show("rotation");
      }) }, "Mark rotated");
      return h("li", h("span", { class: "mono" }, it.path === "(no access)" ? `Secret ${it.node.slice(0, 8)} (no access)` : it.path), btn);
    })) : h("div", { class: "empty" }, h("p", "Nothing to rotate."))));
}

// ------------------------------------------------------------------ Activity (audit log)

async function activityView(target) {
  const log = await rpc("vault.log", { limit: 300 });
  mount(target, h("div", { class: "page" },
    h("p", { class: "muted" }, `Signed changes since checkpoint #${log.checkpoint_seq}. Reads are not recorded – they happen offline.`),
    h("div", { class: "panel" }, h("table",
      h("thead", h("tr", h("th", "#"), h("th", "When"), h("th", "Who"), h("th", "What"), h("th", "Where"))),
      h("tbody", log.commits.map((c) => h("tr",
        h("td", c.seq), h("td", when(c.time)), h("td", c.author),
        h("td", c.operations.join(", ")), h("td", { class: "mono" }, c.paths.join(", ")))))))));
}

// ------------------------------------------------------------------ Run (exec profiles)

async function runView(target, ctx) {
  const { profiles } = await rpc("exec.profiles");
  if (!profiles.length) {
    mount(target, h("div", { class: "page" }, h("div", { class: "empty" },
      h("h3", "No profiles"),
      h("p", "Profiles come from the .nepomuk.toml of a project. Open the project folder instead of the vault file to run a local release build."))));
    return;
  }
  const profile = h("select", profiles.map((p) => h("option", { value: p.name }, p.name)));
  const command = h("input", { class: "mono", value: settings.get(`cmd.${ctx.state.conn?.project}`, "./gradlew bundleRelease") });
  const info = h("p", { class: "muted" });
  const out = h("div");
  const describe = () => {
    const p = profiles.find((x) => x.name === profile.value);
    info.textContent = `Provides ${[...p.env.map((e) => `$${e}`), ...p.files.map((f) => `$${f} (file)`)].join(", ")}. Values are masked in the output.`;
  };
  profile.addEventListener("change", describe);
  describe();
  const run = h("button", { class: "primary", type: "submit" }, "Run");
  mount(target, h("div", { class: "page" },
    h("form", { onSubmit: (ev) => {
      ev.preventDefault();
      settings.set(`cmd.${ctx.state.conn?.project}`, command.value);
      busy(run, async () => {
        mount(out, h("div", { class: "spinner" }));
        const r = await rpc("exec.run", { profile: profile.value, command: splitArgs(command.value) }).catch((e) => { mount(out); throw e; });
        mount(out, h("div", { class: "stack" },
          h("p", h("strong", r.exit_code === 0 ? "Finished" : `Exited with code ${r.exit_code}`)),
          h("pre", { class: "output" }, r.stdout + (r.stderr ? `\n${r.stderr}` : ""))));
      });
    } }, h("label", "Profile", profile), info, h("label", "Command", command), h("div", { class: "actions" }, run)),
    out));
}

// ------------------------------------------------------------------ Vault

async function vaultView(target, ctx) {
  const [info, me, touch] = await Promise.all([rpc("vault.info"), rpc("whoami"), rpc("touchid.status").catch(() => ({ available: false }))]);
  const touchCard = touch.available ? h("div", { class: "card" },
    h("h3", "Touch ID"),
    touch.enabled
      ? h("p", "This Mac unlocks the vault with your fingerprint. Your password is sealed by the Secure Enclave and opens only after Touch ID with the fingers enrolled now.")
      : h("p", "Off. To turn it on, lock the vault and tick “Use Touch ID to unlock on this Mac” when you unlock with your password."),
    touch.enabled ? h("div", { class: "actions" }, h("button", { class: "danger", onClick: async (ev) => {
      const r = await busy(ev.currentTarget, () => rpc("touchid.disable"));
      if (r) { toast("Touch ID turned off for this vault."); ctx.show("vault"); }
    } }, "Turn off Touch ID")) : null) : null;
  const verify = h("button", { onClick: () => busy(verify, async () => {
    const r = await rpc("vault.verify");
    toast(`Verified: every signature and permission up to #${r.seq} is valid.`);
  }) }, "Verify the whole log");
  const clip = h("input", { type: "number", min: 5, max: 600, value: settings.get("clipboardSeconds", 30) });
  const idle = h("input", { type: "number", min: 1, max: 120, value: settings.get("idleMinutes", 10) });
  const saveSettings = h("button", { type: "submit" }, "Save settings");
  mount(target, h("div", { class: "page" },
    h("div", { class: "card" },
      h("h3", "Master"),
      h("p", `${info.master} holds every right. Every client pins this fingerprint.`),
      fingerprint(info.master_fingerprint, 88),
      h("div", { class: "actions" }, verify, h("button", { onClick: () => invoke("copy_plain", { text: info.master_fingerprint }).then(() => toast("Fingerprint copied.")) }, "Copy fingerprint"))),
    h("div", { class: "card" },
      h("h3", "You"),
      h("p", `${me.name}, ${me.kind === "password" ? "password identity" : "identity file"}${me.master ? ", master" : ""}.`),
      fingerprint(me.fingerprint, 64),
      me.groups.length ? h("p", "Groups: ", me.groups.map((g) => h("span", { class: "tag" }, g))) : null,
      me.system_rights.length ? h("p", "System rights: ", me.system_rights.map((r) => h("span", { class: "tag brass" }, r.right + (r.delegate ? "+delegate" : "")))) : null),
    h("div", { class: "card" },
      h("h3", "This vault"),
      h("table", h("tbody",
        [["File", info.vault], ["Version", `#${info.seq}`], ["Users", `${info.users} active, ${info.disabled_users} disabled`], ["Groups", info.groups],
         ["Items", info.nodes], ["Grants", info.grants], ["Size", bytes(info.size)], ["Crypto", info.suite], ["Git", info.git ? "pushes on every change" : "local file"]]
          .map(([k, v]) => h("tr", h("th", k), h("td", { class: k === "File" ? "mono" : null }, String(v))))))),
    touchCard,
    h("form", { class: "card", onSubmit: (ev) => {
      ev.preventDefault();
      settings.set("clipboardSeconds", Math.max(5, Number(clip.value) || 30));
      settings.set("idleMinutes", Math.max(1, Number(idle.value) || 10));
      toast("Settings saved.");
    } },
      h("h3", "Settings on this computer"),
      h("div", { class: "field-row" }, h("label", "Clear copied secrets after (seconds)", clip), h("label", "Lock after inactivity (minutes)", idle)),
      h("div", { class: "actions" }, saveSettings)),
    h("div", { class: "actions" }, h("button", { onClick: () => import("./app.js").then((m) => m.switchVault()) }, "Open a different vault"),
      h("button", { class: "quiet", onClick: async () => { await invoke("disconnect"); location.reload(); } }, "Close this vault"))));
}

export const views = {
  secrets: secretsView,
  users: usersView,
  groups: groupsView,
  rotation: rotationView,
  activity: activityView,
  run: runView,
  vault: vaultView,
};

export { basename };
