"use strict";
// CleanGuard web app. No dependencies. File names and model text are untrusted:
// everything is written with textContent, never as HTML.

const TOKEN = document.querySelector('meta[name="cg-token"]').content;
const $ = (id) => document.getElementById(id);

const GROUPS = {
  deletable: { name: "Deletable", help: "There is evidence these are no longer needed: installers, exact duplicates, unfinished downloads." },
  review: { name: "Review", help: "CleanGuard is not sure. Read the reason and decide for yourself." },
  sensitive: { name: "Sensitive", help: "Probably personal documents. They stay put unless you tick one, and moving one needs an extra confirmation." },
  keep: { name: "Keep", help: "Probably still needed: recent, protected or useful files. These cannot be moved from here." },
};
const COLUMNS = [
  { key: "name", label: "Name", sortable: true },
  { key: "size_bytes", label: "Size", sortable: true, num: true },
  { key: "age_days", label: "Age", sortable: true, num: true, cls: "col-age" },
  { key: "reason", label: "Reason" },
];
const CHIPS_WITH_RUN = ["What can I safely remove?", "Which files look private?", "Why are some files marked review?"];
const CHIPS_NO_RUN = ["What does CleanGuard do?", "Is my data sent anywhere?"];

const state = {
  view: "files", status: null, runs: [], runId: null, run: null, tab: "deletable", filter: "",
  sort: { key: "size_bytes", dir: -1 }, selected: new Set(), lastMove: null, pollTimer: null,
  chatBusy: false, browsePath: null,
};

// ---------------------------------------------------------------- helpers
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
    else if (k === "text") node.textContent = v;
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: { "X-CleanGuard-Token": TOKEN } };
  if (init.method === "POST") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body || {});
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw Object.assign(new Error("CleanGuard is not responding. Is it still running in the terminal?"), { kind: "offline" });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || "Something went wrong."), { status: res.status, kind: data.kind });
  return data;
}

let toastTimer;
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
}

function setError(node, message) {
  node.textContent = message || "";
  node.hidden = !message;
}

function formatWhen(iso) {
  if (!iso) return "now";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function baseName(path) {
  const parts = String(path).replace(/[\\/]+$/, "").split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function humanSize(bytes) {                 // same units as the server (schemas.human_size)
  if (bytes < 1e3) return `${bytes} B`;
  if (bytes < 1e6) return `${(bytes / 1e3).toFixed(1)} KB`;
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${(bytes / 1e9).toFixed(1)} GB`;
}

// ---------------------------------------------------------------- status
async function refreshStatus() {
  try {
    state.status = await api("/api/status");
  } catch (e) {
    state.status = null;
    $("status-model").textContent = "App not responding";
    $("status-model").className = "pill bad";
    return;
  }
  const s = state.status;
  const offline = $("status-offline");
  const isOffline = s.offline_line.startsWith("Offline");
  offline.textContent = isOffline ? "Offline, this computer only" : "Model is not on this computer";
  offline.title = s.offline_line;
  offline.className = isOffline ? "pill ok" : "pill bad";
  const model = $("status-model");
  if (!s.model_reachable) {
    model.textContent = "Model not running";
    model.title = "Open the Ollama app.";
    model.className = "pill bad";
  } else if (s.models_missing.length) {
    model.textContent = "Model not installed";
    model.title = `Run: ollama pull ${s.models_missing.join(" and ")}`;
    model.className = "pill bad";
  } else {
    model.textContent = `Model ready: ${s.models.join(", ")}`;
    model.title = "";
    model.className = "pill ok";
  }
}

// ---------------------------------------------------------------- runs list
async function refreshRuns() {
  const { runs } = await api("/api/runs");
  state.runs = runs;
  renderRuns();
}

function stateText(r) {
  if (r.active) return "Scanning";
  if (r.state === "FAILED") return "Stopped";
  if (r.state === "APPROVE") return `${r.deletable} deletable of ${r.files}`;
  if (r.dry_run) return `Dry run, ${r.files} files`;
  if (r.state === "DONE") return `Finished, ${r.files} files`;
  return r.state;
}

function renderRuns() {
  const list = $("run-list");
  list.replaceChildren();
  if (!state.runs.length) {
    list.append(el("li", { class: "run-empty", text: "No scans yet." }));
    return;
  }
  for (const r of state.runs) {
    list.append(el("li", {},
      el("button", {
        class: "run-item", "aria-current": r.run_id === state.runId ? "true" : "false", title: r.root,
        on: { click: () => openRun(r.run_id) },
      },
      el("span", { class: "run-name", text: baseName(r.root) }),
      el("span", { class: "run-sub", text: `${stateText(r)} · ${formatWhen(r.created_at)}` }))));
  }
}

// ---------------------------------------------------------------- open a run
async function openRun(runId) {
  if (runId !== state.runId) {
    state.selected.clear();
    state.lastMove = null;
    state.filter = "";
    $("filter").value = "";
  }
  state.runId = runId;
  setView("files");
  await loadRun();
  renderRuns();
  renderChips();
}

async function loadRun() {
  clearTimeout(state.pollTimer);
  if (!state.runId) return;
  const wasActive = state.run && state.run.run_id === state.runId && state.run.active;
  try {
    state.run = await api(`/api/runs/${state.runId}`);
  } catch (e) {
    toast(e.message);
    return;
  }
  // start on the first group that has anything in it
  if (state.run.summary && (wasActive || !GROUPS[state.tab] || !state.run.summary[state.tab])) {
    state.tab = ["deletable", "review", "sensitive", "keep"].find((g) => state.run.summary[g]) || "deletable";
  }
  renderRun();
  if (state.run.active) {
    state.pollTimer = setTimeout(loadRun, 1000);
  } else if (wasActive) {
    await Promise.all([refreshRuns(), refreshStatus()]);
  }
}

function renderRun() {
  const run = state.run;
  $("empty").hidden = !!run;
  $("run").hidden = !run;
  if (!run) { renderSelectionBar(); return; }
  $("run-folder").textContent = baseName(run.root);
  $("run-folder").title = run.root;
  $("run-meta").textContent = `${run.root} · run ${run.run_id}`;
  $("run-rescan").hidden = run.active || run.state === "SCAN";
  renderNotices(run);
  renderProgress(run);
  const hasResults = !!run.summary && !run.active && run.state !== "FAILED";
  $("results").hidden = !hasResults;
  if (hasResults) { renderTabs(run); renderFiles(run); }
  renderSelectionBar();
}

function renderProgress(run) {
  const box = $("progress");
  box.hidden = !run.active;
  if (!run.active) return;
  const lines = run.progress.slice(-5);
  box.replaceChildren(el("ul", {}, ...lines.map((text, i) =>
    el("li", {}, i === lines.length - 1 ? el("span", { class: "spinner", "aria-hidden": "true" }) : null, text))));
}

function renderNotices(run) {
  const box = $("notices");
  box.replaceChildren();
  if (state.lastMove) box.append(moveNotice(state.lastMove));
  if (run.job_error) box.append(el("div", { class: "note note-warn", text: run.job_error }));
  if (run.state === "FAILED" && !run.active) {
    const isModel = run.error === "LLMConnectionError" || run.error === "ModelNotFoundError";
    const missing = (state.status && state.status.models_missing) || [];
    const text = run.error === "ModelNotFoundError"
      ? "The scan stopped because the model it needs is not installed. Nothing was moved. Install it in a terminal, then continue:"
      : isModel
        ? "The scan stopped because CleanGuard could not connect to the local model. Nothing was moved, and the files checked so far are saved. Start Ollama (the Ollama app, or `ollama serve` in a terminal), then continue."
        : `The scan stopped: ${run.error}. Nothing was moved.`;
    const note = el("div", { class: "note note-warn" }, el("p", { text }));
    if (run.error === "ModelNotFoundError" && missing.length) {
      note.append(el("pre", { class: "preview", text: missing.map((m) => `ollama pull ${m}`).join("\n") }));
    }
    if (run.can_resume && run.failed_from !== "SCAN") {
      note.append(el("button", { class: "btn btn-primary", text: "Continue scan", on: { click: resumeRun } }));
    }
    box.append(note);
  } else if (run.dry_run && !run.active) {
    box.append(el("div", { class: "note", text: "Dry run: this is a report only, so nothing can be moved. Scan again without dry run to move files." }));
  } else if (run.state === "DONE" && !state.lastMove && !run.active) {
    box.append(el("div", { class: "note", text: "This scan is finished, so no more files can be moved from it. Scan again to clean up the rest." }));
  }
}

function moveNotice(m) {
  const note = el("div", { class: m.status === "rolled_back" ? "note note-warn" : "note note-ok" });
  if (m.status === "rolled_back") {
    note.append(el("p", { text: "An error occurred, so every file was put back. Nothing moved." }));
    return note;
  }
  note.append(el("p", {}, el("strong", { text: `Moved ${m.moved} file${m.moved === 1 ? "" : "s"} (${m.size}) to quarantine.` }), " Nothing was deleted."));
  for (const s of m.skipped) {
    note.append(el("p", { text: `Not moved: ${s.name} (${s.why}). It is still in its folder.` }));
  }
  if (m.moved) note.append(el("button", { class: "btn", text: "Undo this move", on: { click: () => restoreBatch(m.batch_id) } }));
  note.append(el("button", { class: "btn", text: "Scan again", on: { click: rescan } }));
  return note;
}

// ---------------------------------------------------------------- tabs and files
function renderTabs(run) {
  const tabs = $("tabs");
  tabs.replaceChildren();
  for (const [key, g] of Object.entries(GROUPS)) {
    tabs.append(el("button", {
      class: `tab g-${key}`, role: "tab", "aria-selected": state.tab === key ? "true" : "false",
      on: { click: () => { state.tab = key; renderTabs(run); renderFiles(run); } },
    },
    el("span", { class: "tab-name", text: g.name }),
    el("span", { class: "tab-count", text: String(run.summary[key]) }),
    el("span", { class: "tab-size", text: run.summary.sizes[key] })));
  }
  $("tab-help").textContent = GROUPS[state.tab].help;
}

function currentRows(run) {
  const q = state.filter.trim().toLowerCase();
  const rows = run.files.filter((f) => f.group === state.tab && (!q || f.rel_path.toLowerCase().includes(q)));
  const { key, dir } = state.sort;
  rows.sort((a, b) => (typeof a[key] === "string" ? a[key].localeCompare(b[key]) : a[key] - b[key]) * dir);
  return rows;
}

function canSelect(f) {
  return state.run.can_move && f.selectable && !f.batch_id;
}

function renderHead(run) {
  const head = $("file-head");
  head.replaceChildren();
  if (run.can_move) head.append(el("th", { class: "col-check", scope: "col" }, el("span", { class: "sr-only", text: "Select" })));
  for (const c of COLUMNS) {
    const cls = [c.num ? "num" : "", c.cls || "", c.sortable ? "sortable" : ""].join(" ").trim();
    if (!c.sortable) { head.append(el("th", { scope: "col", class: cls, text: c.label })); continue; }
    const active = state.sort.key === c.key;
    head.append(el("th", {
      scope: "col", class: cls, "aria-sort": active ? (state.sort.dir > 0 ? "ascending" : "descending") : "none",
    }, el("button", {
      class: "sort-btn",
      text: c.label + (active ? (state.sort.dir > 0 ? " ▲" : " ▼") : ""),
      on: { click: () => {
        state.sort = { key: c.key, dir: active ? -state.sort.dir : (c.key === "name" ? 1 : -1) };
        renderFiles(run);
      } },
    })));
  }
}

function fileRow(f, run) {
  const nameCell = el("td", {},
    el("button", { class: "file-link", text: f.name, on: { click: () => openFile(f) } }));
  if (f.sensitive && f.group !== "sensitive") nameCell.append(el("span", { class: "chip g-sensitive", text: "sensitive" }));
  if (f.group === "sensitive") nameCell.append(el("span", { class: "chip g-sensitive", text: f.sensitive_type }));
  if (f.batch_id) nameCell.append(el("span", { class: "chip", text: "in quarantine" }));
  if (f.folder) nameCell.append(el("span", { class: "file-folder", text: f.folder + "/" }));
  const row = el("tr", {});
  if (run.can_move) {
    const cell = el("td", { class: "col-check" });
    if (canSelect(f)) {
      cell.append(el("input", {
        type: "checkbox", "aria-label": `Select ${f.name}`, checked: state.selected.has(f.file_id),
        on: { change: (e) => {
          if (e.target.checked) state.selected.add(f.file_id); else state.selected.delete(f.file_id);
          renderSelectionBar();
        } },
      }));
    }
    row.append(cell);
  }
  row.append(nameCell,
    el("td", { class: "num", text: f.size }),
    el("td", { class: "num col-age", text: `${f.age_days} d` }),
    el("td", { class: "reason", text: f.reason }));
  return row;
}

function renderFiles(run) {
  renderHead(run);
  const rows = currentRows(run);
  $("file-rows").replaceChildren(...rows.map((f) => fileRow(f, run)));
  $("no-rows").hidden = rows.length > 0;
  // Sensitive files are never selected in bulk, and Keep files cannot be selected at all.
  const selectAll = $("select-all");
  const pickable = rows.filter(canSelect);
  const show = run.can_move && (state.tab === "deletable" || state.tab === "review") && pickable.length > 0;
  selectAll.hidden = !show;
  if (show) {
    const allOn = pickable.every((f) => state.selected.has(f.file_id));
    selectAll.textContent = allOn ? `Clear these ${pickable.length}` : `Select these ${pickable.length}`;
  }
}

function selectedFiles() {
  if (!state.run) return [];
  return state.run.files.filter((f) => state.selected.has(f.file_id));
}

function renderSelectionBar() {
  const files = state.view === "files" ? selectedFiles() : [];
  const bar = $("selection-bar");
  bar.hidden = files.length === 0;
  if (!files.length) return;
  const bytes = files.reduce((a, f) => a + f.size_bytes, 0);
  const sensitive = files.filter((f) => f.sensitive).length;
  $("selection-text").textContent = `${files.length} file${files.length === 1 ? "" : "s"} selected, ${humanSize(bytes)}`
    + (sensitive ? ` (${sensitive} sensitive)` : "");
}

// ---------------------------------------------------------------- scanning
async function startScan(folder, dryRun) {
  setError($("scan-error"), "");
  $("scan-go").disabled = true;
  try {
    const { run_id } = await api("/api/scan", { method: "POST", body: { folder, dry_run: dryRun } });
    state.tab = "deletable";
    await refreshRuns();
    await openRun(run_id);
    state.selected.clear();
    await refreshRuns();
  } catch (e) {
    setError($("scan-error"), e.message);
    setView("files");
  } finally {
    $("scan-go").disabled = false;
  }
}

function rescan() {
  if (!state.run) return;
  startScan(state.run.root, false);
}

async function resumeRun() {
  try {
    await api(`/api/runs/${state.runId}/resume`, { method: "POST" });
    await loadRun();
    await refreshRuns();
  } catch (e) {
    toast(e.message);
  }
}

// ---------------------------------------------------------------- browse dialog
async function openBrowse(path) {
  try {
    const data = await api(`/api/browse${path ? `?path=${encodeURIComponent(path)}` : ""}`);
    state.browsePath = data.path;
    $("browse-path").textContent = data.path;
    const refused = $("browse-refused");
    refused.hidden = !data.refused;
    refused.textContent = data.refused ? `CleanGuard will not scan this folder: ${data.refused}.` : "";
    $("browse-use").disabled = !!data.refused;
    const list = $("browse-list");
    list.replaceChildren();
    if (data.parent) {
      list.append(el("li", {}, el("button", { class: "browse-item", on: { click: () => openBrowse(data.parent) } }, el("span", { text: "↑ Up one folder" }))));
    }
    for (const f of data.folders) {
      list.append(el("li", {}, el("button", { class: "browse-item", on: { click: () => openBrowse(f.path) } },
        el("span", { text: f.name }),
        f.refused ? el("span", { class: "browse-refused", text: "will not scan" }) : null)));
    }
    if (!data.folders.length) list.append(el("li", { class: "muted no-rows", text: "No subfolders." }));
    const shortcuts = $("browse-shortcuts");
    shortcuts.replaceChildren(...((state.status && state.status.shortcuts) || []).map((s) =>
      el("button", { class: "chip-btn", text: s.name, on: { click: () => openBrowse(s.path) } })));
    if (!$("dlg-browse").open) $("dlg-browse").showModal();
  } catch (e) {
    if ($("dlg-browse").open) toast(e.message); else setError($("scan-error"), e.message);
  }
}

// ---------------------------------------------------------------- move dialog
function moveRow(f) {
  return el("li", {}, el("span", { text: f.rel_path }), el("span", { class: "num", text: f.size }));
}

function openMove() {
  const files = selectedFiles();
  if (!files.length) return;
  const normal = files.filter((f) => !f.sensitive);
  const sensitive = files.filter((f) => f.sensitive);
  const bytes = files.reduce((a, f) => a + f.size_bytes, 0);
  $("move-title").textContent = `Move ${files.length} file${files.length === 1 ? "" : "s"} (${humanSize(bytes)}) to quarantine?`;
  $("move-list").replaceChildren(...normal.map(moveRow));
  $("move-list").hidden = !normal.length;
  $("move-sensitive").hidden = !sensitive.length;
  $("move-sensitive-title").textContent = `Warning: ${sensitive.length} sensitive file${sensitive.length === 1 ? "" : "s"}`;
  $("move-sensitive-list").replaceChildren(...sensitive.map(moveRow));
  $("move-sensitive-input").value = "";
  $("move-input").value = "";
  setError($("move-error"), "");
  updateMoveButton();
  $("dlg-move").showModal();
  (sensitive.length ? $("move-sensitive-input") : $("move-input")).focus();
}

function updateMoveButton() {
  const needSensitive = !$("move-sensitive").hidden;
  const ok = $("move-input").value.trim() === "MOVE"
    && (!needSensitive || $("move-sensitive-input").value.trim() === "SENSITIVE");
  $("move-go").disabled = !ok;
}

async function doMove() {
  const go = $("move-go");
  go.disabled = true;
  go.textContent = "Moving ...";
  try {
    const result = await api(`/api/runs/${state.runId}/move`, {
      method: "POST",
      body: {
        file_ids: [...state.selected], confirm: $("move-input").value.trim(),
        sensitive_confirm: $("move-sensitive-input").value.trim(),
      },
    });
    state.lastMove = result;
    state.selected.clear();
    $("dlg-move").close();
    await Promise.all([loadRun(), refreshRuns()]);
    document.querySelector(".main").scrollTop = 0;
  } catch (e) {
    setError($("move-error"), e.message);
  } finally {
    go.textContent = "Move files";
    updateMoveButton();
  }
}

// ---------------------------------------------------------------- one file
let openFileId = null;
async function openFile(f) {
  openFileId = f.file_id;
  $("file-title").textContent = f.name;
  const badges = [el("span", { class: `chip g-${f.group}`, text: GROUPS[f.group].name })];
  if (f.sensitive) badges.push(el("span", { class: "chip g-sensitive", text: `sensitive: ${f.sensitive_type}` }));
  if (f.batch_id) badges.push(el("span", { class: "chip", text: "in quarantine" }));
  $("file-badges").replaceChildren(...badges);
  const facts = [["Location", f.rel_path], ["Size", f.size], ["Last changed", `${f.age_days} days ago`], ["Decided by", decidedBy(f.decided_by)]];
  $("file-facts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));
  $("file-reason").textContent = f.reason;
  setError($("file-error"), "");
  $("file-preview").hidden = true;
  $("file-preview-note").textContent = "Loading ...";
  $("dlg-file").showModal();
  try {
    const p = await api(`/api/runs/${state.runId}/files/${f.file_id}/preview`);
    if (openFileId !== f.file_id) return;
    $("file-preview-note").textContent = p.note;
    if (p.text != null) {
      $("file-preview").textContent = p.text;
      $("file-preview").hidden = false;
    }
  } catch (e) {
    if (openFileId === f.file_id) $("file-preview-note").textContent = e.message;
  }
}

function decidedBy(by) {
  return { rule: "A fixed rule", llm_fast: "The local model", llm_reasoning: "The local model (second look)",
    fallback: "Safe default: the model gave no valid answer", invariant: "A safety rule",
    evidence: "The evidence rule (no proof it is unneeded)" }[by] || by;
}

async function revealFile() {
  try {
    await api(`/api/runs/${state.runId}/files/${openFileId}/reveal`, { method: "POST" });
  } catch (e) {
    setError($("file-error"), e.message);
  }
}

// ---------------------------------------------------------------- quarantine
async function loadQuarantine() {
  try {
    renderQuarantine(await api("/api/quarantine"));
  } catch (e) {
    toast(e.message);
  }
}

function batchStatus(b) {
  if (b.can_restore) return `${b.files} file${b.files === 1 ? "" : "s"}, ${b.size}`;
  return b.status === "rolled_back" ? "Put back after an error" : "Restored";
}

function renderQuarantine(q) {
  $("q-meta").textContent = `${q.total} held in ${q.dir}`;
  const box = $("q-batches");
  box.replaceChildren();
  if (!q.batches.length) {
    box.append(el("p", { class: "muted", text: "Nothing has been moved yet." }));
    return;
  }
  for (const b of q.batches) {
    const head = el("div", { class: "batch-head" },
      el("div", {},
        el("div", { class: "batch-id", text: `${formatWhen(b.created_at)} · ${batchStatus(b)}` }),
        el("div", { class: "batch-sub", text: b.batch_id })),
      b.can_restore ? el("button", { class: "btn", text: "Restore all", on: { click: () => restoreBatch(b.batch_id) } }) : null);
    const files = el("ul", { class: "batch-files" }, ...b.entries.map((e) =>
      el("li", {},
        el("span", {}, e.name, el("span", { class: "where", text: e.status === "moved" ? `from ${e.original_path}` : `${e.status}: ${e.restored_to || e.original_path}` })),
        el("span", { class: "num", text: e.size }))));
    box.append(el("div", { class: "batch" }, head, files));
  }
}

async function restoreBatch(batchId) {
  try {
    const r = await api(`/api/quarantine/${batchId}/restore`, { method: "POST" });
    let text = r.restored === 1 ? "Restored 1 file to its folder." : `Restored ${r.restored} files to their folders.`;
    if (r.renamed) text += ` ${r.renamed} renamed because the name was taken.`;
    if (r.missing) text += ` ${r.missing} missing from quarantine.`;
    toast(text);
    state.lastMove = null;
    await Promise.all([loadQuarantine(), state.runId ? loadRun() : null, refreshRuns()]);
  } catch (e) {
    toast(e.message);
  }
}

// ---------------------------------------------------------------- views
function setView(view) {
  state.view = view;
  $("view-files").hidden = view !== "files";
  $("view-quarantine").hidden = view !== "quarantine";
  $("nav-files").toggleAttribute("aria-current", false);
  $("nav-quarantine").toggleAttribute("aria-current", false);
  $(view === "files" ? "nav-files" : "nav-quarantine").setAttribute("aria-current", "page");
  if (view === "quarantine") loadQuarantine();
  renderSelectionBar();
}

// ---------------------------------------------------------------- chat
function addMessage(kind, text) {
  const m = el("div", { class: `msg msg-${kind}`, text });
  $("chat-log").append(m);
  $("chat-log").scrollTop = $("chat-log").scrollHeight;
  return m;
}

function renderChips() {
  const chips = $("chat-chips");
  const list = state.runId ? CHIPS_WITH_RUN : CHIPS_NO_RUN;
  chips.replaceChildren(...list.map((text) =>
    el("button", { class: "chip-btn", type: "button", text, on: { click: () => sendChat(text) } })));
}

function actionButtons(actions) {
  const box = el("div", { class: "msg-actions" });
  for (const a of actions) {
    if (a.type === "select") {
      const known = state.run ? state.run.files.filter((f) => a.file_ids.includes(f.file_id) && canSelect(f)) : [];
      if (!known.length) continue;
      box.append(el("button", {
        class: "btn btn-small", text: `Select ${known.length} suggested file${known.length === 1 ? "" : "s"}`,
        on: { click: () => {
          known.forEach((f) => state.selected.add(f.file_id));
          state.tab = known[0].group;
          setView("files");
          renderRun();
          toast("Selected. Nothing moves until you confirm.");
        } },
      }));
    } else if (a.type === "scan") {
      box.append(el("button", {
        class: "btn btn-small", text: `Scan ${baseName(a.folder)}`,
        on: { click: () => startScan(a.folder, false) },
      }));
    }
  }
  return box.childElementCount ? box : null;
}

async function sendChat(text) {
  const message = (text ?? $("chat-input").value).trim();
  if (!message || state.chatBusy) return;
  $("chat-input").value = "";
  state.chatBusy = true;
  $("chat-send").disabled = true;
  addMessage("user", message);
  const pending = addMessage("bot", "Thinking ...");
  try {
    const res = await api("/api/chat", { method: "POST", body: { message, run_id: state.runId } });
    pending.textContent = res.reply;
    const buttons = actionButtons(res.actions);
    if (buttons) pending.append(buttons);
  } catch (e) {
    pending.className = "msg msg-error";
    pending.textContent = e.message;
    if (e.kind === "model_down") refreshStatus();
  } finally {
    state.chatBusy = false;
    $("chat-send").disabled = false;
    $("chat-log").scrollTop = $("chat-log").scrollHeight;
  }
}

// ---------------------------------------------------------------- wiring
function wire() {
  $("nav-files").addEventListener("click", () => setView("files"));
  $("nav-quarantine").addEventListener("click", () => setView("quarantine"));
  $("scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    startScan($("scan-folder").value, $("scan-dry").checked);
  });
  $("scan-browse").addEventListener("click", () => openBrowse($("scan-folder").value.trim() || null));
  $("browse-cancel").addEventListener("click", () => $("dlg-browse").close());
  $("browse-use").addEventListener("click", () => {
    $("scan-folder").value = state.browsePath;
    setError($("scan-error"), "");
    $("dlg-browse").close();
  });
  $("run-rescan").addEventListener("click", rescan);
  $("filter").addEventListener("input", (e) => {
    state.filter = e.target.value;
    if (state.run) renderFiles(state.run);
  });
  $("select-all").addEventListener("click", () => {
    const pickable = currentRows(state.run).filter(canSelect);
    const allOn = pickable.every((f) => state.selected.has(f.file_id));
    pickable.forEach((f) => (allOn ? state.selected.delete(f.file_id) : state.selected.add(f.file_id)));
    renderFiles(state.run);
    renderSelectionBar();
  });
  $("selection-clear").addEventListener("click", () => {
    state.selected.clear();
    if (state.run) renderFiles(state.run);
    renderSelectionBar();
  });
  $("selection-move").addEventListener("click", openMove);
  $("move-cancel").addEventListener("click", () => $("dlg-move").close());
  $("move-input").addEventListener("input", updateMoveButton);
  $("move-sensitive-input").addEventListener("input", updateMoveButton);
  $("move-go").addEventListener("click", doMove);
  $("file-close").addEventListener("click", () => $("dlg-file").close());
  $("file-reveal").addEventListener("click", revealFile);
  $("chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendChat(); });
  $("chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendChat(); }
  });
  $("chat-reset").addEventListener("click", async () => {
    await api("/api/chat/reset", { method: "POST", body: { run_id: state.runId } }).catch(() => {});
    $("chat-log").replaceChildren();
    toast("Started a new chat.");
  });
}

async function start() {
  wire();
  renderChips();
  await refreshStatus();
  try {
    await refreshRuns();
    const active = state.runs.find((r) => r.active);
    if (active) await openRun(active.run_id);
  } catch (e) {
    toast(e.message);
  }
  setInterval(refreshStatus, 15000);
}

start();
