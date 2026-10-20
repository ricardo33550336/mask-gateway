/* 脱敏网关 - 管理界面逻辑（原生 JS，无依赖、无构建） */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let rules = [];
let detectors = [];
let currentTest = null; // 测试弹窗当前使用的规则（来自表单或列表）

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// 诊断接口需要 token（启动时 -admin-token / ADMIN_TOKEN）。token 只放在
// sessionStorage，关闭标签页即失效；不写 localStorage、不写 cookie。
const adminToken = () => sessionStorage.getItem("adminToken") || "";

// 401/403 对使用者来说几乎总是“没填 token”或“网关没开管理接口”，直接翻译成可操作的提示。
const authHint = (msg) => {
  if (/unauthorized/i.test(msg))
    return "需要 token：在页面顶部填入 -admin-token / ADMIN_TOKEN 的值，点「保存 token」后再试";
  if (/disabled/i.test(msg))
    return "网关未启用管理接口：启动时加 -admin-token（或 ADMIN_TOKEN 环境变量）后重启";
  return msg;
};

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  const token = adminToken();
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch("/api" + path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function hint(msg, ok = true) {
  const el = $("#hint");
  el.textContent = msg;
  el.style.color = ok ? "var(--green)" : "var(--red)";
  setTimeout(() => (el.textContent = ""), 3000);
}

const ruleType = (r) => (r.type === "detector" || (!r.type && r.detector) ? "detector" : "regex");

/* ---------------- 列表 ---------------- */

async function load() {
  [rules, detectors] = await Promise.all([api("/rules"), api("/detectors")]);
  // 检测器清单是异步拿到的，必须在拿到之后重建下拉框，否则 <select> 永远是空的。
  fillDetectorOptions();
  render();
}

function matchLabel(r) {
  if (ruleType(r) === "detector") {
    const extra =
      r.detector === "high_entropy"
        ? ` <span class="muted">阈值 ${r.threshold || 4.0} / 长度 ${r.minLength || 20}</span>`
        : "";
    return `<span class="badge detector">${esc(r.detector)}</span>${extra}`;
  }
  return `<code>${esc(r.pattern)}</code>`;
}

function render() {
  const tbody = $("#rules-table tbody");
  tbody.innerHTML = "";
  $("#empty").classList.toggle("hidden", rules.length > 0);

  rules
    .slice()
    .sort((a, b) => a.id - b.id)
    .forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${esc(r.name)}</strong>${
          r.description ? `<div class="desc">${esc(r.description)}</div>` : ""
        }</td>
        <td>${matchLabel(r)}</td>
        <td><span class="badge ${r.action}">${esc(r.action)}</span></td>
        <td>${
          r.action === "mask" ? esc(r.replacement) : '<span class="muted">—</span>'
        }</td>
        <td>${
          r.fields && r.fields.length
            ? r.fields.map((f) => `<code>${esc(f)}</code>`).join(" ")
            : '<span class="muted">全部</span>'
        }</td>
        <td>${
          r.scopes && r.scopes.length
            ? r.scopes.map(esc).join(", ")
            : '<span class="muted">全部</span>'
        }</td>
        <td>
          <label class="switch">
            <input type="checkbox" data-id="${r.id}" ${r.enabled ? "checked" : ""}>
            <span></span>
          </label>
        </td>
        <td class="row-actions">
          <button class="btn small" data-act="edit" data-id="${r.id}">编辑</button>
          <button class="btn small" data-act="test" data-id="${r.id}">测试</button>
          <button class="btn small danger" data-act="del" data-id="${r.id}">删除</button>
        </td>`;
      tbody.appendChild(tr);
    });
}

/* ---------------- 新建 / 编辑 ---------------- */

function fillDetectorOptions() {
  const sel = $("#f-detector");
  const prev = sel.value; // load() 期间表单可能开着，保留用户已选的值
  sel.innerHTML = detectors
    .map((d) => `<option value="${esc(d.name)}">${esc(d.name)} — ${esc(d.description)}</option>`)
    .join("");
  if (prev && detectors.some((d) => d.name === prev)) sel.value = prev;
}

function openForm(rule) {
  $("#modal-title").textContent = rule ? "编辑规则 #" + rule.id : "新建规则";
  $("#f-id").value = rule ? rule.id : "";
  $("#f-name").value = rule ? rule.name : "";
  $("#f-desc").value = rule ? rule.description || "" : "";
  $("#f-type").value = rule ? ruleType(rule) : "regex";
  $("#f-pattern").value = rule && ruleType(rule) === "regex" ? rule.pattern : "";
  $("#f-detector").value = rule && rule.detector ? rule.detector : detectors[0]?.name || "";
  $("#f-threshold").value = rule && rule.threshold ? rule.threshold : "";
  $("#f-minlength").value = rule && rule.minLength ? rule.minLength : "";
  $("#f-action").value = rule ? rule.action : "mask";
  $("#f-replacement").value = rule ? rule.replacement || "" : "";
  $$("#scopes input").forEach((cb) => (cb.checked = rule && (rule.scopes || []).includes(cb.value)));
  $$("#fields input").forEach((cb) => (cb.checked = rule && (rule.fields || []).includes(cb.value)));
  syncTypeFields();
  $("#modal").classList.remove("hidden");
  $("#f-name").focus();
}

function syncTypeFields() {
  const isDetector = $("#f-type").value === "detector";
  $("#detector-wrap").classList.toggle("hidden", !isDetector);
  $("#pattern-wrap").classList.toggle("hidden", isDetector);
  $("#pattern-wrap").required = !isDetector;
  syncDetectorFields();
  syncReplacementField();
}

function syncDetectorFields() {
  const det = $("#f-detector").value;
  const info = detectors.find((d) => d.name === det);
  const tunable = $("#f-type").value === "detector" && info && info.tunable;
  $("#entropy-wrap").classList.toggle("hidden", !tunable);
  const desc = $("#detector-desc");
  desc.textContent = $("#f-type").value === "detector" && info ? info.description : "";
  desc.classList.toggle("hidden", !desc.textContent);
}

function syncReplacementField() {
  const isMask = $("#f-action").value === "mask";
  $("#replacement-wrap").classList.toggle("hidden", !isMask);
}

function readForm() {
  const type = $("#f-type").value;
  const scopes = [...$$("#scopes input:checked")].map((cb) => cb.value);
  const fields = [...$$("#fields input:checked")].map((cb) => cb.value);
  const action = $("#f-action").value;
  const payload = {
    name: $("#f-name").value.trim(),
    description: $("#f-desc").value.trim(),
    type,
    action,
    replacement: $("#f-replacement").value.trim(),
    scopes,
    fields,
  };
  if (type === "detector") {
    payload.detector = $("#f-detector").value;
    payload.threshold = Number($("#f-threshold").value) || 0;
    payload.minLength = Number($("#f-minlength").value) || 0;
    payload.pattern = "";
  } else {
    payload.pattern = $("#f-pattern").value.trim();
    payload.detector = "";
    payload.threshold = 0;
    payload.minLength = 0;
  }
  return payload;
}

async function saveForm(e) {
  e.preventDefault();
  const id = $("#f-id").value;
  const payload = readForm();
  try {
    if (id) await api("/rules/" + id, { method: "PUT", body: JSON.stringify(payload) });
    else await api("/rules", { method: "POST", body: JSON.stringify(payload) });
    closeModal();
    await load();
    hint(id ? "规则已更新" : "规则已创建");
  } catch (err) {
    hint(err.message, false);
  }
}

function closeModal() {
  $("#modal").classList.add("hidden");
  $("#test-modal").classList.add("hidden");
}

// 只关测试弹窗，保留表单弹窗及其填写内容
function closeTestModal() {
  $("#test-modal").classList.add("hidden");
}

/* ---------------- 删除 ---------------- */

async function remove(id) {
  if (!confirm("确认删除该规则？")) return;
  try {
    await api("/rules/" + id, { method: "DELETE" });
    await load();
    hint("规则已删除");
  } catch (err) {
    hint(err.message, false);
  }
}

/* ---------------- 测试匹配 ---------------- */

function openTest(rule) {
  currentTest = rule;
  if (ruleType(rule) === "detector") {
    const extra =
      rule.detector === "high_entropy"
        ? `（阈值 ${rule.threshold || 4.0} / 长度 ${rule.minLength || 20}）`
        : "";
    $("#t-pattern").textContent = "detector: " + rule.detector + extra;
  } else {
    $("#t-pattern").textContent = rule.pattern;
  }
  $("#t-action").textContent = rule.action;
  $("#t-action").className = "badge " + rule.action;
  $("#t-replacement").textContent = rule.action === "mask" ? rule.replacement : "—";
  $("#t-text").value = "";
  $("#t-result").classList.add("hidden");
  $("#test-modal").classList.remove("hidden");
  $("#t-text").focus();
}

async function runTest() {
  if (!currentTest) return;
  const testText = $("#t-text").value;
  if (!testText) return;

  const r = currentTest;
  try {
    const res = await api("/preview", {
      method: "POST",
      body: JSON.stringify({
        type: ruleType(r),
        pattern: r.pattern || "",
        detector: r.detector || "",
        threshold: r.threshold || 0,
        minLength: r.minLength || 0,
        testText,
        action: r.action,
        replacement: r.replacement || "",
      }),
    });
    const label = $("#t-result-label");
    $("#t-result").classList.remove("hidden");
    if (!res.hasMatch) {
      label.textContent = "未匹配";
      label.className = "result-label no";
      $("#t-result-body").textContent = testText;
    } else if (res.result === "reject") {
      label.textContent = "匹配 → 请求将被拒绝（400）";
      label.className = "result-label rejected";
      $("#t-result-body").textContent = "request blocked by prompt protection policy";
    } else {
      label.textContent = "匹配 → 脱敏结果";
      label.className = "result-label ok";
      $("#t-result-body").textContent = res.result;
    }
  } catch (err) {
    // 试跑接口需要 admin token（known_secret 是子串匹配，免鉴权就会变成密钥 oracle），
    // 没带 token 时要把"去填 token"这个指引给出来，而不是只抛 401。
    hint(authHint(err.message), false);
  }
}

/* ---------------- 诊断事件（响应侧守卫） ---------------- */

const eventLabels = {
  leak: "回显泄漏",
  sensitive: "响应含敏感内容",
  model_mismatch: "模型不一致",
};
const actionLabels = {
  blocked: "已阻断",
  aborted: "已断流",
  warned: "仅告警",
};

async function loadEvents() {
  const box = $("#audit-list");
  const status = $("#audit-status");
  try {
    const data = await api("/events?limit=50");
    if (!data.enabled) {
      status.textContent = "未开启（启动时加 -audit）";
      box.innerHTML = "";
      return;
    }
    status.textContent = "";
    if (!data.events.length) {
      box.innerHTML = '<li class="muted">暂无事件</li>';
      return;
    }
    box.innerHTML = data.events
      .map((e) => {
        const time = new Date(e.time).toLocaleString();
        const parts = [
          `<span class="badge ${e.action === "warned" ? "mask" : "reject"}">${esc(actionLabels[e.action] || e.action)}</span>`,
          `<strong>${esc(eventLabels[e.kind] || e.kind)}</strong>`,
          e.rule ? `规则 ${esc(e.rule)}` : "",
          e.detector ? `检测器 <code>${esc(e.detector)}</code>` : "",
          e.model ? `请求模型 <code>${esc(e.model)}</code>` : "",
          e.upstreamModel ? `响应模型 <code>${esc(e.upstreamModel)}</code>` : "",
          e.matchedLen ? `命中 ${e.matchedLen} 字节` : "",
          e.path ? `<code>${esc(e.path)}</code>` : "",
          e.hint ? `片段 <code>${esc(e.hint)}</code>` : "",
        ].filter(Boolean);
        return `<li><span class="muted">${esc(time)}</span> ${parts.join(" · ")}</li>`;
      })
      .join("");
  } catch (err) {
    status.textContent = err.message;
  }
}

async function clearEvents() {
  try {
    await api("/events", { method: "DELETE" });
    await loadEvents();
    hint("事件已清空");
  } catch (err) {
    hint(err.message, false);
  }
}

/* ---------------- 已知密钥（-secret-file） ---------------- */

// 接口只回路径与键名，绝不回值；token 与诊断事件共用同一个 sessionStorage 键。
async function loadSecrets() {
  const status = $("#secrets-status");
  const tbody = $("#secrets-table tbody");
  const empty = $("#secrets-empty");
  let data;
  try {
    data = await api("/secrets");
  } catch (err) {
    status.textContent = authHint(err.message);
    return;
  }

  const files = data.files || [];
  const list = data.list || [];
  status.textContent = `${data.values} 个值 · ${files.length} 份文件` +
    (data.listPath ? ` · 列表 ${data.listPath}` : "");
  empty.classList.toggle("hidden", files.length > 0 || list.length > 0);

  // 可删除的只看"列表里的路径"：pinned（-secret-file）删了下次开机又回来，只能看。
  tbody.innerHTML = files
    .map((f) => {
      const removable = !f.pinned && list.some((p) => f.path === p || f.path.startsWith(p.replace(/\/$/, "") + "/"));
      const note = f.skipped
        ? `<span class="badge reject">跳过</span> ${esc(f.skipped)}`
        : '<span class="badge mask">生效</span>';
      const tag = f.pinned
        ? '<span class="badge detector" title="来自 -secret-file，不能在界面上删除">pinned</span>'
        : `<span class="badge detector">${esc(f.mode)}</span>`;
      return `<tr>
        <td><code>${esc(f.path)}</code></td>
        <td>${tag}</td>
        <td>${f.collected}</td>
        <td>${(f.keys || []).map((k) => `<code>${esc(k)}</code>`).join(" ") || '<span class="muted">—</span>'}</td>
        <td>${note}</td>
        <td class="row-actions">${
          removable
            ? `<button class="btn small danger" data-del="${esc(
                list.find((p) => f.path === p || f.path.startsWith(p.replace(/\/$/, "") + "/")) || ""
              )}">删除</button>`
            : '<span class="muted">—</span>'
        }</td>
      </tr>`;
    })
    .join("");

  // 列表里有、但没扫出文件的路径（比如目录下没有 .env）也要露出来，否则“我明明加了”无从排查。
  const extra = list.filter((p) => !files.some((f) => f.path === p || f.path.startsWith(p.replace(/\/$/, "") + "/")));
  tbody.innerHTML += extra
    .map((p) => `<tr>
      <td><code>${esc(p)}</code></td>
      <td><span class="badge detector">list</span></td>
      <td>0</td>
      <td><span class="muted">—</span></td>
      <td><span class="badge reject">空</span> 没有找到带 ###secret 的 .env</td>
      <td class="row-actions"><button class="btn small danger" data-del="${esc(p)}">删除</button></td>
    </tr>`)
    .join("");
}

async function addSecretPath() {
  const input = $("#secret-path");
  const path = input.value.trim();
  if (!path) {
    hint("先填一个 .env 或项目目录路径", false);
    return;
  }
  try {
    const data = await api("/secrets/files", { method: "POST", body: JSON.stringify({ path }) });
    input.value = "";
    await loadSecrets();
    hint(`已添加，当前 ${data.values} 个值`);
  } catch (err) {
    hint(authHint(err.message), false);
    if (/unauthorized|disabled/i.test(err.message)) $("#admin-token").focus();
  }
}

async function removeSecretPath(path) {
  try {
    const data = await api("/secrets/files?path=" + encodeURIComponent(path), { method: "DELETE" });
    await loadSecrets();
    hint(`已移除，当前 ${data.values} 个值`);
  } catch (err) {
    hint(authHint(err.message), false);
  }
}

async function reloadSecrets() {
  try {
    const data = await api("/secrets/reload", { method: "POST" });
    await loadSecrets();
    hint(`已重载：${data.values} 个值`);
  } catch (err) {
    hint(authHint(err.message), false);
  }
}

/* ---------------- 事件绑定 ---------------- */

$("#btn-create").addEventListener("click", () => openForm(null));
$("#btn-cancel").addEventListener("click", closeModal);
$("#rule-form").addEventListener("submit", saveForm);
$("#f-action").addEventListener("change", syncReplacementField);
$("#f-type").addEventListener("change", syncTypeFields);
$("#f-detector").addEventListener("change", syncDetectorFields);
$("#btn-test").addEventListener("click", () => openTest(readForm()));
$("#t-run").addEventListener("click", runTest);
$("#t-close").addEventListener("click", closeTestModal);

// 点击遮罩关闭：测试弹窗只关自己；表单弹窗点击遮罩才整体关闭
$("#test-modal").addEventListener("click", (e) => {
  if (e.target === $("#test-modal")) closeTestModal();
});
$("#modal").addEventListener("click", (e) => {
  if (e.target === $("#modal")) closeModal();
});

// ESC：优先只关测试弹窗，再关表单弹窗
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!$("#test-modal").classList.contains("hidden")) closeTestModal();
  else if (!$("#modal").classList.contains("hidden")) closeModal();
});

$("#rules-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const rule = rules.find((r) => r.id === id);
  if (!rule) return;
  if (btn.dataset.act === "edit") openForm(rule);
  else if (btn.dataset.act === "test") openTest(rule);
  else if (btn.dataset.act === "del") remove(id);
});

$("#rules-table").addEventListener("change", async (e) => {
  if (e.target.matches('input[type="checkbox"][data-id]')) {
    const id = Number(e.target.dataset.id);
    try {
      await api("/rules/" + id + "/status", {
        method: "POST",
        body: JSON.stringify({ enabled: e.target.checked }),
      });
      await load();
      hint(e.target.checked ? "规则已启用" : "规则已停用");
    } catch (err) {
      hint(err.message, false);
      e.target.checked = !e.target.checked;
    }
  }
});

$("#admin-token").value = adminToken();
$("#btn-token").addEventListener("click", async () => {
  sessionStorage.setItem("adminToken", $("#admin-token").value.trim());
  hint("token 已保存（仅本次会话）");
  await Promise.all([loadEvents(), loadSecrets()]);
});
$("#btn-secrets").addEventListener("click", loadSecrets);
$("#btn-secret-add").addEventListener("click", addSecretPath);
$("#secret-path").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    addSecretPath();
  }
});
$("#secrets-table").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-del]");
  if (btn) removeSecretPath(btn.dataset.del);
});
$("#btn-secrets-reload").addEventListener("click", reloadSecrets);
$("#secrets-panel").addEventListener("toggle", (e) => {
  if (e.target.open) loadSecrets();
});
$("#btn-events").addEventListener("click", loadEvents);
$("#btn-events-clear").addEventListener("click", clearEvents);
$(".audit").addEventListener("toggle", (e) => {
  if (e.target.open) loadEvents();
});

fillDetectorOptions();
load();
