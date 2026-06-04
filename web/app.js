const $ = (s) => document.querySelector(s);
const order = { FOUND: 0, UNCERTAIN: 1, UNVERIFIABLE: 2, ERROR: 3, NOT_FOUND: 4 };
let es = null;

// --- tab switching ---------------------------------------------------------
document.querySelectorAll("#tabs button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    b.classList.add("active");
    $("#panel-" + b.dataset.tab).classList.add("active");
    if (b.dataset.tab === "investigations") { loadTargets(); loadRuns(); }
    if (b.dataset.tab === "timeline") loadChanges();
    if (b.dataset.tab === "sources") loadSources();
  });
});

function formParams() {
  const data = new FormData($("#q"));
  const params = new URLSearchParams();
  const obj = {};
  for (const [k, v] of data.entries()) if (v.trim()) { params.set(k, v.trim()); obj[k] = v.trim(); }
  return { params, obj };
}

// --- live SSE search -------------------------------------------------------
$("#q").addEventListener("submit", (e) => {
  e.preventDefault();
  if (es) es.close();
  $("#results").querySelector("tbody").innerHTML = "";
  $("#summary").innerHTML = "";
  const { params } = formParams();
  if ([...params].length === 0) { $("#status").textContent = "Enter at least one field."; return; }
  $("#go").disabled = true;
  $("#status").textContent = "Researching…";
  let hits = 0;
  es = new EventSource("/api/search?" + params.toString());
  es.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    if (ev.type === "finding") {
      addRow(ev.finding);
      if (["FOUND", "UNCERTAIN"].includes(ev.finding.verdict))
        $("#status").textContent = `Researching… ${++hits} hit(s)`;
    } else if (ev.type === "summary") { renderSummary(ev.summary); }
    else if (ev.type === "done") { $("#status").textContent = `Done — ${ev.hits}/${ev.total}.`; $("#go").disabled = false; es.close(); }
    else if (ev.type === "error") { $("#status").textContent = "Error: " + ev.message; $("#go").disabled = false; es.close(); }
  };
  es.onerror = () => { $("#go").disabled = false; es.close(); };
});

// --- persisted scan --------------------------------------------------------
$("#save").addEventListener("click", async () => {
  const { obj } = formParams();
  if (Object.keys(obj).length === 0) { $("#status").textContent = "Enter at least one field."; return; }
  $("#status").textContent = "Running & saving (correlating)…";
  const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });
  const d = await r.json();
  $("#status").textContent = `Saved run #${d.run_id}: ${d.hits} hit(s), ${d.summary.identities} identities, ${d.changes.length} change(s).`;
  renderSummary(d.summary);
});

function addRow(f) {
  const tr = document.createElement("tr");
  tr.className = f.verdict;
  const label = f.url ? `<a href="${f.url}" target="_blank" rel="noopener">${esc(f.label)}</a>` : esc(f.label);
  tr.innerHTML = `<td><span class="v ${f.verdict}">${f.verdict}</span></td><td>${f.confidence.toFixed(2)}</td>
    <td>${esc(f.source)}</td><td>${label}</td><td class="reasons">${(f.reasons||[]).map(esc).join("<br>")}</td>`;
  const tbody = $("#results").querySelector("tbody");
  const rows = [...tbody.children];
  const idx = rows.findIndex((row) => order[row.className] > order[f.verdict]);
  if (idx === -1) tbody.appendChild(tr); else tbody.insertBefore(tr, rows[idx]);
}

function renderSummary(s) {
  if (!s || !s.clusters || !s.clusters.length) { $("#summary").innerHTML = ""; return; }
  let html = `<h2>Identities (${s.identities})</h2>`;
  for (const c of s.clusters) {
    const sig = Object.entries(c.signals || {}).map(([k, v]) => `${k}: ${[].concat(v).join(", ")}`).join(" · ") || "—";
    const flags = (c.flags && c.flags.length) ? `<span class="flag">${c.flags.join(", ")}</span>` : "";
    html += `<div class="cluster"><b>#${c.id} ${esc(c.label||"")}</b> · score ${c.score} · ${c.found} found / ${c.uncertain} uncertain ${flags}<br><small>${esc(sig)}</small></div>`;
  }
  $("#summary").innerHTML = html;
}

// --- dashboard loaders -----------------------------------------------------
async function table(target, url, cols, mapRow) {
  const rows = await (await fetch(url)).json();
  if (!rows.length) { $(target).innerHTML = "<p class='tag'>No data yet.</p>"; return; }
  let h = "<table><thead><tr>" + cols.map((c) => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
  h += rows.map((r) => "<tr>" + mapRow(r).map((c) => `<td>${c}</td>`).join("") + "</tr>").join("");
  $(target).innerHTML = h + "</tbody></table>";
}

const loadTargets = () => table("#targets", "/api/targets", ["id", "label", "watch", "query"],
  (t) => [t.id, esc(t.label||""), t.watchlist ? "✓" : "", esc(JSON.stringify(t.query))]);

const loadRuns = () => table("#runs", "/api/runs", ["run", "target", "status", "stats"],
  (r) => [r.id, r.target_id, r.status, esc(JSON.stringify(r.stats))]);

const loadChanges = () => table("#changes", "/api/changes", ["when","kind","source","label","detail"],
  (c) => [c.created_at.replace("T"," ").slice(0,16), badge(c.kind), esc(c.source||""), esc(c.label||""), esc(JSON.stringify(c.detail))]);

const loadSources = () => table("#sources", "/api/sources", ["source","kind","reliability","ok","fail","breaker"],
  (s) => [esc(s.name), esc(s.kind||""), bar(s.reliability), s.successes, s.failures, badge(s.breaker_state)]);

$("#graph-load").addEventListener("click", () => {
  const id = $("#graph-target").value || 0;
  table("#entities", `/api/targets/${id}/entities`, ["id","identity","score","sources","flags"],
    (e) => [e.id, esc(e.label||""), bar(e.confidence),
            esc((e.sources||[]).join(", ")),
            (e.flags&&e.flags.length)?`<span class="flag">${esc(e.flags.join(", "))}</span>`:""]);
});

function badge(k){ return `<span class="badge ${esc(k)}">${esc(k)}</span>`; }
function bar(v){ v=v||0; return `<span class="bar"><span style="width:${Math.round(v*100)}%"></span></span> ${v.toFixed(2)}`; }
function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
