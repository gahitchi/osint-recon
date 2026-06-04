const form = document.getElementById("q");
const tbody = document.querySelector("#results tbody");
const statusEl = document.getElementById("status");
const summaryEl = document.getElementById("summary");
const goBtn = document.getElementById("go");

const order = { FOUND: 0, UNCERTAIN: 1, ERROR: 2, NOT_FOUND: 3 };
let es = null;

form.addEventListener("submit", (e) => {
  e.preventDefault();
  if (es) es.close();
  tbody.innerHTML = "";
  summaryEl.innerHTML = "";

  const data = new FormData(form);
  const params = new URLSearchParams();
  for (const [k, v] of data.entries()) if (v.trim()) params.set(k, v.trim());
  if ([...params].length === 0) { statusEl.textContent = "Enter at least one field."; return; }

  goBtn.disabled = true;
  statusEl.textContent = "Researching…";
  let hits = 0;

  es = new EventSource("/api/search?" + params.toString());
  es.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    if (ev.type === "finding") {
      addRow(ev.finding);
      if (ev.finding.verdict === "FOUND" || ev.finding.verdict === "UNCERTAIN") {
        statusEl.textContent = `Researching… ${++hits} hit(s)`;
      }
    } else if (ev.type === "summary") {
      renderSummary(ev.summary);
    } else if (ev.type === "done") {
      statusEl.textContent = `Done — ${ev.hits} hit(s) of ${ev.total} checks.`;
      goBtn.disabled = false;
      es.close();
    } else if (ev.type === "error") {
      statusEl.textContent = "Error: " + ev.message;
      goBtn.disabled = false;
      es.close();
    }
  };
  es.onerror = () => { goBtn.disabled = false; es.close(); };
});

function addRow(f) {
  const tr = document.createElement("tr");
  tr.className = f.verdict;
  const label = f.url
    ? `<a href="${f.url}" target="_blank" rel="noopener">${esc(f.label)}</a>`
    : esc(f.label);
  tr.innerHTML = `
    <td><span class="v ${f.verdict}">${f.verdict}</span></td>
    <td>${f.confidence.toFixed(2)}</td>
    <td>${esc(f.source)}</td>
    <td>${label}</td>
    <td class="reasons">${(f.reasons || []).map(esc).join("<br>")}</td>`;
  // keep table roughly sorted by verdict priority
  const rows = [...tbody.children];
  const idx = rows.findIndex((r) => order[r.className] > order[f.verdict]);
  if (idx === -1) tbody.appendChild(tr); else tbody.insertBefore(tr, rows[idx]);
}

function renderSummary(s) {
  if (!s || !s.clusters || !s.clusters.length) return;
  let html = `<h2>Identity clusters (${s.identities})</h2>`;
  for (const c of s.clusters) {
    const sig = Object.entries(c.signals || {})
      .map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ") || "—";
    html += `<div class="cluster"><b>Cluster ${c.id}</b> · score ${c.score}
      · ${c.found} found / ${c.uncertain} uncertain<br>
      <small>${esc(sig)}</small></div>`;
  }
  summaryEl.innerHTML = html;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
