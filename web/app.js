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
    if (b.dataset.tab === "insights") { loadInsights(); loadRuleCatalogue(); }
    if (b.dataset.tab === "keys") { loadKeys(); loadModules(); }
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

function breakdownHtml(bd) {
  if (!bd || !bd.contributions) return "";
  const sign = (d) => (d >= 0 ? "+" : "") + d.toFixed(2);
  const rows = bd.contributions
    .map((c) => `<span class="bd-row">${sign(c.delta)} <b>${esc(c.term)}</b> — ${esc(c.reason)}</span>`).join("");
  let shadow = "";
  if (bd.shadow_total != null && bd.shadow_total !== bd.total)
    shadow = `<span class="bd-shadow">independence-adjusted: ${bd.shadow_total.toFixed(2)}`
      + (bd.shadow_note ? ` — ${esc(bd.shadow_note)}` : "") + `</span>`;
  return `<details class="why"><summary>why ${bd.total.toFixed(2)}</summary>`
    + `<div class="bd"><span class="bd-row">base ${bd.base.toFixed(2)}</span>${rows}`
    + `<span class="bd-row bd-total">= ${bd.total.toFixed(2)}</span>${shadow}</div></details>`;
}

function addRow(f) {
  const tr = document.createElement("tr");
  tr.className = f.verdict;
  const label = f.url ? `<a href="${f.url}" target="_blank" rel="noopener">${esc(f.label)}</a>` : esc(f.label);
  const reasons = (f.reasons || []).map(esc).join("<br>") + breakdownHtml(f.breakdown);
  tr.innerHTML = `<td><span class="v ${f.verdict}">${f.verdict}</span></td><td>${f.confidence.toFixed(2)}</td>
    <td>${esc(f.source)}</td><td>${label}</td><td class="reasons">${reasons}</td>`;
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

// --- Discovery map (self-contained force-directed graph; no external deps) --
const TYPE_COLORS = {
  username:"#58a6ff", account_profile:"#79c0ff",
  email:"#f0883e", domain:"#3fb950", subdomain:"#56d364", hostname:"#56d364",
  mx_host:"#2ea043", nameserver:"#2ea043",
  ip_address:"#bc8cff", asn:"#d2a8ff", netblock:"#d2a8ff",
  url:"#8b949e", link:"#6e7681", hash:"#ff7b72", breach:"#f85149",
  phone:"#e3b341", name:"#e3b341",
};
const typeColor = (t) => TYPE_COLORS[t] || "#8b93a7";
let mapState = null, lastGraph = null, resizeTimer = null;

// Refit the canvas when the window resizes, while the map tab is showing one.
window.addEventListener("resize", () => {
  if (!lastGraph || !$("#panel-map").classList.contains("active")) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => startSim(lastGraph), 180);
});

async function loadMap() {
  const run = $("#map-run").value.trim();
  $("#map-status").textContent = "Loading…";
  let url = run ? `/api/runs/${run}/graph` : null;
  if (!url) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) { $("#map-status").textContent = "No runs yet — run a saved scan first."; return; }
    url = `/api/runs/${runs[0].id}/graph`;
  }
  const g = await (await fetch(url)).json();
  if (!g.nodes || !g.nodes.length) { $("#map-status").textContent = "No artifacts for this run."; clearMap(); return; }
  $("#map-status").textContent = `run #${g.run_id}: ${g.nodes.length} nodes, ${g.edges.length} edges`;
  $("#map-legend").innerHTML = [...new Set(g.nodes.map(n=>n.type))].sort()
    .map(t=>`<span class="leg"><i style="background:${typeColor(t)}"></i>${esc(t)}</span>`).join("");
  startSim(g);
}

function clearMap(){ if(mapState&&mapState.raf) cancelAnimationFrame(mapState.raf);
  const cv=$("#map-canvas"); if(cv){const c=cv.getContext("2d"); c&&c.clearRect(0,0,cv.width,cv.height);}
  $("#map-detail").innerHTML=""; }

function startSim(g){
  if(mapState){ if(mapState.raf) cancelAnimationFrame(mapState.raf);
    if(mapState.onUp) window.removeEventListener("mouseup", mapState.onUp); }
  const cv=$("#map-canvas"), wrap=$("#map-wrap");
  const W=cv.width=wrap.clientWidth||900, H=cv.height=520, ctx=cv.getContext("2d");
  const byId=new Map();
  lastGraph=g;
  const N=g.nodes.length;
  const nodes=g.nodes.slice(0,400).map((n,i)=>{ const a=(i/Math.max(1,N))*Math.PI*2;
    const node={...n, x:Math.cos(a)*140+(Math.random()*30-15), y:Math.sin(a)*140+(Math.random()*30-15),
                vx:0, vy:0, fx:null, fy:null}; byId.set(n.id,node); return node; });
  const edges=g.edges.map(e=>({s:byId.get(e.source), t:byId.get(e.target)})).filter(e=>e.s&&e.t);
  const view={scale:1, ox:0, oy:0};
  let alpha=1, dragNode=null, hover=null, panning=false, panStart=null;
  mapState={raf:null, onUp:null};

  const toScreen=(n)=>[W/2+view.ox+n.x*view.scale, H/2+view.oy+n.y*view.scale];
  const toWorld=(px,py)=>[(px-W/2-view.ox)/view.scale, (py-H/2-view.oy)/view.scale];
  function pick(px,py){ const [wx,wy]=toWorld(px,py); let best=null,bd=1e9;
    for(const n of nodes){ const d=(n.x-wx)**2+(n.y-wy)**2; if(d<bd){bd=d;best=n;} }
    return bd < (14/view.scale)**2 ? best : null; }

  function tick(){
    if(alpha>0.02){
      for(let i=0;i<nodes.length;i++){ const a=nodes[i];
        for(let j=i+1;j<nodes.length;j++){ const b=nodes[j];
          let dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy+0.01, d=Math.sqrt(d2), f=2400/d2;
          dx/=d; dy/=d; a.vx+=dx*f; a.vy+=dy*f; b.vx-=dx*f; b.vy-=dy*f; } }
      for(const e of edges){ let dx=e.t.x-e.s.x, dy=e.t.y-e.s.y, d=Math.sqrt(dx*dx+dy*dy)+0.01, f=(d-72)*0.02;
        dx/=d; dy/=d; e.s.vx+=dx*f; e.s.vy+=dy*f; e.t.vx-=dx*f; e.t.vy-=dy*f; }
      for(const n of nodes){ n.vx-=n.x*0.0022; n.vy-=n.y*0.0022;
        if(n.fx!=null){ n.x=n.fx; n.y=n.fy; n.vx=0; n.vy=0; }
        else { n.vx*=0.86; n.vy*=0.86; n.x+=n.vx; n.y+=n.vy; } }
      alpha*=0.99;
    }
    draw(); mapState.raf=requestAnimationFrame(tick);
  }
  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.lineWidth=1; ctx.strokeStyle="rgba(139,147,167,.22)";
    for(const e of edges){ const [sx,sy]=toScreen(e.s),[tx,ty]=toScreen(e.t);
      ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(tx,ty); ctx.stroke(); }
    for(const n of nodes){ const [x,y]=toScreen(n), r=n.depth===0?7:5;
      ctx.beginPath(); ctx.arc(x,y,r,0,6.2832); ctx.fillStyle=typeColor(n.type); ctx.fill();
      if(n===hover||n.depth===0){ ctx.lineWidth=2; ctx.strokeStyle="#fff"; ctx.stroke(); } }
    if(hover){ const [x,y]=toScreen(hover); const txt=`${hover.type}: ${hover.value}`;
      ctx.font="12px system-ui"; const w=ctx.measureText(txt).width+12;
      ctx.fillStyle="rgba(0,0,0,.82)"; ctx.fillRect(x+8,y-23,w,18);
      ctx.fillStyle="#fff"; ctx.fillText(txt, x+14, y-10); }
  }
  function detail(n){ $("#map-detail").innerHTML =
    `<b style="color:${typeColor(n.type)}">${esc(n.type)}</b><br>${esc(n.value)}`+
    `<br><small class="tag">depth ${n.depth} · via ${esc(n.source_module)} · conf ${(+n.confidence||0).toFixed(2)}</small>`+
    (n.data&&Object.keys(n.data).length?`<pre>${esc(JSON.stringify(n.data,null,1)).slice(0,600)}</pre>`:""); }

  cv.onmousedown=(ev)=>{ const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    const n=pick(px,py);
    if(n){ dragNode=n; n.fx=n.x; n.fy=n.y; detail(n); }
    else { panning=true; panStart=[px-view.ox, py-view.oy]; } };
  cv.onmousemove=(ev)=>{ const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    if(dragNode){ const [wx,wy]=toWorld(px,py); dragNode.fx=wx; dragNode.fy=wy; alpha=Math.max(alpha,0.3); }
    else if(panning){ view.ox=px-panStart[0]; view.oy=py-panStart[1]; }
    else { hover=pick(px,py); cv.style.cursor=hover?"pointer":"grab"; } };
  cv.onwheel=(ev)=>{ ev.preventDefault(); const r=cv.getBoundingClientRect(), px=ev.clientX-r.left, py=ev.clientY-r.top;
    const [wx,wy]=toWorld(px,py), f=ev.deltaY<0?1.1:0.9;
    view.scale=Math.min(4, Math.max(0.25, view.scale*f));
    view.ox=px-W/2-wx*view.scale; view.oy=py-H/2-wy*view.scale; };
  mapState.onUp=()=>{ if(dragNode){ dragNode.fx=null; dragNode.fy=null; dragNode=null; } panning=false; };
  window.addEventListener("mouseup", mapState.onUp);
  tick();
}
$("#map-load").addEventListener("click", loadMap);

// --- Modules & keys --------------------------------------------------------
async function loadModules(){
  const mods = await (await fetch("/api/modules")).json();
  let h = `<table><thead><tr><th>Module</th><th>Consumes</th><th>Produces</th><th>Auth</th><th>State</th></tr></thead><tbody>`;
  for(const m of mods){
    const auth = m.keyless ? `<span class="badge">keyless</span>`
      : `<span class="badge open">key: ${esc(m.requires_keys.join(","))}</span>`;
    const state = m.enabled ? `<span class="v FOUND">enabled</span>` : `<span class="v NOT_FOUND">needs key</span>`;
    h += `<tr><td><b>${esc(m.name)}</b></td><td><small>${esc(m.consumes.join(", "))}</small></td>`+
         `<td><small>${esc(m.produces.join(", ")||"—")}</small></td><td>${auth}</td><td>${state}</td></tr>`;
  }
  $("#modules").innerHTML = h + "</tbody></table>";
}
async function loadKeys(){
  const keys = await (await fetch("/api/keys")).json();
  let h = `<table><thead><tr><th>Key</th><th>Status</th><th>Used by</th><th>Configure</th></tr></thead><tbody>`;
  for(const k of keys){
    const status = k.configured ? `<span class="v FOUND">set (${esc(k.source)})</span>`
      : (k.optional ? `<span class="badge">optional</span>` : `<span class="v NOT_FOUND">not set</span>`);
    h += `<tr><td><b>${esc(k.name)}</b><br><small class="tag">${esc(k.description)}</small></td>`+
         `<td>${status}</td><td><small>${esc((k.modules||[]).join(", "))}</small></td>`+
         `<td><input data-key="${esc(k.name)}" type="password" placeholder="paste key…" style="width:150px" />`+
         ` <button class="setkey" data-key="${esc(k.name)}">Save</button>`+
         (k.source==="file" ? ` <button class="clearkey" data-key="${esc(k.name)}">Clear</button>` : "")+
         (k.source==="env" ? ` <small class="tag">(from env)</small>` : "")+`</td></tr>`;
  }
  $("#keys").innerHTML = h + "</tbody></table>";
  document.querySelectorAll(".setkey").forEach(b=>b.onclick=()=>
    saveKey(b.dataset.key, document.querySelector(`input[data-key="${b.dataset.key}"]`).value));
  document.querySelectorAll(".clearkey").forEach(b=>b.onclick=()=>saveKey(b.dataset.key, ""));
}
// --- Insights (correlation-rule findings) ----------------------------------
const SEV_CLASS = { high:"FOUND", medium:"UNCERTAIN", low:"UNVERIFIABLE", info:"NOT_FOUND" };
const sevBadge = (s) => `<span class="v ${SEV_CLASS[s]||"NOT_FOUND"}">${esc(s)}</span>`;

async function loadInsights(){
  let run = $("#ins-run").value.trim();
  if (!run) {
    const runs = await (await fetch("/api/runs")).json();
    if (!runs.length) { $("#ins-status").textContent = "No runs yet — run a saved scan first."; $("#insights").innerHTML=""; return; }
    run = runs[0].id;
  }
  const d = await (await fetch(`/api/runs/${run}/rules`)).json();
  const items = d.insights || [];
  $("#ins-status").textContent = `run #${d.run_id}: ${items.length} insight(s)`;
  if (!items.length) { $("#insights").innerHTML = "<p class='tag'>No correlation rules fired for this run.</p>"; return; }
  $("#insights").innerHTML = items.map(h => {
    const ev = (h.evidence||[]).slice(0,8)
      .map(e=>`<span class="leg"><i style="background:${typeColor(e.type)}"></i>${esc(e.type)}: ${esc(e.value)}</span>`).join("");
    const key = (h.key && h.key !== "*") ? ` <small class="tag">· ${esc(h.key)}</small>` : "";
    return `<div class="cluster">${sevBadge(h.severity)} <b>${esc(h.title)}</b>${key}`+
           `<br><small>${esc(h.description)}</small>`+
           (ev ? `<div class="map-legend">${ev}</div>` : "")+`</div>`;
  }).join("");
}

async function loadRuleCatalogue(){
  const rules = await (await fetch("/api/rules")).json();
  let h = `<table><thead><tr><th>Severity</th><th>Rule</th><th>Kind</th><th>What it means</th></tr></thead><tbody>`;
  for (const r of rules)
    h += `<tr><td>${sevBadge(r.severity)}</td><td><b>${esc(r.title)}</b><br><small class="tag">${esc(r.id)}</small></td>`+
         `<td><span class="badge">${esc(r.kind)}</span></td><td><small>${esc(r.description)}</small></td></tr>`;
  $("#rulecat").innerHTML = h + "</tbody></table>";
}
$("#ins-load").addEventListener("click", loadInsights);

async function saveKey(name, value){
  const st = $("#keys-status");
  if (st) st.textContent = value ? `Saving ${name}…` : `Clearing ${name}…`;
  try {
    const r = await fetch("/api/keys", { method:"POST", headers:{"Content-Type":"application/json"},
                                         body: JSON.stringify({ name, value }) });
    const d = await r.json();
    if (!r.ok) { if (st) st.textContent = `Error: ${d.error || r.status}`; return; }
    if (st) st.textContent = d.configured ? `${name}: saved` : `${name}: cleared`;
  } catch (e) {
    if (st) st.textContent = `Error: ${e.message}`;
  }
  loadKeys(); loadModules();
}
