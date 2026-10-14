async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

async function refreshHeartbeat() {
  const btn = document.getElementById("hb-toggle");
  try {
    const d = await api("/api/heartbeat");
    btn.textContent = d.enabled ? "ON — click to stop" : "OFF — click to start";
    btn.dataset.enabled = d.enabled ? "1" : "0";
  } catch (e) {
    btn.textContent = "heartbeat error";
  }
}

document.getElementById("hb-toggle").addEventListener("click", async () => {
  const btn = document.getElementById("hb-toggle");
  const next = btn.dataset.enabled !== "1";
  await api("/api/heartbeat", { method: "POST", body: JSON.stringify({ enabled: next }) });
  await refreshHeartbeat();
});

function renderRule(rule) {
  const card = el("article", "card");
  card.dataset.id = rule.id;

  const id = el("div", "id", rule.id);
  const h2 = el("h2", null, rule.title || rule.id);
  const summary = el("p", "summary", rule.summary || "");
  const actions = el("div", "actions");
  const runBtn = el("button", "primary", "Run");
  const evalBtn = el("button", null, "Evaluate");
  const badge = el("span", "badge quiet", "idle");
  const out = el("pre", null, "");

  runBtn.addEventListener("click", async () => {
    runBtn.disabled = true;
    evalBtn.disabled = true;
    badge.className = "badge quiet";
    badge.textContent = "running…";
    out.textContent = "";
    try {
      const data = await api(`/api/run/${encodeURIComponent(rule.id)}`, { method: "POST", body: "{}" });
      out.textContent = JSON.stringify(data.result, null, 2);
      badge.textContent = "ran — evaluate next";
    } catch (e) {
      badge.className = "badge err";
      badge.textContent = "run failed";
      out.textContent = String(e);
    } finally {
      runBtn.disabled = false;
      evalBtn.disabled = false;
    }
  });

  evalBtn.addEventListener("click", async () => {
    runBtn.disabled = true;
    evalBtn.disabled = true;
    badge.className = "badge quiet";
    badge.textContent = "evaluating…";
    try {
      const data = await api(`/api/evaluate/${encodeURIComponent(rule.id)}`, {
        method: "POST",
        body: JSON.stringify({ settle_s: 2.5 }),
      });
      const r = data.result || {};
      badge.className = r.fired ? "badge fired" : "badge quiet";
      badge.textContent = r.fired ? "FIRED" : "not fired";
      out.textContent = JSON.stringify(r, null, 2);
      if (r.grafana_url) {
        let link = actions.querySelector("a.grafana");
        if (!link) {
          link = el("a", "ghost grafana", "Grafana Explore");
          link.target = "_blank";
          link.rel = "noreferrer";
          actions.appendChild(link);
        }
        link.href = r.grafana_url;
      }
    } catch (e) {
      badge.className = "badge err";
      badge.textContent = "eval failed";
      out.textContent = String(e);
    } finally {
      runBtn.disabled = false;
      evalBtn.disabled = false;
    }
  });

  actions.append(runBtn, evalBtn, badge);
  card.append(id, h2, summary, actions, out);
  return card;
}

document.getElementById("mixed-run").addEventListener("click", async () => {
  const btn = document.getElementById("mixed-run");
  const badge = document.getElementById("mixed-badge");
  const out = document.getElementById("mixed-out");
  const count = Number(document.getElementById("mixed-count").value || 40);
  const attack_ratio = Number(document.getElementById("mixed-ratio").value || 0.45);
  btn.disabled = true;
  badge.className = "badge quiet";
  badge.textContent = "running…";
  out.textContent = "";
  try {
    const data = await api("/api/run-mixed", {
      method: "POST",
      body: JSON.stringify({ count, attack_ratio }),
    });
    const r = data.result || {};
    badge.className = "badge fired";
    badge.textContent = `done (${r.count || 0})`;
    out.textContent = JSON.stringify(
      {
        count: r.count,
        attack_ratio: r.attack_ratio,
        kind_counts: r.kind_counts,
        note: r.note,
        sample: (r.steps || []).slice(0, 12),
      },
      null,
      2
    );
  } catch (e) {
    badge.className = "badge err";
    badge.textContent = "failed";
    out.textContent = String(e);
  } finally {
    btn.disabled = false;
  }
});

async function main() {
  await refreshHeartbeat();
  const root = document.getElementById("rules");
  const data = await api("/api/rules");
  for (const rule of data.rules || []) {
    root.appendChild(renderRule(rule));
  }
}

main().catch((e) => {
  document.getElementById("rules").textContent = String(e);
});
