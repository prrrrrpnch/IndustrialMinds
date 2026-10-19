// Incidents panel: correlated blocked/alerted commands (middleware/incidents.py), polled from /api/incidents.
(function () {
    function esc(v) {
        return String(v === null || v === undefined ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }
    function clock(t) {
        const d = new Date(t * 1000);
        return isNaN(d) ? "" : d.toLocaleTimeString();
    }
    function render(list) {
        const box = document.getElementById("incident-list");
        const count = document.getElementById("incident-count");
        if (!box) return;
        const open = list.filter((i) => i.status === "open").length;
        if (count) count.textContent = `${list.length} incident${list.length === 1 ? "" : "s"} (${open} open)`;
        if (!list.length) {
            box.innerHTML = '<p class="tracer-empty">No incidents. Blocked or alerted commands from the same source are grouped here with a severity, a timeline and the response taken.</p>';
            return;
        }
        box.innerHTML = list.map((i) => {
            const types = (i.types || []).map((t) => (t.count ? `${esc(t.type)} ×${t.count}` : esc(t.type))).join(", ");
            const q = i.quarantined
                ? `<span class="inc-q">QUARANTINED${i.quarantine_remaining_s > 0 ? ` (${i.quarantine_remaining_s}s left)` : " (lifted)"}</span>`
                : "";
            const tl = (i.timeline || []).slice(-8).map((e) =>
                `<li>${esc(clock(e.t))} ${esc(e.verdict)} ${esc(e.register)}=${esc(e.value)} - ${esc(e.type)} (${esc(e.reason)})</li>`).join("");
            return `<div class="inc sev-${esc(i.severity)}">` +
                `<div class="inc-head"><b>${esc(i.id)}</b><span class="inc-sev">${esc(i.severity)}</span>` +
                `<span>${esc(i.status)}</span>${q}</div>` +
                `<div>${esc(i.summary)}</div>` +
                `<div class="inc-meta">drops ${esc(i.drops)} · alerts ${esc(i.alerts)} · registers: ${esc((i.registers || []).join(", "))} · ${types}</div>` +
                `<ul class="inc-tl">${tl}</ul></div>`;
        }).join("");
    }
    async function poll() {
        try {
            const r = await fetch("/api/incidents", { cache: "no-store" });
            if (r.ok) render(await r.json());
        } catch (e) { /* the dashboard keeps running without the incidents panel */ }
    }
    document.addEventListener("DOMContentLoaded", () => { poll(); setInterval(poll, 2000); });
})();
