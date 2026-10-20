// Investigator findings (middleware/investigator.py), polled from /api/investigations.
// Every recommendation is a PROPOSAL. The dashboard deliberately has no Apply button: a person makes the change.
(function () {
    function esc(v) {
        return String(v === null || v === undefined ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }
    function clock(t) {
        const d = new Date(t * 1000);
        return isNaN(d) ? "" : d.toLocaleTimeString();
    }
    function render(list) {
        const box = document.getElementById("investigation-list");
        if (!box) return;
        if (!list || !list.length) return;
        box.innerHTML = list.map((f) => {
            const actions = (f.recommended_actions || []).map((a) =>
                `<li><span class="inv-act">${esc(a.action)}</span>${a.target ? " &rarr; " + esc(a.target) : ""} &mdash; ${esc(a.why)}` +
                ` <span class="inv-approve">(needs approval${a.applied ? "" : "; not applied"})</span></li>`).join("");
            const rejected = (f.rejected_actions || []).length
                ? `<div class="inv-body"><span class="inv-label">Discarded</span>${f.rejected_actions.length} proposed action(s) outside the allow-list</div>` : "";
            return `<div class="inv sev-${esc(f.severity)}">` +
                `<div class="inv-head"><b>${esc(f.incident_id)}</b>` +
                `<span class="inv-engine ${f.engine === "rules" ? "rules" : ""}">${f.engine === "llm" ? "investigated" : "summary only"}</span>` +
                `<span>${esc(f.severity)} &middot; confidence ${esc(f.confidence)}</span>` +
                (f.reached_plc ? `<span class="inv-plc">reached the PLC</span>` : "") +
                `<span style="opacity:.6">${esc(clock(f.generated_at))}</span></div>` +
                `<div class="inv-body"><b>${esc(f.headline)}</b></div>` +
                `<div class="inv-body"><span class="inv-label">What happened</span>${esc(f.what_happened)}</div>` +
                `<div class="inv-body"><span class="inv-label">Hypothesis</span>${esc(f.attack_hypothesis)}</div>` +
                (f.affected_stages && f.affected_stages.length
                    ? `<div class="inv-body"><span class="inv-label">Stages</span>${esc(f.affected_stages.join(", "))}</div>` : "") +
                (actions ? `<div class="inv-body"><span class="inv-label">Proposed</span></div><ul class="inv-actions">${actions}</ul>` : "") +
                rejected +
                `<div class="inv-body"><span class="inv-label">Caveats</span>${esc(f.caveats)}</div>` +
                (f.evidence_used && f.evidence_used.length
                    ? `<div class="inv-body"><span class="inv-label">Evidence read</span>${esc(f.evidence_used.map((e) => e.tool).join(" &rarr; ")).replace(/&amp;rarr;/g, "&rarr;")}</div>` : "") +
                `</div>`;
        }).join("");
    }
    async function poll() {
        try {
            const r = await fetch("/api/investigations", { cache: "no-store" });
            if (r.ok) render(await r.json());
        } catch (e) { /* the dashboard keeps running without the investigations panel */ }
    }
    document.addEventListener("DOMContentLoaded", () => { poll(); setInterval(poll, 3000); });
})();
