// Live physical model card: what the model is, the operating point it runs at, how well it was measured, and what it cannot do.
// Published by the middleware at startup (POST /api/model) so this shows the model that is ACTUALLY running, env overrides included.
(function () {
    function esc(v) {
        return String(v === null || v === undefined ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }
    function operatingPoint(c) {
        const op = c.operating_point || {};
        const m = op.measured || {};
        const name = op.name ? esc(op.name) : "shipped";
        const bits = [];
        if (c.threshold !== null && c.threshold !== undefined) bits.push(`threshold ${Number(c.threshold).toFixed(4)}`);
        if (m.alarm_episodes_per_benign_hour !== undefined) bits.push(`${m.alarm_episodes_per_benign_hour} alerts/h`);
        if (m.segments_detected !== undefined) bits.push(`${m.segments_detected}/${m.segments_total} attack segments`);
        if (m.f1 !== undefined) bits.push(`F1 ${m.f1}`);
        const overridden = c.shipped_threshold !== undefined && c.shipped_threshold !== null
            && Math.abs(Number(c.shipped_threshold) - Number(c.threshold)) > 1e-9;
        return `${name}${overridden ? ' <span class="m-warn">(overridden)</span>' : ""} &middot; ${esc(bits.join(" &middot; ")).replace(/&amp;middot;/g, "&middot;")}`;
    }
    function render(c) {
        const box = document.getElementById("model-body");
        const role = document.getElementById("model-role");
        if (!box) return;
        if (!c || !c.model) return;
        if (role) role.textContent = c.status === "OK" ? "advisory · never blocks" : esc(c.status);
        const limits = (c.known_limits || []).map((l) => `<li>${esc(l)}</li>`).join("");
        box.innerHTML =
            `<div class="m-line"><span class="m-key">Model</span> ${esc(c.model)} (${esc(c.variant)}), ${esc(c.features)} features over a ${esc(c.window_seconds)} s window</div>` +
            `<div class="m-line"><span class="m-key">Role</span> ${esc(c.role)}</div>` +
            `<div class="m-line"><span class="m-key">Operating point</span> ${operatingPoint(c)}</div>` +
            (c.held_out_result ? `<div class="m-line"><span class="m-key">Held-out SWaT</span> ${esc(c.held_out_result)}</div>` : "") +
            (c.trained_on ? `<div class="m-line"><span class="m-key">Trained on</span> ${esc(c.trained_on)}</div>` : "") +
            (limits ? `<div class="m-line"><span class="m-key">Known limits</span></div><ul class="m-limits">${limits}</ul>` : "");
    }
    async function poll() {
        try {
            const r = await fetch("/api/model", { cache: "no-store" });
            if (r.ok) render(await r.json());
        } catch (e) { /* the dashboard keeps running without the model card */ }
    }
    document.addEventListener("DOMContentLoaded", () => { poll(); setInterval(poll, 10000); });
})();
