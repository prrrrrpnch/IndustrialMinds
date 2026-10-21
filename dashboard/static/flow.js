// =========================================================
// LIVE NETWORK FLOW
// Every command the middleware received, drawn from the host that really sent it, through the
// middleware's layers, to the PLC (or stopped at the layer that caught it). Driven by /api/flow,
// which is built from the same per-command traces as the Packet Tracer (nothing is simulated here).
// =========================================================

(function () {
    const SVG_NS = "http://www.w3.org/2000/svg";
    const MAX_SOURCES = 5;
    const MAX_DOTS = 25;
    const SEG_MS = 260;

    const BOX = {
        mw: { x: 360, y: 30, w: 300, h: 270 },
        cyber: { x: 385, y: 70, w: 250, h: 52, label: "Cyber Agent (rules)" },
        physical: { x: 385, y: 140, w: 250, h: 52, label: "Physical Agent (rules + model)" },
        orch: { x: 385, y: 210, w: 250, h: 52, label: "Orchestrator (fusion)" },
        plc: { x: 800, y: 135, w: 170, h: 60 },
    };
    const P = {
        entry: [360, 165],
        cyber: [510, 96],
        physical: [510, 166],
        orch: [510, 236],
        exit: [660, 165],
        plc: [800, 165],
    };

    let svg, ticker, status;
    let lastSeq = 0;
    let initialised = false;
    let labels = {};
    const sources = new Map();          // ip -> {ip, trusted, sent, pass, alert, drop, lastSeen, y}
    const dots = [];

    function el(tag, attrs, parent) {
        const e = document.createElementNS(SVG_NS, tag);
        for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
        if (parent) parent.appendChild(e);
        return e;
    }

    function text(parent, x, y, str, cls, anchor) {
        const t = el("text", { x, y, class: cls || "flow-text", "text-anchor": anchor || "middle" }, parent);
        t.textContent = str;
        return t;
    }

    function drawStatic() {
        svg.innerHTML = "";
        el("g", { id: "flow-edges" }, svg);
        const mw = el("g", {}, svg);
        el("rect", { x: BOX.mw.x, y: BOX.mw.y, width: BOX.mw.w, height: BOX.mw.h, rx: 14, class: "flow-mw" }, mw);
        text(mw, BOX.mw.x + BOX.mw.w / 2, BOX.mw.y + 22, "MIDDLEWARE  :5021", "flow-title");
        for (const key of ["cyber", "physical", "orch"]) {
            const b = BOX[key];
            el("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 9, class: "flow-layer", id: `flow-box-${key}` }, mw);
            text(mw, b.x + b.w / 2, b.y + b.h / 2 + 5, b.label, "flow-text");
        }
        el("line", { x1: P.exit[0], y1: P.exit[1], x2: P.plc[0], y2: P.plc[1], class: "flow-edge" }, svg);
        const plc = el("g", {}, svg);
        el("rect", { x: BOX.plc.x, y: BOX.plc.y, width: BOX.plc.w, height: BOX.plc.h, rx: 12, class: "flow-plc", id: "flow-box-plc" }, plc);
        text(plc, BOX.plc.x + BOX.plc.w / 2, BOX.plc.y + 26, "PLC (twin)", "flow-title");
        const plcSub = text(plc, BOX.plc.x + BOX.plc.w / 2, BOX.plc.y + 46, ":5020", "flow-sub");
        if (plcSub && plcSub.setAttribute) plcSub.setAttribute("id", "flow-plc-sub");
        el("g", { id: "flow-sources" }, svg);
        el("g", { id: "flow-dots" }, svg);
    }

    function visibleSources() {
        return [...sources.values()].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, MAX_SOURCES)
            .sort((a, b) => a.first - b.first);
    }

    function drawSources() {
        const g = svg.querySelector("#flow-sources");
        const edges = svg.querySelector("#flow-edges");
        g.innerHTML = "";
        edges.innerHTML = "";
        const vis = visibleSources();
        const gap = 300 / Math.max(vis.length, 1);
        vis.forEach((s, i) => {
            s.y = 30 + gap * i + gap / 2;
            const cls = s.trusted === false ? "flow-src untrusted" : s.trusted === true ? "flow-src trusted" : "flow-src";
            el("line", { x1: 280, y1: s.y, x2: P.entry[0], y2: P.entry[1], class: "flow-edge" }, edges);
            el("rect", { x: 10, y: s.y - 30, width: 270, height: 60, rx: 10, class: cls }, g);
            const name = labels[s.ip] || (s.trusted === false ? "unknown host" : "host");
            text(g, 145, s.y - 10, `${name}`, "flow-title");
            text(g, 145, s.y + 6, s.ip + (s.trusted === false ? "  (untrusted)" : s.trusted ? "  (trusted)" : ""), "flow-sub");
            text(g, 145, s.y + 22, `sent ${s.sent} · pass ${s.pass} · alert ${s.alert} · drop ${s.drop}`, "flow-sub");
        });
    }

    function flash(id, cls) {
        const b = svg.querySelector(`#flow-box-${id}`);
        if (!b) return;
        b.classList.add(cls);
        setTimeout(() => b.classList.remove(cls), 450);
    }

    function launch(ev, src) {
        if (dots.length >= MAX_DOTS || src.y === undefined) return;
        const path = [[280, src.y], P.entry, P.cyber];
        if (ev.stopped_at !== "cyber") path.push(P.physical);
        if (!ev.stopped_at) path.push(P.orch, P.exit, P.plc);
        const colour = ev.verdict === "DROP" || ev.verdict === "UNDELIVERED" ? "dot-drop" : ev.verdict === "ALERT" ? "dot-alert" : "dot-pass";
        const c = el("circle", { r: 7, cx: path[0][0], cy: path[0][1], class: `flow-dot ${src.trusted === false ? "dot-untrusted" : colour}` },
            svg.querySelector("#flow-dots"));
        dots.push({ c, path, t0: performance.now(), ev, colour });
    }

    function step(now) {
        for (let i = dots.length - 1; i >= 0; i--) {
            const d = dots[i];
            const k = (now - d.t0) / SEG_MS;
            const seg = Math.floor(k);
            if (seg >= d.path.length - 1) {
                const end = d.ev.stopped_at || "plc";
                flash(end, d.ev.verdict === "DROP" || d.ev.verdict === "UNDELIVERED" ? "hit-drop" : d.ev.verdict === "ALERT" ? "hit-alert" : "hit-pass");
                if (end === "plc") {
                    // A command that reached the PLC marks it up; one the PLC never took marks it DOWN (and says so on the node).
                    const down = d.ev.verdict === "UNDELIVERED";
                    const box = svg.querySelector("#flow-box-plc");
                    if (box) box.classList.toggle("plc-down", down);
                    const sub = svg.querySelector("#flow-plc-sub");
                    if (sub) sub.textContent = down ? ":5020 unreachable" : ":5020";
                }
                d.c.remove();
                dots.splice(i, 1);
                continue;
            }
            if (seg >= 1) d.c.setAttribute("class", `flow-dot ${d.colour}`);      // past the source: show the verdict colour
            const [x1, y1] = d.path[seg];
            const [x2, y2] = d.path[seg + 1];
            const f = k - seg;
            d.c.setAttribute("cx", x1 + (x2 - x1) * f);
            d.c.setAttribute("cy", y1 + (y2 - y1) * f);
        }
        requestAnimationFrame(step);
    }

    function addTicker(ev) {
        const li = document.createElement("li");
        const who = labels[ev.source_ip] || ev.source_ip;
        const where = ev.stopped_at ? ` · stopped at the ${ev.stopped_at === "cyber" ? "Cyber" : "Physical"} Agent` : ev.forwarded ? " · forwarded to the PLC" : ev.verdict === "UNDELIVERED" ? " · never reached the PLC" : "";
        li.className = `tick tick-${String(ev.verdict).toLowerCase()}`;
        li.innerHTML = `<span class="t-time">${safe(ev.time)}</span><span class="t-src">${safe(who)}</span>` +
            `<span class="t-cmd">${safe(ev.command)}=${safe(ev.value)}</span>` +
            `<span class="verdict ${verdictClass(ev.verdict)}">${safe(ev.verdict)}</span>` +
            `<span class="t-why">${safe(String(ev.reason || "").split(" (")[0])}${safe(where)}</span>`;
        ticker.prepend(li);
        while (ticker.children.length > 8) ticker.removeChild(ticker.lastChild);
    }

    function ingest(ev) {
        if (!ev.source_ip) return;
        let s = sources.get(ev.source_ip);
        if (!s) {
            s = { ip: ev.source_ip, trusted: ev.trusted, sent: 0, pass: 0, alert: 0, drop: 0, first: ev.seq, lastSeen: ev.seq };
            sources.set(ev.source_ip, s);
        }
        if (ev.trusted !== null && ev.trusted !== undefined) s.trusted = ev.trusted;
        s.sent += 1;
        s.lastSeen = ev.seq;
        if (ev.verdict === "DROP") s.drop += 1; else if (ev.verdict === "ALERT") s.alert += 1; else s.pass += 1;
    }

    async function poll() {
        try {
            const r = await fetch(`/api/flow?since=${lastSeq}`, { cache: "no-store" });
            if (!r.ok) return;
            const data = await r.json();
            labels = data.labels || {};
            const evs = data.events || [];
            if (evs.length) {
                evs.forEach((ev) => ingest(ev));
                drawSources();
                for (const ev of evs.slice(-8)) addTicker(ev);
                if (initialised) {
                    evs.forEach((ev, i) => setTimeout(() => launch(ev, sources.get(ev.source_ip)), i * 120));
                }
                lastSeq = Math.max(lastSeq, data.last_seq || 0);
            } else if (data.last_seq < lastSeq) {
                lastSeq = data.last_seq;            // dashboard restarted: follow its counter again
            }
            initialised = true;
            status.textContent = sources.size ? `${sources.size} source host(s) seen` : "waiting for traffic";
        } catch (e) { /* the rest of the dashboard keeps working */ }
    }

    document.addEventListener("DOMContentLoaded", () => {
        svg = document.getElementById("flow-svg");
        ticker = document.getElementById("flow-ticker");
        status = document.getElementById("flow-status");
        if (!svg) return;
        drawStatic();
        poll();
        setInterval(poll, 700);
        requestAnimationFrame(step);
    });
})();
