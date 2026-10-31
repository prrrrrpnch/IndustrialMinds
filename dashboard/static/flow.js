// =========================================================
// LIVE NETWORK FLOW
// Every command the middleware received, drawn from the host that really sent it, through the
// middleware's layers, to the PLC (or stopped at the layer that caught it). Driven by /api/flow,
// which is built from the same per-command traces as the Packet Tracer (nothing is simulated here).
//
// What each source host IS (operator / attacker) comes from the lab setup (IM_HOST_ROLES), not from the
// middleware's source whitelist: a whitelisted address may SEND, it is not thereby trusted.
// =========================================================

(function () {
    const SVG_NS = "http://www.w3.org/2000/svg";
    const MAX_SOURCES = 5;
    const MAX_DOTS = 40;            // dots on screen at once; further commands wait in the queue below instead of being dropped
    const MAX_BACKLOG = 60;         // a longer queue (a flood, a hidden tab) skips the oldest animations; counts stay exact
    const LAUNCH_GAP_MS = 110;      // spacing between launches, so a burst reads as a stream rather than one blob
    const SEG_MS = 260;
    const POLL_MS = 700;

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

    let svg, status;
    let lastSeq = 0;
    let initialised = false;
    let polling = false;
    let labels = {};
    let roles = {};
    let lastLaunch = 0;
    const sources = new Map();          // ip -> {ip, whitelisted, sent, pass, alert, drop, first, lastSeen, y, node}
    const dots = [];                    // animations in flight
    const pending = [];                 // commands waiting to be drawn

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

    // ---- source hosts --------------------------------------------------------------------------------------------
    function roleOf(s) { return roles[s.ip] || null; }

    function isHostile(s) { return roleOf(s) === "attacker" || s.whitelisted === false; }

    // The legitimate sender is SCADA. On a one-computer run every sender shares the loopback address, which the
    // dashboard labels "this machine" - that traffic is SCADA's, so it is drawn as SCADA too.
    function isScada(s) {
        const r = roleOf(s);
        return r === "operator" || (r === null && labels[s.ip] === "this machine");
    }

    function hostName(s) {
        const r = roleOf(s);
        if (r === "attacker") return labels[s.ip] || "Attacker laptop";
        if (isScada(s)) return "SCADA";
        return labels[s.ip] || "host";
    }

    // Like the PLC node (":5020"), the sender's node just names the port it talks to; no counters.
    function hostDetail(s) {
        const r = roleOf(s);
        if (r === "attacker") return `${s.ip}  ·  attacker (untrusted host)  →  :5021`;
        if (s.whitelisted === false) return `${s.ip}  ·  not on the whitelist  →  :5021`;
        return `${s.ip}  →  :5021`;
    }

    function visibleSources() {
        return [...sources.values()].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, MAX_SOURCES)
            .sort((a, b) => a.first - b.first);
    }

    function nodeClass(s) {
        const r = roleOf(s);
        return r === "attacker" ? "flow-src attacker" : r === "operator" ? "flow-src operator" : s.whitelisted === false ? "flow-src attacker" : "flow-src";
    }

    // Source nodes are created once and updated in place: rebuilding them on every poll made the whole left side flicker.
    function syncSources() {
        const edges = svg.querySelector("#flow-edges");
        const g = svg.querySelector("#flow-sources");
        const vis = visibleSources();
        const visIps = new Set(vis.map((s) => s.ip));
        for (const s of sources.values()) {
            if (!visIps.has(s.ip) && s.node) { s.node.group.remove(); s.node.edge.remove(); s.node = null; s.y = undefined; }
        }
        const gap = 300 / Math.max(vis.length, 1);
        vis.forEach((s, i) => {
            s.y = 30 + gap * i + gap / 2;
            if (!s.node) {
                const group = el("g", {}, g);
                s.node = {
                    group,
                    edge: el("line", {}, edges),
                    rect: el("rect", { x: 10, width: 270, height: 48, rx: 10 }, group),
                    name: text(group, 145, 0, "", "flow-title"),
                    detail: text(group, 145, 0, "", "flow-sub"),
                };
            }
            const n = s.node;
            n.edge.setAttribute("x1", 280); n.edge.setAttribute("y1", s.y);
            n.edge.setAttribute("x2", P.entry[0]); n.edge.setAttribute("y2", P.entry[1]);
            n.edge.setAttribute("class", isHostile(s) ? "flow-edge hostile" : "flow-edge");
            n.rect.setAttribute("y", s.y - 24);
            n.rect.setAttribute("class", nodeClass(s));
            n.name.setAttribute("y", s.y - 4); n.name.textContent = hostName(s);
            n.detail.setAttribute("y", s.y + 14); n.detail.textContent = hostDetail(s);
        });
    }

    // ---- animation -------------------------------------------------------------------------------------------------
    function flash(id, cls) {
        const b = svg.querySelector(`#flow-box-${id}`);
        if (!b) return;
        b.classList.add(cls);
        setTimeout(() => b.classList.remove(cls), 450);
    }

    function verdictColour(ev) {
        return ev.verdict === "DROP" || ev.verdict === "UNDELIVERED" ? "dot-drop" : ev.verdict === "ALERT" ? "dot-alert" : "dot-pass";
    }

    function launch(ev, now) {
        const src = sources.get(ev.source_ip);
        if (!src || src.y === undefined) return;            // a host that is not on screen has no lane to travel along
        const path = [[280, src.y], P.entry, P.cyber];
        if (ev.stopped_at !== "cyber") path.push(P.physical);
        if (!ev.stopped_at) path.push(P.orch, P.exit, P.plc);
        const colour = verdictColour(ev);
        const c = el("circle", { r: 7, cx: path[0][0], cy: path[0][1], class: `flow-dot ${isHostile(src) ? "dot-untrusted" : colour}` },
            svg.querySelector("#flow-dots"));
        dots.push({ c, path, t0: now, ev, colour });
    }

    function arrive(d) {
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
    }

    function drainPending(now) {
        while (pending.length > MAX_BACKLOG) pending.shift();               // too far behind: skip the oldest animations
        while (pending.length && dots.length < MAX_DOTS && now - lastLaunch >= LAUNCH_GAP_MS) {
            launch(pending.shift(), now);
            lastLaunch = now;
        }
    }

    function step() {
        // Re-arm FIRST. This loop used to re-arm at its end, so a single exception inside it ended the animation for good:
        // every dot froze where it was and the on-screen count climbed to the cap, after which new packets were dropped.
        requestAnimationFrame(step);
        const now = performance.now();           // ONE clock for launch and update (the rAF timestamp can precede a launch's time)
        drainPending(now);
        for (let i = dots.length - 1; i >= 0; i--) {
            const d = dots[i];
            try {
                const k = Math.max(0, (now - d.t0) / SEG_MS);
                const seg = Math.floor(k);
                if (seg >= d.path.length - 1) {
                    arrive(d);
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
            } catch (e) {
                d.c.remove();                    // one broken dot must never stop the others
                dots.splice(i, 1);
            }
        }
    }

    // ---- data ----------------------------------------------------------------------------------------------------------
    function ingest(ev) {
        if (!ev.source_ip) return;
        const wl = ev.whitelisted !== undefined ? ev.whitelisted : ev.trusted;
        let s = sources.get(ev.source_ip);
        if (!s) {
            s = { ip: ev.source_ip, whitelisted: wl, sent: 0, pass: 0, alert: 0, drop: 0, first: ev.seq, lastSeen: ev.seq, y: undefined, node: null };
            sources.set(ev.source_ip, s);
        }
        if (wl !== null && wl !== undefined) s.whitelisted = wl;
        s.sent += 1;
        s.lastSeen = ev.seq;
        if (ev.verdict === "DROP") s.drop += 1; else if (ev.verdict === "ALERT") s.alert += 1; else s.pass += 1;
    }

    async function poll() {
        if (polling) return;                      // never overlap: two requests with the same `since` would deliver every event twice
        polling = true;
        try {
            const r = await fetch(`/api/flow?since=${lastSeq}`, { cache: "no-store" });
            if (!r.ok) return;
            const data = await r.json();
            labels = data.labels || {};
            roles = data.roles || {};
            const evs = data.events || [];
            if (evs.length) {
                evs.forEach((ev) => ingest(ev));
                syncSources();
                if (initialised && !document.hidden) evs.forEach((ev) => pending.push(ev));
                lastSeq = Math.max(lastSeq, data.last_seq || 0);
            } else if (data.last_seq < lastSeq) {
                lastSeq = data.last_seq;            // dashboard restarted: follow its counter again
            }
            initialised = true;
            status.textContent = sources.size ? `${sources.size} source host(s) seen` : "waiting for traffic";
        } catch (e) { /* the rest of the dashboard keeps working */ }
        finally {
            polling = false;
            setTimeout(poll, POLL_MS);
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        svg = document.getElementById("flow-svg");
        status = document.getElementById("flow-status");
        if (!svg) return;
        drawStatic();
        poll();
        requestAnimationFrame(step);
    });
})();
