/*
 * ui.js - small presentation helpers for the dashboard (no data logic):
 *   - a live clock in the header,
 *   - the extra KPI cards (ALERT / UNDELIVERED / BLOCK RATE), filled from the same /api/dashboard poll,
 *   - collapsible sections (click a section title; the choice is remembered in this browser only).
 * Everything here is optional: if it fails, the dashboard still works.
 */
(function () {
    "use strict";

    function setText(id, text) {
        var el = document.getElementById(id);
        if (el) { el.textContent = text; }
    }

    // ---- clock -----------------------------------------------------------
    function tick() {
        var d = new Date();
        function p(n) { return (n < 10 ? "0" : "") + n; }
        setText("live-clock", p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()));
    }
    tick();
    setInterval(tick, 1000);

    // ---- extra KPI cards ---------------------------------------------------
    var polling = false;
    function refreshKpis() {
        if (polling) { return; }
        polling = true;
        fetch("/api/dashboard", { cache: "no-store" })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                var o = (d && d.overview) || {};
                var total = o.total_requests || 0;
                setText("kpi-alert", String(o.alert || 0));
                setText("kpi-undelivered", String(o.undelivered || 0));
                setText("kpi-rate", total ? Math.round(100 * (o.drop || 0) / total) + "%" : "0%");
                var cards = document.querySelectorAll(".summary-card.alert, .summary-card.undelivered");
                cards.forEach(function (c) {
                    var v = c.querySelector(".card-value");
                    c.classList.toggle("lit", !!v && v.textContent !== "0");
                });
            })
            .catch(function () { /* the main poll already reports a dead dashboard */ })
            .then(function () { polling = false; });
    }
    refreshKpis();
    setInterval(refreshKpis, 2000);

    // ---- collapsible sections ------------------------------------------------
    var KEY = "im-collapsed";
    function load() {
        try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { return {}; }
    }
    function save(state) {
        try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* private window: fine */ }
    }
    var state = load();

    document.querySelectorAll("section.card[id]").forEach(function (sec) {
        var head = sec.querySelector(".card-header h2");
        if (!head) { return; }
        head.classList.add("collapsible");
        head.setAttribute("role", "button");
        head.setAttribute("tabindex", "0");
        head.setAttribute("title", "click to collapse / expand");
        if (state[sec.id]) { sec.classList.add("collapsed"); }
        function toggle() {
            var now = sec.classList.toggle("collapsed");
            state[sec.id] = now;
            save(state);
        }
        head.addEventListener("click", toggle);
        head.addEventListener("keydown", function (e) {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
        });
    });

    // ---- highlight the nav link of the section in view ---------------------------
    var links = Array.prototype.slice.call(document.querySelectorAll(".top-nav a"));
    if ("IntersectionObserver" in window && links.length) {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (en) {
                if (!en.isIntersecting) { return; }
                links.forEach(function (a) {
                    a.classList.toggle("active", a.getAttribute("href") === "#" + en.target.id);
                });
            });
        }, { rootMargin: "-20% 0px -70% 0px" });
        links.forEach(function (a) {
            var t = document.querySelector(a.getAttribute("href"));
            if (t) { io.observe(t); }
        });
    }
})();
