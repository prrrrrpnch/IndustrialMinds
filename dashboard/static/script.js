// =========================================================
// INDUSTRIAL MIND DASHBOARD
// =========================================================

let cpuChart = null;


// =========================================================
// FETCH DASHBOARD DATA
// =========================================================

async function refreshDashboard() {

    try {

        const response = await fetch(
            "/api/dashboard",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const data = await response.json();

        updateOverview(
            data.overview || {}
        );

        updateScadaToPlc(
            data.scada_to_plc || []
        );

        updatePlcToScada(
            data.plc_to_scada || []
        );

        updateTelemetry(
            data.telemetry || {}
        );

        updateCpuChart(
            data.cpu_history || []
        );

        updateCpuValue(
            data.telemetry || {}
        );

    } catch (error) {

        console.error(
            "Dashboard update failed:",
            error
        );
    }
}


// =========================================================
// OVERVIEW
// =========================================================

function updateOverview(overview) {

    const total =
        document.getElementById(
            "kpi-total"
        );

    const pass =
        document.getElementById(
            "kpi-pass"
        );

    const drop =
        document.getElementById(
            "kpi-drop"
        );

    if (total) {

        total.textContent =
            overview.total_requests ?? 0;
    }

    if (pass) {

        pass.textContent =
            overview.pass ?? 0;
    }

    if (drop) {

        drop.textContent =
            overview.drop ?? 0;
    }
}


// =========================================================
// SCADA -> PLC TABLE
// =========================================================

function updateScadaToPlc(events) {

    const tbody =
        document.getElementById(
            "tbody-scada-plc"
        );

    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    events.forEach(event => {

        const row =
            document.createElement(
                "tr"
            );

        const verdict =
            String(
                event.verdict || "UNKNOWN"
            ).toUpperCase();

        row.innerHTML = `
            <td>${safe(event.timestamp)}</td>

            <td>
                <span class="transaction-id">
                    ${safe(event.tx_id)}
                </span>
            </td>

            <td>${safe(event.command)}</td>

            <td>
                <span class="verdict ${verdictClass(verdict)}">
                    ${safe(verdict)}
                </span>
            </td>

            <td>${safe(event.reason)}</td>

            <td>
                ${formatLatency(event.latency_ms)}
            </td>
        `;

        tbody.appendChild(row);
    });
}


// =========================================================
// PLC -> SCADA TABLE
// =========================================================

function updatePlcToScada(events) {

    const tbody =
        document.getElementById(
            "tbody-plc-scada"
        );

    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    events.forEach(event => {

        const row =
            document.createElement(
                "tr"
            );

        const verdict =
            String(
                event.verdict || "PASS"
            ).toUpperCase();

        row.innerHTML = `
            <td>${safe(event.timestamp)}</td>

            <td>
                <span class="transaction-id">
                    ${safe(event.tx_id)}
                </span>
            </td>

            <td>${safe(event.command)}</td>

            <td>
                <span class="verdict ${verdictClass(verdict)}">
                    ${safe(verdict)}
                </span>
            </td>

            <td>${safe(event.reason)}</td>

            <td>
                ${formatLatency(event.latency_ms)}
            </td>
        `;

        tbody.appendChild(row);
    });
}


// =========================================================
// TELEMETRY
// =========================================================

const _prevTelemetry = {};

function updateTelemetry(telemetry) {

    const registers =
        telemetry.registers || {};

    // One row per machine from the central config
    // (docs/interfaces.MACHINES, injected by the template).

    (window.IM_MACHINES || []).forEach(machine => {

        const value =
            Number(
                registers[machine.name] ?? 0
            );

        const range = machine.max - machine.min;
        const frac = range > 0
            ? Math.max(0, Math.min(1, (value - machine.min) / range))
            : 0;

        setText(
            `val-${machine.name}`,
            `${value.toFixed(1)}${unitSuffix(machine.unit)}`
        );

        setBar(
            `bar-${machine.name}`,
            value - machine.min,
            machine.max - machine.min
        );

        // Process graphics (tank fill / pH marker / pressure dial)
        const tank = document.getElementById(`tank-${machine.name}`);
        if (tank) {
            tank.style.height = `${frac * 100}%`;
        }
        const marker = document.getElementById(`gauge-${machine.name}`);
        if (marker) {
            if (marker.classList.contains("dial-needle")) {
                marker.style.transform =
                    `translateX(-50%) rotate(${-90 + frac * 180}deg)`;
            } else {
                marker.style.left = `${frac * 100}%`;
            }
        }

        // Highlight moves of more than 3% of range between polls
        const prev = _prevTelemetry[machine.name];
        if (prev !== undefined && range > 0 &&
            Math.abs(value - prev) > 0.03 * range) {
            flashPoint(machine.name);
        }
        _prevTelemetry[machine.name] = value;
    });
}


function flashPoint(name) {

    const el = document.getElementById(`row-${name}`);
    if (!el) {
        return;
    }
    el.classList.remove("changed");
    void el.offsetWidth;  // restart the CSS animation
    el.classList.add("changed");
    setTimeout(() => el.classList.remove("changed"), 1800);
}


function unitSuffix(unit) {

    if (unit === "deg") {
        return "°";
    }

    if (unit === "C") {
        return "°C";
    }

    return unit ? ` ${unit}` : "";
}


// =========================================================
// CPU VALUE
// =========================================================

function updateCpuValue(telemetry) {

    const element =
        document.getElementById(
            "val-cpu-load"
        );

    if (!element) {
        return;
    }

    const value =
        Number(
            telemetry.cpu_load ?? 0
        );

    element.textContent =
        `${value.toFixed(1)}%`;
}


// =========================================================
// BAR UPDATE
// =========================================================

function setBar(
    id,
    value,
    maximum
) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    const percentage =
        Math.max(
            0,
            Math.min(
                100,
                (value / maximum) * 100
            )
        );

    element.style.width =
        `${percentage}%`;
}


// =========================================================
// CPU GRAPH
// =========================================================

function updateCpuChart(history) {

    const canvas =
        document.getElementById(
            "cpuLoadChart"
        );

    if (!canvas) {
        return;
    }

    // MicroLineChart ships with the dashboard (static/vendor/microchart.js). It cannot fail to load from a CDN, because
    // there is no CDN; if it is ever missing that is a packaging bug and should be loud, not a silent empty panel.
    if (typeof MicroLineChart === "undefined") {
        canvas.insertAdjacentHTML(
            "afterend",
            '<p class="chart-missing">CPU chart unavailable: static/vendor/microchart.js did not load.</p>'
        );
        return;
    }

    const labels =
        history.map(
            point => point.time
        );

    const values =
        history.map(
            point =>
                Number(point.value)
        );

    if (!cpuChart) {

        cpuChart =
            new MicroLineChart(
                canvas,
                {
                    min: 0,
                    max: 100,
                    suffix: "%"
                }
            );
    }

    cpuChart.update(
        labels,
        values
    );
}


// =========================================================
// HELPERS
// =========================================================

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value;
    }
}


function formatLatency(value) {

    const number =
        Number(value);

    if (
        Number.isNaN(number)
    ) {

        return "—";
    }

    return `${number.toFixed(1)} ms`;
}


function verdictClass(verdict) {

    const value =
        String(
            verdict || ""
        ).toLowerCase();

    if (value === "alert") {
        return "alert";
    }

    if (value === "pass") {
        return "pass";
    }

    // AUDIT C1: approved by the agents, but the PLC never took it. Not a success and not a block - its own state, so the
    // operator cannot mistake it for a setpoint that was applied.
    if (value === "undelivered") {
        return "undelivered";
    }

    if (
        value === "drop" ||
        value === "alert" ||
        value === "blocked"
    ) {
        return "drop";
    }

    return "unknown";
}


function safe(value) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "—";
    }

    return String(value)
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


// =========================================================
// RESET
// =========================================================

async function resetDashboard() {

    try {

        const response =
            await fetch(
                "/api/reset",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    }
                }
            );

        const result =
            await response.json();

        if (!result.success) {

            console.error(
                "Reset failed:",
                result.error
            );

            return;
        }

        console.log(
            "[DASHBOARD] Reset successful"
        );

        await refreshDashboard();

    } catch (error) {

        console.error(
            "Reset failed:",
            error
        );
    }
}


// =========================================================
// BUTTON EVENTS
// =========================================================

function setupButtons() {

    const resetButton =
        document.getElementById(
            "btn-reset-data"
        );

    if (resetButton) {

        resetButton.addEventListener(
            "click",
            resetDashboard
        );
    }
}


// =========================================================
// BLOCKED IPS / BLOCKED SOURCES
// Real data from logs/blocked_attacks.jsonl via /api/blocked-ips
// =========================================================

let selectedBlockedIp = null;
let selectedAttackKey = null;
let blockedDetailRecords = [];


function blockedFilters() {

    return {
        attackType:
            document.getElementById("filter-attack-type")?.value || "",
        ip:
            (document.getElementById("filter-ip")?.value || "").trim()
    };
}


async function refreshBlockedIps() {

    const { attackType, ip } = blockedFilters();

    const params = new URLSearchParams();

    if (attackType) {
        params.set("attack_type", attackType);
    }

    if (ip) {
        params.set("ip", ip);
    }

    try {

        const response = await fetch(
            `/api/blocked-ips?${params.toString()}`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        updateAttackTypeOptions(data.attack_types || {});

        renderBlockedIps(data.sources || []);

        setText(
            "blocked-count",
            `${(data.sources || []).length} sources · ` +
            `${data.matching_records ?? 0} blocked attacks` +
            (data.matching_records !== data.total_records
                ? ` (of ${data.total_records})`
                : "")
        );

        setText(
            "blocked-log-info",
            data.log_file || "logs/blocked_attacks.jsonl"
        );

        if (selectedBlockedIp) {
            await loadBlockedDetail(selectedBlockedIp, false);
        }

    } catch (error) {

        console.error("Blocked IP update failed:", error);
    }
}


function updateAttackTypeOptions(counts) {

    const select =
        document.getElementById("filter-attack-type");

    if (!select) {
        return;
    }

    const current = select.value;

    const types = Object.keys(counts);

    if (current && !types.includes(current)) {
        types.push(current);
    }

    const signature = JSON.stringify(
        types.map(t => [t, counts[t] ?? 0])
    );

    if (select.dataset.signature === signature) {
        return;
    }

    select.dataset.signature = signature;

    select.innerHTML =
        `<option value="">All Attack Types</option>` +
        types.sort().map(t =>
            `<option value="${safe(t)}">${safe(t)} (${counts[t] ?? 0})</option>`
        ).join("");

    select.value = current;
}


function renderBlockedIps(sources) {

    const tbody =
        document.getElementById("tbody-blocked-ips");

    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    if (!sources.length) {

        tbody.innerHTML =
            `<tr><td colspan="7" class="empty-row">No blocked sources match the current filters.</td></tr>`;

        return;
    }

    sources.forEach(source => {

        const row = document.createElement("tr");

        row.className =
            "clickable-row" +
            (source.source_ip === selectedBlockedIp ? " selected-row" : "");

        const types =
            Object.entries(source.attack_types || {})
                .map(([t, n]) => `${safe(t)} ×${n}`)
                .join("<br>");

        row.innerHTML = `
            <td><span class="transaction-id ip-link">${safe(source.source_ip)}</span></td>
            <td><span class="verdict drop">${safe(source.attack_count)}</span></td>
            <td>${types || "—"}</td>
            <td>${safe(source.latest_attack_type)}</td>
            <td>${safe(source.latest_machine)}</td>
            <td class="reason-cell">${safe(source.latest_reason)}</td>
            <td>${safe(formatDateTime(source.last_seen))}</td>
        `;

        row.addEventListener(
            "click",
            () => loadBlockedDetail(source.source_ip, true)
        );

        tbody.appendChild(row);
    });
}


async function loadBlockedDetail(ip, userClick) {

    if (userClick) {

        selectedBlockedIp = ip;
        selectedAttackKey = null;

        document
            .querySelectorAll("#tbody-blocked-ips tr")
            .forEach(tr => tr.classList.toggle(
                "selected-row",
                tr.querySelector(".ip-link")?.textContent === ip
            ));
    }

    const { attackType } = blockedFilters();

    const params = new URLSearchParams();

    if (attackType) {
        params.set("attack_type", attackType);
    }

    try {

        const response = await fetch(
            `/api/blocked-ips/${encodeURIComponent(ip)}?${params.toString()}`,
            { cache: "no-store" }
        );

        const data = await response.json();

        blockedDetailRecords = data.attacks || [];

        const panel = document.getElementById("blocked-detail");

        if (panel) {
            panel.style.display = "block";
        }

        setText(
            "blocked-detail-title",
            `${ip} · ${data.count} blocked attack${data.count === 1 ? "" : "s"}` +
            (attackType ? ` · ${attackType}` : "")
        );

        renderBlockedDetail(blockedDetailRecords);

        if (userClick && blockedDetailRecords.length) {
            showAttackRecord(blockedDetailRecords[0]);
        } else if (selectedAttackKey) {
            const rec = blockedDetailRecords.find(r => attackKey(r) === selectedAttackKey);
            if (rec) {
                showAttackRecord(rec);
            }
        }

        if (userClick && panel) {
            panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }

    } catch (error) {

        console.error("Blocked IP detail failed:", error);
    }
}


function attackKey(record) {

    return `${record.tx_id}|${record.timestamp}`;
}


function renderBlockedDetail(records) {

    const tbody =
        document.getElementById("tbody-blocked-detail");

    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    if (!records.length) {

        tbody.innerHTML =
            `<tr><td colspan="10" class="empty-row">No attacks for this source match the selected attack type.</td></tr>`;

        return;
    }

    records.forEach(record => {

        const row = document.createElement("tr");

        row.className =
            "clickable-row" +
            (attackKey(record) === selectedAttackKey ? " selected-row" : "");

        row.innerHTML = `
            <td>${safe(formatDateTime(record.timestamp))}</td>
            <td><span class="transaction-id">${safe(String(record.tx_id || "").slice(0, 8))}</span></td>
            <td>${safe(record.attack_type)}</td>
            <td>${safe(record.machine)}<br><span class="muted">${safe(record.register_name)} (reg ${safe(record.register)})</span></td>
            <td>${formatValue(record.requested_value, record.unit)}</td>
            <td>${formatValue(record.current_value, record.unit)}</td>
            <td><span class="verdict ${record.cyber?.verdict === "PASS" ? "pass" : "drop"}">${safe(record.cyber?.verdict)}</span></td>
            <td><span class="verdict ${record.physical?.verdict === "PASS" ? "pass" : "drop"}">${safe(record.physical?.verdict)}</span></td>
            <td><span class="verdict drop">${safe(record.orchestrator?.decision)}</span></td>
            <td>${formatLatency(record.latency_ms)}</td>
        `;

        row.addEventListener(
            "click",
            () => showAttackRecord(record)
        );

        tbody.appendChild(row);
    });
}


function showAttackRecord(record) {

    selectedAttackKey = attackKey(record);

    document
        .querySelectorAll("#tbody-blocked-detail tr")
        .forEach((tr, i) => tr.classList.toggle(
            "selected-row",
            blockedDetailRecords[i] && attackKey(blockedDetailRecords[i]) === selectedAttackKey
        ));

    const box = document.getElementById("attack-record");

    if (!box) {
        return;
    }

    const fields = [
        ["Time", record.time],
        ["Source IP", record.source_ip],
        ["Source port", record.source_port],
        ["Attack type", record.attack_type],
        ["Reason code", record.reason_code],
        ["Transaction ID", record.tx_id],
        ["Direction", record.direction],
        ["Modbus function code", record.function_code],
        ["Machine", record.machine],
        ["Register", `${record.register_name} (address ${record.register})`],
        ["Requested value", formatValue(record.requested_value, record.unit, true)],
        ["Current value", formatValue(record.current_value, record.unit, true)],
        ["HMAC signature", record.signature],
        ["HMAC status", record.hmac_status],
        ["Cyber Agent", `${record.cyber?.verdict} — ${record.cyber?.reason}`],
        ["Physical Agent", `${record.physical?.verdict} — ${record.physical?.reason}`],
        ["Orchestrator", `${record.orchestrator?.decision} — ${record.orchestrator?.reason}`],
        ["Latency", formatLatency(record.latency_ms)],
    ];

    box.innerHTML =
        `<div class="attack-record-grid">` +
        fields.map(([k, v]) =>
            `<span class="attack-record-key">${safe(k)}</span>` +
            `<span class="attack-record-val">${safe(v)}</span>`
        ).join("") +
        `</div>`;

    box.style.display = "block";
}


function closeBlockedDetail() {

    selectedBlockedIp = null;
    selectedAttackKey = null;

    const panel = document.getElementById("blocked-detail");

    if (panel) {
        panel.style.display = "none";
    }

    document
        .querySelectorAll("#tbody-blocked-ips tr")
        .forEach(tr => tr.classList.remove("selected-row"));
}


function formatDateTime(ts) {

    const n = Number(ts);

    if (!ts || Number.isNaN(n)) {
        return "";
    }

    const d = new Date(n * 1000);

    return d.toLocaleDateString() + " " + d.toLocaleTimeString();
}


function formatValue(value, unit, plain) {

    if (value === null || value === undefined || value === "") {
        return plain ? "—" : "—";
    }

    const n = Number(value);

    const text = Number.isNaN(n)
        ? String(value)
        : `${n.toFixed(2)}${unitSuffix(unit)}`;

    return plain ? text : safe(text);
}


function setupBlockedSection() {

    const select = document.getElementById("filter-attack-type");
    const input = document.getElementById("filter-ip");
    const close = document.getElementById("btn-close-detail");

    let debounce = null;

    if (select) {
        select.addEventListener("change", refreshBlockedIps);
    }

    if (input) {
        input.addEventListener("input", () => {
            clearTimeout(debounce);
            debounce = setTimeout(refreshBlockedIps, 250);
        });
    }

    if (close) {
        close.addEventListener("click", closeBlockedDetail);
    }
}


// =========================================================
// START
// =========================================================

// =========================================================
// PACKET TRACER (Phase 9): per-tx hop-by-hop view
// =========================================================

let tracerSelected = null;     // full tx_id the user clicked; null = follow the latest
let tracerLastKey = "";

const HOP_TITLES = {
    arrival: "1  Arrival (network)",
    cyber_rules: "2  Cyber Agent - rules",
    cyber_model: "3  Cyber model (advisory)",
    physical_rules: "4  Physical Agent - rules",
    physical_model: "5  Physical model (advisory)",
    orchestrator: "6  Orchestrator - fusion",
    outcome: "7  Outcome",
};

function fmtVal(v) {
    if (v === null || v === undefined) return "—";
    if (typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}=${fmtVal(x)}`).join(", ");
    if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(Math.round(v * 10000) / 10000);
    return String(v);
}

function renderTrace(t) {
    const box = document.getElementById("tracer-detail");
    if (!box) return;
    const head = `<div class="tracer-head"><b>${safe(t.short_id)}</b> <span class="verdict ${verdictClass(t.verdict)}">${safe(t.verdict)}</span> ` +
        `<span class="tracer-reason">${safe(t.reason)}</span> <span class="tracer-id">${safe(t.tx_id)}</span></div>`;
    const hops = (t.hops || []).map((h) => {
        const checks = (h.checks || []).map((c) =>
            `<li class="chk chk-${String(c.result).toLowerCase()}"><span class="chk-name">${safe(c.check)}</span>` +
            `<span class="chk-res">${safe(c.result)}</span><span class="chk-detail">${safe(c.detail)}</span></li>`).join("");
        const vals = Object.entries(h.values || {}).map(([k, v]) =>
            `<div class="kv"><span class="k">${safe(k)}</span><span class="v">${safe(fmtVal(v))}</span></div>`).join("");
        const ms = (h.ms === null || h.ms === undefined) ? "" : `<span class="hop-ms">${fmtVal(h.ms)} ms</span>`;
        return `<div class="hop hop-${String(h.outcome).toLowerCase()}"><div class="hop-title">${safe(HOP_TITLES[h.hop] || h.hop)}` +
            `<span class="hop-outcome">${safe(h.outcome)}</span>${ms}</div>${checks ? `<ul class="chk-list">${checks}</ul>` : ""}<div class="kvs">${vals}</div></div>`;
    }).join('<div class="hop-arrow">&#9660;</div>');
    const tm = Object.entries(t.timings_ms || {}).map(([k, v]) => `${k} ${fmtVal(v)} ms`).join("  ·  ");
    box.innerHTML = head + hops + (tm ? `<div class="tracer-timings">timings: ${safe(tm)}</div>` : "");
}

async function refreshTracer() {
    try {
        const r = await fetch("/api/traces", { cache: "no-store" });
        if (!r.ok) return;
        const list = await r.json();
        const ul = document.getElementById("tracer-list");
        if (!ul) return;
        const key = JSON.stringify(list.map((x) => x.tx_id)) + tracerSelected;
        if (key !== tracerLastKey) {
            tracerLastKey = key;
            ul.innerHTML = list.map((x) =>
                `<li class="tr-item${x.tx_id === (tracerSelected || (list[0] && list[0].tx_id)) ? " sel" : ""}" data-tx="${safe(x.tx_id)}">` +
                `<span class="tr-id">${safe(x.short_id)}</span><span class="verdict ${verdictClass(x.verdict)}">${safe(x.verdict)}</span>` +
                `<span class="tr-cmd">${safe(x.command)}=${safe(x.value)}</span></li>`).join("");
            ul.querySelectorAll(".tr-item").forEach((li) => li.addEventListener("click", () => {
                const first = ul.querySelector('.tr-item');
                tracerSelected = (li === first) ? null : li.dataset.tx;   // newest item = follow live
                tracerLastKey = "";
                refreshTracer();
            }));
        }
        const follow = document.getElementById("tracer-follow");
        if (follow) follow.textContent = tracerSelected ? "pinned (click the newest item to follow)" : "following latest";
        const target = tracerSelected || (list[0] && list[0].tx_id);
        if (!target) return;
        const d = await fetch(`/api/trace/${encodeURIComponent(target)}`, { cache: "no-store" });
        if (d.ok) renderTrace(await d.json());
    } catch (e) { /* dashboard keeps running without the tracer */ }
}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupButtons();

        refreshTracer();
        setInterval(refreshTracer, 1000);

        setupBlockedSection();

        refreshDashboard();

        refreshBlockedIps();

        setInterval(
            refreshDashboard,
            1000
        );

        setInterval(
            refreshBlockedIps,
            3000
        );
    }
);