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

        setText(
            `val-${machine.name}`,
            `${value.toFixed(1)}${unitSuffix(machine.unit)}`
        );

        setBar(
            `bar-${machine.name}`,
            value - machine.min,
            machine.max - machine.min
        );
    });
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

    if (typeof Chart === "undefined") {

        console.error(
            "Chart.js is not loaded."
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

    if (cpuChart) {

        cpuChart.data.labels =
            labels;

        cpuChart.data.datasets[0].data =
            values;

        cpuChart.update(
            "none"
        );

        return;
    }

    const ctx =
        canvas.getContext(
            "2d"
        );

    cpuChart =
        new Chart(
            ctx,
            {
                type: "line",

                data: {

                    labels: labels,

                    datasets: [
                        {
                            label:
                                "CPU Load (%)",

                            data: values,

                            borderWidth: 2,

                            fill: true,

                            tension: 0.3,

                            pointRadius: 0
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    animation: false,

                    scales: {

                        x: {
                            ticks: {
                                maxTicksLimit: 8
                            }
                        },

                        y: {

                            beginAtZero: true,

                            min: 0,

                            max: 100,

                            ticks: {

                                callback:
                                    value =>
                                        `${value}%`
                            }
                        }
                    },

                    plugins: {

                        legend: {
                            display: false
                        }
                    }
                }
            }
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

    if (value === "pass") {
        return "pass";
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
// ATTACK PANEL
// =========================================================

function toggleAttackPanel() {

    const panel =
        document.getElementById(
            "attack-panel"
        );

    if (!panel) {
        return;
    }

    if (
        panel.style.display === "none" ||
        panel.style.display === ""
    ) {

        panel.style.display =
            "block";

    } else {

        panel.style.display =
            "none";
    }
}


// =========================================================
// TRIGGER ATTACK
// =========================================================

async function triggerAttack(attack) {

    try {

        const response =
            await fetch(
                "/api/trigger-attack",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        attack: attack,
                        source_ip:
                            (document.getElementById("attack-source-ip")?.value || "").trim()
                    })
                }
            );

        const result =
            await response.json();

        console.log(
            "Attack:",
            result
        );

        if (!result.success) {

            console.error(
                "Attack rejected:",
                result.error
            );

            return;
        }

        console.log(
            `[DASHBOARD] ${attack} launched`
        );

    } catch (error) {

        console.error(
            "Attack failed:",
            error
        );
    }
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

    const attackButton =
        document.getElementById(
            "btn-trigger-attack"
        );

    const resetButton =
        document.getElementById(
            "btn-reset-data"
        );

    if (attackButton) {

        attackButton.addEventListener(
            "click",
            toggleAttackPanel
        );
    }

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

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupButtons();

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