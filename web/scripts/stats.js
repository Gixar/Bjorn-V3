// stats.js — live stats dashboard client (WebSocket + polling fallback)

const STAT_KEYS = [
    "coins", "level", "known_hosts", "vulnerabilities",
    "credentials_cracked", "data_stolen", "zombies", "attacks",
    "targets", "open_ports",
];

const MAX_CHART_POINTS = 60;
const CHART_TRACKED = ["coins", "known_hosts", "vulnerabilities", "attacks"];
const CHART_COLORS = {
    coins: "#e99f00",
    known_hosts: "#42ced3",
    vulnerabilities: "#ff5555",
    attacks: "#12b800",
};

let ws = null;
let wsRetryCount = 0;
let pollTimer = null;
let chart = null;
let chartLabels = [];
let chartData = { coins: [], known_hosts: [], vulnerabilities: [], attacks: [] };

function setIndicator(state, text) {
    const el = document.getElementById("ws-indicator");
    const textEl = document.getElementById("ws-indicator-text");
    if (!el || !textEl) return;
    el.className = "ws-indicator ws-" + state;
    textEl.textContent = text;
}

function applySnapshot(data) {
    STAT_KEYS.forEach((key) => {
        const el = document.getElementById("stat-" + key);
        if (el && data[key] !== undefined) el.textContent = data[key];
    });

    const orchBadge = document.getElementById("orchestrator-badge");
    if (orchBadge) {
        orchBadge.textContent = "Orchestrator: " + (data.orchestrator_status || "—");
        orchBadge.className = "status-badge " + (data.orchestrator_status === "IDLE" ? "badge-idle" : "badge-active");
    }

    const wifiBadge = document.getElementById("wifi-badge");
    if (wifiBadge) {
        wifiBadge.textContent = data.wifi_connected ? "Wi-Fi: connected" : "Wi-Fi: disconnected";
        wifiBadge.className = "status-badge " + (data.wifi_connected ? "badge-good" : "badge-bad");
    }

    const modeBadge = document.getElementById("mode-badge");
    if (modeBadge) {
        modeBadge.textContent = data.manual_mode ? "Mode: manual" : "Mode: auto";
        modeBadge.className = "status-badge badge-idle";
    }

    pushChartPoint(data);
}

function pushChartPoint(data) {
    if (!chart) return;
    const label = new Date(data.timestamp || Date.now()).toLocaleTimeString();
    chartLabels.push(label);
    CHART_TRACKED.forEach((key) => chartData[key].push(data[key] || 0));

    if (chartLabels.length > MAX_CHART_POINTS) {
        chartLabels.shift();
        CHART_TRACKED.forEach((key) => chartData[key].shift());
    }

    chart.data.labels = chartLabels;
    chart.data.datasets.forEach((ds) => {
        ds.data = chartData[ds.statKey];
    });
    chart.update("none");
}

function initChart() {
    const ctx = document.getElementById("stats-chart");
    if (!ctx || typeof Chart === "undefined") return;

    chart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: CHART_TRACKED.map((key) => ({
                statKey: key,
                label: key.replace("_", " "),
                data: [],
                borderColor: CHART_COLORS[key],
                backgroundColor: CHART_COLORS[key] + "33",
                tension: 0.25,
                pointRadius: 0,
                borderWidth: 2,
            })),
        },
        options: {
            responsive: true,
            animation: false,
            scales: {
                x: { ticks: { color: "#999", maxTicksLimit: 8 }, grid: { color: "#333" } },
                y: { ticks: { color: "#999" }, grid: { color: "#333" }, beginAtZero: true },
            },
            plugins: {
                legend: { labels: { color: "#e0e0e0" } },
            },
        },
    });
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/stats`;

    try {
        ws = new WebSocket(url);
    } catch (e) {
        scheduleReconnectOrFallback();
        return;
    }

    ws.onopen = () => {
        wsRetryCount = 0;
        stopPolling();
        setIndicator("connected", "Live");
    };

    ws.onmessage = (event) => {
        try {
            applySnapshot(JSON.parse(event.data));
        } catch (e) {
            console.error("Error parsing stats WS message:", e);
        }
    };

    ws.onclose = () => {
        setIndicator("connecting", "Reconnecting…");
        scheduleReconnectOrFallback();
    };

    ws.onerror = () => {
        try { ws.close(); } catch (_) {}
    };
}

function scheduleReconnectOrFallback() {
    wsRetryCount += 1;
    if (wsRetryCount <= 5) {
        setTimeout(connectWebSocket, Math.min(1000 * wsRetryCount, 5000));
    } else {
        setIndicator("polling", "Live (polling)");
        startPolling();
    }
}

function startPolling() {
    if (pollTimer) return;
    pollOnce();
    pollTimer = setInterval(pollOnce, 3000);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

function pollOnce() {
    fetch("/api/stats")
        .then((r) => r.json())
        .then(applySnapshot)
        .catch((e) => console.error("Error polling /api/stats:", e));
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    initChart();
    pollOnce();
    connectWebSocket();
});

document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
        stopPolling();
    } else if (!ws || ws.readyState !== WebSocket.OPEN) {
        startPolling();
    }
});
