/* logs.js — dedicated LOGS page. Rendering lives in common.js. */

const maxLines = 2000;
let logInterval = null;
let isConsoleOn = false;
let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 11 : 12.5;

function fetchLogs() {
    fetch("/get_logs")
        .then((r) => r.text())
        .then((data) => {
            const el = document.getElementById("log-console");
            if (el) renderLogsInto(el, data, maxLines);
        })
        .catch((e) => console.error("fetch logs", e));
}

function toggleConsole() {
    const img = document.getElementById("toggle-console-image");
    const label = document.getElementById("console-state-label");
    isConsoleOn = !isConsoleOn;
    if (isConsoleOn) {
        if (!logInterval) {
            fetchLogs();
            logInterval = setInterval(fetchLogs, 1500);
        }
        if (img) img.src = "/web/images/on.png";
        if (label) label.textContent = "Stop";
    } else {
        if (logInterval) {
            clearInterval(logInterval);
            logInterval = null;
        }
        if (img) img.src = "/web/images/off.png";
        if (label) label.textContent = "Start";
    }
}

function clearConsoleView() {
    const el = document.getElementById("log-console");
    if (el) el.innerHTML = "";
}

function adjustFontSize(change) {
    fontSize += change;
    const el = document.getElementById("log-console");
    if (el) el.style.fontSize = fontSize + "px";
}

// Auto-start streaming on load — a dedicated logs page is expected to be live.
document.addEventListener("DOMContentLoaded", () => toggleConsole());
