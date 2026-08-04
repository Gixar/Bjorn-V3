/* common.js — shared navigation, toasts, and helpers for Bjorn web UI */

const STATS_SVG = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M4 20V10M12 20V4M20 20v-7" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const LOGS_SVG = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M4 6h16M4 12h16M4 18h10" stroke-linecap="round"/>
</svg>`;

const TELEGRAM_SVG = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M21 4L3 11l6 2 2 6 3-4 4 3 3-14z" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const BLE_SVG = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M7 8l10 8-5 4V4l5 4L7 16" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const BJORN_NAV = [
    { href: "/index.html", label: "Home", icon: "/web/images/console_icon.png", match: ["/", "/index.html"] },
    { href: "/stats.html", label: "Stats", svg: STATS_SVG, match: ["/stats.html"] },
    { href: "/network.html", label: "Network", icon: "/web/images/network_icon.png", match: ["/network.html"] },
    { href: "/netkb.html", label: "NetKB", icon: "/web/images/netkb_icon.png", match: ["/netkb.html"] },
    { href: "/credentials.html", label: "Creds", icon: "/web/images/cred_icon.png", match: ["/credentials.html"] },
    { href: "/loot.html", label: "Loot", icon: "/web/images/loot_icon.png", match: ["/loot.html"] },
    { href: "/config.html", label: "Config", icon: "/web/images/config_icon.png", match: ["/config.html"] },
    { href: "/bjorn.html", label: "Screen", icon: "/web/images/bjorn_icon.png", match: ["/bjorn.html"] },
    { href: "/logs.html", label: "Logs", svg: LOGS_SVG, match: ["/logs.html"] },
    { href: "/telegram.html", label: "Telegram", svg: TELEGRAM_SVG, match: ["/telegram.html"] },
    { href: "/ble.html", label: "BLE", svg: BLE_SVG, match: ["/ble.html"] },
];

function currentPath() {
    let p = window.location.pathname || "/";
    if (p === "" || p === "/") return "/index.html";
    return p;
}

function isActive(item) {
    const path = currentPath();
    return (item.match || [item.href]).some((m) => path === m || path.endsWith(m));
}

/** Inject the shared top navigation into #app-nav (or create it). */
function renderNav(extraStatusHtml = "") {
    let host = document.getElementById("app-nav");
    if (!host) {
        host = document.createElement("nav");
        host.id = "app-nav";
        host.className = "topnav";
        document.body.prepend(host);
    }

    const links = BJORN_NAV.map((item) => {
        const active = isActive(item) ? " active" : "";
        const icon = item.svg
            ? item.svg
            : `<img src="${item.icon}" alt="">`;
        return `<a class="nav-link${active}" href="${item.href}" title="${item.label}">
            ${icon}
            <span>${item.label}</span>
        </a>`;
    }).join("");

    host.innerHTML = `
        <a class="topnav-brand" href="/index.html" title="Bjorn Home">
            <img src="/web/images/bjorn_icon.png" alt="Bjorn">
            <div class="topnav-brand-text">Bjorn<span>Cyberviking</span></div>
        </a>
        <div class="topnav-links">${links}</div>
        <div class="topnav-status" id="topnav-status">${extraStatusHtml}</div>
    `;
}

// ---------------------------------------------------------------------------
// Log console rendering (shared by the home dashboard and the Logs page).
// Log lines carry scan/target-controlled text, so escape before decorating.
// ---------------------------------------------------------------------------
const LOG_LEVEL_CLASSES = {
    DEBUG: "debug", INFO: "info", WARNING: "warning",
    ERROR: "error", CRITICAL: "critical", SUCCESS: "success",
};
const _logFileColors = new Map();

/** HTML-escape untrusted text before it touches innerHTML. */
function escHtml(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function _logRandomColor() {
    const letters = "89ABCDEF";
    let color = "#";
    for (let i = 0; i < 6; i++) color += letters[Math.floor(Math.random() * letters.length)];
    return color;
}

/** Escape a raw log line, then decorate filenames/levels/numbers. Returns null to skip. */
function colorizeLogLine(line) {
    if (line.includes("==>") || line.includes("<==")) return null;
    let modified = escHtml(line);

    modified = modified.replace(/\w+\.py/g, (fileName) => {
        if (!_logFileColors.has(fileName)) _logFileColors.set(fileName, _logRandomColor());
        return `<span style="color:${_logFileColors.get(fileName)}">${fileName}</span>`;
    });

    modified = modified.replace(/\b(DEBUG|INFO|WARNING|ERROR|CRITICAL|SUCCESS)\b/g, (m) =>
        `<span class="${LOG_LEVEL_CLASSES[m]}">${m}</span>`
    );
    modified = modified.replace(/^\d+/, (m) => `<span class="line-number">${m}</span>`);
    modified = modified.replace(/\b\d+\b/g, (m) => `<span class="number">${m}</span>`);
    return modified;
}

/** Render raw /get_logs text into an element, keeping at most maxLines, auto-scrolled. */
function renderLogsInto(el, text, maxLines) {
    const colored = [];
    text.split("\n").forEach((line) => {
        const c = colorizeLogLine(line);
        if (c !== null) colored.push(c);
    });
    let all = colored;
    if (maxLines && all.length > maxLines) all = all.slice(all.length - maxLines);
    el.innerHTML = all.join("<br>") + "<br>";
    el.scrollTop = el.scrollHeight;
}

/** Simple toast notifications (replaces alert() for non-blocking feedback). */
function toast(message, type = "info", durationMs = 3200) {
    let root = document.getElementById("toast-root");
    if (!root) {
        root = document.createElement("div");
        root.id = "toast-root";
        document.body.appendChild(root);
    }
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.textContent = message;
    root.appendChild(el);
    setTimeout(() => {
        el.style.opacity = "0";
        el.style.transition = "opacity 0.25s";
        setTimeout(() => el.remove(), 280);
    }, durationMs);
}

/** POST JSON helper. Returns parsed body or throws. */
async function postJson(url, body) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try {
        data = await res.json();
    } catch (_) {
        data = { status: res.ok ? "success" : "error", message: res.statusText };
    }
    if (!res.ok || data.status === "error") {
        const msg = (data && data.message) || "Request failed";
        throw new Error(msg);
    }
    return data;
}

/** Confirm destructive actions. */
function confirmAction(message) {
    return window.confirm(message);
}

/** Shared system actions used across pages. */
const SystemActions = {
    async clearFiles() {
        if (!confirmAction("Clear ALL Bjorn data/config files? This cannot be undone.")) return;
        try {
            const d = await postJson("/clear_files");
            toast(d.message || "Files cleared", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async clearFilesLight() {
        if (!confirmAction("Clear logs, loot, and scan results (keep config)?")) return;
        try {
            const d = await postJson("/clear_files_light");
            toast(d.message || "Files cleared", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async reboot() {
        if (!confirmAction("Reboot the Raspberry Pi now?")) return;
        try {
            const d = await postJson("/reboot");
            toast(d.message || "Rebooting…", "info");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async shutdown() {
        if (!confirmAction("Shut down the Raspberry Pi now?")) return;
        try {
            const d = await postJson("/shutdown");
            toast(d.message || "Shutting down…", "info");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async restartService() {
        if (!confirmAction("Restart bjorn.service?")) return;
        try {
            const d = await postJson("/restart_bjorn_service");
            toast(d.message || "Service restarting…", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async backup() {
        try {
            const d = await postJson("/backup");
            if (d.url) {
                const a = document.createElement("a");
                a.href = d.url;
                a.download = d.filename || "backup.zip";
                a.click();
            }
            toast(d.message || "Backup ready", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    restore() {
        const input = document.createElement("input");
        input.type = "file";
        input.accept = ".zip";
        input.onchange = async () => {
            const file = input.files[0];
            if (!file) return;
            const form = new FormData();
            form.append("file", file);
            try {
                const res = await fetch("/restore", { method: "POST", body: form });
                const d = await res.json();
                if (d.status === "error") throw new Error(d.message);
                toast(d.message || "Restore complete", "success");
            } catch (e) {
                toast(e.message, "error");
            }
        };
        input.click();
    },
    async stopOrchestrator() {
        try {
            const d = await postJson("/stop_orchestrator");
            toast(d.message || "Orchestrator stopping", "info");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async startOrchestrator() {
        try {
            const d = await postJson("/start_orchestrator");
            toast(d.message || "Orchestrator starting", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async disconnectWifi() {
        if (!confirmAction("Disconnect Wi-Fi and clear preconfigured credentials?")) return;
        try {
            const d = await postJson("/disconnect_wifi");
            toast(d.message || "Wi-Fi disconnected", "info");
        } catch (e) {
            toast(e.message, "error");
        }
    },
    async initializeCsv() {
        try {
            const d = await postJson("/initialize_csv");
            toast(d.message || "CSV files initialized", "success");
        } catch (e) {
            toast(e.message, "error");
        }
    },
};

/** Close open dropdowns when clicking outside. */
document.addEventListener("click", (e) => {
    document.querySelectorAll(".dropdown.show").forEach((dd) => {
        if (!dd.contains(e.target)) dd.classList.remove("show");
    });
});

function toggleDropdown(btn) {
    const dd = btn.closest(".dropdown");
    if (!dd) return;
    document.querySelectorAll(".dropdown.show").forEach((other) => {
        if (other !== dd) other.classList.remove("show");
    });
    dd.classList.toggle("show");
}

// Auto-render nav when DOM is ready (pages can still call renderNav() themselves for custom status).
document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("app-nav") || document.body.dataset.skipNav === "1") {
        // host already present or page opted out
        if (document.getElementById("app-nav") && !document.getElementById("app-nav").dataset.rendered) {
            renderNav();
            document.getElementById("app-nav").dataset.rendered = "1";
        }
        return;
    }
    renderNav();
});
