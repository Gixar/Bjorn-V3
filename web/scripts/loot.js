let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 12 : 14;

function generateFileListHTML(files, path, indent) {
    let html = "<ul>";
    (files || []).forEach((file) => {
        if (file.is_directory) {
            const icon = path === "/" ? "web/images/mainfolder.png" : "web/images/subfolder.png";
            html += `
                <li style="margin-left: ${indent * 12}px;">
                    <img src="${icon}" alt="">
                    <strong>${file.name}</strong>
                    ${generateFileListHTML(file.children || [], `${path}/${file.name}`, indent + 1)}
                </li>`;
        } else {
            html += `
                <li style="margin-left: ${indent * 12}px;">
                    <img src="web/images/file.png" alt="">
                    <a href="/download_file?path=${encodeURIComponent(file.path)}">${file.name}</a>
                </li>`;
        }
    });
    html += "</ul>";
    return html;
}

function refreshLoot() {
    fetch("/list_files")
        .then((r) => r.json())
        .then((data) => {
            const el = document.getElementById("file-list");
            if (!el) return;
            if (!data || (Array.isArray(data) && data.length === 0)) {
                el.innerHTML = '<p class="muted">No loot files yet.</p>';
                return;
            }
            el.innerHTML = generateFileListHTML(data, "/", 0);
        })
        .catch((error) => {
            console.error("Error:", error);
            if (typeof toast === "function") toast("Failed to load loot", "error");
        });
}

function adjustLootFontSize(change) {
    fontSize += change;
    const el = document.getElementById("file-list");
    if (el) el.style.fontSize = fontSize + "px";
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    refreshLoot();
    setInterval(refreshLoot, 15000);
});

window.adjustLootFontSize = adjustLootFontSize;
window.refreshLoot = refreshLoot;
