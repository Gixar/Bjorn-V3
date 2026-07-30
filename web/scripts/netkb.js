let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 11 : 13;

function fetchNetkbData() {
    fetch("/netkb_data")
        .then((r) => r.text())
        .then((data) => {
            const el = document.getElementById("netkb-table");
            if (el) el.innerHTML = data;
        })
        .catch((error) => {
            console.error("Error:", error);
            if (typeof toast === "function") toast("Failed to load NetKB", "error");
        });
}

function adjustNetkbFontSize(change) {
    fontSize += change;
    const el = document.getElementById("netkb-table");
    if (el) el.style.fontSize = fontSize + "px";
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetchNetkbData();
    setInterval(fetchNetkbData, 10000);
});

window.adjustNetkbFontSize = adjustNetkbFontSize;
window.fetchNetkbData = fetchNetkbData;
