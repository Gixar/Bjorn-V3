let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 11 : 13;

function fetchNetworkData() {
    fetch("/network_data")
        .then((r) => r.text())
        .then((data) => {
            const el = document.getElementById("network-table");
            if (el) el.innerHTML = data;
        })
        .catch((error) => {
            console.error("Error:", error);
            if (typeof toast === "function") toast("Failed to load network data", "error");
        });
}

function adjustNetworkFontSize(change) {
    fontSize += change;
    const el = document.getElementById("network-table");
    if (el) el.style.fontSize = fontSize + "px";
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetchNetworkData();
    setInterval(fetchNetworkData, 60000);
});

window.adjustNetworkFontSize = adjustNetworkFontSize;
window.fetchNetworkData = fetchNetworkData;
