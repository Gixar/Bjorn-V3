let fontSize = /Mobi|Android/i.test(navigator.userAgent) ? 11 : 13;

function fetchCredentials() {
    fetch("/list_credentials")
        .then((r) => r.text())
        .then((data) => {
            const el = document.getElementById("credentials-table");
            if (el) el.innerHTML = data;
        })
        .catch((error) => {
            console.error("Error:", error);
            if (typeof toast === "function") toast("Failed to load credentials", "error");
        });
}

function adjustCredFontSize(change) {
    fontSize += change;
    const el = document.getElementById("credentials-table");
    if (el) el.style.fontSize = fontSize + "px";
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof renderNav === "function") renderNav();
    fetchCredentials();
    setInterval(fetchCredentials, 15000);
});

window.adjustCredFontSize = adjustCredFontSize;
window.fetchCredentials = fetchCredentials;
