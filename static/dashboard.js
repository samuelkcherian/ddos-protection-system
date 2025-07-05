document.getElementById("toggleSidebar").addEventListener("click", () => {
    const sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle("open");
});

// Load data and populate table
async function fetchData() {
    const response = await fetch("/data");
    const data = await response.json();

    const table = document.getElementById("table-body");
    table.innerHTML = "";

    let total = 0, blocked = 0, suspicious = 0;

    data.forEach(entry => {
        total++;
        if (entry.status === "Blocked") blocked++;
        if (entry.status === "Suspicious") suspicious++;

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${entry.ip}</td>
            <td>${entry.packet_count}</td>
            <td>${new Date(entry.last_seen).toLocaleString()}</td>
            <td class="${getStatusClass(entry.status)}">${entry.status}</td>
            <td>${entry.suspicion_score || 0}</td>
            <td>${entry.blocked_at ? formatTime(entry.blocked_at) : "-"}</td>
            <td>${entry.status === "Blocked" ? `<button class="unblock-btn" onclick="unblockIP('${entry.ip}')">Unblock</button>` : "-"}</td>
        `;

        table.appendChild(row);
    });

    document.getElementById("totalIPs").textContent = total;
    document.getElementById("blockedIPs").textContent = blocked;
    document.getElementById("suspiciousIPs").textContent = suspicious;
}

// Format blocked_at time
function formatTime(isoTime) {
    try {
        return new Date(isoTime).toLocaleString();
    } catch {
        return "-";
    }
}

// Return CSS class for status color
function getStatusClass(status) {
    if (status === "Blocked") return "status-blocked";
    if (status === "Suspicious") return "status-suspicious";
    return "status-safe";
}

// Call unblock endpoint
async function unblockIP(ip) {
    const confirmed = confirm(`Unblock IP ${ip}?`);
    if (!confirmed) return;

    const res = await fetch(`/unblock/${ip}`, { method: "POST" });
    if (res.ok) {
        alert(`✅ ${ip} unblocked successfully.`);
        fetchData(); // Refresh
    } else {
        alert(`❌ Failed to unblock ${ip}`);
    }
}

// Auto refresh every 5s
setInterval(fetchData, 5000);
fetchData(); // Initial call
