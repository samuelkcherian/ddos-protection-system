document.getElementById("toggleSidebar").addEventListener("click", () => {
    const sidebar = document.querySelector(".sidebar");
    const main = document.querySelector(".main");
    sidebar.classList.toggle("closed");
    main.classList.toggle("expanded");
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
            <td><span class="${getStatusClass(entry.status)}">${entry.status}</span></td>
            <td>${entry.suspicion_score || 0}</td>
            <td>${entry.blocked_duration || "-"}</td>
            <td>${entry.status === "Blocked" && entry.blocked_at ? getTimeUntilUnblock(entry.blocked_at) : "-"}</td>
        `;

        table.appendChild(row);
    });

    document.getElementById("totalIPs").textContent = total;
    document.getElementById("blockedIPs").textContent = blocked;
    document.getElementById("suspiciousIPs").textContent = suspicious;
}

function getStatusClass(status) {
    if (status === "Blocked") return "status-blocked";
    if (status === "Suspicious") return "status-suspicious";
    return "status-safe";
}

function getTimeUntilUnblock(blocked_at) {
    const unblockAfterSec = 300;
    const blockedTime = new Date(blocked_at);
    const now = new Date();
    const elapsed = Math.floor((now - blockedTime) / 1000);
    const remaining = unblockAfterSec - elapsed;

    if (remaining <= 0) return "Unblocking...";

    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    return `${String(minutes).padStart(2, '0')}m ${String(seconds).padStart(2, '0')}s`;
}

function timeAgo(isoTime) {
    if (!isoTime) return "-";
    const now = new Date();
    const then = new Date(isoTime);
    const diff = Math.floor((now - then) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return then.toLocaleString();
}


// Auto refresh every 5s
setInterval(fetchData, 5000);
fetchData(); // Initial call
