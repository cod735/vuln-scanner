// ── SocketIO connection ──────────────────────────────────────────
const socket = io();

socket.on("connect",    () => console.log("[WS] Connected"));
socket.on("disconnect", () => console.log("[WS] Disconnected"));

// Scan status updates
socket.on("scan_status", (data) => {
    const bar = document.getElementById("scan-status-bar");
    const msg = document.getElementById("scan-status-msg");
    if (bar) bar.classList.add("active");
    if (msg) msg.textContent = `Layer ${data.layer || ""} — ${data.message}`;

    if (data.status === "complete" || data.status === "error") {
        setTimeout(() => {
            if (bar) bar.classList.remove("active");
            if (data.status === "complete") location.reload();
        }, 1500);
    }
});

// Port scan progress bar
socket.on("scan_progress", (data) => {
    const fill = document.getElementById("progress-fill");
    if (fill) fill.style.width = data.percent + "%";
});

// ── Scan form submit ─────────────────────────────────────────────
function startScan() {
    const input  = document.getElementById("scan-target");
    const target = input ? input.value.trim() : "";
    if (!target) return;

    const bar = document.getElementById("scan-status-bar");
    const msg = document.getElementById("scan-status-msg");
    if (bar) bar.classList.add("active");
    if (msg) msg.textContent = "Starting scan...";

    fetch("/api/scan/start", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ target })
    })
    .then(r => r.json())
    .then(d => {
        if (d.error && msg) msg.textContent = "Error: " + d.error;
    })
    .catch(e => console.error("Scan start error:", e));
}

// Allow Enter key in scan input
document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("scan-target");
    if (input) {
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") startScan();
        });
    }
});

// ── Chart helpers ────────────────────────────────────────────────
function buildDonut(canvasId, labels, values, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const total = values.reduce((a, b) => a + b, 0);
    if (total === 0) {
        ctx.parentElement.innerHTML =
            '<p style="color:var(--text-muted);font-size:12px;text-align:center;padding-top:80px">No data</p>';
        return;
    }
    new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data:            values,
                backgroundColor: colors,
                borderWidth:     0,
                hoverOffset:     6,
            }]
        },
        options: {
            responsive:       true,
            maintainAspectRatio: false,
            cutout:           "72%",
            plugins: {
                legend: {
                    position: "right",
                    labels: {
                        color:     "#94a3b8",
                        font:      { size: 12 },
                        boxWidth:  12,
                        padding:   14,
                    }
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) =>
                            ` ${ctx.label}: ${ctx.raw} (${Math.round(ctx.raw/total*100)}%)`
                    }
                }
            }
        }
    });
}

function buildBar(canvasId, labels, values, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: "bar",
        data: {
            labels,
            datasets: [{
                data:            values,
                backgroundColor: color || "rgba(0,212,255,0.5)",
                borderColor:     color || "rgba(0,212,255,0.8)",
                borderWidth:     1,
                borderRadius:    4,
            }]
        },
        options: {
            responsive:          true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    ticks: { color: "#64748b", font: { size: 11 } },
                    grid:  { color: "rgba(255,255,255,0.04)" }
                },
                y: {
                    ticks: { color: "#64748b", font: { size: 11 } },
                    grid:  { color: "rgba(255,255,255,0.06)" },
                    beginAtZero: true,
                }
            }
        }
    });
}