/*=============================================================
    AISOC ENTERPRISE DASHBOARD CONTROLLER v3.0
==============================================================*/

document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("alertSearch");
    const severitySelect = document.getElementById("severityFilter");
    const rows = document.querySelectorAll(".log-row");
    const statCards = document.querySelectorAll(".stat-card[data-filter]");

    function filterAlerts() {
        const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
        const selectedSeverity = severitySelect ? severitySelect.value.toLowerCase() : "all";

        rows.forEach(row => {
            const textContent = row.innerText.toLowerCase();
            const rowSeverity = row.dataset.severity || "";

            const matchesText = !query || textContent.includes(query);
            const matchesSeverity = selectedSeverity === "all" || rowSeverity === selectedSeverity;

            row.style.display = (matchesText && matchesSeverity) ? "" : "none";
        });
    }

    // Event Listeners for Filters
    if (searchInput) {
        searchInput.addEventListener("input", filterAlerts);
    }

    if (severitySelect) {
        severitySelect.addEventListener("change", filterAlerts);
    }

    // KPI Stat Card Click Handler (Quick Severity Filter)
    statCards.forEach(card => {
        card.addEventListener("click", () => {
            statCards.forEach(c => c.classList.remove("active-filter"));
            card.classList.add("active-filter");

            const filterValue = card.dataset.filter;
            if (severitySelect) {
                severitySelect.value = filterValue;
                filterAlerts();
            }
        });
    });

    // Keyboard Shortcuts: Press '/' to focus search input, 'Esc' to clear
    document.addEventListener("keydown", (e) => {
        if (e.key === "/" && document.activeElement !== searchInput) {
            e.preventDefault();
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        } else if (e.key === "Escape" && document.activeElement === searchInput) {
            searchInput.value = "";
            filterAlerts();
            searchInput.blur();
        }
    });
});
