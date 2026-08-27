/**
 * Smart Log Analyzer & Anomaly Detector - Application JavaScript
 * Manages Theme Switching (Light/Dark), Chart.js Visualizations,
 * Dynamic Table Filtering & Pagination, CSV Ingestion, and AI Analysis.
 */

window.LogApp = (function () {
    'use strict';

    // Chart instances for dynamic theme updates
    let timelineChart = null;
    let severityChart = null;
    let sourceChart = null;

    // Logs explorer state
    let logsState = {
        page: 1,
        perPage: 25,
        search: '',
        severity: 'ALL',
        source: 'ALL',
        anomalyOnly: false,
        startDate: '',
        endDate: '',
        sortBy: 'timestamp',
        sortDir: 'desc',
        searchTimeout: null,
    };

    // =========================================================================
    // 1. Theme Manager (Light / Dark Mode)
    // =========================================================================
    function initTheme() {
        const savedTheme = localStorage.getItem('logapp_theme') || 'dark';
        applyTheme(savedTheme);

        const toggleBtn = document.getElementById('themeToggleBtn');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
                const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
                applyTheme(nextTheme);
            });
        }
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('logapp_theme', theme);

        const toggleBtn = document.getElementById('themeToggleBtn');
        if (toggleBtn) {
            toggleBtn.setAttribute('title', theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode');
        }

        // Update charts with high-contrast theme colors
        updateChartsTheme(theme);
    }

    function getThemeColors() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        return {
            isDark: isDark,
            textColor: isDark ? '#cbd5e1' : '#334155',
            headingColor: isDark ? '#f8fafc' : '#0f172a',
            gridColor: isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.06)',
            borderColor: isDark ? '#1e293b' : '#e2e8f0',
            primary: isDark ? '#60a5fa' : '#3b82f6',
            danger: isDark ? '#f87171' : '#ef4444',
            warning: isDark ? '#fbbf24' : '#f59e0b',
            success: isDark ? '#34d399' : '#10b981',
            info: isDark ? '#38bdf8' : '#0284c7',
            tooltipBg: isDark ? '#0f182c' : '#ffffff',
            tooltipText: isDark ? '#f8fafc' : '#0f172a',
        };
    }

    function updateChartsTheme() {
        const colors = getThemeColors();
        if (timelineChart) {
            if (timelineChart.options.scales?.x) {
                timelineChart.options.scales.x.ticks.color = colors.textColor;
                timelineChart.options.scales.x.grid.color = colors.gridColor;
            }
            if (timelineChart.options.scales?.y) {
                timelineChart.options.scales.y.ticks.color = colors.textColor;
                timelineChart.options.scales.y.grid.color = colors.gridColor;
            }
            if (timelineChart.options.plugins?.legend?.labels) {
                timelineChart.options.plugins.legend.labels.color = colors.headingColor;
            }
            timelineChart.update();
        }
        if (sourceChart) {
            if (sourceChart.options.scales?.x) {
                sourceChart.options.scales.x.ticks.color = colors.textColor;
                sourceChart.options.scales.x.grid.color = colors.gridColor;
            }
            if (sourceChart.options.scales?.y) {
                sourceChart.options.scales.y.ticks.color = colors.textColor;
                sourceChart.options.scales.y.grid.color = colors.gridColor;
            }
            sourceChart.update();
        }
        if (severityChart) {
            if (severityChart.options.plugins?.legend?.labels) {
                severityChart.options.plugins.legend.labels.color = colors.headingColor;
            }
            if (severityChart.data.datasets && severityChart.data.datasets[0]) {
                severityChart.data.datasets[0].borderColor = colors.borderColor;
            }
            severityChart.update();
        }
    }

    // =========================================================================
    // 2. Toast Notification Helper
    // =========================================================================
    function showToast(message, type = 'success') {
        const toastEl = document.getElementById('appToast');
        const toastMsg = document.getElementById('toastMessage');
        if (!toastEl || !toastMsg) return;

        toastEl.className = 'toast align-items-center text-white border-0';
        if (type === 'success') toastEl.classList.add('bg-success');
        else if (type === 'danger') toastEl.classList.add('bg-danger');
        else if (type === 'warning') toastEl.classList.add('bg-warning', 'text-dark');
        else toastEl.classList.add('bg-primary');

        toastMsg.textContent = message;
        const toast = new bootstrap.Toast(toastEl, { delay: 4500 });
        toast.show();
    }

    // =========================================================================
    // 2b. Global Delete Confirmation Modal Handler
    // =========================================================================
    let activeDeleteCallback = null;

    function showDeleteConfirmationModal({ targetDesc, onConfirm }) {
        const modalEl = document.getElementById('deleteConfirmModal');
        const descEl = document.getElementById('deleteModalTargetDesc');
        const radioLocal = document.getElementById('deleteScopeLocal');

        if (!modalEl) {
            // Fallback if modal not present
            if (confirm(targetDesc || 'Are you sure you want to delete this data?')) {
                onConfirm(false);
            }
            return;
        }

        if (descEl && targetDesc) descEl.textContent = targetDesc;
        if (radioLocal) radioLocal.checked = true; // Default to safe local deletion

        activeDeleteCallback = onConfirm;
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    // Initialize modal confirm button listener once
    document.addEventListener('DOMContentLoaded', () => {
        const confirmDeleteBtn = document.getElementById('btnConfirmDeleteModal');
        if (confirmDeleteBtn) {
            confirmDeleteBtn.addEventListener('click', async () => {
                const scope = document.querySelector('input[name="deleteScopeRadio"]:checked')?.value || 'local';
                const purgeSupabase = (scope === 'supabase');

                const spinner = document.getElementById('deleteModalSpinner');
                const icon = document.getElementById('deleteModalIcon');
                const modalEl = document.getElementById('deleteConfirmModal');
                const modal = modalEl ? bootstrap.Modal.getInstance(modalEl) : null;

                confirmDeleteBtn.disabled = true;
                if (spinner) spinner.classList.remove('d-none');
                if (icon) icon.classList.add('d-none');

                try {
                    if (activeDeleteCallback) {
                        await activeDeleteCallback(purgeSupabase);
                    }
                    if (modal) modal.hide();
                } catch (err) {
                    showToast(`Deletion error: ${err.message}`, 'danger');
                } finally {
                    confirmDeleteBtn.disabled = false;
                    if (spinner) spinner.classList.add('d-none');
                    if (icon) icon.classList.remove('d-none');
                    activeDeleteCallback = null;
                }
            });
        }
    });
    function initUpload() {
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('csvFileInput');
        const fileNameBadge = document.getElementById('selectedFileName');
        const uploadForm = document.getElementById('uploadForm');
        const uploadFeedback = document.getElementById('uploadFeedback');
        const submitBtn = document.getElementById('btnSubmitUpload');
        const spinner = document.getElementById('uploadSpinner');
        const btnText = document.getElementById('uploadBtnText');

        if (!dropzone || !fileInput || !uploadForm) return;

        dropzone.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileNameBadge.textContent = fileInput.files[0].name;
                fileNameBadge.className = 'badge bg-primary';
            }
        });

        // Drag & drop events
        ['dragenter', 'dragover'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
            });
        });

        dropzone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                fileNameBadge.textContent = fileInput.files[0].name;
                fileNameBadge.className = 'badge bg-primary';
            }
        });

        // Form Submit
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!fileInput.files.length) {
                showToast('Please select a CSV file first.', 'warning');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            submitBtn.disabled = true;
            spinner.classList.remove('d-none');
            btnText.textContent = 'Processing...';
            uploadFeedback.classList.add('d-none');
            uploadFeedback.innerHTML = '';

            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData,
                });
                const data = await response.json();

                if (response.ok && data.success) {
                    showToast(data.message, 'success');
                    uploadFeedback.className = 'alert alert-success mt-3 small';
                    uploadFeedback.innerHTML = `
                        <strong><i class="bi bi-check-circle-fill me-1"></i>Ingestion Complete:</strong><br>
                        • Processed: ${data.total_processed} rows<br>
                        • Successfully Imported: ${data.imported_count} rows<br>
                        • Anomalies Detected: ${data.anomalies_detected}<br>
                        • Duplicates Skipped: ${data.duplicate_count || 0}<br>
                        • Rejected: ${data.rejected_count} rows
                    `;
                    uploadFeedback.classList.remove('d-none');

                    // If errors occurred on some rows, display them
                    if (data.errors && data.errors.length > 0) {
                        let errList = '<div class="mt-2 text-danger"><strong>Validation Notes:</strong><ul>';
                        data.errors.slice(0, 5).forEach(err => {
                            errList += `<li>Row ${err.row} [${err.field}]: ${err.message}</li>`;
                        });
                        if (data.errors.length > 5) errList += `<li>...and ${data.errors.length - 5} more</li>`;
                        errList += '</ul></div>';
                        uploadFeedback.innerHTML += errList;
                    }

                    setTimeout(() => {
                        const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
                        if (modal) modal.hide();
                        window.location.reload();
                    }, 2200);

                } else {
                    uploadFeedback.className = 'alert alert-danger mt-3 small';
                    let errMsg = `<strong><i class="bi bi-exclamation-triangle-fill me-1"></i>${data.message || 'Validation failed'}</strong>`;
                    if (data.errors && data.errors.length > 0) {
                        errMsg += '<ul class="mt-2 mb-0">';
                        data.errors.slice(0, 5).forEach(err => {
                            errMsg += `<li>Row ${err.row} [${err.field}]: ${err.message}</li>`;
                        });
                        errMsg += '</ul>';
                    }
                    uploadFeedback.innerHTML = errMsg;
                    uploadFeedback.classList.remove('d-none');
                }
            } catch (err) {
                uploadFeedback.className = 'alert alert-danger mt-3 small';
                uploadFeedback.innerHTML = `<strong>Error:</strong> ${err.message || 'Network error during upload.'}`;
                uploadFeedback.classList.remove('d-none');
            } finally {
                submitBtn.disabled = false;
                spinner.classList.add('d-none');
                btnText.textContent = 'Upload & Analyze';
            }
        });
    }

    // =========================================================================
    // 4. Global Action Handlers (Detection & Supabase Sync)
    // =========================================================================
    function initGlobalActions() {
        const detectBtn = document.getElementById('navRunDetectionBtn');
        if (detectBtn) {
            detectBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                showToast('Running deterministic anomaly detection...', 'info');
                try {
                    const res = await fetch('/api/detect', { method: 'POST' });
                    const data = await res.json();
                    if (data.success) {
                        showToast(data.message, 'success');
                        setTimeout(() => window.location.reload(), 1200);
                    } else {
                        showToast(data.message || 'Detection failed', 'danger');
                    }
                } catch (err) {
                    showToast('Failed to trigger anomaly detection.', 'danger');
                }
            });
        }

        const syncBtn = document.getElementById('btnSyncSupabase');
        if (syncBtn) {
            syncBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                syncBtn.disabled = true;
                showToast('Synchronizing with Supabase Cloud...', 'info');
                try {
                    const res = await fetch('/api/sync/supabase', { method: 'POST' });
                    const data = await res.json();
                    if (data.success) {
                        showToast(data.message, 'success');
                    } else {
                        showToast(data.message || 'Supabase sync failed.', 'warning');
                    }
                } catch (err) {
                    showToast('Supabase sync connection failed.', 'danger');
                } finally {
                    syncBtn.disabled = false;
                }
            });
        }

        // Mobile sidebar toggle
        const sidebarToggle = document.getElementById('sidebarToggle');
        const sidebar = document.querySelector('.app-sidebar');
        if (sidebarToggle && sidebar) {
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('show');
            });
        }
    }

    // =========================================================================
    // 5. Dashboard View Logic
    // =========================================================================
    async function initDashboard() {
        const refreshBtn = document.getElementById('btnTimelineRefresh');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => loadDashboardStats());
        }
        await loadDashboardStats();
    }

    async function loadDashboardStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();

            // Populate KPI Cards
            document.getElementById('metricTotalLogs').textContent = data.total_logs.toLocaleString();
            document.getElementById('metricTotalAnomalies').textContent = data.total_anomalies.toLocaleString();
            document.getElementById('metricCriticalAnomalies').textContent = data.critical_anomalies.toLocaleString();
            document.getElementById('metricErrorRate').textContent = `${data.error_rate}%`;
            document.getElementById('metricAiCount').textContent = data.ai_analyses_count.toLocaleString();

            const anomRate = data.total_logs > 0 ? ((data.total_anomalies / data.total_logs) * 100).toFixed(1) : '0.0';
            document.getElementById('metricAnomalyRate').textContent = `${anomRate}%`;

            // Render Charts
            renderTimelineChart(data.timeline);
            renderSeverityChart(data.severity_distribution);
            renderSourceChart(data.anomalies_by_source);
            renderRecentAnomalies(data.recent_anomalies);

        } catch (err) {
            console.error('Failed to load dashboard stats:', err);
        }
    }

    function renderTimelineChart(timeline) {
        const ctx = document.getElementById('timelineChart');
        if (!ctx) return;

        const colors = getThemeColors();
        if (timelineChart) timelineChart.destroy();

        if (!timeline.labels || timeline.labels.length === 0) {
            document.getElementById('timelineEmpty')?.classList.remove('d-none');
            return;
        }
        document.getElementById('timelineEmpty')?.classList.add('d-none');

        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: timeline.labels,
                datasets: [
                    {
                        label: 'Total Logs Ingested',
                        data: timeline.total_series,
                        borderColor: colors.primary,
                        backgroundColor: 'rgba(37, 99, 235, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3,
                    },
                    {
                        label: 'Flagged Anomalies',
                        data: timeline.anomaly_series,
                        borderColor: colors.danger,
                        backgroundColor: 'rgba(239, 68, 68, 0.2)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 4,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: {
                        ticks: { color: colors.textColor, maxRotation: 45 },
                        grid: { color: colors.gridColor }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: colors.textColor },
                        grid: { color: colors.gridColor }
                    }
                },
                plugins: {
                    legend: { labels: { color: colors.textColor } }
                }
            }
        });
    }

    function renderSeverityChart(severityMap) {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        const colors = getThemeColors();
        if (severityChart) severityChart.destroy();

        const labels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL'];
        const counts = labels.map(l => severityMap[l] || 0);

        severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: [
                        colors.success,
                        colors.warning,
                        colors.danger,
                        '#991b1b'
                    ],
                    borderWidth: 2,
                    borderColor: colors.borderColor,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: colors.textColor, boxWidth: 12 } }
                },
                cutout: '65%'
            }
        });
    }

    function renderSourceChart(sourcesMap) {
        const ctx = document.getElementById('sourceChart');
        if (!ctx) return;

        const colors = getThemeColors();
        if (sourceChart) sourceChart.destroy();

        const labels = Object.keys(sourcesMap);
        const data = Object.values(sourcesMap);

        sourceChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Anomalies Count',
                    data: data,
                    backgroundColor: 'rgba(239, 68, 68, 0.75)',
                    borderColor: colors.danger,
                    borderWidth: 1,
                    borderRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: { color: colors.textColor },
                        grid: { color: colors.gridColor }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: colors.textColor, stepSize: 1 },
                        grid: { color: colors.gridColor }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function renderRecentAnomalies(anomalies) {
        const container = document.getElementById('recentAnomaliesList');
        if (!container) return;

        if (!anomalies || anomalies.length === 0) {
            container.innerHTML = `
                <div class="p-4 text-center text-muted">
                    <i class="bi bi-check-circle text-success display-6"></i>
                    <p class="mb-0 mt-2">No anomalies detected in the dataset.</p>
                </div>
            `;
            return;
        }

        let html = '';
        anomalies.forEach(a => {
            const scoreClass = a.anomaly_score >= 70 ? 'text-danger' : 'text-warning';
            const aiBadge = a.has_ai_analysis 
                ? '<span class="badge bg-success-subtle text-success border"><i class="bi bi-stars me-1"></i>AI Explained</span>'
                : '<span class="badge bg-secondary-subtle text-muted">No AI</span>';

            html += `
                <a href="/logs/${a.id}" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center py-3">
                    <div class="pe-3" style="max-width: 75%;">
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <span class="badge bg-secondary-subtle text-body border">${a.source}</span>
                            <span class="badge bg-danger">${a.severity}</span>
                            <small class="font-monospace text-muted">${a.timestamp}</small>
                        </div>
                        <div class="small font-monospace text-truncate text-body">
                            ${a.message}
                        </div>
                        <div class="small text-muted text-truncate mt-1">
                            ${a.anomaly_reason || 'Score threshold exceeded'}
                        </div>
                    </div>
                    <div class="text-end">
                        <div class="fw-bold ${scoreClass} fs-5">${a.anomaly_score}<small class="fs-6 text-muted">/100</small></div>
                        <div class="mt-1">${aiBadge}</div>
                    </div>
                </a>
            `;
        });
        container.innerHTML = html;
    }

    // =========================================================================
    // 6. Logs Explorer Table Logic
    // =========================================================================
    function initLogsExplorer() {
        const searchInput = document.getElementById('filterSearch');
        const severitySelect = document.getElementById('filterSeverity');
        const sourceSelect = document.getElementById('filterSource');
        const anomalySwitch = document.getElementById('filterAnomalyOnly');
        const startDate = document.getElementById('filterStartDate');
        const endDate = document.getElementById('filterEndDate');
        const resetBtn = document.getElementById('btnResetFilters');
        const perPageSelect = document.getElementById('selectPerPage');
        const clearAllBtn = document.getElementById('btnClearAllLogs');

        if (searchInput) {
            searchInput.addEventListener('input', () => {
                clearTimeout(logsState.searchTimeout);
                logsState.searchTimeout = setTimeout(() => {
                    logsState.search = searchInput.value;
                    logsState.page = 1;
                    fetchLogs();
                }, 300);
            });
        }

        if (severitySelect) {
            severitySelect.addEventListener('change', () => {
                logsState.severity = severitySelect.value;
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (sourceSelect) {
            sourceSelect.addEventListener('change', () => {
                logsState.source = sourceSelect.value;
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (anomalySwitch) {
            logsState.anomalyOnly = anomalySwitch.checked;
            anomalySwitch.addEventListener('change', () => {
                logsState.anomalyOnly = anomalySwitch.checked;
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (startDate) {
            startDate.addEventListener('change', () => {
                logsState.startDate = startDate.value;
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (endDate) {
            endDate.addEventListener('change', () => {
                logsState.endDate = endDate.value;
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (searchInput) searchInput.value = '';
                if (severitySelect) severitySelect.value = 'ALL';
                if (sourceSelect) sourceSelect.value = 'ALL';
                if (anomalySwitch) anomalySwitch.checked = false;
                if (startDate) startDate.value = '';
                if (endDate) endDate.value = '';

                logsState = {
                    ...logsState,
                    page: 1,
                    search: '',
                    severity: 'ALL',
                    source: 'ALL',
                    anomalyOnly: false,
                    startDate: '',
                    endDate: '',
                };
                fetchLogs();
            });
        }

        if (perPageSelect) {
            perPageSelect.addEventListener('change', () => {
                logsState.perPage = parseInt(perPageSelect.value);
                logsState.page = 1;
                fetchLogs();
            });
        }

        if (clearAllBtn) {
            clearAllBtn.addEventListener('click', () => {
                showDeleteConfirmationModal({
                    targetDesc: 'Are you sure you want to purge ALL logs across the system? Choose whether to delete from local cache only or permanently wipe from Supabase cloud database as well.',
                    onConfirm: async (purgeSupabase) => {
                        const res = await fetch('/api/logs/batch-delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ clear_all: true, purge_supabase: purgeSupabase })
                        });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            fetchLogs();
                        } else {
                            showToast(data.message || 'Failed to clear logs.', 'danger');
                        }
                    }
                });
            });
        }

        fetchLogs();
    }

    async function fetchLogs() {
        const tbody = document.getElementById('logsTableBody');
        const summary = document.getElementById('logsCountSummary');
        if (!tbody) return;

        const params = new URLSearchParams({
            page: logsState.page,
            per_page: logsState.perPage,
            search: logsState.search,
            severity: logsState.severity,
            source: logsState.source,
            anomaly_only: logsState.anomalyOnly,
            start_date: logsState.startDate,
            end_date: logsState.endDate,
            sort_by: logsState.sortBy,
            sort_dir: logsState.sortDir,
        });

        try {
            const res = await fetch(`/api/logs?${params.toString()}`);
            const data = await res.json();

            if (summary) {
                summary.textContent = `Showing ${(data.page - 1) * data.per_page + (data.items.length ? 1 : 0)} - ${(data.page - 1) * data.per_page + data.items.length} of ${data.total} logs`;
            }

            if (!data.items || data.items.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="10" class="text-center py-5 text-muted">
                            <i class="bi bi-inbox display-6 d-block mb-2"></i>
                            No log records found matching your filter criteria.
                        </td>
                    </tr>
                `;
                renderPagination(0, 1);
                return;
            }

            let rowsHtml = '';
            data.items.forEach(log => {
                const rowClass = log.anomaly ? 'row-anomaly' : '';
                const sevBadge = getSeverityBadge(log.severity);
                const statusBadge = log.status_code ? `<span class="badge ${log.status_code >= 500 ? 'bg-danger' : log.status_code >= 400 ? 'bg-warning text-dark' : 'bg-success'}">${log.status_code}</span>` : '<span class="text-muted">-</span>';
                
                // Anomaly Score bar
                const scoreFillColor = log.anomaly_score >= 70 ? '#ef4444' : log.anomaly_score >= 50 ? '#f59e0b' : '#10b981';
                const scoreHtml = `
                    <div class="d-flex align-items-center">
                        <div class="mini-score-bar">
                            <div class="mini-score-fill" style="width: ${log.anomaly_score}%; background-color: ${scoreFillColor};"></div>
                        </div>
                        <span class="small font-monospace">${log.anomaly_score}</span>
                    </div>
                `;

                const anomBadge = log.anomaly 
                    ? '<span class="badge bg-danger">ANOMALY</span>' 
                    : '<span class="badge bg-success-subtle text-success border">NORMAL</span>';

                const aiBadge = log.has_ai_analysis
                    ? '<span class="badge bg-primary-subtle text-primary border" title="AI Analysis available"><i class="bi bi-stars"></i> Ready</span>'
                    : '<span class="text-muted small">-</span>';

                rowsHtml += `
                    <tr class="${rowClass}">
                        <td class="font-monospace small text-nowrap">${log.timestamp}</td>
                        <td><span class="badge bg-secondary-subtle text-body border">${log.source}</span></td>
                        <td><span class="badge bg-primary-subtle text-primary border">${log.event_type}</span></td>
                        <td>${sevBadge}</td>
                        <td>${statusBadge}</td>
                        <td>${scoreHtml}</td>
                        <td>${anomBadge}</td>
                        <td>${aiBadge}</td>
                        <td>
                            <div class="text-truncate font-monospace small" style="max-width: 320px;" title="${log.message}">
                                ${log.message}
                            </div>
                            ${log.anomaly ? `<div class="small text-danger text-truncate" style="max-width: 320px;"><i class="bi bi-info-circle me-1"></i>${log.anomaly_reason || ''}</div>` : ''}
                        </td>
                        <td class="text-end text-nowrap">
                            <a href="/logs/${log.id}" class="btn btn-xs btn-outline-primary btn-sm me-1" title="Inspect Log & AI Explanation">
                                <i class="bi bi-eye"></i>
                            </a>
                            <button class="btn btn-xs btn-outline-danger btn-sm btn-delete-log" data-log-id="${log.id}" title="Delete Record">
                                <i class="bi bi-trash"></i>
                            </button>
                        </td>
                    </tr>
                `;
            });

            tbody.innerHTML = rowsHtml;
            renderPagination(data.pages, data.page);

            // Bind delete single log buttons with modal confirmation
            document.querySelectorAll('.btn-delete-log').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-log-id');
                    showDeleteConfirmationModal({
                        targetDesc: `Are you sure you want to delete log record #${id}? Choose whether to remove from local database only or permanently purge from Supabase cloud database.`,
                        onConfirm: async (purgeSupabase) => {
                            const delRes = await fetch(`/api/logs/${id}?purge_supabase=${purgeSupabase}`, { method: 'DELETE' });
                            const delData = await delRes.json();
                            if (delData.success) {
                                showToast(delData.message, 'success');
                                fetchLogs();
                            } else {
                                showToast(delData.message || 'Failed to delete log.', 'danger');
                            }
                        }
                    });
                });
            });

        } catch (err) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="10" class="text-center py-4 text-danger">
                        Failed to fetch logs: ${err.message}
                    </td>
                </tr>
            `;
        }
    }

    function renderPagination(totalPages, currentPage) {
        const pagContainer = document.getElementById('logsPagination');
        if (!pagContainer) return;

        if (totalPages <= 1) {
            pagContainer.innerHTML = '';
            return;
        }

        let html = '';
        // Prev button
        html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage - 1}">Previous</a>
        </li>`;

        // Page numbers
        let startPage = Math.max(1, currentPage - 2);
        let endPage = Math.min(totalPages, currentPage + 2);

        for (let i = startPage; i <= endPage; i++) {
            html += `<li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" data-page="${i}">${i}</a>
            </li>`;
        }

        // Next button
        html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage + 1}">Next</a>
        </li>`;

        pagContainer.innerHTML = html;

        pagContainer.querySelectorAll('a.page-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const p = parseInt(link.getAttribute('data-page'));
                if (p >= 1 && p <= totalPages && p !== currentPage) {
                    logsState.page = p;
                    fetchLogs();
                }
            });
        });
    }

    function getSeverityBadge(sev) {
        if (sev === 'CRITICAL') return '<span class="badge bg-dark-danger text-white">CRITICAL</span>';
        if (sev === 'ERROR') return '<span class="badge bg-danger">ERROR</span>';
        if (sev === 'WARNING') return '<span class="badge bg-warning text-dark">WARNING</span>';
        return '<span class="badge bg-success">INFO</span>';
    }

    // =========================================================================
    // 7. Log Detail & AI Explanation Logic
    // =========================================================================
    function initLogDetail() {
        const aiBtn = document.getElementById('btnGenerateAI');
        const deleteBtn = document.getElementById('btnDeleteCurrentLog');

        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => {
                const logId = deleteBtn.getAttribute('data-log-id');
                showDeleteConfirmationModal({
                    targetDesc: `Are you sure you want to delete log inspection #${logId}? Choose whether to delete from local cache only or permanently purge from Supabase cloud database.`,
                    onConfirm: async (purgeSupabase) => {
                        const res = await fetch(`/api/logs/${logId}?purge_supabase=${purgeSupabase}`, { method: 'DELETE' });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            setTimeout(() => window.location.href = '/logs', 800);
                        } else {
                            showToast(data.message || 'Failed to delete log.', 'danger');
                        }
                    }
                });
            });
        }

        if (aiBtn) {
            aiBtn.addEventListener('click', async () => {
                const logId = aiBtn.getAttribute('data-log-id');
                const spinner = document.getElementById('aiSpinner');
                const btnIcon = document.getElementById('aiBtnIcon');
                const btnText = document.getElementById('aiBtnText');
                const errorAlert = document.getElementById('aiErrorAlert');
                const resultsContainer = document.getElementById('aiResultsContainer');
                const emptyState = document.getElementById('aiEmptyState');
                const statusText = document.getElementById('aiStatusText');

                aiBtn.disabled = true;
                if (spinner) spinner.classList.remove('d-none');
                if (btnIcon) btnIcon.classList.add('d-none');
                if (btnText) btnText.textContent = 'Analyzing with Gemini...';
                if (errorAlert) errorAlert.classList.add('d-none');

                try {
                    const res = await fetch(`/api/logs/${logId}/analyze`, { method: 'POST' });
                    const result = await res.json();

                    if (res.ok && result.success) {
                        showToast('Gemini root-cause analysis completed!', 'success');
                        
                        document.getElementById('aiExplanationText').textContent = result.data.explanation;
                        document.getElementById('aiRootCauseText').textContent = result.data.likely_root_cause;
                        document.getElementById('aiNextStepText').textContent = result.data.recommended_next_step;

                        if (resultsContainer) resultsContainer.classList.remove('d-none');
                        if (emptyState) emptyState.classList.add('d-none');
                        if (statusText) statusText.textContent = `Analysis generated on ${result.data.analyzed_at}`;
                        if (btnText) btnText.textContent = 'Regenerate Analysis';

                    } else {
                        if (errorAlert) {
                            errorAlert.innerHTML = `<strong><i class="bi bi-exclamation-octagon me-1"></i>AI Analysis Error:</strong> ${result.message || 'Failed to generate explanation.'}`;
                            errorAlert.classList.remove('d-none');
                        }
                        showToast(result.message || 'AI request failed.', 'danger');
                        if (btnText) btnText.textContent = 'Retry Analysis';
                    }
                } catch (err) {
                    if (errorAlert) {
                        errorAlert.innerHTML = `<strong>Network Error:</strong> ${err.message || 'Unable to connect to analysis endpoint.'}`;
                        errorAlert.classList.remove('d-none');
                    }
                    showToast('Connection error during AI analysis.', 'danger');
                    if (btnText) btnText.textContent = 'Retry Analysis';
                } finally {
                    aiBtn.disabled = false;
                    if (spinner) spinner.classList.add('d-none');
                    if (btnIcon) btnIcon.classList.remove('d-none');
                }
            });
        }
    }

    // Initialize core handlers on DOM ready
    document.addEventListener('DOMContentLoaded', () => {
        initTheme();
        initUpload();
        initGlobalActions();
    });

    return {
        initTheme,
        initDashboard,
        initLogsExplorer,
        initLogDetail,
        showToast,
    };
})();
