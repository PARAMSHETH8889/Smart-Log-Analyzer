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
    // 2b. Main Database (Supabase) Permanent Deletion Warning Modal Handler
    // =========================================================================
    let activeMainDbDeleteCallback = null;

    function showMainDbDeleteModal({ targetText, warningStatement, onConfirm }) {
        const modalEl = document.getElementById('mainDbDeleteModal');
        const targetEl = document.getElementById('mainDbTargetText');
        const warnEl = document.getElementById('mainDbWarningStatement');

        if (!modalEl) {
            if (confirm(`⚠️ WARNING: Permanently delete ${targetText} from MAIN DATABASE (Supabase) and local storage? This action cannot be recovered.`)) {
                onConfirm();
            }
            return;
        }

        if (targetEl && targetText) targetEl.textContent = targetText;
        if (warnEl && warningStatement) warnEl.innerHTML = warningStatement;

        activeMainDbDeleteCallback = onConfirm;
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    // Initialize modal confirm button listener once
    document.addEventListener('DOMContentLoaded', () => {
        const confirmBtn = document.getElementById('btnConfirmMainDbDelete');
        if (confirmBtn) {
            confirmBtn.addEventListener('click', async () => {
                const spinner = document.getElementById('mainDbDeleteSpinner');
                const icon = document.getElementById('mainDbDeleteIcon');
                const modalEl = document.getElementById('mainDbDeleteModal');
                const modal = modalEl ? bootstrap.Modal.getInstance(modalEl) : null;

                confirmBtn.disabled = true;
                if (spinner) spinner.classList.remove('d-none');
                if (icon) icon.classList.add('d-none');

                try {
                    if (activeMainDbDeleteCallback) {
                        await activeMainDbDeleteCallback();
                    }
                    if (modal) modal.hide();
                } catch (err) {
                    showToast(`Deletion failed: ${err.message}`, 'danger');
                } finally {
                    confirmBtn.disabled = false;
                    if (spinner) spinner.classList.add('d-none');
                    if (icon) icon.classList.remove('d-none');
                    activeMainDbDeleteCallback = null;
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

            const syncCheckbox = document.getElementById('chkUploadSyncSupabase');
            if (syncCheckbox && syncCheckbox.checked) {
                formData.append('sync_to_supabase', 'true');
            }

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

                const responseText = await response.text();
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (jsonErr) {
                    let cleanMsg = responseText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
                    if (cleanMsg.length > 180) cleanMsg = cleanMsg.substring(0, 180) + '...';
                    data = {
                        success: false,
                        message: cleanMsg || `Upload error (HTTP ${response.status})`
                    };
                }

                if (response.ok && data.success) {
                    showToast(data.message, 'success');
                    uploadFeedback.className = 'alert alert-success mt-3 small';
                    uploadFeedback.innerHTML = `
                        <div class="d-flex align-items-center justify-content-between mb-2">
                            <strong><i class="bi bi-check-circle-fill me-1 text-success"></i>Ingestion Complete!</strong>
                            <span class="badge bg-success">${data.imported_count} Records</span>
                        </div>
                        <ul class="mb-2 ps-3">
                            <li>Processed: <strong>${data.total_processed}</strong> rows</li>
                            <li>Imported: <strong>${data.imported_count}</strong> rows</li>
                            <li>Anomalies Flagged: <strong>${data.anomalies_detected}</strong></li>
                            <li>Duplicates Skipped: <strong>${data.duplicate_count || 0}</strong></li>
                        </ul>
                        <div class="d-flex gap-2 mt-2 pt-2 border-top">
                            <button type="button" class="btn btn-sm btn-primary flex-fill" onclick="window.location.reload();">
                                <i class="bi bi-table me-1"></i>View in Logs Table
                            </button>
                        </div>
                    `;
                    uploadFeedback.classList.remove('d-none');

                    // If errors occurred on some rows, display them
                    if (data.errors && data.errors.length > 0) {
                        let errList = '<div class="mt-2 text-warning"><strong>Validation Notes:</strong><ul>';
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
                    }, 2500);

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
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
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
                showToast('Copying ALL records to Supabase Cloud...', 'info');
                try {
                    const res = await fetch('/api/sync/supabase', { method: 'POST' });
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
                    if (data.success) {
                        showToast(data.message || 'All records successfully copied to Supabase!', 'success');
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

        const clearLocalBtn = document.getElementById('btnClearLocalLogs');
        const purgeMainBtn = document.getElementById('btnPurgeMainDB');

        if (clearLocalBtn) {
            clearLocalBtn.addEventListener('click', async () => {
                if (confirm('Delete all log data from LOCAL storage/database? (Your Main Supabase Cloud Database will NOT be affected)')) {
                    try {
                        const res = await fetch('/api/logs/batch-delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ clear_all: true, purge_supabase: false })
                        });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            fetchLogs();
                        } else {
                            showToast(data.message || 'Failed to clear local logs.', 'danger');
                        }
                    } catch (err) {
                        showToast('Failed to clear local logs.', 'danger');
                    }
                }
            });
        }

        if (purgeMainBtn) {
            purgeMainBtn.addEventListener('click', () => {
                showMainDbDeleteModal({
                    targetText: 'ALL RECORDS in Main Database & Local Storage',
                    warningStatement: 'This action will permanently delete <strong>ALL LOGS, ANOMALIES, AND AI ANALYSES</strong> from your <strong>MAIN DATABASE (SUPABASE CLOUD)</strong> and local database.',
                    onConfirm: async () => {
                        const res = await fetch('/api/logs/batch-delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ clear_all: true, purge_supabase: true })
                        });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            fetchLogs();
                        } else {
                            showToast(data.message || 'Failed to purge main database.', 'danger');
                        }
                    }
                });
            });
        }

        const cleanDatasetBtn = document.getElementById('btnCleanDataset');
        if (cleanDatasetBtn) {
            cleanDatasetBtn.addEventListener('click', async () => {
                cleanDatasetBtn.disabled = true;
                const originalHtml = cleanDatasetBtn.innerHTML;
                cleanDatasetBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Cleaning...';
                try {
                    const res = await fetch('/api/dataset/clean', { method: 'POST' });
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
                    if (data.success) {
                        showToast(data.message || 'Dataset successfully cleaned and formatted!', 'success');
                        fetchLogs();
                    } else {
                        showToast(data.message || 'Failed to clean dataset.', 'danger');
                    }
                } catch (err) {
                    showToast('Network error while cleaning dataset.', 'danger');
                } finally {
                    cleanDatasetBtn.disabled = false;
                    cleanDatasetBtn.innerHTML = originalHtml;
                }
            });
        }

        const copyAllBtn = document.getElementById('btnCopyAllMainDB') || document.getElementById('btnCleanSyncSupabase');
        if (copyAllBtn) {
            copyAllBtn.addEventListener('click', async () => {
                copyAllBtn.disabled = true;
                const originalHtml = copyAllBtn.innerHTML;
                copyAllBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Copying ALL to Main DB...';
                try {
                    const res = await fetch('/api/dataset/sync-supabase', { method: 'POST' });
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
                    if (data.success) {
                        showToast(data.message || 'All records successfully copied to Main Supabase Database!', 'success');
                        fetchLogs();
                    } else {
                        showToast(data.message || data.error || 'Failed to copy data to Main Database.', 'danger');
                    }
                } catch (err) {
                    showToast('Network error while copying to Main Database.', 'danger');
                } finally {
                    copyAllBtn.disabled = false;
                    copyAllBtn.innerHTML = originalHtml;
                }
            });
        }

        const feedAiBtn = document.getElementById('btnFeedAiSupabase');
        if (feedAiBtn) {
            feedAiBtn.addEventListener('click', async () => {
                feedAiBtn.disabled = true;
                const originalHtml = feedAiBtn.innerHTML;
                feedAiBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Feeding AI...';
                try {
                    const res = await fetch('/api/dataset/feed-ai-supabase', { method: 'POST' });
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
                    if (data.success) {
                        showToast(data.message || 'AI analyses successfully fed to Supabase ai_analysis table!', 'success');
                        fetchLogs();
                    } else {
                        showToast(data.message || 'Failed to feed AI analyses to Supabase.', 'danger');
                    }
                } catch (err) {
                    showToast('Network error while feeding AI analyses to Supabase.', 'danger');
                } finally {
                    feedAiBtn.disabled = false;
                    feedAiBtn.innerHTML = originalHtml;
                }
            });
        }

        let selectedLogIds = new Set();

        function updateSelectionUI() {
            const actionBar = document.getElementById('selectionActionBar');
            const countText = document.getElementById('selectedCountText');
            const selectAllCheckbox = document.getElementById('selectAllLogs');

            if (countText) {
                countText.textContent = `${selectedLogIds.size} log${selectedLogIds.size === 1 ? '' : 's'} selected`;
            }
            if (actionBar) {
                if (selectedLogIds.size > 0) {
                    actionBar.classList.remove('d-none');
                } else {
                    actionBar.classList.add('d-none');
                }
            }
            if (selectAllCheckbox) {
                const rowCheckboxes = document.querySelectorAll('.row-select-checkbox');
                if (rowCheckboxes.length > 0 && Array.from(rowCheckboxes).every(cb => cb.checked)) {
                    selectAllCheckbox.checked = true;
                    selectAllCheckbox.indeterminate = false;
                } else if (Array.from(rowCheckboxes).some(cb => cb.checked)) {
                    selectAllCheckbox.checked = false;
                    selectAllCheckbox.indeterminate = true;
                } else {
                    selectAllCheckbox.checked = false;
                    selectAllCheckbox.indeterminate = false;
                }
            }
        }

        // Select All Checkbox Handler
        const selectAllCb = document.getElementById('selectAllLogs');
        if (selectAllCb) {
            selectAllCb.addEventListener('change', () => {
                const rowCheckboxes = document.querySelectorAll('.row-select-checkbox');
                rowCheckboxes.forEach(cb => {
                    const logId = parseInt(cb.getAttribute('data-log-id'));
                    cb.checked = selectAllCb.checked;
                    if (selectAllCb.checked) {
                        selectedLogIds.add(logId);
                    } else {
                        selectedLogIds.delete(logId);
                    }
                });
                updateSelectionUI();
            });
        }

        // Deselect All Action
        const deselectBtn = document.getElementById('btnDeselectAll');
        if (deselectBtn) {
            deselectBtn.addEventListener('click', () => {
                selectedLogIds.clear();
                const rowCheckboxes = document.querySelectorAll('.row-select-checkbox');
                rowCheckboxes.forEach(cb => cb.checked = false);
                updateSelectionUI();
            });
        }

        // Delete Selected (Local Only)
        const deleteSelectedLocalBtn = document.getElementById('btnDeleteSelectedLocal');
        if (deleteSelectedLocalBtn) {
            deleteSelectedLocalBtn.addEventListener('click', async () => {
                if (selectedLogIds.size === 0) return;
                const count = selectedLogIds.size;
                if (confirm(`Delete ${count} selected log(s) from LOCAL storage/database? (Main Database will NOT be affected)`)) {
                    try {
                        const res = await fetch('/api/logs/batch-delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ log_ids: Array.from(selectedLogIds), purge_supabase: false })
                        });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            selectedLogIds.clear();
                            updateSelectionUI();
                            fetchLogs();
                        } else {
                            showToast(data.message || 'Failed to delete selected logs.', 'danger');
                        }
                    } catch (err) {
                        showToast('Network error while deleting selected logs.', 'danger');
                    }
                }
            });
        }

        // Delete Selected from Main DB (Supabase + Local)
        const deleteSelectedMainBtn = document.getElementById('btnDeleteSelectedMainDB');
        if (deleteSelectedMainBtn) {
            deleteSelectedMainBtn.addEventListener('click', () => {
                if (selectedLogIds.size === 0) return;
                const count = selectedLogIds.size;
                showMainDbDeleteModal({
                    targetText: `${count} Selected Log Records`,
                    warningStatement: `This action will permanently delete <strong>${count} SELECTED LOGS, ANOMALIES, AND AI ANALYSES</strong> from your <strong>MAIN SUPABASE DATABASE</strong> and local storage.`,
                    onConfirm: async () => {
                        const res = await fetch('/api/logs/batch-delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ log_ids: Array.from(selectedLogIds), purge_supabase: true })
                        });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            selectedLogIds.clear();
                            updateSelectionUI();
                            fetchLogs();
                        } else {
                            showToast(data.message || 'Failed to delete selected logs from main database.', 'danger');
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
                        <td colspan="11" class="text-center py-5 text-muted">
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
                        <td class="text-center">
                            <input class="form-check-input row-select-checkbox" type="checkbox" data-log-id="${log.id}">
                        </td>
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
                            <button class="btn btn-xs btn-outline-secondary btn-sm btn-delete-local me-1" data-log-id="${log.id}" title="Delete from Local Database only">
                                <i class="bi bi-trash"></i>
                            </button>
                            <button class="btn btn-xs btn-outline-danger btn-sm btn-delete-main" data-log-id="${log.id}" title="Permanently Delete from Main Database (Supabase Cloud)">
                                <i class="bi bi-cloud-slash"></i>
                            </button>
                        </td>
                    </tr>
                `;
            });

            tbody.innerHTML = rowsHtml;
            renderPagination(data.pages, data.page);

            // Bind row selection checkboxes
            tbody.querySelectorAll('.row-select-checkbox').forEach(cb => {
                cb.addEventListener('change', () => {
                    const id = parseInt(cb.getAttribute('data-log-id'));
                    if (cb.checked) {
                        selectedLogIds.add(id);
                    } else {
                        selectedLogIds.delete(id);
                    }
                    updateSelectionUI();
                });
            });

            // 1. Bind Delete Local buttons (deletes from local SQLite only)
            document.querySelectorAll('.btn-delete-local').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const id = btn.getAttribute('data-log-id');
                    if (confirm(`Delete log #${id} from LOCAL database only? (Supabase cloud database will remain untouched)`)) {
                        try {
                            const delRes = await fetch(`/api/logs/${id}?purge_supabase=false`, { method: 'DELETE' });
                            const delData = await delRes.json();
                            if (delData.success) {
                                showToast(delData.message, 'success');
                                fetchLogs();
                            } else {
                                showToast(delData.message || 'Failed to delete log locally.', 'danger');
                            }
                        } catch (e) {
                            showToast('Failed to delete log.', 'danger');
                        }
                    }
                });
            });

            // 2. Bind Permanently Delete from Main Database (Supabase Cloud + Local)
            document.querySelectorAll('.btn-delete-main').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-log-id');
                    showMainDbDeleteModal({
                        targetText: `Log Record #${id}`,
                        warningStatement: `This action will permanently delete Log #${id} from your <strong>MAIN SUPABASE DATABASE</strong> and local storage.`,
                        onConfirm: async () => {
                            const delRes = await fetch(`/api/logs/${id}?purge_supabase=true`, { method: 'DELETE' });
                            const delData = await delRes.json();
                            if (delData.success) {
                                showToast(delData.message, 'success');
                                fetchLogs();
                            } else {
                                showToast(delData.message || 'Failed to delete log from main database.', 'danger');
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
        const deleteLocalBtn = document.getElementById('btnDeleteLocal');
        const deleteMainBtn = document.getElementById('btnDeleteMainDB');

        // Button 1: Delete Local Only
        if (deleteLocalBtn) {
            deleteLocalBtn.addEventListener('click', async () => {
                const logId = deleteLocalBtn.getAttribute('data-log-id');
                if (confirm(`Delete log #${logId} from LOCAL storage/database only? (Your Main Supabase Cloud Database will NOT be affected)`)) {
                    try {
                        const res = await fetch(`/api/logs/${logId}?purge_supabase=false`, { method: 'DELETE' });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            setTimeout(() => window.location.href = '/logs', 800);
                        } else {
                            showToast(data.message || 'Failed to delete log locally.', 'danger');
                        }
                    } catch (e) {
                        showToast('Failed to delete log from local database.', 'danger');
                    }
                }
            });
        }

        // Button 2: Permanently Delete from Main Database (Supabase + Local)
        if (deleteMainBtn) {
            deleteMainBtn.addEventListener('click', () => {
                const logId = deleteMainBtn.getAttribute('data-log-id');
                showMainDbDeleteModal({
                    targetText: `Log Record #${logId}`,
                    warningStatement: `This action will permanently delete Log #${logId} from your <strong>MAIN SUPABASE DATABASE</strong> and local storage.`,
                    onConfirm: async () => {
                        const res = await fetch(`/api/logs/${logId}?purge_supabase=true`, { method: 'DELETE' });
                        const data = await res.json();
                        if (data.success) {
                            showToast(data.message, 'success');
                            setTimeout(() => window.location.href = '/logs', 800);
                        } else {
                            showToast(data.message || 'Failed to delete log from main database.', 'danger');
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
                    const resText = await res.text();
                    let result;
                    try {
                        result = JSON.parse(resText);
                    } catch (e) {
                        let clean = resText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
                        if (clean.length > 180) clean = clean.substring(0, 180) + '...';
                        result = { success: false, message: clean || `Server returned status ${res.status}` };
                    }

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

    // =========================================================================
    // 8. Live Computer Log Monitor
    // =========================================================================
    function initLiveMonitor() {
        let isStreaming = true;
        let streamTimer = null;
        let capturedCount = 0;
        let anomaliesCount = 0;
        let seenIds = new Set();

        const tableBody = document.getElementById('liveLogsTableBody');
        const emptyRow = document.getElementById('liveEmptyRow');
        const capturedMetric = document.getElementById('liveCapturedCount');
        const anomaliesMetric = document.getElementById('liveAnomaliesCount');
        const lastCaptureText = document.getElementById('lastCaptureTime');
        const statusText = document.getElementById('streamStatusText');
        const statusBadge = document.getElementById('liveStatusBadge');
        const captureNowBtn = document.getElementById('btnCaptureNow');
        const toggleStreamBtn = document.getElementById('btnToggleAutoStream');
        const streamIcon = document.getElementById('autoStreamIcon');
        const streamText = document.getElementById('autoStreamText');
        const channelSelect = document.getElementById('selectLiveChannel');
        const intervalSelect = document.getElementById('selectStreamInterval');
        const clearConsoleBtn = document.getElementById('btnClearLiveConsole');
        const syncSupabaseBtn = document.getElementById('btnLiveSyncSupabase');
        const scrollContainer = document.getElementById('liveTableScrollContainer');
        const autoScrollChk = document.getElementById('chkAutoScroll');

        async function captureEvents() {
            const channel = channelSelect ? channelSelect.value : 'Application';
            try {
                const res = await fetch('/api/live/capture', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ count: 4, channel: channel })
                });
                const resText = await res.text();
                let data;
                try { data = JSON.parse(resText); } catch(e) { data = { success: false }; }

                if (data.success && data.items && data.items.length > 0) {
                    if (emptyRow && emptyRow.parentNode) {
                        emptyRow.remove();
                    }

                    data.items.forEach(log => {
                        if (seenIds.has(log.id)) return;
                        seenIds.add(log.id);

                        capturedCount++;
                        if (log.anomaly) anomaliesCount++;

                        const rowClass = log.anomaly ? 'row-anomaly table-danger' : '';
                        const sevBadge = getSeverityBadge(log.severity);
                        const statusBadge = log.status_code ? `<span class="badge ${log.status_code >= 500 ? 'bg-danger' : log.status_code >= 400 ? 'bg-warning text-dark' : 'bg-success'}">${log.status_code}</span>` : '<span class="text-muted">-</span>';
                        const anomBadge = log.anomaly 
                            ? '<span class="badge bg-danger"><i class="bi bi-exclamation-triangle-fill me-1"></i>ANOMALY</span>' 
                            : '<span class="badge bg-success-subtle text-success border">NORMAL</span>';

                        const tr = document.createElement('tr');
                        tr.className = rowClass;
                        tr.innerHTML = `
                            <td class="font-monospace small text-nowrap">${log.timestamp}</td>
                            <td><span class="badge bg-secondary-subtle text-body border">${log.source}</span></td>
                            <td><span class="badge bg-primary-subtle text-primary border">${log.event_type}</span></td>
                            <td>${sevBadge}</td>
                            <td>${statusBadge}</td>
                            <td>${anomBadge}</td>
                            <td>
                                <div class="text-truncate font-monospace small" style="max-width: 380px;" title="${log.message}">
                                    ${log.message}
                                </div>
                                ${log.anomaly ? `<div class="small text-danger text-truncate" style="max-width: 380px;"><i class="bi bi-info-circle me-1"></i>${log.anomaly_reason || ''}</div>` : ''}
                            </td>
                            <td class="text-end text-nowrap">
                                <a href="/logs/${log.id}" class="btn btn-xs btn-outline-primary btn-sm" title="Inspect Log & AI Explanation">
                                    <i class="bi bi-eye"></i>
                                </a>
                            </td>
                        `;

                        if (tableBody.firstChild) {
                            tableBody.insertBefore(tr, tableBody.firstChild);
                        } else {
                            tableBody.appendChild(tr);
                        }
                    });

                    // Keep table buffer under 200 items
                    while (tableBody.children.length > 200) {
                        tableBody.removeChild(tableBody.lastChild);
                    }

                    if (capturedMetric) capturedMetric.textContent = capturedCount;
                    if (anomaliesMetric) anomaliesMetric.textContent = anomaliesCount;
                    if (lastCaptureText) lastCaptureText.textContent = `Last capture: ${new Date().toLocaleTimeString()}`;

                    if (autoScrollChk && autoScrollChk.checked && scrollContainer) {
                        scrollContainer.scrollTop = 0;
                    }
                }
            } catch (err) {
                console.error('[LiveStream Error]', err);
            }
        }

        function startStream() {
            stopStream();
            const interval = parseInt(intervalSelect ? intervalSelect.value : 3000) || 3000;
            isStreaming = true;
            if (statusText) {
                statusText.textContent = 'Active Streaming';
                statusText.className = 'fw-bold mb-0 text-success';
            }
            if (statusBadge) {
                statusBadge.className = 'badge bg-danger d-inline-flex align-items-center gap-1';
                statusBadge.innerHTML = '<span class="spinner-grow spinner-grow-sm text-light" style="width: 0.5rem; height: 0.5rem;" role="status"></span> LIVE STREAM';
            }
            if (streamIcon) streamIcon.className = 'bi bi-pause-fill me-1';
            if (streamText) streamText.textContent = 'Pause Auto-Stream';
            
            captureEvents();
            streamTimer = setInterval(captureEvents, interval);
        }

        function stopStream() {
            if (streamTimer) {
                clearInterval(streamTimer);
                streamTimer = null;
            }
            isStreaming = false;
            if (statusText) {
                statusText.textContent = 'Stream Paused';
                statusText.className = 'fw-bold mb-0 text-secondary';
            }
            if (statusBadge) {
                statusBadge.className = 'badge bg-secondary d-inline-flex align-items-center gap-1';
                statusBadge.innerHTML = '<i class="bi bi-pause-circle"></i> PAUSED';
            }
            if (streamIcon) streamIcon.className = 'bi bi-play-fill me-1';
            if (streamText) streamText.textContent = 'Resume Auto-Stream';
        }

        if (captureNowBtn) {
            captureNowBtn.addEventListener('click', () => {
                captureEvents();
                showToast('Capturing live log events from host PC...', 'info');
            });
        }

        if (toggleStreamBtn) {
            toggleStreamBtn.addEventListener('click', () => {
                if (isStreaming) {
                    stopStream();
                } else {
                    startStream();
                }
            });
        }

        if (intervalSelect) {
            intervalSelect.addEventListener('change', () => {
                if (isStreaming) {
                    startStream();
                }
            });
        }

        if (clearConsoleBtn) {
            clearConsoleBtn.addEventListener('click', () => {
                tableBody.innerHTML = `
                    <tr id="liveEmptyRow">
                        <td colspan="8" class="text-center py-5 text-muted">
                            <i class="bi bi-terminal display-6 d-block mb-2"></i>
                            Display cleared. Listening for incoming live computer events...
                        </td>
                    </tr>
                `;
                capturedCount = 0;
                anomaliesCount = 0;
                seenIds.clear();
                if (capturedMetric) capturedMetric.textContent = '0';
                if (anomaliesMetric) anomaliesMetric.textContent = '0';
            });
        }

        if (syncSupabaseBtn) {
            syncSupabaseBtn.addEventListener('click', async () => {
                syncSupabaseBtn.disabled = true;
                const originalHtml = syncSupabaseBtn.innerHTML;
                syncSupabaseBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Syncing...';
                try {
                    const res = await fetch('/api/dataset/sync-supabase', { method: 'POST' });
                    const resText = await res.text();
                    let data;
                    try { data = JSON.parse(resText); } catch(e) { data = { success: false, message: resText.replace(/<[^>]+>/g, '').trim() }; }
                    if (data.success) {
                        showToast(data.message || 'Live logs synced to Supabase!', 'success');
                    } else {
                        showToast(data.message || data.error || 'Failed to sync live logs.', 'danger');
                    }
                } catch (err) {
                    showToast('Network error while syncing.', 'danger');
                } finally {
                    syncSupabaseBtn.disabled = false;
                    syncSupabaseBtn.innerHTML = originalHtml;
                }
            });
        }

        startStream();
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
        initLiveMonitor,
        showToast,
    };
})();
