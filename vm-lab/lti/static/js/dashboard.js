// Central Piedmont LabsConnect - Instructor Dashboard JavaScript

let currentPage = 1;
const pageSize = 20;
let totalRecordings = 0;
let currentPlayer = null;
let currentRecordingId = null;
let demoVMSessionId = null;

// Initialize dashboard on load
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    // Set user info from config
    if (window.dashboardConfig) {
        document.getElementById('instructor-name').textContent = window.dashboardConfig.instructorName || 'Instructor';
        document.getElementById('course-name').textContent = window.dashboardConfig.courseName || 'Course';
    }

    // Load initial data
    loadStats();
    loadRecordings();
    loadActiveSessions();
    loadAssignments();
    checkDemoVM();

    // Set up auto-refresh for active sessions and demo VM status
    setInterval(loadActiveSessions, 30000);
    setInterval(checkDemoVM, 30000);

    // Set default date filter to last 30 days
    const today = new Date();
    const thirtyDaysAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
    document.getElementById('filter-date-to').value = formatDate(today);
    document.getElementById('filter-date-from').value = formatDate(thirtyDaysAgo);
}

function formatDate(date) {
    return date.toISOString().split('T')[0];
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatDuration(seconds) {
    if (!seconds) return 'N/A';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins > 60) {
        const hours = Math.floor(mins / 60);
        const remainingMins = mins % 60;
        return `${hours}h ${remainingMins}m`;
    }
    return `${mins}m ${secs}s`;
}

function formatFileSize(bytes) {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// API Calls
async function apiCall(endpoint, options = {}) {
    const baseUrl = window.dashboardConfig?.apiBase || '';
    const token = window.dashboardConfig?.token || '';

    // Add Authorization header with token
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    try {
        const response = await fetch(`${baseUrl}${endpoint}`, {
            ...options,
            headers,
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        return null;
    }
}

async function loadStats() {
    const stats = await apiCall('/api/stats');
    if (stats) {
        document.getElementById('total-sessions').textContent = stats.total_sessions || 0;
        document.getElementById('active-sessions').textContent = stats.active_sessions || 0;
        document.getElementById('total-recordings').textContent = stats.total_recordings || 0;
        document.getElementById('unique-students').textContent = stats.unique_students || 0;
    }
}

async function loadRecordings() {
    const tbody = document.getElementById('recordings-body');
    tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-8 text-center text-slate-500">Loading recordings...</td></tr>';

    // Build query params
    const params = new URLSearchParams();
    params.append('limit', pageSize);
    params.append('offset', (currentPage - 1) * pageSize);

    const studentFilter = document.getElementById('filter-student').value;
    const dateFrom = document.getElementById('filter-date-from').value;
    const dateTo = document.getElementById('filter-date-to').value;
    const assignment = document.getElementById('filter-assignment').value;

    if (studentFilter) {
        if (studentFilter.includes('@')) {
            params.append('user_email', studentFilter);
        } else {
            params.append('user_name', studentFilter);
        }
    }
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (assignment) params.append('assignment_id', assignment);

    if (window.dashboardConfig?.courseId) {
        params.append('course_id', window.dashboardConfig.courseId);
    }

    const data = await apiCall(`/api/recordings?${params.toString()}`);

    if (!data || !data.recordings) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-8 text-center text-slate-500">Failed to load recordings</td></tr>';
        return;
    }

    totalRecordings = data.total || 0;
    updatePagination();

    if (data.recordings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-8 text-center text-slate-500">No recordings found</td></tr>';
        return;
    }

    tbody.innerHTML = data.recordings.map(recording => `
        <tr class="hover:bg-slate-50 transition">
            <td class="px-6 py-4 text-sm font-medium text-slate-900">${escapeHtml(recording.user_name || 'Unknown')}</td>
            <td class="px-6 py-4 text-sm text-slate-600">${escapeHtml(recording.user_email || 'Unknown')}</td>
            <td class="px-6 py-4 text-sm text-slate-600">${escapeHtml(recording.assignment_title || recording.course_title || 'N/A')}</td>
            <td class="px-6 py-4 text-sm text-slate-600">${formatDateTime(recording.started_at)}</td>
            <td class="px-6 py-4 text-sm text-slate-600">${formatDuration(recording.duration_seconds)}</td>
            <td class="px-6 py-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusClasses(recording.status)}">
                    ${recording.status}
                </span>
            </td>
            <td class="px-6 py-4">
                <div class="flex items-center gap-2">
                    <button onclick="playRecording(${recording.id})"
                            class="px-3 py-1.5 bg-cpcc-primary text-white text-xs font-medium rounded-lg hover:bg-cpcc-dark transition">
                        Play
                    </button>
                    <button onclick="viewText(${recording.id})"
                            class="px-3 py-1.5 bg-slate-100 text-slate-700 text-xs font-medium rounded-lg hover:bg-slate-200 transition">
                        Text
                    </button>
                    <button onclick="downloadRecording(${recording.id})"
                            class="px-3 py-1.5 bg-slate-100 text-slate-700 text-xs font-medium rounded-lg hover:bg-slate-200 transition">
                        Download
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

function getStatusClasses(status) {
    switch (status) {
        case 'completed':
            return 'bg-emerald-100 text-emerald-800';
        case 'running':
            return 'bg-blue-100 text-blue-800';
        case 'error':
            return 'bg-red-100 text-red-800';
        default:
            return 'bg-slate-100 text-slate-800';
    }
}

async function loadActiveSessions() {
    const grid = document.getElementById('active-sessions-grid');
    const data = await apiCall('/api/sessions?status=running');

    if (!data || !data.sessions || data.sessions.length === 0) {
        grid.innerHTML = '<p class="text-slate-500 text-sm col-span-full">No active sessions</p>';
        document.getElementById('active-sessions').textContent = '0';
        return;
    }

    let sessions = data.sessions;
    if (window.dashboardConfig?.courseId) {
        sessions = sessions.filter(s => s.course_id === window.dashboardConfig.courseId);
    }

    document.getElementById('active-sessions').textContent = sessions.length;

    if (sessions.length === 0) {
        grid.innerHTML = '<p class="text-slate-500 text-sm col-span-full">No active sessions for this course</p>';
        return;
    }

    grid.innerHTML = sessions.map(session => `
        <div class="bg-slate-50 rounded-xl p-4 border border-slate-200">
            <div class="flex items-start justify-between mb-3">
                <div>
                    <h4 class="font-semibold text-slate-800">${escapeHtml(session.user_name || 'Unknown Student')}</h4>
                    <p class="text-sm text-slate-500">${escapeHtml(session.user_email || '')}</p>
                </div>
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-100 text-emerald-800">
                    <span class="w-1.5 h-1.5 bg-emerald-500 rounded-full mr-1 animate-pulse"></span>
                    Active
                </span>
            </div>
            <div class="space-y-1 text-sm">
                <p class="text-slate-600"><span class="text-slate-400">VM:</span> ${escapeHtml(session.vm_ip || 'N/A')}</p>
                <p class="text-slate-600"><span class="text-slate-400">Started:</span> ${formatDateTime(session.created_at)}</p>
                <p class="text-slate-600"><span class="text-slate-400">Expires:</span> ${formatDateTime(session.expires_at)}</p>
            </div>
        </div>
    `).join('');
}

async function loadAssignments() {
    const data = await apiCall('/api/recordings?limit=1000');
    if (!data || !data.recordings) return;

    const assignments = new Map();
    data.recordings.forEach(r => {
        if (r.assignment_id && r.assignment_title) {
            assignments.set(r.assignment_id, r.assignment_title);
        }
    });

    const select = document.getElementById('filter-assignment');
    select.innerHTML = '<option value="">All Assignments</option>';
    assignments.forEach((title, id) => {
        const option = document.createElement('option');
        option.value = id;
        option.textContent = title;
        select.appendChild(option);
    });
}

// Pagination
function updatePagination() {
    const totalPages = Math.ceil(totalRecordings / pageSize);
    document.getElementById('page-info').textContent = `Page ${currentPage} of ${totalPages || 1}`;
    document.getElementById('prev-page').disabled = currentPage <= 1;
    document.getElementById('next-page').disabled = currentPage >= totalPages;
}

function nextPage() {
    const totalPages = Math.ceil(totalRecordings / pageSize);
    if (currentPage < totalPages) {
        currentPage++;
        loadRecordings();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadRecordings();
    }
}

// Filters
function applyFilters() {
    currentPage = 1;
    loadRecordings();
}

function clearFilters() {
    document.getElementById('filter-student').value = '';
    document.getElementById('filter-date-from').value = '';
    document.getElementById('filter-date-to').value = '';
    document.getElementById('filter-assignment').value = '';
    currentPage = 1;
    loadRecordings();
}

// Recording Playback
async function playRecording(recordingId) {
    currentRecordingId = recordingId;
    const modal = document.getElementById('player-modal');
    const container = document.getElementById('player-container');
    const infoDiv = document.getElementById('recording-info');

    modal.classList.remove('hidden');
    container.innerHTML = '<p class="text-white text-center py-8">Loading recording...</p>';

    const info = await apiCall(`/api/recordings/${recordingId}`);
    if (info) {
        document.getElementById('player-title').textContent =
            `Recording: ${info.user_name || 'Unknown'} - ${formatDateTime(info.started_at)}`;
        infoDiv.innerHTML = `
            <div class="grid grid-cols-2 gap-2 text-sm">
                <p><span class="text-slate-400">Student:</span> ${escapeHtml(info.user_name || 'Unknown')}</p>
                <p><span class="text-slate-400">Email:</span> ${escapeHtml(info.user_email || 'Unknown')}</p>
                <p><span class="text-slate-400">Course:</span> ${escapeHtml(info.course_title || 'N/A')}</p>
                <p><span class="text-slate-400">Assignment:</span> ${escapeHtml(info.assignment_title || 'N/A')}</p>
                <p><span class="text-slate-400">Duration:</span> ${formatDuration(info.duration_seconds)}</p>
                <p><span class="text-slate-400">Size:</span> ${formatFileSize(info.file_size_bytes)}</p>
            </div>
        `;
    }

    try {
        if (currentPlayer) {
            currentPlayer.dispose();
            currentPlayer = null;
        }
        container.innerHTML = '';

        const token = window.dashboardConfig?.token || '';
        const castUrl = `${window.dashboardConfig?.apiBase || ''}/api/recordings/${recordingId}/cast?_token=${encodeURIComponent(token)}`;

        currentPlayer = AsciinemaPlayer.create(
            castUrl,
            container,
            {
                cols: 120,
                rows: 30,
                autoPlay: true,
                preload: true,
                poster: 'npt:0:1',
                theme: 'asciinema'
            }
        );
    } catch (error) {
        console.error('Player error:', error);
        container.innerHTML = `
            <div class="text-white text-center py-8">
                <p class="mb-4">Unable to play recording.</p>
                <button onclick="viewText(${recordingId}); closePlayer();"
                        class="px-4 py-2 bg-slate-600 rounded-lg hover:bg-slate-500 transition">
                    View as text instead
                </button>
            </div>
        `;
    }
}

function setPlaybackSpeed(speed) {
    if (currentPlayer && currentPlayer.setSpeed) {
        currentPlayer.setSpeed(speed);
    }
}

function closePlayer() {
    const modal = document.getElementById('player-modal');
    modal.classList.add('hidden');
    if (currentPlayer) {
        currentPlayer.dispose();
        currentPlayer = null;
    }
    currentRecordingId = null;
}

// Text View
async function viewText(recordingId) {
    currentRecordingId = recordingId;
    const modal = document.getElementById('text-modal');
    const content = document.getElementById('text-content');

    modal.classList.remove('hidden');
    content.textContent = 'Loading...';

    const info = await apiCall(`/api/recordings/${recordingId}`);
    if (info) {
        document.getElementById('text-title').textContent =
            `Transcript: ${info.user_name || 'Unknown'} - ${formatDateTime(info.started_at)}`;
    }

    try {
        const baseUrl = window.dashboardConfig?.apiBase || '';
        const token = window.dashboardConfig?.token || '';
        const response = await fetch(`${baseUrl}/api/recordings/${recordingId}/view`, {
            headers: { 'Authorization': `Bearer ${token}` },
            credentials: 'include'
        });
        const text = await response.text();
        content.textContent = text || '(Empty recording)';
    } catch (error) {
        content.textContent = 'Failed to load recording content.';
    }
}

function closeTextView() {
    const modal = document.getElementById('text-modal');
    modal.classList.add('hidden');
    currentRecordingId = null;
}

async function downloadTranscript() {
    if (!currentRecordingId) return;

    const content = document.getElementById('text-content').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recording-${currentRecordingId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// Download
async function downloadRecording(recordingId) {
    const baseUrl = window.dashboardConfig?.apiBase || '';

    const logLink = document.createElement('a');
    logLink.href = `${baseUrl}/api/recordings/${recordingId}/download`;
    logLink.download = `session-${recordingId}.log`;
    logLink.click();

    setTimeout(() => {
        const timingLink = document.createElement('a');
        timingLink.href = `${baseUrl}/api/recordings/${recordingId}/timing`;
        timingLink.download = `session-${recordingId}.timing`;
        timingLink.click();
    }, 500);
}

// Utility
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modals on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closePlayer();
        closeTextView();
    }
});

// Close modals on outside click
document.addEventListener('click', function(e) {
    if (e.target.id === 'player-modal' || e.target.id === 'text-modal') {
        closePlayer();
        closeTextView();
    }
});

// ============================================================================
// Demo VM Functions
// ============================================================================

async function checkDemoVM() {
    const data = await apiCall('/api/demo-vm');
    if (data && data.session_id) {
        demoVMSessionId = data.session_id;
        showDemoVMActive(data);
    } else {
        demoVMSessionId = null;
        showDemoVMInactive();
    }
}

function showDemoVMInactive() {
    document.getElementById('demo-vm-inactive').classList.remove('hidden');
    document.getElementById('demo-vm-loading').classList.add('hidden');
    document.getElementById('demo-vm-active').classList.add('hidden');
}

function showDemoVMLoading() {
    document.getElementById('demo-vm-inactive').classList.add('hidden');
    document.getElementById('demo-vm-loading').classList.remove('hidden');
    document.getElementById('demo-vm-active').classList.add('hidden');
}

function showDemoVMActive(data) {
    document.getElementById('demo-vm-inactive').classList.add('hidden');
    document.getElementById('demo-vm-loading').classList.add('hidden');
    document.getElementById('demo-vm-active').classList.remove('hidden');

    document.getElementById('demo-vm-ip').textContent = data.vm_ip || 'N/A';
    document.getElementById('demo-vm-link').href = data.url || '#';
}

async function launchDemoVM() {
    showDemoVMLoading();

    try {
        const token = window.dashboardConfig?.token || '';
        const response = await fetch('/api/demo-vm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to provision demo VM');
        }

        const data = await response.json();
        demoVMSessionId = data.session_id;
        showDemoVMActive(data);

        loadStats();
        loadActiveSessions();

    } catch (error) {
        console.error('Error launching demo VM:', error);
        alert('Failed to launch demo VM: ' + error.message);
        showDemoVMInactive();
    }
}

async function destroyDemoVM() {
    if (!demoVMSessionId) {
        alert('No active demo VM to destroy');
        return;
    }

    if (!confirm('Are you sure you want to destroy the demo VM? This cannot be undone.')) {
        return;
    }

    try {
        const token = window.dashboardConfig?.token || '';
        const response = await fetch(`/api/demo-vm`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to destroy demo VM');
        }

        demoVMSessionId = null;
        showDemoVMInactive();

        loadStats();
        loadActiveSessions();

    } catch (error) {
        console.error('Error destroying demo VM:', error);
        alert('Failed to destroy demo VM: ' + error.message);
    }
}
