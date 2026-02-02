// VM Lab Instructor Dashboard JavaScript

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
    try {
        const response = await fetch(`${baseUrl}${endpoint}`, options);
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
    tbody.innerHTML = '<tr><td colspan="7" class="loading">Loading recordings...</td></tr>';

    // Build query params
    const params = new URLSearchParams();
    params.append('limit', pageSize);
    params.append('offset', (currentPage - 1) * pageSize);

    const studentFilter = document.getElementById('filter-student').value;
    const dateFrom = document.getElementById('filter-date-from').value;
    const dateTo = document.getElementById('filter-date-to').value;
    const assignment = document.getElementById('filter-assignment').value;

    if (studentFilter) {
        // Search both name and email
        if (studentFilter.includes('@')) {
            params.append('user_email', studentFilter);
        } else {
            params.append('user_name', studentFilter);
        }
    }
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (assignment) params.append('assignment_id', assignment);

    // Add course filter if available
    if (window.dashboardConfig?.courseId) {
        params.append('course_id', window.dashboardConfig.courseId);
    }

    const data = await apiCall(`/api/recordings?${params.toString()}`);

    if (!data || !data.recordings) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">Failed to load recordings</td></tr>';
        return;
    }

    totalRecordings = data.total || 0;
    updatePagination();

    if (data.recordings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">No recordings found</td></tr>';
        return;
    }

    tbody.innerHTML = data.recordings.map(recording => `
        <tr>
            <td>${escapeHtml(recording.user_name || 'Unknown')}</td>
            <td>${escapeHtml(recording.user_email || 'Unknown')}</td>
            <td>${escapeHtml(recording.assignment_title || recording.course_title || 'N/A')}</td>
            <td>${formatDateTime(recording.started_at)}</td>
            <td>${formatDuration(recording.duration_seconds)}</td>
            <td><span class="status-badge status-${recording.status}">${recording.status}</span></td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-primary btn-sm" onclick="playRecording(${recording.id})"
                            data-tooltip="Play recording">
                        &#9658; Play
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="viewText(${recording.id})"
                            data-tooltip="View as text">
                        &#128196; Text
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="downloadRecording(${recording.id})"
                            data-tooltip="Download files">
                        &#8681; Download
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function loadActiveSessions() {
    const grid = document.getElementById('active-sessions-grid');
    const data = await apiCall('/api/sessions?status=running');

    if (!data || !data.sessions || data.sessions.length === 0) {
        grid.innerHTML = '<p class="no-data">No active sessions</p>';
        document.getElementById('active-sessions').textContent = '0';
        return;
    }

    // Filter by course if specified
    let sessions = data.sessions;
    if (window.dashboardConfig?.courseId) {
        sessions = sessions.filter(s => s.course_id === window.dashboardConfig.courseId);
    }

    document.getElementById('active-sessions').textContent = sessions.length;

    if (sessions.length === 0) {
        grid.innerHTML = '<p class="no-data">No active sessions for this course</p>';
        return;
    }

    grid.innerHTML = sessions.map(session => `
        <div class="active-card">
            <h4>${escapeHtml(session.user_name || 'Unknown Student')}</h4>
            <p>${escapeHtml(session.user_email || '')}</p>
            <p>VM: ${escapeHtml(session.vm_name || 'N/A')}</p>
            <p class="time">Started: ${formatDateTime(session.created_at)}</p>
            <p class="time">Expires: ${formatDateTime(session.expires_at)}</p>
        </div>
    `).join('');
}

async function loadAssignments() {
    // Try to load unique assignments from recordings
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

    // Show modal
    modal.classList.add('active');
    container.innerHTML = '<p style="color: white; text-align: center; padding: 2rem;">Loading recording...</p>';

    // Get recording info
    const info = await apiCall(`/api/recordings/${recordingId}`);
    if (info) {
        document.getElementById('player-title').textContent =
            `Recording: ${info.user_name || 'Unknown'} - ${formatDateTime(info.started_at)}`;
        infoDiv.innerHTML = `
            <p><strong>Student:</strong> ${escapeHtml(info.user_name || 'Unknown')}</p>
            <p><strong>Email:</strong> ${escapeHtml(info.user_email || 'Unknown')}</p>
            <p><strong>Course:</strong> ${escapeHtml(info.course_title || 'N/A')}</p>
            <p><strong>Assignment:</strong> ${escapeHtml(info.assignment_title || 'N/A')}</p>
            <p><strong>Duration:</strong> ${formatDuration(info.duration_seconds)}</p>
            <p><strong>Size:</strong> ${formatFileSize(info.file_size_bytes)}</p>
        `;
    }

    // Try to play with asciinema player
    try {
        // Clear previous player
        if (currentPlayer) {
            currentPlayer.dispose();
            currentPlayer = null;
        }
        container.innerHTML = '';

        // Fetch the cast file URL
        const castUrl = `${window.dashboardConfig?.apiBase || ''}/api/recordings/${recordingId}/cast`;

        // Create player
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
            <p style="color: white; text-align: center; padding: 2rem;">
                Unable to play recording.
                <button class="btn btn-secondary" onclick="viewText(${recordingId}); closePlayer();">
                    View as text instead
                </button>
            </p>
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
    modal.classList.remove('active');
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

    modal.classList.add('active');
    content.textContent = 'Loading...';

    // Get recording info for title
    const info = await apiCall(`/api/recordings/${recordingId}`);
    if (info) {
        document.getElementById('text-title').textContent =
            `Transcript: ${info.user_name || 'Unknown'} - ${formatDateTime(info.started_at)}`;
    }

    // Fetch text content
    try {
        const baseUrl = window.dashboardConfig?.apiBase || '';
        const response = await fetch(`${baseUrl}/api/recordings/${recordingId}/view`);
        const text = await response.text();
        content.textContent = text || '(Empty recording)';
    } catch (error) {
        content.textContent = 'Failed to load recording content.';
    }
}

function closeTextView() {
    const modal = document.getElementById('text-modal');
    modal.classList.remove('active');
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

    // Download log file
    const logLink = document.createElement('a');
    logLink.href = `${baseUrl}/api/recordings/${recordingId}/download`;
    logLink.download = `session-${recordingId}.log`;
    logLink.click();

    // Download timing file after a short delay
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
    if (e.target.classList.contains('modal')) {
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
    document.getElementById('demo-vm-inactive').style.display = 'block';
    document.getElementById('demo-vm-loading').style.display = 'none';
    document.getElementById('demo-vm-active').style.display = 'none';
}

function showDemoVMLoading() {
    document.getElementById('demo-vm-inactive').style.display = 'none';
    document.getElementById('demo-vm-loading').style.display = 'block';
    document.getElementById('demo-vm-active').style.display = 'none';
}

function showDemoVMActive(data) {
    document.getElementById('demo-vm-inactive').style.display = 'none';
    document.getElementById('demo-vm-loading').style.display = 'none';
    document.getElementById('demo-vm-active').style.display = 'flex';

    document.getElementById('demo-vm-ip').textContent = data.vm_ip || 'N/A';
    document.getElementById('demo-vm-expires').textContent = data.expires_at ? formatDateTime(data.expires_at) : 'N/A';
    document.getElementById('demo-vm-link').href = data.url || '#';
}

async function launchDemoVM() {
    showDemoVMLoading();

    try {
        const response = await fetch('/api/demo-vm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to provision demo VM');
        }

        const data = await response.json();
        demoVMSessionId = data.session_id;
        showDemoVMActive(data);

        // Refresh stats
        loadStats();
        loadActiveSessions();

    } catch (error) {
        console.error('Error launching demo VM:', error);
        alert('Failed to launch demo VM: ' + error.message);
        showDemoVMInactive();
    }
}

async function extendDemoVM() {
    if (!demoVMSessionId) {
        alert('No active demo VM to extend');
        return;
    }

    try {
        const response = await fetch(`/api/demo-vm/extend`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to extend session');
        }

        const data = await response.json();
        document.getElementById('demo-vm-expires').textContent = data.expires_at ? formatDateTime(data.expires_at) : 'N/A';
        alert('Demo VM session extended by 1 hour');

    } catch (error) {
        console.error('Error extending demo VM:', error);
        alert('Failed to extend session: ' + error.message);
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
        const response = await fetch(`/api/demo-vm`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to destroy demo VM');
        }

        demoVMSessionId = null;
        showDemoVMInactive();

        // Refresh stats
        loadStats();
        loadActiveSessions();

        alert('Demo VM destroyed successfully');

    } catch (error) {
        console.error('Error destroying demo VM:', error);
        alert('Failed to destroy demo VM: ' + error.message);
    }
}
