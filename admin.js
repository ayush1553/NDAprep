// Admin Dashboard Logic
document.addEventListener('DOMContentLoaded', () => {
    checkAdminAccess();
    loadUsers();
});

const SESSION_KEY = 'nda_platform_session';
const adminUser = JSON.parse(localStorage.getItem(SESSION_KEY));

function checkAdminAccess() {
    if (!adminUser || adminUser.role !== 'admin') {
        alert('Access Denied: Admin privileges required.');
        window.location.href = 'login.html';
        return;
    }
    document.getElementById('admin-email').textContent = adminUser.email;
}

async function loadUsers() {
    try {
        const response = await fetch('/api/admin/users', {
            headers: {
                'x-admin-email': adminUser.email
            }
        });

        if (!response.ok) throw new Error('Failed to fetch data');

        const users = await response.json();
        renderUsers(users);
        updateSummary(users);
    } catch (err) {
        console.error(err);
        document.getElementById('users-table-body').innerHTML = `<tr><td colspan="8" class="empty-state">Error loading users data.</td></tr>`;
    }
}

function renderUsers(users) {
    const tbody = document.getElementById('users-table-body');
    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No users registered yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = users.map(u => `
        <tr>
            <td>${u.email}</td>
            <td>${new Date(u.created_at).toLocaleDateString()}</td>
            <td>${u.total_attempts || 0}</td>
            <td>${u.pyqs_attempted || 0} / ${u.mocks_attempted || 0}</td>
            <td>${u.avg_score ? u.avg_score.toFixed(1) : '0.0'}%</td>
            <td>${u.avg_accuracy ? u.avg_accuracy.toFixed(1) : '0.0'}%</td>
            <td>${u.last_attempt_date ? new Date(u.last_attempt_date).toLocaleDateString() : 'Never'}</td>
            <td><button class="btn-view" onclick="viewUserDetail('${u.user_id}', '${u.email}')">View Details</button></td>
        </tr>
    `).join('');
}

function updateSummary(users) {
    document.getElementById('total-users-count').textContent = users.length;
    const totalAttempts = users.reduce((sum, u) => sum + (u.total_attempts || 0), 0);
    document.getElementById('total-attempts-all').textContent = totalAttempts;

    // Simple mock for "Active Today" - check last_attempt_date
    const today = new Date().toLocaleDateString();
    const activeToday = users.filter(u => u.last_attempt_date && new Date(u.last_attempt_date).toLocaleDateString() === today).length;
    document.getElementById('active-today').textContent = activeToday;
}

async function viewUserDetail(userId, email) {
    document.getElementById('detail-user-email').textContent = `Test History for ${email}`;
    const modal = document.getElementById('user-detail-modal');
    modal.style.display = 'flex';

    try {
        const response = await fetch(`/api/admin/user/${userId}/attempts`, {
            headers: {
                'x-admin-email': adminUser.email
            }
        });

        if (!response.ok) throw new Error('Failed to fetch history');

        const attempts = await response.json();
        renderHistory(attempts);
    } catch (err) {
        console.error(err);
        document.getElementById('history-table-body').innerHTML = `<tr><td colspan="8" class="empty-state">Error loading history.</td></tr>`;
    }
}

function renderHistory(attempts) {
    const tbody = document.getElementById('history-table-body');
    if (attempts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No attempts yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = attempts.map(a => `
        <tr>
            <td>${new Date(a.submitted_at).toLocaleDateString()} ${new Date(a.submitted_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
            <td>${a.test_id}</td>
            <td>${a.test_type}</td>
            <td>${a.subject || '-'}</td>
            <td>${a.score} / ${a.max_score}</td>
            <td>${a.accuracy}%</td>
            <td>${formatTime(a.time_taken)}</td>
            <td><button class="btn-view" style="background:#27ae60" onclick="viewAttemptReview('${a.attempt_id}')">Review</button></td>
        </tr>
    `).join('');
}

function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
}

async function viewAttemptReview(attemptId) {
    try {
        const response = await fetch(`/api/attempts/id/${attemptId}`);
        if (!response.ok) throw new Error('Failed to fetch attempt details');

        const attempt = await response.json();

        // Save to localStorage so result.html can display it
        localStorage.setItem('ndaExamResult', JSON.stringify(attempt));
        window.open('result.html', '_blank');
    } catch (err) {
        console.error(err);
        alert('Error loading test attempt review.');
    }
}

function closeModal() {
    document.getElementById('user-detail-modal').style.display = 'none';
}

// Close modal on outside click
window.onclick = (event) => {
    const modal = document.getElementById('user-detail-modal');
    if (event.target == modal) closeModal();
};
