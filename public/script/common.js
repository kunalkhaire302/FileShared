// ===== Common Utilities =====

// Toast notification system
(function () {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    window.showToast = function (message, type = 'info') {
        const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
        `;
        container.appendChild(toast);
        setTimeout(() => { if (toast.parentElement) toast.remove(); }, 4000);
    };
})();

// Active nav highlighting
(function () {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-links a').forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'index.html')) {
            link.style.color = '#007aff';
            link.style.fontWeight = '600';
        }
    });
})();

// Auth state management
function getToken() {
    return localStorage.getItem('token');
}

function getUserName() {
    const token = getToken();
    if (!token) return null;
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp < Math.floor(Date.now() / 1000)) {
            localStorage.removeItem('token');
            return null;
        }
        return payload.name || 'User';
    } catch (e) {
        return null;
    }
}

function isLoggedIn() {
    return getUserName() !== null;
}

function logout() {
    localStorage.removeItem('token');
    showToast('Logged out successfully', 'success');
    setTimeout(() => { window.location.href = '/index.html'; }, 800);
}

// Update nav based on login state
(function () {
    document.addEventListener('DOMContentLoaded', () => {
        const loginBtn = document.getElementById('login-button');
        const logoutBtn = document.getElementById('logout-button');
        const dashboardLink = document.getElementById('dashboard-link');
        const userName = getUserName();

        if (userName) {
            if (loginBtn) loginBtn.style.display = 'none';
            if (logoutBtn) logoutBtn.style.display = 'block';
            if (dashboardLink) dashboardLink.style.display = 'block';
        } else {
            if (loginBtn) loginBtn.style.display = 'block';
            if (logoutBtn) logoutBtn.style.display = 'none';
            if (dashboardLink) dashboardLink.style.display = 'none';
        }
    });
})();

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format date
function formatDate(dateStr) {
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Time remaining
function timeRemaining(expiresAt) {
    const diff = new Date(expiresAt) - new Date();
    if (diff <= 0) return 'Expired';
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ${hours % 24}h remaining`;
    if (hours > 0) return `${hours}h remaining`;
    return `${Math.floor(diff / (1000 * 60))}m remaining`;
}

// Authenticated fetch helper
function authFetch(url, options = {}) {
    const token = getToken();
    if (token) {
        options.headers = options.headers || {};
        options.headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(url, options);
}

// Get file icon based on extension
function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
        pdf: '📄', doc: '📝', docx: '📝', txt: '📝',
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
        mp4: '🎬', mov: '🎬', avi: '🎬',
        mp3: '🎵', wav: '🎵',
        zip: '📦', rar: '📦', '7z': '📦',
        csv: '📊', xls: '📊', xlsx: '📊',
        ppt: '📊', pptx: '📊',
        html: '🌐', css: '🎨', json: '📋', xml: '📋'
    };
    return icons[ext] || '📎';
}
