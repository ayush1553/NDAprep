/**
 * AUTH.JS - API Based Authentication
 * Communicates with the Node.js server.
 */

const AUTH_CONFIG = {
    API_URL: '/api',
    SESSION_KEY: 'nda_platform_session'
};

const Auth = {
    // 1. Password Hashing (SHA-256) - Keep on client for extra layer
    async hashPassword(password) {
        const msgUint8 = new TextEncoder().encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // 2. Auth Logic via API
    async checkEmail(email) {
        const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/check/${encodeURIComponent(email)}`);
        const data = await response.json();
        return data.user;
    },

    async login(email, password) {
        // Hashing Disabled as per user request for development visibility
        // const hashedPassword = await this.hashPassword(password);
        const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: password }) // Raw password
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Login failed');
        }

        const user = await response.json();
        this.startSession(user);
        return user;
    },

    async signup(email, password, username) {
        // Hashing Disabled
        // const hashedPassword = await this.hashPassword(password);
        const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password: password, username }) // Include username
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Signup failed');
        }

        const user = await response.json();
        this.startSession(user);
        return user;
    },

    // 3. Session Management (Still in localStorage for fast UI check)
    startSession(user) {
        const sessionData = {
            id: user.id || user.user_id,
            email: user.email,
            username: user.username, // Store username
            role: user.role || 'user',
            login_at: new Date().toISOString()
        };
        localStorage.setItem(AUTH_CONFIG.SESSION_KEY, JSON.stringify(sessionData));
        this.updateSidebarUI();
    },

    updateSidebarUI() {
        const session = this.getSession();
        const displayName = session ? (session.username || session.email) : '';

        // Unified Sidebar Elements
        const userDisplay = document.getElementById('user-display');
        const loginLink = document.getElementById('login-link');
        const signupLink = document.getElementById('signup-link');
        const logoutLink = document.getElementById('logout-link');

        if (session) {
            if (userDisplay) {
                userDisplay.innerHTML = `<i class="fa-solid fa-circle-user icon"></i> ${displayName}`;
                userDisplay.style.setProperty('display', 'flex', 'important');
            }
            if (loginLink) loginLink.style.setProperty('display', 'none', 'important');
            if (signupLink) signupLink.style.setProperty('display', 'none', 'important');
            if (logoutLink) logoutLink.style.setProperty('display', 'block', 'important');
        } else {
            if (userDisplay) userDisplay.style.setProperty('display', 'none', 'important');
            if (loginLink) loginLink.style.setProperty('display', 'block', 'important');
            if (signupLink) signupLink.style.setProperty('display', 'block', 'important');
            if (logoutLink) logoutLink.style.setProperty('display', 'none', 'important');
        }
    },

    getSession() {
        const session = localStorage.getItem(AUTH_CONFIG.SESSION_KEY);
        return session ? JSON.parse(session) : null;
    },

    logout() {
        localStorage.removeItem(AUTH_CONFIG.SESSION_KEY);
        this.updateSidebarUI();
        window.location.reload();
    },

    // 4. Guards
    requireAuth(redirectUrl) {
        const session = this.getSession();
        if (!session) {
            const currentUrl = encodeURIComponent(window.location.href);
            window.location.href = `login.html?redirect=${currentUrl}`;
            return false;
        }
        return true;
    }
};

// Global Menu Toggle for shared Sidebar
function toggleMenu() {
    const navOverlay = document.getElementById('navOverlay');
    if (navOverlay) {
        navOverlay.classList.toggle('active');

        // Prevent body scrolling when menu is open
        if (navOverlay.classList.contains('active')) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
    } else {
        // Fallback for older sidebar implementations
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        if (sidebar) sidebar.classList.toggle('active');
        if (overlay) overlay.classList.toggle('active');
    }
}

// Initial UI Update
document.addEventListener('DOMContentLoaded', () => {
    Auth.updateSidebarUI();
});

window.Auth = Auth;
