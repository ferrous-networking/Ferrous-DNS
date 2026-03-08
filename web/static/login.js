function loginApp() {
    return {
        username: '',
        password: '',
        rememberMe: false,
        setupRequired: false,
        setupPassword: '',
        setupConfirm: '',
        error: '',
        loading: false,

        async init() {
            const theme = localStorage.getItem('theme') || 'light';
            document.documentElement.classList.toggle('dark', theme === 'dark');
            try {
                const res = await fetch(`${API_BASE}/auth/status`);
                if (res.ok) {
                    const data = await res.json();
                    if (!data.enabled) {
                        window.location.href = '/dashboard.html';
                        return;
                    }
                    this.setupRequired = data.setup_required;
                }
            } catch (e) {
                console.error('Auth status check failed:', e);
            }
            // If already authenticated, redirect
            if (!this.setupRequired) {
                const probe = await apiFetch(`${API_BASE}/health`);
                if (probe.ok) {
                    window.location.href = '/dashboard.html';
                    return;
                }
            }
            setTimeout(() => lucide.createIcons(), 100);
        },

        async setupAdmin() {
            if (!this.setupPassword || this.setupPassword !== this.setupConfirm) return;
            this.error = '';
            this.loading = true;
            try {
                const res = await fetch(`${API_BASE}/auth/setup`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password: this.setupPassword})
                });
                if (res.ok || res.status === 204) {
                    this.setupRequired = false;
                    this.password = this.setupPassword;
                    this.username = 'admin';
                    this.setupPassword = '';
                    this.setupConfirm = '';
                    await this.login();
                } else {
                    const data = await res.json().catch(() => ({}));
                    this.error = data.error || 'Setup failed';
                }
            } catch (e) {
                this.error = 'Setup failed: ' + e.message;
            } finally {
                this.loading = false;
            }
        },

        async login() {
            if (!this.username || !this.password) return;
            this.error = '';
            this.loading = true;
            try {
                const res = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: this.username,
                        password: this.password,
                        remember_me: this.rememberMe
                    })
                });
                if (res.ok) {
                    window.location.href = '/dashboard.html';
                } else {
                    const data = await res.json().catch(() => ({}));
                    this.error = data.error || 'Invalid username or password';
                }
            } catch (e) {
                this.error = 'Login failed: ' + e.message;
            } finally {
                this.loading = false;
            }
        }
    };
}
