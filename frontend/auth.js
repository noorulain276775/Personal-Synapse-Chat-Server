// Matrix Authentication Client
class MatrixAuthClient {
    constructor() {
        this.client = null;
        this.isAuthenticated = false;
        this.currentUser = null;
        
        this.initializeElements();
        this.setupEventListeners();
        this.setupPasswordStrength();
    }
    
    initializeElements() {
        // Tab elements
        this.tabButtons = document.querySelectorAll('.tab-button');
        this.tabContents = document.querySelectorAll('.tab-content');
        
        // Form elements
        this.loginForm = document.getElementById('loginForm');
        this.registerForm = document.getElementById('registerForm');
        this.passwordResetForm = document.getElementById('passwordResetForm');
        
        // Input elements
        this.loginUsername = document.getElementById('loginUsername');
        this.loginPassword = document.getElementById('loginPassword');
        this.regUsername = document.getElementById('regUsername');
        this.regEmail = document.getElementById('regEmail');
        this.regDisplayName = document.getElementById('regDisplayName');
        this.regPassword = document.getElementById('regPassword');
        this.regPasswordConfirm = document.getElementById('regPasswordConfirm');
        this.resetEmail = document.getElementById('resetEmail');
        
        // Other elements
        this.statusMessage = document.getElementById('statusMessage');
        this.logContent = document.getElementById('logContent');
        this.passwordStrength = document.getElementById('passwordStrength');
        this.passwordResetModal = document.getElementById('passwordResetModal');
        this.closeModal = document.querySelector('.close');
        
        // SSO buttons
        this.googleLogin = document.getElementById('googleLogin');
        this.githubLogin = document.getElementById('githubLogin');
        this.microsoftLogin = document.getElementById('microsoftLogin');
    }
    
    setupEventListeners() {
        // Tab switching
        this.tabButtons.forEach(button => {
            button.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });
        
        // Form submissions
        this.loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        this.registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        this.passwordResetForm.addEventListener('submit', (e) => this.handlePasswordReset(e));
        
        // Password confirmation
        this.regPasswordConfirm.addEventListener('input', () => this.validatePasswordMatch());
        
        // Modal
        this.closeModal.addEventListener('click', () => this.closePasswordResetModal());
        window.addEventListener('click', (e) => {
            if (e.target === this.passwordResetModal) {
                this.closePasswordResetModal();
            }
        });
        
        // Forgot password link
        document.getElementById('forgotPassword').addEventListener('click', (e) => {
            e.preventDefault();
            this.showPasswordResetModal();
        });
        
        // SSO buttons
        this.googleLogin.addEventListener('click', () => this.handleSSOLogin('google'));
        this.githubLogin.addEventListener('click', () => this.handleSSOLogin('github'));
        this.microsoftLogin.addEventListener('click', () => this.handleSSOLogin('microsoft'));
    }
    
    setupPasswordStrength() {
        this.regPassword.addEventListener('input', () => this.updatePasswordStrength());
    }
    
    switchTab(tabName) {
        // Remove active class from all tabs and contents
        this.tabButtons.forEach(btn => btn.classList.remove('active'));
        this.tabContents.forEach(content => content.classList.remove('active'));
        
        // Add active class to selected tab and content
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(tabName).classList.add('active');
    }
    
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.textContent = `[${timestamp}] ${message}`;
        this.logContent.appendChild(logEntry);
        this.logContent.scrollTop = this.logContent.scrollHeight;
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
    
    showStatus(message, type = 'info') {
        this.statusMessage.textContent = message;
        this.statusMessage.className = `status-message ${type}`;
        this.statusMessage.style.display = 'block';
        
        setTimeout(() => {
            this.statusMessage.style.display = 'none';
        }, 5000);
    }
    
    updatePasswordStrength() {
        const password = this.regPassword.value;
        const strength = this.calculatePasswordStrength(password);
        
        this.passwordStrength.className = `password-strength ${strength.level}`;
        this.passwordStrength.innerHTML = `<div class="password-strength-bar"></div>`;
        
        if (password.length > 0) {
            this.passwordStrength.style.display = 'block';
        } else {
            this.passwordStrength.style.display = 'none';
        }
    }
    
    calculatePasswordStrength(password) {
        let score = 0;
        let feedback = [];
        
        if (password.length >= 8) score += 1;
        else feedback.push('At least 8 characters');
        
        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Lowercase letter');
        
        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Uppercase letter');
        
        if (/\d/.test(password)) score += 1;
        else feedback.push('Number');
        
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
        else feedback.push('Special character');
        
        if (password.length >= 12) score += 1;
        
        const levels = ['weak', 'fair', 'good', 'strong'];
        const level = levels[Math.min(score, 3)];
        
        return { score, level, feedback };
    }
    
    validatePasswordMatch() {
        const password = this.regPassword.value;
        const confirm = this.regPasswordConfirm.value;
        
        if (confirm && password !== confirm) {
            this.regPasswordConfirm.setCustomValidity('Passwords do not match');
        } else {
            this.regPasswordConfirm.setCustomValidity('');
        }
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const username = this.loginUsername.value;
        const password = this.loginPassword.value;
        
        if (!username || !password) {
            this.showStatus('Please enter both username and password', 'error');
            return;
        }
        
        try {
            this.log('Attempting to login...', 'info');
            
            // Create Matrix client
            this.client = matrixcs.createClient({
                baseUrl: "http://localhost:8008",
                useAuthorizationHeader: true
            });
            
            // Login
            const response = await this.client.login('m.login.password', {
                user: username,
                password: password
            });
            
            this.log(`Login successful! User ID: ${response.user_id}`, 'success');
            this.showStatus('Login successful!', 'success');
            
            // Store authentication state
            this.isAuthenticated = true;
            this.currentUser = {
                user_id: response.user_id,
                access_token: response.access_token
            };
            
            // Redirect to chat or show success
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 1000);
            
        } catch (error) {
            this.log(`Login failed: ${error.message}`, 'error');
            this.showStatus(`Login failed: ${error.message}`, 'error');
        }
    }
    
    async handleRegister(e) {
        e.preventDefault();
        
        const username = this.regUsername.value;
        const email = this.regEmail.value;
        const displayName = this.regDisplayName.value;
        const password = this.regPassword.value;
        const passwordConfirm = this.regPasswordConfirm.value;
        
        // Validate input
        if (password !== passwordConfirm) {
            this.showStatus('Passwords do not match', 'error');
            return;
        }
        
        const strength = this.calculatePasswordStrength(password);
        if (strength.score < 3) {
            this.showStatus('Password is too weak. Please use a stronger password.', 'error');
            return;
        }
        
        try {
            this.log('Attempting to register...', 'info');
            
            // Create Matrix client
            this.client = matrixcs.createClient({
                baseUrl: "http://localhost:8008"
            });
            
            // Register user
            const response = await this.client.register(
                username,
                password,
                null,
                {
                    initial_device_display_name: 'Web Client',
                    auth: {
                        type: 'm.login.dummy'
                    }
                }
            );
            
            this.log(`Registration successful! User ID: ${response.user_id}`, 'success');
            this.showStatus('Registration successful! You can now login.', 'success');
            
            // Clear form
            this.registerForm.reset();
            this.passwordStrength.style.display = 'none';
            
            // Switch to login tab
            setTimeout(() => {
                this.switchTab('login');
            }, 2000);
            
        } catch (error) {
            this.log(`Registration failed: ${error.message}`, 'error');
            this.showStatus(`Registration failed: ${error.message}`, 'error');
        }
    }
    
    async handlePasswordReset(e) {
        e.preventDefault();
        
        const email = this.resetEmail.value;
        
        if (!email) {
            this.showStatus('Please enter your email address', 'error');
            return;
        }
        
        try {
            this.log(`Sending password reset email to ${email}...`, 'info');
            
            // In a real implementation, this would call your password reset API
            // For demo purposes, we'll just show a success message
            this.showStatus('Password reset email sent! Check your inbox.', 'success');
            this.closePasswordResetModal();
            
        } catch (error) {
            this.log(`Password reset failed: ${error.message}`, 'error');
            this.showStatus(`Password reset failed: ${error.message}`, 'error');
        }
    }
    
    async handleSSOLogin(provider) {
        try {
            this.log(`Initiating SSO login with ${provider}...`, 'info');
            
            // In a real implementation, this would redirect to the OIDC provider
            // For demo purposes, we'll show a message
            this.showStatus(`${provider} SSO is not configured yet. Please use username/password login.`, 'info');
            
            // Example of what the real implementation would look like:
            // const ssoUrl = `http://localhost:8008/_matrix/client/r0/login/sso/redirect/${provider}`;
            // window.location.href = ssoUrl;
            
        } catch (error) {
            this.log(`SSO login failed: ${error.message}`, 'error');
            this.showStatus(`SSO login failed: ${error.message}`, 'error');
        }
    }
    
    showPasswordResetModal() {
        this.passwordResetModal.style.display = 'block';
    }
    
    closePasswordResetModal() {
        this.passwordResetModal.style.display = 'none';
        this.passwordResetForm.reset();
    }
    
    // Utility methods
    validateUsername(username) {
        const errors = [];
        
        if (username.length < 3) {
            errors.push('Username must be at least 3 characters long');
        }
        
        if (username.length > 20) {
            errors.push('Username must be no more than 20 characters long');
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            errors.push('Username can only contain letters, numbers, and underscores');
        }
        
        if (!/^[a-zA-Z]/.test(username)) {
            errors.push('Username must start with a letter');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
    
    validateEmail(email) {
        const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return pattern.test(email);
    }
}

// Initialize the authentication client when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new MatrixAuthClient();
});
