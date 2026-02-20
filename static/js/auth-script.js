const API_URL = '/api';

let csrfToken = null;

async function fetchCSRFToken() {
    try {
        const response = await fetch(`${API_URL}/csrf-token`, { credentials: 'include' });
        const data = await response.json();
        csrfToken = data.csrf_token;
        return csrfToken;
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
        return null;
    }
}

document.addEventListener('DOMContentLoaded', async function () {
    await fetchCSRFToken();
    initializePasswordStrengthIndicator();
});

function checkPasswordStrength(password) {
    const checks = {
        length: password.length >= 12,
        minLength: password.length >= 8,
        maxLength: password.length <= 128,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>\-_+=\[\]\\\/~`]/.test(password),
        noSequential: !(/012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)),
        noCommon: !['password', '12345678', 'qwerty', 'abc123', 'password123', 'admin', 'letmein', 'welcome', 'monkey', '123456789'].includes(password.toLowerCase())
    };

    const score = Object.values(checks).filter(Boolean).length;

    return {
        score,
        maxScore: Object.keys(checks).length,
        checks,
        isStrong: score >= 9,
        percentage: (score / Object.keys(checks).length) * 100
    };
}

function updatePasswordStrength(inputId, indicatorId) {
    const password = document.getElementById(inputId).value;
    const indicator = document.getElementById(indicatorId);
    if (!indicator) return;

    if (password.length === 0) {
        indicator.style.display = 'none';
        return;
    }

    indicator.style.display = 'block';
    const result = checkPasswordStrength(password);

    let strengthText, strengthColor;

    if (result.percentage < 40) {
        strengthText = 'Very Weak'; strengthColor = '#dc3545';
    } else if (result.percentage < 60) {
        strengthText = 'Weak'; strengthColor = '#fd7e14';
    } else if (result.percentage < 80) {
        strengthText = 'Medium'; strengthColor = '#ffc107';
    } else if (result.percentage < 100) {
        strengthText = 'Good'; strengthColor = '#20c997';
    } else {
        strengthText = 'Excellent'; strengthColor = '#28a745';
    }

    const check = (v) => v ? '✓' : '✗';
    const col = (v) => v ? '#28a745' : '#dc3545';

    indicator.innerHTML = `
        <div style="margin-top:0.75rem;padding:0.75rem;background:#f8f9fa;border-radius:8px;border:1px solid #dee2e6;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                <span style="font-size:0.85rem;font-weight:600;color:${strengthColor};">Password Strength: ${strengthText}</span>
                <span style="font-size:0.75rem;color:#6c757d;">${Math.round(result.percentage)}%</span>
            </div>
            <div style="height:6px;background:#e9ecef;border-radius:3px;overflow:hidden;margin-bottom:0.75rem;">
                <div style="height:100%;width:${result.percentage}%;background:${strengthColor};transition:all 0.3s ease;"></div>
            </div>
            <div style="font-size:0.75rem;line-height:1.8;">
                <div style="color:${col(result.checks.length)};">${check(result.checks.length)} At least 12 characters</div>
                <div style="color:${col(result.checks.uppercase)};">${check(result.checks.uppercase)} One uppercase letter (A-Z)</div>
                <div style="color:${col(result.checks.lowercase)};">${check(result.checks.lowercase)} One lowercase letter (a-z)</div>
                <div style="color:${col(result.checks.number)};">${check(result.checks.number)} One number (0-9)</div>
                <div style="color:${col(result.checks.special)};">${check(result.checks.special)} One special character (!@#$%^&*...)</div>
                <div style="color:${col(result.checks.noSequential)};">${check(result.checks.noSequential)} No sequential characters</div>
                <div style="color:${col(result.checks.noCommon)};">${check(result.checks.noCommon)} Not a common password</div>
            </div>
        </div>
    `;
}

function initializePasswordStrengthIndicator() {
    const signupPassword = document.getElementById('signup-password');
    if (!signupPassword) return;

    const strengthIndicator = document.createElement('div');
    strengthIndicator.id = 'password-strength-indicator';
    strengthIndicator.style.display = 'none';
    signupPassword.closest('.form-group').appendChild(strengthIndicator);

    signupPassword.addEventListener('input', function () {
        updatePasswordStrength('signup-password', 'password-strength-indicator');
    });

    signupPassword.addEventListener('paste', function () {
        setTimeout(() => updatePasswordStrength('signup-password', 'password-strength-indicator'), 10);
    });
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';

    const btn = input.parentElement.querySelector('.toggle-password');
    if (!btn) return;

    btn.innerHTML = isHidden
        ? `<svg width="20" height="20" viewBox="0 0 20 20" fill="none">
               <path d="M2 10s2.5-6 8-6 8 6 8 6-2.5 6-8 6-8-6-8-6z" stroke="currentColor" stroke-width="1.5"/>
               <line x1="3" y1="3" x2="17" y2="17" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
           </svg>`
        : `<svg width="20" height="20" viewBox="0 0 20 20" fill="none">
               <path d="M10 4C4.5 4 2 10 2 10s2.5 6 8 6 8-6 8-6-2.5-6-8-6z" stroke="currentColor" stroke-width="1.5"/>
               <circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.5"/>
           </svg>`;
}

function sanitizeInput(input, maxLength = 100) {
    if (!input) return '';
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML.substring(0, maxLength).trim();
}

function validateEmail(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(email)) return { valid: false, message: 'Please enter a valid email address' };
    if (email.length > 254) return { valid: false, message: 'Email is too long' };
    const [local, domain] = email.split('@');
    if (local.length > 64) return { valid: false, message: 'Email local part is too long' };
    const disposable = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'throwaway.email', 'trashmail.com'];
    if (disposable.includes(domain.toLowerCase())) return { valid: false, message: 'Disposable email addresses are not allowed' };
    return { valid: true, message: '' };
}

function validatePhone(phone) {
    const cleaned = phone.replace(/[\s\-\(\)]/g, '');
    const regex = /^\+?[1-9]\d{1,14}$/;
    if (!regex.test(cleaned)) return { valid: false, message: 'Please enter a valid phone number (e.g., +1234567890)' };
    return { valid: true, message: '', cleaned };
}

function validateName(name) {
    if (name.length < 2) return { valid: false, message: 'Name must be at least 2 characters long' };
    if (name.length > 100) return { valid: false, message: 'Name is too long' };
    if (!/^[a-zA-Z\s'\-]+$/.test(name)) return { valid: false, message: 'Name contains invalid characters' };
    return { valid: true, message: '' };
}

function showError(message, duration = 5000) {
    document.querySelector('.error-message-banner')?.remove();
    const div = document.createElement('div');
    div.className = 'error-message-banner';
    div.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#dc3545;color:white;padding:15px 30px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:10000;font-size:14px;max-width:500px;animation:slideDown 0.3s ease;';
    div.innerHTML = `<div style="display:flex;align-items:center;gap:10px;"><svg width="20" height="20" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="white" stroke-width="2"/><path d="M10 6v5M10 14h.01" stroke="white" stroke-width="2" stroke-linecap="round"/></svg><span>${message}</span></div>`;
    document.body.appendChild(div);
    setTimeout(() => { div.style.animation = 'slideUp 0.3s ease'; setTimeout(() => div.remove(), 300); }, duration);
}

function showSuccess(message, duration = 4000) {
    document.querySelector('.success-message-banner')?.remove();
    const div = document.createElement('div');
    div.className = 'success-message-banner';
    div.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#28a745;color:white;padding:15px 30px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:10000;font-size:14px;max-width:500px;animation:slideDown 0.3s ease;';
    div.innerHTML = `<div style="display:flex;align-items:center;gap:10px;"><svg width="20" height="20" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="white" stroke-width="2"/><path d="M6 10l3 3 5-6" stroke="white" stroke-width="2" stroke-linecap="round"/></svg><span>${message}</span></div>`;
    document.body.appendChild(div);
    setTimeout(() => { div.style.animation = 'slideUp 0.3s ease'; setTimeout(() => div.remove(), 300); }, duration);
}

function setButtonLoading(btn, loading, originalText) {
    if (loading) {
        btn.disabled = true;
        btn.style.opacity = '0.7';
        btn.style.cursor = 'not-allowed';
    } else {
        btn.textContent = originalText;
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
    }
}

async function handleSignup(event) {
    event.preventDefault();

    const name = sanitizeInput(document.getElementById('signup-name').value.trim(), 100);
    const email = document.getElementById('signup-email').value.trim().toLowerCase();
    const phone = document.getElementById('signup-phone').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;

    const nameValidation = validateName(name);
    if (!nameValidation.valid) { showError(nameValidation.message); return false; }

    const emailValidation = validateEmail(email);
    if (!emailValidation.valid) { showError(emailValidation.message); return false; }

    const phoneValidation = validatePhone(phone);
    if (!phoneValidation.valid) { showError(phoneValidation.message); return false; }

    if (password !== confirmPassword) {
        showError('Passwords do not match!');
        document.getElementById('signup-confirm-password').focus();
        return false;
    }

    const strengthResult = checkPasswordStrength(password);
    if (!strengthResult.isStrong) {
        const missing = [];
        if (!strengthResult.checks.length) missing.push('at least 12 characters');
        if (!strengthResult.checks.uppercase) missing.push('one uppercase letter');
        if (!strengthResult.checks.lowercase) missing.push('one lowercase letter');
        if (!strengthResult.checks.number) missing.push('one number');
        if (!strengthResult.checks.special) missing.push('one special character');
        if (!strengthResult.checks.noSequential) missing.push('no sequential characters');
        if (!strengthResult.checks.noCommon) missing.push('must not be a common password');
        showError('Password must contain: ' + missing.join(', '));
        return false;
    }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Creating secure account...';
    setButtonLoading(submitBtn, true);

    try {
        if (!csrfToken) await fetchCSRFToken();

        const response = await fetch(`${API_URL}/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                name,
                email,
                phone: phoneValidation.cleaned,
                password,
                csrf_token: csrfToken
            })
        });

        const data = await response.json();

        if (response.ok && data.message) {
            showSuccess('Account created successfully! Redirecting to login...');
            setTimeout(() => { window.location.href = '/login'; }, 1500);
        } else {
            showError(data.error || 'Registration failed. Please try again.');
            setButtonLoading(submitBtn, false, originalText);
        }
    } catch (error) {
        console.error('Signup error:', error);
        showError('Network error. Please check your connection and try again.');
        setButtonLoading(submitBtn, false, originalText);
    }

    return false;
}

async function handleLogin(event) {
    event.preventDefault();

    const email = sanitizeInput(document.getElementById('login-email').value.trim(), 254);
    const password = document.getElementById('login-password').value;

    if (!email || !password) { showError('Please enter both email and password'); return false; }
    if (email.length < 3) { showError('Please enter a valid email address'); return false; }

    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Signing in securely...';
    setButtonLoading(submitBtn, true);

    try {
        if (!csrfToken) await fetchCSRFToken();

        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password, csrf_token: csrfToken })
        });

        const data = await response.json();

        if (response.ok && data.token) {
            localStorage.setItem('auth_token', data.token);
            localStorage.setItem('user_name', data.user?.name || '');
            showSuccess('Welcome back!');
            setTimeout(() => { window.location.href = '/'; }, 1000);
        } else {
            if (response.status === 403) {
                showError(data.error || 'Access denied.');
            } else if (response.status === 429) {
                showError('Too many login attempts. Please wait and try again.');
            } else if (response.status === 401) {
                showError('Invalid email or password. Please try again.');
            } else {
                showError(data.error || 'Login failed. Please try again.');
            }
            setButtonLoading(submitBtn, false, originalText);
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('Network error. Please check your connection and try again.');
        setButtonLoading(submitBtn, false, originalText);
    }

    return false;
}

const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from { opacity: 0; transform: translateX(-50%) translateY(-20px); }
        to { opacity: 1; transform: translateX(-50%) translateY(0); }
    }
    @keyframes slideUp {
        from { opacity: 1; transform: translateX(-50%) translateY(0); }
        to { opacity: 0; transform: translateX(-50%) translateY(-20px); }
    }
`;
document.head.appendChild(style);

if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}