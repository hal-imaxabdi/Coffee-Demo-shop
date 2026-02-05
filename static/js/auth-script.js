// API Base URL
const API_URL = '/api';

// CSRF Token management
let csrfToken = null;

// Fetch CSRF token on page load
async function fetchCSRFToken() {
    try {
        const response = await fetch(`${API_URL}/csrf-token`, {
            credentials: 'include'
        });
        const data = await response.json();
        csrfToken = data.csrf_token;
        return csrfToken;
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
        return null;
    }
}

// Initialize CSRF token
document.addEventListener('DOMContentLoaded', async function() {
    await fetchCSRFToken();
    initializePasswordStrengthIndicator();
});

// Password strength validation
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
    const requiredScore = 9; // All checks must pass
    
    return {
        score: score,
        maxScore: Object.keys(checks).length,
        checks: checks,
        isStrong: score >= requiredScore,
        percentage: (score / Object.keys(checks).length) * 100
    };
}

// Real-time password strength indicator
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
    
    let strengthText = '';
    let strengthColor = '';
    let barWidth = result.percentage;
    
    if (result.percentage < 40) {
        strengthText = 'Very Weak';
        strengthColor = '#dc3545';
    } else if (result.percentage < 60) {
        strengthText = 'Weak';
        strengthColor = '#fd7e14';
    } else if (result.percentage < 80) {
        strengthText = 'Medium';
        strengthColor = '#ffc107';
    } else if (result.percentage < 100) {
        strengthText = 'Good';
        strengthColor = '#20c997';
    } else {
        strengthText = 'Excellent';
        strengthColor = '#28a745';
    }
    
    indicator.innerHTML = `
        <div style="margin-top: 0.75rem; padding: 0.75rem; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-size: 0.85rem; font-weight: 600; color: ${strengthColor};">
                    Password Strength: ${strengthText}
                </span>
                <span style="font-size: 0.75rem; color: #6c757d;">
                    ${Math.round(result.percentage)}%
                </span>
            </div>
            <div style="height: 6px; background: #e9ecef; border-radius: 3px; overflow: hidden; margin-bottom: 0.75rem;">
                <div style="height: 100%; width: ${barWidth}%; background: ${strengthColor}; transition: all 0.3s ease;"></div>
            </div>
            <div style="font-size: 0.75rem; line-height: 1.6;">
                <div style="color: ${result.checks.length ? '#28a745' : '#dc3545'};">
                    ${result.checks.length ? '✓' : '✗'} At least 12 characters (minimum 8)
                </div>
                <div style="color: ${result.checks.uppercase ? '#28a745' : '#dc3545'};">
                    ${result.checks.uppercase ? '✓' : '✗'} One uppercase letter (A-Z)
                </div>
                <div style="color: ${result.checks.lowercase ? '#28a745' : '#dc3545'};">
                    ${result.checks.lowercase ? '✓' : '✗'} One lowercase letter (a-z)
                </div>
                <div style="color: ${result.checks.number ? '#28a745' : '#dc3545'};">
                    ${result.checks.number ? '✓' : '✗'} One number (0-9)
                </div>
                <div style="color: ${result.checks.special ? '#28a745' : '#dc3545'};">
                    ${result.checks.special ? '✓' : '✗'} One special character (!@#$%^&*...)
                </div>
                <div style="color: ${result.checks.noSequential ? '#28a745' : '#dc3545'};">
                    ${result.checks.noSequential ? '✓' : '✗'} No sequential characters
                </div>
                <div style="color: ${result.checks.noCommon ? '#28a745' : '#dc3545'};">
                    ${result.checks.noCommon ? '✓' : '✗'} Not a common password
                </div>
            </div>
        </div>
    `;
}

// Initialize password strength indicator
function initializePasswordStrengthIndicator() {
    const signupPassword = document.getElementById('signup-password');
    if (signupPassword) {
        const strengthIndicator = document.createElement('div');
        strengthIndicator.id = 'password-strength-indicator';
        strengthIndicator.style.display = 'none';
        signupPassword.parentElement.parentElement.appendChild(strengthIndicator);
        
        signupPassword.addEventListener('input', function() {
            updatePasswordStrength('signup-password', 'password-strength-indicator');
        });
        
        signupPassword.addEventListener('paste', function(e) {
            setTimeout(() => {
                updatePasswordStrength('signup-password', 'password-strength-indicator');
            }, 10);
        });
    }
}

// Toggle password visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
    
    // Update button icon if needed
    const button = input.nextElementSibling;
    if (button && button.classList.contains('toggle-password')) {
        button.setAttribute('aria-label', type === 'password' ? 'Show password' : 'Hide password');
    }
}

// Input sanitization
function sanitizeInput(input, maxLength = 100) {
    if (!input) return '';
    
    // Remove any HTML tags and trim
    const div = document.createElement('div');
    div.textContent = input;
    let cleaned = div.innerHTML;
    
    // Limit length
    cleaned = cleaned.substring(0, maxLength);
    
    // Trim whitespace
    return cleaned.trim();
}

// Email validation
function validateEmail(email) {
    // RFC 5322 compliant regex (simplified)
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (!regex.test(email)) {
        return { valid: false, message: 'Please enter a valid email address' };
    }
    
    if (email.length > 254) {
        return { valid: false, message: 'Email is too long' };
    }
    
    const [local, domain] = email.split('@');
    if (local.length > 64) {
        return { valid: false, message: 'Email local part is too long' };
    }
    
    // Check for disposable email domains
    const disposableDomains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 
                               'mailinator.com', 'throwaway.email', 'trashmail.com'];
    if (disposableDomains.includes(domain.toLowerCase())) {
        return { valid: false, message: 'Disposable email addresses are not allowed' };
    }
    
    return { valid: true, message: '' };
}

// Phone validation
function validatePhone(phone) {
    // Remove formatting
    const cleaned = phone.replace(/[\s\-\(\)]/g, '');
    
    // E.164 format validation
    const regex = /^\+?[1-9]\d{1,14}$/;
    
    if (!regex.test(cleaned)) {
        return { 
            valid: false, 
            message: 'Please enter a valid phone number (e.g., +1234567890)' 
        };
    }
    
    return { valid: true, message: '', cleaned: cleaned };
}

// Name validation
function validateName(name) {
    if (name.length < 2) {
        return { valid: false, message: 'Name must be at least 2 characters long' };
    }
    
    if (name.length > 100) {
        return { valid: false, message: 'Name is too long' };
    }
    
    // Allow letters, spaces, hyphens, and apostrophes
    const regex = /^[a-zA-Z\s\'-]+$/;
    if (!regex.test(name)) {
        return { valid: false, message: 'Name contains invalid characters' };
    }
    
    return { valid: true, message: '' };
}

// Show error message
function showError(message, duration = 5000) {
    // Remove existing error if any
    const existingError = document.querySelector('.error-message-banner');
    if (existingError) {
        existingError.remove();
    }
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message-banner';
    errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: #dc3545;
        color: white;
        padding: 15px 30px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        font-size: 14px;
        max-width: 500px;
        animation: slideDown 0.3s ease;
    `;
    
    errorDiv.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                <circle cx="10" cy="10" r="9" stroke="white" stroke-width="2"/>
                <path d="M10 6v5M10 14h.01" stroke="white" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(errorDiv);
    
    setTimeout(() => {
        errorDiv.style.animation = 'slideUp 0.3s ease';
        setTimeout(() => errorDiv.remove(), 300);
    }, duration);
}

// Show success message
function showSuccess(message, duration = 3000) {
    const existingSuccess = document.querySelector('.success-message-banner');
    if (existingSuccess) {
        existingSuccess.remove();
    }
    
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message-banner';
    successDiv.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: #28a745;
        color: white;
        padding: 15px 30px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        font-size: 14px;
        max-width: 500px;
        animation: slideDown 0.3s ease;
    `;
    
    successDiv.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                <circle cx="10" cy="10" r="9" stroke="white" stroke-width="2"/>
                <path d="M6 10l3 3 5-6" stroke="white" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(successDiv);
    
    setTimeout(() => {
        successDiv.style.animation = 'slideUp 0.3s ease';
        setTimeout(() => successDiv.remove(), 300);
    }, duration);
}

// Handle signup form submission
async function handleSignup(event) {
    event.preventDefault();
    
    const name = sanitizeInput(document.getElementById('signup-name').value.trim(), 100);
    const email = document.getElementById('signup-email').value.trim().toLowerCase();
    const phone = document.getElementById('signup-phone').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;
    
    // Validate name
    const nameValidation = validateName(name);
    if (!nameValidation.valid) {
        showError(nameValidation.message);
        return false;
    }
    
    // Validate email
    const emailValidation = validateEmail(email);
    if (!emailValidation.valid) {
        showError(emailValidation.message);
        return false;
    }
    
    // Validate phone
    const phoneValidation = validatePhone(phone);
    if (!phoneValidation.valid) {
        showError(phoneValidation.message);
        return false;
    }
    
    // Validate passwords match
    if (password !== confirmPassword) {
        showError('Passwords do not match!');
        document.getElementById('signup-confirm-password').focus();
        return false;
    }
    
    // Validate password strength
    const strengthResult = checkPasswordStrength(password);
    if (!strengthResult.isStrong) {
        let missingRequirements = [];
        if (!strengthResult.checks.length) missingRequirements.push('at least 12 characters');
        if (!strengthResult.checks.uppercase) missingRequirements.push('one uppercase letter');
        if (!strengthResult.checks.lowercase) missingRequirements.push('one lowercase letter');
        if (!strengthResult.checks.number) missingRequirements.push('one number');
        if (!strengthResult.checks.special) missingRequirements.push('one special character');
        if (!strengthResult.checks.noSequential) missingRequirements.push('no sequential characters');
        if (!strengthResult.checks.noCommon) missingRequirements.push('must not be a common password');
        
        showError('Password must contain:\n• ' + missingRequirements.join('\n• '));
        return false;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Creating secure account...';
    submitBtn.disabled = true;
    submitBtn.style.opacity = '0.7';
    submitBtn.style.cursor = 'not-allowed';
    
    try {
        // Ensure we have CSRF token
        if (!csrfToken) {
            await fetchCSRFToken();
        }
        
        const response = await fetch(`${API_URL}/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken || ''
            },
            credentials: 'include',
            body: JSON.stringify({
                name: name,
                email: email,
                phone: phoneValidation.cleaned,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('Account created successfully! Redirecting to login...');
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        } else {
            showError(data.message || 'Registration failed. Please try again.');
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
            submitBtn.style.opacity = '1';
            submitBtn.style.cursor = 'pointer';
        }
    } catch (error) {
        console.error('Signup error:', error);
        showError('Network error. Please check your connection and try again.');
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
        submitBtn.style.opacity = '1';
        submitBtn.style.cursor = 'pointer';
    }
    
    return false;
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();
    
    const login = sanitizeInput(document.getElementById('login-email').value.trim(), 254);
    const password = document.getElementById('login-password').value;
    
    // Basic validation
    if (!login || !password) {
        showError('Please enter both email/phone and password');
        return false;
    }
    
    if (login.length < 3) {
        showError('Please enter a valid email or phone number');
        return false;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Signing in securely...';
    submitBtn.disabled = true;
    submitBtn.style.opacity = '0.7';
    submitBtn.style.cursor = 'not-allowed';
    
    try {
        // Ensure we have CSRF token
        if (!csrfToken) {
            await fetchCSRFToken();
        }
        
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken || ''
            },
            credentials: 'include',
            body: JSON.stringify({
                login: login,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Update CSRF token if provided
            if (data.csrf_token) {
                csrfToken = data.csrf_token;
            }
            
            showSuccess(`Welcome back, ${data.user.name}!`);
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1000);
        } else {
            // Show specific error messages
            if (response.status === 403) {
                showError(data.message);
            } else if (response.status === 429) {
                showError('Too many login attempts. Please wait a moment and try again.');
            } else if (response.status === 401) {
                showError('Invalid email/phone or password. Please try again.');
            } else {
                showError(data.message || 'Login failed. Please try again.');
            }
            
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
            submitBtn.style.opacity = '1';
            submitBtn.style.cursor = 'pointer';
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('Network error. Please check your connection and try again.');
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
        submitBtn.style.opacity = '1';
        submitBtn.style.cursor = 'pointer';
    }
    
    return false;
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateX(-50%) translateY(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
    }
    
    @keyframes slideUp {
        from {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
        to {
            opacity: 0;
            transform: translateX(-50%) translateY(-20px);
        }
    }
`;
document.head.appendChild(style);

// Prevent form resubmission on page reload
if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}
