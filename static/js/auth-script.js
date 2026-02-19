const API_URL = '/api';

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.setAttribute('type', input.type === 'password' ? 'text' : 'password');
}

async function handleSignup(event) {
    event.preventDefault();

    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const phone = document.getElementById('signup-phone').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;

    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return false;
    }

    if (password.length < 8) {
        alert('Password must be at least 8 characters long!');
        return false;
    }

    try {
        const response = await fetch(`${API_URL}/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ name, email, phone, password }),
        });

        const data = await response.json();

        if (data.success) {
            alert('Sign up successful! Redirecting to login page...');
            window.location.href = '/login';
        } else {
            alert(data.message || 'Sign up failed. Please try again.');
        }
    } catch {
        alert('An error occurred. Please try again.');
    }

    return false;
}

async function handleLogin(event) {
    event.preventDefault();

    const login = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ login, password }),
        });

        const data = await response.json();

        if (data.success) {
            alert(`Login successful! Welcome back, ${data.user.name}!`);
            window.location.href = '/dashboard';
        } else {
            alert(data.message || 'Invalid email/phone or password!');
        }
    } catch {
        alert('An error occurred. Please try again.');
    }

    return false;
}