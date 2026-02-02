// API Base URL
const API_URL = '/api';

// Toggle password visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
}

// Handle signup form submission
async function handleSignup(event) {
    event.preventDefault();
    
    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const phone = document.getElementById('signup-phone').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;
    
    // Validate passwords match
    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return false;
    }
    
    // Validate password strength (at least 8 characters)
    if (password.length < 8) {
        alert('Password must be at least 8 characters long!');
        return false;
    }
    
    try {
        const response = await fetch(`${API_URL}/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                name: name,
                email: email,
                phone: phone,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Sign up successful! Redirecting to login page...');
            window.location.href = '/login';
        } else {
            alert(data.message || 'Sign up failed. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    }
    
    return false;
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();
    
    const login = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                login: login,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Login successful! Welcome back, ' + data.user.name + '!');
            window.location.href = '/dashboard';
        } else {
            alert(data.message || 'Invalid email/phone or password!');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    }
    
    return false;
}
