// Toggle password visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
}

// Handle signup form submission
function handleSignup(event) {
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
    
    // Store user data (in a real app, this would be sent to a server)
    const userData = {
        name: name,
        email: email,
        phone: phone,
        password: password
    };
    
    // Store in users list
    let users = JSON.parse(localStorage.getItem('users') || '[]');
    
    // Check if user already exists
    const existingUser = users.find(u => u.email === email || u.phone === phone);
    if (existingUser) {
        alert('User with this email or phone already exists!');
        return false;
    }
    
    users.push(userData);
    localStorage.setItem('users', JSON.stringify(users));
    
    alert('Sign up successful! Redirecting to login page...');
    window.location.href = 'login.html';
    
    return false;
}

// Handle login form submission
function handleLogin(event) {
    event.preventDefault();
    
    const login = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    // Get stored users data
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    
    if (users.length === 0) {
        alert('No account found. Please sign up first!');
        return false;
    }
    
    // Find user by email or phone
    const user = users.find(u => (u.email === login || u.phone === login) && u.password === password);
    
    if (user) {
        // Store current session
        sessionStorage.setItem('currentUser', JSON.stringify(user));
        sessionStorage.setItem('isLoggedIn', 'true');
        
        alert('Login successful! Welcome back, ' + user.name + '!');
        window.location.href = 'dashboard.html';
    } else {
        alert('Invalid email/phone or password!');
    }
    
    return false;
}
