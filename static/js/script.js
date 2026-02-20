const API_URL = '/api';

function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    return token ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
}

window.addEventListener('DOMContentLoaded', async function () {
    await checkLoginStatus();
});

async function checkLoginStatus() {
    const navButtons = document.getElementById('navButtons');
    const token = localStorage.getItem('auth_token');
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/current-user`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();

        if (data.success && data.user) {
            navButtons.innerHTML = `
                <span class="user-name">Welcome, ${data.user.name.split(' ')[0]}!</span>
                <a href="/dashboard" class="btn-signin">Dashboard</a>
                <a href="#" class="btn-signup" onclick="logout(event)">Logout</a>
            `;
        } else {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_name');
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

async function logout(event) {
    if (event) event.preventDefault();
    if (!confirm('Are you sure you want to logout?')) return;

    try {
        await fetch(`${API_URL}/logout`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
    } catch (error) {
        console.error('Logout error:', error);
    }

    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_name');
    window.location.href = '/';
}

function navigateToSection(event, sectionId) {
    event.preventDefault();
    const target = document.getElementById(sectionId);
    if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    return false;
}

async function orderItem(itemName, itemPrice) {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        if (confirm('Please login to place an order. Would you like to login now?')) {
            window.location.href = '/login';
        }
        return;
    }

    try {
        const response = await fetch(`${API_URL}/orders`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ item: itemName, price: itemPrice })
        });

        const data = await response.json();

        if (response.status === 401) {
            localStorage.removeItem('auth_token');
            if (confirm('Your session has expired. Please login again.')) {
                window.location.href = '/login';
            }
            return;
        }

        if (data.success) {
            alert(`${itemName} (${itemPrice}) has been added to your orders!`);
        } else {
            alert(data.error || 'Failed to place order.');
        }
    } catch (error) {
        console.error('Order error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function subscribeNewsletter() {
    const emailInput = document.getElementById('newsletter-email');
    const email = emailInput.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email || !emailRegex.test(email)) {
        alert('Please enter a valid email address.');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/newsletter`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await response.json();

        if (data.success) {
            alert('Thank you for subscribing to our newsletter!');
            emailInput.value = '';
        } else {
            alert(data.message || 'Subscription failed.');
        }
    } catch (error) {
        alert('An error occurred. Please try again.');
    }
}

let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', function () {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    navbar.style.transform = (scrollTop > lastScrollTop && scrollTop > 100) ? 'translateY(-100%)' : 'translateY(0)';
    lastScrollTop = scrollTop;
});

const observer = new IntersectionObserver(function (entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

document.querySelectorAll('.menu-item, .feature-card, .testimonial-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});