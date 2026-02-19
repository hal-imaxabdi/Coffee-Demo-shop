const API_URL = '/api';

window.addEventListener('DOMContentLoaded', checkLoginStatus);

async function checkLoginStatus() {
    const navButtons = document.getElementById('navButtons');

    try {
        const response = await fetch(`${API_URL}/current-user`, { credentials: 'include' });
        const data = await response.json();

        if (data.success && data.user) {
            const firstName = data.user.name.split(' ')[0];
            navButtons.innerHTML = `
                <span class="user-name">Welcome, ${firstName}!</span>
                <a href="/dashboard" class="btn-signin">Dashboard</a>
                <a href="#" class="btn-signup" onclick="logout(event)">Logout</a>
            `;
        }
    } catch {
        // User not authenticated — default nav buttons remain
    }
}

async function logout(event) {
    event.preventDefault();
    if (!confirm('Are you sure you want to logout?')) return;

    try {
        await fetch(`${API_URL}/logout`, { method: 'POST', credentials: 'include' });
    } finally {
        window.location.href = '/';
    }
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
    try {
        const userResponse = await fetch(`${API_URL}/current-user`, { credentials: 'include' });
        const userData = await userResponse.json();

        if (!userData.success) {
            if (confirm('Please login to place an order. Would you like to login now?')) {
                window.location.href = '/login';
            }
            return;
        }

        const response = await fetch(`${API_URL}/orders`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ item: itemName, price: itemPrice }),
        });

        const data = await response.json();
        alert(data.success
            ? `${itemName} (${itemPrice}) has been added to your orders!`
            : data.message || 'Failed to place order.'
        );
    } catch {
        alert('An error occurred. Please try again.');
    }
}

async function subscribeNewsletter() {
    const emailInput = document.getElementById('newsletter-email');
    const email = emailInput.value.trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        alert('Please enter a valid email address.');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/newsletter`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });

        const data = await response.json();
        if (data.success) {
            alert('Thank you for subscribing to our newsletter!');
            emailInput.value = '';
        } else {
            alert(data.message || 'Subscription failed.');
        }
    } catch {
        alert('An error occurred. Please try again.');
    }
}

let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', () => {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    navbar.style.transform = (scrollTop > lastScrollTop && scrollTop > 100)
        ? 'translateY(-100%)'
        : 'translateY(0)';
    lastScrollTop = scrollTop;
});

const observer = new IntersectionObserver(
    entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    },
    { threshold: 0.1, rootMargin: '0px 0px -50px 0px' }
);

document.querySelectorAll('.menu-item, .feature-card, .testimonial-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});