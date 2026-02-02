// Check login status on page load
window.addEventListener('DOMContentLoaded', function() {
    checkLoginStatus();
});

// Function to check if user is logged in
function checkLoginStatus() {
    const isLoggedIn = sessionStorage.getItem('isLoggedIn');
    const currentUser = sessionStorage.getItem('currentUser');
    const navButtons = document.getElementById('navButtons');
    
    if (isLoggedIn === 'true' && currentUser) {
        const user = JSON.parse(currentUser);
        navButtons.innerHTML = `
            <span class="user-name">Welcome, ${user.name.split(' ')[0]}!</span>
            <a href="dashboard.html" class="btn-signin">Dashboard</a>
            <a href="#" class="btn-signup" onclick="logout(event)">Logout</a>
        `;
    }
}

// Logout function
function logout(event) {
    if (event) event.preventDefault();
    if (confirm('Are you sure you want to logout?')) {
        sessionStorage.removeItem('currentUser');
        sessionStorage.removeItem('isLoggedIn');
        alert('You have been logged out successfully!');
        window.location.href = 'index.html';
    }
}

// Navigate to section without triggering logout
function navigateToSection(event, sectionId) {
    event.preventDefault();
    const target = document.getElementById(sectionId);
    if (target) {
        target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
    return false;
}

// Order item function
function orderItem(itemName, itemPrice) {
    const isLoggedIn = sessionStorage.getItem('isLoggedIn');
    
    if (isLoggedIn === 'true') {
        // Add to cart or orders
        let orders = JSON.parse(localStorage.getItem('orders') || '[]');
        const currentUser = JSON.parse(sessionStorage.getItem('currentUser'));
        
        const order = {
            id: Date.now(),
            userId: currentUser.email,
            item: itemName,
            price: itemPrice,
            date: new Date().toISOString(),
            status: 'pending'
        };
        
        orders.push(order);
        localStorage.setItem('orders', JSON.stringify(orders));
        
        alert(`${itemName} (${itemPrice}) has been added to your cart!`);
    } else {
        if (confirm('Please login to place an order. Would you like to login now?')) {
            window.location.href = 'login.html';
        }
    }
}

// Newsletter subscription
function subscribeNewsletter() {
    const emailInput = document.getElementById('newsletter-email');
    const email = emailInput.value.trim();
    
    if (email && isValidEmail(email)) {
        let subscribers = JSON.parse(localStorage.getItem('newsletterSubscribers') || '[]');
        
        if (!subscribers.includes(email)) {
            subscribers.push(email);
            localStorage.setItem('newsletterSubscribers', JSON.stringify(subscribers));
            alert('Thank you for subscribing to our newsletter!');
            emailInput.value = '';
        } else {
            alert('You are already subscribed!');
        }
    } else {
        alert('Please enter a valid email address.');
    }
}

// Email validation helper
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Add scroll animation
let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', function() {
    let scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    if (scrollTop > lastScrollTop && scrollTop > 100) {
        navbar.style.transform = 'translateY(-100%)';
    } else {
        navbar.style.transform = 'translateY(0)';
    }
    
    lastScrollTop = scrollTop;
});

// Add fade-in animation on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe elements for animation
document.querySelectorAll('.menu-item, .feature-card, .testimonial-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

console.log('Coffee-in website loaded successfully!');
