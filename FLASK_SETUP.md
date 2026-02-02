# Flask Template Setup Guide

## 📁 Folder Structure You Need

```
your-project/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── coffee_shop.db                  # Database (auto-created)
│
├── templates/                      # HTML files go here
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   └── dashboard.html
│
└── static/                         # CSS, JS, Images go here
    ├── css/
    │   ├── styles.css
    │   ├── auth-styles.css
    │   └── dashboard.css
    ├── js/
    │   ├── script.js
    │   └── auth-script.js
    └── images/
        ├── 1.jpg
        ├── 2.jpg
        ├── capuccino.jpg
        └── ... (all your images)
```

## 🚀 Step-by-Step Setup

### Step 1: Create Folder Structure

```bash
# Create folders
mkdir templates
mkdir static
mkdir static/css
mkdir static/js
mkdir static/images
```

### Step 2: Move Your Files

**Move HTML files to templates:**
```bash
move index.html templates/
move login.html templates/
move signup.html templates/
move dashboard.html templates/
```

**Move CSS files to static/css:**
```bash
move styles.css static/css/
move auth-styles.css static/css/
move dashboard.css static/css/
```

**Move JS files to static/js:**
```bash
move script-flask.js static/js/script.js
move auth-script-flask.js static/js/auth-script.js
```

**Move images to static/images:**
```bash
move images/* static/images/
```

### Step 3: Update HTML Files

You need to update paths in your HTML files to work with Flask's template system.

#### **In ALL HTML files (index.html, login.html, signup.html, dashboard.html):**

**OLD CSS links:**
```html
<link rel="stylesheet" href="styles.css">
<link rel="stylesheet" href="auth-styles.css">
<link rel="stylesheet" href="dashboard.css">
```

**NEW Flask CSS links:**
```html
<link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
<link rel="stylesheet" href="{{ url_for('static', filename='css/auth-styles.css') }}">
<link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
```

**OLD JS links:**
```html
<script src="script.js"></script>
<script src="auth-script.js"></script>
```

**NEW Flask JS links:**
```html
<script src="{{ url_for('static', filename='js/script.js') }}"></script>
<script src="{{ url_for('static', filename='js/auth-script.js') }}"></script>
```

**OLD image links:**
```html
<img src="images/1.jpg" alt="Coffee">
```

**NEW Flask image links:**
```html
<img src="{{ url_for('static', filename='images/1.jpg') }}" alt="Coffee">
```

**OLD navigation links:**
```html
<a href="index.html">Home</a>
<a href="login.html">Login</a>
<a href="signup.html">Signup</a>
<a href="dashboard.html">Dashboard</a>
```

**NEW Flask navigation links:**
```html
<a href="/">Home</a>
<a href="/login">Login</a>
<a href="/signup">Signup</a>
<a href="/dashboard">Dashboard</a>
```

### Step 4: Replace app.py

Use the new `app_with_templates.py` as your `app.py`

### Step 5: Start Flask

```bash
python app.py
```

### Step 6: Access Your Site

Open browser and go to:
```
http://localhost:5000
```

## 📝 Quick Find & Replace Guide

Open each HTML file and do these replacements:

### For index.html:

1. **Find:** `href="styles.css"`  
   **Replace:** `href="{{ url_for('static', filename='css/styles.css') }}"`

2. **Find:** `src="images/`  
   **Replace:** `src="{{ url_for('static', filename='images/`

3. **Find:** `href="login.html"`  
   **Replace:** `href="/login"`

4. **Find:** `href="signup.html"`  
   **Replace:** `href="/signup"`

5. **Find:** `src="script.js"`  
   **Replace:** `src="{{ url_for('static', filename='js/script.js') }}"`

### For login.html:

1. **Find:** `href="auth-styles.css"`  
   **Replace:** `href="{{ url_for('static', filename='css/auth-styles.css') }}"`

2. **Find:** `src="images/`  
   **Replace:** `src="{{ url_for('static', filename='images/`

3. **Find:** `href="signup.html"`  
   **Replace:** `href="/signup"`

4. **Find:** `window.location.href = 'dashboard.html'`  
   **Replace:** `window.location.href = '/dashboard'`

5. **Find:** `src="auth-script.js"`  
   **Replace:** `src="{{ url_for('static', filename='js/auth-script.js') }}"`

### For signup.html:

1. **Find:** `href="auth-styles.css"`  
   **Replace:** `href="{{ url_for('static', filename='css/auth-styles.css') }}"`

2. **Find:** `src="images/`  
   **Replace:** `src="{{ url_for('static', filename='images/`

3. **Find:** `href="login.html"`  
   **Replace:** `href="/login"`

4. **Find:** `window.location.href = 'login.html'`  
   **Replace:** `window.location.href = '/login'`

5. **Find:** `src="auth-script.js"`  
   **Replace:** `src="{{ url_for('static', filename='js/auth-script.js') }}"`

### For dashboard.html:

1. **Find:** `href="styles.css"`  
   **Replace:** `href="{{ url_for('static', filename='css/styles.css') }}"`

2. **Find:** `href="dashboard.css"`  
   **Replace:** `href="{{ url_for('static', filename='css/dashboard.css') }}"`

3. **Find:** `src="images/`  
   **Replace:** `src="{{ url_for('static', filename='images/`

4. **Find:** `href="index.html"`  
   **Replace:** `href="/"`

5. **Find:** `window.location.href = 'login.html'`  
   **Replace:** `window.location.href = '/login'`

6. **Find:** `window.location.href = 'index.html'`  
   **Replace:** `window.location.href = '/'`

## ✅ Verify Everything Works

1. Start Flask: `python app.py`
2. Open: `http://localhost:5000`
3. Test navigation between pages
4. Test login with: `admin@coffee.com` / `admin123`
5. Try placing an order (should work now!)
6. Check dashboard

## 🎯 Benefits of Flask Template Structure

✅ **Sessions work properly** - No more authentication issues!  
✅ **Clean URLs** - `/login` instead of `login.html`  
✅ **Better organization** - Separation of concerns  
✅ **Production ready** - Standard Flask structure  
✅ **Easy deployment** - Can deploy to Heroku, PythonAnywhere, etc.

## 🐛 Common Issues

### Issue: 404 Not Found
**Solution:** Make sure HTML files are in `templates/` folder

### Issue: CSS not loading
**Solution:** Make sure CSS files are in `static/css/` folder and using `url_for()`

### Issue: Images not loading
**Solution:** Make sure images are in `static/images/` folder and using `url_for()`

### Issue: Still getting "not authenticated"
**Solution:** Make sure you're accessing via `http://localhost:5000` not `file:///`

## 📚 Need Help?

Check the structure:
```bash
# Show your folder structure
tree /F  # Windows
ls -R    # Mac/Linux
```

The structure should match the one at the top of this guide!
