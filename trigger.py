import requests
from bs4 import BeautifulSoup
import time
import random

# URL of the honeypot login page
base_url = "http://localhost:5000"
login_url = f"{base_url}/login"

def automated_login_attempt(username, password, delay=0.05):
    """
    Simulates an automated login attempt that would trigger timing detection
    
    Parameters:
    - username: Username to try
    - password: Password to try
    - delay: Simulated delay between requests (low values appear more bot-like)
    """
    print(f"Attempting automated login with {username}:{password}")
    
    # Get the login page
    session = requests.Session()
    response = session.get(base_url)
    
    # Very short pause (too short to be human-like)
    time.sleep(delay)
    
    # Submit the login form with minimal delay
    login_data = {
        'username': username,
        'password': password
    }
    
    response = session.post(login_url, data=login_data)
    
    # Check if we were redirected to the fake admin panel
    if "SysAdmin Control Panel" in response.text:
        print("Triggered honeypot's fake admin panel!")
        
        # Try clicking on the "Logs" section with minimal delay
        time.sleep(delay)
        response = session.get(f"{base_url}/api/system/logs")
        print("Accessed system logs page")
    else:
        print("Login failed")
    
    return response.text

def run_multiple_attempts():
    """Run several automated attempts with different usernames"""
    common_usernames = ["admin", "root", "administrator", "user", "test"]
    common_passwords = ["admin", "password", "123456", "admin123", "root"]
    
    for i in range(3):  # Multiple attempts will increase threat score
        username = random.choice(common_usernames)
        password = random.choice(common_passwords)
        automated_login_attempt(username, password)
        time.sleep(0.2)  # Short delay between attempts (suspiciously fast)

if __name__ == "__main__":
    print("Starting automated login script that would trigger timing detection...")
    run_multiple_attempts()
    print("Complete - this activity would be flagged as suspicious by the honeypot")