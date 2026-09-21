import time
import os
import shutil
from pathlib import Path
import requests
import urllib3

# Suppress insecure request warnings for self-signed certificates in scanner
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

os.environ['WDM_LOG'] = '0'

IMMEDIATE_STOPS = ["iplogger", "grabify", "webhook.site", "requestbin", "ngrok", "serveo.net", "loca.lt"]
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

def _find_browser_binary():
    """Detect available browser binary on Windows/Linux/Mac."""
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("msedge"),
        shutil.which("microsoft-edge")
    ]
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("chrome"),
        shutil.which("google-chrome")
    ]
    
    for p in chrome_paths:
        if p and os.path.exists(p):
            return "chrome", p
            
    for p in edge_paths:
        if p and os.path.exists(p):
            return "edge", p
            
    return None, None

def _trace_with_requests(url: str):
    """Fast HTTP-based redirect tracer using requests."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    })
    
    try:
        req_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
        response = session.get(req_url, allow_redirects=True, timeout=8, verify=False)
        final_url = str(response.url)
        
        # Check redirect history
        was_redirected = len(response.history) > 0
        clean_original = url.replace("https://", "").replace("http://", "").rstrip("/")
        clean_final = final_url.replace("https://", "").replace("http://", "").rstrip("/")
        if clean_original.lower() != clean_final.lower():
            was_redirected = True
            
        return final_url, was_redirected, None
    except requests.exceptions.RequestException as e:
        return url, False, str(e)

def get_final_url(url: str):
    """
    Multi-tier Zero-Trust URL Tracer:
    1. First performs fast HTTP redirect resolution via requests.
    2. If suspected evasion / JS redirect or browser available, attempts headless Edge/Chrome.
    3. Guarantees non-crashing fallback at all times.
    """
    print(f"\n🕸️ [ZERO-TRUST TRACER] Initiating Deep Scan for: {url}")
    
    # Tier 1: Fast HTTP session trace
    http_final, http_redirected, http_error = _trace_with_requests(url)
    
    # Check if immediate threat detected during HTTP trace
    if any(threat in http_final.lower() for threat in IMMEDIATE_STOPS):
        print(f"🚨 [THREAT SPOTTED] Known hacker tool in URL chain: {http_final}")
        return http_final, True, None
    
    # Check browser availability for Tier 2 deep Selenium trace
    browser_type, binary_path = _find_browser_binary()
    if not browser_type:
        print("ℹ️ [TRACER] No local Chrome/Edge binary detected for Selenium. Using high-speed HTTP tracer.")
        return http_final, http_redirected, http_error

    driver = None
    try:
        if browser_type == "edge":
            from selenium import webdriver
            from selenium.webdriver.edge.options import Options as EdgeOptions
            from selenium.webdriver.edge.service import Service as EdgeService
            
            print("🚀 [SELENIUM] Launching Headless Microsoft Edge Browser...")
            edge_options = EdgeOptions()
            edge_options.add_argument("--headless=new")
            edge_options.add_argument("--disable-gpu")
            edge_options.add_argument("--no-sandbox")
            edge_options.add_argument("--disable-dev-shm-usage")
            edge_options.add_argument("--log-level=3")
            edge_options.add_argument(f"user-agent={DEFAULT_USER_AGENT}")
            edge_options.binary_location = binary_path
            
            driver = webdriver.Edge(options=edge_options)
        else:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver.chrome.service import Service as ChromeService
            from webdriver_manager.chrome import ChromeDriverManager
            
            print("🚀 [SELENIUM] Launching Headless Google Chrome Browser...")
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_argument(f"user-agent={DEFAULT_USER_AGENT}")
            chrome_options.binary_location = binary_path
            
            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
        driver.set_page_load_timeout(15)
        target = url if url.startswith(("http://", "https://")) else f"http://{url}"
        driver.get(target)
        
        last_printed_url = ""
        # Monitor for dynamic JavaScript redirects (up to 5 seconds)
        for _ in range(5):
            time.sleep(1)
            current_url = driver.current_url
            if current_url != last_printed_url:
                print(f"🔄 [REDIRECT JUMP] Moved to: {current_url}")
                last_printed_url = current_url
                
            if any(threat in current_url.lower() for threat in IMMEDIATE_STOPS):
                print(f"🚨 [THREAT SPOTTED] Hacker tool reached in browser: {current_url}")
                break

        final_destination = driver.current_url
        clean_original = url.replace("https://", "").replace("http://", "").rstrip("/")
        clean_final = final_destination.replace("https://", "").replace("http://", "").rstrip("/")
        was_redirected = clean_original.lower() != clean_final.lower()
        
        print(f"🎯 [TRACER SUCCESS] Final Destination: {final_destination} (Redirected: {was_redirected})")
        return final_destination, was_redirected, None

    except Exception as e:
        print(f"⚠️ [SELENIUM WARNING] Browser trace encountered issue ({e}). Falling back to HTTP trace.")
        return http_final, http_redirected, None
    finally:
        if driver:
            try:
                driver.quit()
                print("🧹 [SELENIUM] Browser closed.")
            except Exception:
                pass