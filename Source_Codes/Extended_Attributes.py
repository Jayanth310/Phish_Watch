import os
import configparser
from datetime import datetime
import logging
import sqlite3
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import sys
import csv
from threading import Lock
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse
import tldextract
import signal
import shutil
import subprocess
import platform
import threading


global total_processed
global starting_point
total_processed = 0
starting_point = 0


def is_chrome_installed():
    """Check if Google Chrome or Chromium is installed."""
    return shutil.which("google-chrome")

def install_google_chrome():
    """Download and install Google Chrome dynamically in Kali Linux."""
    print("Google Chrome not found. Installing...")

    chrome_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
    chrome_deb = "google-chrome-stable_current_amd64.deb"

    # Download Google Chrome
    subprocess.run(["wget", chrome_url], check=True)

    # Install Chrome
    subprocess.run(["sudo", "apt", "install", "./" + chrome_deb, "-y"], check=True)

    # Clean up downloaded file
    os.remove(chrome_deb)


def signal_handler(sig, frame):
    global executor_running
    
    # Add a flag to prevent multiple executions
    if hasattr(signal_handler, 'called'):
        return
    signal_handler.called = True

    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    if executor_running:
        logging.warning("Stopping executor due to signal...")

    # Update logs and tracker files
    integrate_log_updates(
        "Extended Attributes Detection",
        run_id,
        interrupted=True,
        progress=progress,
        error_type="Keyboard Interrupt"
    )
    print(f"Execution interrupted at {progress}% completion.")
    
    # Instead of sys.exit(), set a flag and allow normal termination
    os._exit(1)  # Use os._exit() instead of sys.exit() to avoid thread cleanup issues


# Add session expired handler after signal_handler
def signal_session_expired(sig, frame):
    """Handle EC2 session expiration (SIGHUP) gracefully.
    Works on Linux and macOS (including EC2 instances).
    """
    # Add a flag to prevent multiple executions
    if hasattr(signal_session_expired, 'called'):
        return
    signal_session_expired.called = True

    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"EC2 session expired at {progress}%.")

    integrate_log_updates(
        "Extended Attributes Detection",
        run_id,
        interrupted=True,
        progress=progress,
        error_type="Session Expired"
    )
    print(f"EC2 session expired at {progress}% completion.")
    sys.exit(3)

# Update signal handlers
signal.signal(signal.SIGINT, signal_handler)           # Ctrl+C
if platform.system().lower() == "linux":
    signal.signal(signal.SIGHUP, signal_session_expired)   # EC2 Session expired

# Function to ensure a directory exists
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'Config', 'Config.ini'), encoding="utf8")


# Get base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))

# Paths from Config.ini
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hashes_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hashes_dir', fallback='Hashes'))

# Ensure directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hashes_dir)  # Ensure the HASHES directory exists

# Function to compute file hash
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()


# Set up logging function
def setup_logging(log_file):
    """
    Sets up logging for the script.
    """
    try:
        # Ensure directory exists for logs
        ensure_directory_exists(os.path.dirname(log_file))

        # Remove all default handlers (e.g., console handler)
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Set up logging to log only to the file
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, mode='a', encoding='utf-8')  # Only log to file
            ]
        )
        logging.info("Logging initialized and active.")  # Test log
    except Exception as e:
        print(f"Error initializing logging: {e}")
        sys.exit(1)


# Function to check and update hash
def check_and_update_hash(db_file, hash_file):
    if not os.path.exists(db_file):
        print("Database file does not exist. Creating new database...")
        return True  # Need to create/update the database

    if not os.path.exists(hash_file):
        print("Hash file does not exist. Proceeding with updates...")
        return True  # No hash to compare, assume changes

    # Compare current hash with stored hash
    current_hash = compute_file_hash(db_file)
    with open(hash_file, "r") as hf:
        stored_hash = hf.read().strip()

    if current_hash != stored_hash:
        print("Hash mismatch. Updates are required...")
        return True
    else:
        print("Hash matches. No updates needed...")
        return False

# Function to update hash
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)

# Handle file initialization and timestamp updates
def handle_files(base_name, file_type, directory):
    """
    Handle file initialization and timestamp updates for log, output, and DB files.
    """
    existing_files = [
        f for f in os.listdir(directory) if base_name in f and f.endswith(file_type)
    ]
    if existing_files:
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = os.path.join(directory, existing_files[0])
 
        # Rename the existing file with a new timestamp
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        new_file_path = os.path.join(directory, new_file_name)
        os.rename(latest_file, new_file_path)
        logging.info(f"Updated file timestamp and renamed: {new_file_path}")
        return new_file_path
    else:
        # Create a new file if no matching file exists
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        new_file_path = os.path.join(directory, new_file_name)
        if file_type == ".log":
            open(new_file_path, 'a').close()
        logging.info(f"Created new file: {new_file_path}")
        return new_file_path
 
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Function to set up session with retries
def setup_session():
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# Detect the latest file
def detect_latest_file(directory, prefix):
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if f"{prefix}" in f]
        if not files:
            raise FileNotFoundError(f"No files with prefix '{prefix}' found in {directory}")
        latest_file = max(files, key=os.path.getmtime)
        logging.info(f"Detected latest file: {latest_file}")
        return latest_file
    except Exception as e:
        logging.error(f"Error detecting latest file: {e}")
        raise


# Function to check open ports (80, 443)
def check_ports(domain):
    ports_status = {80: "Closed", 443: "Closed"}
    for port in [80, 443]:
        try:
            with socket.create_connection((domain, port), timeout=3):
                ports_status[port] = "Open"
        except (socket.timeout, socket.error):
            continue
    return ports_status

# Function to check SSL/TLS status
def check_ssl_tls(domain):
    ports = [80, 443]
    results = {}
    for port in ports:
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, port))
            results[port] = "Valid"
        except (ssl.SSLError, socket.error):
            logging.info(f"SSL/TLS status for {domain} on port {port}: Invalid")
            results[port] = "Invalid"
        except Exception:
            logging.info(f"SSL/TLS status for {domain} on port {port}: Null")
            results[port] = "Null"
    return results


# Detect the operating system and return the appropriate ChromeDriver path
system = platform.system().lower()
def get_chromedriver_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Project directory
    drivers_path = os.path.join(base_dir, "drivers")  # Path to stored drivers

    arch = platform.machine().lower()

    if system == "windows":
        return ChromeDriverManager().install()
        # if "64" in arch:
        #     return os.path.join(drivers_path, "win64.exe")
        # else:
        #     return os.path.join(drivers_path, "wind32.exe")

    elif system == "darwin":  # macOS
        if "arm" in arch:  # Apple Silicon (M1, M2, etc.)
            return os.path.join(drivers_path, "mac_arm64")
        else:
            return os.path.join(drivers_path, "mac_x64")

    elif system == "linux":
        return os.path.join(drivers_path, "linux64")

    else:
        raise Exception("Unsupported OS")

# Check and install Chrome if necessary
if system == "linux" and not is_chrome_installed():
    install_google_chrome()

driver_path = get_chromedriver_path()


# Function to get the final redirected URL and check page content

def get_final_url_and_content(domain):
    """
    Retrieves the final redirected URL and page content for a given domain using Selenium.
    Automatically downloads and manages the correct Chromedriver version.
    """

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")  # Run in headless mode (no GUI)
    chrome_options.add_argument("--disable-gpu")  # Disables GPU acceleration
    chrome_options.add_argument("--disable-dev-shm-usage")  # Prevents shared memory crashes
    chrome_options.add_argument("--disable-software-rasterizer")  # Prevents GPU emulation
    chrome_options.add_argument("--disable-webgl")  # Disables WebGL to prevent GLES errors
    chrome_options.add_argument("--disable-3d-apis")  # Disables all 3D rendering APIs
    chrome_options.add_argument("--disable-features=WebGL2")  # Disables WebGL2 features
    chrome_options.add_argument("--disable-features=WebGPU")  # Disables WebGPU
    chrome_options.add_argument("--log-level=3")  # Suppress logging output
    chrome_options.add_argument("--disable-logging")  # Disable logging
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging", 'enable-automation'])
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")  # Prevent automation detection

    # Automatically download & manage the correct Chromedriver version
    service = Service(ChromeDriverManager().install())

    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        driver.get(f"http://{domain}")
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        final_url = driver.current_url
        page_source = driver.page_source
    except Exception as e:
        logging.error(f"Error getting final URL and content for {domain}: {e}")
        final_url = "Null"
        page_source = ""
    finally:
        driver.quit()

    return final_url, page_source


# Detect parked domains (both redirect-based & keyword-based)
def is_parked_domain(final_url, page_source):
    parsed_url = urlparse(final_url)
    extracted = tldextract.extract(parsed_url.netloc)
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    RAW_PARKED_DOMAINS = config.get("PARKED_DOMAINS", "domains_list")
    PARKED_DOMAINS = [domain.strip() for domain in RAW_PARKED_DOMAINS.split("\n")]
    PARKED_DOMAINS.pop(0)
    if domain_name in PARKED_DOMAINS:
        return True

    soup = BeautifulSoup(page_source, "html.parser")
    text_content = soup.get_text(separator=" ").lower()
    RAW_PARKED_KEYWORDS = config.get("PARKED_KEYWORDS", "keywords_list")
    PARKED_KEYWORDS = [domain.strip() for domain in RAW_PARKED_KEYWORDS.split("\n")]
    PARKED_KEYWORDS.pop(0)
    is_parked = any(keyword in text_content for keyword in PARKED_KEYWORDS)
    return is_parked

# Function to check if a website is hosted
def check_hosting_status(url):
    try:
        if url == "Null":
            return "No"
        response = requests.get(url, timeout=5, allow_redirects=True)
        if response.status_code == 200 and len(response.text.strip()) > 500:
            return "Yes"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking hosting status for {url}: {e}")
    return "No"

# Check for login page
def has_login_page(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            login_keywords = ["login", "signin", "auth", "register", "user", "account", "authenticate"]
            has_login = any(keyword in soup.get_text().lower() for keyword in login_keywords)
            return has_login
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking login page for {url}: {e}")
    return False

# Check for company keywords
def check_company_keywords(page_source):
    soup = BeautifulSoup(page_source, "html.parser")
    text_content = soup.get_text().lower()
    RAW_COMPANY_KEYWORDS = config.get("COMPANY_KEYWORDS", "company_keywords_list")
    COMPANY_KEYWORDS = [domain.strip() for domain in RAW_COMPANY_KEYWORDS.split("\n")]
    COMPANY_KEYWORDS.pop(0)
    found_keywords = [word for word in COMPANY_KEYWORDS if word.lower() in text_content]
    return " | ".join(found_keywords) if found_keywords else "No"

def port_status_conversion(port_status):
    open_ports = [port for port, status in port_status.items() if status == "Open"]
    return " | ".join(map(str, open_ports)) if open_ports else "Null"



# Process a single domain
def process_single_domain(domain):
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(process_single_domain, 'connection_lost'):
        return None

    final_url, page_source = get_final_url_and_content(domain)
    ports_status = check_ports(domain)
    ssl_tls_status = check_ssl_tls(domain)
    hosting_status = "No"


    if is_parked_domain(final_url, page_source):
        attributes = {
            "Domain": domain,
            "Redirection": f"{final_url} (Parked Domain)",
            "Website": "No",
            "Login Page": "No",
            "Port": port_status_conversion(ports_status),
            "SSL": "Yes" if any(status == "Valid" for port, status in ssl_tls_status.items() if ports_status[port] == "Open") else "No",
            "Company Keywords": "No"
        }
    else:
        hosting_status = check_hosting_status(final_url)
        login_status = "Yes" if hosting_status == "Yes" and has_login_page(final_url) else "No"
        company_keywords_found = check_company_keywords(page_source) if hosting_status == "Yes" else "No"
        attributes = {
            "Domain": domain,
            "Redirection": final_url,
            "Website": hosting_status,
            "Login Page": login_status,
            "Port": port_status_conversion(ports_status),
            "SSL": "Yes" if any(status == "Valid" for port, status in ssl_tls_status.items() if ports_status[port] == "Open") else "No",
            "Company Keywords": company_keywords_found
        }
    return attributes


def remove_duplicates(file_path):
    """
    Reads the existing file and removes duplicates based on domain.
    """
    seen = set()
    unique_rows = []

    with open(file_path, 'r', newline='', encoding="utf8") as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            if row['Domain'] not in seen:
                unique_rows.append(row)
                seen.add(row['Domain'])
    return unique_rows



def write_results_to_file(results, input_file, output_file):
    headers = ["Redirection", "Website", "Login Page", "Port", "SSL", "Company Keywords"]

    # Check if the results are empty
    if not results:
        logging.info("No new results to write. The results are empty.")
        return

    results_dict = {result["Domain"]: result for result in results}

    try:

        existing_rows = remove_duplicates(output_file) if os.path.exists(output_file) else []

        with open(input_file, "r", encoding="utf8") as input_csv:
            reader = csv.DictReader(input_csv)
            existing_headers = reader.fieldnames
            all_headers = existing_headers + [header for header in headers if header not in existing_headers]
            updated_rows = []
            for row in reader:
                domain = row.get("Domain", "").strip()
                if domain in results_dict:
                    matched_data = results_dict[domain]
                    row.update({
                        "Run_id": row.get("Run_id"),
                        "Customer_id": row.get("Customer_id"),
                        "Timestamp": row.get("Timestamp"),
                        "Domain": domain,
                        "IP Address": row.get("IP Address"),
                        "Name Server": row.get("Name Server"),
                        "Mail Server": row.get("Mail Server"),
                        "Registrar": row.get("Registrar"),
                        "Registrant": row.get("Registrant"),
                        "Registered Address": row.get("Registered Address"),
                        "Registration Country": row.get("Registration Country"),
                        "Registration Date": row.get("Registration Date"),
                        "Remarks": row.get("Remarks"),
                        'Website': str(matched_data.get("Website", "Null")).strip(),
                        "Redirection": str(matched_data.get("Redirection", "Null")).strip(),
                        "Login Page": str(matched_data.get("Login Page", "No")).strip(),
                        "Port": str(matched_data.get("Port", "Null")).strip(),
                        "SSL": str(matched_data.get("SSL", "Null")).strip(),
                        "Company Keywords": str(matched_data.get("Company Keywords", "Null")).strip()
                    })
                    updated_rows.append(row)
                    break

            # Merge existing rows with updated rows (filter out duplicates)
            final_rows = [row for row in updated_rows if row["Domain"] not in {d["Domain"] for d in existing_rows}]

            # Ensure final rows are only written to the output file with valid fieldnames
            with open(output_file, mode='a', newline='', encoding='utf-8') as output_csv:
                writer = csv.DictWriter(output_csv, fieldnames=all_headers)

                # Write header only if the file is empty
                if os.path.getsize(output_file) == 0:
                    writer.writeheader()

                writer.writerows(final_rows)

    except Exception as e:
        logging.error(f"Error writing results: {e}")

def insert_results_to_db(db_file, data):
    """
    Ensures the database table exists and inserts unique data rows.
    Handles multiple rows at once.
    """
    
    db_lock = Lock()
    try:
        with db_lock:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_attributes (
                    domain TEXT PRIMARY KEY,
                    redirection TEXT,
                    login_page TEXT,
                    port INTEGER,
                    ssl TEXT,
                    company_keywords TEXT
                )
            ''')

            for item in data:
                # Check if the domain already exists in the table
                cursor.execute('''
                    SELECT * FROM domain_attributes WHERE domain = ?
                ''', (item["Domain"],))
                if cursor.fetchone() is None:
                    # Insert the record
                    cursor.execute('''
                        INSERT INTO domain_attributes (domain, redirection, login_page, port, ssl, company_keywords)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        item["Domain"],
                        item["Redirection"],
                        item["Login Page"],
                        item["Port"],
                        item["SSL"],
                        item["Company Keywords"]
                    ))

            conn.commit()
            conn.close()
    except Exception as e:
        logging.error(f"Error updating db: {e}")

    # logging.info(f"Database updated successfully with {len(data)} records.")


def integrate_log_updates(option_name, run_id, success=False, interrupted=False, progress=0, error_type=None):
    """
    Updates Run_Master.csv and Run_Tracker.csv with process status.

    Parameters:
        option_name (str): The name of the task
        success (bool): Whether the execution was successful
        interrupted (bool): Whether the execution was interrupted
        progress (float): The percentage completion at the time of interruption
        error_type (str): The type of error that occurred
    """
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_master_path = os.path.join(input_dir, "Run_Master.csv")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")

    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "interrupted" if interrupted else "success"
        percentage = "100%" if success else f"{progress:.2f}%"
        error_type = error_type if error_type else "N/A"

        # Load existing Run_Master.csv data
        run_master_data = []
        if os.path.exists(run_master_path):
            with open(run_master_path, "r", newline="", encoding="utf-8") as master_file:
                run_master_data = list(csv.reader(master_file))

        # Use run_id from the last row if data exists
        if run_master_data:
            run_master_data
            last_row = run_master_data[-1]
            _run_id = run_id or last_row[0]  # Keep the same run_id as the last row
            start_timestamp_str = last_row[3]

            # Calculate completion time if the operation is successful
            if success and start_timestamp_str:
                start_timestamp = datetime.strptime(start_timestamp_str, "%Y-%m-%d %H:%M:%S")
                completion_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S") - start_timestamp
                formatted_completion_time = str(completion_time).split(".")[0]
                status = f"success,{formatted_completion_time}"

        # Prepare new rows for CSV files
        new_master_row = [_run_id, customer_id, customer_name, timestamp, option_name, status, error_type]
        new_tracker_row = [_run_id, customer_id, customer_name, timestamp, option_name, percentage, total_processed]

        # Append to Run_Master.csv
        with open(run_master_path, "a", newline="", encoding="utf-8") as master_file:
            csv.writer(master_file).writerow(new_master_row)

        # Append to Run_Tracker.csv
        with open(run_tracker_path, "a", newline="", encoding="utf-8") as tracker_file:
            csv.writer(tracker_file).writerow(new_tracker_row)

        logging.info(f"Log updates integrated: {option_name}, Status: {status}, Completion: {percentage}")
    except Exception as e:
        logging.error(f"Error integrating log updates: {e}")


def set_starting_point(option_name):
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")

    if not os.path.exists(run_tracker_path):
        logging.warning(f"Run Tracker file not found at {run_tracker_path}.")
        return None

    latest_row = []

    try:
        with open(run_tracker_path, "r", encoding="utf8") as tracker_file:
            reader = list(csv.DictReader(tracker_file))

        # Filtering and handling rows where Component_Status is not '100%'
        for row in reader:
            if row["Component_Name"].startswith(option_name):
                if row["Component_Status"] != "100%":
                    latest_row.append(row)
                else:
                    # Remove all previous rows when Component_Status is 100%
                    latest_row = []

        # Sorting and fetching data from latest run tracker record
        if latest_row:
            latest_row.sort(key=lambda x: x["Timestamp"], reverse=True)
            global starting_point, total_processed
            starting_point = int(latest_row[0]["Processed"])
            total_processed += starting_point
            logging.info(f"{total_processed} already processed starting from {starting_point + 1}.")
            print(f"\n{total_processed} already processed starting from {starting_point + 1}.\n")
            return latest_row[0]["Run_id"]
        return None
    except Exception as e:
        logging.error(f"Error setting starting point: {e}")
        return None

def fetch_run_id(option_name):

    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")

    if not os.path.exists(run_tracker_path):
        logging.warning(f"Run Master file not found at {run_tracker_path}.")
        return "00"

    run_master_data = []

    try:
        with open(run_tracker_path, "r", newline="", encoding="utf-8") as master_file:
            run_master_data = list(csv.DictReader(master_file))

        if not run_master_data:
            return "00"

        if new_session == "False":
            latest_row = []
            # Filtering and handling rows where Component_Status is not '100%'
            for row in run_master_data:
                if row["Component_Name"].startswith(option_name):
                    if row["Component_Status"] != "100%":
                        latest_row.append(row)
                    else:
                        # Remove all previous rows when Component_Status is 100%
                        latest_row = []
            # Sorting and fetching data from latest run master record
            if latest_row:
                latest_row.sort(key=lambda x: x["Timestamp"], reverse=True)
                run_id = latest_row[0]["Run_id"]
        else:
            run_id = run_master_data[-1]["Run_id"]
        return str(int(run_id)).zfill(2)
    except Exception as e:
        logging.error(f"Error fetching run_id: {e}")
        return "00"


executor_running = False  # Global state flag

# Main function
def main(new_session, input_file=None, customer_id=None, customer_name=None):

    global run_id
    if new_session == "False":
        run_id = set_starting_point("Extended Attributes")
    else:
        run_id = fetch_run_id("Extended Attributes")


    # Configure logging
    base_name = f"Extended_Attributes_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)

    setup_logging(log_file)


    # Detect latest file if no input file provided
    if not input_file:
        input_file = detect_latest_file(output_dir, "Base_Attributes")
        if input_file:
            print(f"Detected latest input file: {input_file}")
            logging.info(f"Detected latest input file: {input_file}")
            while True:  # Loop until valid input is provided
                proceed = input("Do you want to proceed with this file? (y/n or 0 to exit): ").strip().lower()
                if proceed == 'y':
                    break  # Proceed with the detected file
                elif proceed == 'n':
                    input_file = input("Enter the input file path (or type '0' to exit): ").strip()
                    if input_file == '0':
                        print("Returning to main menu...")
                        sys.exit(1)  # Graceful exit to the main menu
                    if not os.path.isfile(input_file):
                        print("The specified file does not exist. Please try again.")
                        logging.error("The specified input file does not exist.")
                    else:
                        break  # Valid file provided by the user
                elif proceed == '0':
                    print("Returning to main menu...")
                    sys.exit(1)  # Graceful exit to the main menu
                else:
                    print("Invalid input. Please enter 'y' for yes, 'n' for no, or '0' to exit.")
        else:
            print("No latest input file detected. Please provide the file path manually.")
            logging.error("No latest input file detected.")
            while True:  # Loop until valid input is provided
                input_file = input("Enter the input file path (or type '0' to exit): ").strip()
                if input_file == '0':
                    print("Returning to main menu...")
                    sys.exit(1)  # Graceful exit to the main menu
                if not os.path.isfile(input_file):
                    print("The specified file does not exist. Please try again.")
                    logging.error("The specified input file does not exist.")
                else:
                    break  # Valid file provided by the user

    logging.info(f"Using input file: {input_file}")

    # Generate naming components for files
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
    db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
    hash_file = handle_files(base_name, "_hash.txt", hashes_dir)

    # Check and update hash before processing
    if not check_and_update_hash(db_file, hash_file):
        logging.info("No updates required. Exiting script.")
        print("Database is up-to-date. Exiting.")
        return


    session = setup_session()
    domains = []


    try:
        with open(input_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains.append(row["Domain"])
        global total_to_process
        total_to_process = len(domains)
        lock = Lock()

        logging.info(f"Total domains to process: {total_to_process}")

        def process_batch_domains(domain_list):
            global executor_running
            results = {}

            executor_running = True
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(process_single_domain, domain): domain for domain in domain_list}

                try:
                    for future in as_completed(futures):
                        domain = futures[future]
                        try:
                            with lock:
                                result = future.result()
                                if result:
                                    results[domain] = result
                                    write_results_to_file([result], input_file, output_file)
                                    insert_results_to_db(db_file, [result])
                        except Exception as e:
                            logging.error(f"Error processing domain {domain}: {e}")
                        finally:
                            with lock:
                                global total_processed
                                total_processed += 1
                                progress_percentage = round((total_processed / total_to_process) * 100, 2)
                                logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")

                except KeyboardInterrupt:
                    logging.warning("KeyboardInterrupt detected. Stopping processing...")
                    executor_running = False
                    raise  # Let signal handler handle logging and exit

            executor_running = False
            return results

        for i in range(starting_point, total_to_process, min(total_to_process, 1000)):
            batch = domains[i: min(i + 1000, total_to_process)]
            batch_result = process_batch_domains(batch)


            logging.info(f"Results written to output file: {output_file}")

        logging.info(f"Total domains processed successfully: {total_to_process}")

        # Update hash file
        update_hash_file(db_file, hash_file)


        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Extended Attributes Detection", run_id, success=True)
        print(f"Script completed successfully! Output File: {output_file}")
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")

        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Extended Attributes Detection",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error in main function: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: extended_attributes.py <customer_id> <customer_name> [<input_file>]")
        input_file = None
        customer_id = input("Enter Customer ID: ")
        customer_name = input("Enter Customer Name: ")
    else:
        customer_id = sys.argv[1]
        customer_name = sys.argv[2]
        input_file = sys.argv[3]
        new_session = sys.argv[4]

    main(new_session, input_file, customer_id, customer_name)
