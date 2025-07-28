import os
import platform
import sys
import io
import contextlib
from datetime import datetime
import whois
import configparser
import logging
import ssl
import sqlite3
import csv
from urllib3 import PoolManager
from itertools import islice
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import socket
import io
import contextlib
import signal


global total_processed
global starting_point
total_processed = 0
starting_point = 0

def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Analytical Attributes Detection",
        run_id,
        interrupted=True,
        progress=progress,
        error_type="Keyboard Interrupt"
    )
    print(f"Execution interrupted at {progress}% completion.")
    sys.exit(1)

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
        "Analytical Attributes Detection",
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
# Initialize config parser
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'Config', 'Config.ini'), encoding="utf8")
 
# Configure SSL to allow legacy renegotiation
ssl_context = ssl.create_default_context()
try:
    ssl_context.options |= ssl.OP_LEGACY_SERVER_CONNECT  # Optional, can be skipped for newer Python versions
except AttributeError:
    pass  # Fall back to default SSL context if OP_LEGACY_SERVER_CONNECT is not available
 
# Initialize PoolManager with the SSL context
http = PoolManager(ssl_context=ssl_context)
 
# Ensure a directory exists
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Set up logging
def setup_logging(log_file):
    """
    Sets up logging for the script.
    """
    try:
        # Ensure directory exists for logs
        ensure_directory_exists(os.path.dirname(log_file))
       
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, mode='a', encoding='utf-8')  # Only log to file
            ]
        )
        logging.info("Logging initialized and active.")  # Test log
        logging.getLogger('whois').setLevel(logging.CRITICAL)
    except Exception as e:
        print(f"Error initializing logging: {e}")
        sys.exit(1)
 
# Helper function to compute file hash
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
# Check and update hash
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
    
# Update hash file
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash updated in {hash_file}")

 
 
# Handle file initialization and timestamp updates
def handle_files(base_name, file_type, directory):
    """
    Handle file initialization and timestamp updates for log, output, and DB files.
    """
    ensure_directory_exists(directory)
    existing_files = [
        f for f in os.listdir(directory) if base_name in f and f.endswith(file_type)
    ]
    if existing_files:
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = existing_files[0]
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        old_file_path = os.path.join(directory, latest_file)
        new_file_path = os.path.join(directory, new_file_name)
        os.rename(old_file_path, new_file_path)
        logging.info(f"Updated file timestamp: {new_file_path}")
        return new_file_path
    else:
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        new_file_path = os.path.join(directory, new_file_name)
        if file_type == ".log":
            open(new_file_path, 'a').close()
        logging.info(f"Created new file: {new_file_path}")
        return new_file_path
 
# Generate consistent file paths
def generate_file_paths(customer_id, customer_name, log_dir, output_dir, db_dir, hash_dir):
    codename = "Analytical_Attributes"
    base_name = f"{codename}_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
    db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
    hash_file = os.path.join(hash_dir, f"{base_name}_db_hash.txt")  # Ensure hash_file uses hash_dir
    return log_file, output_file, db_file, hash_file
 
 
 
 
# Initialize the database
def initialize_database(db_file):
    ensure_directory_exists(os.path.dirname(db_file))
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                blacklisted TEXT,
                age_of_registration TEXT,
                directory_listing TEXT
            )
        ''')
        conn.commit()
 
 
 
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
 
# Directory listing checker
def check_directory_listing(domain):
    url = f"https://{domain}/"
    try:
        response = http.request('GET', url, timeout=10)
        if response.status == 200:
            html_content = response.data.decode('utf-8', errors='ignore')
            return "Yes" if "Index of /" in html_content else "No"
        else:
            return "No"
    except Exception as e:
        logging.error(f"Error checking directory listing for {domain}: {e}")
        return "Not Listed"
 
# WHOIS information
 
def get_whois_info(domain):
    """
    Retrieve WHOIS information for a given domain.
    """
    try:
        # Redirect `stderr` to prevent output in the terminal
        with io.StringIO() as buf, contextlib.redirect_stderr(buf):
            whois_info = whois.whois(domain)
 
        # Process the WHOIS data
        reg_date = whois_info.creation_date
        if not reg_date:
            return "Null"
 
        if isinstance(reg_date, list):
            reg_date = reg_date[0]
 
        if not isinstance(reg_date, datetime):
            reg_date = datetime.strptime(str(reg_date), "%Y-%m-%d %H:%M:%S")
 
        # Calculate the age of registration
        age = datetime.now() - reg_date
        years = age.days // 365
        months = (age.days % 365) // 30
 
        return f"{years} years" if years else f"{months} months"
    except Exception as e:
        # Log the error instead of printing it
        logging.error(f"Error querying WHOIS for {domain}: {e}")
        return "unknown"
 
 
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Update check_blacklist_dnsbl to include connection check
def check_blacklist_dnsbl(domain):
    """
    Check if a domain is blacklisted in any of the given DNSBLs.
    """
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(check_blacklist_dnsbl, 'connection_lost'):
        return "Error"

    # Rest of the existing check_blacklist_dnsbl function...
    raw_dnsbls = config.get("DNSBLS", "dnsbl_list")
    dnsbls = [dnsbl.strip() for dnsbl in raw_dnsbls.split(",")]
    
    dnsbl_lock = Lock()
    max_retries = 2
    attempt = 0
    
    while attempt < max_retries:
        try:
            with dnsbl_lock:
                for dnsbl in dnsbls:
                    query = f"{domain}.{dnsbl}"
                    try:
                        socket.gethostbyname(query)  # Query the DNSBL
                        logging.info(f"{domain} is blacklisted by {dnsbl}.")
                        return "Yes"
                    except socket.gaierror:
                        # Not blacklisted in this DNSBL
                        pass
                    
                    return "No"  # Not blacklisted in any DNSBLs
        
            attempt += 1
            logging.warning(f"Retrying query for {domain}... Attempt {attempt} of {max_retries}")
            time.sleep(5)  # Wait before retrying
        except Exception as e:
            logging.error(f"Error querying DNSBLs for {domain}: {e}")
            return "Error"
    
    logging.error("Max retries reached. Could not complete the DNSBL queries.")
    return "Null"

# Read domains from file
def read_domains_from_file(input_file):
    """
    Read and clean domains from the input file.
    """
    domains = []
    try:
        with open(input_file, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains.append(row["Domain"])
        return domains
    except Exception as e:
        logging.error(f"Error reading input file {input_file}: {e}")
        return []


lock = Lock()

# Process domains in batches
def process_domain(domain, db_file):
    """
    Process a single domain and return the result, without writing to the database.
    """
    domain = domain.strip()
    if not domain:
        return None  # Skip empty domains

    # Check if domain is already processed
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM domain_info WHERE domain = ?", (domain,))
        if cursor.fetchone():
            return None

    # Fetch details for the domain
    blacklist_status = check_blacklist_dnsbl(domain)
    registration_age = get_whois_info(domain)
    directory_listing = check_directory_listing(domain)

    result = {
    "Domain": domain,
    "Blacklisted": blacklist_status,
    "Age of Registration": registration_age,
    "Directory Listing": directory_listing,
    }

    return result

def batch_insert_into_db(results, db_file):
    """
    Insert multiple domain results into the database in a single transaction.
    
    Args:
        results (list): List of domain results to insert.
        db_file (str): Path to the SQLite database file.
    """
    db_lock = Lock()
    if not results:
        return
        
    with db_lock:  # Use lock to prevent database contention
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Insert data into the database in a single batch
            cursor.executemany('''
                INSERT OR IGNORE INTO domain_info 
                (domain, blacklisted, age_of_registration, directory_listing)
                VALUES (?, ?, ?, ?)''', 
                [(r["Domain"], r["Blacklisted"], r["Age of Registration"], r["Directory Listing"]) 
                 for r in results])

            conn.commit()
            conn.close()
            logging.info(f"Database updated with {len(results)} domains.")
        except Exception as e:
            logging.error(f"Error updating database {db_file}: {e}")

def process_domains_in_batches(domains, db_file, input_file, output_file):
    """
    Process a list of domains in batches using multithreading.
    """
    global total_to_process
    total_to_process = len(domains)
    logging.info(f"Total domains to process: {total_to_process}")
       
    # Use ThreadPoolExecutor for concurrent processing
    def process_batch_domain(domain_list):
        result_counter = 0
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = { executor.submit(process_domain, domain, db_file): domain for domain in domain_list}
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        result_counter += 1
                        batch_insert_into_db([result], db_file)
                        write_results_to_file([result], input_file, output_file)
                except Exception as e:
                    logging.error(f"Error processing domain {domain}: {e}")

                finally:
                    with lock:
                        global total_processed
                        total_processed = total_processed + 1
                        progress_percentage = round((total_processed / total_to_process) * 100, 2)
                        logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")
                        
            return result_counter
   
    for i in range(starting_point, total_to_process, min(total_to_process, 1000)):
        batch = domains[i: min(i + 1000, total_to_process)]
        batch_result = process_batch_domain(batch)

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


# Write results to file
def write_results_to_file(results, input_file, output_file):
    headers = ["Blacklisted", "Age of Registration", "Directory Listing"]

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
                        "Name Server": row.get("Name Server"),
                        "Mail Server": row.get("Mail Server"),
                        "Registrar": row.get("Registrar"),
                        "Registrant": row.get("Registrant"),
                        "Registered Address": row.get("Registered Address"),
                        "Registration Country": row.get("Registration Country"),
                        "Registration Date": row.get("Registration Date"),
                        "Remarks": row.get("Remarks"),
                        'Website': row.get("Website"),
                        "IP Address": row.get("IP Address"),
                        "Redirection": row.get("Redirection"),
                        "Login Page": row.get("Login Page"),
                        "Port": row.get("Port"),
                        "SSL": row.get("SSL"),
                        "Blacklisted": matched_data.get("Blacklisted", "No"),
                        "Age of Registration": matched_data.get("Age of Registration", "Null"),
                        "Directory Listing": matched_data.get("Directory Listing", "Not Listed"),
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



def integrate_log_updates(option_name, run_id, success=False, interrupted=False, progress=0, error_type=None):
    """
    Updates Run_Master.csv and Run_Tracker.csv with process status.

    Parameters:
        option_name (str): The name of the task (e.g., "Hoarded Domains Checker").
        success (bool): Whether the execution was successful.
        interrupted (bool): Whether the execution was interrupted.
        progress (float): The percentage completion at the time of interruption.
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


# Main function
def main(new_session, input_file=None, customer_id=None, customer_name=None):
    try:
        
        global run_id
        if new_session == "False":
            run_id = set_starting_point("Analytical Attributes")
        else:
            run_id = fetch_run_id("Analytical Attributes")
        
        
        # Directories from Config.ini
        base_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
        output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
        db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
        hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
        log_file, output_file, db_file, hash_file = generate_file_paths(customer_id, customer_name, log_dir, output_dir, db_dir, hash_dir)
    
        # Update logging to use the actual log file
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        setup_logging(log_file)
        
        logging.info("Script started.")
        logging.info(f"Customer ID: {customer_id}, Customer Name: {customer_name}")

        if not input_file:
            input_file = detect_latest_file(output_dir, "Extended_Attributes")
            if input_file:
                print(f"Detected latest input file: {input_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        input_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if input_file == '0':
                            print("Exiting...")
                            sys.exit(1)
                        elif os.path.isfile(input_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        sys.exit(1)
        
        # Check and update hash
        if check_and_update_hash(db_file, hash_file):
            initialize_database(db_file)
    
            # After updates, save the new hash
            new_hash = compute_file_hash(db_file)
            with open(hash_file, "w") as hf:
                hf.write(new_hash)
        
        initialize_database(db_file)
        domains = read_domains_from_file(input_file)
        
        
        process_domains_in_batches(domains, db_file, input_file, output_file)

        update_hash_file(db_file, hash_file)

        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Analytical Attributes Detection", run_id, success=True)
        logging.info(f"Processing completed! Log File: {log_file}, Output File: {output_file}")
        
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
    
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Analytical Attributes Detection",
            run_id,
            interrupted=True,
            progress=progress,
            error_type="Keyboard Interrupt"
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}") 
    
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python Analytical_Attributes.py <customer_id> <customer_name>")
        sys.exit(1)
 
    customer_id = sys.argv[1]
    customer_name = sys.argv[2]
    new_session = sys.argv[3]
    main(new_session, customer_id=customer_id, customer_name=customer_name)
 