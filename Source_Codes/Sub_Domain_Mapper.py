import requests
import json
import logging
import os
import sqlite3
import argparse
import csv
import configparser
import time
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor
import math
from threading import Lock
import sys
import pandas as pd
import signal
import platform

global total_processed
global total_to_process
global starting_point
total_processed = 0
total_to_process = 0
starting_point = 0

# Add a database lock
db_lock = Lock()

def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Sub Domain Mapper",
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
        "Sub Domain Mapper",
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
# Helper function to compute file hash
def compute_file_hash(file_path):
    """Compute the SHA-256 hash of a file."""
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
# Function to check and update hash
def check_and_update_hash(db_file, hash_file):
    """Check if the database file has changed by comparing its hash."""
    if not os.path.exists(db_file):
        logging.info("Database file does not exist. Assuming updates are needed.")
        return True
 
    if not os.path.exists(hash_file):
        logging.info("Hash file does not exist. Assuming updates are needed.")
        return True
 
    # Compute current hash
    current_hash = compute_file_hash(db_file)
 
    # Compare with stored hash
    with open(hash_file, "r") as hf:
        stored_hash = hf.read().strip()
 
    if current_hash != stored_hash:
        logging.info("Database hash mismatch. Updates are required.")
        return True
    else:
        logging.info("Database hash matches. No updates needed.")
        return False
 
# Function to update hash file
def update_hash_file(db_file, hash_file):
    """Update the hash file with the current hash of the database."""
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash file updated: {hash_file}")
 
 
 
# Ensure directory exists function
def ensure_directory_exists(path):
    """Ensure the directory exists; create it if it doesn't."""
    logging.debug(f"Directory verified: {path}")
    if not os.path.exists(path):
        os.makedirs(path)
 
# Read configuration from Config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Get base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Paths from config.ini
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
 
 
# Ensure the required directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hash_dir)

def initialize_run_files(input_dir):
    """
    Ensure Run_Master.csv and Run_Tracker.csv exist with proper headers.
    """
    run_master_path = os.path.join(input_dir, "Run_Master.csv")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")

    if not os.path.exists(run_master_path):
        with open(run_master_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Run_ID", "Customer_ID", "Customer_Name", "Timestamp", "Component_Name", "Component_Status"])

    if not os.path.exists(run_tracker_path):
        with open(run_tracker_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Run_ID", "Customer_ID", "Customer_Name", "Timestamp", "Component_Name", "Completion_Percentage"])

    return run_master_path, run_tracker_path

# Handle files
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
        if file_type in [".log", ".csv"]:
            open(new_file_path, 'a').close()
        logging.info(f"Created new file: {new_file_path}")
        return new_file_path
 
# Set up logging
def setup_logging(customer_id, customer_name):
    """Sets up logging with customer details in the filename."""
    base_name = f"Sub_Domain_Mapper_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)
 
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
 
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
        logging.FileHandler(log_file, mode='a', encoding='utf-8')  # Only log to file
        ]
    )
    logging.info("Logging system initialized.")
    return log_file
 
# Initialize database
def init_db(db_file):
    """Initialize the database for storing subdomains."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            primary_domain TEXT,
            subdomain TEXT,
            UNIQUE(primary_domain, subdomain)
        )
    ''')
    conn.commit()
    conn.close()

def get_subdomains(domain):
    """Fetches subdomains from crt.sh with retry logic on HTTP 429."""
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(get_subdomains, 'connection_lost'):
        return None

    url = f'https://crt.sh/?q={domain}&output=json'
    retries = 5
    backoff_factor = 2
    for i in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                cert_data = json.loads(response.text)
                subdomains = set()
                for entry in cert_data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.splitlines():
                        if subdomain.endswith(f'.{domain}') and not subdomain.startswith('*'):
                            subdomains.add(subdomain)
                return list(subdomains) if subdomains else None
            elif response.status_code == 429:
                logging.warning(f"Rate limited by crt.sh for {domain}. Retrying after {backoff_factor ** i} seconds.")
                time.sleep(backoff_factor ** i)
            else:
                logging.error(f"Failed to fetch subdomains for {domain}. HTTP Status: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Exception while fetching subdomains for {domain}: {e}")
            return None
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


def write_to_csv(output_file, domain, subdomains):
    """Write subdomains to CSV file."""
    # Convert single string to list if needed
    if isinstance(subdomains, str):
        subdomains = [subdomains]

    headers = ["Run_id", "Customer_id", "Timestamp", "Domain", "Subdomain"]
    lock = Lock()

    with lock:
        try:
            # Check if file exists
            file_exists = os.path.exists(output_file)
            
            # Get run ID and timestamp
            run_id = fetch_run_id("Sub Domain Mapper")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Track seen domain-subdomain pairs
            seen_pairs = set()
            if file_exists:
                with open(output_file, 'r', newline='', encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        seen_pairs.add((row["Domain"], row["Subdomain"]))
            
            # Open file in append mode
            with open(output_file, 'a', newline='', encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                
                # Write header if file doesn't exist
                if not file_exists or os.path.getsize(output_file) == 0:
                    writer.writeheader()
                
                # Write each unique subdomain
                for subdomain in subdomains:
                    if (domain, subdomain) not in seen_pairs:
                        writer.writerow({
                            "Run_id": str(int(run_id)).zfill(2),
                            "Customer_id": customer_id,
                            "Timestamp": timestamp,
                            "Domain": domain,
                            "Subdomain": subdomain
                        })
                        seen_pairs.add((domain, subdomain))
                    
        except Exception as e:
            logging.error(f"Error writing to CSV: {e}")

def batch_insert_to_db(db_file, domain_subdomains_list):
    """
    Insert multiple domain-subdomain pairs into the database in a single transaction.
    
    Args:
        db_file (str): Path to the SQLite database
        domain_subdomains_list (list): List of tuples (domain, subdomain_list)
    """
    if not domain_subdomains_list:
        return
        
    with db_lock:
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Create table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    subdomain TEXT,
                    UNIQUE(domain, subdomain)
                )
            ''')
            
            # Prepare data for batch insertion
            all_pairs = []
            for domain, subdomains in domain_subdomains_list:
                for subdomain in subdomains:
                    all_pairs.append((domain, subdomain))
            
            # Batch insert using executemany
            cursor.executemany('''
                INSERT OR IGNORE INTO subdomains (domain, subdomain)
                VALUES (?, ?)
            ''', all_pairs)
            
            conn.commit()
            logging.info(f"Batch inserted {len(all_pairs)} domain-subdomain pairs into the database")
        except Exception as e:
            logging.error(f"Error batch inserting to database: {e}")
        finally:
            conn.close()

def process_files_in_batch(input_hoarded_file, input_variation_file, input_name_split_file, output_file, db_file):
    lock = Lock()
    all_domains = []

    try:
        hoarded_domains = load_domains(input_hoarded_file, "Hoarded Domains")
        variation_domains = load_domains(input_variation_file, "Name Variations Domains")
        name_split_domains = load_domains(input_name_split_file, "Name Split Domains")
        
        all_domains = hoarded_domains + variation_domains + name_split_domains

        batch_size = 1000
        
        global total_to_process
        total_to_process = len(all_domains)
        total_batches = math.ceil(total_to_process / batch_size)

        logging.info(f"Total domains to process: {total_to_process}")
        
        def process_domain(domain_list):
            # Collect domain-subdomain pairs for batch database insertion
            domain_subdomains_batch = []
            batch_size_db = 50  # Number of domain-subdomain pairs to collect before inserting
            
            # Parallel processing
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(get_subdomains, domain): domain for domain in domain_list}

                for future in futures:
                    domain = futures[future]
                    try:
                        subdomains = future.result()
                        if subdomains:
                            write_to_csv(output_file, domain, subdomains)
                            domain_subdomains_batch.append((domain, subdomains))
                        else:
                            write_to_csv(output_file, domain, ["No subdomain"])
                            domain_subdomains_batch.append((domain, ["No subdomain"]))
                            
                        # Process database updates in batches
                        if len(domain_subdomains_batch) >= batch_size_db:
                            batch_insert_to_db(db_file, domain_subdomains_batch)
                            domain_subdomains_batch.clear()
                            
                    except Exception as e:
                        logging.error(f"Error processing domain {domain}: {e}")
                        continue

                    with lock:
                        global total_processed
                        total_processed += 1
                        progress = round((total_processed / total_to_process) * 100, 2)

                        # Log progress and update tracker
                        logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress}%).")

            # Process any remaining domain-subdomain pairs
            if domain_subdomains_batch:
                batch_insert_to_db(db_file, domain_subdomains_batch)


        # Process each batch of domains
        for i in range(starting_point, len(all_domains), batch_size):
            batch = all_domains[i:i + batch_size]
            logging.info(f"Processing batch {i // batch_size + 1}/{total_batches} with {len(batch)} domains.")

            process_domain(batch)
            
    except Exception as e:
        logging.error(f"Error processing domains: {e}")

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
                run_master_data = list(csv.DictReader(master_file))

        # Use run_id from the last row if data exists
        if run_master_data:
            last_row = run_master_data[-1]
            _run_id = run_id or last_row["Run_id"]  # Keep the same run_id as the last row

            # Calculate completion time if the operation is successful
            start_timestamp_str = None
            if success:
                run_master_data.sort(key=lambda x: x["Timestamp"], reverse=True)
                for run in run_master_data:
                    if run["Component_Name"] == "":
                        start_timestamp_str = run["Timestamp"]
                        break
                    
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

def load_domains(input_file, label=""):
    domains = set()
    
    logging.info(f"Reading {label} file: {input_file}")
    try:
        with open(input_file, 'r', encoding="utf8") as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                domain = row.get('Domain')
                if domain:
                    domains.add(domain)
    except FileNotFoundError:
        print(f"File not found: {input_file}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")
    return list(domains)
 
def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator and Updater")
    parser.add_argument('hoarded_domains_checker', type=str, help='The hoarded domains file')
    parser.add_argument('name_variation_domain_generator', type=str, help='The name variations file')
    parser.add_argument('name_split_detection', type=str, help='The name split file')
    parser.add_argument('customer_id', type=str, help='Customer ID')
    parser.add_argument('customer_name', type=str, help='Customer Name')
    parser.add_argument('new_session', type=str, help="Start new session")

    args = parser.parse_args()
    
    global run_id
    global new_session
    new_session = args.new_session
    
    if new_session == "False":
        run_id = set_starting_point("Sub Domain Mapper")
    else:
        run_id = fetch_run_id("Sub Domain Mapper")
        

    base_name = f"Sub_Domain_Mapper_{args.customer_name}_{args.customer_id}"
    db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
    hash_file = handle_files(f"{base_name}", "_hash.txt", hash_dir)

    setup_logging(args.customer_id, args.customer_name)
    global customer_id
    global customer_name
    customer_id = args.customer_id
    customer_name = args.customer_name
    

    if not check_and_update_hash(db_file, hash_file):
        return
    try:
        init_db(db_file)

        # Read the total domains to process for progress tracking
        total_domains = []
        for file_path in [args.hoarded_domains_checker, args.name_variation_domain_generator, args.name_split_detection]:
            with open(file_path, 'r') as f:
                total_domains.extend(line.strip() for i, line in enumerate(f) if i > 0 and line.strip())

        
        # Process the files in batch
        process_files_in_batch(
            args.hoarded_domains_checker,
            args.name_variation_domain_generator,
            args.name_split_detection,
            output_file,
            db_file,
        )
        
        update_hash_file(db_file, hash_file)

        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Sub Domain Mapper", run_id, success=True)
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
    
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Sub Domain Mapper",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")


if __name__ == '__main__':
    main()
