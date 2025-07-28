import hashlib
import os
import logging
import pandas as pd
import dns.resolver
import sqlite3
from datetime import datetime, timedelta
import sys
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
from threading import Lock
import signal
import platform
 
global total_processed
global total_to_process
global starting_point
total_to_process = 0
total_processed = 0
starting_point = 0

# Initialize global variables
total_processed = 0
total_to_process = 0
progress_data = {
    "last_processed_domain": -1,  # Index in the list
    "last_processed_tld": -1,     # Index in the list
    "total_processed": 0
}

# Add locks for thread-safety
lock = Lock()
db_lock = Lock()  # Database lock

def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Hoarded Domains Checker",
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
        "Hoarded Domains Checker",
        run_id,
        interrupted=True,
        progress=progress,
        error_type="Session Expired"
    )
    print(f"EC2 session expired at {progress}% completion.")
    sys.exit(3)


signal.signal(signal.SIGINT, signal_handler)           # Ctrl+C
if platform.system().lower() == "linux":
    signal.signal(signal.SIGHUP, signal_session_expired)   # EC2 Session expired


# Initialize config parser
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Base directory for current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Paths from Config.ini
input_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'input_dir', fallback='Inputs')))
log_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs')))
output_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs')))
db_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB')))
hashes_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'hashes_dir', fallback='Hashes')))
 
# Ensure directories exist
os.makedirs(input_dir, exist_ok=True)
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)
os.makedirs(db_dir, exist_ok=True)
os.makedirs(hashes_dir, exist_ok=True)  # Ensure HASHES directory exists
 
def ensure_directory_exists(directory):
    """
    Ensures that the given directory exists. If not, it creates the directory.
    """
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Created directory: {directory}")
    else:
        logging.info(f"Directory already exists: {directory}")
 
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
 
# Helper function to compute file hash
def compute_file_hash(file_path):
    """
    Computes the SHA256 hash of a given file.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        logging.warning(f"File not found for hashing: {file_path}")
        return None
 
# Check and update hash logic
def check_and_update_hash(db_file, hash_file):
    """
    Checks the hash of the database file against the stored hash.
    Updates the hash file if the hash has changed.
    """
    current_hash = compute_file_hash(db_file)
    if current_hash is None:
        logging.error("Unable to compute hash; database file not found.")
        return False
 
    # Check if the hash file exists
    if os.path.exists(hash_file):
        with open(hash_file, 'r') as f:
            stored_hash = f.read().strip()
       
        if stored_hash == current_hash:
            logging.info("Database hash matches the stored hash. No updates required.")
            return True
        else:
            logging.info("Database hash differs from the stored hash. Updating...")
    else:
        logging.info("Hash file does not exist. Creating a new hash file...")
 
    # Update or create the hash file
    with open(hash_file, 'w') as f:
        f.write(current_hash)
    logging.info(f"Hash updated in: {hash_file}")
    return False
 
# Update hash file
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash updated in {hash_file}")

 
def ask_for_tld_file():
    """
    Detects or prompts for the TLD file to use.
    """
    # Detect the latest TLD file
    tld_files = [f for f in os.listdir(output_dir) if f.startswith("tld_updater_")]
    if tld_files:
        tld_files.sort(key=lambda f: os.path.getmtime(os.path.join(output_dir, f)), reverse=True)
        latest_tld_file = os.path.join(output_dir, tld_files[0])
 
        # Display detected TLD file (single message)
        print(f"Detected the latest TLD file: {latest_tld_file}")
        logging.info(f"Detected the latest TLD file: {latest_tld_file}")
 
        while True:
            proceed = input("Do you want to use this file? (y/n, or '0' to return to the main menu): ").strip().lower()
            if proceed == 'y':
                return latest_tld_file
            elif proceed == 'n':
                while True:
                    tld_file = input("Enter the path to the TLD file (or '0' to exit): ").strip()
                    if tld_file == '0':
                        print("Returning to the main menu.")
                        logging.info("User exited TLD file selection.")
                        return None
                    if os.path.isfile(tld_file):
                        logging.info(f"User provided TLD file: {tld_file}")
                        return tld_file
                    else:
                        print(f"Error: The file '{tld_file}' does not exist. Please try again.")
                        logging.error(f"User provided non-existent TLD file: {tld_file}")
            elif proceed == '0':
                print("Returning to the main menu.")
                logging.info("User exited TLD file selection.")
                return None
            else:
                print("Invalid input. Please enter 'y' for yes, 'n' for no, or '0' to exit.")
    else:
        # No TLD files detected, prompt for file
        return input("No TLD files detected. Please enter the path to the TLD file (or '0' to exit): ").strip()
 
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
 
# Configure paths for log, output, database, and hash files
def configure_paths(customer_id, customer_name):
    """
    Generates paths for log, output, database, and hash files based on the configuration.
    """
    global run_id
    run_id = fetch_run_id("Hoarded Domains Checker")
    codename = "Hoarded_domains_checker"
    base_name = f"{codename}_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
    db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
    hash_file = os.path.join(hashes_dir, f"{base_name}_hash.txt")  # Save hash file in the HASHES directory
    return log_file, output_file, db_file, hash_file
 
def confirm_or_change_domain_file():
    """
    Asks the user whether to proceed with the detected domain file or specify a new one.
    """
    domain_file = os.path.join(input_dir, "primary_domains.csv")
    if not os.path.exists(domain_file):
        raise FileNotFoundError(f"Domain file not found: {domain_file}")
 
    # Display detected input file (single message)
    print(f"Detected input file: {domain_file}")
    logging.info(f"Detected input file: {domain_file}")
 
    while True:
        proceed = input("Do you want to proceed with this file? (y/n): ").strip().lower()
        if proceed == 'y':
            return domain_file
        elif proceed == 'n':
            while True:
                domain_file = input("Enter the path to the domain file (or '0' to exit): ").strip()
                if domain_file == '0':
                    print("Exiting Hoarded Domains Checker.")
                    logging.info("User exited the Hoarded Domains Checker.")
                    sys.exit(0)
                if os.path.isfile(domain_file):
                    logging.info(f"User provided domain file: {domain_file}")
                    return domain_file
                else:
                    print(f"Error: The file '{domain_file}' does not exist. Please try again.")
                    logging.error(f"User provided non-existent file: {domain_file}")
        else:
            print("Invalid input. Please enter 'y' for yes or 'n' for no.")
 
# Load domain and TLD data
def load_data(domain_file, tld_file):
    """
    Loads domain and TLD data.
    """
    try:
        domains = pd.read_csv(domain_file, header=None)[0].dropna().tolist()
        tlds = pd.read_csv(tld_file, header=None)[0].dropna().tolist()
        logging.info(f"Loaded {len(domains)} domains and {len(tlds)} TLDs.")
        return domains, tlds
    except Exception as e:
        logging.error(f"Error loading input files: {str(e)}")
        raise


def check_dns_records(domain_name):
    """
    Checks DNS records for a domain and logs the types of records it has.
    Logs 'has DNS records' if any are found, otherwise logs 'no DNS records.'
    """
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(check_dns_records, 'connection_lost'):
        return False

    record_types = [
        'A',      # IPv4 address
        'AAAA',   # IPv6 address
        'CNAME',  # Canonical Name
        'MX',     # Mail Exchange
        'NS',     # Name Server
        'SOA',    # Start of Authority
        'TXT',    # Text Records
        'SRV',    # Service Locator
        'PTR',    # Pointer Record (reverse DNS)
    ]

    has_records = False
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            for rdata in answers:
                logging.info(f"Domain {domain_name} has {record_type} record: {rdata}")
                has_records = True
        except Exception:
            pass  # Skip errors and move to the next record type
   
    if not has_records:
        logging.info(f"Domain {domain_name} has no DNS records.")
    return has_records
 
 
def format_time(seconds):
    """
    Converts seconds into a human-readable format (hours, minutes, seconds).
    """
    return str(timedelta(seconds=int(seconds)))
 
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
 
def insert_data_to_db(db_file, data):
    """
    Ensures the database table exists and inserts unique data rows in a batch.
    
    Args:
        db_file (str): Path to the SQLite database
        data (list): List of domains to insert
    """
    if not data:
        return
        
    # Set adapters and converters for datetime objects
    sqlite3.register_adapter(datetime, lambda x: x.isoformat())
    sqlite3.register_converter("timestamp", lambda x: datetime.fromisoformat(x.decode("utf-8")))
 
    with db_lock:  # Use lock to prevent database contention
        try:
            conn = sqlite3.connect(db_file, detect_types=sqlite3.PARSE_DECLTYPES)
            cursor = conn.cursor()
     
            # Create the table if it doesn't exist
            cursor.execute('''CREATE TABLE IF NOT EXISTS domains (
                                domain TEXT PRIMARY KEY,
                                checked_at TIMESTAMP
                            )''')
            
            # Find domains that don't already exist in the database
            existing_domains = set()
            cursor.execute("SELECT domain FROM domains")
            for row in cursor.fetchall():
                existing_domains.add(row[0])
                
            new_domains = [(domain, datetime.now()) for domain in data if domain not in existing_domains]
            
            if new_domains:
                # Batch insert new domains
                cursor.executemany("INSERT INTO domains (domain, checked_at) VALUES (?, ?)", new_domains)
                    
            conn.commit()
            conn.close()
            if new_domains:
                logging.info(f"Inserted {len(new_domains)} new domains into the database in a batch.")
        except Exception as e:
            logging.error(f"Error updating database: {e}")
 
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
 
def append_to_file(output_file, data):
    """Append data to a file without overwriting existing results."""
    headers = ["Run_id", "Customer_id", "Timestamp", "Domain"]
    
    # Add additional columns to the data
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_id = fetch_run_id("Hoarded Domains Checker")
    data_to_append = [{
        "Run_id": str(int(run_id)).zfill(2),
        "Customer_id": customer_id,
        "Timestamp": timestamp,
        "Domain": domain
    } for domain in data]

    # Check if the output file exists
    file_exists = os.path.exists(output_file)
    
    # Append to file in append mode
    with open(output_file, 'a', newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        
        # Write headers only if the file does not already exist or empty
        if not file_exists or os.path.getsize(output_file) == 0:
            writer.writeheader()
        
        existing_rows = remove_duplicates(output_file) if os.path.exists(output_file) else []
        new_data = [row for row in data_to_append if row["Domain"] not in {d["Domain"] for d in existing_rows}]
        
        # Write rows to the file
        writer.writerows(new_data)
        
    
    # logging.info(f"Appended {len(data_to_append)} rows to {output_file}.")


def generate_tld_swaps(domains, tlds, output_file, db_file):
    """
    Generate TLD swap variations and check which ones exist.
    """
    lock = Lock()
 
    global total_processed
    total_processed = 0
    
    # Load progress from temp file or initialize
    if new_session == "False" and os.path.exists("hoarded_temp.json"):
        with open("hoarded_temp.json", 'r') as f:
            progress_data = json.load(f)
            total_processed = progress_data["total_processed"]
    else:
        progress_data = {
            "last_processed_domain": -1,
            "last_processed_tld": -1,
            "total_processed": 0
        }
    
    def save_progress():
        """Save progress data to the temp file."""
        with open("hoarded_temp.json", 'w') as f:
            json.dump(progress_data, f, indent=4)
    
    # Calculate the total permutations to process
    global total_to_process # For full TLD swaps
    total_to_process = len(tlds) * sum(max(len(dom.split(".")), 1) for dom in domains) # For single TLD swaps
    
    def process_domain(domain, start_tld=0):
        results = []
        tld_variations = []
 
        def generate_tld_variations(domain_parts, tld_list):
            base_name = domain_parts[0]
            tld_parts = domain_parts[1:]
 
            # Full TLD replacement
            for tld in tld_list:
                yield f"{base_name}.{tld}"
 
            # Single TLD replacement
            seen_combinations = set()  # To track unique combinations
            for i in range(len(tld_parts)):
                for tld in tld_list:
                    new_tld_parts = tld_parts[:i] + [tld] + tld_parts[i + 1:]
                    new_combination = f"{base_name}.{'.'.join(new_tld_parts)}"
                    if new_combination not in seen_combinations:
                        seen_combinations.add(new_combination)
                        yield new_combination
    
        domain_parts = domain.split('.')
        tld_variations = list(generate_tld_variations(domain_parts, tlds))

        # Resume from the last processed TLD for this domain
        tld_variations = tld_variations[start_tld:]
 
        def process_tld_variation(swapped_domain):
            if check_dns_records(swapped_domain):
                append_to_file(output_file, [swapped_domain])  # Append instead of overwriting
                insert_data_to_db(db_file, [swapped_domain])
                return swapped_domain
            return None
 
        # Use batch processing for database operations
        valid_domains_batch = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(process_tld_variation, tld) for tld in tld_variations]
            for idx, future in enumerate(as_completed(futures), start=start_tld):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        valid_domains_batch.append(result)
                        
                        # Process in batches to reduce database lock frequency
                        if len(valid_domains_batch) >= 50:  # Configurable batch size
                            insert_data_to_db(db_file, valid_domains_batch)
                            valid_domains_batch.clear()
                except Exception as e:
                    logging.error(f"Error processing TLD variation for {domain}: {e}")
                finally:
                    with lock:
                        global total_processed
                        total_processed += 1
                        progress_data["last_processed_tld"] = idx
                        progress_data["total_processed"] = total_processed
                        progress_percentage = round((total_processed / total_to_process) * 100, 2)
                        logging.info(f"Processed {total_processed}/{total_to_process} swaps ({progress_percentage}%).")
                        save_progress()
        
        # Process any remaining domains in the batch
        if valid_domains_batch:
            insert_data_to_db(db_file, valid_domains_batch)
            
        return results
 
    # Ensure existing results are not overwritten
    if not os.path.exists(output_file):
        open(output_file, 'w').close()
    
    # Start from the last processed domain and TLD
    if new_session == "False":
        start_domain_index = progress_data["last_processed_domain"] + 1
    else:
        start_domain_index = 0
    
    all_results = []
    for idx, domain in enumerate(domains[start_domain_index:], start=start_domain_index):
        
        logging.info(f"Processing domain: {domain}")
        start_tld_index = 0 if idx != progress_data["last_processed_domain"] else progress_data["last_processed_tld"] + 1
        all_results.extend(process_domain(domain, start_tld_index))
        
        # Update progress after processing each domain
        progress_data["last_processed_domain"] = idx
        save_progress()
    
    
    # Clean up temp file after completion
    os.remove("hoarded_temp.json")
 
    logging.info(f"Total TLD swaps processed: {total_processed}/{total_to_process}.")
 
 
def integrate_log_updates(option_name, run_id, success=False, interrupted=False, progress=0, error_type=None):
    """
    Updates Run_Master.csv and Run_Tracker.csv with process status.
 
    Parameters:
        option_name (str): The name of the task (e.g., "Hoarded Domains Checker").
        success (bool): Whether the execution was successful.
        interrupted (bool): Whether the execution was interrupted.
        progress (float): The percentage completion at the time of interruption.
        error_type (str): The type of error that occurred.
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
 
def main(customer_id, customer_name, new_session):
    """
    Main execution function for the Hoarded Domains Checker.
    """
    log_file, output_file, db_file, hash_file = configure_paths(customer_id, customer_name)
    setup_logging(log_file)
 
    try:
        domain_file = confirm_or_change_domain_file()
        tld_file = ask_for_tld_file()
       
 
        if check_and_update_hash(db_file, hash_file):
            logging.info("Database is up to date. Exiting without processing.")
            return
 
        domains, tlds = load_data(domain_file, tld_file)
        global total_to_process
        total_to_process = len(domains) * len(tlds)
 
        global run_id
        if new_session == "False":
            run_id = set_starting_point("Hoarded Domains Checker")
        else:
            run_id = fetch_run_id("Hoarded Domains Checker")
 
        logging.info("Generating TLD swaps...")
 
        generate_tld_swaps(domains, tlds, output_file, db_file)

        update_hash_file(db_file, hash_file)
 
        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Hoarded Domains Checker", run_id, success=True)
 
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
   
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Hoarded Domains Checker",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
   
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
 
 
# Wrapper integration
if __name__ == "__main__":
    # if len(sys.argv) < 4:
    if len(sys.argv) < 4:
        sys.exit("Error: Missing arguments. Ensure this script is invoked programmatically by the wrapper.")
    else:
        customer_id = sys.argv[1]
        customer_name = sys.argv[2]
        new_session = sys.argv[3]
        main(customer_id, customer_name, new_session)
