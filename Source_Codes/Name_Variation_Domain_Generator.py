import os
import logging
import platform
import sqlite3
import hashlib
import csv
import configparser
import sys
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import signal

global total_processed
global total_to_process
global starting_point
total_processed = 0
total_to_process = 0
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
        "Name Variation Domain Generator",
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
        "Name Variation Domain Generator",
        run_id,
        interrupted=True,
        progress=progress,
        error_type="Session Expired"
    )
    print(f"EC2 session expired at {progress}% completion.")
    sys.exit(3)

# Add signal handlers after the global variables
signal.signal(signal.SIGINT, signal_handler)           # Ctrl+C
if platform.system().lower() == "linux":
    signal.signal(signal.SIGHUP, signal_session_expired)   # EC2 Session expired

# Ensure directory exists function
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Compute file hash with additional safeguards
def compute_file_hash(file_path):
    """Compute the SHA-256 hash of a file."""
    if not os.path.exists(file_path):
        return ""
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    logging.info(f"Computed hash for {file_path} at {datetime.now().isoformat()}")
    return hash_func.hexdigest()


def check_and_update_hash(db_file, hash_file):
    if not os.path.exists(db_file) or not os.path.exists(hash_file):
        logging.info("Database file or hash file does not exist; updates are needed.")
        return True
 
    current_hash = compute_file_hash(db_file)
    with open(hash_file, "r") as hf:
        stored_hash = hf.read().strip()
 
    if current_hash != stored_hash:
        logging.info("Database has changed. Updates are needed.")
        return True
    else:
        logging.info("Database has not changed. No updates required.")
        return False

# Update hash file
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash updated in {hash_file}")
 
# Load the hash from a file
def load_hash(hash_file):
    """Load the previous hash from a hash file."""
    if os.path.exists(hash_file):
        with open(hash_file, 'r') as f:
            hash_value = f.read().strip()
        logging.info(f"Loaded hash from {hash_file} at {datetime.now().isoformat()}")
        return hash_value
    return None
 
def save_hash(hash_file, file_hash):
    """Save the new hash to the hash file."""
    with open(hash_file, 'w') as f:
        f.write(file_hash)
    logging.info(f"Saved hash to {hash_file} at {datetime.now().isoformat()}")
 
# Read configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Directory paths from Config.ini
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
 
# Ensure directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hash_dir)
 
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
 
## Handle file initialization and timestamp updates
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

def load_domains(input_file, label=""):
    variations = set()
    
    logging.info(f"Reading {label} file: {input_file}")
    try:
        with open(input_file, 'r', encoding="utf8") as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                domain = row.get('Variation')
                if domain:
                    variations.add(domain)
    except FileNotFoundError:
        print(f"File not found: {input_file}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")
    return list(variations)

# Load lines from a file
def load_lines_from_file(file_path):
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, 'r') as file:
        lines = [line.strip() for line in file if line.strip()]
    if not lines:
        logging.error(f"File is empty: {file_path}")
        raise ValueError(f"File is empty: {file_path}")
    return lines
 
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
    
    # if not has_records:
        # logging.info(f"Domain {domain_name} has no DNS records.")
    return has_records

def domain_exists_parallel(domain_list, output_file, db_file, output_hash_file, db_hash_file):
    """Check if domains exist in parallel."""
    results = {}
    domain_lock = Lock()
    batch_size = 10  # Configurable batch size for database operations
    valid_domains_batch = []
    last_logged_progress = -1
    
    def process_domain(domain):
        if check_dns_records(domain):
            # Instead of immediately updating database, collect for batch processing
            return domain
        return None
    
    def process_valid_domains_batch():
        if valid_domains_batch:
            # Update output file and database with valid domains in a batch
            append_to_csv(output_file, output_hash_file, valid_domains_batch)
            insert_combinations_into_db(db_file, db_hash_file, valid_domains_batch)
            valid_domains_batch.clear()
    
    with ThreadPoolExecutor(max_workers=150) as executor:  # Adjust max_workers based on your system's capabilities
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domain_list}
        for future in as_completed(future_to_domain):
            try:
                domain = future.result()
                if domain:
                    # logging.info(f"Valid domain: {domain}")
                    results[domain] = True
                    
                    with domain_lock:
                        valid_domains_batch.append(domain)
                        # Process in batches to reduce database lock frequency
                        # if len(valid_domains_batch) >= batch_size:
                        process_valid_domains_batch()
            except Exception as e:
                    logging.error(f"Error processing {future_to_domain[future]}: {e}")
            finally:
                with domain_lock:
                    global total_processed
                    total_processed = total_processed + 1
                    progress_percentage = round((total_processed / total_to_process) * 100, 2)
                    if progress_percentage % 5 == 0 and progress_percentage != last_logged_progress:
                        last_logged_progress = progress_percentage
                        logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")
    
    # Process any remaining domains in the batch
    with domain_lock:
        process_valid_domains_batch()
        
    return results
 
 
 
# Generate combinations of name variations with TLDs
def generate_combinations_multithreaded(name_variations, tlds, output_file, db_file, output_hash_file, db_hash_file):
    if not name_variations or not tlds:
        logging.error("Name variations or TLDs are empty.")
        raise ValueError("Name variations or TLDs cannot be empty.")
    
 
    valid_combinations = []
    all_combinations = [name + "." + tld for name in name_variations for tld in tlds]
    global total_to_process
    total_to_process = len(all_combinations)
    logging.info(f"Total domains to process: {total_to_process}")
   
    # Divide combinations into batches for multithreading
    for i in range(starting_point, len(all_combinations), 1000):
        batch = all_combinations[i:i + 1000]
       
        batch_results = domain_exists_parallel(batch, output_file, db_file, output_hash_file, db_hash_file)
        valid_domains = [domain for domain, exists in batch_results.items() if exists]
        valid_combinations.extend(valid_domains)
 
    return valid_combinations

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

# Append new combinations to the CSV file
def append_to_csv(output_file, hash_file, combinations):
    """Append data to a file."""
    headers = ["Run_id", "Customer_id", "Timestamp", "Domain"]
    
    try:
        # Add additional columns to the data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        run_id = fetch_run_id("Name Variation Domain Generator")
        data_to_append = [{
            "Run_id": str(int(run_id)).zfill(2),
            "Customer_id": customer_id,
            "Timestamp": timestamp,
            "Domain": combo
        } for combo in combinations]
        
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
            
            
            # Save the new hash
            # new_hash = compute_file_hash(output_file)
            # save_hash(hash_file, new_hash)
    except Exception as e:
        logging.error(f"Error appending to CSV file {output_file}: {e}")
 
 
db_lock = Lock()
# Insert combinations into the database
def insert_combinations_into_db(db_file, db_hash_file, combinations):
    """
    Inserts domain combinations into the database while ensuring thread safety with db_lock.
 
    Args:
        db_file (str): Path to the SQLite database file.
        db_hash_file (str): Path to the file storing the database hash.
        combinations (list): List of domain combinations to insert.
        db_lock (threading.Lock): Thread lock for database access.
   
    Returns:
        int: Number of new entries added to the database.
    """
    if not combinations:
        return 0
        
    new_entries_count = 0
    conn = None
 
    with db_lock:  # Ensures only one thread can access the database at a time
        try:
            # Connect to the database
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
 
            # Create table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_combinations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE
                )
            """)
 
            # Use batch insert with executemany instead of individual inserts
            # This reduces the number of database operations significantly
            try:
                cursor.executemany("INSERT OR IGNORE INTO domain_combinations (domain) VALUES (?)", 
                                  [(domain,) for domain in combinations])
                new_entries_count = cursor.rowcount
            except sqlite3.IntegrityError as e:
                logging.error(f"Database integrity error during batch insert: {e}")
 
            # Commit changes
            conn.commit()
 
            # # Update hash file with the latest database hash
            # new_db_hash = compute_file_hash(db_file)
            # with open(db_hash_file, 'w') as f:
            #     f.write(new_db_hash)
 
        except sqlite3.OperationalError as e:
            logging.error(f"Database operational error: {e}")
            raise
        except sqlite3.IntegrityError as e:
            logging.error(f"Database integrity error: {e}")
            raise
        finally:
            if conn:
                conn.close()
                
    return new_entries_count

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
 

# Main function
def main(customer_id, customer_name, new_session):
    try:
        base_name = f"Name_Variation_Domain_Generator_{customer_name}_{customer_id}"
        
        global run_id
        if new_session == "False":
            run_id = set_starting_point("Name Variation Domain Generator")
        else:
            run_id = fetch_run_id("Name Variation Domain Generator")

        # Handle file paths
        log_file = handle_files(base_name, ".log", log_dir)
        output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
        db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
        output_hash_file = handle_files(base_name, "_output_hash.txt", hash_dir)
        db_hash_file = handle_files(base_name, "_db_hash.txt", hash_dir)

        # Reinitialize logging with updated log filename
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[logging.FileHandler(log_file, mode='a', encoding='utf-8')]
        )
        logging.info(f"Logging system initialized. Log file: {log_file}")
 
        # Detect input files
        tld_file = detect_latest_file(output_dir, "tld_updater")
        name_variations_file = detect_latest_file(output_dir, "Variations_Generator")
    
        # Handle TLD file
        if not tld_file:
            while True:
                tld_file = input("Enter the TLD input file path (or type '0' to exit): ").strip()
                if tld_file == '0':
                    print("Exiting to main menu...")
                    return  # Exit to the main menu
                elif os.path.isfile(tld_file):
                    break
                else:
                    print("Invalid file path. Please try again.")
        else:
            print(f"Detected TLD File: {tld_file}")
            user_input = input("Do you want to proceed with this file? (yes/no): ").strip().lower()
            if user_input == 'no':
                while True:
                    tld_file = input("Enter the TLD input file path (or type '0' to exit): ").strip()
                    if tld_file == '0':
                        print("Exiting to main menu...")
                        return  # Exit to the main menu
                    elif os.path.isfile(tld_file):
                        break
                    else:
                        print("Invalid file path. Please try again.")
 
        # Handle Name Variations file
        if not name_variations_file:
            while True:
                name_variations_file = input("Enter the name variations input file path (or type '0' to exit): ").strip()
                if name_variations_file == '0':
                    print("Exiting to main menu...")
                    return  # Exit to the main menu
                elif os.path.isfile(name_variations_file):
                    break
                else:
                    print("Invalid file path. Please try again.")
        else:
            print(f"Detected Name Variations File: {name_variations_file}")
            user_input = input("Do you want to proceed with this file? (yes/no): ").strip().lower()
            if user_input == 'no':
                while True:
                    name_variations_file = input("Enter the name variations input file path (or type '0' to exit): ").strip()
                    if name_variations_file == '0':
                        print("Exiting to main menu...")
                        return  # Exit to the main menu
                    elif os.path.isfile(name_variations_file):
                        break
                    else:
                        print("Invalid file path. Please try again.")
 
        # Confirm with user whether to proceed with detected or provided files
        print(f"\nProceeding with the following files:\n1. TLD File: {tld_file}\n2. Name Variations File: {name_variations_file}")
        user_input = input("Do you want to proceed with these files? (yes/no): ").strip().lower()
        if user_input == 'no':
            # If user chooses 'no', ask them to provide file paths again
            print("Let's start over. Please provide the correct file paths.")
           
            # Ask for TLD file path again
            while True:
                tld_file = input("Enter the TLD input file path (or type '0' to exit): ").strip()
                if tld_file == '0':
                    print("Exiting to main menu...")
                    return  # Exit to the main menu
                elif os.path.isfile(tld_file):
                    break
                else:
                    print("Invalid file path. Please try again.")
 
            # Ask for Name Variations file path again
            while True:
                name_variations_file = input("Enter the name variations input file path (or type '0' to exit): ").strip()
                if name_variations_file == '0':
                    print("Exiting to main menu...")
                    return  # Exit to the main menu
                elif os.path.isfile(name_variations_file):
                    break
                else:
                    print("Invalid file path. Please try again.")
 

        # Load data from input files
        name_variations = load_domains(name_variations_file, "Variations Generator")
        tlds = load_lines_from_file(tld_file)
 
        
        # Generate combinations of name variations and TLDs
        if check_and_update_hash(db_file, db_hash_file):
            with open(output_file, 'a', newline='', encoding="utf-8") as csvfile:
                headers = ["Run_id", "Customer_id", "Timestamp", "Domain"]
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                # Write headers only if the file does not already exist or empty
                if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                    writer.writeheader()
            
            combinations = generate_combinations_multithreaded(
                name_variations, tlds, output_file, db_file, output_hash_file, db_hash_file
            )

            update_hash_file(db_file, db_hash_file)
            
            
            # Check if all domains have been processed
            if total_to_process == total_processed:
                logging.info("Code executed successfully at 100%.")
                integrate_log_updates("Name Variation Domain Generator", run_id, success=True)


        # Check if output file has changed based on its hash
        previous_output_hash = load_hash(output_hash_file)
        new_output_hash = compute_file_hash(output_file)
 
        if previous_output_hash != new_output_hash:
            logging.info(f"Output file hash changed. Previous: {previous_output_hash}, New: {new_output_hash}")
            new_csv_count = append_to_csv(output_file, output_hash_file, combinations)
            logging.info(f"New combinations added to CSV: {new_csv_count} entries.")
        else:
            logging.info("Output file hash unchanged. No new entries added to CSV.")
            new_csv_count = 0
 
        # Check if the database file has changed based on its hash
        previous_db_hash = load_hash(db_hash_file)
        new_db_hash = compute_file_hash(db_file)
 
        if previous_db_hash != new_db_hash:
            logging.info(f"Database file hash changed. Previous: {previous_db_hash}, New: {new_db_hash}")
            new_db_count = insert_combinations_into_db(db_file, db_hash_file, combinations)
            logging.info(f"New combinations added to DB: {new_db_count} entries.")
        else:
            logging.info("Database file hash unchanged. No new entries added to DB.")
            new_db_count = 0
        
        # Log and print the final success message
        logging.info(f"Process completed. New CSV entries: {new_csv_count}, New DB entries: {new_db_count}.")
        print(f"Success: {new_csv_count} new entries in CSV, {new_db_count} new entries in DB.")
    
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
    
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Name Variation Domain Generator",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)

    except Exception as e:
        logging.error(f"An error occurred during processing: {str(e)}")
        print(f"An error occurred. Check logs for details.")
        sys.exit(1)
 
 
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: Name_Variation_Domain_Generator.py <customer_id> <customer_name>")
        sys.exit(1)
    customer_id = sys.argv[1]
    customer_name = sys.argv[2]
    new_session = sys.argv[3]
    main(customer_id, customer_name, new_session)