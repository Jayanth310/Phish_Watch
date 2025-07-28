import os
import sys
import csv
import logging
import sqlite3
import configparser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import dns.resolver
from threading import Lock
import signal
import platform


# Global variable declarations
global total_to_process
global total_processed
global starting_point
global run_id
global customer_id
global customer_name
global new_session

# Initialize global variables
total_to_process = 0
total_processed = 0
starting_point = 0
run_id = None
customer_id = None
customer_name = None
new_session = None

# Add a global database lock at the top of the file (after imports)
db_lock = Lock()  # Global lock for database operations

def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    global total_processed, total_to_process, run_id
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Name Split Detection",
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
    global total_processed, total_to_process, run_id
    # Add a flag to prevent multiple executions
    if hasattr(signal_session_expired, 'called'):
        return
    signal_session_expired.called = True
    
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"EC2 session expired at {progress}%.")

    integrate_log_updates(
        "Name Split Detection",
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

# Initialize configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Base paths from configuration
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
 
# Ensure directories exist
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)
os.makedirs(db_dir, exist_ok=True)
os.makedirs(hash_dir, exist_ok=True)
 
# Helper function to compute the file hash
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
def setup_logging(log_file):
    try:
        ensure_directory_exists(os.path.dirname(log_file))
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, mode='a', encoding='utf-8')
            ]
        )
        logging.info(f"Logging initialized at {log_file}.")
    except Exception as e:
        print(f"Error initializing logging: {e}")
        sys.exit(1)
 
def check_dns_records(domain_name):
    """
    Checks DNS records for a domain and logs the types of records it has.
    Logs 'has DNS records' if any are found, otherwise logs 'no DNS records.'
    """
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
 
def load_existing_output(output_file):
    if not os.path.exists(output_file):
        return set()
    try:
        with open(output_file, 'r', encoding="utf8") as f:
            reader = csv.DictReader(f)
            existing_entries = {row["Domain"].strip() for row in reader}
        return existing_entries
    except Exception as e:
        logging.error(f"Error reading existing output file {output_file}: {e}")
        return set()
 
def generate_name_split_variants(domain):
    try:
        main_part, tld = domain.rsplit('.', 1)
        return [f"{main_part[:i]}.{main_part[i:]}.{tld}" for i in range(1, len(str(main_part)))]
    except ValueError:
        logging.error(f"Invalid domain format: {domain}")
        return []

def domain_exists_parallel(domain_list, output_file, db_file):
    """Check if domains exist in parallel."""
    global total_processed, total_to_process
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(domain_exists_parallel, 'connection_lost'):
        return None

    results = {}
    domain_lock = Lock()
    batch_size = 100  # Configurable batch size for database operations
    valid_domains_batch = []
    last_logged_progress = -1
    
    def process_domain(domain):
        if check_dns_records(domain):
            # Return the domain if it exists, process in batches later
            return domain
        return None
    
    def process_valid_domains_batch():
        if valid_domains_batch:
            deduplicated_results = deduplicate_results(valid_domains_batch, output_file, db_file)
            if deduplicated_results:
                append_to_file(deduplicated_results, output_file)
                update_database(deduplicated_results, db_file)
            valid_domains_batch.clear()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domain_list}
        for future in as_completed(futures):
            try:
                domain = future.result()
                if domain:
                    results[domain] = True
                    
                    with domain_lock:
                        valid_domains_batch.append(domain)
                        # Process in batches to reduce database lock frequency
                        if len(valid_domains_batch) >= batch_size:
                            process_valid_domains_batch()
            except Exception as e:
                logging.error(f"Error processing domain: {e}")
            finally:
                with domain_lock:
                    total_processed += 1
                    progress_percentage = round((total_processed / total_to_process) * 100, 2)
                    if progress_percentage % 5 == 0 and progress_percentage != last_logged_progress:
                        last_logged_progress = progress_percentage
                        logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")
    
    # Process any remaining domains in the batch
    with domain_lock:
        process_valid_domains_batch()
        
    return results

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

def process_domains_in_batch(input_hoarded_file, input_variation_file, output_file, db_file):

    try:
        hoarded_domains = load_domains(input_hoarded_file, "Hoarded Domains")
        variation_domains = load_domains(input_variation_file, "Name Variation Domains")
        all_domains = hoarded_domains + variation_domains
        total_domains = []
        
        logging.info("Calculating total domains to process.")
        for domain in all_domains:
            generated_domain = generate_name_split_variants(domain)
            if generated_domain:
                total_domains.extend(generated_domain)

        global total_to_process
        total_to_process = len(total_domains)
        logging.info(f"Total domains to process: {total_to_process}")

        for i in range(starting_point, total_to_process, 1000):
            batch = total_domains[i:i + 1000]

            domain_exists_parallel(batch, output_file, db_file)

    except Exception as e:
        logging.error(f"Error processing domains from files: {e}")

 
def deduplicate_results(results, output_file, db_file):
    try:
        existing_output = load_existing_output(output_file)
 
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
 
        cursor.execute('''CREATE TABLE IF NOT EXISTS name_split_variants (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name_split_variant TEXT UNIQUE)''')
 
        cursor.execute("SELECT name_split_variant FROM name_split_variants")
        existing_db = {row[0] for row in cursor.fetchall()}
        # logging.info(f"Existing variants in DB: {existing_db}")
        conn.close()
 
        deduplicated = [
            result for result in results
            if result not in existing_output and result not in existing_db
        ]
        # logging.info("Deduplicated successfully.")
        return deduplicated
    except Exception as e:
        logging.error(f"Error during deduplication: {e}")
        return results

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

def append_to_file(data, output_file):
    """Append data to a file."""
    headers = ["Run_id", "Customer_id", "Timestamp", "Domain"]
    
    
    try:
        # Add additional columns to the data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        run_id = fetch_run_id("Name Split Detection")
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
    except Exception as e:
        logging.error(f"Error appending to CSV file {output_file}: {e}")
 
 
def update_database(results, db_file):
    """
    Updates the database with name split variants.
    
    Args:
        results (list): List of domain variants to add to the database.
        db_file (str): Path to the SQLite database file.
    """
    if not results:
        return
        
    with db_lock:  # Use lock to prevent database contention
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Create table if it doesn't exist (added for safety)
            cursor.execute('''CREATE TABLE IF NOT EXISTS name_split_variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_split_variant TEXT UNIQUE)''')
     
            cursor.executemany('''INSERT OR IGNORE INTO name_split_variants (name_split_variant) VALUES (?)''',
                               [(result,) for result in results])
     
            conn.commit()
            conn.close()
            logging.info(f"Database updated with {len(results)} variants.")
        except Exception as e:
            logging.error(f"Error updating database {db_file}: {e}")
 
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

def integrate_log_updates(option_name, run_id, success=False, interrupted=False, progress=0, error_type=None):
    """
    Updates Run_Master.csv and Run_Tracker.csv with process status.
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
    global starting_point, total_processed, total_to_process
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
            starting_point = int(latest_row[0]["Processed"])
            total_processed = starting_point  # Changed from += to =
            logging.info(f"{total_processed} already processed starting from {starting_point + 1}.")
            print(f"\n{total_processed} already processed starting from {starting_point + 1}.\n")
            return latest_row[0]["Run_id"]
        return None
    except Exception as e:
        logging.error(f"Error setting starting point: {e}")
        return None
 

def main(input_hoarded_file, input_variation_file, customer_id_arg, customer_name_arg, new_session_arg):
    global run_id, customer_id, customer_name, new_session
    customer_id = customer_id_arg
    customer_name = customer_name_arg
    new_session = new_session_arg
    
    try:
        
        if new_session == "False":
            run_id = set_starting_point("Name Split Detection")
        else:
            run_id = fetch_run_id("Name Split Detection")
        base_name = f"Name_Split_Detection_{customer_name}_{customer_id}"
 
        log_file = handle_files(base_name, ".log", log_dir)
        setup_logging(log_file)
    
        output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
        db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
        hash_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_hash.txt"
        hash_file_path = os.path.join(hash_dir, hash_file_name)
    
        if check_and_update_hash(db_file, hash_file_path):
            if not os.path.exists(db_file):
                open(db_file, 'a').close()
            
            
            with open(output_file, 'a', newline='', encoding="utf-8") as csvfile:
                headers = ["Run_id", "Customer_id", "Timestamp", "Domain"]
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                
                # Write headers only if the file does not already exist or empty
                if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                    writer.writeheader()

            process_domains_in_batch(input_hoarded_file, input_variation_file, output_file, db_file)

    
            update_hash_file(db_file, hash_file_path)

                
            # Check if all domains have been processed
            if total_to_process == total_processed:
                logging.info("Code executed successfully at 100%.")
                integrate_log_updates("Name Split Detection", run_id, success=True)
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
    
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Name Split Detection",
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
    if len(sys.argv) != 6:
        print("Usage: python name_split_generator.py <input_file_hoarded> <input_file_variation> <customer_id> <customer_name>")
        sys.exit(1)
 
    input_hoarded_file = sys.argv[1]
    input_variation_file = sys.argv[2]
    customer_id = sys.argv[3]
    customer_name = sys.argv[4]
    new_session = sys.argv[5]
    main(input_hoarded_file, input_variation_file, customer_id, customer_name, new_session)