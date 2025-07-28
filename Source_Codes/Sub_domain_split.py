import os
import sys
import logging
from datetime import datetime
import csv
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import hashlib
import dns.resolver
import re
import pandas as pd
from threading import Lock
import signal
import platform

global total_processed
global total_to_process
global starting_point
total_processed = 0
total_to_process = 0
starting_point = 0

db_lock = Lock()  # Global lock for database operations

def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")

    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Sub Domain Split",
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
        "Sub Domain Split",
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
# Function to ensure directory exists, if not, create it
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Read configuration from Config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Get base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Paths from Config.ini (directories will be moved one level up)
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hashes_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hashes_dir', fallback='Hashes'))
# Ensure directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hashes_dir)
# Function to handle file creation and timestamp updates
def handle_files(base_name, file_type, directory):
    """
    Handle file initialization and timestamp updates for log, output, and DB files.
    """
    existing_files = [
        f for f in os.listdir(directory) if base_name in f and f.endswith(file_type)
    ]
    if existing_files:
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = existing_files[0]
        new_file_path = os.path.join(directory, f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}")
        os.rename(os.path.join(directory, latest_file), new_file_path)
        return new_file_path
    else:
        new_file_path = os.path.join(directory, f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}")
        open(new_file_path, 'a').close()  # Create the file
        return new_file_path
 
# Function to set up logging
def setup_logging(log_file):
    """
    Sets up logging for the script.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file, mode='a', encoding='utf-8'),
            # logging.StreamHandler(sys.stdout)  # Also log to the console
        ]
    )
    logging.info("Logging initialized.")
 
def check_dns_records(domain_name):
    """
    Checks DNS records for a domain and logs the types of records it has.
    Logs 'has DNS records' if any are found, otherwise logs 'no DNS records.'
    """
    # Add a flag to prevent multiple executions of the exit logic
    if hasattr(check_dns_records, 'connection_lost'):
        return False

    # Rest of the existing check_dns_records function...
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

def domain_exists_parallel(domain_list, output_file, db_file):
    """Check if domains exist in parallel."""
    results = {}
    domain_lock = Lock()
    batch_size = 100  # Configurable batch size for database operations
    valid_domains_batch = []
    
    def process_domain(domain):
        if check_dns_records(domain):
            # Instead of immediately updating, collect for batch processing
            return domain
        return None
    
    def process_valid_domains_batch():
        if valid_domains_batch:
            # Update output file and database with valid domains in a batch
            write_results_to_csv([{"sub_domain_split_variant": domain} for domain in valid_domains_batch], output_file)
            update_database([{"sub_domain_split_variant": domain} for domain in valid_domains_batch], db_file, None)
            valid_domains_batch.clear()
    
    with ThreadPoolExecutor(max_workers=150) as executor:  # Adjust max_workers based on your system's capabilities
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domain_list}
        for future in as_completed(future_to_domain):
            try:
                domain = future.result()
                if domain:
                    logging.info(f"Valid domain: {domain}")
                    results[domain] = True
                    
                    with domain_lock:
                        valid_domains_batch.append(domain)
                        # Process in batches to reduce database lock frequency
                        if len(valid_domains_batch) >= batch_size:
                            process_valid_domains_batch()
            except Exception as e:
                    logging.error(f"Error processing {future_to_domain[future]}: {e}")
            finally:
                with domain_lock:
                    global total_processed
                    total_processed = total_processed + 1
                    progress_percentage = round((total_processed / total_to_process) * 100, 2)
                    logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")
    
    # Process any remaining domains in the batch
    with domain_lock:
        process_valid_domains_batch()
        
    return results
 
 
# Function to generate name split variants
def generate_name_split_variants(subdomain):
    """
    Generates all name-split variations of the given subdomain by inserting dots at each position.
    Args:
        subdomain (str): The subdomain to generate variants for.
    Returns:
        list: A list of subdomain variants with dots inserted at each position.
    """
    try:
        main_part, tld = subdomain.rsplit('.', 1)
        variants = []
        for i in range(1, len(main_part)):
            variant = f"{main_part[:i]}.{main_part[i:]}.{tld}"
            if all(len(label) > 0 for label in variant.split('.')):
                variants.append(variant)
        logging.debug(f"Generated {len(variants)} variants for subdomain: {subdomain}")
        return variants
    except ValueError:
        logging.error(f"Invalid subdomain format: {subdomain}")
        return []  
 
# Function to validate subdomain format
def is_valid_subdomain(subdomain):
    """
    Validates that the subdomain is correctly formatted.
    Checks the following conditions:
    1. It doesn't contain invalid characters.
    2. Each label is between 1 and 63 characters long.
    3. The subdomain does not start or end with a dot.
    """
    if not isinstance(subdomain, str):
        return False
 
    # Check if the subdomain has the correct format using regex
    subdomain_regex = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
    if not re.match(subdomain_regex, subdomain):
        return False
 
    # Ensure no label exceeds 63 characters
    labels = subdomain.split('.')
    if any(len(label) > 63 or len(label) == 0 for label in labels):
        return False
 
    # Subdomain should not start or end with a dot
    if subdomain.startswith('.') or subdomain.endswith('.'):
        return False
 
    return True
 
# Function to process subdomains
def process_subdomains(input_file, output_file, db_file, hash_file):
    """
    Processes a list of subdomains from a CSV input file, generating name-split variants for each.
    Args:
        input_file (str): Path to input CSV file containing subdomains.
    Returns:
        list: A list of dictionaries containing original subdomain and generated name-split variants.
    """
    results = []
    try:
        # Check if the file exists
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"The input file {input_file} does not exist.")
 
        # Read subdomains from the CSV file
        with open(input_file, 'r', encoding="utf8") as f:
            reader = csv.DictReader(f)
            
            subdomains = [
        row['Subdomain'] for row in reader
        if row['Subdomain'] and row['Subdomain'].startswith("No subdomain") and row['Subdomain'].strip() and is_valid_subdomain(row['Subdomain'])
    ]
        total_domains = []
        for subdomain in subdomains:
            total_variants = generate_name_split_variants(subdomain)
            if total_variants:
                total_domains.extend(total_variants)
        
        global total_to_process
        total_to_process = len(total_domains)
        logging.info(f"Total domains to process: {total_to_process}")
        
        # Creating an empty output file with only columns
        empty_df = pd.DataFrame(columns=["Run_id", "Customer_id", "Timestamp", "Sub_domain_split_variant"])
        empty_df.to_csv(output_file, index=False, encoding="utf8", header=True)
        
        # Divide combinations into batches for multithreading
        for i in range(starting_point, len(total_domains), 1000):
            batch = total_domains[i:i + 1000]
        
            batch_results = domain_exists_parallel(batch, output_file, db_file)
            valid_domains = [domain for domain, exists in batch_results.items() if exists]
            results.extend(valid_domains)
            
            check_and_update_hash(db_file, hash_file)
            
    except Exception as e:
        logging.error(f"Error processing subdomains from file {input_file}: {e}")
    return results

# Function to compute file hash (SHA-256)
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
# Function to check if the database has changed by comparing hashes
def check_and_update_hash(db_file, hash_file):
    if not os.path.exists(db_file):
        logging.info("Database file does not exist. Creating new database...")
        return True  # Need to create/update the database
 
    if not os.path.exists(hash_file):
        logging.info("Hash file does not exist. Proceeding with updates...")
        return True  # No hash to compare, assume changes
 
    # Compare current hash with stored hash
    current_hash = compute_file_hash(db_file)
    with open(hash_file, "r") as hf:
        stored_hash = hf.read().strip()
 
    if current_hash != stored_hash:
        logging.info("Hash mismatch. Updates are required...")
        return True
    else:
        logging.info("Hash matches. No updates needed...")
        return False

# Update hash file
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash updated in {hash_file}")

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


# Function to write results to CSV
def write_results_to_csv(results, output_file):
    """Append data to a file."""
    headers = ["Run_id", "Customer_id", "Timestamp", "Sub_domain_split_variant"]
    
    try:
        # Add additional columns to the data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        run_id = fetch_run_id("Sub Domain Split")
        data_to_append = [{
            "Run_id": str(int(run_id)).zfill(2),
            "Customer_id": customer_id,
            "Timestamp": timestamp,
            "Sub_domain_split_variant": variant
        } for variant in results]
        
        # Convert input data to a Pandas DataFrame
        new_data_df = pd.DataFrame(data_to_append, columns=headers)
        
        # Check if the file exists and is not empty
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                # Read the existing file
                existing_data_df = pd.read_csv(output_file, encoding="utf8")
                
                # Ensure existing Run_id is formatted
                if 'Run_id' in existing_data_df.columns:
                    existing_data_df['Run_id'] = existing_data_df['Run_id'].apply(lambda x: str(x).zfill(2))
                
                # Concatenate the new data and drop duplicates
                combined_df = pd.concat([existing_data_df, new_data_df]).drop_duplicates(subset="Domain", keep="last")
            except pd.errors.EmptyDataError:
                logging.warning(f"The file {output_file} is empty. Creating a new file.")
                combined_df = new_data_df
        else:
            combined_df = new_data_df
        
        # Save the combined DataFrame back to the file
        combined_df.to_csv(output_file, index=False, encoding="utf8")
    except Exception as e:
        logging.error(f"Error appending to CSV file {output_file}: {e}")
 
# Function to update the database
def update_database(results, db_file, hash_file):
    """
    Updates the database with the sub-domain split variants.
    Args:
        results (list): List of dictionaries with sub-domain split variants.
        db_file (str): Path to SQLite database file.
        hash_file (str): Path to the hash file storing the database hash.
    """
    if not results:
        return
        
    with db_lock:  # Use lock to prevent database contention
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
     
            # Create the table if it doesn't exist
            cursor.execute('''CREATE TABLE IF NOT EXISTS sub_domain_split_variants (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                sub_domain_split_variant TEXT)''')
     
            # Insert the results into the table, ignoring duplicates
            cursor.executemany('''INSERT OR IGNORE INTO sub_domain_split_variants (sub_domain_split_variant) VALUES (?)''',
                               [(result["sub_domain_split_variant"],) for result in results])
     
            conn.commit()
            conn.close()
            logging.info(f"Database updated with {len(results)} variants.")
     
            # Update the hash if a hash file is provided
            if hash_file:
                new_hash = compute_file_hash(db_file)
                with open(hash_file, "w") as hf:
                    hf.write(new_hash)
                logging.info(f"Hash file updated with new hash: {new_hash}")
     
        except Exception as e:
            logging.error(f"Error updating database {db_file}: {e}")

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


# Main function to process and output results
def main(input_file, customer_id, customer_name, new_session):
    """
    Main function to process subdomains and output sub-domain split variants to CSV and database.
    """
    try:
        
        global run_id, total_to_process
        if new_session == "False":
            run_id = set_starting_point("Sub Domain Split")
        else:
            run_id = fetch_run_id("Sub Domain Split")
            
        
        # Base name for file naming
        base_name = f"Sub_Domain_Split_{customer_name}_{customer_id}"
        
 
        # Log, output, database, and hash file handling
        log_file = handle_files(base_name, ".log", log_dir)
        output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
        db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
        hash_file = handle_files(base_name, "_hash.txt", hashes_dir)  # Save the hash in the HASHES directory
 
        # Setup logging
        setup_logging(log_file)
 
        logging.info("Starting Sub-Domain Split Generation")
        logging.info(f"Customer ID: {customer_id}, Customer Name: {customer_name}")

        
        # Check hash and update database only if necessary
        if check_and_update_hash(db_file, hash_file):
            process_subdomains(input_file, output_file, db_file, hash_file)
            update_hash_file(db_file, hash_file)
 
        
        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Sub Domain Split", run_id, success=True)
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
    
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Sub Domain Split",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error in main function: {e}")
 
# Ensure the script is run with appropriate arguments
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: sub_domain_split.py <input_file> <customer_id> <customer_name>")
        sys.exit(1)
 
    input_file = sys.argv[1]
    customer_id = sys.argv[2]
    customer_name = sys.argv[3]
    new_session = sys.argv[4]
    # Execute the main function
    main(input_file, customer_id, customer_name, new_session)