import os
import socket
import logging
import time
import csv
import whois
import sqlite3
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import hashlib
from threading import Lock
import dns.resolver
import signal
import platform



global total_processed
global starting_point
global customer_id
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
        "Base Attributes Detection",
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
        "Base Attributes Detection",
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

# Configuration constants
MAX_WORKERS = 150  # Number of concurrent threads
RETRY_COUNT = 3   # Number of retries for each domain
DELAY_BETWEEN_REQUESTS = 1  # Delay between WHOIS requests (in seconds)
 
# Initialize config parser
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Paths from config.ini
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
 
# Ensure directories exist
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)
os.makedirs(db_dir, exist_ok=True)
os.makedirs(hash_dir, exist_ok=True)
 
# Ensure a directory exists
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Helper function to compute file hash
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
# Function to read and compare hash
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
 
# Set up logging
def setup_logging(log_file):
    """
    Sets up logging for the script. Logs everything to the file,
    but only success messages to the terminal.
    """
    try:
        # Remove existing handlers to avoid duplicate logs
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
 
        # File handler for logging all levels to the log file
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Log all levels to the file
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
 
        # Configure the root logger
        logging.basicConfig(level=logging.DEBUG, handlers=[file_handler])
 
        logging.info("Logging initialized.")
        logging.getLogger('whois').setLevel(logging.CRITICAL)
    except Exception as e:
        print(f"Error initializing logging: {e}")
        sys.exit(1)
 
 
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
 
 
def create_hash_file(output_file_path, base_name):
    """
    Creates a hash file with SHA256 hash of the output file content.
    """
    try:
        with open(output_file_path, 'rb') as f:
            file_data = f.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
 
        hash_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hash.txt"
        hash_file_path = os.path.join(hash_dir, hash_file_name)
 
        with open(hash_file_path, 'w') as hash_file:
            hash_file.write(f"SHA256: {sha256_hash}\n")
            logging.info(f"Hash file created: {hash_file_path}")
    except Exception as e:
        logging.error(f"Error creating hash file: {e}")
 

def init_db(customer_id, customer_name, timestamp):
    db_file = f"Base_Attributes_{customer_name}_{customer_id}_{timestamp}.db"
    db_path = os.path.join(db_dir, db_file)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS whois_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        ip_address TEXT,
        name_server TEXT,
        mail_server TEXT,
        registrar TEXT,
        registrant TEXT,
        registered_address TEXT,
        registration_country TEXT,
        registration_date TEXT,
        remarks TEXT
    )''')
    conn.commit()
    conn.close()
    return db_path
 
 
def format_date(date_value):
    """
    Formats a datetime value to 'YYYY-MM-DD'. Handles both naive and aware datetimes.
    """
    if isinstance(date_value, list):
        # Process the earliest date in the list
        return min(format_date(d) for d in date_value if isinstance(d, (datetime, str))) or "Null"
    elif isinstance(date_value, datetime):
        # Convert to offset-naive datetime if necessary
        if date_value.tzinfo is not None:
            date_value = date_value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return date_value.strftime('%Y-%m-%d')
    elif isinstance(date_value, str):
        # Try parsing a string into datetime
        try:
            parsed_date = datetime.fromisoformat(date_value)
            return parsed_date.strftime('%Y-%m-%d')
        except ValueError:
            return "Null"
    return "Null"

# Create a single global lock for shared resources
global_lock = Lock()

def insert_data_into_db(db_file, data):
    """
    Ensures the database table exists and inserts unique data rows.
    """
    with global_lock:  # Use the global lock
        try:
            with sqlite3.connect(db_file) as conn:
                cursor = conn.cursor()
                # Ensure the table has all the necessary columns
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS consolidated_data (
                        domain TEXT PRIMARY KEY,
                        ip_address TEXT,
                        name_server TEXT,
                        mail_server TEXT,
                        registrar TEXT,
                        registrant TEXT,
                        registered_address TEXT,
                        registration_country TEXT,
                        registration_date TEXT,
                        remarks TEXT
                    )
                ''')

                # Prepare data for insertion (convert all to string or None)
                prepared_data = (
                    str(data['Domain']) if data['Domain'] else None,
                    str(data['IP Address']) if data['IP Address'] else None,
                    str(data['Name Server']) if data['Name Server'] else None,
                    str(data['Mail Server']) if data['Mail Server'] else None,
                    str(data['Registrar']) if data['Registrar'] else None,
                    str(data['Registrant']) if data['Registrant'] else None,
                    str(data['Registered Address']) if data['Registered Address'] else None,
                    str(data['Registration Country']) if data['Registration Country'] else None,
                    str(data['Registration Date']) if data['Registration Date'] else None,
                    str(data['Remarks']) if data['Remarks'] else None,
                )

                # Insert data into the table
                cursor.execute('''
                INSERT OR IGNORE INTO consolidated_data (
                    domain, ip_address, name_server, mail_server, registrar, registrant,
                    registered_address, registration_country, registration_date, remarks
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', prepared_data)

                conn.commit()
                logging.info(f"Data inserted for domain: {data['Domain']}")

        except sqlite3.Error as e:
            logging.error(f"SQLite error in {db_file} for domain {data.get('Domain', 'Unknown')}: {e}")
            raise
        except Exception as e:
            logging.error(f"General error updating database {db_file} for domain {data.get('Domain', 'Unknown')}: {e}")
            raise


def fetch_ip_address(domain):
    """
    Fetches the IP address for a given domain.

    Parameters:
        domain (str): The domain name to check.

    Returns:
        str: The IP address of the domain or "Null" if no address found.
    """
    try:
        # Use socket to get the IP address
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        # No A records found for the domain
        return "Null"
    except Exception as e:
        # Handle any other exceptions
        logging.error(f"Error fetching IP address for domain {domain}: {e}")
        return "Null"




def fetch_mail_server(domain):
    """
    Fetches mail server (MX) records for a given domain using DNS lookup.

    Parameters:
        domain (str): The domain name to check.

    Returns:
        str: A list of mail servers separated by " | " or "Null" if no records found.
    """
    try:
        # Resolve MX records for the domain
        answers = dns.resolver.resolve(domain, 'MX')
        mail_servers = sorted([(record.preference, str(record.exchange)) for record in answers])
        formatted_servers = [f"{server} (Priority: {priority})" for priority, server in mail_servers]
        return ' | '.join(formatted_servers) if formatted_servers else "Null"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # No MX records found for the domain
        return "Null"
    except dns.resolver.Timeout:
        # DNS query timed out
        logging.error(f"DNS query timed out for domain: {domain}")
        return "Null"
    except Exception as e:
        # Handle any other exceptions
        logging.error(f"Error fetching MX records for domain {domain}: {e}")
        return "Null"


def perform_whois(domain, db_file, output_file):
    """Perform WHOIS lookup for a domain and store results."""
    for attempt in range(RETRY_COUNT):
        try:
            logging.info(f"Attempting WHOIS query for {domain}, attempt {attempt + 1}...")
            result = whois.whois(domain)

            ip_address = fetch_ip_address(domain) or "Null"
            
            if result:
                # Check if WHOIS data has required fields
                has_required_data = any([result.get("registrar"), result.get("creation_date"), result.get("org")])

                if has_required_data:
                    # Convert list-like fields to strings safely
                    name_servers = (
                        ' | '.join(map(str, result.get("name_servers", [])))
                        if isinstance(result.get("name_servers"), (list, set)) 
                        else str(result.get("name_servers", "Null")).replace("\n", " | ")
                    )

                    emails = fetch_mail_server(domain)  # Fetch mail servers via DNS MX lookup

                    address = (
                        ' | '.join(result.get("address", [])) 
                        if isinstance(result.get("address"), (list, set)) 
                        else str(result.get("address", "Null")).replace("\n", " | ")
                    )

                    # Prepare data for insertion
                    data = {
                        'Run_id': run_id,
                        'Customer_id': customer_id,
                        'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'Domain': domain,
                        'IP Address': ip_address,
                        'Name Server': name_servers,
                        'Mail Server': emails,
                        'Registrar': result.get("registrar", "Null"),
                        'Registrant': result.get("org", "Null"),
                        'Registered Address': address,
                        'Registration Country': result.get("country", "Null"),
                        'Registration Date': format_date(result.get("creation_date", "Null")),
                        'Remarks': "Success",
                    }

                    # Append data to CSV and insert into the database
                    append_to_csv(output_file, [data])
                    insert_data_into_db(db_file, data)
                    return data
        except whois.parser.PywhoisError as e:
            logging.error(f"WHOIS lookup failed for {domain} due to WHOIS blocking: {e}")
        except Exception as e:
            logging.error(f"Error querying {domain}: {e}")
            time.sleep(DELAY_BETWEEN_REQUESTS)  # Avoid overloading WHOIS servers

    # Fallback data if WHOIS lookup fails
    data = {
        'Run_id': run_id,
        'Customer_id': customer_id,
        'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Domain': domain,
        'IP Address': ip_address,
        'Name Server': "Null",
        'Mail Server': "Null",
        'Registrar': "Null",
        'Registrant': "Null",
        'Registered Address': "Null",
        'Registration Country': "Null",
        'Registration Date': "Null",
        'Remarks': "WHOIS unavailable or domain not registered.",
    }

    # Log and insert fallback data
    append_to_csv(output_file, [data])
    insert_data_into_db(db_file, data)
    return data
 
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

def append_to_csv(file_path, data):
    """
    Appends data to CSV file after removing duplicates.
    """
    with global_lock:  # Use the global lock
        existing_data = remove_duplicates(file_path) if os.path.exists(file_path) else []
        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            fieldnames = [
                'Run_id', 'Customer_id', 'Timestamp', 'Domain', 'IP Address', 'Name Server', 
                'Mail Server', 'Registrar', 'Registrant', 'Registered Address', 
                'Registration Country', 'Registration Date', 'Remarks'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            # Write header only if the file is empty
            if os.path.getsize(file_path) == 0:
                writer.writeheader()

            # Filter out duplicates
            new_data = [row for row in data if row['Domain'] not in {d['Domain'] for d in existing_data}]

            # Append only new data
            writer.writerows(new_data)
 
 
def find_latest_file(directory):
    """
    Finds the latest file in the directory based on the timestamp.
    Returns the file path of the most recent file or None if no files are found.
    """
    try:
        files = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, f)) and f.endswith('.csv')
        ]
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    except Exception as e:
        logging.error(f"Error detecting latest file: {e}")
        return None
 
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
 
def load_domains(input_file, label=""):
    """
    Reads domains from the input CSV file.
    Returns a list of domains.
    """
    domains = set()
   
    logging.info(f"Reading {label} file: {input_file}")
    try:
        with open(input_file, 'r', encoding="utf-8") as file:
            csv_reader = csv.DictReader(file)
            if 'Domain' not in csv_reader.fieldnames:
                logging.error("The input file is missing the 'Domain' column.")
                print("Error: The input file is missing the 'Domain' column. Please check the file format.")
                return []
            for row in csv_reader:
                domain = row.get('Domain')
                if domain:
                    domains.add(domain.strip())
    except FileNotFoundError:
        logging.error(f"File not found: {input_file}")
        print(f"Error: File not found: {input_file}")
    except Exception as e:
        logging.error(f"Error reading file {input_file}: {e}")
        print(f"Error: Unable to read the file. Details: {e}")
   
    logging.info(f"Loaded {len(domains)} domains from {label} file.")
    return list(domains)
 
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
 
 
def main(new_session, input_file_path=None, customer_id=None, customer_name=None):
    try:
        global run_id
        if new_session == "False":
            run_id = set_starting_point("Base Attributes")
        else:
            run_id = fetch_run_id("Base Attributes")
 
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"Base_Attributes_{customer_name}_{customer_id}"
 
        log_file_path = handle_files(base_name, ".log", log_dir)
        setup_logging(log_file_path)
 
        logging.info("Script started.")
        logging.info(f"Customer ID: {customer_id}, Customer Name: {customer_name}")
 
        output_file_path = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
        db_file_path = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
        hash_file = handle_files(base_name, "_hash.txt", hash_dir)
 
        try:
            domains = load_domains(input_file_path, "Consolidator")
            logging.info(f"Total domains to process: {len(domains)}")
        except FileNotFoundError:
            logging.error("Input file not found.")
            sys.exit(1)
 

        global total_to_process
        total_to_process = len(domains)
 
        if total_to_process == 0:
            logging.error("No domains to process. Exiting.")
            print("No domains to process. Exiting.")
            sys.exit(1)
 
        
        lock = Lock()
        last_logged_progress = -1
        
        def process_batch(domain_list):
            # Process domains in parallel
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(perform_whois, domain, db_file_path, output_file_path): domain for domain in domain_list}
                for future in as_completed(futures):
                    domain = futures[future]  # Get the domain being processed
                    try:
                        result = future.result()
                    except Exception as e:
                        logging.error(f"Error processing domain {domain}: {e}")
                    finally:
                        with lock:
                            global total_processed
                            total_processed += 1
                            progress_percentage = round((total_processed / total_to_process) * 100, 2)
                            if progress_percentage % 5 == 0 and progress_percentage != last_logged_progress:
                                last_logged_progress = progress_percentage
                                logging.info(f"Processed {total_processed}/{total_to_process} domains ({progress_percentage}%).")
 
        # Avoid zero step argument in range()
        batch_size = min(total_to_process, 1000) if total_to_process > 0 else 1
 
        for i in range(starting_point, total_to_process, batch_size):
            batch = domains[i: min(i + batch_size, total_to_process)]
            process_batch(batch)
 
        # After processing all domains, create the hash file
        create_hash_file(db_file_path, hash_file)
 
        # Check if all domains have been processed
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Base Attributes Detection", run_id, success=True)
 
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
   
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Base Attributes Detection",
            run_id,
            interrupted=True,
            progress=progress,
            error_type="Keyboard Interrupt"
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
 
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
 
# Wrapper integration
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python Base_Attributes.py <customer_id> <customer_name> <output_file>")
        sys.exit(1)
 
    customer_id = sys.argv[1]
    customer_name = sys.argv[2]
    output_file = sys.argv[3]
    new_session = sys.argv[4]
 
    main(new_session, input_file_path=output_file, customer_id=customer_id, customer_name=customer_name)