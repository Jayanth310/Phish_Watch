import os
import logging
import sqlite3
from datetime import datetime
import csv
import configparser
import hashlib
import sys
import timeit
import signal
import platform
 
global total_processed
global total_to_process
total_to_process = 0
total_processed = 0
 
 
def signal_handler(sig, frame):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully.
    Works on all platforms (Windows, Linux, macOS).
    """
    # Calculate progress based on processed domains
    progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
    logging.error(f"Code was interrupted at {progress}%.")
 
    # Update logs and tracker files with accurate progress
    integrate_log_updates(
        "Alert Severity",
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
        "Alert Severity",
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
 
# Ensure directory exists function
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Function to compute the hash of a file
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()
 
# Read configuration from Config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Get base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Fetch paths from the config file
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='HASHES'))
 
# Ensure required directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hash_dir)
 
# Function to create or update file paths
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
 
# Function to check and compare file hash
def check_and_update_hash(db_file, hash_file):
    if not os.path.exists(db_file):
        print("Database file does not exist. Creating new database...")
        return True  # Need to create/update the database
 
    if not os.path.exists(hash_file):
        print("Hash file does not exist. Creating hash file...")
        # Create the hash file and proceed with updates
        with open(hash_file, "w") as hf:
            # Write an initial hash value, assuming the DB is empty or new
            initial_hash = compute_file_hash(db_file)
            hf.write(initial_hash)
        return True  # Proceed with updates
 
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
 
# Initialize database
def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT UNIQUE,
            alert_severity REAL,
            severity_level TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()
 
# Function to safely convert fields to boolean-like values
def safe_int(value, is_port=False):
    """
    Converts various input values into an integer (1 or 0) based on specific rules:
    - 'yes', any text (other than 'no', 'null', 'Null', 'none', 'unknown', or 'error'): 1
    - 'no', 'null', 'Null', 'none', 'unknown', 'error', empty: 0
    - Always returns 1 for 'port' fields.
    """
    try:
        # Special handling for the 'port' field
        if is_port:
            return 1
 
        # Normalize input to lowercase string for comparison
        if isinstance(value, str):
            value = value.strip().lower()
 
        # Treat text fields as 'yes' unless explicitly 'no', 'null', 'Null', 'none', or 'error'
        if value in ["no", "null", "Null", "none", "error", "unknown", ""]:
            return 0
        return 1
    except Exception:
        return 0
 
# Calculate severity
def calculate_severity(row, weights):
    """Calculates alert severity based on row attributes and weights."""
    try:
        # Helper to normalize field values
        def normalize_field(value):
            if isinstance(value, str):
                return value.strip()
            elif isinstance(value, (int, float)):
                return str(value)  # Convert numbers to strings
            else:
                return ""  # Fallback for other types
       
        # Initialize the weighted score with base score
        weighted_score = 2
       
        # Incremental score calculation
       
        # Name Server - 1 point if not "Null"
        weighted_score += weights.get("name_server", 0) * (1 if normalize_field(row.get("Name Server")) != "Null" else 0)
       
        # Mail Server - 1 point if not "Null"
        weighted_score += weights.get("mail_server", 0) * (1 if normalize_field(row.get("Mail Server")) != "Null" else 0)
       
        # Registrar - 1 point if not "Null"
        weighted_score += weights.get("registrar", 0) * (1 if normalize_field(row.get("Registrar")) != "Null" else 0)
       
        # Blacklisted - 1 point if "Yes"
        weighted_score += weights.get("blacklisted", 0) * (1 if normalize_field(row.get("Blacklisted")).lower() == "yes" or ((row.get("IP Address") and safe_int(row.get("IP Address")), 0)) else 0)
       
        # Age of Registration - Use the value and apply weights (convert months to years if necessary)
        weighted_score += weights.get("age_of_registration", 0) * safe_int(row.get("Age of Registration", 0))
       
        # Directory Listing - 1 point if "Yes"
        weighted_score += weights.get("directory_listing", 0) * (1 if normalize_field(row.get("Directory Listing")).lower() == "yes" else 0)
       
        # SSL - 1 point if "Yes"
        weighted_score += weights.get("ssl", 0) * (1 if normalize_field(row.get("SSL")).lower() == "yes" else 0)
       
        # Login Page Exists - 1 point if "Yes"
        weighted_score += weights.get("login_page", 0) * (1 if normalize_field(row.get("Login Page")).lower() == "yes" else 0)
       
        # Port Open - 1 point if port is not 0
        weighted_score += weights.get("port", 0) * safe_int(row.get("Port", 0), is_port=True)
       
        # Normalize the score between 0 and 1
        total_weights = sum(weights.values())
        normalize_score = min(1.0, weighted_score / total_weights)
        return normalize_score
    except Exception as e:
        logging.error(f"Error in calculate_severity: {e}")
        return 0
 
# Classify severity
def classify_severity(alert_severity):
    if 0.8 <= alert_severity <= 1.0:
        return "Critical"
    elif 0.6 <= alert_severity <= 0.8:
        return "High"
    elif 0.5 <= alert_severity <= 0.6:
        return "Medium"
    elif 0.2 <= alert_severity <= 0.5:
        return "Low"
    else:
        return "Unknown"
 
# Process alerts
def standardize_domain(domain):
    """Standardize domain names for consistency."""
    if isinstance(domain, str):
        domain = domain.strip().lower()
        domain = domain.split('(')[0]  # Remove embedded URLs or comments
    return domain
 
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
 
# Process alerts
def process_alerts(db_path, weights, hash_file, input_file, output_file):
    """Process merged alerts data for severity calculation."""
    global total_to_process, total_processed
    try:
       
        results = []
 
        # Open the input file once to avoid repeated reads
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            rows = list(reader)
            total_to_process = len(rows)
           
            logging.info(f"Processing {total_to_process} for alert severity calculation.")
           
            # Prepare row data for severity calculation
            for row in rows:
                domain = row.get("Domain")
 
                # Calculate severity
                alert_severity = calculate_severity(row, weights)
 
                # Classify severity
                severity_level = classify_severity(alert_severity)
 
                # Append the result for the current domain
                results.append({
                    "Domain": domain,
                    "Alert Severity": round(alert_severity, 2),
                    "Severity Level": severity_level
                })
 
                total_processed += 1
                progress_percentage = round((total_processed / total_to_process) * 100, 2)
                if progress_percentage % 5.0 == 0:
                    logging.info(f"Total rows processed: {total_processed}/{total_to_process} ({progress_percentage}%)")
               
               
                # Insert into the database
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR IGNORE INTO alerts (alert_name, alert_severity, severity_level, timestamp) VALUES (?, ?, ?, ?)",
                    (domain, alert_severity, severity_level, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
                conn.close()
       
        # Write results
        write_results_to_file(results, input_file, output_file)
 
        # After processing, update the hash file
        new_hash = compute_file_hash(db_path)
        with open(hash_file, "w") as hf:
            hf.write(new_hash)
 
    except Exception as e:
        logging.error(f"Error processing alerts from merged data: {e}")
 
def write_results_to_file(results, input_file, output_file):
    """
    Write results to the CSV file in a clean and proper format.
    Appends to the file if new results exists else the file remain same.
    """
    try:
        results_dict = {result["Domain"]: result for result in results}
       
        #Define the header
        new_headers = ["Domain", "Alert Severity", "Severity Level"]
        updated_rows = []
       
        # Read the existing CSV file
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
            # Read the CSV into a dictionary
            reader = csv.DictReader(infile)
           
            # Get the existing headers from the input file
            existing_headers = reader.fieldnames
 
            # Combine existing headers with the new ones, ensuring no duplicates
            all_headers = existing_headers + [header for header in new_headers if header not in existing_headers]
           
            # Get the existing rows from the input file
            for row in reader:
                domain = row.get("Domain", "").strip()
               
               
                # If the domain matches one of the new data, update the row
                if domain in results_dict:
                   
                    # Get the corresponding new data and update the row
                    matched_data = results_dict[domain]
                   
                    row["Alert Severity"] = matched_data.get("Alert Severity", row.get("Alert Severity", "Null"))
                    row["Severity Level"] = matched_data.get("Severity Level", row.get("Severity Level", "Null"))
 
                else:
                   
                    # If no match is found, fill with empty values
                    row["Alert Severity"] = "0.5"
                    row["Severity Level"] = "Medium"
 
                updated_rows.append(row)
 
 
        # Write the updated data with the new headers to the output file
        with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=all_headers)
           
            # Write the header row (including the new columns)
            writer.writeheader()
           
            # Write the rows
            writer.writerows(updated_rows)
 
 
        logging.info(f"Results written to output file: {output_file}")
       
    except Exception as e:
        logging.error(f"Error writing to output file {output_file}: {e}")
 
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
 
 
 
 
# Main execution
def main(new_session, input_file=None, customer_id=None, customer_name=None):
   
    try:
        global run_id
        if new_session == "False":
            run_id = set_starting_point("Alert Severity")
        else:
            run_id = fetch_run_id("Alert Severity")
       
       
        code_name = "Alert_Severity"
        base_name = f"{code_name}_{customer_name}_{customer_id}"
   
        # Handle file paths
        log_file_path = handle_files(base_name, ".log", log_dir)
        output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
        db_path = handle_files(f"{run_id}_{base_name}", ".db", db_dir)
        hash_file = os.path.join(hash_dir, f"{base_name}_db_hash.txt")
 
   
        # Reinitialize logging with updated log filename
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file_path, mode='a', encoding='utf-8')  # Only log to file
            ]
        )
        logging.info(f"Logging system initialized. Log file: {log_file_path}")
       
        if not input_file:
            input_file = detect_latest_file(output_dir, "Analytical_Attributes")
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
       
        # Check if the DB needs to be updated based on hash comparison
        if check_and_update_hash(db_path, hash_file):
            # Initialize DB if needed
            init_db(db_path)
       
   
        weights = {
            "name_server": 1.0,
            "mail_server": 1.0,
            "registrar": 1.0,
            "blacklisted": 1.0,
            "age_of_registration": 1.0,
            "directory_listing": 1.0,
            "ssl": 1.0,
            "login_page": 1.0,
            "port": 1.0
        }
       
       
       
   
        start_time = timeit.default_timer()
        # Process alerts
        process_alerts(db_path, weights, hash_file, input_file, output_file)
        end_time = timeit.default_timer()
        execution_time = end_time - start_time
        format_execution_time = lambda t: f"{t:.2f} seconds" if t < 60 else (f"{t / 60:.2f} minutes" if t < 3600 else f"{t / 3600:.2f} hours")
       
        update_hash_file(hash_file, db_path)
       
        if total_to_process == total_processed:
            logging.info("Code executed successfully at 100%.")
            integrate_log_updates("Alert Severity", run_id, success=True)
   
        print(f"Alerts processed successfully. Results saved to {output_file}.")
        logging.info(f"Alerts processed successfully. Results saved to {output_file}.")
        logging.info(f"Execution time: {format_execution_time(execution_time)}")
   
    except KeyboardInterrupt:
        # Calculate progress based on processed domains
        progress = round((total_processed / total_to_process) * 100, 2) if total_to_process else 0
        logging.error(f"Code was interrupted at {progress}%.")
   
        # Update logs and tracker files with accurate progress
        integrate_log_updates(
            "Alert Severity",
            run_id,
            interrupted=True,
            progress=progress
        )
        print(f"Execution interrupted at {progress}% completion.")
        sys.exit(1)
   
 
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python Alert_Severity_Computation.py <customer_id> <customer_name>")
        sys.exit(1)
 
    customer_id = sys.argv[1]
    customer_name = sys.argv[2]
    new_session = sys.argv[3]
    main(new_session, input_file=None, customer_id=customer_id, customer_name=customer_name)
 
 
 