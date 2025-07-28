import os
import sys
import csv
import sqlite3
import logging
import configparser
import hashlib
from datetime import datetime
import pandas as pd

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")


# Ensure directory exists
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
    except Exception as e:
        print(f"Error initializing logging: {e}")
        sys.exit(1)
 
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
 


# Compute and store the hash of a file
def compute_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

# Check if database file hash has changed
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


# Load data from CSV
columns = ["Run_id", "Customer_id", "Timestamp", "Domain", "Subdomain"]

def load_data_from_csv(file_path):
    if not os.path.exists(file_path):
        logging.warning(f"File {file_path} does not exist.")
        return pd.DataFrame(columns=columns)

    if os.path.getsize(file_path) == 0:
        logging.warning(f"File {file_path} is empty.")
        return pd.DataFrame(columns=columns)

    try:
        df = pd.read_csv(file_path, encoding='utf8')

        if df.empty:
            logging.warning(f"File {file_path} has no valid data.")
            return pd.DataFrame(columns=columns)

        # Ensure Run_id is always two digits
        df['Run_id'] = df['Run_id'].astype(str).apply(lambda x: f"{int(x):02d}")
        
        logging.info(f"Loaded {len(df)} rows from {file_path}")
        return df
    except pd.errors.EmptyDataError:
        logging.error(f"No data found in {file_path}. Returning an empty DataFrame.")
        return pd.DataFrame(columns=columns)
    except Exception as e:
        logging.error(f"Error loading data from {file_path}: {e}")
        return pd.DataFrame(columns=columns)

# Write data to CSV
def write_data_to_csv(file_path, data):
    try:
        data.groupby('Domain').last().reset_index()
        data.to_csv(file_path, index=False, encoding='utf8')
        logging.info(f"Results written to CSV file: {file_path}")
    except Exception as e:
        logging.error(f"Error writing results to CSV file {file_path}: {e}")
        raise
 
# Insert data into the database
def insert_data_into_db(db_file, data):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS consolidated_data (
                    domain TEXT PRIMARY KEY
                )
            ''')

            data.to_sql('consolidated_data', conn, if_exists='replace', index=False)
            logging.info(f"Database updated with {len(data)} rows: {db_file}")
    except Exception as e:
        logging.error(f"Error updating database {db_file}: {e}")
        raise

def remove_duplicates(file_path):
    try:
        # Read the CSV file with DictReader
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            fieldnames = reader.fieldnames  # Get the column names from the file

        # Use a dictionary to store rows with unique domains
        unique_rows = {}
        for row in rows:
            domain = row['Domain']  # Assuming "Domain" is the header name for the domain column
            unique_rows[domain] = row  # Keep only the last occurrence of each domain

        # Write back the unique rows to the same file
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()  # Write the header
            writer.writerows(unique_rows.values())  # Write the unique rows
    
    except Exception as e:
        logging.error(f"Error: {e}")


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
def main(input_files, customer_id, customer_name):
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Paths from Config.ini
    log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
    output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
    db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
    hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='HASHES'))

    # Ensure directories exist
    ensure_directory_exists(log_dir)
    ensure_directory_exists(output_dir)
    ensure_directory_exists(db_dir)
    ensure_directory_exists(hash_dir)  # Ensure HASHES directory exists

    base_name = f"Consolidator_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)

    # Update logging to use the actual log file
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    setup_logging(log_file)

    logging.info("Starting script execution.")
    logging.info("Loading input files: %s", input_files)
    logging.info("Customer ID: %s, Customer Name: %s", customer_id, customer_name)

    run_id = fetch_run_id("Consolidator")
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", output_dir)
    db_file = handle_files(f"{run_id}_{base_name}", ".db", db_dir)

    # Hash file for the database
    hash_file = os.path.join(hash_dir, f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_hash.txt")

    # Check if database file needs to be updated
    if check_and_update_hash(db_file, hash_file):
        # ✅ Initial merge with the first CSV
        merged_df = pd.read_csv(input_files[0])

        # ✅ Convert `Run_id` to string and format it to always be two digits
        merged_df['Run_id'] = merged_df['Run_id'].astype(str).str.zfill(2)

        # ✅ Iterating through the remaining CSV files
        for file_path in input_files[1:]:
            df = pd.read_csv(file_path)

            if df.empty:
                continue

            # ✅ Ensure `Run_id` is a string in both DataFrames before merging
            df['Run_id'] = df['Run_id'].astype(str).str.zfill(2)

            merged_df = merged_df.merge(df, on=['Run_id', 'Customer_id', 'Timestamp', 'Domain'], how='outer')

        # ✅ Ensure `Run_id` is properly formatted before saving
        merged_df['Run_id'] = merged_df['Run_id'].astype(str).str.zfill(2)

        # ✅ Save the cleaned DataFrame
        write_data_to_csv(output_file, merged_df)
        remove_duplicates(output_file)
        insert_data_into_db(db_file, merged_df)

        update_hash_file(db_file, hash_file)

        logging.info(f"Consolidation completed successfully with {merged_df.shape[0]} unique domains.")
        logging.info(f"Log File: {log_file}")
        logging.info(f"Output File: {output_file}")
        logging.info(f"Database File: {db_file}")
        logging.info(f"Hash File: {hash_file}")

        print(f"Consolidation completed successfully with {merged_df.shape[0]} unique domains.")
        print(f"Log File: {log_file}")
        print(f"Output File: {output_file}")
        print(f"Database File: {db_file}")
        print(f"Hash File: {hash_file}")
    else:
        logging.info("No updates required, as the database is unchanged.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python Consolidator.py <customer_id> <customer_name>")
        sys.exit(1)

    input_files = sys.argv[1:-2]
    customer_id = sys.argv[-2]
    customer_name = sys.argv[-1]
    new_session = "True"
    main(input_files, customer_id, customer_name)