import sys
import os
import logging
import configparser
from datetime import datetime
import csv
import hashlib
import sqlite3

# Initialize config parser
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Base directory for current script
base_dir = os.path.dirname(os.path.abspath(__file__))

input_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'input_dir', fallback='Inputs')))
log_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs')))
output_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs')))
utility_output_dir = os.path.abspath(os.path.join(base_dir, '..', config.get('DEFAULT', 'utility_output_dir', fallback='Utility_Outputs')))

# Ensure directories exist
os.makedirs(input_dir, exist_ok=True)
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)


def ensure_directory_exists(directory):
    """
    Ensures that the given directory exists. If not, it creates the directory.
    """
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        logging.info(f"Created directory: {directory}")
    else:
        logging.info(f"Directory already exists: {directory}")


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
def configure_paths(customer_id, customer_name, run_id):
    """
    Generates paths for log, output, database, and hash files based on the configuration.
    """
    codename = "Unique_Blacklisted_IPs"
    base_name = f"{codename}_{customer_name}_{customer_id}"
    log_file = handle_files(base_name, ".log", log_dir)
    output_file = handle_files(f"{run_id}_{base_name}", ".csv", utility_output_dir)
    return log_file, output_file


def create_initial_files(output_file):
    """
    Creates the output file with the header if it does not already exist.
    """
    headers = ["Run_id", "Customer_id", "Timestamp", "Domain", "IP"]
    
    # Check if the output file exists
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        with open(output_file, 'w', newline='', encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
        logging.info(f"Created output file with headers: {output_file}")
    else:
        logging.info(f"Output file already exists and is not empty: {output_file}")


def insert_data_to_db(db_file, data):
    """
    Ensures the database table exists and inserts unique data rows.
    """


    try:
        conn = sqlite3.connect(db_file, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()

        # Create the table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS unique_blacklisted_ips (
                            domain TEXT,
                            ip TEXT PRIMARY KEY
                        )''')

        data_to_insert = [{
            "Domain": item["Domain"],
            "IP": item["IP"]
        } for item in data]

        for item in data_to_insert:
            cursor.execute('''
                INSERT OR IGNORE INTO unique_blacklisted_ips (domain, ip)
                VALUES (?, ?)
            ''', (item["Domain"], item["IP"]))

        conn.commit()

    except Exception as e:
        logging.error(f"Error inserting data to database: {str(e)}")
    finally:
        conn.close()
    
 
def remove_duplicates(file_path):
    """
    Reads the existing file and removes duplicates based on domain.
    """
    seen = set()
    unique_rows = []
 
    with open(file_path, 'r', newline='', encoding="utf8") as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            if row['IP Address'] not in seen:
                unique_rows.append(row)
                seen.add(row['IP Address'])
    return unique_rows
 
def append_to_file(output_file, results):
    """Append data to a file without overwriting existing results."""
    headers = ["Run_id", "Customer_id", "Timestamp", "IP", "Domain"]
    
    # Add additional columns to the data
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    data_to_append = [{
        "Run_id": str(int(run_id)).zfill(2),
        "Customer_id": customer_id,
        "Timestamp": timestamp,
        "IP": data["IP"],
        "Domain": data["Domain"],
    } for data in results]

    # Check if the output file exists
    file_exists = os.path.exists(output_file)
    
    # Read existing rows before opening the file in append mode
    existing_rows = remove_duplicates(output_file) if file_exists else []
    new_data = [row for row in data_to_append if row["Domain"] not in {d["Domain"] for d in existing_rows}]
    
    # Append to file in append mode
    with open(output_file, 'a', newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        
        # Write headers only if the file does not already exist or empty
        if not file_exists or os.path.getsize(output_file) == 0:
            writer.writeheader()
        
        # Write rows to the file
        writer.writerows(new_data)



def process_unique_blacklisted_ips(input_file, output_file):
    
    try:
        # Read the input file and collect IPs
        with open(input_file, 'r', newline='', encoding="utf8") as infile:
            reader = csv.DictReader(infile)
            ip_counts = {}
            data = []
            for row in reader:
                if row["Blacklisted"].lower() == "yes":
                    ip = row['IP Address']
                    domain = row['Domain']
                    if ip not in ip_counts:
                        ip_counts[ip] = []
                    ip_counts[ip].append(domain)
                    data.append({"Domain": domain, "IP": ip})

        # Filter out non-unique IPs
        unique_data = [item for item in data if len(ip_counts[item["IP"]]) == 1]

        if not unique_data:
            logging.info("No unique blacklisted IPs found. Exiting without processing.")
            print("No unique blacklisted IPs found.")
            return
        
        # Append data to the output file
        append_to_file(output_file, unique_data)
    except FileNotFoundError as e:
        logging.error(f"File not found: {str(e)}")
    except Exception as e:
        logging.error(f"Error processing ip domain mapping: {str(e)}")
def main(customer_id, customer_name):
    """
    Main execution function for the unique_blacklisted_ips.
    """
    
    try:
        log_file, output_file = configure_paths(customer_id, customer_name, run_id)
        setup_logging(log_file)
        
        create_initial_files(output_file)
        
        process_unique_blacklisted_ips(input_file, output_file)

        logging.info(f"Unique blacklisted IPs utility successfully. Results saved to {output_file}.")
    except Exception as e:
        logging.error(f"Error in main function: {str(e)}")
        return

if __name__ == "__main__":
    customer_id = sys.argv[1]
    customer_name = sys.argv[2]
    run_id = sys.argv[3]
    input_file = sys.argv[4]

    main(customer_id, customer_name)