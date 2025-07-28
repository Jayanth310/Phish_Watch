import dns.resolver
import concurrent.futures
import logging
import os
import sqlite3
import datetime
import configparser
from itertools import islice
import sys
import hashlib
 
# Ensure directory exists
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
# Set up logging
def setup_logging(log_file):
    """Sets up logging for the script."""
    try:
        # Ensure directory exists for logs
        ensure_directory_exists(os.path.dirname(log_file))

        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[logging.FileHandler(log_file, mode='a', encoding='utf-8')]  # Only log to file
        )
        logging.info("Logging initialized and active.")  # Test log
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

# Compare current file hash with the stored hash
def check_and_update_hash(db_file, hash_file):
    """Checks if the database file has been modified by comparing hashes."""
    if not os.path.exists(db_file):
        print("Database file does not exist. Creating new database...")
        return True  # Need to create/update the database

    # If hash file does not exist, create it and assume updates are needed
    if not os.path.exists(hash_file):
        print("Hash file does not exist. Creating hash file...")
        new_hash = compute_file_hash(db_file)
        with open(hash_file, "w") as hf:
            hf.write(new_hash)
        # print(f"Hash file created with hash: {new_hash}")
        return True  # Hash file was just created, so updates are needed

    # Compare current hash with stored hash
    current_hash = compute_file_hash(db_file)
    with open(hash_file, "r") as hf:
        stored_hash = hf.read().strip()

    if current_hash != stored_hash:
        print("Hash mismatch. Updates are required...")
        # Update the hash file after detecting changes
        with open(hash_file, "w") as hf:
            hf.write(current_hash)
        return True  # Updates are needed
    else:
        print("Hash matches. No updates needed...")
        return False

 
# Handle file initialization and timestamp updates
def handle_files(base_name, file_type, directory):
    """Handle file initialization and timestamp updates for log, output, and DB files."""
    existing_files = [
        f for f in os.listdir(directory) if base_name in f and f.endswith(file_type)
    ]
   
    if existing_files:
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = existing_files[0]
       
        new_file_name = f"{base_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        old_file_path = os.path.join(directory, latest_file)
        new_file_path = os.path.join(directory, new_file_name)
       
        os.rename(old_file_path, new_file_path)
        logging.info(f"Updated file timestamp: {new_file_path}")
        return new_file_path
    else:
        new_file_name = f"{base_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        new_file_path = os.path.join(directory, new_file_name)
        if file_type == ".log":
            open(new_file_path, 'a').close()  # Create the log file
        logging.info(f"Created new file: {new_file_path}")
        return new_file_path

# Initialize SQLite database and create table if necessary
def init_db(db_name):
    """Initialize the database and create the necessary table."""
    db_dir = os.path.dirname(db_name)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
   
    conn = sqlite3.connect(db_name, uri=True)  # Ensure database is writable
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS domain_check_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            status TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()
 
# Insert data into the database
def insert_data_to_db(db_name, domain, status):
    """Insert domain check result into the database."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_name, uri=True)  # Ensure database is writable
    c = conn.cursor()
    c.execute('''
        INSERT INTO domain_check_data (domain, status, timestamp)
        VALUES (?, ?, ?)
    ''', (domain, status, timestamp))
    conn.commit()
    conn.close()
 
# Check if a domain exists by querying multiple DNS records
def domain_exists(domain):
    """Check if a domain exists by querying various DNS records (A, NS, MX, AAAA, CNAME)."""
    record_types = ['A', 'NS', 'MX', 'AAAA', 'CNAME']
    for record_type in record_types:
        try:
            dns.resolver.resolve(domain, record_type)
            return True  # If any record exists, domain is considered "exists"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue  # Continue checking the next record type
    return False  # No records were found, so the domain doesn't exist
 
# Write the header to the output file if not already written
# def write_header_to_output(output_file):
#     """Write the header to the output file if not already written."""
#     if not os.path.exists(output_file):
#         with open(output_file, 'a', encoding="utf-8") as outfile:
#             outfile.write("Domains\n")
 
# Process a single batch of domains, check existence, and write results to the output file
def process_batch(batch, output_file, db_name):
    """Process a single batch of domains, check existence, and write results to the output file."""

    # Read existing domains from the output file to avoid duplicates
    if os.path.exists(output_file):
        with open(output_file, "r") as outfile:
            existing_domains = set(line.strip() for line in outfile)
    else:
        existing_domains = set()

    # Filter out already processed domains
    batch_to_process = [domain for domain in batch if domain not in existing_domains]
    if not batch_to_process:
        logging.info("No new domains to process in this batch.")
        return

    batch_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        results = {executor.submit(domain_exists, domain): domain for domain in batch_to_process}
 
        for future in concurrent.futures.as_completed(results):
            domain = results[future]
            exists = future.result()
            
            # Log and update results
            if exists:
                logging.info(f"{domain} - Exists")
                batch_results.append(f"{domain}\n")
                insert_data_to_db(db_name, domain, 'Exists')
            else:
                logging.info(f"{domain} - Does not exist")
                insert_data_to_db(db_name, domain, 'Does not exist')
        # Write new batch results to the output file
    if batch_results:
        with open(output_file, 'a', encoding="utf-8") as outfile:
            outfile.writelines(batch_results)

# Process domains in concurrent batches and write results
def process_domains(input_file, output_file, db_name, hash_file):
    """Process domains in concurrent batches and write results."""
    total_processed = 0
    try:
        # Check and update the hash before processing
        if check_and_update_hash(db_name, hash_file):
            # Write the header to the output file
            # write_header_to_output(output_file)

            # Process in batches
            with open(input_file, 'r') as infile:
                while True:
                    batches = [list(islice(infile, 10000)) for _ in range(5)]
                    batches = [batch for batch in batches if batch]
                    if not batches:
                        break

                    for batch in batches:
                        process_batch([line.strip() for line in batch if line.strip()], output_file, db_name)
                        total_processed += len(batch)

                        if total_processed % 10000 == 0:
                            logging.info(f"Total processed: {total_processed}")

            logging.info(f"Domain existence check completed. Total processed: {total_processed}")
            print(f"Domain existence check completed. Total processed: {total_processed}")
        else:
            logging.info("No updates required, skipping domain check.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(f"An error occurred: {e}")

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: python domain_existence_check.py <input_file> <customer_id> <customer_name>")

    input_file = sys.argv[1]
    customer_id = sys.argv[2]
    customer_name = sys.argv[3]

    # Setup directories
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
    output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
    db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
    hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hashes_dir', fallback='HASHES'))

    # Ensure directories exist
    ensure_directory_exists(log_dir)
    ensure_directory_exists(output_dir)
    ensure_directory_exists(db_dir)
    ensure_directory_exists(hash_dir)  # Ensure the HASHES directory exists

    # Get base name for files
    base_name = f"Domain_Existence_Check_{customer_name}_{customer_id}"

    # Handle files: log, output, and database
    log_file = handle_files(base_name, ".log", log_dir)
    output_file = handle_files(base_name, ".csv", output_dir)
    db_file = handle_files(base_name, ".db", db_dir)

    # Set up the hash file to store the hash of the database
    hash_file = os.path.join(hash_dir, f"{base_name}_db_hash.txt")

    # Update logging to use the actual log file
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Setup logging
    setup_logging(log_file)

    # Initialize DB
    init_db(db_file)

    # Process domains
    process_domains(input_file, output_file, db_file, hash_file)
