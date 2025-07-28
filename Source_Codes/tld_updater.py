import requests
import os
import logging
import csv
import sqlite3
import hashlib
from threading import Lock
import sys
from datetime import datetime
 
# Ensure directory exists function
def ensure_directory_exists(path):
    """Creates a directory if it does not exist."""
    if not os.path.exists(path):
        os.makedirs(path)
 
# Global lock for thread-safe file operations
file_lock = Lock()
 
# Configuration
TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, '..', 'Logs')
output_dir = os.path.join(base_dir, '..', 'Outputs')
db_dir = os.path.join(base_dir, '..', 'DB')
hash_dir = os.path.join(base_dir, '..', 'Hashes')
 
# Ensure directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
ensure_directory_exists(hash_dir)
 
# Function to handle file initialization and timestamp update
# Function to handle file initialization and timestamp update
def handle_files(base_name, file_type, directory):
    """
    Handle file initialization and timestamp updates for log, output, and DB files.
    If the file exists, update its timestamp; otherwise, create a new file with a timestamp.
 
    Args:
        base_name (str): The base name for the file (e.g., 'tld_updater').
        file_type (str): The file type/extension (e.g., '.csv', '.db', '.log').
        directory (str): The directory where the file resides.
 
    Returns:
        str: The updated file path.
    """
    # Modify this check to ensure that only the correct files are considered
    if file_type == ".csv":
        existing_files = [
            f for f in os.listdir(directory) if f.startswith("tld_updater") and f.endswith(".csv")
        ]
    else:
        # For other file types like .db or .log, consider them as usual
        existing_files = [
            f for f in os.listdir(directory) if base_name in f and f.endswith(file_type)
        ]

    if existing_files:
        # Use the latest file (sorted by modification time)
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = existing_files[0]
 
        # Rename with updated timestamp
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        old_file_path = os.path.join(directory, latest_file)
        new_file_path = os.path.join(directory, new_file_name)
 
        os.rename(old_file_path, new_file_path)
        logging.info(f"Updated file timestamp: {new_file_path}")
        return new_file_path
    else:
        # Create a new file with a timestamp
        new_file_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_type}"
        new_file_path = os.path.join(directory, new_file_name)
        if file_type == ".log":
            # Create an empty log file
            open(new_file_path, 'a').close()
        logging.info(f"Created new file: {new_file_path}")
        return new_file_path

 
# Function to set up logging
def setup_logging(log_file):
    """Sets up logging for the script."""
    try:
        ensure_directory_exists(os.path.dirname(log_file))
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
        logging.info("Logging initialized.")
    except Exception as e:
        print(f"Error setting up logging: {str(e)}")
        sys.exit(1)
 
# Function to create the database
def create_db(db_file):
    """Creates the database file and a table to store TLDs."""
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS tlds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tld TEXT UNIQUE
            )
        ''')
        conn.commit()
        conn.close()
        logging.info(f"Database created or verified at {db_file}.")
    except sqlite3.Error as e:
        logging.error(f"Error creating database: {str(e)}")
        sys.exit(1)

# Function to fetch TLD data
def fetch_tld_data():
    """Fetches the current list of TLDs from IANA's data source."""
    try:
        response = requests.get(TLD_URL, timeout=30)
        response.raise_for_status()  # Raises HTTPError for bad responses
        tld_list = response.text.splitlines()[1:]  # Skip the first line (comment)
        logging.info("Successfully fetched TLD data.")
        return tld_list
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching TLD data: {str(e)}")
        return []
 
# Function to merge data and deduplicate in the output file
def merge_and_deduplicate_output(file_path, tlds):
    """
    Merge new TLDs with existing ones, remove duplicates, and write back to the file.
 
    Args:
        file_path (str): The path to the output file.
        tlds (list): List of new TLDs to add.
 
    Returns:
        int: The total number of unique TLDs after merging.
    """
    existing_tlds = set()
 
    # Read existing TLDs from the file if it exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            existing_tlds = {row[0] for row in reader}
 
    # Merge and deduplicate TLDs
    updated_tlds = sorted(existing_tlds.union(set(tlds)))
 
    # Write updated TLDs back to the file
    with file_lock:
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            for tld in updated_tlds:
                writer.writerow([tld])
 
    logging.info(f"Merged and deduplicated TLDs written to {file_path}.")
    return len(updated_tlds)
 
# Function to update the database with TLDs
def update_db_with_tlds(db_file, tlds):
    """Updates the database with the fetched TLDs."""
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        for tld in tlds:
            c.execute('''
                INSERT OR IGNORE INTO tlds (tld) VALUES (?)
            ''', (tld,))
        conn.commit()
        conn.close()
        logging.info(f"Database updated with {len(tlds)} TLDs.")
    except sqlite3.Error as e:
        logging.error(f"Error updating database {db_file}: {str(e)}")
        sys.exit(1)
 
# Function to generate a hash for a file
def generate_file_hash(file_path):
    """Generates a hash for the given file."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"Error generating hash for {file_path}: {str(e)}")
        return None
 
# Function to handle hash file creation and comparison
def handle_hash_file(file_path, component_name):
    """
    Handles hash file creation and comparison.
 
    Args:
        file_path (str): The file to hash.
        component_name (str): The component name for naming the hash file.
 
    Returns:
        bool: True if the hash matches the previous run; False otherwise.
    """
    
    if not os.path.exists(file_path):
        return False
    
    current_hash = generate_file_hash(file_path)
    if not current_hash:
        return False
 
    # Generate hash file name
    hash_file_path = handle_files(component_name, "_hash.txt", hash_dir)
    # hash_file_name = f"{component_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hash"
    # hash_file_path = os.path.join(hash_dir, hash_file_name)
 
    # Check if a previous hash file exists
    existing_hash_files = [
        f for f in os.listdir(hash_dir) if f.startswith(component_name) and f.endswith("_hash.txt")
    ]
 
    if existing_hash_files:
        existing_hash_files.sort(key=lambda f: os.path.getmtime(os.path.join(hash_dir, f)), reverse=True)
        latest_hash_file = os.path.join(hash_dir, existing_hash_files[0])
        with open(latest_hash_file, 'r') as f:
            previous_hash = f.read().strip()
        if previous_hash == current_hash:
            logging.info("Hash matches the previous run. No updates needed.")
            return True
 
    # Save the current hash
    with open(hash_file_path, 'w') as f:
        f.write(current_hash)
    logging.info(f"New hash file created: {hash_file_path}")
    return False
 
# Main function to run the TLD updater
def run_tld_updater():
    """Main function to run the TLD updater."""
    # Handle file paths with updated timestamps
    log_file = handle_files("tld_updater", ".log", log_dir)
    output_file = handle_files("tld_updater", ".csv", output_dir)
    db_file = handle_files("tld_updater", ".db", db_dir)
 
    # Set up logging
    setup_logging(log_file)
 
    # Create database if it doesn't exist
    create_db(db_file)
 
 
    # Check hash to determine if updates are needed
    if handle_hash_file(output_file, "tld_updater"):
        logging.info("No changes detected in the TLD source. Exiting updater.")
        print("No updates needed.")
        return
 
    # Fetch TLDs from the source
    logging.info("Fetching TLD list...")
    tlds = fetch_tld_data()
 
    if not tlds:
        logging.warning("Failed to fetch TLDs.")
        print("Error: Failed to fetch TLDs.")
        return

    # Merge and deduplicate TLDs in the output file
    total_tlds = merge_and_deduplicate_output(output_file, tlds)
 
    # Update the database with new TLDs
    update_db_with_tlds(db_file, tlds)
    
    handle_hash_file(output_file, "tld_updater")
    
    print(f"Success: {total_tlds} TLDs fetched and updated.")
    logging.info(f"TLD updater completed successfully.")
 
if __name__ == "__main__":
    run_tld_updater()
 