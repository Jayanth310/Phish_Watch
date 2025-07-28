import os
import logging
import sqlite3
import csv
from datetime import datetime
import configparser
import pandas as pd
import string
import sys
import hashlib

global total_processed
total_processed = 0

global customer_name
 
# Function to ensure directory exists
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
 
 
# Read configuration from config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "..", 'Config', 'Config.ini'), encoding="utf8")
 
# Paths from Config.ini
base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
input_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'input_dir', fallback='Inputs'))
hash_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'hash_dir', fallback='Hashes'))
 
# Ensure directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
 
 
# Function to handle files and update timestamps
def handle_files(codename, customer_id, customer_name, file_type, directory):
    existing_files = [
        f for f in os.listdir(directory) if f.startswith(f"{codename}_{customer_name}_{customer_id}") and f.endswith(file_type)
    ]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if existing_files:
        existing_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
        latest_file = existing_files[0]
        new_file_name = f"{codename}_{customer_name}_{customer_id}_{timestamp}{file_type}"
        old_file_path = os.path.join(directory, latest_file)
        new_file_path = os.path.join(directory, new_file_name)
        os.rename(old_file_path, new_file_path)
        return new_file_path
    else:
        new_file_name = f"{codename}_{customer_name}_{customer_id}_{timestamp}{file_type}"
        return os.path.join(directory, new_file_name)
 
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

# Update hash file
def update_hash_file(db_file, hash_file):
    new_hash = compute_file_hash(db_file)
    with open(hash_file, "w") as hf:
        hf.write(new_hash)
    logging.info(f"Hash updated in {hash_file}")




# Initialize the database
def init_db(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS variations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            variation TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
 
 
# Variation rules
def adjacent_character_swapping(domain):
    variations = []
    for i in range(len(domain) - 1):
        swapped = list(domain)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        variations.append(''.join(swapped))
    return variations
 
 
def character_replacement(domain):
    similar_characters = {
        'a': '4', 'b': '6', 'e': '3', 'g': '9', 'i': '1', 'o': '0', 's': '5', 't': '7', 'z': '2'
    }
    variations = []
    for char in domain:
        if char in similar_characters:
            variations.append(domain.replace(char, similar_characters[char]))
    return variations
 
 
def doubling_characters(domain):
    variations = []
    for i in range(len(domain)):
        doubled = domain[:i] + domain[i] * 2 + domain[i+1:]
        variations.append(doubled)
    return variations
 
 
def omission_of_characters(domain):
    variations = []
    for i in range(len(domain)):
        omitted = domain[:i] + domain[i+1:]
        variations.append(omitted)
    return variations
 
 
def reversing_characters(domain):
    return [domain[::-1]]
 
 
def vowel_substitution(domain):
    vowel_subs = {
        'a': ['e', 'i', 'o', 'u'],
        'e': ['a', 'i', 'o', 'u'],
        'i': ['a', 'e', 'o', 'u'],
        'o': ['a', 'e', 'i', 'u'],
        'u': ['a', 'e', 'i', 'o'],
    }
    variations = []
    for i, char in enumerate(domain):
        if char in vowel_subs:
            for replacement in vowel_subs[char]:
                new_domain = domain[:i] + replacement + domain[i+1:]
                variations.append(new_domain)
    return variations
 
 
def keyboard_proximity_typos(domain):
    proximity_map = {
        'q': 'w', 'w': 'q', 'e': 'r', 'r': 'e', 't': 'y', 'y': 't', 'u': 'i',
        'i': 'u', 'o': 'p', 'p': 'o', 'a': 's', 's': 'a', 'd': 'f', 'f': 'd',
        'g': 'h', 'h': 'g', 'j': 'k', 'k': 'j', 'l': ';', ';': 'l',
        'z': 'x', 'x': 'z', 'c': 'v', 'v': 'c', 'b': 'n', 'n': 'b', 'm': ',',
        ',': 'm', '.': '/'
    }
    variations = []
    for char in domain:
        if char in proximity_map:
            variations.append(domain.replace(char, proximity_map[char]))
    return variations
 
 
def random_number_insertion(domain):
    variations = []
    for i in range(len(domain) + 1):
        for num in range(10):
            new_domain = domain[:i] + str(num) + domain[i:]
            variations.append(new_domain)
    return variations
 
 
def random_letter_insertion(domain):
    variations = []
    for i in range(len(domain) + 1):
        for letter in string.ascii_lowercase:
            new_domain = domain[:i] + letter + domain[i:]
            variations.append(new_domain)
    return variations
 
 
def add_common_prefixes(domain):
    prefixes = ['www.', 'mail.', 'secure.', 'login.', 'support.']
    return [prefix + domain for prefix in prefixes]
 
 
def add_common_suffixes(domain):
    suffixes = ['.com', '.net', '.org', '.info', '.co', '.biz']
    return [domain + suffix for suffix in suffixes]
 
 
def duplicate_words(domain):
    parts = domain.split('.')
    if len(parts) > 1:
        duplicated = [parts[0] + parts[0] + '.' + parts[1]]
    else:
        duplicated = [parts[0] + parts[0]]
    return duplicated
 
 
def hyphen_insertion(domain):
    variations = []
    for i in range(1, len(domain)):
        if domain[i].isalnum() and domain[i - 1].isalnum():
            variations.append(domain[:i] + '-' + domain[i:])
    return variations
 
 
# Generate variations
def generate_variations(domain):
    variations = set()
    variations.update(adjacent_character_swapping(domain))
    variations.update(character_replacement(domain))
    variations.update(doubling_characters(domain))
    variations.update(omission_of_characters(domain))
    variations.update(reversing_characters(domain))
    variations.update(vowel_substitution(domain))
    variations.update(keyboard_proximity_typos(domain))
    variations.update(random_number_insertion(domain))
    variations.update(random_letter_insertion(domain))
    variations.update(add_common_prefixes(domain))
    variations.update(add_common_suffixes(domain))
    variations.update(duplicate_words(domain))
    variations.update(hyphen_insertion(domain))
    return list(variations)

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

def integrate_log_updates(option_name, run_id, success=False, interrupted=False, progress=0):
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
        new_master_row = [_run_id, customer_id, customer_name, timestamp, option_name, status]
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
 

# Main function
def main(customer_details_file, customer_id, new_session):
    codename = "Variations_Generator"
 
    try:
        # Fetch customer details
        customer_details = pd.read_csv(customer_details_file)
        customer_row = customer_details[customer_details['customer_id'].str.upper() == customer_id.upper()]
 
        if customer_row.empty:
            raise ValueError(f"No details found for Customer ID: {customer_id}")
        global customer_name
        customer_name = customer_row.iloc[0]['customer_name']
        input_strings = customer_row.iloc[0]['strings']
        if isinstance(input_strings, str):
            input_strings = input_strings.split(',')
        else:
            raise ValueError("Invalid format in strings column for the customer.")
        
        run_id = fetch_run_id("Variation Generator")
 
        # Handle file paths
        log_file = handle_files(codename, customer_id, customer_name, ".log", log_dir)
        output_file = handle_files(f"{run_id}_{codename}", customer_id, customer_name, ".csv", output_dir)
        db_file = handle_files(f"{run_id}_{codename}", customer_id, customer_name, ".db", db_dir)
        hash_file = handle_files(f"{codename}", customer_id, customer_name, "_hash.txt", hash_dir)

        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, mode='a', encoding='utf-8')  # Only log to file
            ]
        )
        logging.info("Variations Generator started.")
 
        init_db(db_file)
 
        total_variations = 0
        list_of_variations = []
        
        for string in input_strings:
            string = string.strip()
            if not string:
                continue
            variations = generate_variations(string)
            total_variations += len(variations)
            list_of_variations.extend(variations)
        
        global total_processed
        total_processed = total_variations
        
        data = []
        for variation in list_of_variations:
            data.append({
                'Run_id': run_id,
                'Customer_id': customer_id,
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Variation': variation
            })
        
        headers = ['Run_id', 'Customer_id', 'Timestamp', 'Variation']
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.DictWriter(csvfile, fieldnames=headers)
            
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                csv_writer.writeheader()
            
            csv_writer.writerows(data)

        update_hash_file(db_file, hash_file)
        integrate_log_updates("Variations Generator", run_id, new_session)
        logging.info(f"Generated {total_variations} variations and saved to {output_file}.")
        print(f"Success: {total_variations} variations generated. Output saved to {output_file}")
 
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {str(e)}")
 
 
# Wrapper integration
if __name__ == "__main__":
    customer_details_file = os.path.join(input_dir, "Customer_details.csv")

    if len(sys.argv) != 3:
        print("Usage: variation_generator.py <customer_id>")
        sys.exit(1)
    customer_id = sys.argv[1]
    new_session = sys.argv[2]
    main(customer_details_file, customer_id, new_session)