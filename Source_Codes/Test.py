import os
import logging
import sqlite3
import datetime
import argparse
import csv
import configparser
import pandas as pd
 
# Ensure directory exists function
def ensure_directory_exists(path):
    """Ensure the directory exists; create it if it doesn't."""
    if not os.path.exists(path):
        os.makedirs(path)
 
# Read configuration from Config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'Config', 'Config.ini'), encoding="utf8"))
 
# Get base directory for the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
 
# Fetch paths from the config file
log_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'log_dir', fallback='Logs'))
output_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'output_dir', fallback='Outputs'))
db_dir = os.path.join(base_dir, '..', config.get('DEFAULT', 'db_dir', fallback='DB'))
 
# Ensure required directories exist
ensure_directory_exists(log_dir)
ensure_directory_exists(output_dir)
ensure_directory_exists(db_dir)
 
# Set up logging
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"alert_severity_logs_{timestamp}.log"
log_file_path = os.path.join(log_dir, log_filename)
 
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file_path, mode='a', encoding='utf-8')  # Only log to file
    ]
)
 
logging.info("Logging system initialized. Log file created at: %s", log_file_path)
 
# Function to create database path
def get_db_path(customer_id, customer_name,timestamp):
    """Generates a unique database path based on customer ID and name."""
    db_filename = f"alert_severity_{customer_id}_{customer_name}_{timestamp}.db"
    return os.path.join(db_dir, db_filename)
 
# Initialize database
def init_db(db_path):
    """Initialize the database for storing alerts."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT,
            alert_severity INTEGER,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()
 
def is_numeric(value):
    """Check if the value is a valid number."""
    try:
        int(value)
        return True
    except ValueError:
        return False
def safe_int(value):
    """Safely converts a value to an integer, returning 0 for invalid conversions."""
    try:
        # Check if the value can be interpreted as an integer (1 or 0)
        if isinstance(value, str):
            if value.strip().lower() in ["no", "null", "false", "0"]:
                return 0
            elif value.strip().lower() in ["yes", "1", "true"]:
                return 1
        return int(value)
    except ValueError:
        return 0  # Return 0 for invalid or non-numeric values
 
def calculate_severity(row, weights):
    """Calculates alert severity based on row attributes and weights."""
    base_score = 2  # Base score for all domains
    total_weight = sum(weights.values())
    incremental_score = (
        weights["base"] * base_score +
        weights["resolution_server"] * safe_int(row.get("Resolution Server Exists", 0)) +
        weights["multiple_ips"] * safe_int(row.get("More Than 1 IP", 0)) +
        weights["mail_server"] * safe_int(row.get("Mail Server Exists", 0)) +
        weights["login_page"] * safe_int(row.get("Login Page Exists", 0))
    )
    weighted_average = incremental_score / total_weight
    return weighted_average
 
def classify_severity(alert_severity):
    """Classifies severity based on alert severity score."""
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
 
def process_alerts(input_file, output_file, db_path, weights):
    try:
        # Check the file extension and read the file accordingly
        file_extension = os.path.splitext(input_file)[1].lower()
 
        if file_extension == '.csv':
            data = pd.read_csv(input_file)
        elif file_extension == '.xlsx':
            data = pd.read_excel(input_file)
        else:
            raise ValueError("Unsupported file format. Please provide a .csv or .xlsx file.")
 
        # Ensure headers are correctly processed
        if data.empty or 'Domain' not in data.columns:
            raise ValueError("Input file does not have the correct headers or is empty.")
 
        # Create database and ensure table is initialized
        init_db(db_path)
 
        # Iterate through rows to process alerts
        for index, row in data.iterrows():
            try:
                # Process only valid rows; skip headers or invalid data
                if pd.isna(row['Domain']):
                    continue
 
                # Calculate severity score using the new function
                alert_severity = calculate_severity(row, weights)
 
                # Classify severity
                alert_classification = classify_severity(alert_severity)
 
                # Insert valid data into the database
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO alerts (alert_name, alert_severity, timestamp) VALUES (?, ?, ?)",
                               (row['Domain'], alert_classification, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                conn.commit()
                conn.close()
 
            except Exception as row_error:
                logging.error(f"Error processing row {row.to_dict()}: {row_error}")
 
        # Save output to a new file (Excel or CSV based on input file type)
        if file_extension == '.csv':
            data.to_csv(output_file, index=False)
        elif file_extension == '.xlsx':
            with pd.ExcelWriter(output_file) as writer:
                data.to_excel(writer, index=False)
       
        logging.info(f"Processed alerts saved to {output_file}")
 
    except Exception as e:
        logging.error(f"Error processing alerts: {e}")
 
# Alert severity computation
def compute_alert_severity(input_file, output_file, db_path, weights):
    """Compute alert severity based on input file and save to the output file."""
    try:
        # Read the input file (CSV or XLSX)
        file_extension = os.path.splitext(input_file)[1].lower()
 
        if file_extension == '.csv':
            data = pd.read_csv(input_file)
        elif file_extension == '.xlsx':
            data = pd.read_excel(input_file)
        else:
            raise ValueError("Unsupported file format. Please provide a .csv or .xlsx file.")
 
        # Normalize column names to lowercase
        data.columns = map(str.lower, data.columns)
 
        # Validate if the required columns exist
        required_columns = ['domain', 'name server', 'mail server', 'registrar', 'ssl', 'login page']
        for col in required_columns:
            if col not in data.columns:
                logging.error(f"Input file is missing required column: {col}")
                print(f"Error: Input file is missing required column: {col}. Exiting.")
                return
 
        # Prepare output file
        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['Domain', 'Alert Severity', 'Severity Level'])  # Output headers
 
            # Prepare database connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
 
            for idx, row in data.iterrows():
                try:
                    # Extract domain and attributes
                    domain = row['domain']
                    resolution_server_exists = 1 if row.get('name server', 'null') != "null" else 0
                    more_than_one_ip = 1 if ',' in str(row.get('name server', '')) else 0
                    mail_server_exists = 1 if row.get('mail server', 'null') != "null" else 0
                    ssl_enabled = 1 if row.get('ssl', 'no').strip().lower() == 'yes' else 0
                    login_page_exists = 1 if row.get('login page', 'no').strip().lower() == 'yes' else 0
 
                    # Calculate alert severity
                    row_data = {
                        "Resolution Server Exists": resolution_server_exists,
                        "More Than 1 IP": more_than_one_ip,
                        "Mail Server Exists": mail_server_exists,
                        "SSL": ssl_enabled,
                        "Login Page Exists": login_page_exists,
                    }
                    alert_severity = calculate_severity(row_data, weights)
 
                    # Classify severity level
                    severity_level = classify_severity(alert_severity)
 
                    # Write to output file
                    writer.writerow([domain, round(alert_severity, 2), severity_level])
 
                    # Insert into the database
                    cursor.execute(
                        "INSERT INTO alerts (alert_name, alert_severity, timestamp) VALUES (?, ?, ?)",
                        (domain, severity_level, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    )
 
                except Exception as e:
                    logging.warning(f"Skipping row {idx + 1} due to error: {e}")
                    continue
 
            # Commit changes to the database
            conn.commit()
            conn.close()
 
        logging.info(f"Processed alerts from {input_file}. Results saved to {output_file}.")
        print(f"Alerts processed successfully. Results saved to {output_file}.")
 
    except Exception as e:
        logging.error(f"Error processing alerts: {e}")
        print("An error occurred. Check the log file for details.")
 
def load_weights(config):
    """Load weights from the configuration file."""
    try:
        weights = {
            "base": float(config.get("Weights", "base", fallback=2.0)),
            "resolution_server": float(config.get("Weights", "resolution_server", fallback=1.0)),
            "multiple_ips": float(config.get("Weights", "multiple_ips", fallback=1.0)),
            "mail_server": float(config.get("Weights", "mail_server", fallback=1.0)),
            "website": float(config.get("Weights", "website", fallback=1.0)),
            "login_page": float(config.get("Weights", "login_page", fallback=1.0)),
            "blacklisted": float(config.get("Weights", "blacklisted", fallback=1.0)),
            "recent_creation": float(config.get("Weights", "recent_creation", fallback=1.0)),
            "risky_geography": float(config.get("Weights", "risky_geography", fallback=1.0)),
        }
        logging.info(f"Weights loaded successfully: {weights}")
        return weights
    except Exception as e:
        logging.error(f"Error loading weights from config: {e}")
        raise
 
 
# Main execution logic
def main():
    parser = argparse.ArgumentParser(description="Alert Severity Computation")
    parser.add_argument('input_file', type=str, help='The input file containing alert data (CSV or XLSX)')
    parser.add_argument('customer_id', type=str, help='Customer ID')
    parser.add_argument('customer_name', type=str, help='Customer Name')
 
    args = parser.parse_args()
 
    # Fetch customer details
    customer_id = args.customer_id
    customer_name = args.customer_name
 
    # Generate DB and output file paths
    db_path = get_db_path(customer_id, customer_name,timestamp)
    output_filename = f"alert_severity_{customer_id}_{customer_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output_file = os.path.join(output_dir, output_filename)
 
    # Initialize the database
    init_db(db_path)  # This ensures the alerts table exists before we use it
    logging.info(f"Database initialized at {db_path}")
 
    # Load weights dynamically from config
    weights = load_weights(config)
 
    # Run the computation
    compute_alert_severity(args.input_file, output_file, db_path, weights)
if __name__ == '__main__':
    main()
 
 