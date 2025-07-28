import configparser
import os
import logging
import subprocess
import sys
import csv
import pandas as pd 
import time
from datetime import datetime
from tabulate import tabulate
import shutil
import glob
import platform

system = platform.system().lower()

if system == "windows":
    use_python = "python"
else:
    use_python = "python3"

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'Config', 'Config.ini'), encoding="utf8")

# Access the specific section, e.g., "DEFAULT"
log_dir = config.get('DEFAULT', 'log_dir', fallback='Logs')
log_file = os.path.join(log_dir, "wrapper.log")

# Ensure log directory exists
if not os.path.exists(os.path.dirname(log_file)):
    os.makedirs(os.path.dirname(log_file))

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file, mode='a', encoding='utf-8')  # Only log to file
    ]
)

logging.info("Logging setup complete.")

def ensure_directory_exists(path):
    """Ensures the specified directory exists."""
    if not os.path.exists(path):
        os.makedirs(path)

def create_run_files():
    """Creates Run_Master and Run_Tracker files in the Input directory with specified headers."""
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    ensure_directory_exists(input_dir)
    
    run_master_path = os.path.join(input_dir, "Run_Master.csv")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")
    
    
    run_master_headers = ["Run_id", "Customer_id", "Customer_name", "Timestamp", "Component_Name", "Component_State", "Error_Type"]
    run_tracker_headers = ["Run_id", "Customer_id", "Customer_name", "Timestamp", "Component_Name", "Component_Status", "Processed"]

    try:
        # Create Run_Master file with headers if it doesn't exist
        if not os.path.exists(run_master_path):
            with open(run_master_path, "w", newline="", encoding="utf-8") as master_file:
                writer = csv.writer(master_file)
                writer.writerow(run_master_headers)
            logging.info(f"Created Run_Master file at {run_master_path}")

        # Create Run_Tracker file with headers if it doesn't exist
        if not os.path.exists(run_tracker_path):
            with open(run_tracker_path, "w", newline="", encoding="utf-8") as tracker_file:
                writer = csv.writer(tracker_file)
                writer.writerow(run_tracker_headers)
            logging.info(f"Created Run_Tracker file at {run_tracker_path}")
        
        
    except Exception as e:
        logging.error(f"Error creating run files: {str(e)}")
        print(f"An error occurred while creating run files. Check logs for details.")

def check_pending_runs():
    """Checks the Run_Tracker file for pending runs and returns the latest unique pending run for each component."""
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")
    
    pending_runs = []
    unique_components = {}
    
    if not os.path.exists(run_tracker_path):
        logging.info("Run_Tracker file not found. No pending runs exist.")
        return pending_runs
        
    try:
        with open(run_tracker_path, "r", newline="", encoding="utf-8") as tracker_file:
            reader = csv.DictReader(tracker_file)
            rows = []

            # Collect and sort rows based on Timestamp in descending order
            for row in reader:
                if row.get("Component_Name").strip() == "":
                    continue
                try:
                    timestamp = datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
                    rows.append({
                        "Run_id": row.get("Run_id"),
                        "Customer_id": row.get("Customer_id"),
                        "Customer_name": row.get("Customer_name"),
                        "Timestamp": timestamp,
                        "Component_Name": row.get("Component_Name").strip(),
                        "Component_Status": row.get("Component_Status").strip(),
                    })
                except (ValueError, KeyError) as e:
                    logging.warning(f"Skipping invalid row due to error: {e}")

            rows.sort(key=lambda x: x["Timestamp"])
            
            # Process rows for latest unique components
            for row in rows:
                component_name = row["Component_Name"]
                if row["Component_Status"] != "100%":
                    if component_name:
                        unique_components[component_name] = row
                else:  # Component status is "100%"
                    if component_name in unique_components:
                        del unique_components[component_name]

            # Convert unique_components back to a list
            pending_runs = [
                {
                    "Run_id": data["Run_id"],
                    "Customer_id": data["Customer_id"],
                    "Customer_name": data["Customer_name"],
                    "Timestamp": data["Timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Component_Name": data["Component_Name"],
                    "Component_Status": data["Component_Status"],
                }
                for data in unique_components.values()
            ]

        return pending_runs

    except Exception as e:
        logging.error(f"An error occurred while processing the Run_Tracker file: {e}")
        return pending_runs

def check_completed_runs():
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_master_path = os.path.join(input_dir, "Run_Master.csv")
    
    completed_runs = []
    
    if not os.path.exists(run_master_path):
        logging.info("Run_Master file not found. No pending runs exist.")
        return completed_runs
    
    try:
        with open(run_master_path, "r", encoding="utf8") as master_file:
            reader = csv.DictReader(master_file)
            
            # Collect and sort rows based on Timestamp in descending order
            for row in reader:
                if row.get("Component_Name").strip() == "":
                    continue
                try:
                    component_name = row["Component_Name"]
                    if str(row["Component_State"]).startswith("success"):
                        if component_name:
                            completed_runs.append(row)
                except (ValueError, KeyError) as e:
                    logging.warning(f"Skipping invalid row due to error: {e}")

            # rows.sort(key=lambda x: x["Timestamp"])
        return completed_runs
    except Exception as e:
        logging.error(f"An error occurred while processing the Run_Master file: {e}")
        return completed_runs

def generate_run_id():
    """Generates a sequential two-digit Run_ID."""
    global active_run_id
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_master_path = os.path.join(input_dir, "Run_Master.csv")

    if active_run_id is None:  # Generate new Run_ID only for new sessions
        if not os.path.exists(run_master_path):
            active_run_id = "01"
        else:
            with open(run_master_path, "r", newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                run_ids = [row["Run_id"] for row in reader if row["Run_id"].isdigit()]
                if run_ids:
                    last_run_id = int(max(run_ids))
                    active_run_id = f"{last_run_id + 1:02d}"  # Increment and format as two digits
                else:
                    active_run_id = "01"
    return active_run_id

def update_run_tracker(run_id, customer_id, customer_name):
    """Updates Run_Tracker.csv with relevant entries."""
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(run_tracker_path, "a", newline="", encoding="utf-8") as tracker_file:
            writer = csv.writer(tracker_file)
            # Add a row with empty Component_Status unless explicitly set
            writer.writerow([run_id, customer_id, customer_name, timestamp, "", "", ""])
        logging.info(f"Run_Tracker updated: Run_ID={run_id}, Customer_ID={customer_id}")
    except Exception as e:
        logging.error(f"Error updating Run_Tracker: {str(e)}")
        print("An error occurred while updating Run_Tracker. Check logs.")

def show_registered_customers():
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    customer_details_path = os.path.join(input_dir, "Customer_details.csv")
    customer_details = []
    try:
        with open(customer_details_path, "r", encoding="utf8") as cfile:
            reader = csv.DictReader(cfile)
            for row in reader:
                customer_detail = {
                    "customer_id": row["customer_id"],
                    "customer_name": row["customer_name"]
                }
                customer_details.append(customer_detail)
        
        data_for_tabulate = []
        for customer in customer_details:
            data_for_tabulate.append([customer['customer_id'], customer['customer_name']])
        
        print("\nRegistered Customers:\n")
        print(tabulate(data_for_tabulate, headers=["Customer ID", "Customer Name"], tablefmt="pretty"))
    except Exception as e:
        logging.error(f"Error while fetching registered customers details: {e}")

def show_pending_runs():
    pending_runs = check_pending_runs()
    
    if not pending_runs:
        print("\nNo pending runs listed here.")
        logging.info("No pending runs found.")
        return
    
    df = pd.DataFrame(pending_runs)
    keys = ['Run_id', 'Customer_id', 'Customer_name', 'Timestamp', 'Component_Name', 'Component_Status']
    data_for_tabulate = []
    for run in pending_runs:
        data_for_tabulate.append([run[key] for key in keys])
    print(f"\nAll pending runs:")
    print(tabulate(data_for_tabulate, headers=keys, tablefmt="pretty"))

def show_completed_run():
    completed_run = check_completed_runs()
    
    if not completed_run:
        print("\nNo completed runs listed here.")
        logging.info("No completed runs found.")
        return
    
    df = pd.DataFrame(completed_run)
    keys = ['Run_id', 'Customer_id', 'Customer_name', 'Timestamp', 'Component_Name', 'Component_State']
    data_for_tabulate = []
    for run in completed_run:
        data_for_tabulate.append([run[key] for key in keys])
    print(f"\nAll completed runs:")
    print(tabulate(data_for_tabulate, headers=keys, tablefmt="pretty"))

def check_component_pending_run(component_name):
    pending_runs = check_pending_runs()
    
    matching_runs = [run for run in pending_runs if component_name in run.get("Component_Name")]

    if not matching_runs:
        print(f"No pending run found for component: {component_name}")
        return False

    # Prepare table only for matching runs
    keys = ['Run_id', 'Customer_id', 'Customer_name', 'Timestamp', 'Component_Name', 'Component_Status']
    data_for_tabulate = [[run[key] for key in keys] for run in matching_runs]

    print("\nPending run found.\n")
    print(tabulate(data_for_tabulate, headers=keys, tablefmt="pretty"))
    
    while True:
        # Ask the user if they want to continue with this run
        user_input = input(f"\nDo you want to continue with this run (Component: {component_name})? (y/n): ")
        if user_input.lower() == 'y':
            return True
        elif user_input.lower() == 'n':
            return False
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

def start_new_run():
    """Handles starting a new run, including customer details and managing pending runs."""
    global active_run_id, active_customer_id, active_customer_name  # Declare global variables

    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_master_path = os.path.join(input_dir, "Run_Master.csv")
    customer_details_path = os.path.join(input_dir, "Customer_details.csv")

    # Step 1: Prompt for Customer_ID
    while True:
        try:
            active_customer_id = input("Enter Customer ID: ").strip().upper()
            if check_customer_id_exists(active_customer_id):
                # Fetch existing Customer_Name from Customer_details.csv
                with open(customer_details_path, "r", newline="", encoding="utf-8") as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        if row["customer_id"].strip().upper() == active_customer_id:
                            active_customer_name = row["customer_name"].strip()
                            break
                print(f"\nActive Customer ID: {active_customer_id}")
                print(f"Active Customer Name: {active_customer_name}")
                logging.info(f"Active Customer set: ID={active_customer_id}, Name={active_customer_name}")
                break
            else:
                print(f"Customer ID '{active_customer_id}' does not exist.")
                choice = input("Do you want to add it? (y/n): ").strip().lower()
                if choice == "y":
                    active_customer_name = input("Enter Customer Name: ").strip()
                    strings = input("Enter multiple strings separated by commas (e.g., string1,string2): ").strip()
                    add_new_customer_to_csv(active_customer_id, active_customer_name, strings)
                    logging.info(f"New Customer added: ID={active_customer_id}, Name={active_customer_name}")
                    break
                elif choice == "n":
                    print("Cannot proceed without a valid Customer ID. Please try again.")
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")
        except KeyboardInterrupt:
            return
        except Exception as e:
            logging.error(f"Error updating Run_Master: {str(e)}")
            print("An error occurred while updating Run_Master. Check logs.")

    # Step 2: Generate or Reuse Run_ID
    run_id = generate_run_id()
    # create_control_flag_file()
    # Step 3: Update Run_Master
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(run_master_path, "a", newline="", encoding="utf-8") as master_file:
            writer = csv.writer(master_file)
            writer.writerow([run_id, active_customer_id, active_customer_name, timestamp, "", ""])
        logging.info(f"Run_Master updated: Run_ID={run_id}, Customer_ID={active_customer_id}")
    except KeyboardInterrupt:
        return
    except Exception as e:
        logging.error(f"Error updating Run_Master: {str(e)}")
        print("An error occurred while updating Run_Master. Check logs.")

    # Step 4: Update Run_Tracker
    update_run_tracker(run_id, active_customer_id, active_customer_name)
    # Step 5: Display Menu Options and Handle Task Execution
    print(f"\nRun ID: {run_id} initialized for Customer ID: {active_customer_id}.")
    print(f"Select tasks to execute for Customer '{active_customer_name}' (Run ID: {run_id}):")
    while True:
        print("\nSelect an option:")
        for key, value in menu_options.items():
            print(f"{key}. {value}")
        try:
            choice = int(input("Enter your choice: "))
            if choice in menu_options:
                if choice == 12:  # Exit option
                    global active_run_id
                    active_run_id = None  # Reset Run_ID on exit
                    logging.info("User exited the session.")
                    return  # Exit to the main menu
                else:
                    is_pending = check_component_pending_run(menu_options[choice])
                    if not is_pending:
                        print("\nStarting new run.\n")
                        # Execute selected task and pass active session details
                        execute_option(choice, active_customer_id, active_customer_name, new_session=True)
                    else:
                        print("\nContinuing pending run.\n")
                        # Execute selected task and pass active session details
                        execute_option(choice, active_customer_id, active_customer_name, new_session=False)
            else:
                print("Invalid choice. Please select a valid option.")
        except KeyboardInterrupt:
            return
        except ValueError:
            print("Invalid input. Please enter a valid number.")
        except Exception as e:
            logging.error(f"Unexpected error during task selection: {str(e)}")
            print("An unexpected error occurred. Check logs.")

def complete_run():
    """Handles completing pending runs."""
    global active_customer_id, active_customer_name, active_run_id

    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    # run_control_flag_path = os.path.join(input_dir, "Phishwatch_Run_Control_Flag.csv")

    # Fetch data from control flag file
    # flag_data = []
    # try:
    #     with open(run_control_flag_path, "r", encoding="utf-8") as control_file:
    #         reader = csv.DictReader(control_file)
    #         flag_data = [row for row in reader if row["Status"] == "Stopped"]  # Only include "Stopped" runs
    # except Exception as e:
    #     logging.error(f"Error reading control flag file: {str(e)}")
    #     print("An error occurred while reading the control flag file. Check logs for details.")
    #     return

    while True:
        pending_runs = check_pending_runs()
        if not pending_runs:
            print("\nNo pending runs listed here. Please select Option 4.")
            logging.info("No pending runs found.")
            return

        # Filter pending_runs to include only those with a matching entry in flag_data
        valid_runs = []
        for run in pending_runs:
            # for flag_row in flag_data:
                # if run["Run_id"] == flag_row["Run_id"]:
                    valid_runs.append(run)
                    break  # Stop checking flag_data for this run once a match is found

        if not valid_runs:
            print("\nNo valid pending runs found that match the control flag data.")
            logging.info("No valid pending runs found that match the control flag data.")
            return

        # Prompt user for run_id
        while True:
            run_id = input("Enter run_id (0 to exit): ").strip()
            if run_id == '0':
                logging.info("Exiting to main menu.")
                return
            else:
                run_id = run_id.zfill(2)  # Pad with zero if single digit

            matched_runs = [run for run in valid_runs if run.get("Run_id") == run_id]
            if matched_runs:
                break
            else:
                print(f"No valid pending runs found with Run ID: {run_id}. Exiting to main menu.")
                logging.warning(f"No valid pending runs matched for Run ID: {run_id}. Exiting to main menu.")
                return

        # Display pending runs
        keys = ['Run_id', 'Customer_id', 'Customer_name', 'Timestamp', 'Component_Name', 'Component_Status']
        data_for_tabulate = [[run[key] for key in keys] for run in matched_runs]

        print("\nPending runs:")
        print(tabulate(data_for_tabulate, headers=keys, tablefmt="pretty"))

        try:
            choice = int(input("\nSelect a pending run to complete (enter number or 0 to exit): ").strip())
            if 1 <= choice <= len(matched_runs):
                selected_run = matched_runs[choice - 1]
                active_customer_id = selected_run["Customer_id"]
                active_customer_name = selected_run["Customer_name"]
                active_run_id = selected_run["Run_id"]

                # Execute the component (placeholder for actual execution logic)
                print(f"Executing Component: {selected_run['Component_Name']} for Run ID: {selected_run['Run_id']}")
                logging.info(f"Executing Component: {selected_run['Component_Name']} for Run ID: {selected_run['Run_id']}")

                # Fetch selected run from menu items
                selected_option = None
                for key, value in menu_options.items():
                    if selected_run["Component_Name"] in value:
                        selected_option = key
                        break

                if selected_option:
                    # Execute selected task and pass active session details
                    # update_control_flag_file(selected_run["Component_Name"], "Continue")
                    execute_option(selected_option, active_customer_id, active_customer_name, new_session=False)
                else:
                    logging.error(f"No matching menu option found for Component: {selected_run['Component_Name']}")
                    print("Error: No matching menu option found. Check logs for details.")
                return
            elif choice == 0:  # Exit option
                logging.info("User exited to main menu.")
                return  # Exit to the main menu
            else:
                print("Invalid selection. Please choose a valid run number.")
        except ValueError:
            print("Invalid input. Please enter a number corresponding to the pending runs.")

 

def ensure_no_temporary_files():
    """Checks for and removes temporary files created by external programs."""
    directory = config.get("DEFAULT", "input_dir")
    for file_name in os.listdir(directory):
        if file_name.startswith("~$") and file_name.endswith(".csv"):
            temp_file_path = os.path.join(directory, file_name)
            try:
                os.remove(temp_file_path)
                logging.info(f"Removed temporary file: {temp_file_path}")
                print(f"Removed temporary file: {temp_file_path}")
            except Exception as e:
                logging.error(f"Error removing temporary file {temp_file_path}: {str(e)}")
                print(f"Warning: Could not remove temporary file {temp_file_path}. Check permissions.")
 
# New function to get the latest TLD file
def get_latest_tld_file():
    """Automatically detects the latest TLD file that starts with 'tld_updater' and ends with '.csv'."""
    try:
        output_directory = config.get("DEFAULT", "output_dir")
        output_path = os.path.join(os.path.dirname(__file__), output_directory)
        
        # List all files in the directory that start with 'tld_updater' and end with '.csv'
        tld_files = [f for f in os.listdir(output_path) 
                    if f.startswith("tld_updater") and f.endswith(".csv")]

        if not tld_files:
            logging.info("No valid TLD files found in the Outputs directory.")
            print("No valid TLD files found in the Outputs directory.")
            return None

        # Sort files by modification time (most recent first)
        tld_files.sort(key=lambda x: os.path.getmtime(os.path.join(output_path, x)), reverse=True)
        latest_file = tld_files[0]
        latest_file_path = os.path.join(output_path, latest_file)

        logging.info(f"Detected the latest TLD file: {latest_file_path}")
        print(f"Detected the latest TLD file: {latest_file_path}")
        return latest_file_path
    except Exception as e:
        logging.error(f"Error detecting the latest TLD file: {str(e)}")
        print("Error detecting the latest TLD file. Check logs.")
        return None


def validate_tld_file(file_path):
    """Validate if the TLD file contains at least one valid TLD."""
    try:
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file if line.strip()]
            # Check if any line matches the valid TLD format (uppercase alphabetical strings)
            for line in lines:
                if line.isalpha() and line.isupper():
                    return True  # At least one valid TLD found
        logging.warning(f"The file '{file_path}' does not contain valid TLDs.")
        return False
    except Exception as e:
        logging.error(f"Error reading TLD file '{file_path}': {e}")
        return False


# Menu options for the wrapper
menu_options = {
    0: "Change Customer ID",
    1: "Hoarded Domains Checker",
    2: "Variations Generator",
    3: "Name Variation Domain Generator",
    4: "Name Split Detection",
    5: "Sub Domain Mapper",
    6: "Sub Domain Split",
    7: "Consolidator",
    8: "Base Attributes Detection",
    9: "Extended Attributes Detection",
    10: "Analytical Attributes Detection",
    11:"Alert Severity Computation",
    12: "Exit PhishWATCH"
}
 
def get_customer_details_path():
    """Constructs the full path to the Customer_details.csv file."""
    return os.path.join(config.get("DEFAULT", "input_dir"), "Customer_details.csv")
 
def check_customer_id_exists(customer_id):
    """Checks if the customer ID exists in the Customer_details.csv file."""
    try:
        file_path = get_customer_details_path()
 
        # Open the file for reading with UTF-8 encoding
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # Normalize both the input and the file's customer_id for comparison
                if row['customer_id'].strip().upper() == customer_id.strip().upper():
                    logging.info(f"Customer ID '{customer_id}' exists in the file.")
                    return True
 
        # If no match is found
        logging.info(f"Customer ID '{customer_id}' does not exist in the file.")
        return False
    except FileNotFoundError:
        print("Error: Customer_details.csv not found in the Inputs directory.")
        logging.error("Customer_details.csv not found.")
        return False
    except Exception as e:
        logging.error(f"Error while checking customer ID: {str(e)}")
        print("An error occurred while checking the customer ID. Check the logs.")
        return False
 
def add_new_customer_to_csv(customer_id, customer_name, strings):
    """Appends a new customer to the Customer_details.csv file."""
    try:
        file_path = get_customer_details_path()
        rows = []
        
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            rows = list(csv.DictReader(file))
            rows.append({
                'customer_id': customer_id.strip().upper(),
                'customer_name': customer_name.strip(),
                'strings': strings.strip()
            })
        
        # Open the file for appending with UTF-8 encoding
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(
                file,
                fieldnames=['customer_id', 'customer_name', 'strings'],
                quoting=csv.QUOTE_ALL  # Quote all fields to avoid issues with special characters
            )
            
            writer.writeheader()  # Write header only if file doesn't exist
            
            
            writer.writerows(rows)
 
        logging.info(f"Added new customer to CSV: {customer_id}, {customer_name}, {strings}")
        print(f"New customer ID '{customer_id}' successfully added to the file.")
    except PermissionError:
        logging.error(f"Permission denied while accessing {file_path}.")
        print(f"Error: Unable to write to {file_path}. Please check file permissions.")
    except Exception as e:
        logging.error(f"Error while adding new customer: {str(e)}")
        print("An error occurred while adding the new customer. Check the logs.")
 
 
# Helper function to ensure directories exist
def ensure_directory_exists(path):
    """Ensures the specified directory exists."""
    if not os.path.exists(path):
        os.makedirs(path)
 
# Function to run the TLD Updater automatically at the start
def run_tld_updater():
    """Runs the TLD Updater automatically at the start."""
    try:
        logging.info("Running TLD Updater.")

        # Locate the TLD Updater script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "tld_updater.py")

        # Execute the script
        result = subprocess.run(
            [use_python, script_path, "default", "default"],
            capture_output=True, text=True, check=True
        )
        
        # Suppress unnecessary output, log relevant success
        if "No updates needed." not in result.stdout:
            logging.info("TLD Updater completed successfully.")
            # print("TLD Updater executed successfully.")
        else:
            logging.info("TLD Updater completed successfully with no updates.")
    except subprocess.CalledProcessError as e:
        logging.error(f"TLD Updater failed: {e.stderr.strip()}")
        print("An error occurred while running the TLD Updater. Check logs.")
    except Exception as e:
        logging.error(f"Error running TLD Updater: {str(e)}")
        print("An unexpected error occurred. Check logs.")

 
# Function to prompt for a customer ID
def prompt_for_customer_id():
    """Prompts the user to enter a Customer ID and ensures it exists or allows adding a new one."""
    ensure_no_temporary_files()  # Remove temporary files before proceeding

    while True:
        customer_id = input("Enter Customer ID: ").strip().upper()  # Normalize to uppercase
        if check_customer_id_exists(customer_id):
            # Customer ID exists, retrieve name
            file_path = get_customer_details_path()
            with open(file_path, mode='r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row['customer_id'].strip().upper() == customer_id:
                        customer_name = row['customer_name'].strip()
                        print(f"\nActive Customer ID: {customer_id}")
                        print(f"Active Customer Name: {customer_name}\n")
                        logging.info(f"Active Customer set: ID={customer_id}, Name={customer_name}")
                        return customer_id, customer_name
        else:
            # Customer ID does not exist
            print(f"Customer ID '{customer_id}' does not exist.")
            choice = input("Do you want to add it? (y/n): ").strip().lower()
            if choice == 'y':
                customer_name = input("Enter Customer Name: ").strip()
                strings = input("Enter multiple strings separated by commas (e.g., string1,string2,...): ").strip()
                add_new_customer_to_csv(customer_id, customer_name, strings)
                print(f"\nActive Customer ID: {customer_id}")
                print(f"Active Customer Name: {customer_name}\n")
                logging.info(f"New Customer added and set as Active: ID={customer_id}, Name={customer_name}")
                return customer_id, customer_name
            elif choice == 'n':
                print("Exiting. Customer ID not added.")
                logging.info("User opted not to add a new Customer ID.")
                sys.exit(0)
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

# Function to prompt for a customer Name 
def prompt_for_customer_name():
    """Prompt the user to set an active customer name."""
    customer_name = input("Enter Customer Name: ").strip()
    if not customer_name:
        print("Customer Name cannot be empty. Please enter a valid name.")
        return prompt_for_customer_name()
    print(f"Active Customer Name : {customer_name}")
    return customer_name

 
# Function to get file path from the user
def ask_for_file_path(prompt):
    """Asks the user for a valid file path."""
    file_path = input(f"{prompt}: ").strip()
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} does not exist. Please provide a valid path.")
        return ask_for_file_path(prompt)
    return file_path

def create_new_customer(customer_details_file):
    """Handles the creation of a new customer and ensures proper CSV formatting."""
    try:
        customer_id = input("Enter Customer ID: ").strip()
        if not customer_id:
            print("Error: Customer ID cannot be empty.")
            logging.error("Customer ID is empty.")
            return None

        customer_name = input("Enter Customer Name: ").strip()
        if not customer_name:
            print("Error: Customer Name cannot be empty.")
            logging.error("Customer Name is empty.")
            return None

        strings = input("Enter multiple strings separated by commas (e.g., string1,string2,...): ").strip()
        if not strings:
            print("Error: strings cannot be empty.")
            logging.error("strings are empty.")
            return None

        # Check if the file exists; if not, create a new one
        if not os.path.isfile(customer_details_file):
            print(f"Customer details file '{customer_details_file}' does not exist. Creating a new file.")
            logging.info(f"Creating new customer details file: {customer_details_file}")

        # Append the new customer details to the CSV file
        with open(customer_details_file, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([customer_id, customer_name, strings])

        print(f"New customer ID '{customer_id}' successfully added to the file.")
        logging.info(f"New customer '{customer_id}, {customer_name}' with strings '{strings}' added to file.")
        return customer_id

    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Error creating new customer: {str(e)}")
        return None

 
# Menu Option 0: Change Customer ID
def change_customer_id():
    """Handles the 'Change Customer ID' option."""
    global active_customer_id, active_customer_name
    ensure_no_temporary_files()  # Remove temp files before proceeding
    file_path = get_customer_details_path()
    
    while True:
        customer_id = input("Enter New Customer ID: ").strip().upper()
        if check_customer_id_exists(customer_id):
            print(f"\nCustomer ID '{customer_id}' already exists.")
            logging.info(f"Customer ID '{customer_id}' already exists.")
            continue

        with open(file_path, mode='r', encoding='utf-8') as file:
            rows = list(csv.DictReader(file))
            
            for row in rows:
                if row['customer_id'].strip().upper() == active_customer_id:
                    customer_name = input("Enter Customer Name (press Enter to keep existing): ").strip()
                    strings = input("Enter multiple strings separated by commas (press Enter to keep existing): ").strip()
                    
                    row["customer_id"] = customer_id
                    row["customer_name"] = customer_name or row["customer_name"]
                    row["strings"] = strings or row["strings"]
    
            choice = input("Do you want to update current user? (y/n): ").strip().lower()
            if choice == 'y':
                with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.DictWriter(file, fieldnames=['customer_id', 'customer_name', 'strings'], quoting=csv.QUOTE_ALL)
                    writer.writeheader()
                    writer.writerows(rows)
                
                active_customer_id = customer_id
                active_customer_name = customer_name
                
                print(f"\nActive Customer ID updated to: {customer_id}")
                print(f"Active Customer Name updated to: {customer_name}")
                logging.info(f"Active Customer ID updated to: {customer_id}")
                logging.info(f"Active Customer Name updated to: {customer_name}")
                return customer_id, customer_name
            
            elif choice == 'n':
                print("Exiting. Customer ID not updated.")
                logging.info("User opted not to update Customer ID.")
                return  # Exit to the main menu
            
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
                logging.error("Invalid input for updating Customer ID.")
                continue


# Menu Option 1: Hoarded Domains Checker
def run_hoarded_domains_checker(customer_id, customer_name, new_session):
    """Executes the Hoarded Domains Checker."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Hoarded Domains Checker.")
        
        # Locate the Hoarded Domains Checker script
        script_path = os.path.join(os.path.dirname(__file__), config.get("SOURCE_CODES", "source_dir"), "Hoarded_Domains_Checker.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return

        # Execute the Hoarded Domains Checker script with the required arguments
        subprocess.run(
            [use_python, script_path, customer_id, customer_name, str(new_session)],
            check=True,
        )
        logging.info("Hoarded Domains Checker completed successfully.")
        print("Hoarded Domains Checker executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        # print("KeyboardInterrupt caught in Hoarded Domains Checker.")
        # logging.error("KeyboardInterrupt caught in Hoarded Domains Checker.")
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Hoarded Domains Checker: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Hoarded Domains Checker: {str(e)}")
        print("An unexpected error occurred. Check the logs for details.")

 
# Menu Option 2: Variation Generator
def run_variations_generator(customer_id, new_session):
    """Executes the Variations Generator."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Run ID: {active_run_id}")
        logging.info(f"Running Variations Generator for Customer ID: {customer_id}")

        # Locate Customer_details.csv file
        input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
        customer_details_file = os.path.join(input_dir, "Customer_details.csv")

        # Check if Customer_details.csv exists
        if not os.path.isfile(customer_details_file):
            raise FileNotFoundError(f"Customer details file not found: {customer_details_file}")

        # Locate the Variation Generator script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Variation_generator.py")
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"Variation Generator script not found: {script_path}")

        # Normalize customer_id to uppercase before passing it to the script
        customer_id_upper = customer_id.upper()

        # Execute the Variation Generator script with the required arguments
        subprocess.run(
            [use_python, script_path, customer_id_upper, str(new_session)],
            check=True
        )
        logging.info("Variations Generator completed successfully.")
        print("Variations Generator executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        # print("KeyboardInterrupt caught in Variations Generator.")
        # logging.error("KeyboardInterrupt caught in Variations Generator.")
        pass
    except FileNotFoundError as fnf_error:
        logging.error(f"File not found: {fnf_error}")
        print(f"Error: {fnf_error}")
    except subprocess.CalledProcessError as cpe:
        logging.error(f"Error executing Variation Generator script: {cpe}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Variations Generator: {str(e)}")
        print(f"An unexpected error occurred: {str(e)}")


# Menu Option 3: Name Variation Domain Generator
def run_name_variation_domain_generator(customer_id, customer_name, new_session):
    """Executes the Name Variation Domain Generator."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Name Variation Domain Generator.")
 
        # Locate the Name Variation Domain Generator script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Name_Variation_Domain_Generator.py")
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"Name Variation Domain Generator script not found: {script_path}")
 
        # Execute the Name Variation Domain Generator script with the required arguments
        subprocess.run(
            [use_python, script_path, customer_id, customer_name, str(new_session)],
            check=True
        )
        logging.info("Name Variation Domain Generator completed successfully.")
        print("Name Variation Domain Generator executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        pass
    except FileNotFoundError as fnf_error:
        logging.error(f"File not found: {fnf_error}")
        print(f"Error: {fnf_error}")
    except subprocess.CalledProcessError as cpe:
        logging.error(f"Error executing Name Variation Domain Generator script: {cpe}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Name Variation Domain Generator: {str(e)}")
        print(f"An unexpected error occurred: {str(e)}")
 

# Menu Option 4: Name Split Detection
def run_name_split_detection(customer_id, new_session):
    """Executes the Name Split Detection."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Name Split Detection.")
       
        # Helper: Fetch the latest file by prefix
        def get_latest_file(directory, prefix):
            """
            Fetch the latest file in the directory that matches the given prefix.
            Args:
                directory (str): Path to the directory.
                prefix (str): Prefix to filter files.
            Returns:
                str: Path to the latest file or None if no matching file is found.
            """
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and f"{prefix}" in f
                ]
                return max(files, key=os.path.getmtime) if files else None
            except Exception as e:
                logging.error(f"Error fetching latest file for prefix '{prefix}': {e}")
                return None
 
        # Helper: Validate the file naming convention
        def validate_file(file_path, customer_id, customer_name):
            if not os.path.isfile(file_path):
                logging.error(f"File '{file_path}' does not exist.")
                return False
            return True
 
        # Helper: Fetch customer name from details file
        def get_customer_name(customer_id):
            """
            Fetch the customer name based on the customer ID.
            Args:
                customer_id (str): Customer ID.
            Returns:
                str: Customer name.
            """
            try:
                details_file = os.path.join(config.get("DEFAULT", "input_dir", fallback="Inputs"), "Customer_details.csv")
                if not os.path.isfile(details_file):
                    raise FileNotFoundError(f"Customer details file '{details_file}' not found.")
                with open(details_file, 'r') as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        if row.get('customer_id', '').strip() == customer_id.strip():
                            return row.get('customer_name', 'Unknown')
                logging.warning(f"Customer ID '{customer_id}' not found in customer details file.")
                return "Unknown"
            except Exception as e:
                logging.error(f"Error fetching customer name: {e}")
                return "Unknown"
 
        # Fetch customer name dynamically
        customer_name = get_customer_name(customer_id)
        if customer_name == "Unknown":
            logging.warning("Customer name could not be determined. Prompting for manual input.")
            customer_name = input("Enter Customer Name manually: ").strip()
            if not customer_name:
                print("Customer Name is required. Exiting.")
                return
 
        # Automatically detect latest files
        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
 
        latest_hoarded_file = {}
        latest_variations_file = {}
 
        # Prompt for missing files
       
        if not latest_hoarded_file:
            latest_hoarded_file = get_latest_file(output_dir, "Hoarded_domains_checker")
            if latest_hoarded_file:
                print(f"Detected latest hoarded file: {latest_hoarded_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_hoarded_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_hoarded_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_hoarded_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return
 
        if not latest_variations_file:
            latest_variations_file = get_latest_file(output_dir, "Name_Variation_Domain_Generator")
            if latest_variations_file:
                print(f"Detected latest variation file: {latest_variations_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_variations_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_variations_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_variations_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return
 
        # Locate script path
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Name_Split_Detection.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return
 
        # Execute the script
        subprocess.run(
    [use_python, script_path, latest_hoarded_file, latest_variations_file, customer_id, customer_name, str(new_session)],
    check=True
)
 
        logging.info("Name Split Detection completed successfully.")
        print("Name Split Detection executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Name Split Detection: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Name Split Detection: {str(e)}")
        print(f"An unexpected error occurred. Check the logs for details.")


# Menu Option 5: Sub Domain Mapper
def run_sub_domain_mapper(customer_id, customer_name, new_session):
    """
    Executes the Sub Domain Mapper script with dynamic file detection and user confirmation.
    Args:
        customer_id (str): Active customer ID.
        customer_name (str): Active customer name.
    """
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Sub Domain Mapper.")

        # Load configuration
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), 'Config', 'Config.ini'), encoding="utf8")  # Ensure the path to your config file is correct

        # Helper Function: Fetch Latest File
        def get_latest_file(directory, prefix):
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and f"{prefix}" in f
                ]
                return max(files, key=os.path.getmtime) if files else None
            except Exception as e:
                logging.error(f"Error fetching latest file for prefix '{prefix}': {e}")
                return None
        
        # Fetch necessary inputs dynamically
        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")

        # Helper Function: Confirm or Provide File
        hoarded_domains_file = {}
        name_split_file = {}
        name_variations_file = {}
        if not hoarded_domains_file:
            hoarded_domains_file = get_latest_file(output_dir, "Hoarded_domains_checker")
            if hoarded_domains_file:
                print(f"Detected latest Hoarded Domains file: {hoarded_domains_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        hoarded_domains_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if hoarded_domains_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(hoarded_domains_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        if not name_variations_file:
            name_variations_file = get_latest_file(output_dir, "Name_Variation_Domain_Generator")
            if name_variations_file:
                print(f"Detected latest Name Variations file: {name_variations_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        name_variations_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if name_variations_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(name_variations_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        if not name_split_file:
            name_split_file = get_latest_file(output_dir, "Name_Split_Detection")
            if name_split_file:
                print(f"Detected latest Name Split file: {name_split_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        name_split_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if name_split_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(name_split_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        # Locate the Sub Domain Mapper script
        source_dir = config.get("SOURCE_CODES", "source_dir", fallback="Source_Codes")
        script_path = os.path.join(source_dir, "Sub_Domain_Mapper.py")

        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return

        # Execute the Subdomain Mapper script
        subprocess.run(
            [
                use_python,
                script_path,
                hoarded_domains_file,
                name_variations_file,
                name_split_file,
                customer_id,
                customer_name,
                str(new_session)
            ],
            check=True
        )

        logging.info("Sub Domain Mapper completed successfully.")
        print("Sub Domain Mapper executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Sub Domain Mapper: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Sub Domain Mapper: {str(e)}")
        print(f"An unexpected error occurred. Check the logs for details.")



#menu option 6 subdomain_split
def run_sub_domain_split(customer_id, new_session):
    """Executes the Sub Domain Split."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Sub Domain Split.")

        # Helper function to get the latest file
        def get_latest_file(directory, prefix):
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and f"{prefix}" in f
                ]
                return max(files, key=os.path.getmtime) if files else None
            except Exception as e:
                logging.error(f"Error fetching latest file for prefix '{prefix}': {e}")
                return None

        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
        latest_subdomain_mapper_file = {}
        
        if not latest_subdomain_mapper_file:
            latest_subdomain_mapper_file = get_latest_file(output_dir, "Sub_Domain_Mapper")
            if latest_subdomain_mapper_file:
                print(f"Detected latest Name Split file: {latest_subdomain_mapper_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_subdomain_mapper_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_subdomain_mapper_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_subdomain_mapper_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        # Fetch customer name dynamically
        def get_customer_name(customer_id):
            """
            Fetch the customer name based on the customer ID.
            Args:
                customer_id (str): Customer ID.
            Returns:
                str: Customer name.
            """
            try:
                customer_details_file = os.path.join(config.get("DEFAULT", "input_dir", fallback="Inputs"), "Customer_details.csv")
                if not os.path.isfile(customer_details_file):
                    raise FileNotFoundError(f"Customer details file '{customer_details_file}' not found.")
                with open(customer_details_file, 'r') as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        if row.get('customer_id', '').strip() == customer_id.strip():
                            return row.get('customer_name', 'Unknown')
                logging.warning(f"Customer ID '{customer_id}' not found in customer details file.")
                return "Unknown"
            except Exception as e:
                logging.error(f"Error fetching customer name for ID '{customer_id}': {e}")
                return "Unknown"

        customer_name = get_customer_name(customer_id)

        # Locate the Sub Domain Split script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Sub_domain_split.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return

        # Execute the Sub Domain Split script with the required arguments
        subprocess.run(
            [use_python, script_path, latest_subdomain_mapper_file, customer_id, customer_name, str(new_session)],
            check=True
        )
        logging.info("Sub Domain Split completed successfully.")
        print("Sub Domain Split executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Sub Domain Split: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Sub Domain Split: {str(e)}")
        print(f"An unexpected error occurred. Check the logs for details.")



# Menu Option 7: Consolidator
def run_consolidator(customer_id):
    """Executes the Consolidator."""
    try:
        print(f"Active Customer ID: {customer_id}")
        logging.info("Running Consolidator.")

        # Helper function to fetch the customer name
        def get_customer_name(customer_id):
            """Fetch the customer name based on the customer ID."""
            try:
                # Assuming a CSV file exists with customer details
                customer_details_file = os.path.join(config.get("DEFAULT", "input_dir", fallback="Inputs"), "Customer_details.csv")
                if not os.path.isfile(customer_details_file):
                    raise FileNotFoundError(f"Customer details file '{customer_details_file}' not found.")

                with open(customer_details_file, 'r') as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        if row.get('customer_id', '').strip() == customer_id.strip():
                            return row.get('customer_name', 'Unknown')
                logging.warning(f"Customer ID '{customer_id}' not found in customer details file.")
                return "Unknown"
            except Exception as e:
                logging.error(f"Error fetching customer name for ID '{customer_id}': {e}")
                return "Unknown"

        # Helper function to fetch the latest file or prompt the user
        def get_latest_file(directory, prefix):
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and f"{prefix}" in f
                ]
                return max(files, key=os.path.getmtime) if files else None
            except Exception as e:
                logging.error(f"Error fetching latest file for prefix '{prefix}': {e}")
                return None

        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
        latest_hoarded_file = {}
        latest_variations_file = {}
        latest_name_split_file = {}
        latest_subdomain_mapper_file = {}
        latest_subdomain_split_file = {}

        # Fetch required files
        
        if not latest_hoarded_file:
            latest_hoarded_file = get_latest_file(output_dir, "Hoarded_domains_checker")
            if latest_hoarded_file:
                print(f"Detected latest hoarded file: {latest_hoarded_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_hoarded_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_hoarded_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_hoarded_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        if not latest_variations_file:
            latest_variations_file = get_latest_file(output_dir, "Name_Variation_Domain_Generator")
            if latest_variations_file:
                print(f"Detected latest variation file: {latest_variations_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_variations_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_variations_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_variations_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return
        
        
        if not latest_name_split_file:
            latest_name_split_file = get_latest_file(output_dir, "Name_Split_Detection")
            if latest_name_split_file:
                print(f"Detected latest Name Split file: {latest_name_split_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_name_split_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_name_split_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_name_split_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return
        
        if not latest_subdomain_mapper_file:
            latest_subdomain_mapper_file = get_latest_file(output_dir, "Sub_Domain_Mapper")
            if latest_subdomain_mapper_file:
                print(f"Detected latest Sub Domain Mapper file: {latest_subdomain_mapper_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_subdomain_mapper_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_subdomain_mapper_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_subdomain_mapper_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return
        
        if not latest_subdomain_split_file:
            latest_subdomain_split_file = get_latest_file(output_dir, "Sub_Domain_Split")
            if latest_subdomain_split_file:
                print(f"Detected latest Name Split Split file: {latest_subdomain_split_file}")
                while True:
                    choice = input("Do you want to proceed with this file? (y/n) [0 to exit]: ").strip().lower()
                    if choice == 'y':
                        break
                    elif choice == 'n':
                        latest_subdomain_split_file = input("Enter the input file path (or type '0' to exit): ").strip()
                        if latest_subdomain_split_file == '0':
                            print("Exiting...")
                            # sys.exit(1)
                            return
                        elif os.path.isfile(latest_subdomain_split_file):
                            break
                    elif choice == '0':
                        print("Exiting...")
                        # sys.exit(1)
                        return

        # Combine all input files

        input_files = [
            latest_hoarded_file,
            latest_variations_file,
            latest_name_split_file,
            latest_subdomain_mapper_file,
            latest_subdomain_split_file
        ]

        # Fetch customer name dynamically
        customer_name = get_customer_name(customer_id)

        # Locate the Consolidator script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Consolidator.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return

        # Execute the Consolidator script with the required arguments
        subprocess.run(
            [use_python, script_path] + input_files + [customer_id, customer_name],
            check=True
        )
        logging.info("Consolidator completed successfully.")
        print("Consolidator executed successfully. Check logs and output for results.")
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Consolidator: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Consolidator: {str(e)}")
        print(f"An unexpected error occurred. Check the logs for details.")

# Menu Option 8: Base Attributes Detection
def run_base_attributes_detection(customer_id, customer_name, new_session):
    """
    Executes the Base Attributes Detection script.
    Detects the latest Consolidator file based solely on the latest timestamp,
    and asks the user for confirmation to proceed with the detected file.
    """
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Base Attributes Detection.")
 
        # Helper Function: Fetch Latest File
        def get_latest_file(directory, prefix):
            """
            Fetch the latest file in the directory that matches the given prefix.
            Args:
                directory (str): Path to the directory.
                prefix (str): Prefix to filter files.
            Returns:
                str: Path to the latest file or None if no matching file is found.
            """
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and prefix in f and f.endswith('.csv')
                ]
                if not files:
                    return None
                latest_file = max(files, key=os.path.getmtime)
                return latest_file
            except Exception as e:
                logging.error(f"Error while fetching the latest file for prefix '{prefix}': {e}")
                return None
 
        # Read configuration to get output directory
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), 'Config', 'Config.ini'), encoding="utf8")
        output_dir = config.get('DEFAULT', 'output_dir', fallback='Outputs')
       
        # Fetch the latest input file for Consolidator
        latest_input_file = get_latest_file(output_dir, 'Consolidator')
 
        if not latest_input_file:
            print("No suitable input file found. Exiting.")
            logging.info("No suitable input file found. Exiting.")
            return
 
        print(f"Detected latest input file: {latest_input_file}")
        logging.info(f"Detected latest input file: {latest_input_file}")
 
        # Confirm user wants to use this file
        while True:
            proceed = input("Do you want to proceed with this file? (y/n or 0 to exit): ").strip().lower()
            if proceed == 'y':
                break
            elif proceed == 'n':
                latest_input_file = input("Enter the path to the input file (or type '0' to exit): ").strip()
                if latest_input_file == '0':
                    print("Returning to main menu...")
                    logging.info("User exited Base Attributes Detection.")
                    return
                if not os.path.isfile(latest_input_file):
                    print("The specified file does not exist. Please try again.")
                    logging.error("The specified input file does not exist.")
                else:
                    break
            elif proceed == '0':
                print("Returning to main menu...")
                logging.info("User exited Base Attributes Detection.")
                return
            else:
                print("Invalid input. Please enter 'y' for yes, 'n' for no, or '0' to exit.")
 
        # Locate the Base Attributes Detection script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Base_Attributes.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return
 
        # Execute the Base Attributes Detection script
        process = subprocess.Popen(
            [use_python, script_path, customer_id, customer_name, latest_input_file, str(new_session)],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        process.communicate()  # Wait for the process to complete
 
        if process.returncode == 0:
            logging.info("Base Attributes Detection completed successfully.")
            print("Base Attributes Detection completed successfully.")
        else:
            logging.error(f"Script exited with return code {process.returncode}.")
            print(f"An error occurred. Check the log file for details.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"Error running Base Attributes Detection: {str(e)}")
        print(f"An error occurred. Check the log file for details.")
 
# Menu Option 9: extended_attributes_detections
def run_extended_attributes_detection(customer_id, customer_name, new_session):
    """Executes the Extended Attributes Detection script."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Extended Attributes Detection.")
 
        # Helper Function: Fetch Latest File
        def get_latest_file(directory, prefix):
            """
            Fetch the latest file in the directory that matches the given prefix.
            Args:
                directory (str): Path to the directory.
                prefix (str): Prefix to filter files.
            Returns:
                str: Path to the latest file or None if no matching file is found.
            """
            try:
                files = [
                    os.path.join(directory, f) for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f)) and f"{prefix}" in f
                ]
                if not files:
                    return None
                latest_file = max(files, key=os.path.getmtime)
                return latest_file
            except Exception as e:
                logging.error(f"Error while fetching the latest file for prefix '{prefix}': {e}")
                return None
 
        # Fetch the latest input file for domain existence
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), 'Config', 'Config.ini'), encoding="utf8")
        output_dir = config.get('DEFAULT', 'output_dir', fallback='Outputs')
        latest_input_file = get_latest_file(output_dir, 'Base_Attributes')
 
        if not latest_input_file:
            print("No suitable input file found. Exiting.")
            logging.info("No suitable input file found. Exiting.")
            return
 
        print(f"Detected latest input file: {latest_input_file}")
        logging.info(f"Detected latest input file: {latest_input_file}")
 
        # Confirm user wants to use this file
        while True:
            proceed = input("Do you want to proceed with this file? (y/n or 0 to exit): ").strip().lower()
            if proceed == 'y':
                break
            elif proceed == 'n':
                latest_input_file = input("Enter the path to the input file (or type '0' to exit): ").strip()
                if latest_input_file == '0':
                    print("Returning to main menu...")
                    logging.info("User exited Extended Attributes Detection.")
                    return
                if not os.path.isfile(latest_input_file):
                    print("The specified file does not exist. Please try again.")
                    logging.error("The specified input file does not exist.")
                else:
                    break
            elif proceed == '0':
                print("Returning to main menu...")
                logging.info("User exited Extended Attributes Detection.")
                return
            else:
                print("Invalid input. Please enter 'y' for yes, 'n' for no, or '0' to exit.")
 
        # Locate the Extended Attributes Detection script
        script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Extended_Attributes.py")
        if not os.path.isfile(script_path):
            print(f"Error: Script '{script_path}' not found.")
            logging.error(f"Script '{script_path}' not found.")
            return
 
        # Execute the Extended Attributes Detection script
        process = subprocess.Popen(
            [use_python, script_path, customer_id, customer_name, latest_input_file, str(new_session)],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        process.communicate()  # Wait for the process to complete
 
        if process.returncode == 0:
            logging.info("Extended Attributes Detection completed successfully.")
            print("Extended Attributes Detection completed successfully.")
        else:
            logging.error(f"Script exited with return code {process.returncode}.")
            print(f"An error occurred. Check the log file for details.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"Error running Extended Attributes Detection: {str(e)}")
        print(f"An error occurred. Check the log file for details.")
 
 
 
 
 # Menu Option 10: analytical_attributes_detection  
def run_analytical_attributes_detection(customer_id, customer_name, new_session):
    """Executes the Analytical Attributes Detection script."""
    try:
        print(f"Active Customer ID: {customer_id}")
        print(f"Active Customer Name: {customer_name}")
        print(f"Active Run ID: {active_run_id}")
        logging.info("Running Analytical Attributes Detection.")
        script_path = os.path.join(os.getcwd(), "Source_Codes", "Analytical_Attributes.py")
 
        # Run the script
        process = subprocess.Popen(
            [use_python, script_path, customer_id, customer_name, str(new_session)],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        process.communicate()
 
        if process.returncode == 0:
            logging.info("Analytical Attributes Detection completed successfully.")
            print("Analytical Attributes Detection completed successfully.")
        else:
            logging.error(f"Script exited with return code {process.returncode}.")
            print(f"An error occurred. Check the log file for details.")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"Error running Analytical Attributes Detection: {str(e)}")
        print(f"An error occurred. Check the log file for details.")
 
# Menu Option 11: Alert severity  computation
def run_alert_severity_computation(customer_id, customer_name, new_session):
    """Runs the Alert Severity Computation."""
    print("\nStarting Alert Severity Computation.")
 
    # Define expected headers for each file type
    expected_headers = {
        "Base_Attributes": [
            "Domain", "Name Server", "Mail Server", "Registrar", "Registrant",
            "Registered Address", "Registration Country", "Registration Date", "Remarks"
        ],
        "Analytical_Attributes": ["Domain", "Blacklisted", "Age of Registration", "Directory Listing"],
        "Extended_Attributes": ["Website (Redirection)", "Login Page", "Port", "SSL"]
    }
 
    # Proceed with the computation
    script_path = os.path.join(config.get("SOURCE_CODES", "source_dir"), "Alert_Severity_Computation.py")
    if not os.path.isfile(script_path):
        print(f"Error: Script '{script_path}' not found.")
        logging.error(f"Script '{script_path}' not found.")
        return
 
    # Execute the Alert Severity script
    
    try:
        subprocess.run(
            [use_python, script_path, customer_id, customer_name, str(new_session)],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        print("Alert Severity Computation completed successfully.")
        logging.info("Alert Severity Computation completed successfully.")
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing Alert Severity Computation: {e}")
        print("An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in Alert Severity Computation: {str(e)}")
        print("An unexpected error occurred. Check the logs for details.")

 

# Menu Option 12: Exit option 
def exit_program():
    """Exits the program gracefully."""
    logging.info("Exiting the program as requested by the user.")
    print("Exiting the PhishWATCH. Goodbye!")
    sys.exit(0)
 
def execute_option(choice, customer_id, customer_name, new_session=True):
    """
    Executes the function corresponding to the user's menu choice.
    """
    if choice == 0:
        return change_customer_id(), customer_name
    elif choice == 1:
        run_hoarded_domains_checker(customer_id,customer_name, new_session)
    elif choice == 2:
        run_variations_generator(customer_id, new_session)
    elif choice == 3:
        run_name_variation_domain_generator(customer_id, customer_name, new_session)
    elif choice == 4:
        run_name_split_detection(customer_id, new_session)
    elif choice == 5:
        run_sub_domain_mapper(customer_id, customer_name, new_session)
    elif choice == 6:
        run_sub_domain_split(customer_id, new_session)
    elif choice == 7:
        run_consolidator(customer_id)
    elif choice == 8:
        run_base_attributes_detection(customer_id, customer_name, new_session)  # Pass active customer details
    elif choice == 9:
        run_extended_attributes_detection(customer_id, customer_name, new_session)  # Pass active customer details
    elif choice == 10:
        run_analytical_attributes_detection(customer_id, customer_name, new_session)
    elif choice == 11:
        run_alert_severity_computation(customer_id, customer_name, new_session)
    elif choice == 12:
        exit_program()
    else:
        print("Invalid choice. Please select a valid option.")
        logging.warning(f"Invalid menu choice: {choice}")
    return customer_id, customer_name

# Global variables for tracking session state
active_run_id = None
active_customer_id = None
active_customer_name = None


def run_phishwatch_utility():
    logging.info("Running Phishwatch_utility.")
    global active_run_id, active_customer_id, active_customer_name
    script_name = None
    
    
    output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
    
    # Validate output directory existence
    if not os.path.isdir(output_dir):
        logging.error(f"Output directory '{output_dir}' not found.")
        print(f"Error: Output directory '{output_dir}' not found.")
        return
    
    # List all files in the output directory
    output_files = [f for f in os.listdir(output_dir) if "Alert_Severity"in f and f.endswith(".csv")]
    
    # Validate output files existence
    if not output_files:
        logging.error(f"No Alert Severity output files found in '{output_dir}'.")
        print(f"No Alert Severity output files found in '{output_dir}'.")
        return
    
    # Prompt user to select a file
    print("Select an Alert Severity output file:")
    for i, file in enumerate(output_files):
        print(f"{i+1}. {file}")
    
    try:
        choice = int(input("Enter your choice: "))
        if choice < 1 or choice > len(output_files):
            raise ValueError("Invalid choice entered.")
        
        selected_file = output_files[choice - 1]
        parts = selected_file.split("_")
        run_id = parts[0]
        active_run_id = run_id
        active_customer_name = parts[2]
        active_customer_id = parts[3]
        print(f"Active Customer ID: {active_customer_id}")
        print(f"Active Customer Name: {active_customer_name}")
        print(f"Active Run ID: {active_run_id}")
        # Pass absolute path of the selected file to the script
        selected_file_path = os.path.join(output_dir, selected_file)
    except ValueError:
        print("Invalid choice. Please select a valid option.")
        logging.warning("Invalid choice entered.")
    
    # Show the Phishwatch_utility menu options
    while True:
        print("\nSelect an option:")
        print("1. IP Domain Mapping")
        print("2. Domain IP Resolution")
        print("3. Unique Blacklisted IPs")
        print("4. Directory Listing Enabled")
        print("5. Exit")
        
        try:
            choice = int(input("Enter your choice: "))
            if choice == 1:
                script_name = "ip_domain_mapping" 
                run_phishwatch_utility_script(script_name, selected_file_path)
            elif choice == 2:
                script_name = "domain_ip_resolution"
                run_phishwatch_utility_script(script_name, selected_file_path)
            elif choice == 3:
                script_name = "unique_blacklisted_ips"
                run_phishwatch_utility_script(script_name, selected_file_path)
            elif choice == 4:
                script_name = "directory_listing_enabled"
                run_phishwatch_utility_script(script_name, selected_file_path)
            elif choice == 5:
                # Step 5: Exit the utility
                print("Exiting the Phishwatch_utility.")
                logging.info("Exiting Phishwatch_utility.")
                return
            else:
                print("Invalid choice. Please select a valid option.")
                raise ValueError("Invalid choice entered.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
            logging.warning("Non-integer value entered in Phishwatch_utility.")
        except Exception as e:
            logging.error(f"Unexpected error in Phishwatch_utility: {str(e)}")
            print("An unexpected error occurred. Check the logs for details.")


def run_phishwatch_utility_script(script_name, selected_file_path):
    # Construct path to script and validate its existence
    try:
        script_path = os.path.join(config.get("PhishWatch", "phishwatch_utility_dir"), f"{script_name}.py")
    except Exception as e:
        logging.error(f"Error accessing {script_name} in config: {e}")
        print(f"Error accessing {script_name} in configuration.")
        return

    if not os.path.isfile(script_path):
        logging.error(f"Script '{script_path}' not found.")
        print(f"Error: Script '{script_path}' not found.")
        return

    # Execute the script
    try:
        subprocess.run(
            [use_python, script_path, active_customer_id, active_customer_name, active_run_id, selected_file_path],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            check=True
        )
        logging.info(f"{script_name} completed successfully.")
        print(f"{script_name} completed successfully.")
    except KeyboardInterrupt:
        logging.warning(f"{script_name} execution interrupted by user.")
        print(f"Execution interrupted by user.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing {script_name}: {e}")
        print(f"An error occurred during execution. Check the logs for details.")
    except Exception as e:
        logging.error(f"Unexpected error in {script_name}: {str(e)}")
        print(f"An unexpected error occurred. Check the logs for details.")


def show_run_status():
    global active_customer_id, active_customer_name
    current_components = list(menu_options.values())
    current_components.pop(0)
    current_components.pop()
    while True:
        run_id = input("Enter run_id (0 to exit): ").strip()
        
        
        # Check if the input is '0' to exit
        if run_id == '0':
            logging.info("Exiting to main menu...")
            print("Exiting to main menu...")
            return
        
        # Check if the run_id is a valid number
        if not run_id.isdigit():
            print("Invalid run_id. Please enter a valid number.")
            continue
        
        # Ensure run_id is formatted with leading zeros (if needed)
        run_id = run_id.zfill(2)
        break
    
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_file = os.path.join(input_dir, "Run_Tracker.csv")
    
    if not os.path.exists(run_tracker_file):
        print("Run Tracker file not found.")
        logging.error("Run Tracker file not found.")
        return
    
    data = []
    
    with open(run_tracker_file, "r", encoding="utf8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["Run_id"] == run_id:
                active_customer_id = row["Customer_id"]
                active_customer_name = row["Customer_name"]
                data.append(row)
    
    if not data or len(data) <= 1:
        print(f"No data found for run_id: {run_id}")
        logging.warning(f"No data found for run_id: {run_id}")
        return
    
    printed_data = []
    
    for component in current_components:
        found = False
        for row in data:
            if row["Component_Name"] == "":
                continue
            if component in row["Component_Name"]:
                printed_data.append({
                "Run_id": row["Run_id"],
                "Customer_id": row["Customer_id"],
                "Customer_name": row["Customer_name"],
                "Timestamp": row["Timestamp"],
                "Component_Name": row["Component_Name"],
                "Component_Status": row["Component_Status"],
            })
                found = True
        
        
        # If component is not found, add additional data
        if not found:
            printed_data.append({
                "Run_id": run_id,
                "Customer_id": active_customer_id,
                "Customer_name": active_customer_name,
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Component_Name": component,
                "Component_Status": "0% (Not Started)",
            })
    
    
    keys = ["Run_id", "Customer_id", "Customer_name", "Timestamp", "Component_Name", "Component_Status"]
    
    data_for_tabulate = []
    for row in printed_data:
        data_for_tabulate.append([row[key] for key in keys])
    
    
    # Display the data
    print("\nRun Status:")
    try:
        print(tabulate(data_for_tabulate, headers= keys,tablefmt="pretty"))
    except Exception as e:
        print(f"Error while displaying data: {e}")

def download_finished_output_file():
    """Handles downloading the finished output file if Alert Severity is 100% complete."""
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_tracker_path = os.path.join(input_dir, "Run_Tracker.csv")

    if not os.path.exists(run_tracker_path):
        print("\nError: Run_Tracker.csv file not found.")
        logging.error("Run_Tracker.csv file not found.")
        return

    run_id = input("Enter the Run ID: ").strip().zfill(2)  # Standardize Run ID format

    try:
        df = pd.read_csv(run_tracker_path)

        # Standardize Run ID and clean column names
        df["Run_id"] = df["Run_id"].astype(str).str.zfill(2)
        df["Component_Name"] = df["Component_Name"].str.strip()

        # Find the row corresponding to the run_id and "Alert Severity Computation"
        matching_row = df[(df["Run_id"] == run_id) & (df["Component_Name"] == "Alert Severity Computation")]

        if matching_row.empty:
            print(f"\nError: No records found for Run ID '{run_id}' with Component 'Alert Severity Computation'.")
            logging.warning(f"No records found for Run ID '{run_id}' with Component 'Alert Severity Computation'.")
            return

        # Check if Component_Status is 100%
        if not (matching_row["Component_Status"].astype(str).str.strip() == "100%").all():
            print("\nDownload can't be processed as the output is still pending.")
            logging.info(f"Download attempt failed for Run ID '{run_id}' because completion is pending.")
            return

        # Extract values from CSV
        customer_name = matching_row.iloc[0]["Customer_name"].strip()
        customer_id = matching_row.iloc[0]["Customer_id"].strip()

        # Locate the exact output file in the Outputs directory (get timestamp dynamically)
        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
        search_pattern = os.path.join(output_dir, f"{run_id}_Alert_Severity_{customer_name}_{customer_id}_*.csv")
        output_files = glob.glob(search_pattern)

        if not output_files:
            print(f"\nError: No output file found for Run ID '{run_id}' in '{output_dir}'.")
            logging.error(f"Output file for Run ID '{run_id}' not found.")
            return

        # Use the first matching file (should be the correct one)
        output_file = output_files[0]
        expected_filename = os.path.basename(output_file)  # Extract filename with timestamp

        # Prompt user for destination folder
        output_file_path = input("\nEnter the destination folder path to save the output file: ").strip().strip('"').strip("'")

        # Fix Windows path issue
        output_file_path = os.path.normpath(output_file_path)

        # Ensure the path is valid
        if not os.path.exists(output_file_path):
            print(f"\nError: The specified directory '{output_file_path}' does not exist. Please enter a valid path.")
            logging.error(f"Invalid directory specified: {output_file_path}")
            return

        # Copy the file to the user's specified location
        destination_file = os.path.join(output_file_path, expected_filename)
        shutil.copy(output_file, destination_file)

        print(f"\n Success! Output file '{expected_filename}' has been saved to '{destination_file}'.")
        logging.info(f"Output file '{expected_filename}' successfully copied to '{destination_file}'.")

    except Exception as e:
        print("\nAn error occurred while processing the download. Check logs for details.")
        logging.error(f"Error in downloading finished output file: {str(e)}")

def download_output_file():
    """Handles downloading the output file if its 100% complete."""
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_master_path = os.path.join(input_dir, "Run_Master.csv")

    if not os.path.exists(run_master_path):
        print("\nError: Run_Master.csv file not found.")
        logging.error("Run_Master.csv file not found.")
        return

    run_id = input("Enter the Run ID: ").strip().zfill(2)
    
    keys = ["Run_id", "Customer_id", "Customer_name", "Timestamp", "Component_Name"]
    try:
        completed_runs = check_completed_runs()
        
        data_for_tabulate = []
        for run in completed_runs:
            if run["Run_id"] == run_id:
                data_for_tabulate.append([run[key] for key in keys])
        
        if not data_for_tabulate:
            print(f"\nError: No records found for Run ID '{run_id}'.")
            logging.warning(f"No records found for Run ID '{run_id}'.")
            return
        
        print(f"\nCompleted Runs for Run_id {run_id}:")
        
        try:
            print(tabulate(data_for_tabulate, headers=keys, tablefmt="pretty", showindex=range(1, len(data_for_tabulate) + 1)))
        except Exception as e:
            logging.error(f"Error while displaying data: {e}")
            print(f"Somthing went wrong while fetching completed runs. Check logs for details.")
        
        try:
            selected_index = int(input("\nSelect the run to download the output file (0 to exit): "))
        except ValueError:
            logging.error("User entered a non-integer value.")
            print("Invalid input. Please enter a valid number.")
            return
        
        if selected_index == 0:
            print("Exiting download process...")
            return
        
        if selected_index < 1 or selected_index > len(data_for_tabulate):
            print("Invalid index selected. Please try again.")
            return
        
        selected_run = data_for_tabulate[selected_index - 1]
        component_name = str(selected_run[keys.index("Component_Name")]).replace(" ", "_")

        # Locate the exact output file in the Outputs directory
        output_dir = config.get("DEFAULT", "output_dir", fallback="Outputs")
        search_pattern = os.path.join(output_dir, f"{run_id}_{component_name}_*.csv")
        output_files = glob.glob(search_pattern)

        if not output_files:
            print(f"\nError: No output file found for Run ID '{run_id}' and Component '{component_name}' in '{output_dir}'.")
            logging.error(f"Output file for Run ID '{run_id}' and Component '{component_name}' not found.")
            return

        # Use the first matching file (should be the correct one)
        output_file = output_files[0]
        expected_filename = os.path.basename(output_file)  # Extract filename with timestamp

        # Prompt user for destination folder
        output_file_path = input("\nEnter the destination folder path to save the output file: ").strip().strip('"').strip("'")

        # Fix Windows path issue
        output_file_path = os.path.normpath(output_file_path)

        # Ensure the path is valid
        if not os.path.exists(output_file_path):
            print(f"\nError: The specified directory '{output_file_path}' does not exist. Please enter a valid path.")
            logging.error(f"Invalid directory specified: {output_file_path}")
            return

        # Copy the file to the user's specified location
        destination_file = os.path.join(output_file_path, expected_filename)
        shutil.copy(output_file, destination_file)

        print(f"\nSuccess! Output file '{expected_filename}' has been saved to '{destination_file}'.")
        logging.info(f"Output file '{expected_filename}' successfully copied to '{destination_file}'.")

    except Exception as e:
        print("\nAn error occurred while processing the download. Check logs for details.")
        logging.error(f"Error in downloading the output file: {str(e)}")


def create_control_flag_file():
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_control_flag_path = os.path.join(input_dir, "Phishwatch_Run_Control_Flag.csv")
    
    data_to_append = []
    
    for key, value in menu_options.items():
        if key == 0 or key == 12:
            continue
        data_to_append.append({
            "Run_id": active_run_id.zfill(2),
            "Component_name": value,
            "Status": "Continue"
        })
    
    run_control_flag_headers = ["Run_id", "Component_name", "Status"]

    
    with open(run_control_flag_path, "a", newline="", encoding="utf-8") as control_file:
        writer = csv.DictWriter(control_file, fieldnames=run_control_flag_headers)
        if not os.path.exists(run_control_flag_path) or os.stat(run_control_flag_path).st_size == 0:
            writer.writeheader()
        writer.writerows(data_to_append)
    logging.info(f"Created Phishwatch_Run_Control_Flag file at {run_control_flag_path}")

def update_control_flag_file(component_name, status):
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_control_flag_path = os.path.join(input_dir, "Phishwatch_Run_Control_Flag.csv")
    
    if not os.path.exists(run_control_flag_path):
        print("Error: Run Control Flag file not found.")
        logging.error("Run Control Flag file not found.")
        return
    
    updated_rows = []
    update_status = False
    
    try:
        with open(run_control_flag_path, "r", encoding="utf-8") as control_file:
            reader = csv.DictReader(control_file)
            rows = list(reader)
            for row in rows:
                if row["Run_id"] == active_run_id:
                    if update_status or component_name in row["Component_name"]:
                        update_status = True
                        row["Status"] = status
                updated_rows.append(row)
        
        with open(run_control_flag_path, "w", newline="", encoding="utf-8") as control_file:
            writer = csv.DictWriter(control_file, fieldnames=reader.fieldnames)
            writer.writeheader()
            writer.writerows(updated_rows)
        
        logging.info(f"Changed status of component '{component_name}' for run id '{active_run_id}' to '{status}'.")
        print(f"Changed status of component '{component_name}' for run id '{active_run_id}' to '{status}'.")
    except Exception as e:
        print("An error occurred while updating the Run Control Flag file. Check logs for details.")
        logging.error(f"Error updating Run Control Flag file: {str(e)}")



def stop_run():
    global active_run_id, active_customer_id, active_customer_name
    
    input_dir = config.get("DEFAULT", "input_dir", fallback="Inputs")
    run_control_flag_path = os.path.join(input_dir, "Phishwatch_Run_Control_Flag.csv")
    run_tracker_file = os.path.join(input_dir, "Run_Tracker.csv")
    
    if not os.path.exists(run_control_flag_path):
        print("Error: Run Control Flag file not found.")
        logging.error("Run Control Flag file not found.")
        return
    
    if not os.path.exists(run_tracker_file):
        print("Run Tracker file not found.")
        logging.error("Run Tracker file not found.")
        return
    
    current_components = list(menu_options.values())
    current_components.pop(0)
    current_components.pop()
    
    while True:
        run_id = input("Enter run_id (0 to exit): ").strip()
        
        # Check if the input is '0' to exit
        if run_id == '0':
            logging.info("Exiting to main menu...")
            print("Exiting to main menu...")
            return
        
        # Check if the run_id is a valid number
        if not run_id.isdigit():
            print("Invalid run_id. Please enter a valid number.")
            continue
        
        # Ensure run_id is formatted with leading zeros (if needed)
        run_id = run_id.zfill(2)
        active_run_id = run_id
        break
    
    data = []
    
    with open(run_tracker_file, "r", encoding="utf8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["Run_id"] == run_id:
                active_customer_id = row["Customer_id"]
                active_customer_name = row["Customer_name"]
                data.append(row)
    
    updated_data = []
    latest_timestamps = {}  # Dictionary to track the latest timestamp for each component
    
    for component in current_components:
        found = False
        for row in data:
            if row["Component_Name"] == "":
                continue
            elif row["Component_Name"] in component and row["Component_Status"] == "100%":
                found = True
                continue
            elif row["Component_Name"] in component and row["Component_Status"] != "100%":
                component_name = row["Component_Name"]
                timestamp = row["Timestamp"]
                
                # Check if this component has a newer timestamp
                if component_name not in latest_timestamps or timestamp > latest_timestamps[component_name]["Timestamp"]:
                    latest_timestamps[component_name] = {
                        "Run_id": row["Run_id"],
                        "Customer_id": row["Customer_id"],
                        "Customer_name": row["Customer_name"],
                        "Timestamp": timestamp,
                        "Component_Name": component_name,
                        "Component_Status": row["Component_Status"],
                    }
                found = True
        
        # If component is not found, add additional data
        if not found:
            component_name = component
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            latest_timestamps[component_name] = {
                "Run_id": run_id,
                "Customer_id": active_customer_id,
                "Customer_name": active_customer_name,
                "Timestamp": timestamp,
                "Component_Name": component_name,
                "Component_Status": "0% (Not Started)",
            }
    
    # Convert the dictionary values to the updated_data list
    updated_data = list(latest_timestamps.values())
    
    keys = ["Run_id", "Customer_id", "Customer_name", "Timestamp", "Component_Name", "Component_Status"]
    
    with open(run_control_flag_path, "r", encoding="utf-8") as control_file:
        reader = csv.DictReader(control_file)
        rows = list(reader)
        
        for row in rows:
            if row["Run_id"] == run_id and row["Status"] == "Stopped":
                updated_data = [data for data in updated_data if data["Component_Name"] not in row["Component_name"]]
            
    
    data_for_tabulate = []
    for row in updated_data:
        data_for_tabulate.append([row[key] for key in keys])
    
    if not data_for_tabulate:
        print(f"No running run found for run_id: {run_id}")
        logging.warning(f"No running run found for run_id: {run_id}")
        return
    
    # Stop all components with the run id provided by the user
    # for row in data_for_tabulate:
    #     component_name = str(row[keys.index("Component_Name")])
    #     update_control_flag_file(component_name, "Stopped")


def main():
    """Main function to execute the wrapper."""
    global active_run_id, active_customer_id, active_customer_name  # Declare global variables

    # Step 1: Create required files first
    create_run_files()
    print("Required files created successfully.")
    
    # Step 2: Run TLD Updater or other initial setup
    run_tld_updater()
    print("TLD Updater executed successfully.")
    
    # Step 3: Display main menu options to the user
    while True:
        print("\nSelect an option:")
        print("0. Display all registered customers")
        print("1. Show Run Status")
        print("2. Show all pending run")
        print("3. Show all completed run")
        print("4. Start a new run")
        print("5. Complete a pending run")
        print("6. Download Finished Output File")  # Correctly assigned to option 6
        print("7. Download Output File")
        print("8. Phishwatch_utility")
        print("9. Stop a Run")
        print("10. Exit")

        try:
            choice = int(input("Enter your choice: ").strip())

            if choice == 0:
                show_registered_customers()
            elif choice == 1:
                show_run_status()
            elif choice == 2:
                show_pending_runs()
            elif choice == 3:
                show_completed_run()
            elif choice == 4:
                start_new_run()
            elif choice == 5:
                complete_run()
            elif choice == 6:
                download_finished_output_file()  # Ensure this is correctly placed
            elif choice == 7:
                download_output_file()
            elif choice == 8:
                run_phishwatch_utility()  # Correctly placed for option 7
            elif choice == 9:
                stop_run()
            elif choice == 10:
                print("Exiting program...")
                break
            else:
                print("Invalid choice. Please select a valid option.")

        except ValueError:
            print("Invalid input. Please enter a valid number.")
        except Exception as e:
            logging.error(f"Unexpected error in main menu: {str(e)}")
            print("An unexpected error occurred. Check logs for details.")

if __name__ == "__main__":
    main()
