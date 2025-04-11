import os
import re
import subprocess
import sys
import logging
import time

# Set up logging to write log entries to a file
log_file_path = "/mnt/c/Users/gideo/OneDrive/Documents/515R/logfile.log"  # Modify this path as needed
logging.basicConfig(filename=log_file_path, 
                    level=logging.DEBUG,  # Log everything from DEBUG level and higher
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to ensure the script is run as root
def check_root_permissions():
    """Check if the script is running as root, otherwise exit."""
    if os.geteuid() != 0:  # Check if the script is run as root (ID 0)
        error_message = "[ERROR] This script must be run as root. Try: sudo python3 scriptname.py"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(error_message)  # Log the error
        sys.exit(1)  # Exit the script

# Function to check if a file exists
def check_file_exists(file_path):
    """Check if the file exists."""
    if not os.path.exists(file_path):
        error_message = f"[ERROR] {file_path} not found!"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(error_message)  # Log the error
        return False  # Return False if the file does not exist
    return True  # Return True if the file exists

# Function to check file permissions
def check_file_permissions(file_path):
    """Check if the file permissions are -rw-r--r--."""
    try:
        if not check_file_exists(file_path):
            return  # Return if the file does not exist

        # Get the file's permission bits (last 3 digits of octal value)
        file_permissions = oct(os.stat(file_path).st_mode)[-3:]
        
        # Check if the permissions match the expected '-rw-r--r--' (644)
        if file_permissions != "644":
            warning_message = f"[WARNING] The file permissions for {file_path} are not correct. They should be '-rw-r--r--' (644). Current permissions: {file_permissions}"
            print(f"\033[91m{warning_message}\033[0m")  # Print warning in red
            logging.warning(warning_message)  # Log the warning
        else:
            print(f"[INFO] The file permissions for {file_path} are correct!")  # Print info if correct

    except Exception as e:
        error_message = f"[ERROR] An unexpected error occurred while checking permissions for {file_path}: {e}"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(f"{error_message} {e}")  # Log the error

# Function to scan the sshd_config for security risks
def scan_security_risks(file_path, risky_settings):
    """Scan the sshd_config file for security risks."""
    try:
        if not check_file_exists(file_path):
            return  # Return if the file does not exist

        print(f"[INFO] Scanning {file_path} for potential security risks...")

        with open(file_path, "r") as file:
            lines = file.readlines()  # Read all lines from the file

        # Check each line for risky settings
        for line in lines:
            line = line.strip()  # Remove leading/trailing spaces
            for setting, risky_value in risky_settings.items():
                match = re.match(f"^{setting}\\s+(\\S+)", line)  # Match setting and value
                if match and match.group(1) == risky_value:  # If the value matches the risky one
                    warning_message = f"[WARNING] {setting} is set to '{risky_value}' which may be insecure."
                    print(f"\033[91m{warning_message}\033[0m")  # Print warning in red
                    logging.warning(warning_message)  # Log the warning

        print("[INFO] Scan complete.")  # Print info when the scan is complete
    
    except PermissionError as e:
        error_message = f"[ERROR] Permission denied when trying to read {file_path}. Please check your permissions."
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(f"{error_message} {e}")  # Log the error
    except Exception as e:
        error_message = f"[ERROR] An unexpected error occurred while scanning {file_path}: {e}"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(f"{error_message} {e}")  # Log the error

# Function to check for commented-out lines in the file
def check_commented_lines(file_path):
    """Check if any lines are commented out in the file."""
    try:
        if not check_file_exists(file_path):
            return  # Return if the file does not exist

        print(f"[INFO] Checking for commented-out settings in {file_path}...")

        with open(file_path, "r") as file:
            lines = file.readlines()  # Read all lines from the file

        commented_lines = [line.strip() for line in lines if line.strip().startswith("#")]

        if commented_lines:
            print("[INFO] Found commented-out lines:")
            # Join all lines into a string and pass to 'less'
            #print("\n[INFO] Opening results in 'less'. Use ↑ ↓ to scroll, 'q' to quit.", flush=True)  # <-- Add this line
            #time.sleep(0.2)
            output = "\n".join(commented_lines)
            subprocess.run(["less"], input=output.encode(), check=True)
        else:
            print("[INFO] No commented-out lines found.")  # If no commented lines

    except PermissionError as e:
        error_message = f"[ERROR] Permission denied when trying to read {file_path}. Please check your permissions."
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(f"{error_message} {e}")  # Log the error
    except Exception as e:
        error_message = f"[ERROR] An unexpected error occurred while checking commented lines in {file_path}: {e}"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(f"{error_message} {e}")  # Log the error

# Function to prompt the user for an action
def user_prompt():
    """Prompt the user for the next action."""
    # Check file permissions before displaying the menu
    check_file_permissions("/etc/ssh/sshd_config")

    while True:
        try:
            print("\nChoose an action:")
            print("1. Run entire scan for security risks")
            print("2. Check for commented-out settings(Note: OPENS FILE IN LESS. 'q' to quit)")
            print("3. Exit")
            
            choice = input("Enter your choice (1, 2, or 3): ")

            if choice == "1":
                risky_settings = {  # Define risky settings to check in sshd_config
                    "PermitRootLogin": "yes",
                    "PasswordAuthentication": "yes",
                }
                scan_security_risks("/etc/ssh/sshd_config", risky_settings)  # Run security risk scan

                next_action = input("Scan complete. Do you want to: \n1. Exit\n2. Show options\nEnter your choice: ")
                if next_action == "1":
                    print("Exiting program. Goodbye!")  # Print exit message
                    logging.info("User chose to exit the program.")  # Log this action
                    break
                elif next_action == "2":
                    continue
                else:
                    error_message = "[ERROR] Invalid input! Returning to options menu."
                    print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
                    logging.error(error_message)  # Log the error
                    continue

            elif choice == "2":
                check_commented_lines("/etc/ssh/sshd_config")  # Check for commented-out settings
            elif choice == "3":
                print("Exiting program. Goodbye!")  # Print exit message
                logging.info("User chose to exit the program.")  # Log this action
                break
            else:
                error_message = "[ERROR] Invalid input! Please choose 1, 2, or 3."
                print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
                logging.error(error_message)  # Log the error

        except Exception as e:
            error_message = f"[ERROR] An unexpected error occurred: {e}"
            print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
            logging.error(error_message)  # Log the error
            continue

# Main function to run the program
def main():
    """Main function to execute the script."""
    try:
        check_root_permissions()  # Ensure the script is run as root
        user_prompt()  # Call the user prompt function
    
    except Exception as e:
        error_message = f"[ERROR] Unexpected error: {e}"
        print(f"\033[93m{error_message}\033[0m")  # Print error in yellow
        logging.error(error_message)  # Log the error

# Run the main function if this script is executed directly
if __name__ == "__main__":
    main()
