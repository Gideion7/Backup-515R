import os  # Provides functions for interacting with the operating system
import re  # Provides regular expression matching operations

def check_sshd_config(file_path="/etc/ssh/sshd_config"):
    """
    This function checks the SSH daemon configuration file (sshd_config) for potentially insecure settings.
    It looks for specific directives like 'PermitRootLogin' and 'PasswordAuthentication' being set to 'yes',
    which can pose security risks in a server environment.
    """

    # Check if the sshd_config file exists
    if not os.path.exists(file_path):
        print(f"[ERROR] {file_path} not found!")  # Print error message if file is missing
        return  # Exit the function early

    print(f"[INFO] Scanning {file_path} for potential security risks...")  # Notify that scanning has started

    # Dictionary of risky settings and their insecure values
    risky_settings = {
        "PermitRootLogin": "yes",  # Allowing root login is generally insecure
        "PasswordAuthentication": "yes",  # Using passwords instead of keys can be less secure
    }

    # Open the sshd_config file for reading
    with open(file_path, "r") as file:
        lines = file.readlines()  # Read all lines into a list

    # Iterate through each line in the file
    for line in lines:
        line = line.strip()  # Remove leading and trailing whitespace

        # Check each risky setting
        for setting, risky_value in risky_settings.items():
            # Use regex to match the setting and capture its value
            match = re.match(f"^{setting}\\s+(\\S+)", line)
            # If the setting is found and its value matches the risky value
            if match and match.group(1) == risky_value:
                # Print a warning about the insecure setting
                print(f"[WARNING] {setting} is set to '{risky_value}' which may be insecure.")

    print("[INFO] Scan complete.")  # Notify that scanning has finished

# Only run the function if this script is executed directly
if __name__ == "__main__":
    check_sshd_config()
