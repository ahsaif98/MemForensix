import os
import argparse
import subprocess
import time
import sys
import six
import platform

# Global variable to store which platform the user is on
vol_command = "vol.py"
bulk_extractor_command = "bulk_extractor"

def ask_platform():
    """
    Ask the user which platform they are using (Windows or Linux).
    Sets the appropriate command for running Volatility and Bulk Extractor based on the user's input.
    """
    global vol_command, bulk_extractor_command
    while True:
        platform = input("Are you using Windows or Linux? (Enter 'Windows' or 'Linux'): ").strip().lower()
        if platform == 'windows':
            vol_command = "vol2.exe"
            bulk_extractor_command = "bulk_extractor.exe"
            print("Running on Windows. Using vol2.exe for Volatility and bulk_extractor.exe for Bulk Extractor commands.")
            break
        elif platform == 'linux':
            vol_command = "vol.py"
            bulk_extractor_command = "bulk_extractor"
            print("Running on Linux. Using vol.py for Volatility and bulk_extractor for Bulk Extractor commands.")
            break
        else:
            print("Invalid input. Please enter 'Windows' or 'Linux'.")

def run_volatility_imageinfo(img_file):
    print("\nRunning Volatility Imageinfo...")
    time.sleep(5)  # Simulate processing time

    command = "{} -f {} imageinfo".format(vol_command, img_file)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    suggested_profiles = ""
    acquisition_time = ""

    for line in stdout.decode('utf-8').splitlines():
        if "Suggested Profile(s)" in line:
            suggested_profiles = line.strip()
        if "Image local date and time" in line:
            acquisition_time = line.strip().split(" : ")[1]

    print("\n" + suggested_profiles)

    profile = suggested_profiles.split(":")[1].strip().split(",")[0].strip()
    return profile, acquisition_time

def run_kdbgscan(img_file, profile):
    print("\nRunning Volatility KDBGScan...")
    time.sleep(5)  # Simulate processing time

    command = "{} -f {} --profile={} kdbgscan".format(vol_command, img_file, profile)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    kdbg_value = ""
    kd_copy_data_block_value = ""

    for line in stdout.decode('utf-8').splitlines():
        if "Offset (V)" in line:
            kdbg_value = line.split(":")[1].strip()
        elif "KdCopyDataBlock (V)" in line:
            kd_copy_data_block_value = line.split(":")[1].strip()

    if "Win8" in profile or "Win10" in profile or "Win11" in profile:
        return kd_copy_data_block_value if kd_copy_data_block_value else "KdCopyDataBlock value not found."
    else:
        return kdbg_value if kdbg_value else "Offset value not found."

def run_psxview(img_file, profile, kdbg_value):
    print("\nRunning Volatility PSXView...")
    time.sleep(5)  # Simulate processing time

    command = "{} -f {} --profile={} -g {} psxview -R".format(vol_command, img_file, profile, kdbg_value)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    return stdout.decode('utf-8')

def run_pstree(img_file, profile, kdbg_value):
    print("\nRunning Volatility PSTree...")
    time.sleep(5)  # Simulate processing time

    command = "{} -f {} --profile={} -g {} pstree --output=dot --output-file=pstree.dot".format(vol_command, img_file, profile, kdbg_value)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    return stdout.decode('utf-8')

def extract_username_computername(img_file, profile, kdbg_value):
    print("\nRunning Volatility Envars...")
    
    command = "{} -f {} --profile={} -g {} envars -n explorer.exe".format(vol_command, img_file, profile, kdbg_value)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    username = "Username not found."
    computername = "Computer name not found."

    for line in stdout.decode('utf-8').splitlines():
        if "USERNAME" in line:
            username = line.split("USERNAME")[1].strip()
        elif "COMPUTERNAME" in line:
            computername = line.split("COMPUTERNAME")[1].strip()

    return username, computername

def extract_build_info(img_file, profile, kdbg_value):
    print("\nRunning Volatility Printkey for Build Information...")
    time.sleep(5)  # Simulate processing time

    command = '{} -f {} --profile={} -g {} printkey -K "Microsoft\\Windows NT\\CurrentVersion"'.format(vol_command, img_file, profile, kdbg_value)
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()

    build_info = {}
    for line in stdout.decode('utf-8').splitlines():
        if "CurrentBuildNumber" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                build_info["CurrentBuildNumber"] = parts[1].strip().replace("REG_SZ", "").strip()
        elif "BuildLab" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                build_info["BuildLab"] = parts[1].strip().replace("REG_SZ", "").strip()
        elif "BuildLabEx" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                build_info["BuildLabEx"] = parts[1].strip().replace("REG_SZ", "").strip()
        elif "BuildGUID" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                build_info["BuildGUID"] = parts[1].strip().replace("REG_SZ", "").strip()

    return build_info

def extract_data_bulk_extractor(img_file):
    print("\nRunning Bulk Extractor...")

    # Command to run Bulk Extractor (adjust for Windows and Linux)
    command = '{} -E all -o bulk_output {}'.format(bulk_extractor_command, img_file)
    
    result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    # Display initial information
    print("Input file: {}".format(img_file))
    print("Output directory: bulk_output")

    # Read output line by line
    while True:
        output = result.stdout.readline()
        if output == "" and result.poll() is not None:
            break
        if output:
            print(output.strip())

    # Check for errors
    stderr = result.stderr.read()
    if stderr:
        print("Error running Bulk Extractor:")
        print(stderr.strip())
        return None

    print("\nBulk Extractor completed successfully.")
    print("All output is saved to 'bulk_output' directory.")

    return "Bulk Extractor output processing complete."

def extract_shellbags(img_file, profile, kdbg_value):
    """
    Extracts shellbags from a memory image using Volatility and prints the output.
    """
    command = "{} -f {} --profile={} -g {} shellbags".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.check_output(command, shell=True, universal_newlines=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print("An error occurred while extracting shellbags:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)

def extract_ie_history(img_file, profile, kdbg_value):
    """
    Extracts Internet Explorer history from a memory image using Volatility and prints the output.
    """
    command = "{} -f {} --profile={} -g {} iehistory".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.check_output(command, shell=True, universal_newlines=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print("An error occurred while extracting IE history:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)

def extract_clipboard(img_file, profile, kdbg_value):
    """
    Extracts clipboard data from a memory image using Volatility and prints the output.
    """
    print("\nRunning Volatility Clipboard...")
    command = "{} -f {} --profile={} -g {} clipboard -v".format(vol_command, img_file, profile, kdbg_value)
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        print("\nClipboard data extracted:\n")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error occurred while running clipboard command:\n", e.output)

def extract_usbstor(img_file, profile, kdbg_value):
    """
    Extracts USB storage device information from a memory image using Volatility and prints the output.
    """
    print("\nRunning Volatility USBStor...")
    command = "{} -f {} --profile={} -g {} usbstor".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout:
            print("\nUSB storage information extracted:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))
    except Exception as e:
        print("An error occurred while running USBStor extraction: {}".format(e))

def extract_uninstallinfo(img_file, profile, kdbg_value):
    """
    Extracts information about installed and uninstalled programs from a memory image using Volatility's uninstallinfo plugin.
    """
    print("\nRunning Volatility UninstallInfo...")
    command = "{} -f {} --profile={} -g {} uninstallinfo".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout:
            print("\nUninstall Information extracted:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))
    except Exception as e:
        print("An error occurred while running UninstallInfo extraction: {}".format(e))

def extract_shimcachemem(img_file, profile, kdbg_value):
    """
    Extracts Application Compatibility Shim Cache data from a memory image using Volatility's shimcachemem plugin.
    """
    print("\nRunning Volatility ShimCacheMem...")
    command = "{} -f {} --profile={} -g {} shimcachemem".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout:
            print("\nShim Cache data extracted:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))
    except Exception as e:
        print("An error occurred while running ShimCacheMem extraction: {}".format(e))

def extract_dumpcerts(img_file, profile, kdbg_value):
    """
    Extracts SSL certificates from a memory image using Volatility's dumpcerts plugin and stores them in a specified directory.
    """
    print("\nRunning Volatility DumpCerts...")
    dump_dir = "Dumped_SSL_certificates"
    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
        print("Directory {} created.".format(dump_dir))

    command = "{} -f {} --profile={} -g {} dumpcerts --dump-dir={}".format(vol_command, img_file, profile, kdbg_value, dump_dir)
    try:
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout:
            print("\nDumpCerts plugin output:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))
    except Exception as e:
        print("An error occurred while running DumpCerts extraction: {}".format(e))

def extract_editbox(img_file, profile, kdbg_value):
    """
    Extracts data from editboxes in memory using Volatility's editbox plugin.
    """
    print("\nRunning Volatility EditBox...")
    command = "{} -f {} --profile={} -g {} editbox".format(vol_command, img_file, profile, kdbg_value)
    try:
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout:
            print("\nEditBox plugin output:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))
    except Exception as e:
        print("An error occurred while running EditBox extraction: {}".format(e))



def extract_mimikatz(img_file, profile, kdbg_value):
    """
    Extracts credentials using the Mimikatz plugin from a memory image using Volatility.
    """
    print("\nRunning Volatility Mimikatz...")

    # Command to run the mimikatz plugin
    command = "{} -f {} --profile={} -g {} mimikatz".format(vol_command, img_file, profile, kdbg_value)
    
    try:
        # Using subprocess to run the command with text mode enabled
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = result.communicate()

        if stdout:
            print("\nMimikatz plugin output:\n")
            print(stdout)
        if stderr:
            print("\nError Output:\n")
            print(stderr)

    except subprocess.CalledProcessError as e:
        print("An error occurred while extracting Mimikatz data:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)


def extract_filescan(img_file, profile, kdbg_value):
    """
    Runs the Volatility filescan plugin and saves the output to a file named 'filescan.txt'.
    Works with both Python 2 and Python 3.
    """
    print("\nRunning Volatility FileScan...")

    # Command to run filescan and redirect output to 'filescan.txt'
    command = "{} -f {} --profile={} -g {} filescan > filescan.txt".format(vol_command, img_file, profile, kdbg_value)

    try:
        # Using subprocess to run the command
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()

        if stdout:
            print("\nFilescan output saved to 'filescan.txt'.")
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))

    except subprocess.CalledProcessError as e:
        print("An error occurred while running filescan:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)

def dump_files_by_offset(img_file, profile, offset):
    """
    Dumps files from a memory image using the Volatility dumpfiles plugin and an offset.
    Handles directory creation for both Windows and Linux.
    """
    print("\nRunning Volatility DumpFiles with offset...")

    # Set the directory for saving the dumped files
    if platform.system() == "Windows":
        output_dir = os.path.join(os.getcwd(), "dumped_files_windows")
    else:  # Assume Linux/Unix-like system
        output_dir = os.path.join(os.getcwd(), "dumped_files_linux")

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print("Directory '{}' created.".format(output_dir))

    # Command to dump files using the specified offset (-Q) and output directory (-D)
    command = "{} -f {} --profile={} dumpfiles -Q {} -n -D {}".format(vol_command, img_file, profile, offset, output_dir)

    try:
        # Using subprocess to run the command
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()

        if stdout:
            print("\nDumpFiles plugin output:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))

        print("\nDumpFiles completed. Files are saved in the '{}' directory.".format(output_dir))

    except subprocess.CalledProcessError as e:
        print("An error occurred while running dumpfiles:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)

def dump_process_by_pid(img_file, profile, kdbg_value):
    """
    Dumps the memory of a specific process by its PID from a memory image using Volatility's procdump plugin.
    Handles directory creation for both Windows and Linux.
    """
    print("\nRunning Volatility Procdump for a specific process...")

    # Ask the user for the Process ID (PID)
    pid = input("Enter the PID of the process to dump: ").strip()

    # Set the directory for saving the process dumps
    if platform.system() == "Windows":
        output_dir = os.path.join(os.getcwd(), "process_dumps_windows")
    else:  # Assume Linux/Unix-like system
        output_dir = os.path.join(os.getcwd(), "process_dumps_linux")

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print("Directory '{}' created.".format(output_dir))

    # Command to dump the specific process by PID
    command = "{} -f {} --profile={} -g {} procdump --pid={} --dump-dir={}".format(vol_command, img_file, profile, kdbg_value, pid, output_dir)

    try:
        # Using subprocess to run the command
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()

        if stdout:
            print("\nProcdump plugin output:\n")
            print(stdout.decode('utf-8'))
        if stderr:
            print("\nError Output:\n")
            print(stderr.decode('utf-8'))

        print("\nProcdump completed. Process dump saved in the '{}' directory.".format(output_dir))

    except subprocess.CalledProcessError as e:
        print("An error occurred while dumping the process:", e.output)
    except Exception as e:
        print("An unexpected error occurred:", e)


def menu():
    print("\nMemory Analysis Tool")
    print("====================")
    print("1. Show Profiles")
    print("2. Show Acquisition Time")
    print("3. Extract KDBG Value")
    print("4. Hidden Process Crossview Analysis")
    print("5. TreeForm Visualization")
    print("6. Extract Username and Computername")
    print("7. Extract Build Information")
    print("8. Extract Data using Bulk Extractor")
    print("9. Extract Shellbags")
    print("10. Extract IE History")
    print("11. Extract Clipboard Data")
    print("12. Extract USB Storage Information")
    print("13. Extract Uninstall Information")
    print("14. Extract ShimCache Information")
    print("15. Extract SSL Certificates")
    print("16. Extract EditBox Data")
    print("17. Extract Mimikatz Data")  
    print("18. Extract FileScan Data")
    print("19. Dump Files by Offset")  
    print("20. Dump Specific Processes") 
    print("21. Exit")




def main():
    parser = argparse.ArgumentParser(description="Memory Analysis Tool")
    parser.add_argument("-f", "--file", type=str, help="Memory image file")
    args = parser.parse_args()

    if not args.file:
        args.file = raw_input("Please enter the path to the memory dump file: ") if six.PY2 else input("Please enter the path to the memory dump file: ")

    # Ask the user which platform they are using
    ask_platform()

    acquisition_time = None
    profile = None
    kdbg_value = None

    while True:
        menu()
        choice = raw_input("Enter your choice (1-21): ") if six.PY2 else input("Enter your choice (1-21): ")

        if choice == '1':
            profile, acquisition_time = run_volatility_imageinfo(args.file)
        elif choice == '2':
            if acquisition_time:
                print("\nAcquisition Time: {}".format(acquisition_time))
            else:
                print("\nPlease run 'Show Profiles' first to obtain the acquisition time.")
        elif choice == '3':
            if profile:
                kdbg_value = run_kdbgscan(args.file, profile)
                print("\nExtracted Value: {}".format(kdbg_value))
            else:
                print("\nPlease run 'Show Profiles' first to set the profile.")
        elif choice == '4':
            if profile and kdbg_value:
                psxview_output = run_psxview(args.file, profile, kdbg_value)
                print("\n" + psxview_output)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '5':
            if profile and kdbg_value:
                pstree_output = run_pstree(args.file, profile, kdbg_value)
                print("\n" + pstree_output)
                print("\nPSTree visualization has been saved as 'pstree.dot'.")
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '6':
            if profile and kdbg_value:
                username, computername = extract_username_computername(args.file, profile, kdbg_value)
                print("\nUsername: {}".format(username))
                print("Computer Name: {}".format(computername))
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '7':
            if profile and kdbg_value:
                build_info = extract_build_info(args.file, profile, kdbg_value)
                if build_info:
                    print("\nBuild Information:")
                    for key, value in build_info.items():
                        print("{} : {}".format(key, value))
                else:
                    print("\nNo build information found.")
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '8':
            if args.file:
                print("\nStarting data extraction using Bulk Extractor...\n")
                result = extract_data_bulk_extractor(args.file)
                if result:
                    print(result)
            else:
                print("\nPlease provide a memory image file to run Bulk Extractor.")
        elif choice == '9':
            if profile and kdbg_value:
                print("\nExtracting shellbags...\n")
                extract_shellbags(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '10':
            if profile and kdbg_value:
                print("\nExtracting IE history...\n")
                extract_ie_history(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '11':
            if profile and kdbg_value:
                print("\nExtracting clipboard data...\n")
                extract_clipboard(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '12':
            if profile and kdbg_value:
                print("\nExtracting USB storage device information...\n")
                extract_usbstor(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '13':
            if profile and kdbg_value:
                print("\nExtracting uninstall information...\n")
                extract_uninstallinfo(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '14':
            if profile and kdbg_value:
                print("\nExtracting ShimCache data...\n")
                extract_shimcachemem(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '15':
            if profile and kdbg_value:
                print("\nExtracting SSL certificates...\n")
                extract_dumpcerts(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '16':  
            if profile and kdbg_value:
                print("\nExtracting EditBox data...\n")
                extract_editbox(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '17':  
            if profile and kdbg_value:
                print("\nExtracting Mimikatz data...\n")
                extract_mimikatz(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '18':  
            if profile and kdbg_value:
                print("\nExtracting FileScan data...\n")
                extract_filescan(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '19':  
            if profile:
                offset = input("Enter the offset value (e.g., 0x000000007e6a0c80): ").strip()
                print("\nDumping files by offset...\n")
                dump_files_by_offset(args.file, profile, offset)
            else:
                print("\nPlease run 'Show Profiles' first to set the profile.")
        elif choice == '20': 
            if profile and kdbg_value:
                print("\nDumping all processes...\n")
                dump_process_by_pid(args.file, profile, kdbg_value)
            else:
                print("\nPlease run 'Show Profiles' and 'Extract KDBG Value' first.")
        elif choice == '21':  
            print("\nExiting the tool.")
            break
        else:
            print("\nInvalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
