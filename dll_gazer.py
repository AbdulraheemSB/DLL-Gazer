import os
import psutil
import hashlib
import requests
from tqdm import tqdm

# VirusTotal API Key (Replace with your key)
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"

# Directories to scan
DLL_DIRECTORIES = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]

# Function to calculate MD5 and SHA-256 hashes
def calculate_hashes(file_path):
    try:
        with open(file_path, "rb") as f:
            md5_hasher = hashlib.md5()
            sha256_hasher = hashlib.sha256()
            while chunk := f.read(4096):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
            return md5_hasher.hexdigest(), sha256_hasher.hexdigest()
    except Exception:
        return None, None

# Check VirusTotal for a single hash
def check_virustotal_single(md5_hash):
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"data": None}  # Not found in VirusTotal
    else:
        print(f"[❌] Error: {response.status_code} - {response.text}")
        return None

# Scan DLLs on VirusTotal
def check_dlls_on_virustotal(dll_files):
    print("\n[🔍] Checking DLLs on VirusTotal...")

    # Check each DLL hash individually
    for dll in tqdm(dll_files, desc="Checking DLLs", unit="file"):
        md5_hash, sha256_hash = calculate_hashes(dll)
        if md5_hash:
            result = check_virustotal_single(md5_hash)
            
            if result and "data" in result and result["data"]:
                malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
                status = "Malicious 🔴" if malicious > 0 else "Clean 🟢"
            else:
                status = "Unknown (Not found in VirusTotal)"
                
            print(f"[{status}] {dll}")
        

    print("\n[🚀] VirusTotal scan completed!")

# Function to scan DLLs
def scan_dlls(dll_files):

    print("\n[❓] Choose an option:")
    print("1 - Generate MD5 & SHA-256 hashes")
    print("2 - Check DLLs on VirusTotal")
    print("3 - Turn Back")

    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == "1":
        hash_entries = []
        print("\n[⚡] Generating MD5 & SHA-256 hashes...\n")
        for dll in tqdm(dll_files, desc="Hashing DLLs", unit="file"):
            md5_hash, sha256_hash = calculate_hashes(dll)
            if md5_hash:
                hash_entries.append((dll, md5_hash, sha256_hash))
                print(f"{dll} → MD5: {md5_hash} | SHA-256: {sha256_hash}")

        # Prompt user to save hashes
        while True:
            print("\n[💾] Choose an option to save hashes:")
            print("1 - Save as a Log file")
            print("2 - Save as a CSV file")
            print("3 - Turn Back")
            save_choice = input("Enter your choice (1, 2, or 3): ").strip()

            if save_choice == "1":
                with open("dll_hashes.log", "w") as log_file:
                    for dll, md5_hash, sha256_hash in hash_entries:
                        log_file.write(f"{dll}: MD5={md5_hash}, SHA-256={sha256_hash}\n")
                print("\n[📄] Hashes saved to: dll_hashes.log")
                break

            elif save_choice == "2":
                with open("dll_hashes.csv", "w") as csv_file:
                    csv_file.write("File Path,MD5 Hash,SHA-256 Hash\n")
                    for dll, md5_hash, sha256_hash in hash_entries:
                        csv_file.write(f'"{dll}","{md5_hash}","{sha256_hash}"\n')
                print("\n[📄] Hashes saved to: dll_hashes.csv")
                break

            elif save_choice == "3":
                print("\n[↩️] Returning to previous menu...")
                break

            else:
                print("[❌] Invalid choice. Please enter 1, 2, or 3.")

    elif choice == "2":
        check_dlls_on_virustotal(dll_files)

    elif choice == "3":
        print("\n[↩️] Returning to main menu...")

    else:
        print("[❌] Invalid choice. Please enter 1, 2, or 3.")

# Show running DLLs
def show_running_dlls():
    print("\n[🟢] Scanning running DLL files...")
    running_dlls = set()

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            for mod in proc.memory_maps():
                if mod.path.endswith(".dll"):
                    running_dlls.add(mod.path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    print(f"\n=== Running DLL Files ({len(running_dlls)}) ===")
    for dll in running_dlls:
        print(dll)

    print(f"\n[✅] Total DLL files scanned: {len(running_dlls)}")
    scan_dlls(running_dlls)

# Scan all DLLs in system directories
def scan_all_dlls():
    all_dlls = set()

    for directory in DLL_DIRECTORIES:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".dll"):
                    all_dlls.add(os.path.join(root, file))

    print(f"\n=== Found {len(all_dlls)} DLL Files ===")
    for dll in all_dlls:
        print(dll)

    print(f"\n[✅] Total DLL files scanned: {len(all_dlls)}")
    scan_dlls(all_dlls)

# Interactive CLI Menu
while True:
    print("\nChoose an option:")
    print("1 - Scan all DLL files")
    print("2 - Show running DLLs")
    print("3 - Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        scan_all_dlls()
    elif choice == "2":
        show_running_dlls()
    elif choice == "3":
        print("[🚪] Exiting program...")
        break
    else:
        print("[❌] Invalid choice. Please enter 1, 2, or 3.")
