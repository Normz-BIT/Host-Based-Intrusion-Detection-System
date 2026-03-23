# file_monitor.py
import os.path  # for file reading and writing
import hashlib  # to generate file sha256 hashes 
import json     # json read and write functions
from log import log # to log all detections to file
from log import Severity #enum for diffrent severity levels
from log import Event # enum for the diffrent events 


FILE_MONITOR = 'FILE MONITOR' # to show current function in the terminal
HASHES_FILE = 'hashes.json'  # name of the json file with the hashes
MONITORED_DIR = '/etc'      # directory being monitored


#Return SHA-256 hash of a file's contents
def hash_file(filepath):
    sha256 = hashlib.sha256() #store hash object 
    try:
        with open(filepath, 'rb') as f: # open currentt file as binary
            while chunk := f.read(8192): # reads file in 8kB blocks 
                sha256.update(chunk) # adds each chunk into the running hash calculation.
        return sha256.hexdigest() #save hash as sting with only hexadecimal digits. 
    except Exception: # return empty hash if file cannot be read
        return None

# Walk the directory and return a dict of {filepath: hash}
def scan_directory(directory):
    file_hashes = {} # dictionary to hold values
    for root,dirs,files in os.walk(directory): #scan all folders and subfolder
        for name in files:
            full_path = os.path.join(root, name) # save the location of the current file
            hash = hash_file(full_path) # get hash of the current file
            if hash: #if hash is not empty
                file_hashes[full_path] = hash # save file location and hash to dictionary
    return file_hashes # return the dictionary

# Generate and save the initial hashes
def create_baseline():
    print(f"[{FILE_MONITOR}] Creating baseline for {MONITORED_DIR} ...")

    baseline = scan_directory(MONITORED_DIR) # get hashes of all files in the current directory and subfolder

    with open(HASHES_FILE, 'w') as f: #overwrites json file if it exists and creates it if not.
        json.dump(baseline, f, indent=2) #converts the dictionary data into JSON format and writes it to hashes.json.
        print(f"[{FILE_MONITOR}] Baseline saved: {len(baseline)} files hashed.")
    
    return baseline # return file hash dictionary

# Load existing baseline from JSON
def load_baseline():
    
    if not os.path.exists(HASHES_FILE): # check if hash file exist
        return create_baseline() # if not create new hash file
    with open(HASHES_FILE, 'r') as f: # else load file
        return json.load(f) #converts JSON into a dictionary


# Compare current state against base hashes and log any changes.
def check_integrity():
    baseline = load_baseline() # get saved hashes or generates new initial  ones
    current   = scan_directory(MONITORED_DIR) #continously generate new hashes to detect any changes 

    # Detect modified and new files
    for filepath, current_hash in current.items():
        if filepath not in baseline: #check if scanned file exist in the initial scan
            log(Event.FILE_ADDED, Severity.Medium, filepath, 'New file detected')
            create_baseline() #recreate base hashes to prevent same detection
        elif baseline[filepath] != current_hash: # check if file exist but hashes are diffrent
            log(Event.FILE_MODIFIED, Severity.High, filepath, 'File hash changed')
            create_baseline() #recreate base hashes to prevent same detection

    # Detect deleted files
    for filepath in baseline:
        if filepath not in current: # check if file in intial scan exist in the current scan
            log(Event.FILE_DELETED, Severity.Low, filepath, 'File no longer exists')
            create_baseline() #recreate base hashes to prevent same detection