# Norman Martin 2300232 
# March 14,2025
# Computer Security

# hids.py
# Main control script for Host-Based Intrusion Detection System that can 
# detect file changes
# detect repeated failed SSH logins
# log security events
# send at least one type of alert
# demonstrate detection using simulated attacks.



import time     # for sleep function
from file import check_integrity  # monitir files for any alterations
from ssh import detect_brute_force #monitor ssh for brute force attempts
def startup():
    print("=" * 50)
    print("IslandPay Tech Limited Intrusion Detection System")
    print("=" * 50)    

def run_hids():
    # File Integrity Check
    print("\nRunning file integrity checks ...")
    check_integrity()

    # SSH Brute Force Detection
    print("\nScanning SSH logs for brute force attempts...")
    detect_brute_force()

if __name__ == '__main__':
    startup()
    while True:
        run_hids()
        time.sleep(1)

print("\nHIDS scan complete. Check hids.log for details.")