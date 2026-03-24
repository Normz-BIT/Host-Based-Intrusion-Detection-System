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
from spinner import spinner # for console loading

#startup function
def startup():
    
    print(r"""
+-----------------------------------------------------------------------------+
| ___       _                    _  ____               _____            _     |
||_ _| ___ | |  __ _  _ __    __| ||  _ \  __ _  _   _|_   _|___   ___ | |__  |
| | | / __|| | / _` || '_ \  / _` || |_) |/ _` || | | | | | / _ \ / __|| '_ \ |
| | | \__ \| || (_| || | | || (_| ||  __/| (_| || |_| | | ||  __/| (__ | | | ||
||___||___/|_|_\__,_||_|_|_| \__,_||_|    \__,_| \__, | |_| \___| \___||_| |_||
|| | | ||_ _||  _ \ / ___|                       |___/                        |
|| |_| | | | | | | |\___ \                                                    |
||  _  | | | | |_| | ___) |                                                   |
||_| |_||___||____/ |____/                                                    |
+-----------------------------------------------------------------------------+
""")
    

# runs the file monitoring, ssh checks,logs and alerts
def run_hids():
    # File Integrity Check
    spinner("Running file integrity checks ...","\r\n")
    check_integrity()

    # SSH Brute Force Detection
    spinner("Scanning SSH logs for brute force attempts...",'\033[F\r')

    detect_brute_force()


if __name__ == '__main__':
    startup()
    #run checks in a loop until program is closed
    while True:
        run_hids()
        #sleep to reduce cpu cycles 
        time.sleep(5)
#close message
print("\nHIDS scan complete. Check hids.log for details.")


