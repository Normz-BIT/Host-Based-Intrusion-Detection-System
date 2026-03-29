# Asher Smith 
# Norman Martin
# Lilly Whyte 
# Nathan Bowen 

# March 14,2025
# Computer Security

# hids.py
# Main control script for Host-Based Intrusion Detection System that can 
# detect file changes
# detect repeated failed SSH logins
# log security events
# send at least one type of alert
# demonstrate detection using simulated attacks.

from file import check_integrity  # monitir files for any alterations
from ssh import detect_brute_force #monitor ssh for brute force attempts
from spinner import spinner # for console loading
import threading

# to signal the main loop to stop
stop_event = threading.Event()

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
    spin = spinner("Running file integrity checks ...","\r\n",stop=stop_event)
    check_integrity()
    spin.join()
    # SSH Brute Force Detection
    spin=spinner("Scanning SSH logs for brute force attempts...","\r\n",stop=stop_event)
    detect_brute_force()
    spin.join()

# Runs in a background thread and sets stop_event when Enter is pressed.
def wait_for_enter():
    input()
    stop_event.set()

if __name__ == '__main__':
    startup()
    #run checks in a loop until program is closed

    # Start the Enter listener in a thread
    listener = threading.Thread(target=wait_for_enter, daemon=True)
    listener.start()

    while not stop_event.is_set():
        #run core intrusion detection
        run_hids()
        spin = spinner("sleeping Press ENTER to exit","\033[F\033[F\r",stop=stop_event)
        # sleep to reduce cpu cycles , but exit  if Enter is pressed
        stop_event.wait(timeout=0.5)
        if not stop_event.is_set():
            spin.join()
    #close message
    print("\nHIDS scan complete. Check hids.log for details.")


