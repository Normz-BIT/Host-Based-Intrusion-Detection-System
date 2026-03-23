# ssh_monitor.py
import os.path  # for file reading and writing
from collections import defaultdict #dictionary module to store data
from datetime import datetime, timedelta  #time and date modules
from log import log #looging module
from log import Event # enum for the diffrent events 
from log import Severity #enum for diffrent severity levels

SSH = "SSH MONITOR"
AUTH_LOG = '/var/log/auth.log' # location of ssh log file
THRESHOLD = 5        # failed attempts
TIME_WINDOW = 120    # seconds (2 minutes)

# find failed SSH login lines
# Example lines: 
# 2026-03-23T03:26:06.583278-05:00 nm sshd[14867]: Failed password for norman-martin from 192.168.0.10 port 38078 ssh2


# read auth.log 
def read_log():
    if os.path.exists(AUTH_LOG):
        try:
            with open(AUTH_LOG, 'r', errors='replace') as f:
                lines = f.readlines()
            if lines:
                return lines
        except PermissionError:
            print(f"Permission denied reading {AUTH_LOG}.")


def detect_brute_force():
    lines = read_log()
    ip_detected = defaultdict(list) # dictionary to store ip,username,timestamp

    for line in lines:
        if 'Failed password' not in line:
            continue

        words = line.split()


        #extract time and date
        timestamp = words[0]

        # Extract IP since the index is always the word after 'from'
        from_index = words.index('from')
        ip = words[from_index + 1]
        

        # Extract username since it comes after 'for', or after 'invalid user'
        for_index = words.index('for')
        if words[for_index + 1] == 'invalid':
            username = words[for_index + 3]
        else:
            username = words[for_index + 1]
        # Every ip detected is linkt to a nested list of [username,time]
        ip_detected[ip].append ({
            'username': username,
            'time': datetime.fromisoformat(timestamp)
        })
    # check number of falied attempts per ip
    for ip, attempts in ip_detected.items():
          
        if check_logins(attempts):
            usernames = list({a['username'] for a in attempts})
            desc = f"{len(attempts)} failed logins (users: {', '.join(usernames)})"
            log('SSH_BRUTE_FORCE', 'High', ip, desc)
          

#check for 5 failed logins with 2 minutes
def check_logins(attempts):
    sliding_windows = []
    sliding_windows = (attempts[i:] for i in range(THRESHOLD) if attempts[i:])

    for attempt in sliding_windows:   
        for timestamp in attempt:
            print(timestamp['timestamp'])

