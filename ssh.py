# ssh.py
import os.path  # for file reading and writing
from collections import defaultdict #dictionary module to store data
from datetime import datetime, timedelta  #time and date modules
from log import log #looging module
from log import Event # enum for the diffrent events 
from log import Severity #enum for diffrent severity levels

AUTH_LOG = "/var/log/auth.log" # location of ssh log file
THRESHOLD = 5        # failed attempts
TIME_WINDOW = 2   #  2 minutes

# read auth.log 
def read_log():
    if os.path.exists(AUTH_LOG):
        try:
            with open(AUTH_LOG, 'r') as f:
                lines = f.readlines()
            if lines:
                return lines
        except Exception as e:
            print(f"Error Reading {AUTH_LOG}: {e}")

# find failed SSH login lines
#2026-03-23T18:01:26.253290-05:00 nm sshd[17465]: Failed password for norman-martin from 192.168.0.10 port 55954 ssh2
#2026-03-23T18:01:35.916433-05:00 nm sshd[17465]: message repeated 2 times: [ Failed password for norman-martin from 192.168.0.10 port 55954 ssh2]
def search_logs(lines):
    ip_detected = defaultdict(list) # dictionary to store ip,username,timestamp

    for line in lines:
        if 'Failed password' not in line:
            continue

        words = line.split()
        #extract time and date
        timestamp = words[0]

        # Extract IP since the index is always the word after "from"
        from_index = words.index('from')
        ip = words[from_index + 1]
    
        # Extract username since it comes after "for"
        for_index = words.index('for')
        username = words[for_index + 1]
        # Every ip detected is linked to a nested list of [username,time]
        ip_detected[ip].append ({'username': username,'time': datetime.fromisoformat(timestamp)})

        #account for repeated messages
        if 'message repeated' in line:
            repeated_index = words.index('repeated')
            # number of times meaage was repeateed comes after "repeated"
            count = int (words[repeated_index+1])- 1
            for x in range(count):
                # account for number of times message was repeated
                ip_detected[ip].append ({'username': username,'time': datetime.fromisoformat(timestamp)})
        #print(line)
    return ip_detected


#check log gile to ensure to prevent duplicate intrusion logging
def check_logs(desc):
    if os.path.exists("hids.log"): # check if file exist
        with open("hids.log", "r") as f:# open file in read mode
            lines = f.readlines() #create a list of all the lines in the file
            #check if the same log is already in the file
            for line in lines:
                if desc in line:
                    return False
    return True



def detect_brute_force():
    lines = read_log()
    # get list of failed logins
    ip_detected = search_logs(lines) 
    # check number of falied attempts per ip
    for ip, attempts in ip_detected.items():
        # Sort attempts oldest to newest by time
        attempts.sort(key=lambda x: x['time']) 
        
        index = 0
        while index < len(attempts):
            # get time two minutes after current attempt
            window_end = attempts[index]['time'] + timedelta(minutes=TIME_WINDOW)
          
            # Count how many attempts fall within the 2 minutes 
            window = [a for a in attempts[index:] if a['time'] <= window_end]

            if len(window) >= THRESHOLD:
                # get list of usernames with the same ip
                usernames = list({a['username'] for a in window})
                # create a discription with the usernames
                desc = f"{len(window)} failed logins (users: {', '.join(usernames)}) @ {window[-1]['time']}"
                #check log for same event
                if check_logs(desc):
                    # Log intrusion event
                    log(Event.SSH_BRUTE_FORCE, Severity.High, ip, desc)
                
                index+=len(window)
                continue
            index+=1
                    
                
          



