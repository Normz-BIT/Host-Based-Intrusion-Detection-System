# alert.py 
# desktop notification module
import subprocess
import os.path  # for file reading and writing
import string

title = "HIDS Security Events Detected"

 # Send alert
def alert():
    # Read the lastline of hids.log to alert
    alert_lines = []
    if os.path.exists("hids.log"): # check if file exist
        with open("hids.log", "r",encoding='utf-8') as f: # open file in read mode
            lines = f.readlines() #create a list of all the lines in the file
            alert_lines = lines[-1:] # get the last line
    if alert_lines: # if line is not empty
        alert=''.join(alert_lines).strip() #create a string to output
        alert_notification(alert) # sends last line read from the hid.log as a string to desktop
        print(f"\n[ALERT] {title}: {alert}",end="\n"*3) #print alert to terminal

 #Send a desktop notification using notify-send
def alert_notification(message):
    try:
        subprocess.run(['notify-send', '-u', 'critical', title, message])
    except FileNotFoundError:
        print("\nError: notify-send command not found. You may need to install the 'libnotify-bin' package.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    