# alert.py 
# desktop notification module
import subprocess
import os.path  # for file reading and writing

title = "HIDS Security Events Detected"

 # Send alert
def alert():
    # Read the lastline of hids.log to alert
    alert_lines = []
    if os.path.exists('hids.log'):
        with open('hids.log', 'r') as f:
            lines = f.readlines()
            alert_lines = lines[-1:]
    if alert_lines:
        alert_notification(''.join(alert_lines)) # sends last line read from the hid.log as a string to desktop

 #Send a desktop notification using notify-send
def alert_notification(message):
    try:
        subprocess.run(['notify-send', '-u', 'critical', title, message])
        print(f"[ALERT] {title}: {message}")
    except FileNotFoundError:
        print("Error: notify-send command not found. You may need to install the 'libnotify-bin' package.")
    except Exception as e:
        print(f"An error occurred: {e}")