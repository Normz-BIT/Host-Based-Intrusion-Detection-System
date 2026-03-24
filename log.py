# log.py
# writes all the security Detections to a file
import logging # native logging module
from datetime import datetime # get system date and time
from enum import StrEnum  # fro string enums
from alert import alert #function to send alerts of intrusions to user

# Configure the logger to write to hids.log
logging.basicConfig(
    filename="hids.log",
    level=logging.INFO,
    format='%(message)s'
)

# Diffrent severity levels  Low | Medium | High
class Severity(StrEnum):
    Low     = "Low   "
    Medium  = "Medium"
    High    = "High  "

# Diffrent event types  FILE_ADDED | FILE_MODIFIED | FILE_DELETED | HASH_GENERATION_ERROR|SSH_BRUTE_FORCE
class Event(StrEnum):
    FILE_ADDED      = "FILE_ADDED     "
    FILE_MODIFIED   = "FILE_MODIFIED  "
    FILE_DELETED    = "FILE_DELETED   "
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"

def log(event_type, severity, source, description):
    # Write a structured event to hids.log.
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = (
        f"[{timestamp}] | TYPE: {event_type} | SEVERITY: {severity} "
        f"| SOURCE: {source} | DESC: {description}"
    )

    # send information to logger onbject that writes to hids.log
    logging.info(entry)
    # user is alerted after every log
    alert() 
    

