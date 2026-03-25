#Spinner.py
#simple spinner to show that the program is running
from threading import Thread # used to preven spinner from stopping program execution
import sys
import time
import itertools

# run spinner in a new thread
def spinner(description,end,stop,duration=1):
    thread = Thread(target=run_spinner, args=(description, end,stop, duration)) # create new thread for spinner
    thread.daemon = True  # Thread dies with main program
    thread.start()  #start thread
    return thread
    
# print spinner animation
def run_spinner(description,end,stop,duration):
    spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])  # Spinner items
    end_time = time.time() + duration #time to run spinner for
    print(end='\x1b[2K') #clear current line
    try:
        while time.time() < end_time and not stop.is_set():
            frame = next(spinner_cycle)    #cycle through through the items
            sys.stdout.write(f"\r{description}... {frame}") #display message and spinner
            sys.stdout.flush() #clear output
            time.sleep(0.1)  #sleep to animate spinner
        sys.stdout.write(f"{end}")  # write special character to output
    except Exception :
        sys.stdout.flush() # if user interacts with console clear output
        stop.set()


