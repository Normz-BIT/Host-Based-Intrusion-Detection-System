#Spinner.py
#simple spinner to show that the program is running
from threading import Thread # used to preven spinner from stopping program execution
import sys
import time
import itertools



def spinner(description,end,duration=5):
    thread = Thread(target=run_spinner(description,end,duration), args=(10,)) # create new thread for spinner
    #start thread
    thread.start()
    thread.join()
    
def run_spinner(description,end,duration):
    spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])  # Spinner items
    end_time = time.time() + duration #time to run spinner for
    try:
        while time.time() < end_time:
            frame = next(spinner_cycle)    #cycle through through the items
            sys.stdout.write(f"\r{description}... {frame}") #display message and spinner
            sys.stdout.flush() #clear output
            time.sleep(0.1)  #sleep to animate spinner
        sys.stdout.write(f"{end}")  # write special character to output
    except KeyboardInterrupt:
        sys.stdout.flush() # if user interacts with console clear output
