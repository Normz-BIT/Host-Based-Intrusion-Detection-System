import os.path
import subprocess
import time

MONDIR = '/etc/malware.txt'
TARGET = 'norman-martin@192.168.0.8' #Use machine name and IP here

def filemanipulation():
	#Created file in /etc
	with open(MONDIR,"w") as f:
		f.write("MALWARE INSERTED")
		
	time.sleep(5)
	
	#edited file in /etc
	with open(MONDIR,"w") as f:
		f.write("\nNEW MALWARE INSERTED")
	
	time.sleep(5)
	
	#Deleted file in /etc
	os.remove(MONDIR)

def ssh_login_attempt():
	for i in range(5):
		print(f"\nSSH Attempt {i + 1} of 5:")
		subprocess.call(["ssh",
		"-o","StrictHostKeyChecking=no",
		"-o","ConnectTimeout=5",
		"-o","NumberOfPasswordPrompts=1",
		TARGET])
		print(f"Attempt {i + 1} complete")
		time.sleep(1)
	print("\n All attempts complete")
		
if __name__ == "__main__":
	filemanipulation()
	ssh_login_attempt()
