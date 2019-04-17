# CyberChef2
Command and control server for attack/defense competition.

## Requirements
* Python 2.7 and Python 3.7.
* Run on Linux so pwntools and Metasploit scripts run properly.
* Listens on ports 53, 80, and 443.
* Install Python 3.7 requirements by running `pip3 install -f requirements.txt` in root directory.
* Install Python 2.7 requirements by running `pip install -f requirements.txt` in scripts directory.
* Metasploit and msfrpcd. Check if installed by running `msfrpcd -h`.

## Initial Setup
* Run the server with `python3 c2.py`. If it is not the first time running, run `pkill -f c2.py` to kill leftover threads.
* Place the first stage binary of the malware in the same directory, named `malware_installer`.
* To access the admin page, go to http://localhost/admin from the same host.
* Settings you may want to adjust:
  * Change the string CHANGE_ME in malware_install to the IP of the host running the server.
  * Add more IPs to whitelisted_ips to allow other hosts to access the admin site.
  
## Writing Scripts
* Start writing your scripts in the scripts directory.
* They are run with ./, so if it is Python, add `#!/usr/bin/env python` to the top.
* Scripts take the IP it is attacking as the only argument. The templates included implement this functionality.
* Any data scripts print to STDOUT will be searched for flags.
* Start testing your scripts manually by giving it the IP of a known vulnerable host.
* Once the script seems to be working, add it on the scripts page of the admin site.

## Checking for Errors
* Errors that are not handled by the application can be read in the console `c2.py` is run in.
* If an error occurs in one of the threads, it will stop. It can be restarted on the threads page in the admin site, but the underlying issue should be fixed.
* When `c2.py` is first run, it attempts to start the msfrpcd listener. Check the console for errors for this program.
