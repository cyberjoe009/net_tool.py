# net_tool.py
This tool scans the network similar to Nmap.

Below is a Python-based tool inspired by **Nmap** and basic application scanning capabilities, designed for Kali Linux. This script will include:
1. **Port scanning** (TCP SYN, TCP Connect).
2. **Banner grabbing**.
3. **Directory brute-forcing** (similar to Dirbuster).


###Step 1: Install Dependencies
Run these commands in Kali Linux to install required libraries:
```bash

1) Sudo apt update
2) Sudo apt install python3-pip
3) Pip3 install scapy requests argparse





### Step 2: Install the python code net_scan.py
 download net_scan.py






### Step 3: Usage Examples

### 1. **Port Scanning**
-	**TCP Connect Scan** (requires no root):
  ```bash

       run this command 
   ( Python3 net_tool.py scan -t 192.168.1.1 -p 1-100 -s connect )
  ```

### 2. SYN Scan** (requires root privileges):
  ```bash

      run this command
  ( Sudo python3 net_tool.py scan -t 192.168.1.1 -p 1-100 -s syn )
  ```

#### 3. **Directory Bruteforcing**
```bash

      run this command
 ( Python3 net_tool.py dir -u http://example.com -w /usr/share/wordlists/dirbuster/common.txt )


