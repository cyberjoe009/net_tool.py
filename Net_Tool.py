#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from scapy.all import *
from scapy.layers.inet import IP, TCP
import requests
import time

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def tcp_connect_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
                print(f"{GREEN}[+] Port {port} is open - Banner: {banner}{RESET}")
            except:
                print(f"{GREEN}[+] Port {port} is open{RESET}")
        sock.close()
    except KeyboardInterrupt:
        sys.exit(1)
    except:
        pass

def syn_scan(target_ip, port):
    src_port = RandShort()
    syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(syn_packet, timeout=1, verbose=0)
    if resp and resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
            print(f"{GREEN}[+] Port {port} is open{RESET}")
            rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
            send(rst_packet, verbose=0)
        elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK
            pass

def port_scan(target_ip, ports, scan_type):
    print(f"{YELLOW}[*] Scanning {target_ip}...{RESET}")
    start_time = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in ports:
                if scan_type == "syn":
                    futures.append(executor.submit(syn_scan, target_ip, port))
                else:
                    futures.append(executor.submit(tcp_connect_scan, target_ip, port))
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        print(f"{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(1)
    end_time = time.time()
    print(f"{YELLOW}[*] Scan completed in {end_time - start_time:.2f} seconds.{RESET}")

def directory_bruteforce(url, wordlist):
    try:
        with open(wordlist, "r") as f:
            directories = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"{RED}[!] Wordlist file not found.{RESET}")
        return

    print(f"{YELLOW}[*] Bruteforcing directories on {url}...{RESET}")
    for dir in directories:
        full_url = f"{url}/{dir}"
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                print(f"{GREEN}[+] Found: {full_url}{RESET}")
        except requests.exceptions.RequestException:
            pass

def main():
    parser = argparse.ArgumentParser(description="Python Network Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Port scan parser
    scan_parser = subparsers.add_parser("scan", help="Port scanning")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP address")
    scan_parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 1-100)")
    scan_parser.add_argument("-s", "--scan-type", choices=["syn", "connect"], default="connect", help="Scan type")

    # Directory brute-force parser
    dir_parser = subparsers.add_parser("dir", help="Directory brute-forcing")
    dir_parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com)")
    dir_parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")

    args = parser.parse_args()

    if args.command == "scan":
        target_ip = args.target
        port_range = args.ports.split("-")
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        ports = range(start_port, end_port + 1)
        port_scan(target_ip, ports, args.scan_type)
    elif args.command == "dir":
        directory_bruteforce(args.url, args.wordlist)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
