#!bin/python3

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import sqlite3
from colorama import Fore, Style, init
import platform
import subprocess
import sys
import time
import random
init(autoreset=True)


# class DualOutput:
#     def __init__(self, file_path):
#         self.terminal = sys.stdout  
#         self.log = open(file_path, "a", encoding="utf-8") 

#     def write(self, message):
#         self.terminal.write(message)  
#         self.log.write(self.remove_colors(message))

#     def flush(self):
#         self.terminal.flush()
#         self.log.flush()

#     def remove_colors(self, text):
#         return text.replace(Fore.RED, "").replace(Fore.GREEN, "").replace(Fore.YELLOW, "")\
#                    .replace(Fore.BLUE, "").replace(Fore.CYAN, "").replace(Fore.MAGENTA, "")\
#                    .replace(Style.RESET_ALL, "")


# log_file = open("scan_results.txt", "a", encoding="utf-8")
# sys.stdout = DualOutput("scan_results.txt")


def search_vendor(mac_address):
    db_path = "manuf.sqlite"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT full_name FROM manufacturers WHERE mac_prefix = ?;", (mac_address,))
    result = cursor.fetchone()
    
    conn.close()
    return result[0] if result else "Vendor not found"

def os_fingerprint(ip):
    packet = IP(dst=ip)/TCP(dport=80, flags="S") # type: ignore
    response = sr1(packet, timeout=1,verbose=False)

    if response:
        #print("Response received from", ip)
        #print("IP:", response[IP].src)
        print("OS fingerprinting result =>")
        print("TCP Flags:", response[TCP].flags) # type: ignore
        print("Window Size:", response[TCP].window) # type: ignore
        print("TTL:", response[IP].ttl) # type: ignore

        if response[TCP].window == 8192: # type: ignore
            print("Possible OS: Windows")
        elif response[TCP].flags == 0x12: # type: ignore
            print("Possible OS: Linux")
        elif response[IP].ttl == 128: # type: ignore
            print("Possible OS: Windows")
        else:
            print("OS could not be determined")
    #else:
        #print("No response received from", ip)


def check_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) # type: ignore
    response = srp(packet, timeout=3, verbose=False)[0]
    mac_address = response[0][1].hwsrc
    return mac_address


def check_port(ip,port,open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        open_ports[ip].append(port)
    time.sleep(random.uniform(0.5, 2))  


def scan_ip_range(ports_to_check,**kwargs):
    start_ip = kwargs.get('start_ip','192.168.1.0')
    end_ip = kwargs.get('end_ip','192.168.1.255')

    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    ip_list = [str(ipaddress.IPv4Address(ip_num)) for ip_num in range(int(start), int(end) + 1)]
    random.shuffle(ip_list)  

    open_ports = {ip: [] for ip in ip_list}

    max_threads = 400
    threads = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip_num in range(int(start),int(end)+1):
            ip = str(ipaddress.IPv4Address(ip_num))

            for port in ports_to_check:
                executor.submit(check_port,ip,port,open_ports)
                #print(f"Scanning IP {ip}:{port}")

    return open_ports


def is_alive(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", param, "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.returncode == 0
    except:
        return False


def grab_ssh_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner if banner else ""
    except:
        return ""

start_ip = input("Enter start IP (default 192.168.50.0): ") or '192.168.50.0'
end_ip =input("Enter end IP (default 192.168.50.255): ") or '192.168.50.255'

ports_to_check =[21,22,23,25,53,56,67,80,110,123,143,443,445,993,995,3306,3389,8080]
random.shuffle(ports_to_check)
open_ports = scan_ip_range(ports_to_check,start_ip=start_ip,end_ip=end_ip)
ports_defenition = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"DNS",56:"VoIP",67:"DHCP",80:"HTTP",110:"POP3",123:"NTP",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",8080:"HTTP Alternative"}



for ip, ports in open_ports.items():
    if ports:
        print(f"\n{Fore.CYAN}==============================")
        if is_alive(ip):
            print(f"{Fore.GREEN}✔ IP {ip} responds to ping!")
        else:
            print(f"{Fore.RED}✖ IP {ip} doesnt respond to ping.")
        print(f"{Fore.YELLOW}IP {ip} {Fore.GREEN}has open ports:")
        print(f"{Fore.CYAN}=============================={Style.RESET_ALL}")
        
        try:
            mac_address = check_mac(ip)
        except:
            mac_address = f"{Fore.RED}Could not resolve the MAC address{Style.RESET_ALL}"
        
        for port in ports:
            if port ==22:
                banner = grab_ssh_banner(ip,22)
                print(f"{Fore.MAGENTA}{port} ({ports_defenition[port]}) => {banner}{Style.RESET_ALL}")
            else:
                print(f"{Fore.MAGENTA}{port} ({ports_defenition[port]}){Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}------------------------------")
        os_fingerprint(ip)
        print(f"{Fore.BLUE}Target's MAC address: {Fore.WHITE}{mac_address}")
        print(f"{Fore.GREEN}Vendor: {Fore.WHITE}{search_vendor(mac_address[:8].upper())}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}==============================\n")



# sys.stdout = sys.__stdout__