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


def search_vendor(mac_address):
    db_path = "manuf.sqlite"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT full_name FROM manufacturers WHERE mac_prefix = ?;", (mac_address,))
    result = cursor.fetchone()
    
    conn.close()
    return result[0] if result else "Vendor not found"

def os_fingerprint(ip):
    packet = IP(dst=ip)/ICMP() # type: ignore
    response = sr1(packet, timeout=1,verbose=False)

    if response:
        #print("Response received from", ip)
        #print("IP:", response[IP].src)
        print(f"{Fore.BLUE}OS fingerprinting result =>{Style.RESET_ALL}")
        # print("TCP Flags:", response[TCP].flags) # type: ignore
        # print("Window Size:", response[TCP].window) # type: ignore
        print(f"{Fore.RED}TTL:{Style.RESET_ALL}", response[IP].ttl) # type: ignore
        ttl = response.ttl
        df_flag = (response.flags & 2) >> 1 
        esxi = grab_esxi_banner(ip)
        ilo = grab_ilo_banner(ip)
        if esxi != "":
            print(esxi)
        elif ilo != "":
            print(ilo)
        else:  
            if ttl>100 and df_flag==1: # type: ignore
                print(f"{Fore.BLUE}Possible OS:{Style.RESET_ALL} Windows")
            elif ttl<100 and df_flag==0: # type: ignore
                print(f"{Fore.BLUE}Possible OS:{Style.RESET_ALL} Linux")
            else:
                print(f"{Fore.BLUE}OS could not be determined{Style.RESET_ALL}")

def grab_ilo_banner(ip):
    ilo_ports = [22, 23, 80, 443, 17988, 17990, 623]
    open_ports = []
    for port in ilo_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    
    if 443 in open_ports and 17988 in open_ports:
        return f"{Fore.BLUE}Possible OS:{Style.RESET_ALL} HP iLO"
    else:
        return ""

def grab_esxi_banner(ip):
    esxi_ports = [22, 80, 443, 902]
    open_ports = []
    for port in esxi_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    
    if 443 in open_ports and 902 in open_ports:
        return f"{Fore.BLUE}Possible OS:{Style.RESET_ALL} Vmware ESXI"
    else:
        return ""


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

def grab_http_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            banner = s.recv(1024).decode()
            return banner.strip()
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
                print(f"{Fore.MAGENTA}{port} ({ports_defenition[port]}) => {Fore.WHITE}{banner}{Style.RESET_ALL}")
            elif port==80:
                banner = grab_http_banner(ip,80)
                print(f"{Fore.MAGENTA}{port} ({ports_defenition[port]}) => {Fore.WHITE}{banner}{Style.RESET_ALL}")

            else:
                print(f"{Fore.MAGENTA}{port} ({ports_defenition[port]}){Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}------------------------------")
        os_fingerprint(ip)
        print(f"{Fore.CYAN}------------------------------")
        print(f"{Fore.BLUE}Target's MAC address: {Fore.WHITE}{mac_address}")
        print(f"{Fore.GREEN}Vendor: {Fore.WHITE}{search_vendor(mac_address[:8].upper())}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}==============================\n")


