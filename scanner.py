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
from tabulate import tabulate
import random
import logging
init(autoreset=True)

conf.log_suppress = True
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


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
        # print(f"{Fore.BLUE}OS fingerprinting result =>{Style.RESET_ALL}")
        # print("TCP Flags:", response[TCP].flags) # type: ignore
        # print("Window Size:", response[TCP].window) # type: ignore
        # print(f"{Fore.RED}TTL:{Style.RESET_ALL}", response[IP].ttl) # type: ignore
        ttl = response.ttl
        df_flag = (response.flags & 2) >> 1 
        esxi = grab_esxi_banner(ip)
        ilo = grab_ilo_banner(ip)
        if esxi != "":
            return "Vmware ESXI"
        elif ilo != "":
            return "HP ILO"
        else:  
            if ttl>100 and df_flag==1: # type: ignore
                return "Windows"
            elif ttl<100 and df_flag==0: # type: ignore
                return "Linux"
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, 3389)) == 0:
                        return "Windows"
                    else:
                        return "Unknown"
    else:
        return "Unknown"

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


def scan_ip_range(ports_to_check):
    ip_input = input("Please enter ip's you want to scan[192.168.1.0/24,192.168.1.0-255,192.168.1.20]=> ")
    start_ip, end_ip = parse_ip_range(ip_input)
    excluded = input("Do you eant to exclude any ip's? seperate them with space[x.x.x.x y.y.y.y]=> ")
    excluded_ips= excluded.split(" ")




    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    ip_list = [str(ipaddress.IPv4Address(ip_num)) for ip_num in range(int(start), int(end) + 1)]
    for ip in excluded_ips:
        if ip in ip_list:
            ip_list.remove(ip)
    print(f"scanning ips from {ip_list[0]} to {ip_list[len(ip_list)-1]}")
    print(f"excluded ips are {excluded_ips}")
    random.shuffle(ip_list)  

    
    open_ports = {ip: [] for ip in ip_list}

    max_threads = 800
    threads = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for ip_num in range(int(start),int(end)+1):
            ip = str(ipaddress.IPv4Address(ip_num))

            for port in ports_to_check:
                executor.submit(check_port,ip,port,open_ports)
                #print(f"Scanning IP {ip}:{port}")
    for ip in list(open_ports.keys()):
        if not open_ports[ip]: 
            del open_ports[ip]

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
            banner_list = banner.split("\n")
            return_list = []
            for item in banner_list:
                if ("HTTP" in item) or ("Server" in item):
                    return_list.append(item)
            return "\n".join(return_list)
    except:
        return ""


def get_smb_version(ip, port=445): # still incomplete
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))

        smb_negotiate = bytes.fromhex("000000850ff3ff03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

        s.send(smb_negotiate)
        response = s.recv(1024)

        if b"SMB 2.???" in response:
            return "SMBv2 or SMBv3"
        elif b"\xffSMB" in response:
            return "SMBv1"
        else:
            return "Unknown Version"
    
    except socket.timeout:
        return ""
    
    except Exception as e:
        return ""
    
    finally:
        s.close()


def get_host_name(ip):
    try:
        cmd = f"nbtstat -A {ip}"
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8")

        match = re.search(r"(\S+)\s+<00>\s+UNIQUE", output)
        if match:
            return match.group(1)
        else:
            return "Host Name Not Found"
    except subprocess.CalledProcessError:
        return "Error: Could not retrieve Host Name"
    

def parse_ip_range(ip_input):
    if "/" in ip_input:
        try:
            network = ipaddress.ip_network(ip_input, strict=False)
            return str(network[0]), str(network[-1])
        except:
            print("Wrong CIDR Format!")
    
    match = re.match(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", ip_input)
    if match:
        base_ip, start, end = match.groups()
        start_ip = f"{base_ip}.{start}"
        end_ip = f"{base_ip}.{end}"
        return start_ip, end_ip
    
    try:
        ipaddress.ip_address(ip_input)
        return ip_input, ip_input
    except:
        print("Wrong IP address")



def print_results_nmap_style(results):
    table_data = []
    
    for result in results:
        ip = result["IP"]
        mac_address = result["MAC"]
        vendor = result["Vendor"]
        os = result["OS"]
        open_ports_count = len(result["Open Ports"])
        open_ports_str = ", ".join(map(str, result["Open Ports"])) if open_ports_count > 0 else ""
        # smb_version = result["SMB"]
        # hostname = result["Hostname"]
        

        table_data.append([ip, mac_address, vendor, os,open_ports_str, open_ports_count])
        
    headers = ["IP", "MAC Address", "Vendor", "OS", "Ports","Open ports count"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def collect_scan_data(open_ports):
    results = []
    
    for ip, ports in open_ports.items():
        result = {}
        result["IP"] = ip
        
        try:
            mac_address = check_mac(ip)
        except:
            mac_address = f"{Fore.RED}Could not resolve the MAC address{Style.RESET_ALL}"
        
        result["MAC"] = mac_address
        
        vendor = search_vendor(mac_address[:8].upper())
        result["Vendor"] = vendor
        
        os = os_fingerprint(ip)
        result["OS"] = os
        

        # result["Hostname"] = get_host_name(ip)
        

        open_ports_list = list(ports)  
        result["Open Ports"] = open_ports_list
        

        # smb_version = get_smb_version(ip)
        # result["SMB"] = smb_version
        
        results.append(result)
        print(f"IP {ip} Done.")
    
    return results

ports_to_check =[21,22,23,25,53,56,67,80,110,123,143,443,445,993,995,3306,3389,8080]
random.shuffle(ports_to_check)
open_ports = scan_ip_range(ports_to_check)
result = collect_scan_data(open_ports)
print_results_nmap_style(result)
ports_defenition = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"DNS",56:"VoIP",67:"DHCP",80:"HTTP",110:"POP3",123:"NTP",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",8080:"HTTP Alternative"}





