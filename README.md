
# Network Scanner & OS Fingerprinting Tool

This tool is a powerful network scanner that helps you quickly identify open ports, operating systems, and services running on devices within your network. It also provides features like MAC address discovery and vendor identification based on MAC addresses.

## Features

- **Port Scanning**: Check the status of ports (open/closed) for various services (HTTP, SSH, SMB, RDP, etc.).
- **OS Fingerprinting**: Identify the operating system of devices connected to the network using ICMP protocol and TTL values.
- **Banner Grabbing**: Retrieve banners from services like SSH, HTTP, and other protocols.
- **MAC Address Discovery**: Discover the MAC address of devices on the network and identify their vendor.
- **Multithreading Support**: Faster network scanning using threads for parallel operations.

## Installation

To use this tool, you will need Python and some libraries installed.

### Prerequisites

- Python 3.x
- Python libraries:
  - `scapy`
  - `colorama`

### Install Libraries

To install the required libraries, use the following command:

```bash
pip install scapy colorama
```

## Usage

1. First, clone or download the script:

```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

2. Run the script:

```bash
python3 network_scanner.py
```

3. You will be prompted to enter the **start and end IP addresses**. The script will then begin scanning ports and gathering information from devices within the network.

### Example

Input:

```
Enter start IP (default 192.168.50.0): 192.168.50.1
Enter end IP (default 192.168.50.255): 192.168.50.100
```

Output:

```
==============================
✔ IP 192.168.50.1 responds to ping!
IP 192.168.50.1 has open ports:
==============================
Port 22 (ssh) => OpenSSH 7.6p1 Ubuntu
Port 80 (http) => HTTP/1.1 200 OK
------------------------------
OS fingerprinting result =>
TTL: 128
Possible OS: Windows
------------------------------
Target's MAC address: 00:1a:2b:3c:4d:5e
Vendor: Cisco Systems
==============================
```

## Supported Protocols

- **FTP (21)**
- **SSH (22)**
- **Telnet (23)**
- **HTTP (80)**
- **HTTPS (443)**
- **SMB (445)**
- **RDP (3389)**

## Contributing

If you'd like to contribute to the project or add new features, feel free to submit pull requests.

1. Fork the repository.
2. Create a new branch for your changes.
3. Make your changes and submit a pull request.

## Acknowledgments

This project is inspired by various network scanning and port scanning scripts. The tool utilizes the `scapy` and `colorama` libraries for network interaction and output styling.

## License

This project is licensed under the **MIT License**.
