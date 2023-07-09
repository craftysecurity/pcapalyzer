import requests
from scapy.all import *
from collections import defaultdict
import json
import sys

# Function to load protocol names from JSON file
def load_protocol_names(filename):
    with open(filename, 'r') as file:
        return json.load(file)

# Load the protocol_names dictionary from the JSON file
protocol_names = load_protocol_names('protocols.json')

# Open the .pcapng file
packets = rdpcap('/home/ubuntu/capture.pcapng')

# Dictionary to store the collected information for each IP/domain
ip_info = defaultdict(lambda: {'outgoing_packet_count': 0, 'total_data': 0, 'destination_ports': set(), 'protocols': set(), 'domain': 'Not available'})

# Iterate over each packet in the file
for packet in packets:
    try:
        # Check if the packet has Ethernet and IP layers
        if Ether in packet and IP in packet:
            ip = packet[IP].dst
            protocol_num = packet[IP].proto

            # Update the collected information for the IP/domain
            ip_info[ip]['outgoing_packet_count'] += 1
            ip_info[ip]['total_data'] += len(packet)
            ip_info[ip]['destination_ports'].add(packet[IP].dport)
            ip_info[ip]['protocols'].add(protocol_names.get(str(protocol_num), f"Unknown ({protocol_num})"))

        # Check if the packet has UDP and DNS layers
        if UDP in packet and DNS in packet:
            dns = packet[DNS]
            if dns.qr == 1 and dns.an:
                domain = dns.an.rdata.decode('utf-8')  # Extract the domain from the DNS response
                ip_info[packet[IP].src]['domain'] = domain

    except Exception as e:
        # Skip packets that cannot be parsed correctly
        continue

# API call function to retrieve domain information
def get_domain_info(domain):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    headers = {
        "apikey": "INSERT API KEY"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        result = data.get('result', {})
        registration_date = result.get('creation_date')
        registrar = result.get('registrar')
        return registration_date, registrar
    else:
        return None, None

# Save the original standard output stream
original_stdout = sys.stdout

# Open a new file to redirect the output
with open('output.txt', 'w') as file:
    # Iterate over each IP/domain and print the output
    for ip, info in ip_info.items():
        # Print the IP/Domain to the terminal

        print(f"IP: {ip}")
        print(f"Domain: {info['domain']}")

        # Print the IP/Domain to the file
        file.write("IP/Domain:\n")
        file.write(f"IP: {ip}\n")
        file.write(f"Domain: {info['domain']}\n\n")

        # Print the collected information to the terminal
        print(f"Outgoing packet count: {info['outgoing_packet_count']}")
        print(f"Total data to IP/Domain: {info['total_data']} bytes")
        print("Destination ports for outgoing packets:")
        for port in info['destination_ports']:
            print(port)
        print("Protocols:")
        for protocol in info['protocols']:
            print(protocol)
        print()

        # Print the collected information to the file
        file.write(f"Outgoing packet count: {info['outgoing_packet_count']}\n")
        file.write(f"Total data to IP/Domain: {info['total_data']} bytes\n")
        file.write("Destination ports for outgoing packets:\n")
        for port in info['destination_ports']:
            file.write(f"{port}\n")
        file.write("Protocols:\n")
        for protocol in info['protocols']:
            file.write(f"{protocol}\n")
        file.write('\n')

        # Retrieve domain information if available
        domain = info['domain']
        if domain != 'Not available':
            registration_date, registrar = get_domain_info(domain)
            if registration_date:
                # Print registration date to the terminal
                print(f"Registration Date: {registration_date}")
                # Print registration date to the file
                file.write(f"Registration Date: {registration_date}\n")
            if registrar:
                # Print registrar to the terminal
                print(f"Registrar: {registrar}")
                # Print registrar to the file
                file.write(f"Registrar: {registrar}\n")
            print()
            file.write('\n')

# Restore the original standard output
sys.stdout = original_stdout
