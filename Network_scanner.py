import nmap

# Basic user interface header
print(r"""______            _     _  ______                 _           _ 

░██████╗░█████╗░███╗░░██╗░██████╗░██████╗░░█████╗░███╗░░░███╗
██╔════╝██╔══██╗████╗░██║██╔════╝░██╔══██╗██╔══██╗████╗░████║
╚█████╗░███████║██╔██╗██║██║░░██╗░██████╔╝███████║██╔████╔██║
░╚═══██╗██╔══██║██║╚████║██║░░╚██╗██╔══██╗██╔══██║██║╚██╔╝██║
██████╔╝██║░░██║██║░╚███║╚██████╔╝██║░░██║██║░░██║██║░╚═╝░██║
╚═════╝░╚═╝░░╚═╝╚═╝░░╚══╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝""")
print("\n****************************************************************")
print("\n* Copyright of sangram, 2023                              *")
print("\n* https://www.instagram.com/2003_sangram/                 *")
print("\n****************************************************************")

def scan_network(target_ip):
    nm = nmap.PortScanner()

    # Perform a ping scan to discover live hosts in the network
    nm.scan(hosts=target_ip, arguments='-sn')

    # Iterate through each discovered host
    for host in nm.all_hosts():
        print(f"\nHost: {host}")

        # Perform a detailed scan on each live host, including OS detection and service/version detection
        nm.scan(hosts=host, arguments='-sS -O -sV ')

        # Extract information about open ports
        open_ports = [port for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'open']
        print(f"Open Ports: {open_ports}")

        # Extract information about services on open ports, including version
        for port in open_ports:
            service = nm[host]['tcp'][port]['name']
            version = nm[host]['tcp'][port].get('product', 'N/A')
            print(f"Port {port}: {service} ({version})")

        # Extract MAC address (if available)
        mac_address = nm[host]['addresses'].get('mac', 'N/A')
        print(f"MAC Address: {mac_address}")

        # Extract hostname (if available)
        hostname = nm[host].hostname()
        print(f"Hostname: {hostname}")

        # Extract OS information
        os_info = nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else 'N/A'
        print(f"OS: {os_info}")

if __name__ == "__main__":
    # Get the user input for the target IP range
    target_ip = input("Enter the target IP address or range (e.g., 192.168.1.1 or 192.168.1.1/24): ")
    
    # Perform the network scan
    scan_network(target_ip)
