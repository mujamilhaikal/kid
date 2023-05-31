import tkinter as tk
from tkinter import messagebox
import requests
from urllib.parse import urlparse
import urllib3
import colorama
import socket
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama.init()

# Function to check Server Name Indication (SNI)
def check_sni():
    url = entry_url.get()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = perform_check_sni(url)
    messagebox.showinfo('Server Name Indication (SNI)', result)

def perform_check_sni(url):
    try:
        response = requests.get(url, verify=True)
        sni = response.headers.get('Server')
        if sni:
            return f"Server Name Indication (SNI): {sni}"
        else:
            return "Server Name Indication (SNI) not found."
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# Function to check server response
def check_response():
    url = entry_url.get()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = perform_check_response(url)
    messagebox.showinfo('Server Response', result)

def perform_check_response(url):
    try:
        response = requests.get(url, verify=True)
        return f"Server Response: {response.status_code} {response.reason}"
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# Function to check DNS spoofing possibility
def check_dns_spoofing():
    url = entry_url.get()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = perform_check_dns_spoofing(url)
    messagebox.showinfo('DNS Spoofing', result)

def perform_check_dns_spoofing(url):
    domain = urlparse(url).hostname
    try:
        ip = socket.gethostbyname(domain)
        if ip == "127.0.0.1":
            return f"DNS Spoofing detected for {domain}."
        else:
            return f"No DNS Spoofing detected for {domain}."
    except socket.gaierror:
        return f"Error resolving DNS for {domain}."

# Function to find host IP
def find_host():
    url = entry_url.get()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = perform_find_host(url)
    messagebox.showinfo('Host IP', result)

def perform_find_host(url):
    domain = urlparse(url).hostname
    try:
        ip = socket.gethostbyname(domain)
        return f"Host IP for {domain}: {ip}"
    except socket.gaierror:
        return f"Error resolving host {domain}."

# Function to scan ports
def scan_ports():
    url = entry_url.get()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = perform_scan_ports(url)
    messagebox.showinfo('Port Scanner', result)

def perform_scan_ports(url):
    domain = urlparse(url).hostname
    try:
        ip = socket.gethostbyname(domain)
        dangerous_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 993, 995]
        open_ports = []
        for port in dangerous_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            return f"Open dangerous ports on {domain} ({ip}): {open_ports}"
        else:
            return f"No open dangerous ports on {domain} ({ip})."
    except socket.gaierror:
        return f"Error resolving host {domain}."

# Create the main window
window = tk.Tk()
window.title("Network Tools")
window.geometry("600x500")
window.configure(bg="#F0F0F0")

# Create header
header = tk.Label(window, text="Network Tools", font=("Arial", 16, "bold"), bg="#F0F0F0", fg="#333333")
header.pack(pady=20)

# Create URL input and buttons
url_label = tk.Label(window, text="Enter URL:", font=("Arial", 12), bg="#F0F0F0", fg="#333333")
url_label.pack()
entry_url = tk.Entry(window, width=30, font=("Arial", 12))
entry_url.pack(pady=5)

btn_sni = tk.Button(window, text="Check SNI", font=("Arial", 12), command=check_sni, bg="#FFA500", fg="#FFFFFF")
btn_sni.pack(pady=5)

btn_response = tk.Button(window, text="Check Response", font=("Arial", 12), command=check_response, bg="#FFA500", fg="#FFFFFF")
btn_response.pack(pady=5)

btn_dns_spoofing = tk.Button(window, text="Check DNS Spoofing", font=("Arial", 12), command=check_dns_spoofing, bg="#FFA500", fg="#FFFFFF")
btn_dns_spoofing.pack(pady=5)

btn_find_host = tk.Button(window, text="Find Host IP", font=("Arial", 12), command=find_host, bg="#FFA500", fg="#FFFFFF")
btn_find_host.pack(pady=5)

btn_scan_ports = tk.Button(window, text="Scan Ports", font=("Arial", 12), command=scan_ports, bg="#FFA500", fg="#FFFFFF")
btn_scan_ports.pack(pady=5)

# Start the main loop
window.mainloop()
