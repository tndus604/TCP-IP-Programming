import os
import socket
import struct
import time
import zlib
import random
import string
import requests
import ntplib
import dns.resolver
import dns.exception
import threading
import json
from datetime import datetime
from time import ctime
import uuid 

def calculate_icmp_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=1, data_size=192):
    thread_id = threading.get_ident()
    process_id = os.getpid()
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff
    header = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)
    random_char = random.choice(string.ascii_letters + string.digits)
    data = (random_char * data_size).encode()
    chksum = calculate_icmp_checksum(header + data)
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)
    return header + data

def ping(host, ttl=64, timeout=1, sequence_number=1):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(timeout)
        packet = create_icmp_packet(sequence_number=sequence_number)
        sock.sendto(packet, (host, 1))
        start = time.time()
        try:
            data, addr = sock.recvfrom(1024)
            end = time.time()
            total_ping_time = (end - start) * 1000
            return addr, total_ping_time
        except socket.timeout:
            return None, None

def check_server_http(url):
    try:
        response = requests.get(url)
        is_up = response.status_code < 400
        return is_up, response.status_code
    except requests.RequestException:
        return False, None

def check_server_https(url, timeout=5):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=timeout)
        is_up = response.status_code < 400
        return is_up, response.status_code, "Server is up"
    except requests.ConnectionError:
        return False, None, "Connection error"
    except requests.Timeout:
        return False, None, "Timeout occurred"
    except requests.RequestException as e:
        return False, None, f"Error during request: {e}"

def check_ntp_server(server):
    client = ntplib.NTPClient()
    try:
        response = client.request(server, version=3)
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, socket.gaierror):
        return False, None

def check_dns_server_status(server, query, record_type):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]
        return True, results
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        return False, str(e)

def check_tcp_port(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."
    except socket.timeout:
        return False, f"Port {port} on {ip_address} timed out."
    except socket.error:
        return False, f"Port {port} on {ip_address} is closed or not reachable."
    except Exception as e:
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"

def check_udp_port(ip_address, port, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'', (ip_address, port))
            try:
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."
            except socket.timeout:
                return True, f"Port {port} on {ip_address} is open or no response received."
    except Exception as e:
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"

def handle_client(client_sock):
    message = client_sock.recv(1024).decode()
    data = json.loads(message)
    server_name = data['server_name']
    service = data['service']
    details = data['details']
    timestamp = data['timestamp']
    
    task_id = str(uuid.uuid4())  # Generate a unique task ID

    if service == 'HTTP':
        if 'url' in details:
            url = details['url']
            is_up, status_code = check_server_http(url)
            response = f"[{timestamp}] Task ID: {task_id}, HTTP URL: {url}, HTTP server status: {'True' if is_up else 'False'}, Status Code: {status_code if status_code is not None else 'N/A'}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, HTTP: No URL configured for {server_name}"
    elif service == 'HTTPS':
        if 'url' in details:
            url = details['url']
            is_up, status_code, description = check_server_https(url)
            response = f"[{timestamp}] Task ID: {task_id}, HTTPS URL: {url}, HTTPS server status: {'True' if is_up else 'False'}, Status Code: {status_code if status_code is not None else 'N/A'}, Description: {description}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, HTTPS: No URL configured for {server_name}"
    elif service == 'ICMP':
        server_address = details['server_address']
        ping_addr, ping_time = ping(server_address)
        response = f"[{timestamp}] Task ID: {task_id}, Ping: {ping_addr[0]} - {ping_time:.2f} ms" if (ping_addr and ping_time is not None) else f"[{timestamp}] Task ID: {task_id}, Ping: Request timed out or no reply received"
    elif service == 'DNS':
        if 'server_address' in details:
            server_address = details['server_address']
            dns_queries = [
                (server_name, 'A'),
                (server_name, 'MX'),
                (server_name, 'AAAA'),
                (server_name, 'CNAME'),
                ('yahoo.com', 'A'),
            ]
            for dns_query, dns_record_type in dns_queries:
                is_up, query_results = check_dns_server_status(server_address, dns_query, dns_record_type)
                response = f"[{timestamp}] Task ID: {task_id}, DNS Server: {server_address} - Query: {dns_query}, Type: {dns_record_type}, Query Results: {query_results}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, DNS: No server address configured for {server_name}"
    elif service == 'NTP':
        if 'server_address' in details:
            server_address = details['server_address']
            is_up, ntp_time = check_ntp_server(server_address)
            response = f"[{timestamp}] Task ID: {task_id}, NTP: Server {server_address} - {'is up' if is_up else 'is down'}, Time: {ntp_time}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, NTP: No server address configured for {server_name}"
    elif service == 'TCP':
        if 'port' in details:
            port = details['port']
            is_open, description = check_tcp_port(server_name, port)
            response = f"[{timestamp}] Task ID: {task_id}, TCP Port: {server_name} - Port {port} - {'Open' if is_open else 'Closed'}, Description: {description}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, TCP Port: No port configured for {server_name}"
    elif service == 'UDP':
        if 'port' in details and 'server_address' in details:
            port = details['port']
            server_address = details['server_address']
            is_open, description = check_udp_port(server_address, port)
            response = f"[{timestamp}] Task ID: {task_id}, UDP Port: {server_address} - Port {port} - {'Open' if is_open else 'Closed'}, Description: {description}"
        else:
            response = f"[{timestamp}] Task ID: {task_id}, UDP Port: No port configured for {server_address}"
    else:
        response = f"[{timestamp}] Task ID: {task_id}, Unknown service: {service} for server {server_name}"

    client_sock.sendall(response.encode())
    client_sock.close()

def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('127.0.0.1', 54321))
    server_sock.listen(5)
    print("Monitoring Service is listening for incoming connections...")

    try:
        while True:
            client_sock, _ = server_sock.accept()
            threading.Thread(target=handle_client, args=(client_sock,)).start()
    finally:
        server_sock.close()
        print("Monitoring Service socket closed")

if __name__ == "__main__":
    tcp_server()
