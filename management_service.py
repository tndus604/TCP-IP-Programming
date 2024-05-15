import socket
import threading
import time
import json
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

# Configuration of monitoring services
monitoring_services = [
    {'ip': '127.0.0.1', 'port': 54321},
    # Add other monitoring services here
]

# Configuration of tasks
config = {
    'google.com': {
        'HTTP': {'url': 'http://www.google.com', 'frequency': 2},
        'HTTPS': {'url': 'https://www.google.com', 'frequency': 2},
        'ICMP': {'server_address': '8.8.8.8', 'frequency': 2},
        'DNS': {'server_address': '8.8.8.8', 'frequency': 1},
        'NTP': {'server_address': 'pool.ntp.org', 'frequency': 2},
        'TCP': {'port': 80, 'frequency': 2},
        'UDP': {'server_address': '8.8.8.8', 'port': 53, 'frequency': 2}
    },
    'oregonstate.edu': {
        'HTTP': {'url': 'http://oregonstate.edu/', 'frequency': 2},
        'HTTPS': {'url': 'https://oregonstate.edu/', 'frequency': 2},
        'ICMP': {'server_address': '128.193.0.10', 'frequency': 2},
        'DNS': {'server_address': '128.193.0.10', 'frequency': 1},
        'NTP': {'server_address': 'pool.ntp.org', 'frequency': 2},
        'TCP': {'port': 80, 'frequency': 2},
        'UDP': {'server_address': '128.193.0.10', 'port': 53, 'frequency': 2}
    }
}

# Store the status of monitoring services
monitoring_service_status = {service['ip']: 'Offline' for service in monitoring_services}

stop_event = threading.Event()

def tcp_client(monitoring_service, stop_event):
    ip, port = monitoring_service['ip'], monitoring_service['port']
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    while not stop_event.is_set():
        try:
            sock.connect((ip, port))
            print(f"Connected to monitoring service at {ip}:{port}")
            monitoring_service_status[ip] = 'Online'

            while not stop_event.is_set():
                response = sock.recv(1024).decode()
                if not response:
                    break
                print(f"Received: {response}")

        except (ConnectionRefusedError, socket.error):
            print(f"Connection to {ip}:{port} failed. Reconnecting in 5 seconds...")
            monitoring_service_status[ip] = 'Reconnecting'
            stop_event.wait(5)
            continue

        monitoring_service_status[ip] = 'Offline'
        print(f"Disconnected from {ip}:{port}. Reconnecting in 5 seconds...")
        stop_event.wait(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

def monitor_servers(stop_event):
    while not stop_event.is_set():
        for server_name, services in config.items():
            print(f"\n------Distributing tasks for server: {server_name}-----\n")
            for service, details in services.items():
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                message = json.dumps({
                    'server_name': server_name,
                    'service': service,
                    'details': details,
                    'timestamp': timestamp
                })
                for monitoring_service in monitoring_services:
                    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        client_sock.connect((monitoring_service['ip'], monitoring_service['port']))
                        client_sock.sendall(message.encode())
                        response = client_sock.recv(1024).decode()
                        print(f"{response}")
                    except socket.error:
                        print(f"Failed to send message to {monitoring_service['ip']}:{monitoring_service['port']}")
                    finally:
                        client_sock.close()
        stop_event.wait(5)

def display_status(stop_event):
    while not stop_event.is_set():
        print("\nReal-time status of monitoring services:")
        for ip, status in monitoring_service_status.items():
            print(f"{ip}: {status}")
        stop_event.wait(10)

def main():
    threads = []
    for monitoring_service in monitoring_services:
        thread = threading.Thread(target=tcp_client, args=(monitoring_service, stop_event))
        thread.start()
        threads.append(thread)

    monitor_thread = threading.Thread(target=monitor_servers, args=(stop_event,))
    monitor_thread.start()
    threads.append(monitor_thread)

    status_thread = threading.Thread(target=display_status, args=(stop_event,))
    status_thread.start()
    threads.append(status_thread)

    command_completer = WordCompleter(['exit'], ignore_case=True)
    session = PromptSession(completer=command_completer)

    try:
        with patch_stdout():
            while True:
                user_input = session.prompt("Enter command: ")
                if user_input.lower() == "exit":
                    print("Exiting application. Please wait for threads to stop.")
                    stop_event.set()
                    break
    except KeyboardInterrupt:
        print("Exiting application. Please wait for threads to stop.")
        stop_event.set()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
