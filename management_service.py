# management_service.py

import socket
import threading
import time
import json
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

config = {
    'google.com': {
        'HTTP': {'url': 'http://www.google.com', 'frequency': 2},   
        'HTTPS': {'url': 'https://www.google.com', 'frequency': 2},
        'ICMP': {'server_address': '8.8.8.8', 'frequency': 2},
        'DNS': {'server_address': '8.8.8.8', 'frequency': 1},
        'NTP': {'server address': 'pool.ntp.org', 'frequency': 2},
        'TCP': {'port': 80, 'frequency': 2},
        'UDP': {'server_address': '8.8.8.8', 'port': 53, 'frequency': 2}
    },
    'oregonstate.edu': {
        'HTTP': {'url': 'http://oregonstate.edu/', 'frequency': 2}, 
        'HTTPS': {'url': 'https://oregonstate.edu/', 'frequency': 2},
        'ICMP': {'server_address': '128.193.0.10', 'frequency': 2},
        'DNS': {'server_address': '128.193.0.10', 'frequency': 1},
        'NTP': {'server address': 'pool.ntp.org', 'frequency': 2},
        'TCP': {'port': 80, 'frequency': 2},
        'UDP': {'server_address': '128.193.0.10', 'port': 53, 'frequency': 2}
    }
}

def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = '127.0.0.1'
    server_port = 12345
    server_sock.bind((server_address, server_port))
    server_sock.listen(5)
    print("Server is listening for incoming connections...")

    try:
        while True:
            client_sock, client_address = server_sock.accept()
            try:
                message = client_sock.recv(1024)
                print(f"Received message: {message.decode()}")
                response = "Message received"
                client_sock.sendall(response.encode())
            finally:
                client_sock.close()
                print(f"Connection with {client_address} closed")
    finally:
        server_sock.close()
        print("Server socket closed")

def monitor_servers(config):
    for server_name, services in config.items():
        print(f"\n------Monitoring services for server: {server_name}-----\n")
        for service, details in services.items():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = json.dumps({'server_name': server_name, 'service': service, 'details': details, 'timestamp': timestamp})
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect(('127.0.0.1', 54323))
            client_sock.sendall(message.encode())
            response = client_sock.recv(1024).decode()
            print(f"[{timestamp}] {response}")
            client_sock.close()

def worker(stop_event):
    while not stop_event.is_set():
        monitor_servers(config)
        time.sleep(5)

def main():
    stop_event = threading.Event()
    worker_thread = threading.Thread(target=worker, args=(stop_event,))
    worker_thread.start()
    server_thread = threading.Thread(target=tcp_server)
    server_thread.start()
    command_completer = WordCompleter(['exit'], ignore_case=True)
    session = PromptSession(completer=command_completer)
    is_running = True

    try:
        with patch_stdout():
            while is_running:
                user_input = session.prompt("Enter command: ")
                if user_input == "exit":
                    print("Exiting application. Application will stop after the current iteration.")
                    is_running = False
    except KeyboardInterrupt:
        print("Exiting application. Application will stop after the current iteration.")
    finally:
        stop_event.set()
        worker_thread.join()
        server_thread.join()

if __name__ == "__main__":
    main()
