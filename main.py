import socket
import threading
import pyperclip
import argparse
from termcolor import colored

# Configuration
PORT = 65432  # Port to use for communication

# Store clipboard history
clipboard_history = []

def handle_client(conn, addr):
    """Server handler to respond to clipboard requests."""
    global clipboard_history
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        elif data == 'get_clipboard':
            clipboard_content = pyperclip.paste()
            clipboard_history.append(clipboard_content)  # Add to history
            conn.sendall(clipboard_content.encode())
        else:
            conn.sendall(b"Invalid command")
    conn.close()

def server(local_ip):
    """Runs a server to listen for clipboard requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((local_ip, PORT))
        server_socket.listen()
        print(f"Server listening on {local_ip}:{PORT}...")
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

def client(peer_ip):
    """Client that requests clipboard from the peer and allows interaction."""
    global clipboard_history
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((peer_ip, PORT))
            print(colored(f"Connected to {peer_ip}", 'green'))

            while True:
                command = input("\nEnter a command ('show' to list clipboards, 'cp <number>' to copy, 'exit' to quit): ").strip()
                
                if command == 'show':
                    client_socket.sendall(b'get_clipboard')
                    clipboard_content = client_socket.recv(1024).decode()
                    clipboard_history.append(clipboard_content)  # Save to history
                    for idx, content in enumerate(clipboard_history, start=1):
                        print(f"{idx}. {content}")
                
                elif command.startswith('cp'):
                    try:
                        _, number = command.split()
                        index = int(number) - 1
                        if 0 <= index < len(clipboard_history):
                            pyperclip.copy(clipboard_history[index])
                            print(f"\nCopied clipboard entry {number} to local clipboard.")
                        else:
                            print("Invalid number. Please try again.")
                    except (ValueError, IndexError):
                        print("Invalid command format. Use 'cp <number>'.")
                
                elif command == 'exit':
                    break

                else:
                    print("Unknown command. Try 'show' or 'cp <number>'.")
    except ConnectionRefusedError:
        print(colored(f"Failed to connect to {peer_ip}. Is the server running?", 'red'))

def main():
    # Command-line argument parser
    parser = argparse.ArgumentParser(description="Clipboard Sharing App")
    parser.add_argument('--local-ip', type=str, required=True, help='Local IP address of this machine')
    parser.add_argument('--peer-ip', type=str, required=True, help='IP address of the peer machine')

    args = parser.parse_args()
    local_ip = args.local_ip
    peer_ip = args.peer_ip

    # Start the server in a separate thread
    server_thread = threading.Thread(target=server, args=(local_ip,))
    server_thread.start()

    # Run the client part
    client(peer_ip)

if __name__ == "__main__":
    main()
