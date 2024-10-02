import socket
import threading
import pyperclip
import argparse
from termcolor import colored
import os
import platform
import shutil
from pyfiglet import Figlet
from cryptography.fernet import Fernet

# Configuration
PORT = 65432  # Port to use for communication
MAX_CLIPBOARD_LENGTH = 500  # Maximum length of clipboard content to store/display | truncate

# Generate or use a pre-shared key for encryption
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Store clipboard history (local)
clipboard_history = []

def handle_client(conn, addr):
    """Server handler to respond to clipboard requests."""
    global clipboard_history
    print(colored(f"[+] Connected by {addr}", 'green'))
    while True:
        try:
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                break
            data = cipher_suite.decrypt(encrypted_data).decode()
            if data == 'get_clipboard':
                clipboard_content = pyperclip.paste()
                # Truncate if the clipboard content is too long
                if len(clipboard_content) > MAX_CLIPBOARD_LENGTH:
                    clipboard_content = clipboard_content[:MAX_CLIPBOARD_LENGTH] + '... [truncated]'
                clipboard_history.append(clipboard_content)
                encrypted_clipboard = cipher_suite.encrypt(clipboard_content.encode())
                conn.sendall(encrypted_clipboard)
            else:
                response = "Invalid command"
                conn.sendall(cipher_suite.encrypt(response.encode()))
        except Exception as e:
            print(colored(f"[-] An error occurred with {addr}: {e}", 'red'))
            break
    conn.close()
    print(colored(f"[-] Disconnected from {addr}", 'yellow'))

def server(local_ip, stop_event):
    """Runs a server to listen for clipboard requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((local_ip, PORT))
        server_socket.listen()
        print(colored(f"[*] Server listening on {local_ip}:{PORT}...", 'cyan'))
        server_socket.settimeout(1.0)
        while not stop_event.is_set():
            try:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
            except socket.timeout:
                continue

def clear_screen():
    """Clears the terminal screen."""
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    """Displays the 'ClipMate' banner."""
    f = Figlet(font='slant')
    banner = f.renderText('ClipMate')
    terminal_size = shutil.get_terminal_size()
    banner_lines = banner.split('\n')
    centered_banner = '\n'.join(line.center(terminal_size.columns) for line in banner_lines)
    print(colored(centered_banner, 'cyan'))

def client(peer_ip):
    """Client that requests clipboard from the peer and allows interaction."""
    global clipboard_history
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, PORT))
        print(colored(f"\n[+] Connected to {peer_ip}", 'green'))

        while True:
            command = input(colored("CPC > ", 'green')).strip()

            if command == 'help':
                print(colored("\n┌" + "─" * 70 + "┐", 'cyan'))
                print(colored("│" + "Available Commands".center(70) + "│", 'cyan'))
                print(colored("├" + "─" * 70 + "┤", 'cyan'))
                print(colored("│" + "show           - Retrieve and display the peer's clipboard content.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "cp <number>    - Copy specified clipboard entry from local clipboard.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "exit           - Exit the program.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "help           - Display this help message.".ljust(70) + "│", 'cyan'))
                print(colored("└" + "─" * 70 + "┘\n", 'cyan'))

            elif command == 'show':
                encrypted_command = cipher_suite.encrypt(command.encode())
                client_socket.sendall(encrypted_command)
                encrypted_clipboard = client_socket.recv(4096)
                clipboard_content = cipher_suite.decrypt(encrypted_clipboard).decode()
                clipboard_history.append(clipboard_content)
                print(colored("\n┌" + "─" * 70 + "┐", 'magenta'))
                print(colored("│" + "[ Clipboard History ]".center(70) + "│", 'magenta'))
                print(colored("├" + "─" * 70 + "┤", 'magenta'))
                for idx, content in enumerate(clipboard_history, start=1):
                    content_lines = [content[i:i+66] for i in range(0, len(content), 66)]
                    for line_num, line in enumerate(content_lines):
                        if line_num == 0:
                            line_prefix = f"{idx}. "
                        else:
                            line_prefix = "    "
                        print(colored("│" + (line_prefix + line).ljust(70) + "│", 'magenta'))
                print(colored("└" + "─" * 70 + "┘\n", 'magenta'))

            elif command.startswith('cp'):
                try:
                    _, number = command.split()
                    index = int(number) - 1
                    if 0 <= index < len(clipboard_history):
                        pyperclip.copy(clipboard_history[index])
                        print(colored(f"\n[+] Copied clipboard entry {number} to local clipboard.\n", 'green'))
                    else:
                        print(colored("[-] Invalid number. Please try again.\n", 'red'))
                except (ValueError, IndexError):
                    print(colored("[-] Invalid command format. Use 'cp <number>'.\n", 'red'))

            elif command == 'exit':
                client_socket.close()
                print(colored("\n[*] Exiting the program. Goodbye!", 'cyan'))
                break

            else:
                print(colored("[-] Unknown command. Type 'help' to see available commands.\n", 'yellow'))

    except ConnectionRefusedError:
        print(colored(f"[-] Failed to connect to {peer_ip}. Is the server running?", 'red'))
    except Exception as e:
        print(colored(f"[-] An error occurred: {e}", 'red'))

def main():
    # Clear the terminal screen
    clear_screen()

    # Display the 'ClipMate' banner
    display_banner()

    # Command-line argument parser
    parser = argparse.ArgumentParser(description="Clipboard Sharing App")
    parser.add_argument('--local-ip', type=str, required=True, help='Local IP address of this machine')
    parser.add_argument('--peer-ip', type=str, required=True, help='IP address of the peer machine')

    args = parser.parse_args()
    local_ip = args.local_ip
    peer_ip = args.peer_ip

    # Event to signal server shutdown
    stop_event = threading.Event()

    # Start the server in a separate thread
    server_thread = threading.Thread(target=server, args=(local_ip, stop_event), daemon=True)
    server_thread.start()

    try:
        # Run the client part
        client(peer_ip)
    except KeyboardInterrupt:
        print(colored("\n[*] Keyboard interrupt received. Exiting.", 'cyan'))
    finally:
        stop_event.set()
        server_thread.join()

if __name__ == "__main__":
    main()
