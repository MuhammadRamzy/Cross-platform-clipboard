import socket
import threading
import pyperclip
from termcolor import colored
import os
import platform
import shutil
from pyfiglet import Figlet
import sys
import time

# Configuration
PORT = 65432  # Port to use for communication

# Store clipboard history (local)
clipboard_history = []

def get_local_ip():
    """Fetches the local IP address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to reach the address, just to get the local IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def handle_client(conn, addr):
    """Server handler to respond to clipboard requests."""
    print(colored(f"[+] Connected by {addr}", 'green'))
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            command = data.decode()
            if command == 'get_clipboard':
                try:
                    clipboard_content = pyperclip.paste()
                except Exception as e:
                    clipboard_content = f"Error accessing clipboard: {e}"
                try:
                    conn.sendall(clipboard_content.encode())
                except Exception as e:
                    print(colored(f"[-] Error sending data to {addr}: {e}", 'red'))
            else:
                conn.sendall(b"Invalid command")
    except Exception as e:
        print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
    finally:
        conn.close()
        print(colored(f"[-] Disconnected from {addr}", 'yellow'))

def server(local_ip, stop_event):
    """Runs a server to listen for clipboard requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
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
                except Exception as e:
                    print(colored(f"[-] Server error: {e}", 'red'))
        except Exception as e:
            print(colored(f"[-] Failed to start server: {e}", 'red'))
            sys.exit(1)

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
        client_socket.settimeout(10.0)  # Set timeout for connection attempt
        client_socket.connect((peer_ip, PORT))
        print(colored(f"\n[+] Connected to {peer_ip}", 'green'))

        while True:
            command = input(colored("CPC > ", 'green')).strip()

            if command == 'help':
                print(colored("\n┌" + "─" * 70 + "┐", 'cyan'))
                print(colored("│" + "Available Commands".center(70) + "│", 'cyan'))
                print(colored("├" + "─" * 70 + "┤", 'cyan'))
                print(colored("│" + "show           - Retrieve and display the peer's clipboard content.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "cp <number>    - Copy specified clipboard entry to local clipboard.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "exit           - Exit the program.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "help           - Display this help message.".ljust(70) + "│", 'cyan'))
                print(colored("└" + "─" * 70 + "┘\n", 'cyan'))

            elif command == 'show':
                try:
                    client_socket.sendall(b'get_clipboard')
                    clipboard_content = client_socket.recv(4096).decode()
                    if not clipboard_history or clipboard_content != clipboard_history[-1]:
                        clipboard_history.append(clipboard_content)
                        print(colored("\n[+] New clipboard content added to history.\n", 'green'))
                    else:
                        print(colored("\n[!] Clipboard content hasn't changed since last fetch.\n", 'yellow'))

                    # Display clipboard history (truncate content to 100 characters)
                    print(colored("\n┌" + "─" * 70 + "┐", 'magenta'))
                    print(colored("│" + "[ Clipboard History ]".center(70) + "│", 'magenta'))
                    print(colored("├" + "─" * 70 + "┤", 'magenta'))
                    for idx, content in enumerate(clipboard_history, start=1):
                        truncated_content = (content[:97] + '...') if len(content) > 100 else content
                        content_lines = [truncated_content[i:i+66] for i in range(0, len(truncated_content), 66)]
                        for line_num, line in enumerate(content_lines):
                            if line_num == 0:
                                line_prefix = f"{idx}. "
                            else:
                                line_prefix = "    "
                            print(colored("│" + (line_prefix + line).ljust(70) + "│", 'magenta'))
                    print(colored("└" + "─" * 70 + "┘\n", 'magenta'))
                except Exception as e:
                    print(colored(f"[-] Error fetching clipboard content: {e}\n", 'red'))

            elif command.startswith('cp'):
                try:
                    _, number = command.split()
                    index = int(number) - 1
                    if 0 <= index < len(clipboard_history):
                        try:
                            pyperclip.copy(clipboard_history[index])
                            print(colored(f"\n[+] Copied clipboard entry {number} to local clipboard.\n", 'green'))
                        except Exception as e:
                            print(colored(f"[-] Error copying to clipboard: {e}\n", 'red'))
                    else:
                        print(colored("[-] Invalid number. Please try again.\n", 'red'))
                except ValueError:
                    print(colored("[-] Invalid command format. Use 'cp <number>'.\n", 'red'))
                except Exception as e:
                    print(colored(f"[-] An error occurred: {e}\n", 'red'))

            elif command == 'exit':
                client_socket.close()
                print(colored("\n[*] Exiting the program. Goodbye!", 'cyan'))
                break

            else:
                print(colored("[-] Unknown command. Type 'help' to see available commands.\n", 'yellow'))

    except socket.timeout:
        print(colored(f"[-] Connection timed out when connecting to {peer_ip}.", 'red'))
    except ConnectionRefusedError:
        print(colored(f"[-] Failed to connect to {peer_ip}. Is the server running?", 'red'))
    except Exception as e:
        print(colored(f"[-] An error occurred: {e}", 'red'))
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    # Clear the terminal screen
    clear_screen()

    # Display the 'ClipMate' banner
    display_banner()

    # Fetch the local IP address
    local_ip = get_local_ip()
    print(colored(f"[*] Your local IP address is {local_ip}", 'cyan'))

    # Prompt for the peer's IP address
    peer_ip = input(colored("Enter the peer's IP address: ", 'yellow')).strip()

    # Validate the IP address format
    try:
        socket.inet_aton(peer_ip)
    except socket.error:
        print(colored("[-] Invalid IP address format.", 'red'))
        sys.exit(1)

    # Event to signal server shutdown
    stop_event = threading.Event()

    # Start the server in a separate thread
    server_thread = threading.Thread(target=server, args=(local_ip, stop_event), daemon=True)
    server_thread.start()

    try:
        # Give the server a moment to start
        time.sleep(0.5)
        # Run the client part
        client(peer_ip)
    except KeyboardInterrupt:
        print(colored("\n[*] Keyboard interrupt received. Exiting.", 'cyan'))
    finally:
        stop_event.set()
        server_thread.join()

if __name__ == "__main__":
    main()
