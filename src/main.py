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
from tqdm import tqdm  # For progress bar

PORT = 65432
BUFFER_SIZE = 4096  # Size of each chunk of file being sent
clipboard_history = []
download_directory = os.path.join(os.path.expanduser("~"), 'Downloads')

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def send_file(conn, file_path):
    try:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            conn.sendall(f"SEND_FILE {file_name} {file_size}".encode())

            with open(file_path, 'rb') as file, tqdm(
                total=file_size, unit='B', unit_scale=True, unit_divisor=1024, 
                desc=f"Sending {file_name}", ncols=80
            ) as progress_bar:
                while True:
                    bytes_read = file.read(BUFFER_SIZE)
                    if not bytes_read:
                        break
                    conn.sendall(bytes_read)
                    progress_bar.update(len(bytes_read))

            print(colored(f"[+] File '{file_name}' sent successfully.", 'green'))
        else:
            conn.sendall(b"ERROR File does not exist.")
            print(colored("[-] File not found.", 'red'))
    except Exception as e:
        print(colored(f"[-] Error sending file: {e}", 'red'))

def receive_file(conn, file_name, file_size):
    global download_directory
    file_path = os.path.join(download_directory, file_name)

    try:
        with open(file_path, 'wb') as file, tqdm(
            total=file_size, unit='B', unit_scale=True, unit_divisor=1024, 
            desc=f"Receiving {file_name}", ncols=80
        ) as progress_bar:
            total_received = 0
            while total_received < file_size:
                bytes_read = conn.recv(min(BUFFER_SIZE, file_size - total_received))
                if not bytes_read:
                    break
                file.write(bytes_read)
                total_received += len(bytes_read)
                progress_bar.update(len(bytes_read))

        print(colored(f"[+] File received successfully: {file_path}", 'green'))
    except Exception as e:
        print(colored(f"[-] Error receiving file: {e}", 'red'))

def handle_client(conn, addr):
    print(colored(f"[+] Connected by {addr}", 'green'))
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            command = data.decode()

            if command.startswith('get_clipboard'):
                try:
                    clipboard_content = pyperclip.paste()
                except Exception as e:
                    clipboard_content = f"Error accessing clipboard: {e}"
                conn.sendall(clipboard_content.encode())

            elif command.startswith('SEND_FILE'):
                _, file_name, file_size = command.split()
                file_size = int(file_size)
                print(colored(f"\n[*] {addr} is sending a file: {file_name} ({file_size} bytes)", 'cyan'))
                accept = input(colored("Do you want to accept the file? (yes/no): ", 'yellow')).strip().lower()
                if accept == 'yes':
                    conn.sendall(b"ACCEPT_FILE")
                    receive_file(conn, file_name, file_size)
                else:
                    conn.sendall(b"DECLINE_FILE")
            else:
                conn.sendall(b"Invalid command")
    except Exception as e:
        print(colored(f"[-] Error handling client {addr}: {e}", 'red'))
    finally:
        conn.close()
        print(colored(f"[-] Disconnected from {addr}", 'yellow'))

def server(local_ip, stop_event):
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
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    f = Figlet(font='slant')
    banner = f.renderText('ClipMate')
    terminal_size = shutil.get_terminal_size()
    banner_lines = banner.split('\n')
    centered_banner = '\n'.join(line.center(terminal_size.columns) for line in banner_lines)
    print(colored(centered_banner, 'cyan'))

def client(peer_ip):
    global clipboard_history, download_directory
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10.0)
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
                print(colored("│" + "sf <file_path> - Send a file to the peer.".ljust(70) + "│", 'cyan'))
                print(colored("│" + "sf -set <path> - Set the download directory for incoming files.".ljust(70) + "│", 'cyan'))
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
                            print(colored(f"[+] Copied entry {number} to local clipboard.\n", 'green'))
                        except Exception as e:
                            print(colored(f"[-] Error copying to clipboard: {e}\n", 'red'))
                    else:
                        print(colored("[-] Invalid clipboard entry number.\n", 'red'))
                except (ValueError, IndexError):
                    print(colored("[-] Usage: cp <number>\n", 'red'))

            elif command.startswith('sf'):
                if command.startswith('sf -set'):
                    try:
                        _, _, new_path = command.split(' ', 2)
                        if os.path.isdir(new_path):
                            download_directory = new_path
                            print(colored(f"[+] Download directory set to: {download_directory}\n", 'green'))
                        else:
                            print(colored("[-] Invalid directory path.\n", 'red'))
                    except ValueError:
                        print(colored("[-] Usage: sf -set <path>\n", 'red'))

                else:
                    try:
                        _, file_path = command.split(' ', 1)
                        if os.path.exists(file_path):
                            client_socket.sendall(f"sf {file_path}".encode())
                            send_file(client_socket, file_path)
                        else:
                            print(colored("[-] File not found.\n", 'red'))
                    except ValueError:
                        print(colored("[-] Usage: sf <file_path>\n", 'red'))

            elif command == 'exit':
                print(colored("\n[-] Exiting...", 'yellow'))
                client_socket.close()
                break

            else:
                print(colored("[-] Unknown command. Type 'help' for a list of commands.\n", 'red'))

    except Exception as e:
        print(colored(f"[-] Connection error: {e}", 'red'))
    finally:
        client_socket.close()

if __name__ == "__main__":
    stop_event = threading.Event()
    try:
        clear_screen()
        display_banner()

        local_ip = get_local_ip()
        server_thread = threading.Thread(target=server, args=(local_ip, stop_event))
        server_thread.start()

        while True:
            peer_ip = input(colored("\n[?] Enter peer's IP address to connect or type 'exit' to quit: ", 'yellow')).strip()
            if peer_ip == 'exit':
                break
            client(peer_ip)

    except KeyboardInterrupt:
        print(colored("\n[-] Shutting down...", 'yellow'))
        stop_event.set()
        sys.exit(0)
