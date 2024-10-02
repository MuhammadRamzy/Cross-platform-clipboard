import logging
import os
import platform
import shutil
import socket
import ssl
import sys
import threading
import time
from typing import List, Tuple

import pyperclip
from pyfiglet import Figlet
from termcolor import colored

# Constants
DEFAULT_PORT = 65432
DEFAULT_CERT_FILE = 'cert.pem'
DEFAULT_KEY_FILE = 'key.pem'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("clipmate.log"),
        logging.StreamHandler(sys.stdout)
    ]
)


class ClipMateServer:
    """
    Server class to handle incoming clipboard requests.
    """

    def __init__(self, ip: str, port: int, password: str, cert_file: str, key_file: str):
        self.ip = ip
        self.port = port
        self.password = password
        self.cert_file = cert_file
        self.key_file = key_file
        self.stop_event = threading.Event()

    def start(self):
        """Starts the server in a separate thread."""
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def run_server(self):
        """Main server loop."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind((self.ip, self.port))
                server_socket.listen()
                logging.info(f"Server listening on {self.ip}:{self.port}")
                server_socket.settimeout(1.0)

                while not self.stop_event.is_set():
                    try:
                        conn, addr = server_socket.accept()
                        conn = context.wrap_socket(conn, server_side=True)
                        client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                        client_thread.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Server error: {e}")
            except Exception as e:
                logging.error(f"Failed to start server: {e}")
                sys.exit(1)

    def handle_client(self, conn: ssl.SSLSocket, addr: Tuple[str, int]):
        """Handles incoming client connections."""
        logging.info(f"Connected by {addr}")
        try:
            # Authenticate client
            conn.sendall(b"Password: ")
            client_password = conn.recv(1024).decode().strip()
            if client_password != self.password:
                conn.sendall(b"Authentication failed.")
                conn.close()
                logging.warning(f"Authentication failed for {addr}")
                return
            conn.sendall(b"Authentication successful.\n")

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
                        logging.error(f"Error sending data to {addr}: {e}")
                else:
                    conn.sendall(b"Invalid command")
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            logging.info(f"Disconnected from {addr}")

    def stop(self):
        """Stops the server."""
        self.stop_event.set()


class ClipMateClient:
    """
    Client class to interact with the peer's clipboard.
    """

    def __init__(self, peer_ip: str, port: int, password: str, cert_file: str):
        self.peer_ip = peer_ip
        self.port = port
        self.password = password
        self.cert_file = cert_file
        self.clipboard_history: List[str] = []

    def run(self):
        """Runs the client interface."""
        try:
            context = ssl.create_default_context()
            context.load_verify_locations(self.cert_file)

            with socket.create_connection((self.peer_ip, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.peer_ip) as client_socket:
                    logging.info(f"Connected to {self.peer_ip}")
                    # Handle authentication
                    response = client_socket.recv(1024).decode()
                    if "Password:" in response:
                        client_socket.sendall(f"{self.password}\n".encode())
                        auth_response = client_socket.recv(1024).decode()
                        if "successful" not in auth_response:
                            logging.error("Authentication failed.")
                            return
                        else:
                            logging.info("Authentication successful.")
                    else:
                        logging.error("Unexpected response from server.")
                        return

                    self.interactive_shell(client_socket)

        except socket.timeout:
            logging.error(f"Connection timed out when connecting to {self.peer_ip}.")
        except ConnectionRefusedError:
            logging.error(f"Failed to connect to {self.peer_ip}. Is the server running?")
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def interactive_shell(self, client_socket: ssl.SSLSocket):
        """Provides an interactive shell to the user."""
        while True:
            command = input(colored("CPC > ", 'green')).strip()

            if command == 'help':
                self.display_help()
            elif command == 'show':
                self.fetch_clipboard(client_socket)
            elif command.startswith('cp'):
                self.copy_clipboard_entry(command)
            elif command == 'exit':
                logging.info("Exiting the program. Goodbye!")
                break
            else:
                logging.warning("Unknown command. Type 'help' to see available commands.")

    def fetch_clipboard(self, client_socket: ssl.SSLSocket):
        """Fetches the clipboard content from the peer."""
        try:
            client_socket.sendall(b'get_clipboard')
            clipboard_content = client_socket.recv(4096).decode()
            if not self.clipboard_history or clipboard_content != self.clipboard_history[-1]:
                self.clipboard_history.append(clipboard_content)
                logging.info("New clipboard content added to history.")
            else:
                logging.warning("Clipboard content hasn't changed since last fetch.")

            self.display_clipboard_history()
        except Exception as e:
            logging.error(f"Error fetching clipboard content: {e}")

    def copy_clipboard_entry(self, command: str):
        """Copies a specified clipboard entry to the local clipboard."""
        try:
            _, number = command.split()
            index = int(number) - 1
            if 0 <= index < len(self.clipboard_history):
                pyperclip.copy(self.clipboard_history[index])
                logging.info(f"Copied clipboard entry {number} to local clipboard.")
            else:
                logging.error("Invalid number. Please try again.")
        except ValueError:
            logging.error("Invalid command format. Use 'cp <number>'.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def display_clipboard_history(self):
        """Displays the clipboard history."""
        print(colored("\n" + "=" * 80, 'magenta'))
        print(colored("[ Clipboard History ]".center(80), 'magenta'))
        print(colored("=" * 80, 'magenta'))
        for idx, content in enumerate(self.clipboard_history, start=1):
            content_lines = [content[i:i+76] for i in range(0, len(content), 76)]
            for line_num, line in enumerate(content_lines):
                line_prefix = f"{idx}. " if line_num == 0 else "     "
                print(colored(line_prefix + line, 'magenta'))
        print(colored("=" * 80 + "\n", 'magenta'))

    @staticmethod
    def display_help():
        """Displays the help menu."""
        help_text = """
        Available Commands:
        - show           : Retrieve and display the peer's clipboard content.
        - cp <number>    : Copy the specified clipboard entry to your local clipboard.
        - exit           : Exit the program.
        - help           : Display this help message.
        """
        print(colored(help_text, 'cyan'))


def get_local_ip() -> str:
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


def validate_ip(ip: str) -> bool:
    """Validates the given IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def generate_self_signed_cert(cert_file: str, key_file: str):
    """Generates a self-signed certificate if it doesn't exist."""
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logging.info("Generating self-signed certificate...")
        from OpenSSL import crypto

        # Create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().CN = 'ClipMate'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(cert_file, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(key_file, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))


def main():
    # Clear the terminal screen
    clear_screen()

    # Display the 'ClipMate' banner
    display_banner()

    # Fetch the local IP address
    local_ip = get_local_ip()
    logging.info(f"Your local IP address is {local_ip}")

    # Prompt for the peer's IP address
    peer_ip = input(colored("Enter the peer's IP address: ", 'yellow')).strip()
    if not validate_ip(peer_ip):
        logging.error("Invalid IP address format.")
        sys.exit(1)

    # Prompt for the password
    password = input(colored("Enter the password for authentication: ", 'yellow')).strip()
    if not password:
        logging.error("Password cannot be empty.")
        sys.exit(1)

    # Use default port and certificate paths
    port = DEFAULT_PORT
    cert_file = DEFAULT_CERT_FILE
    key_file = DEFAULT_KEY_FILE

    # Generate SSL certificate if it doesn't exist
    generate_self_signed_cert(cert_file, key_file)

    # Start the server
    server = ClipMateServer(local_ip, port, password, cert_file, key_file)
    server.start()

    try:
        # Give the server a moment to start
        time.sleep(0.5)
        # Run the client part
        client = ClipMateClient(peer_ip, port, password, cert_file)
        client.run()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Exiting.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
