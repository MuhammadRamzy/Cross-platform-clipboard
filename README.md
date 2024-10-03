# ClipMate

**ClipMate** is a cross-platform clipboard-sharing tool that allows users on the same network to share and access clipboard content in real time. With ClipMate, you can easily view and copy clipboard entries from other computers on the network, making collaboration seamless.

## Features

- **Real-time Clipboard Sharing**: Fetch clipboard content from peers on the same local network.
- **Clipboard History**: Maintain a local history of clipboard entries retrieved from peers.
- **Cross-Platform**: Works on Windows, macOS, and Linux.
- **Command-Line Interface**: Simple CLI for retrieving, viewing, and copying clipboard content.
- **Easy Setup**: No complex configuration required—just share your local IP with a peer!

## Installation

### Prerequisites

Make sure you have Python 3.6+ installed on your system.

### Installation 
--- 

You can easily install ClipMate from PyPI:

```bash
pip install clipmate
```
Once installed, you can run the program by typing:

```bash
clipmate
```
---
Once ClipMate is running, it will start listening on the default port (`65432`) for incoming clipboard requests.

## Usage Instructions

### Local Network Setup

ClipMate is designed to work within the same **local network** (LAN). This means both computers sharing the clipboard must be connected to the same Wi-Fi network or connected via an Ethernet cable within the same network.

### Starting a Session

1. **Start ClipMate on Both Machines**: 
   - Run `clipmate.py` on both your machine and the peer machine.
   - The peer (the person whose clipboard you want to access) should note their local IP address, displayed by ClipMate when it starts.
   - **Example**: `[*] Your local IP address is 192.168.1.100`.

2. **Enter the Peer’s IP**: 
   - On your machine, you’ll be prompted to enter the IP address of the peer machine.
   - **Example**: Enter `192.168.1.101` if that is the peer's IP.

3. **Retrieve Clipboard**: 
   - After entering the peer's IP, you will be able to interact with their clipboard using simple commands.

### Commands

Once connected, you can use the following commands:

- **show**: Fetch and display the current clipboard content from the peer.
- **cp \<number\>**: Copy a specific clipboard entry from the local history to your clipboard.
- **exit**: Exit the program and disconnect from the peer.
- **help**: Display a list of available commands.

### Example Session

Here's an example session of ClipMate in action:

1. **Peer (Server) Machine**:
   - Start ClipMate by running `python clipmate.py`. It will display the local IP address, e.g., `192.168.1.101`.
   - Wait for the other machine to connect.

2. **Your (Client) Machine**:
   - Start ClipMate by running `python clipmate.py`.
   - When prompted, enter the peer's IP address: `192.168.1.101`.
   - After connecting, you will see the prompt `CPC >`, indicating that you can now interact with the peer's clipboard.

```bash
                                           _________       __  ___      __
                                          / ____/ (_)___  /  |/  /___ _/ /____
                                         / /   / / / __ \/ /|_/ / __ `/ __/ _ \
                                        / /___/ / / /_/ / /  / / /_/ / /_/  __/
                                        \____/_/_/ .___/_/  /_/\__,_/\__/\___/
                                                /_/

[*] Your local IP address is 192.168.1.100
Enter the peer's IP address: 192.168.1.101

[+] Connected to 192.168.1.101
CPC > show

[+] New clipboard content added to history.

┌──────────────────────────────────────────────────────────────────────┐
│                         [ Clipboard History ]                        │
├──────────────────────────────────────────────────────────────────────┤
│ 1. This is the peer's clipboard content!                             │
│ 2. Here’s another clipboard entry from the peer.                     │
└──────────────────────────────────────────────────────────────────────┘

CPC > cp 1
[+] Copied clipboard entry 1 to local clipboard.

CPC > exit
[*] Exiting the program. Goodbye!
```

In this example:
- The `show` command retrieves the clipboard content from the peer and adds it to the local history.
- The `cp 1` command copies the first entry from the clipboard history to the local clipboard.

### Important Notes

- Both machines must be connected to the same **local network**.
- If you encounter connection issues, ensure that no firewall or security software is blocking port `65432`.

## Demo Walkthrough

1. **Setup**: 
   - Both you and your peer must be connected to the same local network.
   - Run `clipmate.py` on both machines.
   
2. **Get Local IP**: 
   - Each machine will display its local IP address (e.g., `192.168.1.x`).
   
3. **Connect to Peer**: 
   - On your machine, enter the peer's local IP address when prompted.

4. **Fetch Clipboard**: 
   - Use the `show` command to retrieve clipboard content from the peer.
   
5. **Copy Content Locally**: 
   - Use `cp <number>` to copy clipboard content from the history to your local clipboard.

## Troubleshooting

- **Connection Refused**: Ensure that the peer’s firewall isn’t blocking the connection on port `65432` and that both machines are on the same local network.
- **Clipboard Not Accessible**: If you receive clipboard access errors, verify that `pyperclip` is installed and working correctly on your system.

## Contributing

Contributions are welcome! Feel free to fork the repository, submit pull requests, or open issues to suggest new features or report bugs.

## License

This project is licensed under the MIT License.

---
