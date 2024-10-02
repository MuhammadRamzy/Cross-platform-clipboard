# Two-Way Clipboard Sharing Application

## Introduction

The Two-Way Clipboard Sharing Application allows users to share clipboard content seamlessly between two computers connected to the same local network. This tool is especially useful for collaborative tasks, enabling easy transfer of text snippets, URLs, or any other clipboard data without the need for email or other transfer methods.

## Goal

The primary goal of this application is to facilitate efficient clipboard sharing between two machines, providing a straightforward command-line interface that allows users to view, copy, and manage clipboard content in real-time.

## How It Works

The application establishes a TCP connection between two PCs using their local IP addresses. Once connected, users can send commands to request clipboard content from the peer machine. The application supports two main operations:
- **Requesting clipboard content** from the other computer.
- **Copying specific clipboard entries** to the local clipboard for immediate use.

### Key Features
- Bidirectional clipboard sharing.
- Simple terminal commands for easy interaction.
- Color-coded feedback for connection status.

## Installation

To set up the project, follow these steps:

### Prerequisites
- Python 3.x installed on both machines.
- Internet connection for package installation.

### Steps to Install

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/clipboard-sharing.git
   cd clipboard-sharing
2. **Install required dependencies using the requirements.txt file**:
    ```bash
    pip install -r requirements.txt


### Usage
To run the application, execute the script on both computers that need to share the clipboard. Each machine should specify its own local IP address and the peer's IP address.

### Example Commands
On PC 1:

    ```bash
    python clipboard_sharing.py --local-ip 192.168.1.101 --peer-ip 192.168.1.102
    
On PC 2:

    ```bash
    python clipboard_sharing.py --local-ip 192.168.1.102 --peer-ip 192.168.1.101
    
### Available Commands
Once the application is running, you can enter the following commands in the terminal:

- show: Lists the clipboard content from the peer machine in a numbered format.
- cp <number>: Copies the content of the specified clipboard entry (by its number) to the local clipboard.
