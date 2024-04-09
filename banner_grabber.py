import socket

def banner_grabber(target, port=80):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target).encode())
            banner = s.recv(1024)
            return banner.decode().strip()
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    target = input("Enter the target IP address or domain name: ")
    port = int(input("Enter the port number (default is 80 for HTTP): ") or 80)
    print(f"Banner from {target}:{port} - {banner_grabber(target, port)}")
