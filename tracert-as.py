import sys
import socket
import ipaddress
import re

PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def is_local(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return True
        for net in PRIVATE_NETS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False

def get_whois_server(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('whois.iana.org', 43))
        s.send(f'{ip}\r\n'.encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        s.close()
        text = data.decode('utf-8', errors='ignore')
        match = re.search(r'refer:\s+(\S+)', text)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None

def query_whois(server, query):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((server, 43))
        s.send(f'{query}\r\n'.encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        s.close()
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_whois(text):
    netname = None
    asn = None
    country = None
    m = re.search(r'netname:\s+(\S+)', text, re.I)
    if m: netname = m.group(1)
    m = re.search(r'origin:\s+AS(\d+)', text, re.I)
    if m: asn = m.group(1)
    if not asn:
        m = re.search(r'aut-num:\s+AS(\d+)', text, re.I)
        if m: asn = m.group(1)
    m = re.search(r'country:\s+(\S+)', text, re.I)
    if m:
        c = m.group(1).upper()
        if c != 'EU':
            country = c
    return netname, asn, country

def get_ip_info(ip):
    if is_local(ip):
        return "local"
    server = get_whois_server(ip) or 'whois.ripe.net'
    resp = query_whois(server, ip)
    if not resp:
        return None
    netname, asn, country = parse_whois(resp)
    parts = []
    if netname: parts.append(netname)
    if asn: parts.append(asn)
    if country: parts.append(country)
    return ", ".join(parts) if parts else None

def traceroute(target, max_hops=30, timeout=2):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return None

    print(f"Tracing to {target} [{target_ip}]:")

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    host = socket.gethostbyname(socket.gethostname())
    recv_sock.bind((host, 0))
    recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    recv_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    recv_sock.settimeout(timeout)
    port = 33434

    for ttl in range(1, max_hops + 1):
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        print(f"{ttl}. ", end="")

        try:
            send_sock.sendto(b"", (target_ip, port + ttl))

            packet, addr = recv_sock.recvfrom(1024)
            src_ip = addr[0]

            ip_header_len = (packet[0] & 0x0F) * 4
            icmp_type = packet[ip_header_len]

            if icmp_type in (11, 3):
                print(src_ip)
                info = get_ip_info(src_ip)
                if info:
                    print(info)

                if src_ip == target_ip:
                    break
            else:
                print("*")
        except socket.timeout:
            print("*")
        except Exception:
            print("*")

        print()

    send_sock.close()
    recv_sock.close()

def main():
    if len(sys.argv) != 2:
        print("Using: python tracert-as.py <IP or domain>")
        return

    target = sys.argv[1]

    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{target} is invalid")
            return

    try:
        traceroute(target)
    except PermissionError:
        print("Error: need admin rights for raw-sockets")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()