import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def detect_protocol_tcp(port, sock):
    try:
        sock.settimeout(2.0)

        if port in (80, 8080, 8000, 8888):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except OSError:
                pass

        try:
            data = sock.recv(1024)
        except socket.timeout:
            return None

        if not data:
            return None

        text = data.decode("latin-1", errors="ignore")
        upper = text.upper()

        if upper.startswith("HTTP/") or "HTTP/1." in upper[:64]:
            return "HTTP"
        if upper.startswith("220") and ("SMTP" in upper or "ESMTP" in upper or "MAIL" in upper):
            return "SMTP"
        if upper.startswith("220") and port in (25, 465, 587):
            return "SMTP"
        if upper.startswith("+OK"):
            return "POP3"
        if upper.startswith("* OK"):
            return "IMAP"
        return None
    except Exception:
        return None

def _probe_ntp(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        ntp_req = b"\x1b" + 47 * b"\x00"
        try:
            s.sendto(ntp_req, (host, port))
            data, _ = s.recvfrom(1024)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(data) >= 48:
            mode = data[0] & 0x7
            if mode in (4, 5):
                return "SNTP" if port == 123 else "NTP"
        return None
    finally:
        s.close()


def _probe_dns(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        dns_req = (
            b"\xab\xcd"
            b"\x01\x00"
            b"\x00\x01"
            b"\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00"
            b"\x00\x01\x00\x01"
        )
        try:
            s.sendto(dns_req, (host, port))
            data, _ = s.recvfrom(1024)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(data) >= 12 and data[:2] == b"\xab\xcd":
            return "DNS"
        return None
    finally:
        s.close()


def detect_protocol_udp(port, host):
    try:
        if port == 123:
            proto = _probe_ntp(host, port)
            if proto:
                return proto
        if port == 53:
            proto = _probe_dns(host, port)
            if proto:
                return proto
        return None
    except PermissionError:
        raise
    except Exception:
        return None

def scan_tcp_port(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        proto = detect_protocol_tcp(port, s)
        return (port, proto)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass

def scan_udp_port(host, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            try:
                s.sendto(b"\0", (host, port))
            except OSError:
                pass

            opened = False
            try:
                s.recvfrom(1024)
                opened = True
            except socket.timeout:
                opened = False
            except ConnectionRefusedError:
                return None
            except OSError:
                opened = False
        finally:
            s.close()

        if opened:
            return (port, detect_protocol_udp(port, host))

        if port in (53, 123):
            proto = detect_protocol_udp(port, host)
            if proto:
                return (port, proto)
        return None
    except PermissionError:
        raise
    except Exception:
        return None

def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP/UDP port scanner with protocol detection",
    )
    parser.add_argument("host", help="target host (IP or hostname)")
    parser.add_argument("-t", "--tcp", action="store_true", help="scan TCP")
    parser.add_argument("-u", "--udp", action="store_true", help="scan UDP")
    parser.add_argument(
        "-p", "--ports", nargs=2, type=int, metavar=("N1", "N2"),
        required=True, help="port range: N1 N2",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    host = args.host

    if not args.tcp and not args.udp:
        print("Error: specify -t and/or -u", file=sys.stderr)
        sys.exit(1)

    n1, n2 = args.ports
    if n1 > n2:
        n1, n2 = n2, n1
    n1 = max(1, n1)
    n2 = min(65535, n2)
    if n1 > n2:
        print("Error: empty port range after clamping to 1..65535", file=sys.stderr)
        sys.exit(1)

    ports = range(n1, n2 + 1)
    n_ports = n2 - n1 + 1
    open_ports = []

    try:
        if args.tcp:
            workers = min(200, n_ports)
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(scan_tcp_port, host, p): p for p in ports}
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        port, app = r
                        open_ports.append(("TCP", port, app))

        if args.udp:
            workers = min(100, n_ports)
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(scan_udp_port, host, p): p for p in ports}
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        port, app = r
                        open_ports.append(("UDP", port, app))

    except PermissionError:
        print("Not enough rights for scanning. Try as admin/root (sudo).", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nCanceled by user.", file=sys.stderr)
        sys.exit(130)

    open_ports.sort(key=lambda x: (x[0], x[1]))
    for proto, port, app in open_ports:
        print(f"{proto} {port} {app}" if app else f"{proto} {port}")


if __name__ == "__main__":
    main()