import socket
import struct
import time
import argparse
import sys
import threading

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_AAAA = 28

TYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 28: 'AAAA',
    16: 'TXT', 33: 'SRV', 41: 'OPT', 255: 'ANY'
}

CLASS_IN = 1

class DNSCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.RLock()

    def get(self, qname, qtype, qclass):
        key = (qname.lower(), qtype, qclass)
        with self.lock:
            entry = self.cache.get(key)
            if not entry:
                return None
            if time.time() >= entry['expire_at']:
                del self.cache[key]
                return None
            return entry['records']

    def put(self, qname, qtype, qclass, records):
        if not records:
            return
        min_ttl = min(r[3] for r in records)
        if min_ttl <= 0:
            return
        
        key = (qname.lower(), qtype, qclass)
        with self.lock:
            self.cache[key] = {
                'records': records,
                'expire_at': time.time() + min_ttl
            }

class DNSParser:
    @staticmethod
    def parse_name(data, offset):
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 10
        jumps = 0
        
        while True:
            if offset >= len(data):
                raise ValueError("Truncated name")
            length = data[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    original_offset = offset
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    raise ValueError("Truncated pointer")
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                if jumps > max_jumps:
                    raise ValueError("Too many compression jumps")
                continue
            labels.append(data[offset:offset + 1 + length])
            offset += 1 + length
        
        if not jumped:
            original_offset = offset
        
        name_bytes = b''.join(labels)
        if labels:
            name_bytes += b'\x00'
        else:
            name_bytes = b'\x00'
        
        return name_bytes, original_offset

    @staticmethod
    def parse_rr(data, offset):
        name_bytes, offset = DNSParser.parse_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Truncated RR header")
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("Truncated RDATA")
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        return name_bytes, rtype, rclass, ttl, rdata, offset

    @staticmethod
    def parse_packet(data):
        if len(data) < 12:
            raise ValueError("Packet too short")
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
        
        offset = 12
        questions = []
        for _ in range(qdcount):
            qname_bytes, offset = DNSParser.parse_name(data, offset)
            if offset + 4 > len(data):
                raise ValueError("Truncated question")
            qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            questions.append({
                'qname_bytes': qname_bytes,
                'qtype': qtype,
                'qclass': qclass
            })
        
        answers = []
        for _ in range(ancount):
            rr = DNSParser.parse_rr(data, offset)
            answers.append(rr)
            offset = rr[5]
        
        authorities = []
        for _ in range(nscount):
            rr = DNSParser.parse_rr(data, offset)
            authorities.append(rr)
            offset = rr[5]
        
        additionals = []
        for _ in range(arcount):
            rr = DNSParser.parse_rr(data, offset)
            additionals.append(rr)
            offset = rr[5]
        
        return {
            'id': tid,
            'flags': flags,
            'questions': questions,
            'answers': answers,
            'authorities': authorities,
            'additionals': additionals
        }

class DNSServer:
    def __init__(self, port, forwarder_ip, forwarder_port):
        self.port = port
        self.forwarder = (forwarder_ip, forwarder_port)
        self.cache = DNSCache()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
    
    def decode_name(self, name_bytes):
        if not name_bytes or name_bytes == b'\x00':
            return '.'
        labels = []
        offset = 0
        while offset < len(name_bytes):
            length = name_bytes[offset]
            if length == 0:
                break
            labels.append(name_bytes[offset+1:offset+1+length].decode('ascii', errors='replace'))
            offset += 1 + length
        return '.'.join(labels)
    
    def build_response(self, request, answer_records, source):
        q = request['questions'][0]
        qname_bytes = q['qname_bytes']
        qtype = q['qtype']
        qclass = q['qclass']
        
        now = time.time()
        out_answers = []
        out_authorities = []
        out_additionals = []
        
        for rec_list, out_list in [
            (answer_records.get('answers', []), out_answers),
            (answer_records.get('authorities', []), out_authorities),
            (answer_records.get('additionals', []), out_additionals)
        ]:
            for r in rec_list:
                name_b, rtype, rclass, original_ttl, rdata, cached_at = r
                elapsed = int(now - cached_at)
                remaining_ttl = max(0, original_ttl - elapsed)
                if remaining_ttl == 0 and original_ttl > 0:
                    remaining_ttl = 1
                out_list.append((name_b, rtype, rclass, remaining_ttl, rdata))
        
        req_flags = request['flags']
        rd = (req_flags >> 8) & 0x01
        flags = 0x8000 | (rd << 8) | 0x0080
        
        qdcount = 1
        ancount = len(out_answers)
        nscount = len(out_authorities)
        arcount = len(out_additionals)
        
        header = struct.pack('!HHHHHH', request['id'], flags, qdcount, ancount, nscount, arcount)
        
        question = qname_bytes + struct.pack('!HH', qtype, qclass)
        
        def pack_rr(rr):
            name_b, rtype, rclass, ttl, rdata = rr
            return name_b + struct.pack('!HHIH', rtype, rclass, ttl, len(rdata)) + rdata
        
        packet = header + question
        for rr in out_answers:
            packet += pack_rr(rr)
        for rr in out_authorities:
            packet += pack_rr(rr)
        for rr in out_additionals:
            packet += pack_rr(rr)
        
        return packet, ancount > 0 or len(out_authorities) > 0
    
    def query_forwarder(self, raw_query):
        fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd_sock.settimeout(2.0)
        try:
            fwd_sock.sendto(raw_query, self.forwarder)
            data, _ = fwd_sock.recvfrom(4096)
            return data
        except (socket.timeout, socket.error) as e:
            print(f"Forwarder error: {e}", file=sys.stderr)
            return None
        finally:
            fwd_sock.close()
    
    def handle_query(self, data, addr):
        try:
            request = DNSParser.parse_packet(data)
            if not request['questions']:
                return
            q = request['questions'][0]
            qname_bytes = q['qname_bytes']
            qtype = q['qtype']
            qclass = q['qclass']
            qname_str = self.decode_name(qname_bytes)
            type_str = TYPE_MAP.get(qtype, str(qtype))
            
            cached = self.cache.get(qname_bytes, qtype, qclass)
            if cached:
                answers = []
                authorities = []
                additionals = []
                for rec in cached:
                    name_b, rtype, rclass, ttl, rdata, ts = rec
                    if name_b.lower() == qname_bytes.lower() and rtype == qtype:
                        answers.append(rec)
                    else:
                        additionals.append(rec)
                
                resp_packet, has_data = self.build_response(request, {
                    'answers': answers,
                    'authorities': authorities,
                    'additionals': additionals
                }, 'cache')
                
                if has_data:
                    self.sock.sendto(resp_packet, addr)
                    print(f"{addr[0]}, {type_str}, {qname_str}, cache")
                    return
            
            fwd_response_raw = self.query_forwarder(data)
            if fwd_response_raw is None:
                self.send_servfail(request, addr, qname_str, type_str)
                return
            
            try:
                fwd_resp = DNSParser.parse_packet(fwd_response_raw)
            except Exception as e:
                print(f"Failed to parse forwarder response: {e}", file=sys.stderr)
                self.send_servfail(request, addr, qname_str, type_str)
                return
            
            if not fwd_resp['answers'] and not fwd_resp['authorities']:
                new_id = request['id']
                new_header = struct.pack('!HHHHHH', new_id, fwd_resp['flags'],
                                         len(fwd_resp['questions']),
                                         len(fwd_resp['answers']),
                                         len(fwd_resp['authorities']),
                                         len(fwd_resp['additionals']))
                modified = bytearray(fwd_response_raw)
                modified[0:2] = struct.pack('!H', new_id)
                self.sock.sendto(bytes(modified), addr)
                print(f"{addr[0]}, {type_str}, {qname_str}, forwarder")
                return
            
            now = time.time()
            all_records = []
            for rr_list in [fwd_resp['answers'], fwd_resp['authorities'], fwd_resp['additionals']]:
                for rr in rr_list:
                    name_b, rtype, rclass, ttl, rdata, _ = rr
                    all_records.append((name_b, rtype, rclass, ttl, rdata, now))
            
            if all_records:
                self.cache.put(qname_bytes, qtype, qclass, all_records)
            
            resp_packet, _ = self.build_response(request, {
                'answers': fwd_resp['answers'],
                'authorities': fwd_resp['authorities'],
                'additionals': fwd_resp['additionals']
            }, 'forwarder')
            
            self.sock.sendto(resp_packet, addr)
            print(f"{addr[0]}, {type_str}, {qname_str}, forwarder")
            
        except Exception as e:
            print(f"Error handling query: {e}", file=sys.stderr)
            try:
                if 'request' in locals():
                    q = request['questions'][0]
                    qname_str = self.decode_name(q['qname_bytes'])
                    type_str = TYPE_MAP.get(q['qtype'], str(q['qtype']))
                    self.send_servfail(request, addr, qname_str, type_str)
            except:
                pass
    
    def send_servfail(self, request, addr, qname_str, type_str):
        q = request['questions'][0]
        flags = 0x8000 | 0x0080 | 0x0002
        header = struct.pack('!HHHHHH', request['id'], flags, 1, 0, 0, 0)
        question = q['qname_bytes'] + struct.pack('!HH', q['qtype'], q['qclass'])
        packet = header + question
        self.sock.sendto(packet, addr)
        print(f"{addr[0]}, {type_str}, {qname_str}, forwarder (SERVFAIL)")
    
    def run(self):
        print(f"DNS Caching Server started on port {self.port}, forwarder: {self.forwarder[0]}:{self.forwarder[1]}")
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                t = threading.Thread(target=self.handle_query, args=(data, addr))
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Server error: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='Caching DNS Server')
    parser.add_argument('-p', '--port', type=int, default=53, help='Listen port (default: 53)')
    parser.add_argument('-f', '--forwarder', type=str, required=True,
                        help='Forwarder IP or hostname with optional port (e.g., 8.8.8.8 or 8.8.8.8:53)')
    args = parser.parse_args()
    
    fwd = args.forwarder
    if ':' in fwd:
        host, port_str = fwd.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            host = fwd
            port = 53
    else:
        host = fwd
        port = 53
    
    try:
        socket.inet_aton(host)
        fwd_ip = host
    except OSError:
        try:
            fwd_ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"Error: cannot resolve forwarder hostname '{host}'", file=sys.stderr)
            sys.exit(1)
    
    server = DNSServer(args.port, fwd_ip, port)
    server.run()

if __name__ == '__main__':
    main()