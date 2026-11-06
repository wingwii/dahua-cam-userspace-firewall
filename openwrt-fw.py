import ctypes
import struct
import socket
import time
import os

PCAP_FILE_PATH = "/etc/config/log/fw.pcap"

# ------------------------------------------------------------------
# Load openwrt libnetfilter_queue.so
# ------------------------------------------------------------------
try:
    libnfq = ctypes.CDLL("libnetfilter_queue.so.1")
except OSError:
    libnfq = ctypes.CDLL("libnetfilter_queue.so")

NF_DROP = 0
NF_ACCEPT = 1
AF_INET = 2

libnfq.nfq_open.restype = ctypes.c_void_p
libnfq.nfq_close.argtypes = [ctypes.c_void_p]
libnfq.nfq_unbind_pf.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
libnfq.nfq_bind_pf.argtypes = [ctypes.c_void_p, ctypes.c_uint16]

libnfq.nfq_create_queue.restype = ctypes.c_void_p
libnfq.nfq_create_queue.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p]

libnfq.nfq_set_mode.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint32]

libnfq.nfq_set_verdict.argtypes = [
    ctypes.c_void_p,       # qh
    ctypes.c_uint32,       # id
    ctypes.c_uint32,       # verdict
    ctypes.c_uint32,       # data_len
    ctypes.c_char_p        # buf
]

libnfq.nfq_fd.restype = ctypes.c_int
libnfq.nfq_fd.argtypes = [ctypes.c_void_p]


class PcapDumper:
    def __init__(self, filename):
        self.filename = filename
        file_exists = os.path.exists(self.filename)
        self.f = open(self.filename, "ab")
        
        if not file_exists or os.path.getsize(self.filename) == 0:
            # PCAP Global Header (24 bytes) - DLT_IPV4 (101)
            global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
            self.f.write(global_header)
            self.f.flush()

    def write_packet(self, raw_ip_packet):
        if not raw_ip_packet:
            return
            
        now = time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1000000)
        pkt_len = len(raw_ip_packet)

        # PCAP Packet Header (16 bytes)
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self.f.write(pkt_header + raw_ip_packet)
        self.f.flush()

    def close(self):
        self.f.close()

def calculate_ip_checksum(ip_header):
    ip_header_no_ckpt = ip_header[:10] + b'\x00\x00' + ip_header[12:]
    if len(ip_header_no_ckpt) % 2 == 1:
        ip_header_no_ckpt += b'\x00'
        
    s = sum(struct.unpack(f'!{len(ip_header_no_ckpt)//2}H', ip_header_no_ckpt))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def process_and_modify_packet(raw_ip_packet):
    if len(raw_ip_packet) < 28:
        return raw_ip_packet

    ip_hdr = raw_ip_packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_hdr)
    ip_hdr_len = (iph[0] & 0x0F) * 4
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    if protocol == 17:
        udp_hdr = raw_ip_packet[ip_hdr_len : ip_hdr_len + 8]
        if len(udp_hdr) < 8:
            return raw_ip_packet

        udph = struct.unpack('!HHHH', udp_hdr)
        src_port, dst_port, old_udp_len, _ = udph
        
        udp_payload = raw_ip_packet[ip_hdr_len + 8 :]

        new_payload = None

        if b"NetKeyboard" in udp_payload:
            print(f"\n[!] Found pattern \"NetKeyboard\" from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            if b"admin" in udp_payload:
                new_payload = udp_payload.replace(b"admin", b"admon")
                pass
            pass

        if b"OnvifUser" in udp_payload:
            print(f"\n[!] Found pattern \"OnvifUser\" from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            new_payload = udp_payload.replace(b"OnvifUser", b"AnvifUser")
            pass


        if new_payload is not None:
            new_udp_len = 8 + len(new_payload)
            new_ip_total_len = ip_hdr_len + new_udp_len

            new_udp_hdr = struct.pack('!HHHH', src_port, dst_port, new_udp_len, 0x0000)

            ip_hdr_modified = (
                raw_ip_packet[:2] + 
                struct.pack('!H', new_ip_total_len) + 
                raw_ip_packet[4:10] + 
                b'\x00\x00' + 
                raw_ip_packet[12:ip_hdr_len]
            )
            ip_checksum = calculate_ip_checksum(ip_hdr_modified)
            new_ip_hdr = ip_hdr_modified[:10] + struct.pack('!H', ip_checksum) + ip_hdr_modified[12:]

            modified_packet = new_ip_hdr + new_udp_hdr + new_payload
            return modified_packet


    return raw_ip_packet


def parse_netlink_msg(data):
    if len(data) < 20:
        return None, None

    offset = 20
    packet_id = None
    payload = None

    while offset < len(data):
        if offset + 4 > len(data):
            break

        attr_len, attr_type = struct.unpack("HH", data[offset : offset + 4])
        if attr_len < 4:
            break

        real_type = attr_type & 0x7FFF

        if real_type == 1:
            hdr_bytes = data[offset + 4 : offset + 12]
            packet_id = struct.unpack("!I", hdr_bytes[:4])[0]

        elif real_type == 10:
            payload = data[offset + 4 : offset + attr_len]

        offset += (attr_len + 3) & ~3

    return packet_id, payload


def main():
    h = libnfq.nfq_open()
    if not h:
        print("[-] Error: nfq_open.")
        return

    libnfq.nfq_unbind_pf(h, AF_INET)
    libnfq.nfq_bind_pf(h, AF_INET)

    qh = libnfq.nfq_create_queue(h, 0, None, None)
    if not qh:
        print("[-] Error: Cannot create NFQUEUE 0.")
        libnfq.nfq_close(h)
        return

    libnfq.nfq_set_mode(qh, 2, 0xFFFF)

    fd = libnfq.nfq_fd(h)
    sock = socket.fromfd(fd, socket.AF_NETLINK, socket.SOCK_RAW)
    sock.setblocking(True)

    pcap = PcapDumper(PCAP_FILE_PATH)

    print(f"[+] NFQUEUE Mangle Filter is running...")

    try:
        while True:
            data = sock.recv(65535)
            if not data:
                continue

            packet_id, raw_packet = parse_netlink_msg(data)

            if packet_id is not None and raw_packet is not None:
                pcap.write_packet(raw_packet)

                modified_packet = process_and_modify_packet(raw_packet)

                if modified_packet != raw_packet:
                    libnfq.nfq_set_verdict(
                        qh, 
                        packet_id, 
                        NF_ACCEPT, 
                        len(modified_packet), 
                        modified_packet
                    )
                else:
                    libnfq.nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, None)

    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        pcap.close()
        libnfq.nfq_destroy_queue(qh)
        libnfq.nfq_close(h)

if __name__ == "__main__":
    main()
