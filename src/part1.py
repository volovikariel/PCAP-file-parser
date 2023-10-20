# PCap file format information found here: https://wiki.wireshark.org/Development/LibpcapFileFormat
import glob
from typing import Literal
from collections import defaultdict
import struct
import ipaddress
import os

PCAP_DIR = "Lab3-pcap-1"


class Packet:
    def __init__(self, contents: bytes, ts_sec: int) -> None:
        self.contents = contents
        self.ts_sec = ts_sec
        self.src_mac = None
        self.dst_mac = None
        self.src_addr = None
        self.dst_addr = None
        self.src_port = None
        self.dst_port = None

    def generate_fields(self):
        # Ethernet headers https://wiki.wireshark.org/Ethernet#packet-format
        # type_length = 2 bytes (base: 12)
        ethernet_headers_struct = (
            # Big endian
            ">"
            # 6 bytes /* Destination MAC address */
            "BBBBBB"
            # 6 bytes /* Source MAC address */
            "BBBBBB"
            # 2 bytes /* Type-Length field; If value 1500 or lower, it's a length field; Otherwise, it's a type field
            "H"
        )
        ethernet_headers = struct.unpack(ethernet_headers_struct, self.contents[0:14])
        dst_mac = bytes(ethernet_headers[0:6])
        src_mac = bytes(ethernet_headers[7:12])
        type_length = ethernet_headers[12]

        # https://wiki.wireshark.org/Ethernet#type-length-field
        class EtherType:
            ipv4 = 0x0800
            arp = 0x0806
            ipx = 0x8137
            ipv6 = 0x86DD

        match type_length:
            case EtherType.ipv4:
                # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
                ipv4_base_ptr = 14
                min_ipv4_hdr_len = 20

                # Before performing a struct.unpack, we need to know the length of the headers (whether there's Options or not)
                # To do this, we simply read the lower 4 bits of the first byte
                # The IHL represents the # of 4 byte chunks
                ihl = self.contents[ipv4_base_ptr] & 0xF
                option_bytes = "B" * ((ihl * 4) - min_ipv4_hdr_len)

                ipv4_header_structure = (
                    # Big endian
                    ">"
                    # 4 bits Version + 4 bits IHL
                    "B"
                    # 1 byte /* Type of service */
                    "B"
                    # 2 bytes /* Total Length */
                    "H"
                    # 2 bytes /* Identification */
                    "H"
                    # 3 bits Flags + 13 bits Fragment Offset
                    "H"
                    # 1 byte /* TTL */
                    "B"
                    # 1 byte /* Protcol */
                    "B"
                    # 2 bytes /* Header Checksum */
                    "h"
                    # 4 bytes /* src addr */
                    "I"
                    # 4 bytes /* dst addr */
                    "I"
                    +
                    # (NOT PARSED) Options
                    option_bytes
                )

                ipv4_headers = struct.unpack(
                    ipv4_header_structure,
                    self.contents[ipv4_base_ptr : ipv4_base_ptr + ihl * 4],
                )

                version = ipv4_headers[0] >> 4
                type_of_service = ipv4_headers[1]
                total_length = ipv4_headers[2]
                identification = ipv4_headers[3]
                flags = ipv4_headers[4] & 0xE000  # Only top 3 bits set
                fragment_offset = ipv4_headers[4] & 0x1FFF  # All but top 3 bits set
                ttl = ipv4_headers[5]
                protocol = ipv4_headers[6]
                header_checksum = ipv4_headers[7]
                self.src_addr = ipaddress.IPv4Address(ipv4_headers[8])
                self.dst_addr = ipaddress.IPv4Address(ipv4_headers[9])
                options = ipv4_headers[10:] if len(option_bytes) != 0 else None

                # For protocol numbers source, see: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
                class Protocols:
                    TCP = 6
                    UDP = 17

                match protocol:
                    case Protocols.TCP:
                        # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
                        tcp_base_ptr = ipv4_base_ptr + ihl * 4
                        min_tcp_hdr_len = 20

                        # Before performing a struct.unpack, we need to know the length of the headers (whether there's Options or not)
                        # To do this, we simply read the data offset bits
                        # data_offset represents the #of 4 byte chunks that compose the TCP headers
                        data_offset = self.contents[tcp_base_ptr + 12] >> 4
                        # The options come in chunks of 4 bytes
                        option_bytes = "I" * (
                            ((data_offset * 4) - min_tcp_hdr_len) // 4
                        )

                        tcp_header_structure = (
                            # Big endian
                            ">"
                            # 2 bytes /* src port */
                            "H"
                            # 2 bytes /* dst port */
                            "H"
                            # 4 byte /* seq num */
                            "I"
                            # 4 byte /* ack num */
                            "I"
                            # 4 bits data offset + 4 bits reserved
                            "B"
                            # 1 byte flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
                            "B"
                            # 2 byte /* window size */
                            "H"
                            # 2 byte /* checksum */
                            "H"
                            # 2 byte /* urgent pointer */
                            "H"
                            +
                            # (UNSUPPORTED) Variable /* Options */
                            option_bytes
                        )

                        tcp_header = struct.unpack(
                            tcp_header_structure,
                            self.contents[
                                tcp_base_ptr : tcp_base_ptr + data_offset * 4
                            ],
                        )
                        self.src_port = tcp_header[0]
                        self.dst_port = tcp_header[1]
                        seq_num = tcp_header[2]
                        ack_num = tcp_header[3]
                        cwr = tcp_header[5] & 0b10000000
                        ece = tcp_header[5] & 0b01000000
                        urg = tcp_header[5] & 0b00100000
                        ack = tcp_header[5] & 0b00010000
                        psh = tcp_header[5] & 0b00001000
                        rst = tcp_header[5] & 0b00000100
                        syn = tcp_header[5] & 0b00000010
                        fin = tcp_header[5] & 0b00000001
                        window_size = tcp_header[6]
                        checksum = tcp_header[7]
                        urgent_pointer = tcp_header[8]
                        options = tcp_header[9:] if len(option_bytes) != 0 else None
                    case _:
                        """TCP is the only transport layer protocol supported."""
                        pass
            case EtherType.arp:
                # https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
                # arpa_base_ptr = byte#15 (#14 if 0-indexed)
                # plen_base_ptr = 1 byte (base: arpa_base_ptr + 5)
                # src_addr      = 4 bytes (base: arpa_base_ptr + 14)
                # dst_addr      = 4 bytes (base: arpa_base_ptr + 24)
                arpa_base_ptr = 14

                arpa_header_structure = (
                    # Big endian
                    ">"
                    # 2 bytes /* htype, hardware type */
                    "H"
                    # 2 bytes /* ptype, protocol type */
                    "H"
                    # 1 byte  /* hlen, hardware address length */
                    "B"
                    # 1 byte  /* plen, protocol address length */
                    "B"
                    # 2 bytes /* oper, operation */
                    "H"
                    # 6 bytes /* sha, sender hardware address */
                    "HHH"
                    # 4 bytes /* spa, sender protocol address */
                    "I"
                    # 6 bytes /* tha, target hardware address */
                    "HHH"
                    # 4 bytes /* tpa, target protocol address */
                    "I"
                )

                arpa_header = struct.unpack(
                    arpa_header_structure, self.contents[arpa_base_ptr:]
                )

                htype = arpa_header[0]
                ptype = arpa_header[1]
                hlen = arpa_header[2]
                plen = arpa_header[3]
                oper = arpa_header[4]
                sha = arpa_header[5 : 5 + 3]
                spa = arpa_header[8]
                tha = arpa_header[9 : 9 + 3]
                tpa = arpa_header[12]

                match ptype:
                    case EtherType.ipv4:
                        self.src_addr = ipaddress.IPv4Address(spa)
                        self.dst_addr = ipaddress.IPv4Address(tpa)
                    case EtherType.ipv6:
                        self.src_addr = ipaddress.IPv6Address(spa)
                        self.dst_addr = ipaddress.IPv6Address(tpa)
            case _ if type_length <= 1500:
                raise Exception("802.2 header packets are not supported.")
            case _:
                raise Exception(
                    "Unsupported link layer packet format.\n"
                    "Only IPv4 and ARPA packets supported."
                )


def extract_packets(file_path: str) -> list[Packet]:
    packets = list()
    with open(file_path, "rb") as f:
        # File size
        f_size = os.path.getsize(file_path)

        global_headers_structure = (
            # Little endian (ASSUMED - as the passed in files all have little endian-style magic number)
            "<"
            # uint32 magic_number;   /* magic number */
            "I"
            # uint16 version_major;  /* major version number */
            "H"
            # uint16 version_minor;  /* minor version number */
            "H"
            # int32  thiszone;       /* GMT to local correction */
            "i"
            # uint32 sigfigs;        /* accuracy of timestamps */
            "I"
            # uint32 snaplen;        /* max length of captured packets, in octets */
            "I"
            # uint32 network;        /* data link type */
            "I"
        )
        global_headers = struct.unpack(global_headers_structure, f.read(24))

        magic_num = global_headers[0]
        v_maj = global_headers[1]
        v_min = global_headers[2]
        this_zone = global_headers[3]
        sigfigs = global_headers[4]
        snaplen = global_headers[5]
        link_type = global_headers[6]

        ethernet = 1
        # I checked all the pcap files provided, and they're all ethernet type.
        # The program won't work with other types of links (see: https://www.tcpdump.org/linktypes.html)
        assert link_type == ethernet

        # Now go through the file one packet at a time
        packet_header_structure = (
            # Little endian
            "<"
            # uint32 ts_sec;         /* timestamp seconds */
            "I"
            # uint32 ts_usec;        /* timestamp microseconds */
            "I"
            # uint32 incl_len;       /* number of octets of packet saved in file */
            "I"
            # uint32 orig_len;       /* actual length of packet */
            "I"
        )

        # We stop when we reach the end of the file
        while f.tell() != f_size:
            packet_headers = struct.unpack(packet_header_structure, f.read(16))
            ts_sec: int = packet_headers[0]
            ts_usec: int = packet_headers[1]
            inc_len: int = packet_headers[2]
            orig_len: int = packet_headers[3]
            packet = Packet(f.read(inc_len), ts_sec)
            packets.append(packet)
    return packets


def main() -> None:
    print("#1")
    all_packets: list[Packet] = list()
    total_num_packets = 0
    for file_path in glob.glob(f"{PCAP_DIR}/*.pcap"):
        packets = extract_packets(file_path)
        print(f"#Packets in {file_path}: {len(packets)}")
        total_num_packets += len(packets)
        all_packets += packets
    print(f"#Packets in total: {total_num_packets}")

    # Generate the IP and TCP information in preparation for the following questions
    for packet in all_packets:
        packet.generate_fields()

    print("\n#2")
    src_addr_to_packet: dict[str, list[Packet]] = defaultdict(list)
    for packet in all_packets:
        src_addr_to_packet[packet.src_addr].append(packet)
    for src_addr, packets in sorted(
        src_addr_to_packet.items(),
        # Sorting in descending order of #packets, and then by the src ip
        key=lambda kv_pair: (len(kv_pair[1]), kv_pair[0]),
        reverse=True,
    ):
        print(f"src IP {src_addr} is associated with: {len(packets)} packets")

    print("\n#3")
    dst_port_to_packet: dict[str, list[Packet]] = defaultdict(list)
    for packet in all_packets:
        # Non-TCP packets don't have a TCP dst_port
        if packet.dst_port:
            dst_port_to_packet[packet.dst_port].append(packet)

    for dst_port, packets in sorted(
        dst_port_to_packet.items(),
        # Sorting in descending order of #packets, and then by the dst port
        key=lambda kv_pair: (len(kv_pair[1]), kv_pair[0]),
        reverse=True,
    ):
        print(f"dst port {dst_port} is associated with: {len(packets)} packets")

    print("\n#4")
    # Making it tuples so as to then be able to sort the IP addresses
    src_ip_dst_port_tuples: set[tuple[ipaddress.IPv4Address, int]] = set(
        (packet.src_addr, packet.dst_port) for packet in all_packets
    )

    for src_addr, dst_port in sorted(
        src_ip_dst_port_tuples,
        key=lambda tuple: (
            tuple[0],
            # Make sure it appears last if there's no port number
            tuple[1] if tuple[1] else -1,
        ),
        reverse=True,
    ):
        print(f"src IP={str(src_addr)}, dst port={dst_port}")
    print(f"total of {len(src_ip_dst_port_tuples)} distinct (src IP, dst port) tuples")


if __name__ == "__main__":
    main()
