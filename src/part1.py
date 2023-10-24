# PCap file format information found here: https://wiki.wireshark.org/Development/LibpcapFileFormat
import glob
from typing import Optional, Callable
import logging
import struct
from collections import defaultdict
import ipaddress
import os
from io import BytesIO
from pathlib import Path

dev_logging = logging.Logger("dev")
enable_dev_logging = False
if not enable_dev_logging:
    dev_logging.setLevel(logging.CRITICAL + 1)

PCAP_DIR = "Lab3-pcap-1"


class MagicNumber:
    little_endian = b"\xD4\xC3\xB2\xA1"
    big_endian = b"\xA1\xB2\xC3\xD4"


# https://www.tcpdump.org/linktypes.html
class LinkType:
    ethernet = 1


# For protocol numbers source, see: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
class NetworkProtocol:
    ICMP = 1
    TCP = 6
    UDP = 17


# https://wiki.wireshark.org/Ethernet#type-length-field
class InternetType:
    ipv4 = 0x0800
    arp = 0x0806
    ipx = 0x8137
    ipv6 = 0x86DD


class PcapFile:
    # header length in bytes
    HEADER_LENGTH = 24

    def __init__(
        self, name: str, headers: bytes, payload: Optional[bytes], size: int
    ) -> None:
        self.name = name
        self.headers = headers
        self.payload = payload
        self.size = size

        self.magic_number = headers[0 : 0 + 4]

        endianness = "<" if self.magic_number == MagicNumber.little_endian else ">"
        self.header_structure = (
            endianness
            +
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

        (
            _,  # We've already assigned self.magic_number
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network,
        ) = struct.unpack(self.header_structure, headers)

        self.pcap_packets: list[PcapPacket] = []

    # Go through the payload and extract all the PcapPackets
    def extract_packets(self):
        payload = BytesIO(self.payload)
        while pcap_headers := payload.read(PcapPacket.HEADER_LENGTH):
            # Packet payload length written within the packet headers
            incl_len = int.from_bytes(
                pcap_headers[4 * 3 : 4 * 4],
                "little" if self.magic_number == MagicNumber.little_endian else "big",
            )
            self.pcap_packets.append(
                PcapPacket(self, pcap_headers, payload.read(incl_len))
            )

    def parse_packets(self):
        for packet in self.pcap_packets:
            packet.parse()


class PcapPacket:
    # header length in bytes
    HEADER_LENGTH = 16

    def __init__(
        self, parent_container: PcapFile, headers: bytes, payload: bytes
    ) -> None:
        self.parent_file = parent_container
        self.headers = headers
        self.payload = payload

        endianness = (
            "<" if self.parent_file.magic_number == MagicNumber.little_endian else ">"
        )
        self.header_structure = (
            endianness
            +
            # uint32 ts_sec;         /* timestamp seconds */
            "I"
            # uint32 ts_usec;        /* timestamp microseconds */
            "I"
            # uint32 incl_len;       /* number of octets of packet saved in file */
            "I"
            # uint32 orig_len;       /* actual length of packet */
            "I"
        )
        (self.ts_sec, self.ts_usec, self.inc_len, self.orig_len) = struct.unpack(
            self.header_structure, self.headers
        )

        self.link_packet: Optional[LinkPacket] = None

    def parse(self):
        payload = BytesIO(self.payload)
        match self.parent_file.network:
            case LinkType.ethernet:
                ethernet_headers = payload.read(EthernetPacket.HEADER_LENGTH)
                # Packet payload length written within the packet headers
                incl_len = int.from_bytes(ethernet_headers[4 * 3 : 4 * 4], "big")
                self.link_packet = EthernetPacket(
                    self, ethernet_headers, payload.read(incl_len)
                )
            case _:
                dev_logging.warning(
                    f"Link type {self.parent_file.network} not supported."
                )
        return self.link_packet


class LinkPacket:
    def __init__(
        self, parent_packet: PcapPacket, headers: bytes, payload: bytes
    ) -> None:
        self.parent_packet = parent_packet
        self.headers = headers
        self.payload = payload
        self.network_packet: Optional[NetworkPacket] = None

    def parse(self):
        match self.type_length:
            case InternetType.ipv4:
                # Read the lower 4 bits of the first byte (contains the IHL)
                # The IHL represents the # of 4 byte chunks in the header
                ihl = self.payload[0] & 0xF
                self.network_packet = IPv4Packet(
                    self, self.payload[: 4 * ihl], self.payload[4 * ihl :]
                )
            case InternetType.arp:
                self.network_packet = ARPPacket(
                    self,
                    self.payload[: ARPPacket.HEADER_LENGTH],
                    self.payload[ARPPacket.HEADER_LENGTH :],
                )
            case _ if self.type_length <= 1500:
                dev_logging.warning("IEEE 802.3 and 802.2 packets are not supported.")
            case _:
                dev_logging.warning(
                    "Unsupported link layer packet format.\n"
                    "Only IPv4 and ARP packets supported."
                )
        return self.network_packet


class EthernetPacket(LinkPacket):
    # Header length in bytes
    HEADER_LENGTH = 14
    # Ethernet headers https://wiki.wireshark.org/Ethernet#packet-format

    def __init__(
        self, parent_container: PcapPacket, headers: bytes, payload: bytes
    ) -> None:
        self.parent_container = parent_container
        self.headers = headers
        self.payload = payload

        self.header_structure = (
            # Big endian
            ">"
            # 6 bytes /* Destination MAC address */
            "BBBBBB"
            # 6 bytes /* Source MAC address */
            "BBBBBB"
            # 2 bytes /* Type-Length field; If value 1500 or lower, it's a length field; Otherwise, it's a type field
            "H"
        )

        header_result_raw = struct.unpack(self.header_structure, self.headers)
        self.dst_mac = bytes(header_result_raw[0:6])
        self.src_mac = bytes(header_result_raw[6:12])
        self.type_length = header_result_raw[12]


class NetworkPacket:
    def __init__(
        self, parent_packet: LinkPacket, headers: bytes, payload: bytes
    ) -> None:
        self.parent_packet = parent_packet
        self.headers = headers
        self.payload = payload

        self.transport_packet: Optional[TransportPacket] = None

    def parse(self):
        match self.get_protocol():
            case NetworkProtocol.TCP:
                # data_offset represents the #of 4 byte chunks that compose the TCP headers
                data_offset = self.payload[12] >> 4
                self.transport_packet = TCPPacket(
                    self,
                    self.payload[: data_offset * 4],
                    self.payload[4 * data_offset :],
                )
            case _:
                dev_logging.warning(
                    f"Protocol #{self.get_protocol()} is not supported for the Network Layer."
                )
        return self.transport_packet

    def get_protocol(self):
        """Implementation in the children."""
        pass


class IPv4Packet(NetworkPacket):
    MIN_IPV4_HEADER_LENGTH = 20

    def __init__(
        self, parent_packet: LinkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

        # Before performing a struct.unpack, we need to know the length of the headers (whether there's Options or not)
        # To do this, we simply read the lower 4 bits of the first byte
        # The IHL represents the # of 4 byte chunks
        self.ihl = self.headers[0] & 0xF
        option_bytes = "B" * ((self.ihl * 4) - self.MIN_IPV4_HEADER_LENGTH)

        # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
        header_structure = (
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

        headers_raw = struct.unpack(header_structure, self.headers)

        self.version = headers_raw[0] >> 4
        self.type_of_service = headers_raw[1]
        self.total_length = headers_raw[2]
        self.identification = headers_raw[3]
        self.flags = headers_raw[4] & 0xE000  # Only top 3 bits set
        self.fragment_offset = headers_raw[4] & 0x1FFF  # All but top 3 bits set
        self.ttl = headers_raw[5]
        self.protocol = headers_raw[6]
        self.header_checksum = headers_raw[7]
        self.src_addr = ipaddress.IPv4Address(headers_raw[8])
        self.dst_addr = ipaddress.IPv4Address(headers_raw[9])
        self.options = headers_raw[10:] if len(option_bytes) != 0 else None

        self.transport_packet: Optional[TransportPacket] = None

    def get_protocol(self):
        return self.protocol


class ARPPacket(NetworkPacket):
    # header length in bytes
    HEADER_LENGTH = 28

    def __init__(
        self, parent_packet: LinkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

        # https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
        arpa_header_structure = (
            # Big endian
            ">"
            # 2 bytes /* htype, hardware type */
            "H"
            # 2 bytes /* protocol, protocol type */
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

        raw_headers = struct.unpack(arpa_header_structure, self.headers)

        self.htype = raw_headers[0]
        self.ptype = raw_headers[1]
        self.hlen = raw_headers[2]
        self.plen = raw_headers[3]
        self.oper = raw_headers[4]
        self.sha = raw_headers[5 : 5 + 3]
        self.spa = raw_headers[8]
        self.tha = raw_headers[9 : 9 + 3]
        self.tpa = raw_headers[12]

        match self.ptype:
            case InternetType.ipv4:
                self.src_addr = ipaddress.IPv4Address(self.spa)
                self.dst_addr = ipaddress.IPv4Address(self.tpa)
            case InternetType.ipv6:
                self.src_addr = ipaddress.IPv6Address(self.spa)
                self.dst_addr = ipaddress.IPv6Address(self.tpa)

    def get_protocol(self):
        return self.ptype


class TransportPacket:
    def __init__(self) -> None:
        self.application_packet: Optional[ApplicationPacket] = None

    def parse(self):
        return self.application_packet


class TCPPacket(TransportPacket):
    MIN_TCP_HEADER_LENGTH = 20

    def __init__(
        self, parent_packet: NetworkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__()
        self.parent_packet = parent_packet
        self.headers = headers
        self.payload = payload

        # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure

        # Before performing a struct.unpack, we need to know the length of the headers (whether there's Options or not)
        # To do this, we simply read the data offset bits
        # data_offset represents the #of 4 byte chunks that compose the TCP headers
        self.data_offset = self.headers[12] >> 4
        # The options come in chunks of 4 bytes
        option_bytes = "I" * (
            ((self.data_offset * 4) - self.MIN_TCP_HEADER_LENGTH) // 4
        )

        # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
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

        raw_headers = struct.unpack(tcp_header_structure, self.headers)
        self.src_port = raw_headers[0]
        self.dst_port = raw_headers[1]
        self.seq_num = raw_headers[2]
        self.ack_num = raw_headers[3]
        self.cwr = raw_headers[5] & 0b10000000
        self.ece = raw_headers[5] & 0b01000000
        self.urg = raw_headers[5] & 0b00100000
        self.ack = raw_headers[5] & 0b00010000
        self.psh = raw_headers[5] & 0b00001000
        self.rst = raw_headers[5] & 0b00000100
        self.syn = raw_headers[5] & 0b00000010
        self.fin = raw_headers[5] & 0b00000001
        self.window_size = raw_headers[6]
        self.checksum = raw_headers[7]
        self.urgent_pointer = raw_headers[8]
        self.options = raw_headers[9:] if len(option_bytes) != 0 else None


class ApplicationPacket:
    pass


def main() -> None:
    pcap_files: list[PcapFile] = list()
    for file_path in glob.glob(f"{PCAP_DIR}/*.pcap"):
        with open(file_path, "rb") as f:
            file = PcapFile(
                Path(file_path).stem,
                f.read(PcapFile.HEADER_LENGTH),
                f.read(),
                os.path.getsize(file_path),
            )
            file.extract_packets()
            file.parse_packets()

            # The parsers run in order (first PcapPacket.parse is ran, then LinkPacket.parse, etc.)
            # If the result of parsing is None (which means, we have reached the end of the packet, there's nothing more to parse)
            # For Example: We have an ethernet packet, no network/transport payload. Then parsing the ethernet packet will return None.
            #              Therefore, the NetworkPacket.parse and TransportPacket.parse methods won't be ran.
            parsers = [
                PcapPacket.parse,
                LinkPacket.parse,
                NetworkPacket.parse,
                TransportPacket.parse,
            ]

            for packet in file.pcap_packets:
                curr_packet = packet
                for parser in parsers:
                    if curr_packet is None:
                        break
                    curr_packet = parser(curr_packet)

            pcap_files.append(file)

    print("#1")
    all_packets: list[PcapPacket] = list()
    total_num_packets = 0
    for file in pcap_files:
        print(f"#Packets in {file.name}: {len(file.pcap_packets)}")
        total_num_packets += len(file.pcap_packets)
        all_packets += file.pcap_packets
    print(f"#Packets in total: {total_num_packets}")

    print("\n#2")
    src_addr_to_packet: dict[str, list[LinkPacket]] = defaultdict(list)
    for packet in all_packets:
        link_packet = packet.link_packet
        if not link_packet:
            continue

        network_packet = link_packet.network_packet
        if not network_packet:
            continue
        # If it's a network type (say ethernet) that has a src_addr
        if hasattr(network_packet, "src_addr"):
            src_addr_to_packet[network_packet.src_addr].append(packet)

    for src_addr, packets in sorted(
        src_addr_to_packet.items(),
        # Sorting in descending order of #packets, and then by the src ip
        key=lambda kv_pair: (len(kv_pair[1]), kv_pair[0]),
        reverse=True,
    ):
        print(f"src IP {src_addr} is associated with: {len(packets)} packets")

    print("\n#3")
    dst_port_to_packet: dict[str, list[TransportPacket]] = defaultdict(list)
    for packet in all_packets:
        link_packet = packet.link_packet
        if not link_packet:
            continue

        network_packet = link_packet.network_packet
        if not network_packet:
            continue

        transport_packet = network_packet.transport_packet
        if not transport_packet:
            continue
        # Non-TCP packets don't have a TCP dst_port
        if not hasattr(transport_packet, "dst_port"):
            continue
        dst_port_to_packet[transport_packet.dst_port].append(packet)

    for dst_port, packets in sorted(
        dst_port_to_packet.items(),
        # Sorting in descending order of #packets, and then by the dst port
        key=lambda kv_pair: (len(kv_pair[1]), kv_pair[0]),
        reverse=True,
    ):
        print(f"dst port {dst_port} is associated with: {len(packets)} packets")

    print("\n#4")
    # Making it tuples so as to then be able to sort the IP addresses
    src_ip_dst_port_tuples: set[tuple[ipaddress.IPv4Address, int]] = set()
    for packet in all_packets:
        link_packet = packet.link_packet
        if not link_packet:
            continue

        network_packet = link_packet.network_packet
        if not network_packet:
            continue
        if not hasattr(network_packet, "src_addr"):
            continue

        transport_packet = network_packet.transport_packet
        if not transport_packet or not hasattr(transport_packet, "dst_port"):
            src_ip_dst_port_tuples.add((network_packet.src_addr, None))
            continue
        src_ip_dst_port_tuples.add((network_packet.src_addr, transport_packet.dst_port))

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
