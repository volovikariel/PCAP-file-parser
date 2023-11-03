# PCap file format information found here: https://wiki.wireshark.org/Development/LibpcapFileFormat
import argparse
import ipaddress
import logging
import os
import struct
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from typing import Optional

dev_logging = logging.Logger("dev")
enable_dev_logging = False
if not enable_dev_logging:
    dev_logging.setLevel(logging.CRITICAL + 1)


class MagicNumber:
    little_endian = b"\xD4\xC3\xB2\xA1"
    big_endian = b"\xA1\xB2\xC3\xD4"


# https://www.tcpdump.org/linktypes.html
class LinkType:
    ethernet = 1


# For protocol numbers source, see: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
class TransportProtocol:
    ICMP = 1  # Not supported
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
            endianness +
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
            endianness +
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
            case InternetType.ipv6:
                self.network_packet = IPv6Packet(
                    self,
                    self.payload[: IPv6Packet.IPV6_HEADER_START_LENGTH],
                    self.payload[IPv6Packet.IPV6_HEADER_START_LENGTH :],
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
                    f"Unsupported link layer packet format {self.type_length}."
                )
        return self.network_packet


class EthernetPacket(LinkPacket):
    # Header length in bytes
    HEADER_LENGTH = 14
    # Ethernet headers https://wiki.wireshark.org/Ethernet#packet-format

    def __init__(
        self, parent_packet: PcapPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

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
            case TransportProtocol.TCP:
                # data_offset represents the #of 4 byte chunks that compose the TCP headers
                data_offset = self.payload[12] >> 4
                self.transport_packet = TCPPacket(
                    self,
                    self.payload[: data_offset * 4],
                    self.payload[4 * data_offset :],
                )
            case TransportProtocol.UDP:
                self.transport_packet = UDPPacket(
                    self,
                    self.payload[: UDPPacket.UDP_HEADERS_LENGTH],
                    self.payload[UDPPacket.UDP_HEADERS_LENGTH :],
                )
            case _:
                # Note: I don't support network packets containing other network packets...
                dev_logging.warning(
                    f"Protocol #{hex(self.get_protocol())} is not supported for the Transport Layer.\n"
                )
        return self.transport_packet

    def get_protocol(self):
        """Implementation in the children."""
        pass


class IPv6Packet(NetworkPacket):
    IPV6_HEADER_START_LENGTH = 40

    def __init__(
        self, parent_packet: LinkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

        # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
        header_structure = (
            # Big endian
            ">"
            # 4 bits Version + 4 bits traffic class
            "B"
            # 4 bits traffic class + 4 bits flow label
            "B"
            # 2 bytes rest of flow label
            "H"
            # 2 bytes /* Payload length */
            "H"
            # 1 byte /* Next header */
            "B"
            # 1 byte /* Hop limit */
            "B"
            # 16 bytes /* Source Address */
            "IIII"
            # 16 bytes /* Destination Address */
            "IIII"
        )

        headers_raw = struct.unpack(header_structure, self.headers)

        self.version = headers_raw[0] >> 4
        # 4 low bits of byte 1 + 4 high bits of byte 2
        self.traffic_class = ((headers_raw[0] & 0xF) << 4) + (headers_raw[1] >> 4)
        # 4 low bits of byte 2 + header_raw[3] which contains the 2 remaining bytes
        #  doing a << (2*8) because the lower bits of byte#2 are the upper bits of the resulting 20 bit number, of which the top 4 bits are thus offset by 16=2*8 bits
        self.flow_label = ((headers_raw[2] & 0xF) << 2 * 8) + headers_raw[3]
        self.next_header = headers_raw[4]
        self.hop_limit = headers_raw[5]
        self.src_addr = ipaddress.IPv6Address(headers_raw[6])
        self.dst_addr = ipaddress.IPv6Address(headers_raw[7])

    def get_protocol(self):
        # Note: I don't parse all of the many extension headers with their own options and all that
        #       It would be quite tedious to write it all out...
        return self.next_header


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
            # 1 byte /* Protocol */
            "B"
            # 2 bytes /* Header Checksum */
            "h"
            # 4 bytes /* src addr */
            "I"
            # 4 bytes /* dst addr */
            "I" +
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
        arp_header_structure = (
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

        raw_headers = struct.unpack(arp_header_structure, self.headers)

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
    def __init__(
        self, parent_packet: NetworkPacket, headers: bytes, payload: bytes
    ) -> None:
        self.parent_packet = parent_packet
        self.headers = headers
        self.payload = payload
        self.application_packet: Optional[ApplicationPacket] = None

    def parse(self):
        return self.application_packet


class TCPPacket(TransportPacket):
    MIN_TCP_HEADER_LENGTH = 20

    def __init__(
        self, parent_packet: NetworkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

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
            "H" +
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


class UDPPacket(TransportPacket):
    UDP_HEADERS_LENGTH = 8

    def __init__(
        self, parent_packet: NetworkPacket, headers: bytes, payload: bytes
    ) -> None:
        super().__init__(parent_packet, headers, payload)

        # https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
        udp_header_structure = (
            # Big endian
            ">"
            # 2 bytes /* src port */
            "H"
            # 2 bytes /* dst port */
            "H"
            # 2 bytes /* length */
            "H"
            # 2 byte /* checksum */
            "H"
        )

        raw_headers = struct.unpack(udp_header_structure, self.headers)
        self.src_port = raw_headers[0]
        self.dst_port = raw_headers[1]
        self.length = raw_headers[2]
        self.checksum = raw_headers[3]


class ApplicationPacket:
    pass


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True, help="filename")
    parser.add_argument("-t", required=True, help="target IP address")
    prob_group = parser.add_argument_group("Probing")
    (
        prob_group.add_argument(
            "-l", default=None, help="width for probing, in seconds", type=int
        ),
    )
    prob_group.add_argument(
        "-m", default=None, help="minimum number of packets in probing", type=int
    )
    scan_group = parser.add_argument_group("Scanning")
    scan_group.add_argument(
        "-n", default=None, help="the width for scanning, in portID", type=int
    )
    scan_group.add_argument(
        "-p", default=None, help="minimum number of packets in scanning", type=int
    )

    # If argv is none, automatically looks at sys.args
    args = parser.parse_args(argv)

    execute_probing = False
    execute_scanning = False
    # If probing is present
    if args.l != None and args.m != None:
        execute_probing = True
    # If scanning is present
    if args.n != None and args.p != None:
        execute_scanning = True
    # If neither is present
    if not execute_probing and not execute_scanning:
        print("both [-l -m] and/or both [-n -p] need to be present")
        return

    file_path: str = args.f
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

        # All packets have been parsed as much as they can, now go through them and remove all non-UDP and non-TCP packets
        # Also remove the packets whose dst_ip is not that of the target ip
        tcp_udp_packets: list[TransportPacket] = list()
        for packet in file.pcap_packets:
            try:
                network_packet = packet.link_packet.network_packet
                # Only consider the ones with dst_addr == the target_addr
                if str(network_packet.dst_addr) != args.t:
                    continue
                if (
                    network_packet.get_protocol() == TransportProtocol.TCP
                    or network_packet.get_protocol() == TransportProtocol.UDP
                ):
                    transport_packet = network_packet.transport_packet
                    tcp_udp_packets.append(transport_packet)
            # Packets that don't go down to the transport layer are ignored
            except:
                continue

        # Now we will organize it based on src_addr's
        src_addr_to_tmstmp_port_tuple = defaultdict(list)
        for packet in tcp_udp_packets:
            dst_port = packet.dst_port

            network_packet = packet.parent_packet
            src_addr = network_packet.src_addr

            ts_sec = int(network_packet.parent_packet.parent_packet.ts_sec)
            ts_usec = int(network_packet.parent_packet.parent_packet.ts_usec)
            # For a prettier output, display both seconds and the microseconds
            ts = float(f"{ts_sec}.{ts_usec}")

            src_addr_to_tmstmp_port_tuple[str(src_addr)].append((ts, dst_port))

        if execute_probing:
            print(
                (((os.get_terminal_size().columns - 7) // 2) * "#")
                + "Probing"
                + (((os.get_terminal_size().columns - 7) // 2) * "#")
            )
            # Note, it's already sorted by time, as we're reading the file top to bottom, so we can run our
            # probing detection algorithm now
            src_ip_port_tuple_to_chunks = defaultdict(list)
            for src_ip, entries in src_addr_to_tmstmp_port_tuple.items():
                for ts, dst_port in entries:
                    key = (src_ip, dst_port)
                    # If we've previously had this port pinged within args.l time, then append it to the same probing chunk
                    if (len(src_ip_port_tuple_to_chunks[key]) != 0) and (
                        (ts - src_ip_port_tuple_to_chunks[key][-1][-1]) <= args.l
                    ):
                        src_ip_port_tuple_to_chunks[key][-1].append(ts)
                    # Otherwise, create a new chunk
                    else:
                        src_ip_port_tuple_to_chunks[key].append([ts])
            # Now check all of the chunks of size >= args.m, and print those out
            for (src_ip, port), chunks in src_ip_port_tuple_to_chunks.items():
                for chunk in chunks:
                    if len(chunk) >= args.m:
                        chunk_length = len(chunk)
                        print(
                            f"\n{src_ip=}\n"
                            f"{port=}\n"
                            f"{chunk_length=}\n"
                            f"Timestamps: {','.join(map(str, chunk))}"
                        )
            print(os.get_terminal_size().columns * "#")

        if execute_scanning:
            print(
                (((os.get_terminal_size().columns - 8) // 2) * "#")
                + "Scanning"
                + (((os.get_terminal_size().columns - 8) // 2) * "#")
            )
            for src_ip, entries in src_addr_to_tmstmp_port_tuple.items():
                # Add all unique ports from this src_ip to the target_ip
                ports = set()
                for _, dst_port in entries:
                    ports.add(dst_port)

                # Sort them to facilitate scanning
                ports = sorted(list(ports))

                scan_chunk = []
                for port in ports:
                    # If we've previously had a smaller port# within args.n, then append it to the same scan chunk
                    if (len(scan_chunk) != 0) and (
                        (port - scan_chunk[-1][-1]) <= args.n
                    ):
                        scan_chunk[-1].append(port)
                    # Otherwise, create a new scan chunk
                    else:
                        scan_chunk.append([port])
                for scan_chunk in scan_chunk:
                    # If a scan chunk has >= args.p ports in it, then print it out
                    if len(scan_chunk) >= args.p:
                        scan_length = len(scan_chunk)
                        print(
                            f"\n{src_ip=}\n"
                            f"{scan_length=}\n"
                            f"Scanned ports: {','.join(map(str, scan_chunk))}"
                        )
            print(os.get_terminal_size().columns * "#")


if __name__ == "__main__":
    main()
