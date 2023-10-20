import glob
from typing import Literal
from collections import defaultdict

PCAP_DIR = "Lab3-pcap-1"


def bytes_to_ipv4_address(bytes: bytes, encoding: Literal["little", "big"]) -> str:
    output = ""
    for byte_num in range(len(bytes)):
        # We want to have a period before every element but the first (Head-Tail pattern)
        if byte_num > 0:
            output += "."
        # If we want to be able to decide on how to decode the byte
        # We have to slice it as opposed to indexing it, this returns a byte, as opposed to an int
        # see: https://stackoverflow.com/a/28249609/13829722 for more information
        output += str(int.from_bytes(bytes[byte_num : byte_num + 1], encoding))
    return output


class Packet:
    contents: bytes
    src_addr: str | bytes | None
    dst_addr: str | bytes | None
    src_port: int | bytes | None
    dst_port: int | bytes | None

    def __init__(self, contents: bytes) -> None:
        self.contents = contents
        self.src_addr = None
        self.dst_addr = None
        self.src_port = None
        self.dst_port = None

    def generate_fields(self):
        # Ethernet headers https://wiki.wireshark.org/Ethernet#packet-format
        # type_length = 2 bytes (base: 12)
        type_length = self.contents[12:14]
        # https://wiki.wireshark.org/Ethernet#type-length-field
        ipv4_packet = b"\x08\x00"
        arpa_packet = b"\x08\x06"
        # I checked all of the provided packets and they all seem to be either IPv4 packets or ARPA packets
        assert type_length in [ipv4_packet, arpa_packet]

        if type_length == ipv4_packet:
            # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
            # ipv4_base_ptr = byte#15 (#14 if 0-indexed)
            # src_addr      = 4 bytes (base: ipv4_base_ptr + 3*4)
            # dst_addr      = 4 bytes (base: ipv4_base_ptr + 4*4)
            ipv4_base_ptr = 14

            src_addr_base_ptr = ipv4_base_ptr + 3 * 4
            dst_addr_base_ptr = ipv4_base_ptr + 4 * 4

            # Storing as bytes temporarily
            self.src_addr = self.contents[src_addr_base_ptr : src_addr_base_ptr + 4]
            self.dst_addr = self.contents[dst_addr_base_ptr : dst_addr_base_ptr + 4]
            # Converting to IPv4 addresses
            self.src_addr = bytes_to_ipv4_address(self.src_addr, "big")
            self.dst_addr = bytes_to_ipv4_address(self.dst_addr, "big")

            # We only care about TCP, which is protocol == 6 as seen here: https://datatracker.ietf.org/doc/html/rfc790 under ASSIGNED INTERNET PROTOCOL NUMBERS
            # protocol_addr = 1 byte  (base: ipv4_base_ptr + 2*4 + 1)
            protocol_base_ptr = ipv4_base_ptr + 2 * 4 + 1
            # I also see 1 (ICMP) and 17 (UDP) in the given data, but we're only asked about TCP - so if we see them, return
            if (
                int.from_bytes(
                    self.contents[protocol_base_ptr : protocol_base_ptr + 1], "big"
                )
                != 6
            ):
                return

            # We can now extract the src and dst port from the TCP packet
            # To know where the TCP packet starts, we have to figure out how long the IPv4 headers were
            # This is given by the IPv4 IHL field (says how many bytes it is in length)
            # ipv4_ihl = 4 bits (ipv4_base_ptr's first byte, but only reading the 4 least significant bytes)
            ipv4_ihl = (
                int.from_bytes(self.contents[ipv4_base_ptr : ipv4_base_ptr + 1], "big")
                & 0b00001111
            )

            # tcp_base_ptr = ipv4_base_ptr + ipv4_ihl*4
            # src_port     = 2 bytes (base: tcp_base_ptr)
            # dst_port     = 2 bytes (base: tcp_base_ptr + 2)
            tcp_base_ptr = ipv4_base_ptr + ipv4_ihl * 4
            src_port_base_ptr = tcp_base_ptr
            dst_port_base_ptr = tcp_base_ptr + 2

            # Storing in raw bytes temporarily
            self.src_port = self.contents[src_port_base_ptr : src_port_base_ptr + 2]
            self.dst_port = self.contents[dst_port_base_ptr : dst_port_base_ptr + 2]

            # Storing in terms of INTs
            self.src_port = int.from_bytes(self.src_port, "big")
            self.dst_port = int.from_bytes(self.dst_port, "big")
        elif type_length == arpa_packet:
            # https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
            # arpa_base_ptr = byte#15 (#14 if 0-indexed)
            # plen_base_ptr = 1 byte (base: arpa_base_ptr + 5)
            # src_addr      = 4 bytes (base: arpa_base_ptr + 14)
            # dst_addr      = 4 bytes (base: arpa_base_ptr + 24)
            arpa_base_ptr = 14

            # First ensure that it's truly IPv4 addresses being used checking that PLEN == 4
            # I made sure that all APRA calls in the given files contain IPv4 addresses
            plen_base_ptr = arpa_base_ptr + 5
            assert (
                int.from_bytes(self.contents[plen_base_ptr : plen_base_ptr + 1], "big")
                == 4
            )

            src_addr_base_ptr = arpa_base_ptr + 14
            dst_addr_base_ptr = arpa_base_ptr + 24

            # Storing as bytes temporarily
            self.src_addr = self.contents[src_addr_base_ptr : src_addr_base_ptr + 4]
            self.dst_addr = self.contents[dst_addr_base_ptr : dst_addr_base_ptr + 4]
            # Conerting to IPv4 addresses
            self.src_addr = bytes_to_ipv4_address(self.src_addr, "big")
            self.dst_addr = bytes_to_ipv4_address(self.dst_addr, "big")


def extract_packets(file_path: str) -> list[Packet]:
    packets = list()
    with open(file_path, "rb") as f:
        # PCap file format information found here: https://wiki.wireshark.org/Development/LibpcapFileFormat
        global_headers = f.read(24)
        # link_type = 4 bytes (base: 20)
        link_type_base_ptr = 20
        link_type = global_headers[link_type_base_ptr : link_type_base_ptr + 4]
        ethernet = b"\x01\x00\x00\x00"
        # I checked all the pcap files provided, and they're all ethernet type.
        # The program won't work with other types of links (see: https://www.tcpdump.org/linktypes.html)
        assert link_type == ethernet

        # Now go through the file one packet at a time
        while packet_headers := f.read(16):
            # Packets 8-12 determine the length
            packet_length = int.from_bytes(packet_headers[8:12], "little")
            packet = Packet(f.read(packet_length))
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
        # Sorting in descending order of #packets, and then by the src ip
        key=lambda kv_pair: (len(kv_pair[1]), kv_pair[0]),
        reverse=True,
    ):
        print(f"dst port {dst_port} is associated with: {len(packets)} packets")

    print("\n#4")
    # Making it tuples so as to then be able to sort the IP addresses
    src_ip_dst_port_tuples: set[tuple[tuple[int], int]] = set()
    for packet in all_packets:
        # I'm assuming that ones without a dst_port are also desired
        dst_port = packet.dst_port if packet.dst_port else None
        src_addr_chunked = tuple(int(chunk) for chunk in packet.src_addr.split("."))
        src_ip_dst_port_tuples.add((src_addr_chunked, dst_port))

    for src_addr, dst_port in sorted(
        src_ip_dst_port_tuples,
        key=lambda tuple: (
            # sort based on the chunks (so 192.X.X.X > 191.X.X.X, 192.2.X.X > 192.1.X.X, etc.)
            tuple[0],
            # Make sure it appears last if there's no port number
            tuple[1] if tuple[1] else -1,
        ),
        reverse=True,
    ):
        print(f"src IP={'.'.join(map(str, src_addr))}, dst port={dst_port}")
    print(f"total of {len(src_ip_dst_port_tuples)} distinct (src IP, dst port) tuples")


if __name__ == "__main__":
    main()
