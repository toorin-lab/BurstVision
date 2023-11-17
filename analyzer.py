from scapy.all import *


def read_pcap_scapy(file_name):
    packets = rdpcap(file_name)

    for i, packet in enumerate(packets[:10]):
        # Get the packet's size
        packet_size = len(packet)
        # Get the packet's time, which is relative to the start of the capture
        packet_time = packet.time

        print(f"Packet {i + 1}: Size={packet_size}, Time={packet_time}")


if __name__ == '__main__':
    read_pcap_scapy('PcabFiles/test.pcap')
