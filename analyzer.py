from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt


def plot_traffic_rate(packets, interval=100):
    packet_sizes = [packet.wirelen for packet in packets]
    timestamps = [packet.time for packet in packets]
    start_time = timestamps[0]

    df = pd.DataFrame({
        'Size': packet_sizes,
        'Timestamp': timestamps
    })
    df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
    df['Interval'] = (df['Elapsed'] // interval).astype(int)
    traffic_summary = df.groupby('Interval')['Size'].sum()
    traffic_summary = traffic_summary.reset_index()
    plt.figure(figsize=(14, 7))
    plt.plot(traffic_summary['Interval'] * interval, traffic_summary['Size'], linewidth=1)
    plt.title('Sum of Bytes in Each n Microseconds Interval')
    plt.xlabel('Interval (n microseconds)')
    plt.ylabel('Sum of Bytes')
    plt.grid(True)
    plt.show()


def read_pcap_scapy(file_name):
    packets = rdpcap(file_name)

    for i, packet in enumerate(packets[:10]):
        # Get the packet's size
        packet_size = packet.wirelen
        # Get the packet's time, which is relative to the start of the capture
        packet_time = packet.time

        print(f"Packet {i + 1}: Size={packet_size}, Time={packet_time}")


if __name__ == '__main__':
    # read_pcap_scapy('PcabFiles/test.pcap')
    packets = rdpcap('PcabFiles/test.pcap')
    plot_traffic_rate(packets, interval=1000)
