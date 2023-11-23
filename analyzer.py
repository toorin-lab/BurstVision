from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


def get_traffic_rate_signal(packets, interval=100):
    if not packets:
        raise ValueError("No packets provided.")
    packet_sizes = [packet.wirelen for packet in packets]
    timestamps = [packet.time for packet in packets]
    start_time = min(timestamps)
    end_time = max(timestamps)
    df = pd.DataFrame({
        'Size': packet_sizes,
        'Timestamp': timestamps
    })
    df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
    df['Interval'] = (df['Elapsed'] // interval).astype(int)
    traffic_summary = df.groupby('Interval')['Size'].sum()
    max_interval = int((end_time - start_time) * 1e6 // interval)
    all_intervals = pd.DataFrame({'Interval': range(max_interval + 1)})
    traffic_summary = all_intervals.merge(traffic_summary, on='Interval', how='left')
    traffic_summary['Size'].fillna(0, inplace=True)

    return traffic_summary


def plot_traffic_rate(packets, interval=100):
    traffic_summary = get_traffic_rate_signal(packets, interval=interval)
    plt.figure(figsize=(14, 7))
    plt.plot(traffic_summary['Interval'] * interval, traffic_summary['Size'], linewidth=1)
    plt.title('Sum of Bytes in Each n Microseconds Interval')
    plt.xlabel('Interval (n microseconds)')
    plt.ylabel('Sum of Bytes')
    plt.grid(True)
    plt.show()


def plot_average_traffic_rate(packets, interval=50, avg_window_size=500):
    traffic_summary = get_traffic_rate_signal(packets, interval=interval)
    kernel = np.ones(avg_window_size // interval) / (avg_window_size // interval)
    averaged_traffic = np.convolve(kernel, traffic_summary['Size'], mode='same')
    plt.figure(figsize=(14, 7))
    plt.plot(traffic_summary['Interval'] * interval, traffic_summary['Size'], linewidth=1,
             label='Original Traffic Rate')
    plt.plot(traffic_summary['Interval'] * interval, averaged_traffic, linewidth=1, color='red',
             label='Averaged Traffic Rate')
    plt.title('Traffic Rate and Its Moving Average')
    plt.xlabel('Interval (n microseconds)')
    plt.ylabel('Traffic Rate')
    plt.grid(True)
    plt.legend()
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
    interval = 100000
    avg_window_size = 1000000
    plot_traffic_rate(packets, interval=interval)
    plot_average_traffic_rate(packets, interval=interval, avg_window_size=avg_window_size)
