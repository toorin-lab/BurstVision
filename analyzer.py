from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


class Burst:
    def __init__(self, timestamp, burst_ratio):
        self.timestamp = timestamp
        self.burst_ratio = burst_ratio

    def __repr__(self):
        return f"Burst(timestamp={self.timestamp}, burst_ratio={self.burst_ratio:.2f})"


class NetworkTraffic:
    def __init__(self, pcab_file_location, interval, avg_window_size, min_burst_ratio):
        self.pcab_file_location = pcab_file_location
        self.packets = rdpcap(pcab_file_location)
        self.interval = interval
        self.avg_window_size = avg_window_size
        self.traffic_rate_signal = self._get_traffic_rate_signal()
        self.avg_rate_signal = self._get_traffic_avg_rate_signal()
        self.min_burst_ratio = min_burst_ratio
        self.bursts = self._get_bursts()

    def _get_traffic_rate_signal(self):
        if not self.packets:
            raise ValueError("No packets provided.")
        packet_sizes = [packet.wirelen for packet in self.packets]
        timestamps = [packet.time for packet in self.packets]
        start_time = min(timestamps)
        end_time = max(timestamps)
        df = pd.DataFrame({
            'Size': packet_sizes,
            'Timestamp': timestamps
        })
        df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
        df['Interval'] = (df['Elapsed'] // self.interval).astype(int)
        traffic_summary = df.groupby('Interval')['Size'].sum()
        max_interval = int((end_time - start_time) * 1e6 // self.interval)
        all_intervals = pd.DataFrame({'Interval': range(max_interval + 1)})
        traffic_summary = all_intervals.merge(traffic_summary, on='Interval', how='left')
        traffic_summary['Size'].fillna(0, inplace=True)

        return traffic_summary

    def _get_traffic_avg_rate_signal(self):
        kernel = np.ones(self.avg_window_size // self.interval) / (self.avg_window_size // self.interval)
        averaged_traffic = np.convolve(kernel, self.traffic_rate_signal['Size'], mode='same')
        return averaged_traffic

    def _get_bursts(self):
        traffic_rate_signal = self.traffic_rate_signal
        avg_traffic_signal = self.avg_rate_signal
        is_burst = traffic_rate_signal['Size'] > (self.min_burst_ratio * avg_traffic_signal)
        bursts = []
        for i in traffic_rate_signal.index[is_burst]:
            signal_time = traffic_rate_signal['Interval'][i]
            burst_ratio = traffic_rate_signal['Size'][i] / avg_traffic_signal[i] if avg_traffic_signal[
                                                                                        i] != 0 else np.inf
            bursts.append(Burst(signal_time * self.interval, burst_ratio))

        return bursts


class PlotNetworkTraffic:
    def __init__(self, network_traffic: NetworkTraffic):
        self.network_traffic = network_traffic

    def plot_traffic_rate(self):
        traffic_summary = network_traffic.traffic_rate_signal
        plt.figure(figsize=(14, 7))
        plt.plot(traffic_summary['Interval'] * self.network_traffic.interval, traffic_summary['Size'], linewidth=1)
        plt.title('Sum of Bytes in Each n Microseconds Interval')
        plt.xlabel('Interval (n microseconds)')
        plt.ylabel('Sum of Bytes')
        plt.grid(True)
        plt.show()

    def plot_average_traffic_rate(self):
        traffic_summary = self.network_traffic.traffic_rate_signal
        kernel = np.ones(self.network_traffic.avg_window_size // self.network_traffic.interval) / (
                self.network_traffic.avg_window_size // self.network_traffic.interval)
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

    def plot_traffic_and_bursts(self):
        plt.figure(figsize=(12, 6))

        plt.plot(self.network_traffic.traffic_rate_signal['Interval'] * interval,
                 self.network_traffic.traffic_rate_signal['Size'], label='Traffic Rate')
        plt.plot(self.network_traffic.traffic_rate_signal['Interval'] * interval, self.network_traffic.avg_rate_signal,
                 label='Average Traffic Rate',
                 alpha=0.7)

        for burst in self.network_traffic.bursts:
            plt.scatter(burst.timestamp, self.network_traffic.traffic_rate_signal['Size'][burst.timestamp / interval],
                        color='red')
            plt.text(burst.timestamp, self.network_traffic.traffic_rate_signal['Size'][burst.timestamp / interval],
                     f"{burst.burst_ratio:.2f}",
                     color='red')

        plt.xlabel('Time Interval')
        plt.ylabel('Traffic Size')
        plt.title('Network Traffic Rate with Bursts')
        plt.legend()
        plt.grid(True)
        plt.show()


def read_pcap_scapy(file_name):
    packets = rdpcap(file_name)
    for i, packet in enumerate(packets[:10]):
        packet_size = packet.wirelen
        packet_time = packet.time
        print(f"Packet {i + 1}: Size={packet_size}, Time={packet_time}")


if __name__ == '__main__':
    interval = 100000
    avg_window_size = 1000000
    network_traffic = NetworkTraffic(pcab_file_location='PcabFiles/test2.pcap', interval=interval,
                                     avg_window_size=avg_window_size, min_burst_ratio=5)
    network_plot = PlotNetworkTraffic(network_traffic=network_traffic)
    # print(network_traffic.traffic_rate_signal)
    # network_plot.plot_average_traffic_rate()
    print(len(network_traffic.bursts))
    network_plot.plot_traffic_and_bursts()
