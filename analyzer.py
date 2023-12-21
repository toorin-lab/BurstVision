import time
from functools import wraps

from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


def progress_decorator(total_steps):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            function_start_time = time.time()

            def update_progress(current_step):
                function_now_time = time.time()
                progress_percent = (current_step / total_steps) * 100
                print(
                    f"\r{func.__name__} Progress: {progress_percent:.2f}% ({function_now_time - function_start_time:.2f}s)",
                    end='', flush=True)

            kwargs['update_progress'] = update_progress
            result = func(*args, **kwargs)
            print()  # Move to the next line after function completion
            return result

        return wrapper

    return decorator


def print_progress(current, total, start_time, message="Processing"):
    progress_percent = (current / total) * 100
    now_time = time.time()
    print(f"\r{message}: {progress_percent:.2f}% ({now_time - start_time:.2f}s)", end='', flush=True)


class Burst:
    def __init__(self, timestamp, burst_ratio):
        self.timestamp = timestamp
        self.burst_ratio = burst_ratio

    def __repr__(self):
        return f"Burst(timestamp={self.timestamp}, burst_ratio={self.burst_ratio:.2f})"


class NetworkTraffic:
    def __init__(self, pcab_file_location, interval, avg_window_size, min_burst_ratio, start_from_packet=0,
                 end_at_packet=None):
        self.pcab_file_location = pcab_file_location
        self.start_from_packet = start_from_packet
        self.end_at_packet = end_at_packet
        self.packets = []
        self._read_packets_based_on_count()
        self.interval = interval
        self.avg_window_size = avg_window_size
        self.traffic_rate_signal = self._get_traffic_rate_signal()
        self.avg_rate_signal = self._get_traffic_avg_rate_signal()
        self.min_burst_ratio = min_burst_ratio
        self.bursts = self._get_bursts()

    def _read_packets_based_on_count(self):
        if self.end_at_packet is None:
            self._read_packets_with_progress()
            return
        packet_count = 0
        progress_start_time = time.time()
        with PcapReader(self.pcab_file_location) as pcap_reader:
            for packet in pcap_reader:
                if packet_count >= self.start_from_packet:
                    if self.end_at_packet is not None and packet_count > self.end_at_packet:
                        break

                    self.packets.append(packet)
                self._update_progress(packet_count,
                                      self.end_at_packet,
                                      progress_start_time=progress_start_time)

                packet_count += 1

        print()  # Ensuring new line after progress bar

    def _update_progress(self, current_count, total_count, progress_start_time):
        if total_count:
            progress = (current_count / total_count) * 100
            progress_end_time = time.time()
            print(f"\rReading packets: {progress:.2f}% ({progress_end_time - progress_start_time:.2f}s)", end='',
                  flush=True)
        else:
            print("\rReading packets...", end='', flush=True)

    def _read_packets_with_progress(self):
        total_file_size = os.path.getsize(self.pcab_file_location)
        processed_size = 0

        packet_count = 0
        start_time = time.time()
        with PcapReader(self.pcab_file_location) as pcap_reader:
            for packet in pcap_reader:
                if packet_count >= self.start_from_packet:
                    self.packets.append(packet)
                packet_count += 1
                processed_size += len(packet)
                progress = (processed_size / total_file_size) * 100
                now_time = time.time()
                print(f"\rReading packets: {progress:.2f}% ({now_time - start_time:.2f}s)", end='', flush=True)
        print()  # Move to the next line after completion

    @progress_decorator(total_steps=4)
    def _get_traffic_rate_signal(self, update_progress):

        if not self.packets:
            raise ValueError("No packets provided.")
        packet_sizes = np.array([packet.wirelen for packet in self.packets])
        timestamps = np.array([packet.time for packet in self.packets])
        start_time = timestamps.min()
        end_time = timestamps.max()
        df = pd.DataFrame({
            'Size': packet_sizes,
            'Timestamp': timestamps
        })
        update_progress(1)
        df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
        df['Interval'] = (df['Elapsed'] // self.interval).astype(int)
        traffic_summary = df.groupby('Interval')['Size'].sum()
        update_progress(2)
        max_interval = int((end_time - start_time) * 1e6 // self.interval)
        all_intervals = pd.DataFrame({'Interval': range(max_interval + 1)})
        update_progress(3)
        traffic_summary = all_intervals.merge(traffic_summary, on='Interval', how='left')
        traffic_summary['Size'].fillna(0, inplace=True)
        traffic_summary['Rate'] = traffic_summary['Size'] / self.interval
        update_progress(4)
        return traffic_summary

    @progress_decorator(total_steps=1)
    def _get_traffic_avg_rate_signal(self, update_progress):
        kernel = np.ones(self.avg_window_size // self.interval) / (self.avg_window_size // self.interval)
        averaged_traffic = np.convolve(kernel, self.traffic_rate_signal['Rate'], mode='same')
        update_progress(1)
        return averaged_traffic

    @progress_decorator(total_steps=2)
    def _get_bursts(self, update_progress):
        traffic_rate_signal = self.traffic_rate_signal
        avg_traffic_signal = self.avg_rate_signal
        is_burst = traffic_rate_signal['Rate'] > (self.min_burst_ratio * avg_traffic_signal)
        burst_traffic = self.traffic_rate_signal[is_burst]
        burst_avg = self.avg_rate_signal[is_burst]
        update_progress(1)
        burst_ratio = np.where(burst_avg != 0, burst_traffic['Rate'] / burst_avg, np.inf)
        bursts = np.array(
            [Burst(time * self.interval, ratio) for time, ratio in zip(burst_traffic['Interval'], burst_ratio)])
        update_progress(2)
        return bursts


class PlotNetworkTraffic:
    def __init__(self, network_traffic: NetworkTraffic):
        self.network_traffic = network_traffic

    @progress_decorator(total_steps=1)
    def plot_traffic_rate(self, update_progress):
        traffic_summary = network_traffic.traffic_rate_signal
        plt.figure(figsize=(14, 7))
        plt.plot(traffic_summary['Interval'] * self.network_traffic.interval, traffic_summary['Rate'], linewidth=1)
        plt.title('Rate in Each n Microseconds Interval')
        plt.xlabel('Interval (n microseconds)')
        plt.ylabel('Sum of Bytes')
        plt.grid(True)
        plt.show()
        update_progress(1)

    @progress_decorator(total_steps=2)
    def plot_average_traffic_rate(self, update_progress):
        traffic_summary = self.network_traffic.traffic_rate_signal
        kernel = np.ones(self.network_traffic.avg_window_size // self.network_traffic.interval) / (
                self.network_traffic.avg_window_size // self.network_traffic.interval)
        averaged_traffic = np.convolve(kernel, traffic_summary['Rate'], mode='same')
        plt.figure(figsize=(14, 7))
        plt.plot(traffic_summary['Interval'] * interval, traffic_summary['Rate'], linewidth=1,
                 label='Original Traffic Rate')
        update_progress(1)
        plt.plot(traffic_summary['Interval'] * interval, averaged_traffic, linewidth=1, color='red',
                 label='Averaged Traffic Rate')
        plt.title('Traffic Rate and Its Moving Average')
        plt.xlabel('Interval (n microseconds)')
        plt.ylabel('Traffic Rate')
        plt.grid(True)
        plt.legend()
        plt.show()
        update_progress(2)

    @progress_decorator(total_steps=5)
    def plot_traffic_and_bursts(self, update_progress):
        # Extract burst timestamps and sizes
        burst_timestamps = np.array([burst.timestamp for burst in self.network_traffic.bursts])
        burst_sizes = np.array(
            [self.network_traffic.traffic_rate_signal['Rate'][burst.timestamp // self.network_traffic.interval] for
             burst in self.network_traffic.bursts])

        update_progress(1)

        plt.figure(figsize=(12, 6))

        # Plot traffic rate
        plt.plot(self.network_traffic.traffic_rate_signal['Interval'] * self.network_traffic.interval,
                 self.network_traffic.traffic_rate_signal['Rate'], label='Traffic Rate', alpha=0.7)
        update_progress(2)

        # Plot average traffic rate
        plt.plot(self.network_traffic.traffic_rate_signal['Interval'] * self.network_traffic.interval,
                 self.network_traffic.avg_rate_signal, label='Average Traffic Rate', color='green', alpha=0.7)
        update_progress(3)

        # Plot bursts
        plt.scatter(burst_timestamps, burst_sizes, color='red', label='Bursts')
        update_progress(4)

        plt.xlabel('Time Interval')
        plt.ylabel('Traffic Size')
        plt.title('Network Traffic Rate with Bursts')
        plt.legend()
        plt.grid(True)
        plt.show()
        update_progress(5)


def read_pcap_scapy(file_name):
    packets = rdpcap(file_name)
    for i, packet in enumerate(packets[:10]):
        packet_size = packet.wirelen
        packet_time = packet.time
        print(f"Packet {i + 1}: Size={packet_size}, Time={packet_time}")


if __name__ == '__main__':
    start_time = time.time()
    interval = 1000
    avg_window_size = 1000000
    network_traffic = NetworkTraffic(pcab_file_location='PcabFiles/traffic.pcapng', interval=interval,
                                     avg_window_size=avg_window_size, min_burst_ratio=5, start_from_packet=0,
                                     end_at_packet=10000)
    network_plot = PlotNetworkTraffic(network_traffic=network_traffic)
    network_plot.plot_traffic_and_bursts()
    end_time = time.time()
    print(f"total execution time : {end_time - start_time}")
