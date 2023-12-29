from scapy.all import *
from utils import progress_decorator
import pandas as pd
import numpy as np



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
        progress = 0
        with PcapReader(self.pcab_file_location) as pcap_reader:
            for packet in pcap_reader:
                if packet_count >= self.start_from_packet:
                    self.packets.append(packet)
                packet_count += 1
                processed_size += len(packet)
                new_progress = (processed_size / total_file_size) * 100
                if new_progress - progress >= 1:
                    progress = new_progress
                    print(f"\rReading packets: {progress:.2f}% ({now_time - start_time:.2f}s)", end='', flush=True)
                now_time = time.time()

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

        # Convert rate from bytes/microsecond to bytes/second
        traffic_summary['Rate'] = (traffic_summary['Size'] / self.interval) * 1e6  # Multiply by 1,000,000

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
