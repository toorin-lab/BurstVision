from scapy.all import *
from utils import progress_decorator
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP


class FiveTuple:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.timestamp = timestamp

    def get_five_tuple(self):
        return self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto

    @staticmethod
    def get_five_tuples_in_time_range(five_tuples, start_time, end_time):
        valid_five_tuples = [event for event in five_tuples if start_time <= event.timestamp <= end_time]
        return valid_five_tuples


class FlowEvent:
    def __init__(self, five_tuples):
        self.flows = []
        for five_tuple in five_tuples:
            src_ip, dst_ip, src_port, dst_port, proto = five_tuple.get_five_tuple()
            if src_port is None or dst_port is None:
                return
            flow = (src_ip, dst_ip, src_port, dst_port, proto)
            reverse_flow = (dst_ip, src_ip, dst_port, src_port, proto)
            flows = [five_tuple.get_five_tuple() for five_tuple in self.flows]
            if flow not in flows and reverse_flow not in flows:
                self.flows.append(five_tuple)


class Burst:
    def __init__(self, timestamp, burst_ratio, interval=None, burst_total_traffic=None, count_of_packets=0):
        self.timestamp = timestamp
        self.burst_ratio = burst_ratio
        self.interval = interval
        self.burst_total_traffic = burst_total_traffic
        self.bursts_total_traffic = 0
        self.count_of_packets = count_of_packets
        self.avg_traffic = 0
        self.number_of_flows = 0

    def is_part_of_burst(self, packet):
        packet_time = packet.time
        burst_start_time = self.timestamp
        burst_end_time = burst_start_time + self.interval
        return burst_start_time <= packet_time <= burst_end_time

    def __repr__(self):
        return f"Burst(timestamp={self.timestamp}, burst_ratio={self.burst_ratio:.2f}, interval={self.interval}, " \
               f"burst_total_traffic={self.burst_total_traffic}, count_of_packets={self.count_of_packets}, avg_traffic={self.avg_traffic}))"


class NetworkTraffic:
    def __init__(self, pcab_file_location, interval, avg_window_size, min_burst_ratio):
        self.pcab_file_location = pcab_file_location
        self.packets = []
        self._read_packets_with_progress()
        self.interval = interval
        self.avg_window_size = avg_window_size
        self.traffic_rate_signal = self._get_traffic_rate_signal()
        self.avg_rate_signal = self._get_traffic_avg_rate_signal()
        self.min_burst_ratio = min_burst_ratio
        self.five_tuples = self.extract_5_tuple()
        self.flow_event = FlowEvent(self.five_tuples)
        self.bursts = self._get_bursts()
        self.inter_burst_duration_signal = self._get_inter_burst_duration_signal()

    def extract_5_tuple(self):
        tuples = []
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                else:
                    continue
                tuples.append(FiveTuple(src_ip, dst_ip, src_port, dst_port, proto, (packet.time - self.start_time) * 1e6))
        return tuples

    def _update_progress(self, current_count, total_count, progress_start_time):
        if total_count:
            progress = (current_count / total_count) * 100
            progress_end_time = time.time()
            return progress, progress_end_time
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
                self.packets.append(packet)
                packet_count += 1
                processed_size += len(packet)
                new_progress = (processed_size / total_file_size) * 100
                if new_progress - progress >= 10:
                    progress = new_progress
                    print(f"\rReading packets: {progress:.0f}% ({now_time - start_time:.2f}s)", end='', flush=True)
                now_time = time.time()

        print()  # Move to the next line after completion

    @progress_decorator(total_steps=4)
    def _get_traffic_rate_signal(self, update_progress):

        if not self.packets:
            raise ValueError("No packets provided.")
        packet_sizes = np.array([packet.wirelen for packet in self.packets])
        timestamps = np.array([packet.time for packet in self.packets])
        start_time = timestamps.min()
        self.start_time = start_time
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
        traffic_summary['Count'] = df.groupby('Interval').size()
        traffic_summary['Count'].fillna(0, inplace=True)
        update_progress(4)
        return traffic_summary

    @progress_decorator(total_steps=1)
    def _get_traffic_avg_rate_signal(self, update_progress):
        kernel = np.ones(self.avg_window_size // self.interval) / (self.avg_window_size // self.interval)
        averaged_traffic = np.convolve(kernel, self.traffic_rate_signal['Rate'], mode='same')
        update_progress(1)
        return averaged_traffic

    def get_continuous_bursts(self, burst_points):
        bursts = []
        current_burst = None
        sum_of_burt_ratio = 0
        total_current_burst_count = 0
        sum_of_timestamps = 0
        prev_timestamp = 0
        count_of_packets = 0
        for i in range(len(burst_points)):
            bursts_point = burst_points[i]
            if current_burst is None:
                current_burst = bursts_point
                sum_of_burt_ratio = bursts_point.burst_ratio
                sum_of_timestamps = bursts_point.timestamp
                count_of_packets = bursts_point.count_of_packets
                total_current_burst_count = 1

                current_burst.count_of_packets = count_of_packets
                current_burst.interval = total_current_burst_count * self.interval
                current_burst.bursts_total_traffic += bursts_point.burst_total_traffic

            elif bursts_point.timestamp - prev_timestamp <= self.interval:
                sum_of_timestamps += bursts_point.timestamp
                sum_of_burt_ratio += bursts_point.burst_ratio
                count_of_packets += bursts_point.count_of_packets
                total_current_burst_count += 1
                current_burst.bursts_total_traffic += bursts_point.burst_total_traffic
                current_burst.burst_ratio = sum_of_burt_ratio / total_current_burst_count
                current_burst.timestamp = sum_of_timestamps / total_current_burst_count
                current_burst.count_of_packets = count_of_packets
                current_burst.interval = total_current_burst_count * self.interval
            else:
                current_burst.interval = total_current_burst_count * self.interval
                bursts.append(current_burst)
                ############################
                current_burst = bursts_point
                sum_of_timestamps = bursts_point.timestamp
                sum_of_burt_ratio = bursts_point.burst_ratio
                count_of_packets = bursts_point.count_of_packets
                current_burst.interval = total_current_burst_count * self.interval
                current_burst.count_of_packets = count_of_packets
                current_burst.bursts_total_traffic += bursts_point.burst_total_traffic

                total_current_burst_count = 1
            current_burst.avg_traffic = current_burst.bursts_total_traffic / current_burst.count_of_packets
            prev_timestamp = bursts_point.timestamp
            if i == len(burst_points) - 1:
                bursts.append(current_burst)
                break

        return bursts

    def get_burst_points(self):
        traffic_rate_signal = self.traffic_rate_signal
        avg_traffic_signal = self.avg_rate_signal
        is_burst = traffic_rate_signal['Rate'] > (self.min_burst_ratio * avg_traffic_signal)
        burst_traffic = self.traffic_rate_signal[is_burst]
        burst_traffic_total = burst_traffic.groupby('Interval')['Size'].sum().fillna(0)

        burst_avg = self.avg_rate_signal[is_burst]
        burst_ratio = np.where(burst_avg != 0, burst_traffic['Rate'] / burst_avg, np.inf)
        bursts_points = np.array(
            [Burst(time * self.interval, ratio, burst_total_traffic=total_traffic, count_of_packets=count) for
             time, ratio, total_traffic, count in
             zip(burst_traffic['Interval'], burst_ratio, burst_traffic_total, burst_traffic['Count'])])
        return bursts_points

    @progress_decorator(total_steps=2)
    def _get_bursts(self, update_progress):
        bursts_points = self.get_burst_points()
        update_progress(1)
        bursts = self.get_continuous_bursts(bursts_points)
        for burst in bursts:
            five_tuples = FiveTuple.get_five_tuples_in_time_range(self.five_tuples, burst.timestamp,
                                                                  burst.timestamp + burst.interval)

            flow_event = FlowEvent(five_tuples)
            burst.number_of_flows = len(flow_event.flows)

        update_progress(2)
        return bursts

    def _get_inter_burst_duration_signal(self):
        inter_burst_duration = []
        for i in range(len(self.bursts) - 1):
            inter_burst_duration.append(
                self.bursts[i + 1].timestamp - self.bursts[i].timestamp + self.bursts[i].interval)
        return inter_burst_duration
