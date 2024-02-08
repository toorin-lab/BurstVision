import bisect
import time

import numpy
from scapy.all import *
from utils import progress_decorator
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


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
    def create_time_index(five_tuples):
        time_index = {}
        for five_tuple in five_tuples:
            timestamp = int(five_tuple.timestamp)
            if timestamp not in time_index:
                time_index[timestamp] = []
            time_index[timestamp].append(five_tuple)
        return time_index

    @staticmethod
    def get_five_tuples_in_time_range(time_index, start_time, end_time):
        timestamps = list(time_index.keys())
        start_idx = bisect.bisect_left(timestamps, int(start_time))
        end_idx = bisect.bisect_right(timestamps, int(end_time))
        valid_five_tuples = []
        for idx in range(start_idx, end_idx):
            timestamp = timestamps[idx]
            valid_five_tuples.extend(time_index[timestamp])
        return valid_five_tuples

        # valid_five_tuples = [event for event in five_tuples if start_time <= event.timestamp <= end_time]
        # return valid_five_tuples


class FlowEvent:
    def __init__(self, five_tuples):
        self.flows = []
        self.flows_index = {}
        for five_tuple in five_tuples:
            self.add_five_tuple(five_tuple)

    def add_five_tuple(self, five_tuple):
        src_ip, dst_ip, src_port, dst_port, proto = five_tuple.get_five_tuple()
        if src_port is None or dst_port is None:
            return
        flow = (src_ip, dst_ip, src_port, dst_port, proto)
        reverse_flow = (dst_ip, src_ip, dst_port, src_port, proto)
        if self.flows_index.get(flow) is None and self.flows_index.get(reverse_flow) is None:
            self.flows.append(five_tuple)
            self.flows_index[(src_ip, dst_ip, src_port, dst_port, proto)] = []


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
    def __init__(self, pcab_file_location, interval, avg_window_size, min_burst_ratio, packets=None):
        self.pcab_file_location = pcab_file_location
        self.index = {}
        self.print_status = True
        if packets is None:
            self.packets = []
            self._read_packets_with_progress(packets)
        else:
            self.packets = packets
            self.print_status = False
        self.interval = interval
        self.avg_window_size = avg_window_size
        self.traffic_rate_signal = self._get_traffic_rate_signal()
        self.avg_rate_signal = self._get_traffic_avg_rate_signal()
        self.min_burst_ratio = min_burst_ratio
        self.flow_event = FlowEvent([])
        self.five_tuples = self.extract_5_tuple()
        self.time_index = FiveTuple.create_time_index(self.five_tuples)
        # self.flow_event = FlowEvent(self.five_tuples)
        self.bursts = self._get_bursts()
        self.inter_burst_duration_signal = self._get_inter_burst_duration_signal()

    def flow_oriented_network_traffic_bursts(self):
        detected_bursts = []
        number_of_bursty_flows = 0
        for flow in self.index.keys():
            if len(self.index[flow]) == 1:
                continue
            flow_network_traffic = NetworkTraffic(pcab_file_location=self.pcab_file_location, interval=self.interval,
                                                  avg_window_size=self.avg_window_size,
                                                  min_burst_ratio=self.min_burst_ratio,
                                                  packets=self.index[flow])
            detected_bursts += flow_network_traffic.bursts
            if len(detected_bursts) >= 1:
                number_of_bursty_flows += 1
        return detected_bursts, number_of_bursty_flows

    def extract_5_tuple(self):
        all_five_tuples = []
        start = time.time()
        if self.print_status:

            print("\nExtracting 5 tuples", end="")
        for key, packets in self.index.items():
            src_ip, dst_ip, src_port, dst_port, proto = key
            for packet in packets:

                five_tuple = FiveTuple(src_ip, dst_ip, src_port, dst_port, proto, (packet.time - self.start_time) * 1e6)
                all_five_tuples.append(five_tuple)
                self.flow_event.add_five_tuple(five_tuple)
        if self.print_status:
            print(f"\rFinished Extracting 5 tuples : ({time.time() - start:.2f}s)")
        return all_five_tuples

    def _update_progress(self, current_count, total_count, progress_start_time):
        if total_count:
            progress = (current_count / total_count) * 100
            progress_end_time = time.time()
            return progress, progress_end_time
        else:
            if self.print_status:
                print("\rReading packets...", end='', flush=True)

    def _read_packets_with_progress(self, packets=None):
        total_file_size = os.path.getsize(self.pcab_file_location)
        processed_size = 0
        packet_count = 0
        start_time = time.time()
        progress = 0
        read_from_file = False
        if packets is None:
            read_from_file = True
            packets = PcapReader(self.pcab_file_location)
        for packet in packets:
            if read_from_file:
                self.packets.append(packet)
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                proto = packet[IP].proto
                key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)
                if key in self.index.keys() or reverse_key in self.index.keys():
                    if reverse_key in self.index.keys():
                        self.index[reverse_key].append(packet)
                    else:
                        self.index[key].append(packet)
                else:
                    self.index[key] = [packet]
            elif IPv6 in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                proto = packet[IPv6].nh
                key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)
                if key in self.index.keys() or reverse_key in self.index:
                    if reverse_key in self.index.keys():
                        self.index[reverse_key].append(packet)
                    else:
                        self.index[key].append(packet)
                else:
                    self.index[key] = [packet]
            packet_count += 1
            processed_size += packet.wirelen
            new_progress = (processed_size / total_file_size) * 100
            if new_progress - progress >= 1:
                progress = new_progress
                if self.print_status:
                    print(f"\rReading packets: {progress:.0f}% ({time.time() - start_time:.2f}s)", end='', flush=True)
        if read_from_file:
            packets.close()
        if self.print_status:
            print()
            print(f"number of packets {packet_count}")

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
        update_progress(1, self)
        df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
        df['Interval'] = (df['Elapsed'] // self.interval).astype(int)
        traffic_summary = df.groupby('Interval')['Size'].sum()

        update_progress(2, self)
        max_interval = int((end_time - start_time) * 1e6 // self.interval)
        all_intervals = pd.DataFrame({'Interval': range(max_interval + 1)})
        update_progress(3, self)
        traffic_summary = all_intervals.merge(traffic_summary, on='Interval', how='left')
        traffic_summary['Size'].fillna(0, inplace=True)

        # Convert rate from bytes/microsecond to bytes/second
        traffic_summary['Rate'] = (traffic_summary['Size'] / self.interval) * 1e6  # Multiply by 1,000,000
        traffic_summary['Count'] = df.groupby('Interval').size()
        traffic_summary['Count'].fillna(0, inplace=True)
        update_progress(4, self)
        return traffic_summary

    @progress_decorator(total_steps=1)
    def _get_traffic_avg_rate_signal(self, update_progress):
        kernel_size = self.avg_window_size // self.interval
        signal_length = len(self.traffic_rate_signal['Rate'])
        if signal_length < kernel_size:
            kernel_size = signal_length
        kernel = np.ones(kernel_size) / kernel_size
        averaged_traffic = np.convolve(kernel, self.traffic_rate_signal['Rate'], mode='same')
        update_progress(1, self)
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
        if len(traffic_rate_signal['Rate']) != len(avg_traffic_signal):
            # print(len(self.packets))
            # print(len(traffic_rate_signal['Rate']))

            # print(len(avg_traffic_signal))
            print(len(np.ones(self.avg_window_size // self.interval) / (self.avg_window_size // self.interval)))
            # print(avg_traffic_signal)
            exit(0)
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
        update_progress(1, self)
        bursts = self.get_continuous_bursts(bursts_points)
        for burst in bursts:
            five_tuples = FiveTuple.get_five_tuples_in_time_range(self.time_index, burst.timestamp,
                                                                  burst.timestamp + burst.interval)

            flow_event = FlowEvent(five_tuples)
            burst.number_of_flows = len(flow_event.flows)

        update_progress(2, self)
        return bursts

    def _get_inter_burst_duration_signal(self, bursts=None):
        if bursts is None:
            bursts = self.bursts
        inter_burst_duration = []
        for i in range(len(bursts) - 1):
            inter_burst_duration.append(
                bursts[i + 1].timestamp - bursts[i].timestamp + bursts[i].interval)
        return inter_burst_duration
