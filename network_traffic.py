import bisect
from scapy.all import *
from utils import progress_decorator
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import dask.dataframe as dd
import warnings
warnings.filterwarnings('ignore')


class CustomPacket:
    def __init__(self, timestamp, wirelen, src_ip, dst_ip, src_port, dst_port, proto):
        self.time = timestamp
        self.wirelen = wirelen
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto


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
    def __init__(self, timestamp, burst_ratio, interval=None, burst_total_traffic=None, count_of_packets=0,
                 real_timestamp=None):
        self.timestamp = timestamp
        self.burst_ratio = burst_ratio
        self.interval = interval
        self.burst_total_traffic = burst_total_traffic
        self.bursts_total_traffic = 0
        self.count_of_packets = count_of_packets
        self.avg_traffic = 0
        self.number_of_flows = 0
        self.real_timestamp = real_timestamp
        self.number_of_bursty_flows = 0

    def is_part_of_burst(self, packet):
        packet_time = packet.time
        burst_start_time = self.timestamp
        burst_end_time = burst_start_time + self.interval
        return burst_start_time <= packet_time <= burst_end_time

    def __repr__(self):
        return f"Burst(timestamp={self.timestamp}, burst_ratio={self.burst_ratio:.2f}, interval={self.interval}, " \
               f"burst_total_traffic={self.burst_total_traffic}, count_of_packets={self.count_of_packets}, avg_traffic={self.avg_traffic}))"


class NetworkTraffic:
    def __init__(self, pcap_file_location, interval, avg_window_size, burst_threshold, packets=None,
                 heavy_rate_threshold=0, reader_mode='pcap', csv_file_location=None, csv_output_mode=False):
        self.reader_mode = reader_mode
        self.pcap_file_location = pcap_file_location
        self.csv_output_mode = csv_output_mode
        self.index = {}
        self.print_status = True
        self.heavy_rate_threshold = heavy_rate_threshold
        self.duration = 0
        self.interval = interval
        self.five_tuple_count_per_interval = np.zeros(70_000_000, dtype=np.float64)
        self.new_five_tuples = np.zeros(70_000_000, dtype=np.float64)
        self.number_of_syn_packets = np.zeros(70_000_000, dtype=np.float64)
        self.number_of_tcp_packets = np.zeros(70_000_000, dtype=np.float64)
        self.number_of_udp_packets = np.zeros(70_000_000, dtype=np.float64)
        self.number_of_ip_addresses = np.zeros(70_000_000, dtype=np.float64)
        self.number_of_ports = np.zeros(70_000_000, dtype=np.float64)
        self.max_port_packet_count_per_interval = np.zeros(70_000_000, dtype=np.float64)
        self.max_ip_packet_count_per_interval = np.zeros(70_000_000, dtype=np.float64) 
        self.max_ip_flow_count_per_interval = np.zeros(70_000_000, dtype=np.float64) 
        self.max_port_flow_count_per_interval = np.zeros(70_000_000, dtype=np.float64) 
        self.five_tuple_lookup = {}
        if reader_mode == 'csv':
            df = dd.read_csv(csv_file_location)
            df = df.compute()
            packets = []
            for index, row in df.iterrows():
                packet = CustomPacket(row['timestamp'], row['packetlength'], row['srcip'], row['dstip'], row['srcport'],
                                      row['dstport'], row['ipprotocol'])
                packets.append(packet)
            self.packets = packets
            self._analyze_csv_packets()
        if packets is None:
            self.packets = []
            self._read_packets_with_progress(packets)
        else:
            self.is_heavy_flow = False
            self.packets = packets
            self.print_status = False
        self.avg_window_size = avg_window_size
        self.traffic_rate_signal = self._get_traffic_rate_signal()
        self.avg_rate_signal = self._get_traffic_avg_rate_signal()
        self.burst_threshold = burst_threshold
        if not self.csv_output_mode:
            self.flow_event = FlowEvent([])
            self.five_tuples = self.extract_5_tuple()
            self.time_index = FiveTuple.create_time_index(self.five_tuples)
        self.bursts = self._get_bursts()
        self.inter_burst_duration_signal = self._get_inter_burst_duration_signal()
        self.flow_burst_counter = {}
        self.flow_duration_dict = {}
        self.heavy_flow_duration_dict = {}
        self.heavy_flow_rate_dict = {}
        self.bursty_flow_duration_dict = {}

    def flow_oriented_network_traffic_bursts(self, heavy_rate_threshold=0, min_heavy_duration=2000):
        detected_bursts = []
        number_of_bursty_flows = 0
        number_of_heavy_flows = 0
        flows = []
        for flow in self.index.keys():
            flow_network_traffic = NetworkTraffic(pcap_file_location=self.pcap_file_location, interval=self.interval,
                                                  avg_window_size=self.avg_window_size,
                                                  burst_threshold=self.burst_threshold,
                                                  packets=self.index[flow], heavy_rate_threshold=heavy_rate_threshold)
            flows.append(flow_network_traffic)
            if flow_network_traffic.is_heavy_flow and flow_network_traffic.duration > min_heavy_duration / 1000:
                number_of_heavy_flows += 1
                self.heavy_flow_duration_dict[flow] = flow_network_traffic.duration
                self.heavy_flow_rate_dict[flow] = flow_network_traffic.avg_rate
            detected_bursts += flow_network_traffic.bursts
            self.flow_burst_counter[flow] = len(flow_network_traffic.bursts)
            self.flow_duration_dict[flow] = flow_network_traffic.duration
            if len(flow_network_traffic.bursts) >= 1:
                number_of_bursty_flows += 1
                self.bursty_flow_duration_dict[flow] = flow_network_traffic.duration

        for burst in self.bursts:
            burst_duration = [burst.real_timestamp, burst.interval + burst.real_timestamp]
            number_of_bursts_in_flows = 0
            for flow in flows:
                for flow_burst in flow.bursts:
                    if flow_burst.real_timestamp > burst_duration[1]:
                        break
                    if burst_duration[0] <= flow_burst.real_timestamp <= burst_duration[1] or \
                            burst_duration[0] <= flow_burst.real_timestamp + flow_burst.interval <= burst_duration[1]:
                        number_of_bursts_in_flows += 1
                        break
            burst.number_of_bursty_flows = number_of_bursts_in_flows
        return detected_bursts, number_of_bursty_flows, number_of_heavy_flows

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

    def _analyze_csv_packets(self):
        if self.reader_mode != 'csv':
            raise ValueError("Reader mode is not set to csv")
        for packet in self.packets:
            src_ip = packet.src_ip
            dst_ip = packet.dst_ip
            src_port = packet.src_port
            dst_port = packet.dst_port
            proto = packet.proto
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)
            if key in self.index.keys() or reverse_key in self.index:
                if reverse_key in self.index.keys():
                    self.index[reverse_key].append(packet)
                else:
                    self.index[key].append(packet)
            else:
                self.index[key] = [packet]

    def _create_index_for_five_tuples(self, packet):
        if not self.csv_output_mode:
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

    def _read_packets_with_progress(self, packets=None, start_from=16_000_000, number_of_packets=2_000_000):
        """Read PCAP file efficiently in binary mode"""
        if packets is not None:
            return self._process_provided_packets(packets)

        total_file_size = os.path.getsize(self.pcap_file_location)
        packet_count = 0
        start_time = time.time()
        
        GLOBAL_HEADER_SIZE = 24
        PACKET_HEADER_SIZE = 16
        ETH_HEADER_SIZE = 14  # Ethernet header size
        IP_HEADER_SIZE = 20   # Minimum IP header size
        TCP_HEADER_SIZE = 20  # Minimum TCP header size
        
        with open(self.pcap_file_location, 'rb') as f:
            # Read and verify magic number
            magic_num = int.from_bytes(f.read(4), 'little')
            byte_order = 'little'
            time_divisor = 1_000_000  # default microseconds 
            # Check magic number and format
            if magic_num == 0xa1b2c3d4:  # Little-endian
                pass
            elif magic_num == 0xd4c3b2a1:  # Big-endian
                byte_order = 'big'
            elif magic_num == 0xa1b23c4d:  # Little-endian nanosecond
                time_divisor = 1_000_000_000
            elif magic_num == 0x4d3cb2a1:  # Big-endian nanosecond
                byte_order = 'big'
                time_divisor = 1_000_000_000
            else:
                raise ValueError(f"Unknown PCAP format: {hex(magic_num)}")
            f.seek(GLOBAL_HEADER_SIZE)
            timestamps = []
            sizes = []
            counter = 0
            index = 0
            prev_interval = None
            packet_start_time = None
            current_flow_set = set()
            current_ip_set = set() # Keep track of unique IPs in the current interval
            current_port_set = set() # Keep track of unique Ports in the current interval
            current_ip_packet_counts = {} # Keep track of packet counts per IP in the current interval
            current_port_packet_counts = {} # Keep track of packet counts per Port in the current interval
            current_ip_to_flows = {} # Keep track of flows associated with each IP in the current interval
            current_port_to_flows = {}
            while index < number_of_packets if number_of_packets is not None else True:
                counter += 1
                header = f.read(PACKET_HEADER_SIZE)
                if len(header) < PACKET_HEADER_SIZE:
                    break
                ts_sec = int.from_bytes(header[0:4], byte_order)
                ts_usec = int.from_bytes(header[4:8], byte_order)
                timestamp = ts_sec + (ts_usec / time_divisor)
                caplen = int.from_bytes(header[8:12], byte_order)
                wirelen = int.from_bytes(header[12:16], byte_order)
                packet_data = f.read(caplen)
                if counter >= start_from:
                    # in here we should use packet_data to extract 5 tuple
                    if packet_start_time is None:
                        packet_start_time = timestamp
                    current_interval = (int((timestamp - packet_start_time) * 1e6) // self.interval)
                    try:
                        eth_header = packet_data[:ETH_HEADER_SIZE]
                        ip_header = packet_data[ETH_HEADER_SIZE:ETH_HEADER_SIZE+IP_HEADER_SIZE]
                        proto = ip_header[9]  # Protocol field in IP header
                        src_ip = ".".join(map(str, ip_header[12:16]))  # Source IP
                        dst_ip = ".".join(map(str, ip_header[16:20]))  # Destination IP
                        
                        if proto == 6 or proto == 17:  # TCP or UDP
                            transport_header = packet_data[ETH_HEADER_SIZE+IP_HEADER_SIZE:]
                            if proto == 6:
                                if len(transport_header) >= 14:  # Need at least 14 bytes for flags
                                    tcp_flags = transport_header[13]
                                    self.number_of_tcp_packets[current_interval] += 1
                                    syn_flag = (tcp_flags & 0x02) != 0  # SYN flag is bit 1 (0x02)
                                    if syn_flag:
                                        self.number_of_syn_packets[current_interval] += 1
                            else:
                                self.number_of_udp_packets[current_interval] += 1
                            src_port = int.from_bytes(transport_header[:2], 'big')
                            dst_port = int.from_bytes(transport_header[2:4], 'big')
                        else:
                            src_port = None
                            dst_port = None
                    except:
                        src_ip = None
                        dst_ip = None
                        src_port = None
                        dst_port = None
                        proto = None
                    
                    # Initialize sets and counts if first packet in interval or interval changes
                    if prev_interval is None or current_interval != prev_interval:
                        if prev_interval is not None:  # Only store if not first interval
                            self.five_tuple_count_per_interval[prev_interval] = len(current_flow_set)
                            self.number_of_ip_addresses[prev_interval] = len(current_ip_set)
                            self.number_of_ports[prev_interval] = len(current_port_set)

                            most_frequent_ip = None
                            max_ip_count = 0
                            # Calculate and store max IP packet count for the previous interval
                            if current_ip_packet_counts:
                                most_frequent_ip = max(current_ip_packet_counts, key=current_ip_packet_counts.get)
                                max_ip_count = current_ip_packet_counts[most_frequent_ip]
                                self.max_ip_packet_count_per_interval[prev_interval] = max_ip_count
                                # Store the number of flows for the most frequent IP
                                self.max_ip_flow_count_per_interval[prev_interval] = len(current_ip_to_flows.get(most_frequent_ip, set()))
                            else:
                                self.max_ip_packet_count_per_interval[prev_interval] = 0
                                self.max_ip_flow_count_per_interval[prev_interval] = 0

                            # Calculate and store max Port packet count for the previous interval
                            if current_port_packet_counts:
                                most_frequent_port = max(current_port_packet_counts, key=current_port_packet_counts.get)
                                max_port_count = current_port_packet_counts[most_frequent_port]
                                self.max_port_packet_count_per_interval[prev_interval] = max_port_count
                                # Store the number of flows for the most frequent port
                                self.max_port_flow_count_per_interval[prev_interval] = len(current_port_to_flows.get(most_frequent_port, set()))
                            else:
                                self.max_port_packet_count_per_interval[prev_interval] = 0
                                self.max_port_flow_count_per_interval[prev_interval] = 0

                        current_flow_set = set()
                        current_ip_set = set()
                        current_port_set = set()
                        current_ip_packet_counts = {}
                        current_port_packet_counts = {}
                        current_port_to_flows = {}
                        current_ip_to_flows = {}
                        prev_interval = current_interval

                    # Add IPs to the current interval's set and update counts
                    if src_ip is not None:
                        current_ip_set.add(src_ip)
                        current_ip_packet_counts[src_ip] = current_ip_packet_counts.get(src_ip, 0) + 1
                        
                        # Add ports to the current interval's set and update counts
                        if src_port is not None:
                            current_port_set.add(src_port)
                            current_port_packet_counts[src_port] = current_port_packet_counts.get(src_port, 0) + 1
                        
                        # Create flow tuple and update flows per IP
                        if dst_ip is not None and src_port is not None and dst_port is not None and proto is not None:
                            flow = (src_ip, dst_ip, src_port, dst_port, proto)
                            reverse_flow = (dst_ip, src_ip, dst_port, src_port, proto)
                            # Update flows for source IP
                            if src_ip not in current_ip_to_flows:
                                current_ip_to_flows[src_ip] = set()
                            if reverse_flow not in current_ip_to_flows[src_ip]:
                                current_ip_to_flows[src_ip].add(flow)
                            
                            # src port
                            if src_port not in current_port_to_flows:
                                current_port_to_flows[src_port] = set()
                            if reverse_flow not in current_port_to_flows[src_port]:
                                current_port_to_flows[src_port].add(flow)

                    # Also track destination IP and port
                    if dst_ip is not None:
                        current_ip_set.add(dst_ip)
                        current_ip_packet_counts[dst_ip] = current_ip_packet_counts.get(dst_ip, 0) + 1
                        
                        # Add destination port to counts
                        if dst_port is not None:
                            current_port_set.add(dst_port)
                            current_port_packet_counts[dst_port] = current_port_packet_counts.get(dst_port, 0) + 1
                            
                        # Update flows for destination IP
                        if dst_ip is not None and src_port is not None and dst_port is not None and proto is not None:
                            flow = (src_ip, dst_ip, src_port, dst_port, proto)
                            reverse_flow = (dst_ip, src_ip, dst_port, src_port, proto)
                            if dst_ip not in current_ip_to_flows:
                                current_ip_to_flows[dst_ip] = set()
                            if reverse_flow not in current_ip_to_flows[dst_ip]:
                                current_ip_to_flows[dst_ip].add(flow)

                            # dst port
                            if dst_port not in current_port_to_flows:
                                current_port_to_flows[dst_port] = set()
                            if reverse_flow not in current_port_to_flows[dst_port]:
                                current_port_to_flows[dst_port].add(flow)
                                
                    if dst_ip is not None:
                        current_ip_set.add(dst_ip)
                        current_ip_packet_counts[dst_ip] = current_ip_packet_counts.get(dst_ip, 0) + 1
                    
                    # Add Ports to the current interval's set
                    if src_port is not None:
                        current_port_set.add(src_port)
                    if dst_port is not None:
                        current_port_set.add(dst_port)

                    five_tuple = (src_ip, dst_ip, src_port, dst_port, proto)
                    reverse_five_tuple = (dst_ip, src_ip, dst_port, src_port, proto)
                    
                    # Only add valid five tuples (skip None values)
                    if None not in (src_ip, dst_ip, src_port, dst_port, proto):
                        if reverse_five_tuple not in current_flow_set: 
                            current_flow_set.add(five_tuple)
                        if self.five_tuple_lookup.get(five_tuple, None) is None:
                            self.new_five_tuples[current_interval] += 1
                            self.five_tuple_lookup[five_tuple] = index
                            self.five_tuple_lookup[reverse_five_tuple] = index

                    index += 1
                    timestamps.append(timestamp)
                    sizes.append(wirelen)
                
                packet_count += 1
                
                # Update progress
                if self.print_status and packet_count % 10000 == 0:
                    progress = (f.tell() / total_file_size) * 100
                    elapsed = time.time() - start_time
                    print(f"\rReading packets: {progress:.0f}% ({elapsed:.2f}s)", end='', flush=True)
        
        # Store counts for the very last interval after the loop finishes
        if prev_interval is not None:
            self.five_tuple_count_per_interval[prev_interval] = len(current_flow_set)
            self.number_of_ip_addresses[prev_interval] = len(current_ip_set)
            self.number_of_ports[prev_interval] = len(current_port_set) # Store Port count for the last interval
            
            most_frequent_ip = None
            max_ip_count = 0
            # Calculate and store max IP packet count for the last interval
            if current_ip_packet_counts:
                most_frequent_ip = max(current_ip_packet_counts, key=current_ip_packet_counts.get)
                max_ip_count = current_ip_packet_counts[most_frequent_ip]
                self.max_ip_packet_count_per_interval[prev_interval] = max_ip_count
            else:
                 self.max_ip_packet_count_per_interval[prev_interval] = 0
            # Calculate and store max Port packet count for the last interval
            if current_port_packet_counts:
                max_port_count = max(current_port_packet_counts.values())
                self.max_port_packet_count_per_interval[prev_interval] = max_port_count
            else:
                 self.max_port_packet_count_per_interval[prev_interval] = 0


        if self.print_status:
            print(f"\nProcessed {packet_count:,} packets")
        
        self.packets = [
            CustomPacket(
                timestamp=ts,
                wirelen=size,
                src_ip=None,    
                dst_ip=None,
                src_port=None,
                dst_port=None,
                proto=None
            )
            for ts, size in zip(timestamps, sizes)
        ]

    def _process_provided_packets(self, packets):
        """Handle pre-provided packets"""
        self.packets = []
        packet_count = 0
        start_time = time.time()
        
        for packet in packets:
            self.packets.append(packet)
            packet_count += 1
            
            if self.print_status and packet_count % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"\rProcessed {packet_count:,} packets ({elapsed:.2f}s)", end='', flush=True)
        
        if self.print_status:
            print(f"\nProcessed {packet_count:,} packets")

    @progress_decorator(total_steps=4)
    def _get_traffic_rate_signal(self, update_progress):
        if not self.packets:
            raise ValueError("No packets provided.")
        packet_sizes = np.array([packet.wirelen for packet in self.packets])
        timestamps = np.array([packet.time for packet in self.packets])
        start_time = timestamps.min()
        end_time = timestamps.max()
        if end_time - start_time == 0:
            self.avg_rate = 0
        else:
            self.avg_rate = sum(packet_sizes) / (end_time - start_time)
        if self.avg_rate >= self.heavy_rate_threshold:
            self.is_heavy_flow = True
        self.duration = end_time - start_time
        self.start_time = start_time
        end_time = timestamps.max()
        df = pd.DataFrame({
            'Size': packet_sizes,
            'Timestamp': timestamps
        })
        update_progress(1, self)
        
        # Sort timestamps and calculate durations between consecutive packets
        df = df.sort_values('Timestamp')
        df['duration'] = df['Timestamp'].diff() * 1e6  # Convert to microseconds
        
        df['Elapsed'] = (df['Timestamp'] - start_time) * 1e6
        df['Interval'] = (df['Elapsed'] // self.interval).astype(int)
        
        # Group by interval and get sum of durations
        duration_sum = df.groupby('Interval')['duration'].sum()
        traffic_summary = df.groupby('Interval')['Size'].sum()

        update_progress(2, self)
        max_interval = int((end_time - start_time) * 1e6 // self.interval)
        all_intervals = pd.DataFrame({'Interval': range(max_interval + 1)})
        update_progress(3, self)
        
        traffic_summary = all_intervals.merge(traffic_summary, on='Interval', how='left')
        traffic_summary['Size'].fillna(0, inplace=True)

        # Add count and duration information
        traffic_summary['Count'] = df.groupby('Interval').size()
        traffic_summary['Count'].fillna(0, inplace=True)
        traffic_summary['duration_sum'] = duration_sum
        traffic_summary['duration_sum'].fillna(0, inplace=True)
        
        # Calculate average duration between packets (handle edge cases)
        traffic_summary['avg_duration'] = traffic_summary.apply(
            lambda row: row['duration_sum'] / (row['Count'] - 1) if row['Count'] > 1 else 0,
            axis=1
        )

        # Convert rate from bytes/microsecond to bytes/second
        traffic_summary['Rate'] = (traffic_summary['Size'] / self.interval) * 1e6
        real_timestamps = all_intervals['Interval'] * self.interval + start_time * 1e6
        traffic_summary['Timestamp'] = real_timestamps
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
        is_burst = traffic_rate_signal['Rate'] - avg_traffic_signal > self.burst_threshold
        burst_traffic = self.traffic_rate_signal[is_burst]
        burst_traffic_total = burst_traffic.groupby('Interval')['Size'].sum().fillna(0)
        burst_avg = self.avg_rate_signal[is_burst]
        burst_ratio = np.where(burst_avg != 0, burst_traffic['Rate'] / burst_avg, np.inf)
        bursts_points = np.array(
            [Burst(time * self.interval, ratio, burst_total_traffic=total_traffic, count_of_packets=count,
                   real_timestamp=real_timestamp) for
             time, ratio, total_traffic, count, real_timestamp in
             zip(burst_traffic['Interval'], burst_ratio, burst_traffic_total, burst_traffic['Count'],
                 burst_traffic['Timestamp'])])
        return bursts_points

    @progress_decorator(total_steps=2)
    def _get_bursts(self, update_progress):
        bursts_points = self.get_burst_points()
        update_progress(1, self)
        bursts = self.get_continuous_bursts(bursts_points)
        if not self.csv_output_mode:
            for burst in bursts:
                five_tuples = FiveTuple.get_five_tuples_in_time_range(self.time_index, burst.timestamp,
                                                                    burst.timestamp + burst.interval)

                flow_event = FlowEvent(five_tuples)
                burst.number_of_flows = len(flow_event.flows)
        update_progress(2, self)
        return bursts

    def _get_inter_burst_duration_signal(self, bursts=None):
        if not self.csv_output_mode:
            if bursts is None:
                bursts = self.bursts
            else:
                bursts = sorted(bursts, key=lambda burst: burst.timestamp)
            inter_burst_duration = []
            for i in range(len(bursts) - 1):
                inter_burst_duration.append(
                    bursts[i + 1].timestamp - bursts[i].timestamp + bursts[i].interval)
            return inter_burst_duration
        return None
