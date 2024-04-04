import numpy as np
import matplotlib.pyplot as plt
from network_traffic import NetworkTraffic
from utils import progress_decorator


class PlotNetworkTraffic:
    def __init__(self, network_traffic_object: NetworkTraffic, bursts=None):
        self.network_traffic = network_traffic_object
        if bursts is not None:
            self.flow_oriented_plot = True
            self.bursts = bursts
        else:
            self.flow_oriented_plot = False

    @progress_decorator(total_steps=1)
    def plot_traffic_rate(self, update_progress):
        traffic_summary = self.network_traffic.traffic_rate_signal
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
        plt.plot(traffic_summary['Interval'] * self.network_traffic.interval, traffic_summary['Rate'], linewidth=1,
                 label='Original Traffic Rate')
        update_progress(1)
        plt.plot(traffic_summary['Interval'] * self.network_traffic.interval, averaged_traffic, linewidth=1,
                 color='red',
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

        plt.xlabel('Time (microseconds)')
        plt.ylabel('Traffic Rate (Bytes / second)')
        plt.title('Traffic rate')
        plt.legend()
        plt.grid(True)
        plt.show()
        update_progress(5)

    @staticmethod
    def plot_cdf(function_outputs, function_name: str, function_atr: str, title: str):
        sorted_outputs = np.sort(function_outputs)
        cumulative_probabilities = np.arange(1, len(sorted_outputs) + 1) / len(sorted_outputs)
        plt.figure(figsize=(10, 6))
        plt.step(sorted_outputs, cumulative_probabilities, where='post')
        plt.title(title)
        plt.xlabel(f'{function_atr}')
        plt.ylabel('CDF')
        plt.grid(True)
        plt.legend()
        plt.show()

    def plot_bursts_duration_cdf(self):
        if self.flow_oriented_plot:
            bursts = self.bursts
        else:
            bursts = self.network_traffic.bursts

        burst_timestamps = [burst.interval for burst in bursts]
        self.plot_cdf(burst_timestamps, 'Burst', 'Length (microseconds)', 'Length of microbursts')

    def bursts_traffic_volume(self):
        if self.flow_oriented_plot:
            bursts = self.bursts
        else:
            bursts = self.network_traffic.bursts
        burst_sizes = [burst.bursts_total_traffic for burst in bursts]
        self.plot_cdf(burst_sizes, 'Burst', 'Traffic volume (bytes)', title="Traffic volume of microbursts")

    def plot_bursts_ratio_cdf(self):
        if self.flow_oriented_plot:
            bursts = self.bursts
        else:
            bursts = self.network_traffic.bursts
        burst_ratios = [burst.burst_ratio for burst in bursts]
        self.plot_cdf(burst_ratios, 'Burst', 'Burst ratio', title="Burst ratio of microbursts")

    def plot_bursts_packet_count_cdf(self):
        if self.flow_oriented_plot:
            bursts = self.bursts
        else:
            bursts = self.network_traffic.bursts
        burst_count = [burst.count_of_packets for burst in bursts]
        self.plot_cdf(burst_count, 'Burst', 'Number of packets', title="Number of packets in microbursts")

    def plot_bursts_avg_packet_size_cdf(self):
        if self.flow_oriented_plot:
            bursts = self.bursts
        else:
            bursts = self.network_traffic.bursts
        burst_avg_traffic = [burst.avg_traffic for burst in bursts]
        self.plot_cdf(burst_avg_traffic, 'Burst', 'Average packet size (bytes)',
                      title="Average packet size of microbursts")

    def plot_inter_burst_duration_signal_cdf(self):
        if self.flow_oriented_plot:
            inter_burst_duration_signal = self.network_traffic._get_inter_burst_duration_signal(bursts=self.bursts)
        else:
            inter_burst_duration_signal = self.network_traffic.inter_burst_duration_signal
        self.plot_cdf(inter_burst_duration_signal, 'Burst', 'Interval (microseconds)',
                      title="Inter-burst interval")

    def plot_bursts_flow_count_cdf(self):
        if self.flow_oriented_plot:
            raise Exception("This plot only works on traffic oriented mode")
        else:
            bursts = self.network_traffic.bursts
        burst_flow_counts = [burst.number_of_flows for burst in bursts]
        self.plot_cdf(burst_flow_counts, 'Burst', 'Number of Flows',
                      title="Number of flows in microbursts")

    def plot_bursts_in_each_flow_cdf(self):
        if not self.flow_oriented_plot:
            raise Exception("This plot only works on flow oriented mode")
        flow_burst_count = [self.network_traffic.flow_burst_counter[flow] for flow in
                            self.network_traffic.flow_burst_counter.keys()]

        self.plot_cdf(flow_burst_count, 'Burst', 'Number of microbursts',
                      title="Number of microbursts in each flow")

    def plot_cdf_flow_duration_all(self):
        if not self.flow_oriented_plot:
            raise Exception("This plot only works on flow oriented mode")
        flow_burst_count = [self.network_traffic.flow_duration_dict[flow] for flow in
                            self.network_traffic.flow_duration_dict.keys()]

        self.plot_cdf(flow_burst_count, 'Burst', 'Duration (microseconds)',
                      title="Duration of flows")

    def plot_cdf_flow_duration_heavy(self):
        if not self.flow_oriented_plot:
            raise Exception("This plot only works on flow oriented mode")
        flow_burst_count = [self.network_traffic.heavy_flow_duration_dict[flow] for flow in
                            self.network_traffic.heavy_flow_duration_dict.keys()]

        self.plot_cdf(flow_burst_count, 'Burst', 'Duration (microseconds)',
                      title="Duration of heavy flows")

    def plot_cdf_flow_duration_bursty(self):
        if not self.flow_oriented_plot:
            raise Exception("This plot only works on flow oriented mode")
        flow_burst_count = [self.network_traffic.bursty_flow_duration_dict[flow] for flow in
                            self.network_traffic.bursty_flow_duration_dict.keys()]

        self.plot_cdf(flow_burst_count, 'Burst', 'Duration (microseconds)',
                      title="Duration of bursty flows")

    def plot_cdf_number_of_concurrent_bursty_flows(self):
        if not self.flow_oriented_plot:
            raise Exception("This plot only works on flow oriented mode")
        flow_burst_count = [burst.number_of_bursty_flows for burst in
                            self.network_traffic.bursts]
        self.plot_cdf(flow_burst_count, 'Burst', 'Number of concurrent bursty flows',
                      title="Number of concurrent bursty flows at each microburst")


