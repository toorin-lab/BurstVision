import time
from plot import PlotNetworkTraffic
import argparse

from network_traffic import NetworkTraffic

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example script with command-line arguments')
    parser.add_argument('--interval', type=int, default=1000, help="default is 100")
    parser.add_argument('--avg_window_size', type=int, default=100000, help="default is 100000")
    parser.add_argument('--min_burst_ratio', type=int, default=5, help="min burst ratio, default value is 5")
    parser.add_argument('--file', type=str, help="location to pcab file")
    parser.add_argument('--plots', nargs='+', type=str, default=[], help='List of plots to generate')
    args = parser.parse_args()
    if not args.file:
        raise Exception("Please specify the file with --file")
    start_time = time.time()
    network_traffic = NetworkTraffic(pcab_file_location=args.file, interval=args.interval,
                                     avg_window_size=args.avg_window_size, min_burst_ratio=args.min_burst_ratio)
    network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic)
    plot_dict = {
        "network_traffic": network_plot.plot_traffic_and_bursts,
        "bursts_duration_cdf": network_plot.plot_bursts_duration_cdf,
        "bursts_traffic_volume": network_plot.bursts_traffic_volume,
        "bursts_ratio_cdf": network_plot.plot_bursts_ratio_cdf,
        "bursts_packet_count_cdf": network_plot.plot_bursts_packet_count_cdf,
        "bursts_avg_packet_size_cdf": network_plot.plot_bursts_avg_packet_size_cdf,
        "inter_burst_duration_signal_cdf": network_plot.plot_inter_burst_duration_signal_cdf,
        "plot_bursts_flow_count_cdf": network_plot.plot_bursts_flow_count_cdf
    }
    print(f"Number of bursts: {len(network_traffic.bursts)}")
    print(f"Number of flows: {len(network_traffic.flow_event.flows)}")
    for plot in args.plots:
        plot_dict[plot]()

