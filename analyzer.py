import os
import platform
import threading
import time
from plot import PlotNetworkTraffic
import argparse
from decimal import Decimal

from network_traffic import NetworkTraffic

blue_start = "\033[94m"
blue_end = "\033[0m"
red_start = "\033[91m"
red_end = "\033[0m"
green_start = "\033[92m"
green_end = "\033[0m"


def plot_menu(plot_dict):
    informational_message = "Select a plot to generate or 0 to exit program and CTRL+C to exit plot:"
    print(blue_start + informational_message + blue_end)
    plot_keys = list(plot_dict.keys())
    menu_lines = []
    items_per_line = 3

    max_length = max(len(plot) for plot in plot_keys) + 4

    for i in range(0, len(plot_keys), items_per_line):
        slice_end = min(i + items_per_line, len(plot_keys))
        line_items = [f"{i + 1}: {plot_keys[i]}".ljust(max_length) for i in range(i, slice_end)]
        line = "  ".join(line_items)
        menu_lines.append(line)
    print("\n".join(menu_lines))
    print(green_start + f"{len(plot_dict) + 1}: Show network traffic information" + green_end)
    print()
    print(red_start + "0: Exit".ljust(max_length) + red_end)
    choice = input("Enter choice: ")
    return choice


def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example script with command-line arguments')
    parser.add_argument('--interval', type=int, default=100, help="default is 100")
    parser.add_argument('--avg_window_size', type=int, default=100000, help="default is 100000")
    parser.add_argument('--min_burst_ratio', type=int, default=5, help="min burst ratio, default value is 5")
    parser.add_argument('--file', type=str, help="location to pcap file")
    parser.add_argument('--plots', nargs='+', type=str, default=[], help='List of plots to generate')
    parser.add_argument('--type', type=str, default="traffic_oriented")
    parser.add_argument('--heavy_rate_threshold', type=str, default=0)
    args = parser.parse_args()
    if not args.file:
        raise Exception("Please specify the file with --file")
    start_time = time.time()
    network_traffic = NetworkTraffic(pcap_file_location=args.file, interval=args.interval,
                                     avg_window_size=args.avg_window_size, min_burst_ratio=args.min_burst_ratio)
    flow_bursts = None
    count_of_bursty_flows = 0
    number_of_heavy_flows = 0
    if args.type == "flow_oriented":
        flow_bursts, count_of_bursty_flows, number_of_heavy_flows = network_traffic.flow_oriented_network_traffic_bursts(
            heavy_rate_threshold=Decimal(args.heavy_rate_threshold))
        network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic, bursts=flow_bursts)

    else:
        network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic)

    plot_dict = {
        "network_traffic": network_plot.plot_traffic_and_bursts,
        "bursts_duration_cdf": network_plot.plot_bursts_duration_cdf,
        "bursts_traffic_volume": network_plot.bursts_traffic_volume,
        "bursts_ratio_cdf": network_plot.plot_bursts_ratio_cdf,
        "bursts_packet_count_cdf": network_plot.plot_bursts_packet_count_cdf,
        "bursts_avg_packet_size_cdf": network_plot.plot_bursts_avg_packet_size_cdf,
        "inter_burst_duration_signal_cdf": network_plot.plot_inter_burst_duration_signal_cdf,
        "plot_bursts_flow_count_cdf": network_plot.plot_bursts_flow_count_cdf,
        "plot_bursts_in_each_flow_cdf": network_plot.plot_bursts_in_each_flow_cdf,
        "plot_cdf_flow_duration_all": network_plot.plot_cdf_flow_duration_all,
        "plot_cdf_flow_duration_heavy": network_plot.plot_cdf_flow_duration_heavy,
        "plot_cdf_flow_duration_bursty": network_plot.plot_cdf_flow_duration_bursty
    }
    error_message = ""

    while True:
        clear_screen()
        if error_message != "":
            print(red_start + error_message + red_end)
            error_message = ""
        if args.type == "flow_oriented":
            print(blue_start + "flow oriented mode" + blue_end)
        else:
            print(blue_start + "Traffic oriented mode" + blue_end)
        choice = plot_menu(plot_dict)
        if choice == '0':
            break
        elif int(choice) == len(plot_dict) + 1:
            clear_screen()
            print(
                f"Number of bursts: {len(flow_bursts) if args.type == 'flow_oriented' else len(network_traffic.bursts)}")
            print(f"Number of bursty flows: {count_of_bursty_flows}")
            print(f"Number of flows: {len(network_traffic.flow_event.flows)}")
            print(f"Number of heavy flows: {number_of_heavy_flows}")
            flows = network_traffic.heavy_flow_duration_dict.keys()
            print()
            print(blue_start + f"Heavy Flows" + blue_end)
            for flow in flows:
                print(f"{flow}: {network_traffic.heavy_flow_rate_dict[flow]}")
            input("\nPress Enter to return to the menu...")
            continue
        clear_screen()
        print(blue_start + "Enter CTRL+C to exit the plot" + blue_end)
        try:
            plot_key = list(plot_dict.keys())[int(choice) - 1]
            plot_dict[plot_key]()
        except (ValueError, IndexError):
            error_message = "Invalid selection, please try again."
        except KeyboardInterrupt:
            pass
        except Exception as ve:
            error_message = str(ve)
    for plot in args.plots:
        plot_dict[plot]()
