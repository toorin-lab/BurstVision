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
    items_per_line = 2

    max_length = max(len(plot) for plot in plot_keys) + 4

    for i in range(0, len(plot_keys), items_per_line):
        slice_end = min(i + items_per_line, len(plot_keys))
        line_items = [f"{i + 1}: {plot_keys[i]}".ljust(max_length) for i in range(i, slice_end)]
        line = " ".join(line_items)
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
    parser.add_argument('-r', type=int, default=100, help="processing resolution (microseconds)")
    parser.add_argument('-a', type=int, default=100000, help="average window size (microseconds)")
    parser.add_argument('-b', type=int, default=5, help="minimum burst ratio (default: 5)")
    parser.add_argument('-f', type=str, help="pcap file (with microsecond time resolution)")
    parser.add_argument('-i', type=str, help="input type (choices: pcap, csv, default: pcap)")
    parser.add_argument('-m', type=str, help="processing mode:  traffic_oriented(default) or flow_oriented")
    parser.add_argument('-ht', type=str, default=0, help="rate threshold for heavy flows (bytes/second)")
    parser.add_argument('-md', type=str, default=100, help="minimum duration of heavy flows (miliseconds, default:100)")

    args = parser.parse_args()
    translated_args = argparse.Namespace()
    translated_args.interval = args.r
    translated_args.avg_window_size = args.a
    translated_args.min_burst_ratio = args.b
    translated_args.file = args.f
    translated_args.type = args.m
    translated_args.heavy_rate_threshold = args.ht
    translated_args.min_heavy_duration = args.md
    translated_args.input_type = args.i
    args = translated_args
    if not args.file:
        raise Exception("Please specify the file with --file")
    start_time = time.time()
    network_traffic = NetworkTraffic(pcap_file_location=args.file, interval=args.interval,
                                     avg_window_size=args.avg_window_size, min_burst_ratio=args.min_burst_ratio,
                                     reader_mode=args.input_type, csv_file_location=args.file)
    flow_bursts = None
    count_of_bursty_flows = 0
    number_of_heavy_flows = 0
    if args.type == "flow_oriented":
        flow_bursts, count_of_bursty_flows, number_of_heavy_flows = network_traffic.flow_oriented_network_traffic_bursts(
            heavy_rate_threshold=Decimal(args.heavy_rate_threshold),
            min_heavy_duration=Decimal(args.min_heavy_duration))
        network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic, bursts=flow_bursts)

    else:
        network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic)

    plot_dict = {
        "Traffic rate": network_plot.plot_traffic_and_bursts,
        "Length of microbursts": network_plot.plot_bursts_duration_cdf,
        "Traffic volume of microbursts": network_plot.bursts_traffic_volume,
        "Burst ratio of microbursts": network_plot.plot_bursts_ratio_cdf,
        "Number of packets in microbursts": network_plot.plot_bursts_packet_count_cdf,
        "Average packet size of microbursts": network_plot.plot_bursts_avg_packet_size_cdf,
        "Inter-burst interval": network_plot.plot_inter_burst_duration_signal_cdf,
        "Number of flows in microbursts": network_plot.plot_bursts_flow_count_cdf,
        "Number of microbursts in each flow": network_plot.plot_bursts_in_each_flow_cdf,
        "Duration of flows": network_plot.plot_cdf_flow_duration_all,
        "Duration of heavy flows": network_plot.plot_cdf_flow_duration_heavy,
        "Duration of bursty flows": network_plot.plot_cdf_flow_duration_bursty,
        "Number of concurrent bursty flows at each microburst": network_plot.plot_cdf_number_of_concurrent_bursty_flows
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
        try:
            choice = int(choice)
        except ValueError as ve:
            error_message = "Invalid selection, please try again."
            continue
        if choice == 0:
            break
        elif choice == len(plot_dict) + 1:
            clear_screen()
            print(
                f"Number of bursts: {len(flow_bursts) if args.type == 'flow_oriented' else len(network_traffic.bursts)}")
            print(f"Number of flows: {len(network_traffic.flow_event.flows)}")
            print(f"Number of bursty flows: {count_of_bursty_flows}")
            print(f"Number of heavy flows: {number_of_heavy_flows}")
            flows = network_traffic.heavy_flow_duration_dict.keys()
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
