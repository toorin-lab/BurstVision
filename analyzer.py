import time
from plot import PlotNetworkTraffic

from network_traffic import NetworkTraffic

if __name__ == '__main__':
    start_time = time.time()
    interval = 1000
    avg_window_size = 1000000
    network_traffic = NetworkTraffic(pcab_file_location='PcabFiles/traffic.pcapng', interval=interval,
                                     avg_window_size=avg_window_size, min_burst_ratio=5, start_from_packet=0,
                                     end_at_packet=100000)
    network_plot = PlotNetworkTraffic(network_traffic_object=network_traffic)
    network_plot.plot_traffic_and_bursts()
    end_time = time.time()
    print(f"total execution time : {end_time - start_time}")
