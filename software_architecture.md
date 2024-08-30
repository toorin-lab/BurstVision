# Software Architecture

## Overview

This project provides a tool for analyzing network traffic data, generating plots, and visualizing key traffic metrics. The tool can operate in different modes (`traffic-oriented` or `flow-oriented`) and allows users to analyze network data by generating plots and summaries for various traffic characteristics.

### Main Components

1. **`analyzer.py`**: The main script that handles user interaction, command-line argument parsing, and coordinates the traffic analysis and plotting functionalities.
2. **`network_traffic.py`**: Contains the core logic for processing network traffic data, including reading packet capture (pcap) files, calculating traffic metrics, and handling flow-oriented traffic analysis.
3. **`plot.py`**: Responsible for generating visual plots from the analyzed network traffic data. It uses `matplotlib` to create various plots such as traffic rates, burst distributions, and flow durations.

## Detailed Architecture

### 1. `analyzer.py`

This is the main entry point for the tool. It performs the following key tasks:

- **Argument Parsing**: Uses `argparse` to handle command-line arguments, which specify input files, processing modes, and other parameters.
- **Menu Handling**: Provides an interactive menu (`plot_menu`) for the user to select different plotting options or view network traffic summaries.
- **Network Traffic Analysis**: Instantiates the `NetworkTraffic` class to analyze the network data and uses the `PlotNetworkTraffic` class to generate plots based on user input.

#### Important Functions

- **`plot_menu(plot_dict)`**: Displays an interactive menu for users to select different plotting options.
- **`clear_screen()`**: Clears the console screen.
- **Main Program Execution**:
  - Parses command-line arguments to set the tool's parameters.
  - Initializes the `NetworkTraffic` object for data analysis.
  - Uses a loop to display the menu, handle user choices, and generate the requested plots.

### 2. `network_traffic.py`

This file contains the core logic for processing network traffic data. It defines several classes and functions that handle reading packet data, calculating various metrics, and performing flow-oriented traffic analysis.

#### Key Classes

- **`CustomPacket`**: A custom class based on the `Packet` class provided by Scapy. We use `CustomPacket` to allow modifications to the packet attributes based on the state of calculations, which Scapy does not provide directly.

- **`FiveTuple`**: A class that stores the attributes of a five-tuple (typically consisting of source IP, destination IP, source port, destination port, and protocol). This is essential for identifying unique network flows.

- **`FlowEvent`**: This class stores the attributes of a network flow, including all relevant metrics that define the flow's behavior over time.

- **`Burst`**: Whenever a burst is detected, an object of the `Burst` class is created to store its properties and metrics.

#### Key Responsibilities of `NetworkTraffic` Class

- **All Metrics Calculation**: The `NetworkTraffic` class is responsible for calculating all metrics related to network traffic, such as traffic rate signals, average traffic rates, burst identification, etc.
- **Initialization (`__init__()`)**: During initialization, the necessary indexes and data structures are set up for further processing. All the essential calculations and pre-computations are performed in this step.

#### Important Functions

- **`flow_oriented_network_traffic_bursts()`**: Called in flow analysis mode, this function identifies bursts in network traffic based on flow characteristics.

- **`extract_5_tuple()`**: This function extracts all five-tuples from the network traffic data, which are used to identify unique network flows.

- **CSV Support**: The tool also supports reading traffic data from CSV files.
  - **`_analyze_csv_packets()`**: This function reads and processes network traffic data from a CSV file format.

- **Traffic Rate Signal Calculation**:
  - **`_get_traffic_rate_signal()`**: Calculates the traffic rate signal, which represents the rate of traffic over time intervals.
  - **`_get_traffic_avg_rate_signal()`**: Using the traffic rate signal calculated by the previous function, this function computes the average traffic rate signal over a specified window.

- **Burst Detection**:
  - **`get_continuous_bursts()`**: Identifies bursts that are continuous, meaning consecutive bursts with no or minimal gaps between them.
  - **`_get_bursts()`**: The core function responsible for identifying bursts in the network traffic data.
  - **`_get_inter_burst_duration_signal()`**: Calculates the inter-burst duration signal, which represents the time intervals between successive bursts.

### 3. `plot.py`

This file is responsible for generating various visual plots from the analyzed network traffic data. It defines the `PlotNetworkTraffic` class, which provides methods to create plots for different traffic characteristics.

#### Key Responsibilities

- **Plotting Traffic Metrics**: Uses `matplotlib` to generate plots for traffic rate, burst distributions, flow durations, etc.
- **Handling Plotting Modes**: Supports both traffic-oriented and flow-oriented plotting modes.

#### Important Functions

- **`__init__()`**: Initializes the `PlotNetworkTraffic` object with the network traffic data and burst information (if provided).
- **`plot_traffic_rate()`**: Plots the rate of traffic over time in specified intervals.
- **`plot_average_traffic_rate()`**: Plots both the original and averaged traffic rates.
- **`plot_traffic_and_bursts()`**: Plots the traffic rate along with burst occurrences, highlighting both in a single plot.
- **`plot_cdf(function_outputs, function_name, function_atr, title)`**: A generic function for plotting the Cumulative Distribution Function (CDF) for different metrics.
- **`plot_bursts_duration_cdf()`**: Plots the CDF of burst durations.
- **`bursts_traffic_volume()`**: Plots the CDF of the total traffic volume of microbursts.
- **`plot_bursts_ratio_cdf()`**: Plots the CDF of burst ratios.
- **`plot_bursts_packet_count_cdf()`**: Plots the CDF of the number of packets in microbursts.
- **`plot_bursts_avg_packet_size_cdf()`**: Plots the CDF of the average packet size in microbursts.
- **`plot_inter_burst_duration_signal_cdf()`**: Plots the CDF of the inter-burst interval durations.
- **`plot_bursts_flow_count_cdf()`**: Plots the CDF of the number of flows in microbursts (only works in traffic-oriented mode).
- **`plot_bursts_in_each_flow_cdf()`**: Plots the CDF of the number of microbursts in each flow (only works in flow-oriented mode).
- **`plot_cdf_flow_duration_all()`**: Plots the CDF of all flow durations (only works in flow-oriented mode).
- **`plot_cdf_flow_duration_heavy()`**: Plots the CDF of the duration of heavy flows (only works in flow-oriented mode).
- **`plot_cdf_flow_duration_bursty()`**: Plots the CDF of the duration of bursty flows (only works in flow-oriented mode).
- **`plot_cdf_number_of_concurrent_bursty_flows()`**: Plots the CDF of the number of concurrent bursty flows at each microburst (only works in flow-oriented mode).

## Interaction Between Components

1. **User Input and Argument Parsing (`analyzer.py`)**: The user runs the `analyzer.py` script and provides input through command-line arguments or the interactive menu.
2. **Data Analysis (`network_traffic.py`)**: Based on user input, the `NetworkTraffic` class processes the network data to compute the necessary metrics.
3. **Plotting (`plot.py`)**: The `PlotNetworkTraffic` class generates plots based on the analyzed data and user selections.

## Conclusion

This project is a comprehensive tool for analyzing and visualizing network traffic data. It integrates data processing, analysis, and visualization functionalities into a single, interactive script, making it easy for users to gain insights into their network traffic patterns.
