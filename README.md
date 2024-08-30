
# Microburst Analysis Tool

This project is designed to analyze network traffic and detect microbursts. Microbursts are short, intense bursts of data traffic that can significantly impact network performance. This tool identifies and analyzes these bursts to provide insights into network behavior.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Files and Functions](#files-and-functions)
- [Flags and Parameters](#flags-and-parameters)
- [Analysis Modes](#analysis-modes)
- [Types of Plots](#types-of-plots)
- [Code Architecture](#code-architecture)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Traffic Analysis**: Analyzes PCAP files to detect and visualize microbursts.
- **Flow-Oriented Analysis**: Provides detailed analysis of network flows.
- **Visualization**: Offers various plots to visualize network traffic and burst characteristics.
- **Support for PCAP and CSV**: Can read data from PCAP files or CSV files containing network packet data.

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/BurstVision.git
   ```
2. Navigate to the project directory:
   ```sh
   cd BurstVision
   ```
3. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
To run the microburst analysis tool, use the following command:
```sh
python analyzer.py -f <path_to_pcap_or_csv_file> -i <input_type> [options]
```

## Files and Functions

### `network_traffic.py`
This file contains the core logic for analyzing network traffic. Key classes and functions include:

- **`CustomPacket`**: Represents a network packet with attributes such as timestamp, wire length, source IP, destination IP, etc.
- **`FiveTuple`**: Represents a 5-tuple used to identify flows. It also includes methods to create time indices and retrieve tuples in a time range.
- **`FlowEvent`**: Manages network flows and provides methods to add and track 5-tuples.
- **`Burst`**: Represents a burst of network traffic, with methods to check if a packet is part of the burst.
- **`NetworkTraffic`**: Main class for handling network traffic analysis. It reads packets, calculates traffic rate signals, identifies bursts, and provides various analysis methods.

### `analyzer.py`
This is the main file to run the program. It includes:
- **Argument Parsing**: Parses command-line arguments for various configurations.
- **Main Logic**: Initializes the `NetworkTraffic` class and handles user interaction for generating plots and viewing analysis results.
- **Menu System**: Provides a user interface to select different plots and display network traffic information.

### `plot.py`
This file handles the plotting functionalities of the tool. 

## Flags and Parameters

### Flags for `analyzer.py`
- `-r`: Processing resolution in microseconds (default: 100).
- `-a`: Average window size in microseconds (default: 100000).
- `-b`: Minimum burst ratio (default: 5).
- `-f`: Path to the PCAP or CSV file.
- `-i`: Input type (`pcap` or `csv`, default: `pcap`).
- `-m`: Processing mode (`traffic_oriented` or `flow_oriented`).
- `-ht`: Rate threshold for heavy flows in bytes/second (default: 0).
- `-md`: Minimum duration of heavy flows in milliseconds (default: 100).

### Example Command
```sh
python analyzer.py -r 200 -b 5 -f test.pcap -m flow_oriented
```

## Analysis Modes

### Traffic-Oriented Mode
In traffic-oriented mode, the tool analyzes the overall traffic to identify microbursts. It calculates the traffic rate over defined intervals and compares it to the average traffic rate to identify bursts.

### Flow-Oriented Mode
In flow-oriented mode, the tool analyzes individual network flows to detect bursts within those flows. This mode provides a more granular analysis by focusing on the behavior of specific flows rather than the overall traffic.

### Microburst Detection Process

#### Step 1: Read Packets
Packets are read from a PCAP or CSV file and stored in the `NetworkTraffic` object. The packets are parsed to extract relevant information, and each packet is assigned to a flow based on its 5-tuple.

#### Step 2: Calculate Traffic Rate Signal
The traffic rate signal is calculated over the defined intervals:
- **Aggregate Packet Sizes**: Sum the sizes of packets within each interval.
  
$$
\text{Traffic Rate} = \frac{\sum \text{Packet Sizes in Interval}}{\text{Interval Duration}}
$$

#### Step 3: Calculate Average Traffic Rate Signal
The moving average of traffic rates is calculated using a sliding window approach:
- **Define Kernel**: A kernel is defined based on the average window size and interval.
- **Convolve Kernel with Traffic Rate Signal**: The kernel is convolved with the traffic rate signal to produce the moving average traffic rate.
  
  
$$
\text{Average Traffic Rate} = \frac{\sum \text{Traffic Rates within Window}}{\text{Window Size}}
$$

#### Step 4: Identify Burst Points
Burst points are identified where the traffic rate exceeds the minimum burst ratio times the moving average traffic rate:
- **Burst Condition**: A burst is identified if:
  
$$
\text{Traffic Rate} > (\text{Min Burst Ratio} \times \text{Average Traffic Rate})
$$


#### Step 5: Group Continuous Bursts
Continuous bursts are grouped together to form a single burst:
- **Initialize Current Burst**: The first burst point is initialized as the current burst.
- **Group Consecutive Bursts**: Consecutive burst points within the same interval are grouped into a single burst.
  
$$
\text{Current Burst Interval} = \text{Sum of Consecutive Burst Intervals}
$$

  
$$
\text{Burst Average Traffic} = \frac{\text{Total Traffic within Burst}}{\text{Number of Packets in Burst}}
$$

#### Step 6: Analyze Bursts and Flows
Bursts are analyzed to determine the number of flows involved and other characteristics:
- **Retrieve FiveTuples**: Identify the flows (5-tuples) within each burst interval.
- **Update Burst Information**: Calculate and update the burst attributes such as the number of flows, average traffic, total traffic, and duration.

## Types of Plots

The tool provides various plots to help visualize network traffic and burst characteristics:

- **Traffic rate**: Visualizes the traffic rate and bursts over time.
  <p align="center">
  <img width="700"  alt="image" src="https://github.com/toorin-lab/BurstVision/assets/88507467/096a9e7f-c520-4e01-a6fc-d8818b93f953">
  </p>
- **Length of microbursts**: Shows the cumulative distribution function (CDF) of the duration of microbursts.
- **Traffic volume of microbursts**: Displays the volume of traffic during microbursts.
  <p align="center">
  <img width="700" alt="image" src="https://github.com/toorin-lab/BurstVision/assets/88507467/48285a60-d0f3-4f84-bba8-6dc33409bf2d">
  </p>
- **Burst ratio of microbursts**: Plots the CDF of burst ratios.
- **Number of packets in microbursts**: Shows the CDF of the number of packets in microbursts.
  <p align="center">
  <img width="700" alt="image" src="https://github.com/toorin-lab/BurstVision/assets/88507467/637f53f0-7e16-4422-8d16-5a04cc98e332">
  </p>
- **Average packet size of microbursts**: Visualizes the CDF of the average packet size during microbursts.
  <p align="center">
  <img width="700" alt="image" src="https://github.com/toorin-lab/BurstVision/assets/88507467/681f5cb4-7fda-49e1-9b17-34a045f01b92">
  </p>
- **Inter-burst interval**: Displays the CDF of the time between bursts.
  <p align="center">
  <img width="700" alt="image" src="https://github.com/toorin-lab/BurstVision/assets/88507467/0f275778-4583-4e6e-b212-91d31f76afca">
  </p>
- **Number of flows in microbursts**: Shows the CDF of the number of flows involved in each burst.
- **Number of microbursts in each flow**: Plots the CDF of the number of bursts within each flow.
- **Duration of flows**: Shows the CDF of the duration of all flows.
- **Duration of heavy flows**: Displays the CDF of the duration of heavy flows.
- **Duration of bursty flows**: Plots the CDF of the duration of bursty flows.
- **Number of concurrent bursty flows at each microburst**: Visualizes the CDF of the number of concurrent bursty flows during each burst.

## Code Architecture
For a detailed explanation of the software architecture, please refer to the [software_architecture.md](software_architecture.md) document.

## Contributing
Contributions are welcome. Please fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

For more detailed documentation and examples, refer to the project's wiki or contact the project maintainers.
