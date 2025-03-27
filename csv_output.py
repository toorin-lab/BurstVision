import pandas as pd

def write_to_csv(network_traffic, output_file):
    """
    Write network traffic analysis results to a CSV file
    
    Parameters:
    network_traffic (NetworkTraffic): NetworkTraffic object containing analysis results
    output_file (str): Path to the output CSV file
    """
    # Get traffic rate signal which contains all intervals
    traffic_signal = network_traffic.traffic_rate_signal
    avg_signal = network_traffic.avg_rate_signal
    
    # Create a dictionary to mark which intervals are bursts
    burst_intervals = {burst.timestamp // network_traffic.interval: 1 for burst in network_traffic.bursts}
    
    # Prepare data for each interval
    intervals_data = []
    for idx, row in traffic_signal.iterrows():
        interval_data = {
            'traffic_rate': row['Rate'],  # bytes per second
            'num_packets': row['Count'],
            'avg_packet_size': row['Size'] / row['Count'] if row['Count'] > 0 else 0,
            'avg_traffic_rate': avg_signal[idx],
            'avg_duration_between_packets': row['avg_duration'] if row['Count'] > 1 else 0,
            'timestamp': row['Timestamp'],
            'is_burst': burst_intervals.get(row['Interval'], 0),
        }
        intervals_data.append(interval_data)
    
    # Create DataFrame and write to CSV
    df = pd.DataFrame(intervals_data)
    df.to_csv(output_file, index=False)

def analyze_bursts_from_csv(csv_file):
    """
    Read CSV file and print burst analysis
    
    Parameters:
    csv_file (str): Path to the CSV file
    """
    try:
        # Read the CSV file
        df = pd.read_csv(csv_file)
        
        # Get all bursts (where is_burst == 1)
        bursts = df[df['is_burst'] == 1]
        
        # Count total number of bursts
        total_bursts = len(bursts)
        
        print("\n=== Burst Analysis ===")
        print(f"Total number of bursts: {total_bursts}")
        
        if total_bursts > 0:
            print("\nBurst Details:")
            print("--------------")
            for idx, burst in bursts.iterrows():
                timestamp_ms = burst['timestamp']  # microseconds
                timestamp_sec = timestamp_ms / 1e6  # convert to seconds
                
                print(f"Burst {idx + 1}:")
                print(f"  Timestamp: {timestamp_sec:.3f} seconds")
                print(f"  Traffic Rate: {burst['avg_traffic_rate']:.2f} bytes/sec")
                print(f"  Packets: {burst['num_packets']}")
                print(f"  Avg Packet Size: {burst['avg_packet_size']:.2f} bytes")
                print(f"  Avg Duration Between Packets: {burst['avg_duration_between_packets']:.2f} microseconds")
                print()
                
            # Calculate some statistics
            avg_traffic_rate = bursts['avg_traffic_rate'].mean()
            avg_packets = bursts['num_packets'].mean()
            avg_duration = bursts['avg_duration_between_packets'].mean()
            
            print("Summary Statistics:")
            print("-----------------")
            print(f"Average traffic rate during bursts: {avg_traffic_rate:.2f} bytes/sec")
            print(f"Average number of packets per burst: {avg_packets:.2f}")
            print(f"Average duration between packets during bursts: {avg_duration:.2f} microseconds")
            
        return total_bursts
            
    except FileNotFoundError:
        print(f"Error: Could not find CSV file: {csv_file}")
        return 0
    except Exception as e:
        print(f"Error analyzing CSV file: {str(e)}")
        return 0
