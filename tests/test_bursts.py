import numpy as np
from network_traffic import Burst
import pandas as pd


def get_bursts(traffic_rate_signal, avg_traffic_signal, min_burst_ratio, interval):
    traffic_rate_signal = traffic_rate_signal
    avg_traffic_signal = avg_traffic_signal
    is_burst = traffic_rate_signal['Rate'] > (min_burst_ratio * avg_traffic_signal)
    burst_traffic = traffic_rate_signal[is_burst]
    burst_avg = avg_traffic_signal[is_burst]
    burst_ratio = np.where(burst_avg != 0, burst_traffic['Rate'] / burst_avg, np.inf)
    bursts_points = np.array(
        [Burst(time * interval, ratio, burst_total_traffic=size) for time, size, ratio in
         zip(burst_traffic['Interval'], burst_traffic['Size'], burst_ratio)])
    print(bursts_points)
    bursts = []
    current_burst = None
    sum_of_burt_ratio = 0
    total_current_burst_count = 0
    sum_of_timestamps = 0
    prev_timestamp = 0
    for i in range(len(bursts_points)):
        bursts_point = bursts_points[i]
        if current_burst is None:
            current_burst = bursts_point
            sum_of_burt_ratio = bursts_point.burst_ratio
            sum_of_timestamps = bursts_point.timestamp
            prev_timestamp = bursts_point.timestamp
            total_current_burst_count = 1
            continue
        if bursts_point.timestamp - prev_timestamp <= interval:
            sum_of_timestamps += bursts_point.timestamp
            sum_of_burt_ratio += bursts_point.burst_ratio
            total_current_burst_count += 1
            current_burst.burst_total_traffic += bursts_point.burst_total_traffic
            current_burst.burst_ratio = sum_of_burt_ratio / total_current_burst_count
            current_burst.timestamp = sum_of_timestamps / total_current_burst_count
            prev_timestamp = bursts_point.timestamp
            current_burst.interval = total_current_burst_count * interval
            if i == len(bursts_points) - 1:
                bursts.append(current_burst)
                break
        else:
            current_burst.interval = total_current_burst_count * interval
            bursts.append(current_burst)
            ############################
            current_burst = bursts_point
            sum_of_timestamps = bursts_point.timestamp
            sum_of_burt_ratio = bursts_point.burst_ratio
            prev_timestamp = bursts_point.timestamp
            current_burst.interval = total_current_burst_count * interval
            total_current_burst_count = 1
            if i == len(bursts_points) - 1:
                bursts.append(current_burst)
                break
    return bursts


np.random.seed(0)
data_length = 10
traffic_rate = np.random.normal(loc=50, scale=10, size=data_length)
avg_traffic = np.full(shape=data_length, fill_value=40)

for i in range(5, 7):
    traffic_rate[i] *= 1.5

traffic_rate_signal = pd.DataFrame({'Rate': traffic_rate, 'Interval': np.arange(data_length)})
traffic_rate_signal['Size'] = np.random.randint(10, 100, size=data_length)
avg_traffic_signal = avg_traffic

min_burst_ratio = 1.4
interval = 2

bursts = get_bursts(traffic_rate_signal, avg_traffic_signal, min_burst_ratio, interval)
print(bursts)
