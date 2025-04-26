"""
Preprocessing Script for UL-ECE-UDP-DDoS-H-IoT2025 Dataset
-----------------------------------------------------------

This script processes raw simulation log data collected using the NS-3 network simulator
to generate the UL-ECE-UDP-DDoS-H-IoT2025 dataset. It extracts and generates the following features:

- Timestamp
- Time elapsed
- Node ID
- Protocol (encoded)
- Protocol description (original string)
- Source IP (encoded)
- Source IP description (original string)
- Destination IP (encoded)
- Destination IP description (original string)
- Payload size
- Total number of messages
- Total number of messages from the same node
- Message frequency (percentage)
- Mean frequency
- Monitoring frequency (5-second window)
- Monitoring total messages
- Monitoring total messages from the same node
- Binary outcome label (malicious or normal)

The resulting data is saved in CSV format for use in DDoS detection research
within healthcare IoT environments.

Author: Mirza Akhi
Affiliation: University of Limerick (UL), Ireland
"""


import pandas as pd
import re

# Initialize an empty list to store extracted features
extracted_data = []

# Initialize counters and accumulators for total messages, messages per node, and running frequency mean
total_messages = 0
node_message_counts = {}
total_number_of_frequencies = 0
frequency_sum = 0
monitor_frequency_sum = 0
wrong_outcome = 0

# Initialize a variable to store the first timestamp
first_timestamp = None

# Define a function to extract features from each line
def extract_features(line):
    global total_messages, first_timestamp, total_number_of_frequencies, frequency_sum, wrong_outcome

    parts = line.strip().split()

    # Extract Node ID
    node_match = re.search(r'/NodeList/(\d+)/', parts[2])
    node_id = int(node_match.group(1)) if node_match else None

    # Skip Node IDs 0 to 4
    if node_id is None or node_id < 6:
        return None

    # Update total messages counter
    total_messages += 1

    # Update messages count for the same node
    if node_id not in node_message_counts:
        node_message_counts[node_id] = 0
    node_message_counts[node_id] += 1

    # Extract timestamp
    timestamp = float(parts[1])

    # Set the first timestamp
    if first_timestamp is None:
        first_timestamp = timestamp

    # Calculate time elapsed since the first timestamp
    time_elapsed = timestamp - first_timestamp

    # Extract Protocol
    protocol = parts[3]

    # Extract Source and Destination IPs
    src_ip = parts[23]
    dst_ip = parts[25].rstrip(')')  # Remove trailing ")" from Destination IP

    # Extract Payload size
    payload_size_match = re.search(r'Payload \(size=(\d+)\)', line)
    payload_size = int(payload_size_match.group(1)) if payload_size_match else None

    # Calculate frequency as a percentage
    frequency = float(node_message_counts[node_id]) / float(total_messages) * 100

    # Update the running sum of frequencies and calculate the mean frequency
    total_number_of_frequencies += 1
    frequency_sum += frequency
    mean_frequency = frequency_sum / total_number_of_frequencies

    return {
        'timestamp': timestamp,
        'time_elapsed': time_elapsed,
        'node_id': node_id,
        'protocol': protocol,
        'protocol_des': protocol,
        'source_ip': src_ip,
        'source_ip_des': src_ip,
        'destination_ip': dst_ip,
        'destination_ip_des': dst_ip,
        'payload_size': payload_size,
        'total_messages': total_messages,
        'total_messages_same_node': node_message_counts[node_id],
        'frequency': frequency,
        'mean_frequency': mean_frequency,
        'monitoring_frequency': None,  # Placeholder
        'monitoring_total_messages': None,  # Placeholder
        'monitoring_total_messages_same_node': None,  # Placeholder
        'outcome': None  # Placeholder
    }

# Read the file line by line
file_path = 'UL-ECE-UDP-DDoS-H-IoT2025-raw.txt'

with open(file_path, 'r') as file:
    for line in file:
        # Skip empty lines
        if line.strip():
            features = extract_features(line)
            if features:  # Only add non-None results
                extracted_data.append(features)

# Convert the list of dictionaries to a DataFrame
df = pd.DataFrame(extracted_data)

# Convert protocol, source_ip, and destination_ip to numeric while keeping original strings in protocol_des, source_ip_des, and destination_ip_des
df['protocol'] = df['protocol'].astype('category').cat.codes
df['source_ip'] = df['source_ip'].astype('category').cat.codes
df['destination_ip'] = df['destination_ip'].astype('category').cat.codes

# Explicitly convert only the appropriate columns to numeric types
df['timestamp'] = df['timestamp'].astype(float)
df['time_elapsed'] = df['time_elapsed'].astype(float)
df['payload_size'] = df['payload_size'].astype(float)
df['total_messages'] = df['total_messages'].astype(int)
df['total_messages_same_node'] = df['total_messages_same_node'].astype(int)
df['frequency'] = df['frequency'].astype(float)

# Calculate monitoring total messages, monitoring total messages for the same node, and monitoring frequency
def calculate_monitoring_frequencies(df):
    global monitor_frequency_sum, total_messages

    monitoring_frequencies = []
    monitoring_total_messages_list = []
    monitoring_total_messages_same_node_list = []

    for index, row in df.iterrows():
        current_timestamp = row['timestamp']
        node_id = row['node_id']

        # Filter the DataFrame to get the rows within the last 5 seconds relative to the current timestamp
        last_5_seconds_data = df[(df['timestamp'] >= current_timestamp - 5) & (df['timestamp'] <= current_timestamp)]

        # Calculate monitoring total messages
        monitoring_total_messages = len(last_5_seconds_data)
        monitoring_total_messages_same_node = len(last_5_seconds_data[last_5_seconds_data['node_id'] == node_id])

        # Calculate monitoring frequency as a percentage
        monitoring_frequency = (monitoring_total_messages_same_node / monitoring_total_messages) * 100 if monitoring_total_messages > 0 else 0

        # Append calculated values to the lists
        monitoring_frequencies.append(monitoring_frequency)
        monitoring_total_messages_list.append(monitoring_total_messages)
        monitoring_total_messages_same_node_list.append(monitoring_total_messages_same_node)

    return monitoring_frequencies, monitoring_total_messages_list, monitoring_total_messages_same_node_list

# Calculate monitoring frequencies and total messages
df['monitoring_frequency'], df['monitoring_total_messages'], df['monitoring_total_messages_same_node'] = calculate_monitoring_frequencies(df)

# Determine outcome based on frequency and monitoring frequency
def determine_outcome(row):
    monitoring_frequency = row['monitoring_frequency']
    mean_frequency = row['mean_frequency']
    return 1 if monitoring_frequency >= mean_frequency else 0

# Apply outcome determination
df['outcome'] = df.apply(determine_outcome, axis=1)

# Check for wrong outcome condition
wrong_outcome = sum(
    (row['outcome'] == 1 and row['node_id'] < 16) or (row['outcome'] == 0 and row['node_id'] > 15)
    for _, row in df.iterrows()
)

# Display the first few rows of the cleaned DataFrame
print(df.head())

# Save the DataFrame to a CSV file
output_csv_path = 'UL-ECE-UDP-DDoS-H-IoT2025.csv'
df.to_csv(output_csv_path, index=False)

