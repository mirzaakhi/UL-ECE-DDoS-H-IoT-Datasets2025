
"""
Preprocessing Script for UL-ECE-MQTT-DDoS-H-IoT2025 Dataset
-----------------------------------------------------------

This script processes raw simulation log data collected using the Cooja network simulator
to generate the UL-ECE-MQTT-DDoS-H-IoT2025 dataset. It extracts features such as:

- Node ID
- Total number of messages
- Per-node message count
- Message frequency (as percentage)
- Binary outcome label (malicious or normal)

The resulting data is saved in CSV formats for use in DDoS detection research
within healthcare IoT environments.

Author: Mirza Akhi
Affiliation: University of Limerick (UL), Ireland
"""

import math

def get_time(time_stamp):
  splited_time_stamp = time_stamp.split(':')

  len_splited_time_stamp = len(splited_time_stamp)

  secs_msecs = splited_time_stamp[len_splited_time_stamp - 1]
  mins = splited_time_stamp[len_splited_time_stamp - 2]

  hrs = 0

  if len_splited_time_stamp >= 3:
    hrs = splited_time_stamp[len_splited_time_stamp - 3]

  secs = secs_msecs.split('.')[0]
  msecs = secs_msecs.split('.')[1]

  total_msecs = int(hrs) * 60 * 60 * 1000 + int(mins) * 60 * 1000 + int(secs) * 1000 + int(msecs)

  return total_msecs



def get_total_message(ids, total_messages):
  index = len(ids) - 1

  if index == 0:
    return 1

  return int(total_messages[index - 1]) + 1



def get_frequency(total_messages, total_messages_each_nodes):
  index = len(total_messages) - 1

  return float( int(total_messages_each_nodes[index]) / int(total_messages[index])) * 100



def get_total_messages_each_node(ids, total_messages_each_nodes):
  index = len(ids) - 1

  if index == 0:
    return 1

  current_index = index
  previous_each_node_index = -1

  index -= 1

  while index != -1:
    if int(ids[index]) == int(ids[current_index]):
      previous_each_node_index = index

    if previous_each_node_index != -1:
      break

    index -= 1

  if previous_each_node_index == -1:
    return 1

  return int(total_messages_each_nodes[previous_each_node_index]) + 1



def get_threshold(time_stamps):
  THRESHOLD_MULTIPLIER = 45
  time_stamp_ms = get_time(time_stamps[len(time_stamps) - 1])

  threshold = (time_stamp_ms / (60 * 60 * 1000)) * THRESHOLD_MULTIPLIER

  return threshold

import pandas as pd
import re
def get_data_frame(file_path):
  # Read the content of the text file
  with open(file_path, 'r') as file:
      lines = file.readlines()

  # Create lists to store data for each column
  time_stamps = []
  ids = []
  total_messages = []
  total_messages_each_nodes = []
  frequencies = []
  messages = []
  outcomes = []

  wrong_outcome = 0

  # Process each line in the text file
  for line in lines:
      # Split the line based on whitespace
      items = re.findall('Node ID: \d+, temperature \d+\.\d+ oF oxygen_level \d+ heart_rate \d+', line)

      if items:
        time_stamp = re.split(r'ID:\d+', line)[0]

        for item in items:
          time_stamps.append(time_stamp)

          match = re.search(r'Node ID: (\d+)', item)

          if match:
              node_id = match.group(1)
              ids.append(node_id)

          total_messages.append(get_total_message(ids, total_messages))
          total_messages_each_nodes.append(get_total_messages_each_node(ids, total_messages_each_nodes))
          frequencies.append(get_frequency(total_messages, total_messages_each_nodes))

          messages.append(item)

          if frequencies[len(frequencies) - 1] >= 5:
            outcomes.append(1)
            if int(node_id) < 16:
              wrong_outcome += 1
          else:
            outcomes.append(0)


  for index, time_stamp in enumerate(time_stamps):
    time_stamps[index] = get_time(time_stamp)

  # Create a dictionary with column names as keys and lists as values
  data_dict = {
      # 'time_stamp': time_stamps,
      'node': ids,
      'total_message': total_messages,
      'total_messages_each_node': total_messages_each_nodes,
      'frequency': frequencies,
      # 'message': messages,
      'outcome': outcomes,
  }

  # Create DataFrame from the dictionary
  df = pd.DataFrame(data_dict)

  return df

file_path = 'UL-ECE-MQTT-DDoS-H-IoT2025-raw.txt'

df = get_data_frame(file_path)

# Save the DataFrame to a CSV file
df.to_csv('UL-ECE-MQTT-DDoS-H-IoT2025.csv', index=False)