# UL-ECE-DDoS-H-IoT-Datasets2025

This repository hosts two new datasets for DDoS attack detection in Healthcare IoT (H-IoT) environments:

- **UL-ECE-MQTT-DDoS-H-IoT2025** (simulated using Cooja with MQTT traffic)
- **UL-ECE-UDP-DDoS-H-IoT2025** (simulated using ns-3 with UDP traffic)

Both datasets provide preprocessed CSV files along with their corresponding preprocessing scripts.

## Repository Structure

```text
UL-ECE-DDoS-H-IoT-Datasets2025/
├── MQTT/
│   ├── UL-ECE-MQTT-DDoS-H-IoT2025.csv
│   ├── UL-ECE-MQTT-DDoS-H-IoT2025-raw.txt (raw data)
│   └── preprocessing_ddos_mqtt_cooja.py
└── UDP/
    ├── UL-ECE-UDP-DDoS-H-IoT2025.csv
    └── preprocessing_ddos_udp_ns_3.py
```

> **Note:**  
> The raw simulation log file for UL-ECE-UDP-DDoS-H-IoT2025 is larger than the platform's upload limit and is available upon request.

## Citation

If you use these datasets in your research, please cite the following article:

```bibtex
@article{akhi2025tcn,
  title={TCN-Based DDoS Detection and Mitigation in 5G Healthcare-IoT: A Frequency Monitoring and Dynamic Threshold Approach},
  author={Akhi, Mirza and Eising, Ciarán and Dhirani, Lubna Luxmi},
  journal={IEEE Access},
  year={2025},
  publisher={IEEE}
}
```

## Authors

- Mirza Akhi   
- University of Limerick (UL), Ireland
