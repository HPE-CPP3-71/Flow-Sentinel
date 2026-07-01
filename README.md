# Flow-Sentinel
Network Flow based Anomaly Detection App

## Protocols and Attacks covered

- ICMP
- HTTP
- DNS
- Portscan
- Bruteforce(SSH and FTP)
- IGMP,PIM (multicast)
- Optional OSPF packet detection using Scapy

---

## Requirements

- Python 3.9+ (or your version)
- Linux (recommended, since the application requires `sudo`. Windows might actively blocks packet capture)
- pip

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/HPE-CPP3-71/Flow-Sentinel.git
cd Flow-Sentinel
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

The project uses the following major dependencies:

- customtkinter
- ntfstream
- joblib
- numpy
- pandas
- scikit-learn
- xgboost
- scapy (optional for OSPF detection)

> **Note:** If `scapy` is not installed, the application will still run, but OSPF rule-based detection will be disabled.

---

## Running the Application

The application requires administrator privileges because it captures and analyzes network packets.

Run:

```bash
sudo python main.py
```

or, if your system uses Python 3:

```bash
sudo python3 main.py
```

---

## Flow-Sentinel Project Structure

```
Flow-Sentinel/
│
├── main.py                 # Entry point
├── backend/                # ML models, Feature Extraction and Predictions
├── core/                   # Contains AppState, a thread-safe monitor object
├── frontend/               # GUI
├── requirements.txt
└── README.md
```

---

## Dependencies

| Package | Purpose |
|----------|---------|
| customtkinter | GUI framework |
| ntfstream | Network flow extraction |
| numpy | Numerical computations |
| pandas | Data processing |
| scikit-learn | Machine learning models |
| xgboost | Gradient boosting model |
| joblib | Model serialization |
| scapy | Packet parsing (optional OSPF detection) |

---

## Notes

- Root (`sudo`) privileges are required for live packet capture.
- Ensure your network interface is available and has the necessary permissions.

---

## Troubleshooting

### Permission Denied

If packet capture fails, make sure you're running:

```bash
sudo python main.py
```

### Missing Dependencies

Reinstall all packages:

```bash
pip install -r requirements.txt
```
Try unistalling and reinstalling  `Libcap` or `Npcap` libraries.
