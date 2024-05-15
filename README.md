# TCP-IP-Programming

## Overview

This project consists of two main components: the Monitoring Service and the Management Service. The Management Service configures and manages monitoring tasks, while the Monitoring Service performs the monitoring tasks and reports back to the Management Service. 

## Usage
### Start the Monitoring Service
1. Open a terminal and navigate to the directory containing `monitoring_service.py`.
2. Run the script with elevated privileges (necessary for certain network operations):
```bash
sudo python3 monitoring_service.py
```

### Start the Management Service
1. Open another terminal and navigate to the directory containing `management_service.py`.
2. Run the script:
```bash
python3 management_service.py
```
