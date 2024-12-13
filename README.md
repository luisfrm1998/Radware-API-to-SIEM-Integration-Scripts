# Radware API to SIEM Integration Scripts

This repository contains Python scripts for integrating operational and security events from the Radware API with a SIEM server. The events are sent in **CEF** (Common Event Format) using **Syslog**.

## Features

- Query operational events from the Radware API.
- Filters by time range, severity, and specific account.
- Formats events into CEF.
- Automatically sends events to a SIEM via Syslog.
- Configurable for periodic execution using cron jobs.

## Requirements

- Python 3.x
- Python libraries:
  - `requests`
  - `logging`
- Access to the Radware API (context and API key).
- A Syslog server configured to receive the events.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/luisfrm1998/Radware-API-to-SIEM-Integration-Scripts
   cd radware-siem-integration
   
## Structure

```plaintext
radware-api-to-siem/
├── scripts/
│   ├── retrive_security_events.py         # Script for security events
│   ├── retrive_operational_events.py      # Script for operational events
├── config/
│   ├── example_config.json                # Centralized configuration file
│   ├── example_last_timestamp_security.txt  # Timestamp for security events
│   ├── example_last_timestamp_operational.txt  # Timestamp for operational events
├── logs/
│   ├── .gitignore                         # Prevent log files from being uploaded
├── requirements.txt                       # Python dependencies
├── README.md                              # Documentation
├── LICENSE                                # License file
