# Radware API to SIEM Integration Scripts

This repository contains Python scripts for integrating operational and security events from the Radware API with a SIEM server. The events are sent in **CEF** (Common Event Format) using **Syslog**.

## Features

- Query security and operational events from the Radware API.
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

---

## Installation

### Step 1: Clone the Repository

Clone this repository to your local environment:

```bash
git clone https://github.com/luisfrm1998/Radware-API-to-SIEM-Integration-Scripts
cd Radware-API-to-SIEM-Integration-Scripts
```

---

### Step 2: Install Dependencies

Install the required Python libraries listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

### Step 3: Configure the Project

1. Open `config/example_config.json` and update the following fields with your specific details:
   - **API credentials:** Replace `"context"` and `"x-api-key"` in the `headers` section with your Radware API credentials.
   - **Syslog details:** Replace `"syslog_server"` and `"syslog_port"` with the IP address and port of your Syslog server.
   - **Default start timestamp:** Update `"default_start_timestamp"` if you want to specify a custom starting point for queries.

2. Ensure that the timestamp files exist and are initialized:
   ```bash
   echo "0" > config/example_last_timestamp_security.txt
   echo "0" > config/example_last_timestamp_operational.txt
   ```

---

### Step 4: Test the Scripts

Before automating, run the scripts manually to ensure everything works as expected:

- **Test Security Events:**
  ```bash
  python3 scripts/retrive_security_events.py
  ```

- **Test Operational Events:**
  ```bash
  python3 scripts/retrive_operational_events.py
  ```

Check the output or logs to verify the scripts are functioning correctly.

---

### Step 5: Automate Execution with Cron Jobs

To run the scripts every minute, set up cron jobs:

1. Open the crontab editor:
   ```bash
   crontab -e
   ```

2. Add the following lines to schedule the scripts:

   ```plaintext
   * * * * * /usr/bin/python3 /path/to/radware-api-to-siem/scripts/retrive_security_events.py >> /path/to/radware-api-to-siem/logs/security.log 2>&1
   * * * * * /usr/bin/python3 /path/to/radware-api-to-siem/scripts/retrive_operational_events.py >> /path/to/radware-api-to-siem/logs/operational.log 2>&1
   ```

   Replace `/path/to/radware-api-to-siem/` with the absolute path to your project directory.

3. Save and exit the editor.

---

### Step 6: Verify the Cron Jobs

1. List the active cron jobs:
   ```bash
   crontab -l
   ```

2. Monitor the logs to ensure the scripts are running as expected:
   ```bash
   tail -f /path/to/radware-api-to-siem/logs/security.log
   tail -f /path/to/radware-api-to-siem/logs/operational.log
   ```
 
---

## Structure

```plaintext
radware-api-to-siem/
├── scripts/
│   ├── retrive_security_events.py         # Script to retrieve and process security events
│   ├── retrive_operational_events.py      # Script to retrieve and process operational events
├── config/
│   ├── example_config.json                # Centralized configuration file
│   ├── example_last_timestamp_security.txt  # Timestamp for security events
│   ├── example_last_timestamp_operational.txt  # Timestamp for operational events
├── logs/
│   ├── security.log                       # Log file for security events
│   ├── operational.log                    # Log file for operational events
│   ├── .gitignore                         # Prevent logs from being uploaded to the repository
├── requirements.txt                       # Python dependencies
├── README.md                              # Project documentation
├── LICENSE                                # License file

