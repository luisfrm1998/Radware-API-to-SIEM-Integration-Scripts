import requests
import logging
import logging.handlers
import time
import json

# Load configuration
with open("config/example_config.json", "r") as config_file:
    config = json.load(config_file)

# API and Syslog configuration
api_url = f"{config['api_url']}/api/sdcc/attack/core/analytics/object/vision/securityevents"
headers = config["headers"]
syslog_server = config["syslog_server"]
syslog_port = config["syslog_port"]
last_timestamp_path = config["last_timestamp_security"]
default_start_timestamp = config["default_start_timestamp"]

# Configure Syslog
logger = logging.getLogger()
syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port))
logger.addHandler(syslog_handler)
logger.setLevel(logging.INFO)


def get_last_timestamp():
    """
    Retrieve the last processed timestamp from a file or return the default.
    """
    try:
        with open(last_timestamp_path, 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return default_start_timestamp


def save_current_timestamp(timestamp):
    """
    Save the current timestamp to a file for future use.
    """
    with open(last_timestamp_path, 'w') as f:
        f.write(str(timestamp))


def fetch_events():
    """
    Query the API for security events.
    """
    start_timestamp = get_last_timestamp()
    current_timestamp = int(time.time() * 1000)

    body = {
        "criteria": [
            {"key": "accountId", "value": "your_account_id_here"},
            {"key": "startTimestamp", "value": [start_timestamp, None]},
            {"key": "endTimestamp", "value": [None, current_timestamp]},
            {"key": "risk", "value": ["Info", "Low", "Medium", "High", "Critical"]}
        ]
    }

    response = requests.post(api_url, headers=headers, json=body)
    if response.status_code == 200:
        save_current_timestamp(current_timestamp)
        return response.json().get('documents', [])
    else:
        logging.error(f"Failed to fetch events: {response.status_code} - {response.text}")
        return []


def format_to_cef(event):
    """
    Convert an event into CEF format for Syslog.
    """
    cef = "CEF:0|Radware|DDoS Protection|1.0|{triggerCode}|{triggerName}|{severity}|".format(
        triggerCode=event.get('triggerCode', 'N/A'),
        triggerName=event.get('triggerName', 'N/A'),
        severity=event.get('severity', 'N/A')
    )
    for key, value in event.items():
        cef += "{}={} ".format(key, value)
    return cef


def send_to_siem(cef_log):
    """
    Send a CEF-formatted log to the Syslog server.
    """
    print(f"Sending event to SIEM: {cef_log}")
    logger.info(cef_log)


def main():
    """
    Fetch and process security events, then send them to the SIEM.
    """
    events = fetch_events()
    if events:
        for event in events:
            cef_log = format_to_cef(event)
            send_to_siem(cef_log)


if __name__ == "__main__":
    main()