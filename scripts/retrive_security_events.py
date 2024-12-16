import requests
import logging
import logging.handlers
import time
import json

# Load configuration
try:
    with open("config/example_config.json", "r") as config_file:
        config = json.load(config_file)
        print("Configuration loaded successfully.")
except Exception as e:
    print(f"Error loading configuration: {e}")
    exit(1)

# API and Syslog configuration
try:
    api_url = f"{config['api_url']}/api/sdcc/attack/core/analytics/object/vision/securityevents"
    headers = config["headers"]
    syslog_server = config["syslog_server"]
    syslog_port = config["syslog_port"]
    last_timestamp_path = config["last_timestamp_security"]
    default_start_timestamp = config["default_start_timestamp"]
    account_id = headers["context"]  # Extract accountId from headers["context"]
    print("Configuration variables set successfully.")
except KeyError as e:
    print(f"Missing configuration key: {e}")
    exit(1)

# Configure Syslog
try:
    logger = logging.getLogger()
    syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port))
    logger.addHandler(syslog_handler)
    logger.setLevel(logging.INFO)
    print("Syslog configured successfully.")
except Exception as e:
    print(f"Error configuring Syslog: {e}")
    exit(1)


def get_last_timestamp():
    """
    Retrieve the last processed timestamp from a file or return the default.
    """
    try:
        with open(last_timestamp_path, 'r') as f:
            content = f.read().strip()
            if not content:
                raise ValueError("Timestamp file is empty. Using default start timestamp.")
            timestamp = int(content)
            print(f"Last timestamp retrieved: {timestamp}")
            return timestamp
    except FileNotFoundError:
        print(f"Timestamp file not found. Using default start timestamp: {default_start_timestamp}")
        return default_start_timestamp
    except ValueError as e:
        print(f"{e}")
        return default_start_timestamp
    except Exception as e:
        print(f"Error reading last timestamp: {e}")
        exit(1)


def save_current_timestamp(timestamp):
    """
    Save the current timestamp to a file for future use.
    """
    try:
        with open(last_timestamp_path, 'w') as f:
            f.write(str(timestamp))
            print(f"Current timestamp saved: {timestamp}")
    except Exception as e:
        print(f"Error saving current timestamp: {e}")


def fetch_events():
    """
    Query the API for security events.
    """
    try:
        start_timestamp = get_last_timestamp()
        current_timestamp = int(time.time() * 1000)
        print(f"Fetching events from {start_timestamp} to {current_timestamp}")

        body = {
            "criteria": [
                {"key": "accountId", "value": account_id},  # Use 'accountId' from the configuration
                {"key": "startTimestamp", "value": [start_timestamp, None]},
                {"key": "endTimestamp", "value": [None, current_timestamp]},
                {"key": "risk", "value": ["Info", "Low", "Medium", "High", "Critical"]}
            ]
        }

        print(f"Request body: {json.dumps(body, indent=4)}")  # Debugging: Print the request body
        response = requests.post(api_url, headers=headers, json=body)
        print(f"API response status: {response.status_code}")
        if response.status_code == 200:
            save_current_timestamp(current_timestamp)
            print("Events fetched successfully.")
            return response.json().get('documents', [])
        else:
            print(f"Error fetching events: {response.status_code} - {response.text}")
            logging.error(f"Failed to fetch events: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"Error in fetch_events: {e}")
        logging.error(f"Error in fetch_events: {e}")
        return []


def format_to_cef(event):
    """
    Convert an event into CEF format for Syslog.
    """
    try:
        cef = "CEF:0|Radware|DDoS Protection|1.0|{triggerCode}|{triggerName}|{severity}|".format(
            triggerCode=event.get('triggerCode', 'N/A'),
            triggerName=event.get('triggerName', 'N/A'),
            severity=event.get('severity', 'N/A')
        )
        for key, value in event.items():
            cef += "{}={} ".format(key, value)
        print(f"Event formatted to CEF: {cef}")
        return cef
    except Exception as e:
        print(f"Error formatting event to CEF: {e}")
        logging.error(f"Error formatting event to CEF: {e}")
        return ""


def send_to_siem(cef_log):
    """
    Send a CEF-formatted log to the Syslog server.
    """
    try:
        print(f"Sending event to SIEM: {cef_log}")
        logger.info(cef_log)
    except Exception as e:
        print(f"Error sending event to SIEM: {e}")
        logging.error(f"Error sending event to SIEM: {e}")


def main():
    """
    Fetch and process security events, then send them to the SIEM.
    """
    try:
        print("Starting main process.")
        events = fetch_events()
        if events:
            for event in events:
                cef_log = format_to_cef(event)
                if cef_log:
                    send_to_siem(cef_log)
        else:
            print("No events to process.")
    except Exception as e:
        print(f"Error in main process: {e}")
        logging.error(f"Error in main process: {e}")


if __name__ == "__main__":
    main()
