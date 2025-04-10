import sys
import json
import os
import gzip
import csv
import re
import requests
import uuid
from datetime import datetime
import urllib3

# Disable warnings about insecure HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List to cache the Splunk base path in memory
SPLUNK_BASE_PATH = []

def get_splunk_base_path():
    """
    Extracts the Splunk installation base path from the /etc/init.d/splunk file.
    Caches the base path in the SPLUNK_BASE_PATH list.
    """
    if SPLUNK_BASE_PATH:
        return SPLUNK_BASE_PATH[0]
    init_file = "/etc/init.d/splunk"
    if not os.path.exists(init_file):
        sys.stderr.write("ERROR: Splunk init file not found.\n")
        return None
    try:
        with open(init_file, "r") as file:
            for line in file:
                if "/bin/splunk" in line:
                    match = re.search(r'"([^"]+/bin/splunk)"', line)
                    if match:
                        full_path = match.group(1)
                        # Remove '/bin/splunk' to obtain the base path
                        base_path = full_path.replace("/bin/splunk", "")
                        SPLUNK_BASE_PATH.append(base_path)
                        return base_path
        sys.stderr.write("ERROR: Splunk binary path not found in init file.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"ERROR reading Splunk init file: {e}\n")
        return None

# Determine the Splunk base directory
SPLUNK_BASE = get_splunk_base_path()
if SPLUNK_BASE is None:
    sys.stderr.write("ERROR: Cannot determine Splunk base directory.\n")
    sys.exit(4)
RESULTS_DIR = os.path.join(SPLUNK_BASE, "var", "run", "splunk", "dispatch")

PENDING_WEBHOOK_FILE = "./pending_webhooks.json"
PENDING_WEBHOOKS = []  # Global list to hold pending webhooks

def load_pending_webhooks():
    """
    Load pending webhooks from the file if it exists.
    The file is in NDJSON format (each line is a JSON object).
    Invalid lines are skipped.
    """
    pending = []
    if os.path.exists(PENDING_WEBHOOK_FILE):
        try:
            with open(PENDING_WEBHOOK_FILE, "r") as file:
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            pending.append(json.loads(line))
                        except json.JSONDecodeError:
                            sys.stderr.write("WARNING: A line in pending_webhooks.json is invalid and will be skipped.\n")
        except Exception as e:
            sys.stderr.write(f"ERROR reading pending_webhooks.json: {e}\n")
    return pending

def save_pending_webhooks():
    """
    Save the current pending webhooks (PENDING_WEBHOOKS) to a file in NDJSON format.
    Each pending webhook is written on a separate line with a "number" field added to track its order.
    """
    global PENDING_WEBHOOKS
    try:
        with open(PENDING_WEBHOOK_FILE, "w") as file:
            for idx, item in enumerate(PENDING_WEBHOOKS, start=1):
                item['number'] = idx
                file.write(json.dumps(item) + "\n")
    except Exception as e:
        sys.stderr.write(f"ERROR saving pending webhooks: {e}\n")

def process_pending_webhooks():
    """
    Process and attempt to resend any pending webhooks.
    If sending is successful, remove the item from the pending list.
    """
    global PENDING_WEBHOOKS
    if not PENDING_WEBHOOKS:
        return
    remaining = []
    for pending_item in PENDING_WEBHOOKS:
        sid_for_log = pending_item.get('sid', 'N/A')
        sys.stdout.write(f"INFO: Attempting to resend pending webhook for SID: {sid_for_log}\n")
        if not send_webhook(pending_item):
            remaining.append(pending_item)
        else:
            sys.stdout.write("INFO: Pending webhook sent successfully.\n")
    PENDING_WEBHOOKS = remaining

def extract_query_from_searchlog(sid):
    """
    Extract the search query from search.log for the given SID.
    Returns an empty string if not found or if the file does not exist.
    """
    search_log_path = os.path.join(RESULTS_DIR, sid, "search.log")
    if not os.path.exists(search_log_path):
        return ""

    pattern = re.compile(
        r'INFO\s+SearchParser\s+\[.*RunDispatch\].*PARSING:\s+(search\s+.*)'
    )

    with open(search_log_path, 'r', encoding='utf-8', errors='replace') as log_file:
        for line in log_file:
            match = pattern.search(line)
            if match:
                return match.group(1).strip()
    return ""

def send_webhook(item):
    """
    Sends the webhook payload to the specified URL.
    Uses authentication if both username and password are provided.
    Otherwise, sends the webhook without authentication.
    Certificate verification is disabled for HTTPS URLs.

    The 'item' dictionary must contain:
      - 'webhook_url': str
      - 'sid': str
      - 'search_name': str
      - 'row_data': dict (data for a single row)
      - 'row_number': int (CSV row number starting at 1)
      - Optionally, other fields like 'description', 'severity', etc.
    Note: The "group_id" field has been removed.
    """
    webhook_url = item.get('webhook_url')
    username = item.get('username', '')
    password = item.get('password', '')

    if not webhook_url:
        sys.stderr.write("ERROR: No webhook URL provided.\n")
        return False

    # Build the payload without the "group_id" field
    payload = {
        "sid": item.get("sid", "N/A"),
        "search_name": item.get("search_name", "N/A"),
        "search_query": item.get("search_query", ""),
        "description": item.get("description", ""),
        "severity": item.get("severity", ""),
        "kill_chain": item.get("kill_chain", ""),
        "mitre_tactics": item.get("mitre_tactics", []),
        "mitre_techniques": item.get("mitre_techniques", []),
        "row_number": item.get("row_number", 0),
        "row_data": item.get("row_data", {})
    }

    # If the URL uses HTTPS, disable certificate verification
    verify_setting = False if webhook_url.lower().startswith("https") else True

    try:
        if username and password:
            response = requests.post(
                webhook_url, json=payload,
                headers={"Content-Type": "application/json"},
                auth=(username, password),
                verify=verify_setting
            )
        else:
            response = requests.post(
                webhook_url, json=payload,
                headers={"Content-Type": "application/json"},
                verify=verify_setting
            )
        if 200 <= response.status_code < 300:
            sys.stdout.write(f"INFO: Webhook sent successfully, status: {response.status_code}\n")
            return True
        else:
            sys.stderr.write(f"ERROR: Webhook failed with status: {response.status_code}\n")
            return False
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to send webhook: {e}\n")
        return False

if __name__ == "__main__":
    # Load any previously pending webhooks from file (NDJSON format)
    PENDING_WEBHOOKS = load_pending_webhooks()

    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("FATAL: Unsupported execution mode (expected --execute flag)\n")
        sys.exit(1)

    try:
        # First, attempt to process any previously pending webhooks
        process_pending_webhooks()

        # Read settings from stdin
        settings = json.loads(sys.stdin.read())
        sid = settings.get('sid', 'N/A')
        search_name = settings.get('search_name', 'N/A')
        search_query = extract_query_from_searchlog(sid)

        # Get configuration fields from settings
        conf = settings.get('configuration', {})
        webhook_url = conf.get('url', '')
        username = conf.get('username', '')
        password = conf.get('password', '')
        description = conf.get('description', '')
        severity = conf.get('severity', '')
        kill_chain = conf.get('kill_chain', '')

        # Process MITRE fields (split by comma if multiple values exist)
        mitre_tactics_raw = conf.get('mitre_tactics', '')
        mitre_techniques_raw = conf.get('mitre_techniques', '')
        mitre_tactics = [x.strip() for x in mitre_tactics_raw.split(',') if x.strip()] if mitre_tactics_raw else []
        mitre_techniques = [x.strip() for x in mitre_techniques_raw.split(',') if x.strip()] if mitre_techniques_raw else []

        # Path to the gzipped CSV of results
        result_csv_gz = os.path.join(RESULTS_DIR, sid, "results.csv.gz")
        if not os.path.exists(result_csv_gz):
            sys.stderr.write(f"ERROR: No results file found for SID: {sid}\n")
            sys.exit(2)

        # Read CSV data from the gzipped file
        extracted_data = []
        with gzip.open(result_csv_gz, 'rt') as src:
            reader = csv.reader(src)
            for row in reader:
                extracted_data.append(row)

        # Filter out columns with headers starting with "__mv_"
        if extracted_data and extracted_data[0]:
            header = extracted_data[0]
            indices_to_keep = [i for i, field in enumerate(header) if not field.startswith("__mv_")]
            filtered_data = []
            for row in extracted_data:
                filtered_row = [row[i] for i in indices_to_keep]
                filtered_data.append(filtered_row)
            extracted_data = filtered_data

        # If there is no data row (only header or empty file), exit
        if len(extracted_data) < 2:
            sys.stderr.write("INFO: No data rows found (only headers or empty file).\n")
            sys.exit(0)

        # Separate header and data rows
        header = extracted_data[0]
        data_rows = extracted_data[1:]

        # Loop over each row and attempt to send a webhook for each row.
        # If sending fails, append it to the global PENDING_WEBHOOKS list.
        for i, row in enumerate(data_rows, start=1):
            row_data_dict = dict(zip(header, row))
            item = {
                "webhook_url": webhook_url,
                "username": username,
                "password": password,
                "sid": sid,
                "search_name": search_name,
                "search_query": search_query,
                "description": description,
                "severity": severity,
                "kill_chain": kill_chain,
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
                "row_number": i,
                "row_data": row_data_dict
            }
            if not send_webhook(item):
                PENDING_WEBHOOKS.append(item)

    except Exception as e:
        sys.stderr.write(f"ERROR: Unexpected error: {e}\n")
        sys.exit(3)
    finally:
        save_pending_webhooks()
