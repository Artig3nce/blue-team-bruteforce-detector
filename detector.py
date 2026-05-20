from collections import defaultdict
import re

# Store failed attempts
failed_attempts = defaultdict(int)

# Threshold for alert
THRESHOLD = 3

# Open log file
with open("sample_logs.txt", "r") as file:
    logs = file.readlines()

# Analyze logs
for line in logs:

    # Search for failed login IP
    match = re.search(r"Failed login from (\d+\.\d+\.\d+\.\d+)", line)

    if match:
        ip = match.group(1)
        failed_attempts[ip] += 1

# Generate alerts
for ip, count in failed_attempts.items():
    if count >= THRESHOLD:

        alert_message = f"[ALERT] Possible brute-force attack from {ip} ({count} failed attempts)"

        print(alert_message)

        # Save alerts
        with open("alerts.txt", "a") as alert_file:
            alert_file.write(alert_message + "\n")