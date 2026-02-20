import csv
import os
from datetime import datetime

# Create logs folder if not exists
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "security_log.csv")

os.makedirs(LOG_DIR, exist_ok=True)


def log_event(attack_type, action):
    """
    attack_type: string (DoS, Probe, etc.)
    action: string ("ALLOWED" or "BLOCKED")
    """

    file_exists = os.path.isfile(LOG_FILE)

    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)

        # Write header only once
        if not file_exists:
            writer.writerow(["timestamp", "attack_type", "action"])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_type,
            action
        ])
