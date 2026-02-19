import random
import time
from datetime import datetime, timedelta

# -----------------------------
# Configuration
# -----------------------------
LOG_TYPES = [
    ("LOGIN_SUCCESS", 0),
    ("LOGIN_FAILED", 2),
    ("BRUTE_FORCE_ATTEMPT", 5),
    ("SQL_INJECTION_DETECTED", 8),
    ("XSS_ATTACK_DETECTED", 7),
    ("MALWARE_SIGNATURE_FOUND", 10),
    ("UNAUTHORIZED_ACCESS", 6),
    ("PORT_SCAN_DETECTED", 4),
    ("DDOS_TRAFFIC_SPIKE", 9),
    ("PHISHING_ATTEMPT", 5)
]

IP_POOL = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.12",
    "203.45.67.89",
    "185.199.110.153",
    "66.249.66.1",
    "45.33.32.156"
]

USERS = ["admin", "guest", "root", "user1", "developer", "test"]

# -----------------------------
# Generate Random Timestamp
# -----------------------------
def random_timestamp():
    start = datetime.now() - timedelta(days=1)
    random_time = start + timedelta(seconds=random.randint(0, 86400))
    return random_time.strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------
# Generate Single Log Line
# -----------------------------
def generate_log():
    event, score = random.choice(LOG_TYPES)
    ip = random.choice(IP_POOL)
    user = random.choice(USERS)
    timestamp = random_timestamp()

    log_line = f"{timestamp} | IP:{ip} | USER:{user} | EVENT:{event} | SCORE:{score}"
    return log_line

# -----------------------------
# Generate Log File
# -----------------------------
def generate_log_file(filename="logs.txt", num_logs=100):
    with open(filename, "w") as f:
        for _ in range(num_logs):
            f.write(generate_log() + "\n")

    print(f"\n✅ Generated {num_logs} logs in {filename}")

# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        num_logs = int(sys.argv[1])
    else:
        num_logs = 100

    generate_log_file("logs.txt", num_logs)
