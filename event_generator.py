from datetime import datetime, timedelta
import random
import csv

usernames = ["admin", "aidan", "guest", "jsmith", "mgarcia"]

# Normal internal network traffic
ip_addresses = [
    "192.168.1.10",
    "192.168.1.24",
    "10.0.0.15",
    "172.16.0.8"
]

# Simulated suspicious public IP activity
attack_scenarios = [
    {
        "ip": "8.8.8.8",
        "username": "admin",
        "failures": 15,
        "successful_login": True
    },
    {
        "ip": "1.1.1.1",
        "username": "jsmith",
        "failures": 12,
        "successful_login": False
    },
    {
        "ip": "208.67.222.222",
        "username": "mgarcia",
        "failures": 11,
        "successful_login": False
    }
]

with open("data/login_events.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "username",
        "ip_address",
        "status"
    ])

    # Generate normal login traffic
    for i in range(20):
        username = random.choice(usernames)
        ip_address = random.choice(ip_addresses)
        status = random.choice(["SUCCESS", "FAILED"])

        writer.writerow([
            datetime.now(),
            username,
            ip_address,
            status
        ])

    # Generate simulated attack traffic
    for attack in attack_scenarios:
        attacker_ip = attack["ip"]
        username = attack["username"]
        failures = attack["failures"]

        attack_start = datetime.now()

        # Generate failed login attempts
        for i in range(failures):
            timestamp = attack_start + timedelta(seconds=i * 3)

            writer.writerow([
                timestamp,
                username,
                attacker_ip,
                "FAILED"
            ])

        # Optionally simulate account compromise
        if attack["successful_login"]:
            success_time = attack_start + timedelta(
                seconds=failures * 3 + 2
            )

            writer.writerow([
                success_time,
                username,
                attacker_ip,
                "SUCCESS"
            ])

print("Login events saved successfully.")
print(f"Generated {len(attack_scenarios)} simulated attack scenarios.")