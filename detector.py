import csv
import sqlite3
from datetime import datetime, timedelta
from ip_enrichment import enrich_ip


DATABASE = "security_monitor.db"
EVENT_FILE = "data/login_events.csv"

failed_attempts = {}
successful_logins = []


# -----------------------------------
# Load login events
# -----------------------------------
with open(EVENT_FILE, "r") as file:
    reader = csv.DictReader(file)

    for event in reader:
        timestamp = datetime.fromisoformat(event["timestamp"])
        ip_address = event["ip_address"]

        if event["status"] == "FAILED":

            if ip_address not in failed_attempts:
                failed_attempts[ip_address] = []

            failed_attempts[ip_address].append(timestamp)

        elif event["status"] == "SUCCESS":

            successful_logins.append({
                "username": event["username"],
                "ip_address": ip_address,
                "timestamp": timestamp
            })


# -----------------------------------
# Helper function for saving alerts
# -----------------------------------
def save_alert(
    alert_type,
    ip_address,
    failed_count,
    severity,
    ip_info
):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE alert_type = ?
        AND ip_address = ?
        AND failed_attempts = ?
    """, (
        alert_type,
        ip_address,
        failed_count
    ))

    existing_alert = cursor.fetchone()

    if existing_alert is not None:
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            ip_address,
            failed_attempts,
            severity,
            country,
            region,
            city,
            organization,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        alert_type,
        ip_address,
        failed_count,
        severity,
        ip_info["country"],
        ip_info["region"],
        ip_info["city"],
        ip_info["organization"],
        ip_info["latitude"],
        ip_info["longitude"]
    ))

    connection.commit()
    connection.close()

    return True


# -----------------------------------
# Detect brute-force attacks
# -----------------------------------
for ip_address, timestamps in failed_attempts.items():

    timestamps.sort()

    for i in range(len(timestamps)):

        window_start = timestamps[i]
        window_end = window_start + timedelta(minutes=2)

        attempts_in_window = [
            time
            for time in timestamps
            if window_start <= time <= window_end
        ]

        if len(attempts_in_window) >= 10:

            print("\nSECURITY ALERT")
            print("Possible brute-force attack detected!")
            print("IP Address:", ip_address)
            print(
                "Failed Attempts:",
                len(attempts_in_window)
            )
            print("Time Window: 2 minutes")

            ip_info = enrich_ip(ip_address)

            print("Country:", ip_info["country"])
            print("Region:", ip_info["region"])
            print("City:", ip_info["city"])
            print(
                "Organization:",
                ip_info["organization"]
            )

            saved = save_alert(
                "Brute Force",
                ip_address,
                len(attempts_in_window),
                "HIGH",
                ip_info
            )

            if saved:
                print("Alert saved to database.")
            else:
                print(
                    "Duplicate brute-force "
                    "alert skipped."
                )

            # One brute-force alert per IP per run
            break


# -----------------------------------
# Detect successful login after
# repeated failures
# -----------------------------------
for login in successful_logins:

    ip_address = login["ip_address"]
    login_time = login["timestamp"]

    if ip_address not in failed_attempts:
        continue

    recent_failures = [
        time
        for time in failed_attempts[ip_address]
        if (
            login_time - timedelta(minutes=2)
            <= time
            < login_time
        )
    ]

    if len(recent_failures) >= 5:

        print("\nSECURITY ALERT")
        print(
            "Successful login after "
            "repeated failures!"
        )
        print("IP Address:", ip_address)
        print("Username:", login["username"])
        print(
            "Previous Failed Attempts:",
            len(recent_failures)
        )

        ip_info = enrich_ip(ip_address)

        print("Country:", ip_info["country"])
        print("Region:", ip_info["region"])
        print("City:", ip_info["city"])
        print(
            "Organization:",
            ip_info["organization"]
        )

        saved = save_alert(
            "Successful Login After Failures",
            ip_address,
            len(recent_failures),
            "CRITICAL",
            ip_info
        )

        if saved:
            print(
                "Compromise alert saved "
                "to database."
            )
        else:
            print(
                "Duplicate compromise "
                "alert skipped."
            )