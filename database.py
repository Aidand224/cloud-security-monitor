import sqlite3
import csv

connection = sqlite3.connect("security_monitor.db")
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    username TEXT,
    ip_address TEXT,
    status TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    ip_address TEXT,
    failed_attempts INTEGER,
    severity TEXT
)
""")

with open("data/login_events.csv", "r") as file:
    reader = csv.DictReader(file)

    for event in reader:
        cursor.execute("""
        INSERT INTO login_events (
            timestamp,
            username,
            ip_address,
            status
        )
        VALUES (?, ?, ?, ?)
        """, (
            event["timestamp"],
            event["username"],
            event["ip_address"],
            event["status"]
        ))

connection.commit()
connection.close()

print("Database created and login events imported.")