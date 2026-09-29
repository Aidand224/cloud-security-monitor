import sqlite3

connection = sqlite3.connect("security_monitor.db")
cursor = connection.cursor()

cursor.execute("PRAGMA table_info(alerts)")
existing_columns = [row[1] for row in cursor.fetchall()]

new_columns = {
    "country": "TEXT",
    "region": "TEXT",
    "city": "TEXT",
    "organization": "TEXT",
    "latitude": "REAL",
    "longitude": "REAL"
}

for column_name, column_type in new_columns.items():
    if column_name not in existing_columns:
        cursor.execute(
            f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}"
        )
        print(f"Added column: {column_name}")

connection.commit()
connection.close()

print("Database upgrade complete.")