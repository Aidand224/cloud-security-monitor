import streamlit as st
import sqlite3
import pandas as pd
import csv

st.set_page_config(
    page_title="Cloud Security Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cloud Security Monitor")
st.caption("Real-Time Authentication Threat Detection & Security Analytics")

st.markdown(
    """
    Monitor authentication activity, detect suspicious login behavior,
    investigate security alerts, and analyze the geographic origin of threats.
    """
)

# -----------------------------
# Load data
# -----------------------------

# Create and populate the database if it does not exist
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

cursor.execute("SELECT COUNT(*) FROM login_events")
event_count = cursor.fetchone()[0]

if event_count == 0:
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

connection = sqlite3.connect("security_monitor.db")

login_events = pd.read_sql_query(
    "SELECT * FROM login_events",
    connection
)

alerts = pd.read_sql_query(
    "SELECT * FROM alerts",
    connection
)

connection.close()

# -----------------------------
# Clean timestamps
# -----------------------------
if not login_events.empty:
    login_events["timestamp"] = pd.to_datetime(
        login_events["timestamp"],
        errors="coerce"
    )

if not alerts.empty:
    alerts["timestamp"] = pd.to_datetime(
        alerts["timestamp"],
        errors="coerce"
    )

# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.header("🔎 Filters")

if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

status_filter = st.sidebar.selectbox(
    "Login Status",
    ["ALL", "SUCCESS", "FAILED"]
)

username_filter = st.sidebar.selectbox(
    "Username",
    ["ALL"] + sorted(login_events["username"].dropna().unique().tolist())
)

ip_filter = st.sidebar.selectbox(
    "IP Address",
    ["ALL"] + sorted(login_events["ip_address"].dropna().unique().tolist())
)

st.sidebar.divider()

severity_filter = st.sidebar.selectbox(
    "Alert Severity",
    ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

# -----------------------------
# Metrics
# -----------------------------
total_logins = len(login_events)

successful_logins = len(
    login_events[login_events["status"] == "SUCCESS"]
)

failed_logins = len(
    login_events[login_events["status"] == "FAILED"]
)

total_alerts = len(alerts)

critical_alerts = len(
    alerts[alerts["severity"] == "CRITICAL"]
) if not alerts.empty else 0

high_alerts = len(
    alerts[alerts["severity"] == "HIGH"]
) if not alerts.empty else 0

col1, col2, col3, col4, col5, col6 = st.columns(6)

col1.metric("Total Logins", total_logins)
col2.metric("Successful", successful_logins)
col3.metric("Failed", failed_logins)
col4.metric("Total Alerts", total_alerts)
col5.metric("Critical", critical_alerts)
col6.metric("High", high_alerts)

if critical_alerts > 0:
    st.error(
        f"🚨 ATTENTION: {critical_alerts} critical security "
        f"alert{'s' if critical_alerts != 1 else ''} detected."
    )
elif high_alerts > 0:
    st.warning(
        f"⚠️ {high_alerts} high-severity security "
        f"alert{'s' if high_alerts != 1 else ''} detected."
    )
else:
    st.success("✅ No high-severity threats detected.")

st.divider()

# -----------------------------
# Login activity
# -----------------------------
left, right = st.columns(2)

with left:
    st.subheader("📊 Login Activity")

    login_status_counts = (
        login_events["status"]
        .value_counts()
    )

    st.bar_chart(login_status_counts)

with right:
    st.subheader("🌐 Failed Attempts by IP")

    failed_by_ip = (
        login_events[login_events["status"] == "FAILED"]
        .groupby("ip_address")
        .size()
        .sort_values(ascending=False)
    )

    st.bar_chart(failed_by_ip)

# -----------------------------
# Suspicious IP
# -----------------------------
st.subheader("⚠️ Suspicious IP Summary")

if not failed_by_ip.empty:
    top_ip = failed_by_ip.index[0]
    top_failures = int(failed_by_ip.iloc[0])

    st.warning(
        f"Most suspicious IP: {top_ip} "
        f"with {top_failures} failed login attempts."
    )
else:
    st.success("No suspicious failed-login activity detected.")

# -----------------------------
# Security alerts
# -----------------------------
st.subheader("🚨 Security Alerts")

filtered_alerts = alerts.copy()

if severity_filter != "ALL":
    filtered_alerts = filtered_alerts[
        filtered_alerts["severity"] == severity_filter
    ]

if filtered_alerts.empty:
    st.success("No security alerts match the current filter.")
else:
    alert_columns = [
        "timestamp",
        "alert_type",
        "severity",
        "ip_address",
        "failed_attempts",
        "country",
        "region",
        "city",
        "organization"
    ]

    available_columns = [
        column
        for column in alert_columns
        if column in filtered_alerts.columns
    ]

    display_alerts = filtered_alerts[
        available_columns
    ].sort_values(
        "timestamp",
        ascending=False
    ).copy()

    display_alerts = display_alerts.rename(columns={
        "timestamp": "Time",
        "alert_type": "Alert Type",
        "severity": "Severity",
        "ip_address": "Source IP",
        "failed_attempts": "Failed Attempts",
        "country": "Country",
        "region": "Region",
        "city": "City",
        "organization": "Organization"
    })

    st.dataframe(
        display_alerts,
        width="stretch",
        hide_index=True,
        column_config={
            "Time": st.column_config.DatetimeColumn(
                "Time",
                format="MM/DD/YYYY HH:mm:ss"
            ),
            "Severity": st.column_config.TextColumn(
                "Severity"
            ),
            "Source IP": st.column_config.TextColumn(
                "Source IP"
            ),
            "Failed Attempts": st.column_config.NumberColumn(
                "Failed Attempts",
                format="%d"
            )
        }
    )
# -----------------------------
# Map
# -----------------------------
st.subheader("🗺️ Alert Locations")

if (
    not alerts.empty
    and "latitude" in alerts.columns
    and "longitude" in alerts.columns
):
    map_data = alerts[
        ["latitude", "longitude"]
    ].dropna()

    if not map_data.empty:
        map_data = map_data.rename(
            columns={
                "latitude": "lat",
                "longitude": "lon"
            }
        )

        st.map(map_data)
    else:
        st.info(
            "No geographic coordinates available yet. "
            "Reserved or private IP addresses cannot be mapped."
        )
else:
    st.info("No geographic alert data available yet.")

# -----------------------------
# Recent login activity
# -----------------------------
st.subheader("📋 Recent Login Activity")

filtered_events = login_events.copy()

if status_filter != "ALL":
    filtered_events = filtered_events[
        filtered_events["status"] == status_filter
    ]

if username_filter != "ALL":
    filtered_events = filtered_events[
        filtered_events["username"] == username_filter
    ]

if ip_filter != "ALL":
    filtered_events = filtered_events[
        filtered_events["ip_address"] == ip_filter
    ]

filtered_events = filtered_events.sort_values(
    "timestamp",
    ascending=False
)

st.dataframe(
    filtered_events,
    width="stretch",
    hide_index=True
)