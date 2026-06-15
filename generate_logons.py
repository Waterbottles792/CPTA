"""
Generate a synthetic DeviceLogonEvents-style dataset (made-up values) so the
SOC-analyst project has logon telemetry to hunt over -- a stand-in for real
Microsoft Defender DeviceLogonEvents.

Produces: devicelogonevents_synthetic.csv

The data is mostly benign internal logons, plus ONE embedded attack:
a public IP brute-forcing the 'administrator' account over RDP
(many LogonFailed, then a LogonSuccess). That's the signal the analyst
should detect.
"""
import csv
import random
import uuid
from datetime import datetime, timedelta, timezone

random.seed(42)

OUT = "devicelogonevents_synthetic.csv"
TENANT_ID = "289ad8c8-bf3f-4c11-b5a6-23d4a99e6d2a"
DOMAIN = "CONTOSO"

COLUMNS = [
    "Timestamp", "TenantId", "DeviceName", "DeviceId", "ActionType",
    "AccountDomain", "AccountName", "AccountSid", "LogonType", "Protocol",
    "FailureReason", "IsLocalAdmin", "RemoteIP", "RemoteIPType", "RemotePort",
    "RemoteDeviceName", "InitiatingProcessAccountName", "InitiatingProcessFileName",
    "ReportId",
]

NORMAL_USERS = ["jsmith", "mwong", "akhan", "rdavis", "lchen", "pgomez", "svc_backup"]
DEVICES = ["FIN-WS-01", "HR-WS-04", "ENG-WS-12", "DC-01", "FILE-SRV-02"]
PRIVATE_IPS = ["10.0.0.15", "10.0.0.22", "10.0.1.7", "192.168.1.30", "172.16.4.9"]


def sid() -> str:
    return f"S-1-5-21-{random.randint(10**8, 10**9)}-{random.randint(10**8, 10**9)}-{random.randint(1000, 9999)}"


def base_row(ts: datetime) -> dict:
    return {
        "Timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
        "TenantId": TENANT_ID,
        "DeviceId": uuid.uuid4().hex,
        "AccountDomain": DOMAIN,
        "ReportId": str(random.randint(1000, 99999)),
        "Protocol": "",
        "RemoteDeviceName": "",
    }


def benign_row(ts: datetime) -> dict:
    user = random.choice(NORMAL_USERS)
    row = base_row(ts)
    row.update({
        "DeviceName": random.choice(DEVICES),
        "ActionType": "LogonSuccess" if random.random() > 0.1 else "LogonFailed",
        "AccountName": user,
        "AccountSid": sid(),
        "LogonType": random.choice(["Interactive", "Network", "Batch"]),
        "FailureReason": "" if row.get("ActionType") == "LogonSuccess" else "",
        "IsLocalAdmin": random.choice(["true", "false", "false", "false"]),
        "RemoteIP": random.choice(PRIVATE_IPS),
        "RemoteIPType": "Private",
        "RemotePort": str(random.randint(1024, 65535)),
        "InitiatingProcessAccountName": user,
        "InitiatingProcessFileName": random.choice(["lsass.exe", "winlogon.exe", "svchost.exe"]),
    })
    # FailureReason only meaningful on failures
    if row["ActionType"] == "LogonFailed":
        row["FailureReason"] = "IncorrectPassword"
    return row


def attack_rows(start: datetime) -> list[dict]:
    """RDP brute force from one public IP against 'administrator'."""
    attacker_ip = "45.137.21.9"
    rows = []
    ts = start
    for i in range(40):                      # 40 rapid failed attempts
        ts += timedelta(seconds=random.randint(2, 8))
        row = base_row(ts)
        row.update({
            "DeviceName": "DC-01",
            "ActionType": "LogonFailed",
            "AccountName": "administrator",
            "AccountSid": "S-1-5-21-1004336348-1177238915-682003330-500",
            "LogonType": "RemoteInteractive",
            "Protocol": "RDP",
            "FailureReason": "IncorrectPassword",
            "IsLocalAdmin": "true",
            "RemoteIP": attacker_ip,
            "RemoteIPType": "Public",
            "RemotePort": str(random.randint(40000, 60000)),
            "RemoteDeviceName": "kali",
            "InitiatingProcessAccountName": "",
            "InitiatingProcessFileName": "svchost.exe",
        })
        rows.append(row)
    # the breach: one success after the storm
    ts += timedelta(seconds=5)
    row = base_row(ts)
    row.update({
        "DeviceName": "DC-01",
        "ActionType": "LogonSuccess",
        "AccountName": "administrator",
        "AccountSid": "S-1-5-21-1004336348-1177238915-682003330-500",
        "LogonType": "RemoteInteractive",
        "Protocol": "RDP",
        "FailureReason": "",
        "IsLocalAdmin": "true",
        "RemoteIP": attacker_ip,
        "RemoteIPType": "Public",
        "RemotePort": str(random.randint(40000, 60000)),
        "RemoteDeviceName": "kali",
        "InitiatingProcessAccountName": "administrator",
        "InitiatingProcessFileName": "winlogon.exe",
    })
    rows.append(row)
    return rows


def main() -> None:
    now = datetime.now(timezone.utc)
    rows = []

    # ~260 benign logons spread over the last 24h
    for _ in range(260):
        ts = now - timedelta(minutes=random.randint(0, 1440))
        rows.append(benign_row(ts))

    # attack burst ~3h ago
    rows.extend(attack_rows(now - timedelta(hours=3)))

    rows.sort(key=lambda r: r["Timestamp"])

    with open(OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in COLUMNS})

    print(f"Wrote {len(rows)} rows to {OUT}")
    print("Includes a 40-attempt RDP brute force from 45.137.21.9 vs 'administrator' (then 1 success).")


if __name__ == "__main__":
    main()
