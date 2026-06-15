"""
Generate synthetic Azure/Sentinel log datasets (made-up values) for the SOC
analyst project. Column names match the course's FIELDS map (the Data Collector
API adds _s/_d suffixes on ingest, and the table name gets a _CL suffix).

Produces:
    signinlogs_synthetic.csv             -> ingest as SigninLogs
    azureactivity_synthetic.csv          -> ingest as AzureActivity
    azurenetworkanalytics_synthetic.csv  -> ingest as AzureNetworkAnalytics

Course FIELDS this matches:
    SigninLogs: TimeGenerated, UserPrincipalName, OperationName, Category,
        ResultSignature, ResultDescription, AppDisplayName, IPAddress, LocationDetails
    AzureActivity: TimeGenerated, OperationNameValue, ActivityStatusValue,
        ResourceGroup, Caller, CallerIpAddress, Category
    AzureNetworkAnalytics_CL: TimeGenerated, FlowType, SrcPublicIPs, DestIP,
        DestPort, VM, AllowedInFlows, AllowedOutFlows, DeniedInFlows, DeniedOutFlows
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone

random.seed(7)
NOW = datetime.now(timezone.utc)


def ts(minutes_ago: int) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


def loc(city: str, state: str, country: str) -> str:
    return json.dumps({"city": city, "state": state, "countryOrRegion": country})


def write_csv(path: str, rows: list[dict]) -> None:
    cols = list(rows[0].keys())
    rows.sort(key=lambda r: r["TimeGenerated"])
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})
    print(f"Wrote {len(rows):>4} rows -> {path}")


# --------------------------------------------------------------------------- #
# SigninLogs
# --------------------------------------------------------------------------- #
def gen_signinlogs() -> None:
    users = ["jsmith", "mwong", "akhan", "rdavis", "lchen", "pgomez", "tnguyen"]
    apps = ["Office 365 Exchange Online", "Azure Portal", "Microsoft Teams",
            "SharePoint Online", "Power BI"]
    good = [("203.0.113.10", "New York", "NY", "US"),
            ("203.0.113.45", "Austin", "TX", "US"),
            ("198.51.100.7", "Seattle", "WA", "US")]
    rows = []

    def row(t, upn, sig, desc, app, ip, location):
        return {
            "TimeGenerated": t, "UserPrincipalName": upn,
            "OperationName": "Sign-in activity", "Category": "SignInLogs",
            "ResultSignature": sig, "ResultDescription": desc,
            "AppDisplayName": app, "IPAddress": ip, "LocationDetails": location,
        }

    # benign
    for _ in range(220):
        u = random.choice(users)
        ip, city, st, ctry = random.choice(good)
        ok = random.random() > 0.12
        rows.append(row(
            ts(random.randint(0, 1440)), f"{u}@contoso.com",
            "SUCCESS" if ok else "50126",
            "" if ok else "Invalid username or password",
            random.choice(apps), ip, loc(city, st, ctry),
        ))

    # ATTACK 1: password spray from a Tor exit node across many users
    for i, u in enumerate(users * 3):
        rows.append(row(
            ts(180 - i % 20), f"{u}@contoso.com", "50126",
            "Invalid username or password", "Azure Portal",
            "185.220.101.5", loc("Unknown", "", "RU"),
        ))

    # ATTACK 2: impossible travel -- jsmith succeeds NY then Moscow 8 min apart
    rows.append(row(ts(200), "jsmith@contoso.com", "SUCCESS", "",
                    "Office 365 Exchange Online", "203.0.113.10",
                    loc("New York", "NY", "US")))
    rows.append(row(ts(192), "jsmith@contoso.com", "SUCCESS", "",
                    "Office 365 Exchange Online", "91.108.23.44",
                    loc("Moscow", "", "RU")))

    write_csv("signinlogs_synthetic.csv", rows)


# --------------------------------------------------------------------------- #
# AzureActivity
# --------------------------------------------------------------------------- #
def gen_azureactivity() -> None:
    callers = ["jsmith@contoso.com", "mwong@contoso.com", "svc-deploy@contoso.com"]
    rgs = ["rg-prod-app", "rg-network", "rg-data", "rg-identity"]
    benign_ops = [
        "MICROSOFT.COMPUTE/VIRTUALMACHINES/READ",
        "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
        "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
        "MICROSOFT.WEB/SITES/RESTART/ACTION",
        "MICROSOFT.KEYVAULT/VAULTS/READ",
    ]
    rows = []

    def row(t, op, status, caller, ip):
        return {
            "TimeGenerated": t, "OperationNameValue": op,
            "ActivityStatusValue": status, "ResourceGroup": random.choice(rgs),
            "Caller": caller, "CallerIpAddress": ip, "Category": "Administrative",
        }

    for _ in range(160):
        rows.append(row(
            ts(random.randint(0, 1440)), random.choice(benign_ops),
            random.choice(["Success", "Start", "Accept"]),
            random.choice(callers), random.choice(["203.0.113.10", "198.51.100.7"]),
        ))

    # ATTACK: priv-esc + firewall tamper + secret dump from one public IP
    rows.append(row(ts(150), "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
                    "Success", "attacker@contoso.com", "45.137.21.9"))
    for i in range(3):
        rows.append(row(ts(148 - i),
                        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
                        "Success", "attacker@contoso.com", "45.137.21.9"))
    rows.append(row(ts(145), "MICROSOFT.KEYVAULT/VAULTS/SECRETS/READ",
                    "Success", "attacker@contoso.com", "45.137.21.9"))

    write_csv("azureactivity_synthetic.csv", rows)


# --------------------------------------------------------------------------- #
# AzureNetworkAnalytics  (NSG flow logs / Traffic Analytics)
# --------------------------------------------------------------------------- #
def gen_networkanalytics() -> None:
    vms = ["vm-web-01", "vm-app-02", "vm-db-03"]
    rows = []

    def row(t, ftype, src, dst, port, vm, ain, aout, din, dout):
        return {
            "TimeGenerated": t, "FlowType": ftype, "SrcPublicIPs": src,
            "DestIP": dst, "DestPort": port, "VM": vm,
            "AllowedInFlows": ain, "AllowedOutFlows": aout,
            "DeniedInFlows": din, "DeniedOutFlows": dout,
        }

    # benign allowed traffic
    for _ in range(180):
        rows.append(row(
            ts(random.randint(0, 1440)), "ExternalPublic",
            random.choice(["52.10.20.30", "13.107.42.14", "20.190.130.1"]),
            random.choice(["10.0.1.10", "10.0.1.11", "10.0.2.20"]),
            random.choice([443, 80, 1433]), random.choice(vms),
            random.randint(5, 200), random.randint(5, 200), 0, 0,
        ))

    # ATTACK 1: port scan -- one external IP, many ports, all DENIED inbound
    for port in [21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5985, 8080, 8443]:
        rows.append(row(
            ts(random.randint(160, 175)), "ExternalPublic", "45.137.21.9",
            "10.0.1.10", port, "vm-web-01", 0, 0, random.randint(30, 90), 0,
        ))

    # ATTACK 2: data exfil -- DB VM, huge ALLOWED outbound to external IP
    for i in range(6):
        rows.append(row(
            ts(140 - i), "ExternalPublic", "194.26.135.7",
            "194.26.135.7", 443, "vm-db-03",
            0, random.randint(8000, 25000), 0, 0,
        ))

    write_csv("azurenetworkanalytics_synthetic.csv", rows)


if __name__ == "__main__":
    gen_signinlogs()
    gen_azureactivity()
    gen_networkanalytics()
    print("\nIngest each with:")
    print("  python ingest_to_loganalytics.py signinlogs_synthetic.csv SigninLogs")
    print("  python ingest_to_loganalytics.py azureactivity_synthetic.csv AzureActivity")
    print("  python ingest_to_loganalytics.py azurenetworkanalytics_synthetic.csv AzureNetworkAnalytics")
