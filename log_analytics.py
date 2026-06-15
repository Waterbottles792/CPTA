from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
import pandas as pd

LOG_ANALYTICS_WORKSPACE_ID = "289ad8c8-bf3f-4c11-b5a6-23d4a99e6d2a"

# Need Azure CLI: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?view=azure-cli-latest&pivots=msi
log_analytics_client = LogsQueryClient(credential=DefaultAzureCredential())

hours_ago = 24

kql_query = f"""
DeviceLogonEvents_CL
| take 10
"""

response = log_analytics_client.query_workspace(
    workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
    query=kql_query,
    timespan=timedelta(hours=hours_ago),
)

# Extract the table
table = response.tables[0]

if len(response.tables[0].rows) == 0:
    print("No data returned from Log Analytics.")
    exit

print(table)

columns = table.columns
rows = table.rows

print(columns)
print(rows)

# # TODO: Handle if returns 0 events
# record_count = len(response.tables[0].rows)

# # Extract columns and rows using dot notation
# columns = table.columns  # Already a list of strings
# rows = table.rows  # List of row data

# df = pd.DataFrame(rows, columns=columns)
# records = df.to_csv(index=False)

# print(records)

# print("fin.")
