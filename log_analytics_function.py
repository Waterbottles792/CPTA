from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
import pandas as pd

LOG_ANALYTICS_WORKSPACE_ID = "289ad8c8-bf3f-4c11-b5a6-23d4a99e6d2a"

TABLE_NAME = "AzureActivity"  # DeviceLogonEvents, AzureNetworkAnalytics, AzureActivity, SigninLogs

# Keys are bare table names (match TABLE_NAME); the "_CL" suffix is added in the
# query. Columns carry _s/_d suffixes because the data lives in custom tables.
FIELDS = {
    "DeviceLogonEvents": "TimeGenerated, AccountName_s, DeviceName_s, ActionType_s, RemoteIP_s, RemoteDeviceName_s",
    "AzureNetworkAnalytics": "TimeGenerated, FlowType_s, SrcPublicIPs_s, DestIP_s, DestPort_d, VM_s, AllowedInFlows_d, AllowedOutFlows_d, DeniedInFlows_d, DeniedOutFlows_d",
    "AzureActivity": "TimeGenerated, OperationNameValue_s, ActivityStatusValue_s, ResourceGroup_s, Caller_s, CallerIpAddress_s, Category_s",
    "SigninLogs": "TimeGenerated, UserPrincipalName_s, OperationName_s, Category_s, ResultSignature_s, ResultDescription_s, AppDisplayName_s, IPAddress_s, LocationDetails_s",
}

HOURS_AGO = 24

# Need Azure CLI: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?view=azure-cli-latest&pivots=msi
log_analytics_client = LogsQueryClient(credential=DefaultAzureCredential())


def query_log_analytics(client, workspace_id, table, fields, timespan_hours_ago):

    kql_query = f'''
    {table}_CL
    | project {fields}
    '''

    print(kql_query)

    response = client.query_workspace(
        workspace_id=workspace_id,
        query=kql_query,
        timespan=timedelta(hours=timespan_hours_ago)
    )

    # Extract the table
    table_results = response.tables[0]

    return table_results


results = query_log_analytics(log_analytics_client, LOG_ANALYTICS_WORKSPACE_ID, TABLE_NAME, FIELDS[TABLE_NAME], HOURS_AGO)

if len(results.rows) == 0:
    print("No data returned from Log Analytics.")
    exit

# Extract columns and rows using dot notation
columns = results.columns  # Already a list of strings
rows = results.rows        # List of row data

df = pd.DataFrame(rows, columns=columns)
records = df.to_csv(index=False)

print(records)

print("fin.")
