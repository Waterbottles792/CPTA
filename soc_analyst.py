from google import genai
from colorama import init
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta
import os
import pandas as pd

init(autoreset=True)

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------

# Read the API key from the environment instead of hardcoding it.
# Set it first:  export GEMINI_API_KEY="your-key"
GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]

WORKSPACE_ID = "289ad8c8-bf3f-4c11-b5a6-23d4a99e6d2a"

MODEL = "gemini-2.5-flash"

MAX_OUTPUT_TOKENS = 5000

HOURS_AGO = 720  # 30 days (synthetic data is older than a few hours)

KQL_QUERY = """
DeviceLogonEvents_CL
| where ActionType_s == "LogonFailed" or LogonType_s in ("Network", "RemoteInteractive")
| project TimeGenerated, DeviceName_s, AccountName_s, AccountDomain_s,
          ActionType_s, LogonType_s, FailureReason_s,
          RemoteIP_s, RemoteIPType_s, IsLocalAdmin_b, InitiatingProcessFileName_s
| order by TimeGenerated desc
| take 200
"""

# Approximate Gemini pricing
INPUT_COST_PER_MILLION = 0.30
OUTPUT_COST_PER_MILLION = 2.50

# ------------------------------------------------------------------
# GEMINI CLIENT
# ------------------------------------------------------------------

gemini_client = genai.Client(
    api_key=GEMINI_API_KEY
)

# ------------------------------------------------------------------
# AZURE LOG ANALYTICS
# ------------------------------------------------------------------

log_analytics_client = LogsQueryClient(
    credential=DefaultAzureCredential()
)


def query_log_analytics(
    client,
    workspace_id,
    query,
    hours_ago
):
    response = client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=timedelta(hours=hours_ago)
    )

    if not response.tables:
        raise Exception("No tables returned.")

    table = response.tables[0]

    if len(table.rows) == 0:
        raise Exception("No rows returned.")

    columns = table.columns
    rows = table.rows

    df = pd.DataFrame(
        rows,
        columns=columns
    )

    return df.to_csv(index=False)

# ------------------------------------------------------------------
# GET LOGS
# ------------------------------------------------------------------


logs = query_log_analytics(
    client=log_analytics_client,
    workspace_id=WORKSPACE_ID,
    query=KQL_QUERY,
    hours_ago=HOURS_AGO
)

# ------------------------------------------------------------------
# BUILD PROMPT
# ------------------------------------------------------------------

prompt = f"""
You are a senior SOC analyst.

Analyze the following logs.

Tasks:
1. Identify suspicious activity
2. Identify indicators of compromise
3. Assign severity
4. Map to MITRE ATT&CK where possible
5. Recommend remediation actions

Logs:

{logs}
"""

# ------------------------------------------------------------------
# TOKEN ESTIMATION
# ------------------------------------------------------------------

token_info = gemini_client.models.count_tokens(
    model=MODEL,
    contents=prompt
)

estimated_input_tokens = token_info.total_tokens

estimated_input_cost = (
    estimated_input_tokens / 1_000_000
) * INPUT_COST_PER_MILLION

estimated_output_cost = (
    MAX_OUTPUT_TOKENS / 1_000_000
) * OUTPUT_COST_PER_MILLION

estimated_total_cost = (
    estimated_input_cost +
    estimated_output_cost
)

print("\n===== ESTIMATE =====\n")

print(
    f"Estimated Input Tokens : {estimated_input_tokens}"
)

print(
    f"Estimated Output Tokens: {MAX_OUTPUT_TOKENS}"
)

print(
    f"Estimated Cost         : ${estimated_total_cost:.6f}"
)

input(
    f"\nPress Enter to proceed with {MODEL}..."
)

# ------------------------------------------------------------------
# GEMINI ANALYSIS
# ------------------------------------------------------------------

response = gemini_client.models.generate_content(
    model=MODEL,
    contents=prompt
)

# ------------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------------

print("\n===== THREAT HUNT RESULTS =====\n")

print(response.text)

# ------------------------------------------------------------------
# USAGE METRICS
# ------------------------------------------------------------------

if hasattr(response, "usage_metadata"):

    usage = response.usage_metadata

    prompt_tokens = usage.prompt_token_count
    completion_tokens = usage.candidates_token_count
    total_tokens = usage.total_token_count

    actual_input_cost = (
        prompt_tokens / 1_000_000
    ) * INPUT_COST_PER_MILLION

    actual_output_cost = (
        completion_tokens / 1_000_000
    ) * OUTPUT_COST_PER_MILLION

    actual_total_cost = (
        actual_input_cost +
        actual_output_cost
    )

    print("\n===== TOKEN USAGE =====\n")

    print(
        f"Prompt Tokens   : {prompt_tokens}"
    )

    print(
        f"Response Tokens : {completion_tokens}"
    )

    print(
        f"Total Tokens    : {total_tokens}"
    )

    print(
        f"Actual Cost     : ${actual_total_cost:.6f}"
    )

print("\nfin.")
