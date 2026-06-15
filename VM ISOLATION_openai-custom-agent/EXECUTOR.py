# Standard library
from datetime import timedelta
import json

# Third-party libraries
import pandas as pd
from colorama import Fore, Style
from google.genai import types
from google.genai import errors as genai_errors
from azure.identity import DefaultAzureCredential
import requests, urllib.parse


# Local modules
# Local modules
import PROMPT_MANAGEMENT


def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token

def get_mde_workstation_id_from_name(token, device_name):
    """
    Look up a Defender for Endpoint machine ID by device name.
    Works if the user provides either the FQDN or just the short hostname.
    
    Args:
        token: an Azure Identity token (DefaultAzureCredential or similar)
        device_name: short hostname or full FQDN string

    Returns:
        The machine ID (string)

    Raises:
        Exception if no matches are found.
    """
    headers = {"Authorization": f"Bearer {token.token}"}

    # Use 'startswith' so "linux-target-1" will match
    # "linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No machine found starting with {device_name}")

    # If multiple machines match, pick the first. 
    # You could add logic here (e.g., choose the most recent 'lastSeen').
    machine_id = machines[0]["id"]
    return machine_id


def quarantine_virtual_machine(token, machine_id):

    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }

    # Example: Isolate a machine
    payload = {
        "Comment": "Isolation via Python Agentic AI using DefaultAzureCredential",
        "IsolationType": "Full"
    }

    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )

    if resp.status_code == 201 or 200:
        return True
    return False

def hunt(gemini_client, threat_hunt_system_message, threat_hunt_user_message, gemini_model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array
    Handles rate-limit/token overage errors gracefully.
    """

    try:
        response = gemini_client.models.generate_content(
            model=gemini_model,
            contents=threat_hunt_user_message["content"],
            config=types.GenerateContentConfig(
                system_instruction=threat_hunt_system_message["content"],
                response_mime_type="application/json",
                max_output_tokens=65536,
            ),
        )

        return json.loads(response.text)

    except json.JSONDecodeError:
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}ERROR: Gemini returned invalid or truncated JSON.{Style.RESET_ALL}")
        print(f"{Fore.WHITE}The response was likely cut off (too many logs/findings). "
              f"Try a narrower query — a single host or a shorter time range.\n")
        return None

    except genai_errors.ClientError as e:
        error_msg = str(e)

        # Print dark red warning
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}The input was too large for this model or hit rate limits.")
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print(f"- Use fewer logs or reduce input size.")
        print(f"- Switch to a model with a larger context window.")
        print(f"- Retry later if rate-limited.\n")

        return None  # You can also choose to raise again or exit

    except genai_errors.APIError as e:
        print(f"{Fore.RED}Unexpected Gemini API error:\n{e}")
        return None

# Ask the model to choose where/how to search and return the query parameters.
# OpenAI's function-calling is replaced here with Gemini structured JSON output
# (response_mime_type="application/json"): the model returns a single JSON object
# whose keys match the query-context the rest of the pipeline expects.
def get_query_context(gemini_client, user_message, model):

    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")

    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION

    contents = (
        user_message["content"]
        + "\n\nReturn ONLY a JSON object (no prose, no markdown) with exactly these keys: "
        + ", ".join(PROMPT_MANAGEMENT.TOOL_PARAM_KEYS)
        + ". Use \"\" for unknown text fields, false for unknown booleans, and [] for unknown arrays. Never omit a key."
    )

    response = gemini_client.models.generate_content(
        model=model,
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=system_message["content"],
            response_mime_type="application/json",
            temperature=0,
        ),
    )

    args = json.loads(response.text)

    return args


def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name):

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}'''
        
    elif table_name == "AzureActivity":
        user_query = f'''{table_name}
| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")
| where Caller startswith "{caller}"
| project {fields}'''
        
    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{user_principal_name}"
| project {fields}'''

    elif table_name == "DeviceLogonEvents":
        # This workspace stores logon data in the custom DeviceLogonEvents_CL
        # table, where columns carry _s/_d suffixes. Map the bare field names the
        # model chose to their _CL equivalents (TimeGenerated keeps its name).
        mapped_fields = ", ".join(
            f.strip() if f.strip() == "TimeGenerated" else f"{f.strip()}_s"
            for f in fields.split(",")
        )
        user_query = f'''DeviceLogonEvents_CL
| where DeviceName_s startswith "{device_name}"
| project {mapped_fields}
| order by TimeGenerated desc
| take 200'''

    else:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}'''
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }
    
    # Extract the table
    table = response.tables[0]

    # TODO: Handle if returns 0 events
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return { "records": records, "count": record_count }

