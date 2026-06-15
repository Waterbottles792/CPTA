# Standard library
from datetime import timedelta
import json

# Third-party libraries
import pandas as pd
from colorama import Fore, Style
from google.genai import types
from google.genai import errors as genai_errors

# Local modules
import PROMPT_MANAGEMENT

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
            ),
        )

        return json.loads(response.text)

    except genai_errors.ClientError as e:
        # 4xx — most commonly 429 (rate limit) or an input that is too large.
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
# whose keys match the query-context the rest of the pipeline expects. The
# tool-selection system prompt already enumerates every parameter, and we
# re-list the required keys to guarantee a complete object.
def get_log_query_from_agent(gemini_client, user_message, model):

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

