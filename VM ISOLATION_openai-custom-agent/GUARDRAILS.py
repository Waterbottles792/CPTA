from colorama import Fore, Style

# TODO: Provide allowed fields later
ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

# Gemini models. Context windows are exact; pricing is approximate (USD per
# million tokens, paid tier) — confirm against current Gemini pricing:
# https://ai.google.dev/gemini-api/docs/pricing
# "tier" is kept only for compatibility with the rate-limit display logic;
# Gemini's RPM/TPM limits differ from OpenAI's tier system, so values are None.
ALLOWED_MODELS = {
    "gemini-2.5-flash":      {"max_input_tokens": 1_048_576, "max_output_tokens": 65_536, "cost_per_million_input": 0.30, "cost_per_million_output": 2.50,  "tier": {"1": None}},
    "gemini-2.5-pro":        {"max_input_tokens": 1_048_576, "max_output_tokens": 65_536, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"1": None}},
    "gemini-2.5-flash-lite": {"max_input_tokens": 1_048_576, "max_output_tokens": 65_536, "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"1": None}},
    "gemini-2.0-flash":      {"max_input_tokens": 1_048_576, "max_output_tokens": 8_192,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"1": None}},
}

def validate_tables_and_fields(table, fields):

    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: "f"Table '{table}' is not in allowed list — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    
    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not in allowed list for Table '{table}' — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
            exit(1)
    
    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")


