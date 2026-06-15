"""
Non-interactive smoke test for the Gemini-ported agent.

Exercises both live Gemini calls WITHOUT Azure:
  1. get_log_query_from_agent()  -> tool-selection JSON (query context)
  2. hunt()                      -> threat-hunt JSON over a built-in synthetic log

Run it (needs GEMINI_API_KEY in your environment):
    cd baseline_agent && python _test_gemini.py
"""
import json
import sys

from google import genai

import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import UTILITIES

if not _keys.GEMINI_API_KEY:
    sys.exit("GEMINI_API_KEY is not set. Run:  export GEMINI_API_KEY=...")

client = genai.Client(api_key=_keys.GEMINI_API_KEY)
model = MODEL_MANAGEMENT.DEFAULT_MODEL

# A tiny synthetic DeviceProcessEvents slice (stands in for the Azure query),
# including one obviously malicious encoded-PowerShell download chain.
SYNTHETIC_LOGS = (
    "TimeGenerated,DeviceName,AccountName,InitiatingProcessCommandLine,ProcessCommandLine\n"
    "2026-06-15T09:01:00Z,edr-andres,irlab14,explorer.exe,\"msedge.exe\" --win-session-start\n"
    "2026-06-15T09:02:00Z,edr-andres,irlab14,services.exe,svchost.exe -k DcomLaunch -p\n"
    "2026-06-15T09:03:27Z,edr-andres,irlab14,\"PowerShell_ISE.exe\",\"cmd.exe\" /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\\ProgramData\\7z.exe; Start-Process 'C:\\ProgramData\\7z.exe' -ArgumentList '/S' -Wait\"\n"
)

QUESTION = "Show me any suspicious PowerShell or LOLBin activity on host edr-andres in the last 24 hours"
user_message = {"role": "user", "content": QUESTION}

print("=" * 60)
print("Q:", QUESTION)
print("=" * 60)

# ---- 1) Gemini tool-selection (structured JSON) -------------------------
print("\n[1] get_log_query_from_agent (Gemini JSON tool selection)...")
ctx = EXECUTOR.get_log_query_from_agent(client, user_message, model=model)
print("Raw query context:")
print(json.dumps(ctx, indent=2))
ctx = UTILITIES.sanitize_query_context(ctx)

# ---- 2) Gemini threat hunt over the synthetic logs ---------------------
print("\n[2] hunt (Gemini JSON threat analysis over synthetic logs)...")
thm = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
    user_prompt=QUESTION,
    table_name=ctx.get("table_name", "DeviceProcessEvents"),
    log_data=SYNTHETIC_LOGS,
)
results = EXECUTOR.hunt(
    gemini_client=client,
    threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=thm,
    gemini_model=model,
)

print("\n===== HUNT RESULTS =====")
print(json.dumps(results, indent=2))

findings = (results or {}).get("findings", [])
print(f"\nOK: Gemini returned {len(findings)} finding(s).")
