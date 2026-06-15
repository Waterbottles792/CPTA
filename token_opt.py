from google import genai
from colorama import init, Fore, Style
import os
import logsshort as logs

init(autoreset=True)

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

MODEL = "gemini-2.5-flash"

prompt = f"""
You are a senior SOC analyst.

Analyze the following logs for:
- Indicators of compromise
- Suspicious activity
- MITRE ATT&CK techniques
- Severity
- Recommended actions

Logs:

{logs.security_logs}
"""

# Count tokens BEFORE sending
token_info = client.models.count_tokens(
    model=MODEL,
    contents=prompt
)

estimated_input_tokens = token_info.total_tokens

print(f"Estimated Input Tokens: {estimated_input_tokens}")

choice = input("Continue? (y/n): ").lower()

if choice != "y":
    exit()

response = client.models.generate_content(
    model=MODEL,
    contents=prompt
)

print("\n===== ANALYSIS =====\n")
print(response.text)

# Usage metadata
if hasattr(response, "usage_metadata"):
    usage = response.usage_metadata

    print("\n===== TOKEN USAGE =====")
    print(f"Prompt Tokens: {usage.prompt_token_count}")
    print(f"Response Tokens: {usage.candidates_token_count}")
    print(f"Total Tokens: {usage.total_token_count}")