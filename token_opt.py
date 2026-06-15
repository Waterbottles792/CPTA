from google import genai
from colorama import init, Fore, Style
import os
import logsshort as logs

init(autoreset=True)

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

MODEL = "gemini-2.5-flash"

# Update these based on current Gemini pricing if needed
COST_PER_MILLION_INPUT = 0.30
COST_PER_MILLION_OUTPUT = 2.50

MAX_OUTPUT_TOKENS = 4000

prompt = f"""
You are a senior SOC analyst and threat hunter.

Review the following logs and identify:

1. Indicators of Compromise
2. Suspicious PowerShell activity
3. LOLBins
4. Persistence mechanisms
5. MITRE ATT&CK techniques
6. Severity
7. Recommended actions

Logs:

{logs.security_logs}
"""

# Count input tokens before sending
token_info = client.models.count_tokens(
    model=MODEL,
    contents=prompt
)

estimated_input_tokens = token_info.total_tokens

estimated_input_cost = (
    estimated_input_tokens / 1_000_000
) * COST_PER_MILLION_INPUT

estimated_output_cost = (
    MAX_OUTPUT_TOKENS / 1_000_000
) * COST_PER_MILLION_OUTPUT

estimated_total_cost = (
    estimated_input_cost +
    estimated_output_cost
)

choice = input(
    f"\nEstimated Input Tokens : {estimated_input_tokens}\n"
    f"Estimated Cost         : ${estimated_total_cost:.6f}\n"
    "Proceed? (y/n): "
).lower()

if choice != "y":
    print("Aborted.")
    exit()

response = client.models.generate_content(
    model=MODEL,
    contents=prompt
)

print("\n===== THREAT HUNT RESULTS =====\n")
print(response.text)

# Usage Metadata
if hasattr(response, "usage_metadata"):

    usage = response.usage_metadata

    prompt_tokens = usage.prompt_token_count
    completion_tokens = usage.candidates_token_count
    total_tokens = usage.total_token_count

    actual_input_cost = (
        prompt_tokens / 1_000_000
    ) * COST_PER_MILLION_INPUT

    actual_output_cost = (
        completion_tokens / 1_000_000
    ) * COST_PER_MILLION_OUTPUT

    actual_total_cost = (
        actual_input_cost +
        actual_output_cost
    )

    print("\n===== TOKEN USAGE =====")

    print(
        f"Prompt Tokens     : {prompt_tokens}"
    )

    print(
        f"Response Tokens   : {completion_tokens}"
    )

    print(
        f"Total Tokens      : {total_tokens}"
    )

    print(
        f"Estimated Cost    : ${estimated_total_cost:.6f}"
    )

    print(
        f"Actual Cost       : ${actual_total_cost:.6f}"
    )

print("\nfin.")
