import os

# Gemini API key — read from the environment so it is never committed.
# Set it first:  export GEMINI_API_KEY="your-key"
# Get a key:     https://aistudio.google.com/app/apikey
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# https://portal.azure.com/#@lognpacific.com/resource/subscriptions/3c95e63a-895a-4386-991e-edbbf57de5c8/resourceGroups/Cyber-Range-Admin-SOC/providers/Microsoft.OperationalInsights/workspaces/LAW-Cyber-Range/Overview
LOG_ANALYTICS_WORKSPACE_ID = "60c7f53e-249a-4077-b68e-55a4ae877d7c"
