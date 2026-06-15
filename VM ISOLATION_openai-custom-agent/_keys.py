import os

# Gemini API key — read from the environment so it is never committed.
# Set it first:  export GEMINI_API_KEY="your-key"
# Get a key:     https://aistudio.google.com/app/apikey
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
LOG_ANALYTICS_WORKSPACE_ID = "289ad8c8-bf3f-4c11-b5a6-23d4a99e6d2a"
