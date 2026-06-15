"""
Pulls logs from your Log Analytics workspace and exposes them as
`security_logs` for the Gemini SOC analyst in token_opt.py.

Re-uses log_analytics_function.py, which queries the table set by TABLE_NAME
and builds a CSV string named `records`. Change TABLE_NAME there to switch
which log source the analyst reviews.
"""
from log_analytics_function import records as security_logs
