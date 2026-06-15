# Install:
# pip install google-genai

from google import genai
import json
import os

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

prompt = "Give me a very short recipe for a cake please."

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt
)

print(f"\n{json.loads(response.text)}\n")
