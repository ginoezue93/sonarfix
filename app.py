import requests
import json

SONAR_URL = "http://localhost:9000"
TOKEN = "DEIN_TOKEN"
PROJECT_KEY = "sard_cases"

response = requests.get(
    f"{SONAR_URL}/api/issues/search",
    params={"componentKeys": PROJECT_KEY, "ps": 500},
    auth=(TOKEN, "")
)

data = response.json()

with open("sonar_report.json", "w") as f:
    json.dump(data, f, indent=2)

print("Report gespeichert!")