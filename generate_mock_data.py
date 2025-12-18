import json
import random
from datetime import datetime, timedelta

# More realistic descriptions and variety
descriptions = [
    "Suspicious login from unfamiliar location",
    "Potential malware execution detected",
    "Unusual data exfiltration to external IP",
    "Privileged account modification",
    "Phishing email with malicious link clicked",
    "Lateral movement indicators",
    "Brute force attempt on account",
    "Benign software update (known false positive)"
]

sources = ["Microsoft Defender for Endpoint", "Microsoft Sentinel", "Azure AD Identity Protection", "Microsoft Defender for Cloud Apps"]

severities = ["Low", "Medium", "High", "Critical"]

alerts = []

for i in range(100):  # 100 alerts for better variety
    timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat()
    alert = {
        "id": f"alert-{i+1:04d}",
        "timestamp": timestamp,
        "severity": random.choice(severities),
        "description": random.choice(descriptions),
        "entity": random.choice([f"user{random.randint(100,999)}@contoso.com", f"device-{random.randint(1,50)}"]),
        "source": random.choice(sources),
        "confidence": round(random.uniform(0.2, 0.98), 2),
        "historical_false_positive": random.choice([True, False, False])  # Bias toward real threats
    }
    alerts.append(alert)

# Save to file
with open('data/mock_alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2)

print("Generated 100 mock alerts in data/mock_alerts.json!")