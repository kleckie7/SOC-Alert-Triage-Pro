import streamlit as st
import pandas as pd
import json
import joblib
import plotly.express as px
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import random
from datetime import datetime, timedelta

# === Auto-generate mock data if missing ===
data_path = 'data/mock_alerts.json'
if not os.path.exists('data'):
    os.makedirs('data', exist_ok=True)

if not os.path.exists(data_path):
    st.info("First run detected – generating mock alert data...")
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
    sources = [
        "Microsoft Defender for Endpoint",
        "Microsoft Sentinel",
        "Azure AD Identity Protection",
        "Microsoft Defender for Cloud Apps"
    ]
    severities = ["Low", "Medium", "High", "Critical"]

    alerts = []
    for i in range(100):
        timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat()
        alert = {
            "id": f"alert-{i+1:04d}",
            "timestamp": timestamp,
            "severity": random.choice(severities),
            "description": random.choice(descriptions),
            "entity": random.choice([f"user{random.randint(100,999)}@contoso.com", f"device-{random.randint(1,50)}"]),
            "source": random.choice(sources),
            "confidence": round(random.uniform(0.2, 0.98), 2),
            "historical_false_positive": random.choice([True, False, False])
        }
        alerts.append(alert)

    with open(data_path, 'w') as f:
        json.dump(alerts, f, indent=2)

# === Auto-train model if missing ===
if not os.path.exists('models'):
    os.makedirs('models', exist_ok=True)

model_path = 'models/priority_model.pkl'
if not os.path.exists(model_path):
    st.info("Training ML prioritization model (this happens once)...")
    with open(data_path, 'r') as f:
        data = json.load(f)
    df = pd.DataFrame(data)

    le_severity = LabelEncoder()
    df['severity_encoded'] = le_severity.fit_transform(df['severity'])
    le_source = LabelEncoder()
    df['source_encoded'] = le_source.fit_transform(df['source'])

    df['priority'] = df.apply(
        lambda row: 1 if (row['severity'] in ['Critical', 'High']
                          and row['confidence'] > 0.7
                          and not row['historical_false_positive']) else 0,
        axis=1
    )

    X = df[['severity_encoded', 'source_encoded', 'confidence']]
    y = df['priority']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    joblib.dump(model, model_path)
    joblib.dump(le_severity, 'models/le_severity.pkl')
    joblib.dump(le_source, 'models/le_source.pkl')
    st.success("Model trained and saved!")

# === Dashboard UI ===
st.set_page_config(page_title="SOC Alert Triage Pro", layout="wide")
st.title("🚨 SOC Alert Triage Pro")
st.subheader("AI-Powered Prioritization for Microsoft's Modern SOC Workflow")
st.markdown("""
Enhances alert triage by scoring threats with ML—focus on high-impact incidents faster!  
Inspired by Microsoft Sentinel, Defender XDR, and the Modern Security Operations flow.
""")

# Load model
@st.cache_resource
def load_model():
    model = joblib.load('models/priority_model.pkl')
    le_severity = joblib.load('models/le_severity.pkl')
    le_source = joblib.load('models/le_source.pkl')
    return model, le_severity, le_source

model, le_severity, le_source = load_model()

# Load alerts
@st.cache_data
def load_alerts():
    with open('data/mock_alerts.json',