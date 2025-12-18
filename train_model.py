import pandas as pd
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Force create the models folder
os.makedirs('models', exist_ok=True)
print("Models folder ready/created.")

# Load the mock alerts
try:
    with open('data/mock_alerts.json', 'r') as f:
        data = json.load(f)
    print(f"Loaded {len(data)} mock alerts from data/mock_alerts.json")
except FileNotFoundError:
    print("Error: data/mock_alerts.json not found! Run generate_mock_data.py first.")
    exit()

df = pd.DataFrame(data)

# Feature encoding
le_severity = LabelEncoder()
df['severity_encoded'] = le_severity.fit_transform(df['severity'])

le_source = LabelEncoder()
df['source_encoded'] = le_source.fit_transform(df['source'])

# Create priority label (high priority if Critical/High + high confidence + not historical FP)
df['priority'] = df.apply(
    lambda row: 1 if (row['severity'] in ['Critical', 'High'] 
                      and row['confidence'] > 0.7 
                      and not row['historical_false_positive']) else 0,
    axis=1
)

# Features and training
X = df[['severity_encoded', 'source_encoded', 'confidence']]
y = df['priority']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Save model and encoders
joblib.dump(model, 'models/priority_model.pkl')
joblib.dump(le_severity, 'models/le_severity.pkl')
joblib.dump(le_source, 'models/le_source.pkl')

accuracy = model.score(X_test, y_test)
print(f"\nAI Model Trained Successfully!")
print(f"Test Accuracy: {accuracy:.2f}")
print("Saved files:")
print("  - models/priority_model.pkl")
print("  - models/le_severity.pkl")
print("  - models/le_source.pkl")