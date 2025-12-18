import streamlit as st
import pandas as pd
import json
import joblib
import plotly.express as px

# Page config for a nicer look
st.set_page_config(page_title="SOC Alert Triage Pro", layout="wide")

st.title("🚨 SOC Alert Triage Pro")
st.subheader("AI-Powered Prioritization for Microsoft's Modern SOC Workflow")
st.markdown("""
Enhances alert triage by scoring threats with ML—focus on high-impact incidents faster!  
Inspired by Microsoft Sentinel, Defender XDR, and the Modern Security Operations flow.
""")

# Load model and encoders (cached for speed)
@st.cache_resource
def load_model():
    model = joblib.load('models/priority_model.pkl')
    le_severity = joblib.load('models/le_severity.pkl')
    le_source = joblib.load('models/le_source.pkl')
    return model, le_severity, le_source

model, le_severity, le_source = load_model()

# Load alerts (cached)
@st.cache_data
def load_alerts():
    with open('data/mock_alerts.json', 'r') as f:
        return json.load(f)

alerts = load_alerts()
df = pd.DataFrame(alerts)

# Apply encodings and predict priority scores
df['severity_encoded'] = le_severity.transform(df['severity'])
df['source_encoded'] = le_source.transform(df['source'])
X = df[['severity_encoded', 'source_encoded', 'confidence']]
df['priority_score'] = model.predict_proba(X)[:, 1]  # Higher = more urgent

# Sidebar controls
st.sidebar.header("Triage Controls")
priority_threshold = st.sidebar.slider("Minimum Priority Score", 0.0, 1.0, 0.6, 0.05)
show_all = st.sidebar.checkbox("Show All Alerts (Unfiltered)", value=False)

if show_all:
    filtered_df = df.sort_values('priority_score', ascending=False)
else:
    filtered_df = df[df['priority_score'] >= priority_threshold].sort_values('priority_score', ascending=False)

# Main display
st.write(f"**{len(filtered_df)} Prioritized Alerts** (out of {len(df)} total)")
columns_to_show = ['id', 'timestamp', 'severity', 'description', 'entity', 'source', 'confidence', 'priority_score']
st.dataframe(
    filtered_df[columns_to_show].style.format({'priority_score': '{:.2f}', 'confidence': '{:.2f}'}),
    use_container_width=True
)

# Chart
fig = px.bar(
    filtered_df.head(20),
    x='id',
    y='priority_score',
    color='severity',
    title="Top 20 Alert Priority Scores",
    labels={'priority_score': 'AI Priority Score (Higher = More Urgent)'},
    hover_data=['description', 'source']
)
fig.update_layout(showlegend=True)
st.plotly_chart(fig, use_container_width=True)

# Alert Details & Actions
st.header("Alert Details & Actions")
selected_id = st.selectbox("Select an Alert for Details", filtered_df['id'])
selected = filtered_df[filtered_df['id'] == selected_id].iloc[0]

st.write("**Description:**", selected['description'])
st.write("**Entity:**", selected['entity'])
st.write("**Source:**", selected['source'])
st.write("**AI Priority Score:**", f"{selected['priority_score']:.2f}")

if st.button("Enrich with External Threat Intel (Mock)"):
    st.info("Enriched: No known campaigns for this entity. (Production: Integrate VirusTotal/OTX API)")

feedback = st.radio("Mark as False Positive?", ("No", "Yes"))
if st.button("Submit Analyst Feedback"):
    st.success("Feedback recorded! (Production: Retrain model periodically)")