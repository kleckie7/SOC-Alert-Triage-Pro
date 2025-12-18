# SOC-Alert-Triage-Pro

AI-Powered Alert Triage Dashboard – Enhances Microsoft's Modern Security Operations Workflow

Reduces SOC analyst fatigue by using ML to prioritize alerts from raw data/detections. Inspired by Microsoft Sentinel, Defender XDR, and the official SOC flowchart.

## Features
- Machine Learning prioritization (Random Forest)
- Interactive filters, table, Plotly charts
- Mock enrichment & feedback loop
- CSV export for case management

## Live Demo
[Your Streamlit URL here after deployment]

## Setup & Run Locally
```bash
git clone https://github.com/YOURUSERNAME/SOC-Alert-Triage-Pro.git
cd SOC-Alert-Triage-Pro
python3 -m venv myenv
source myenv/bin/activate  # On Mac/Linux
pip install -r requirements.txt
python generate_mock_data.py
python train_model.py
streamlit run app.py