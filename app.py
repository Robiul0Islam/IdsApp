import streamlit as st
import pandas as pd
import joblib
import json

# Load model and preprocessing objects
model = joblib.load('trained_model.pkl')
scaler = joblib.load('scaler.pkl')
training_columns = joblib.load('training_columns.pkl')

# Load best threshold if exists, else default to 0.5
try:
    with open('best_threshold.json', 'r') as f:
        best_threshold = json.load(f)["best_threshold"]
except:
    best_threshold = 0.5

st.title("Local Wi-Fi Network Intrusion Detection")

threshold = st.slider(
    "Adjust detection threshold",
    min_value=0.0,
    max_value=1.0,
    value=best_threshold,
    step=0.01,
    help="Lower threshold detects more attacks; higher threshold reduces false alarms."
)

uploaded_file = st.file_uploader("Upload your network traffic CSV file", type=["csv"])

if uploaded_file:
    data = pd.read_csv(uploaded_file)

    st.write("### Raw data preview:")
    st.dataframe(data.head())

    for col in training_columns:
        if col not in data.columns:
            data[col] = 0
    data = data[training_columns]

    scaled_data = scaler.transform(data)

    probabilities = model.predict_proba(scaled_data)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    normal_count = sum(predictions == 0)
    attack_count = sum(predictions == 1)
    total = normal_count + attack_count
    safe_percentage = (normal_count / total) * 100 if total > 0 else 0
    attack_ratio = attack_count / total if total > 0 else 0

    st.write(f"Normal packets detected: {normal_count}")
    st.write(f"Attack packets detected: {attack_count}")
    st.write(f"Safe traffic percentage: {safe_percentage:.2f}%")

    if attack_ratio <= 0.10:
        status = "✅ Network is SAFE"
    elif attack_ratio <= 0.30:
        status = "⚠️ Network is LOW RISK"
    elif attack_ratio <= 0.50:
        status = "⚠️ Network is MEDIUM RISK"
    else:
        status = "🚨 Network is HIGH RISK - Immediate action recommended"

    st.markdown(f"## Connection Status: {status}")

    pred_counts = pd.DataFrame({'Prediction': ['Attack', 'Normal'], 'Count': [attack_count, normal_count]})
    st.write(pred_counts)
