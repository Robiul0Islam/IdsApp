import streamlit as st
import pandas as pd
import joblib

# Load model artifacts
model = joblib.load('trained_model.pkl')
scaler = joblib.load('scaler.pkl')
training_columns = joblib.load('training_columns.pkl')

st.title("Local Wi-Fi Network Intrusion Detection")

# Packet-level threshold slider
threshold = st.slider(
    label="Adjust packet-level detection threshold",
    min_value=0.0,
    max_value=1.0,
    value=0.5,
    step=0.01,
    help="Lower threshold detects more attacks (higher false positives), higher threshold is stricter."
)

uploaded_file = st.file_uploader("Upload your network traffic CSV file", type=["csv"])

if uploaded_file:
    data = pd.read_csv(uploaded_file)

    st.write("### Raw data preview:")
    st.dataframe(data.head())

    # Align columns to training features
    for col in training_columns:
        if col not in data.columns:
            data[col] = 0
    data = data[training_columns]

    # Scale data
    scaled_data = scaler.transform(data)

    # Get predicted attack probabilities per packet
    probabilities = model.predict_proba(scaled_data)[:, 1]

    # Apply packet-level threshold to classify packets
    predictions = (probabilities >= threshold).astype(int)

    # Count packets per class
    normal_count = sum(predictions == 0)
    attack_count = sum(predictions == 1)
    total = normal_count + attack_count
    attack_ratio = attack_count / total if total > 0 else 0

    # Display packet counts and safe percentage
    safe_percentage = (normal_count / total) * 100 if total > 0 else 0
    st.write(f"Normal packets detected: {normal_count}")
    st.write(f"Attack packets detected: {attack_count}")
    st.write(f"Safe traffic percentage: {safe_percentage:.2f}%")

    # Connection-level risk status based on attack_ratio thresholds
    if attack_ratio <= 0.10:
        status = "✅ Network is SAFE"
    elif attack_ratio <= 0.30:
        status = "⚠️ Network is LOW RISK"
    elif attack_ratio <= 0.50:
        status = "⚠️ Network is MEDIUM RISK"
    else:
        status = "🚨 Network is HIGH RISK - Immediate action recommended"

    st.markdown(f"## Connection Status: {status}")

    # Optional: Show prediction counts table
    pred_counts = pd.DataFrame({'Prediction': ['Attack', 'Normal'], 'Count': [attack_count, normal_count]})
    st.write(pred_counts)
