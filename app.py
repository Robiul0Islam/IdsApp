import streamlit as st
import pandas as pd
import joblib

model = joblib.load('trained_model.pkl')
scaler = joblib.load('scaler.pkl')
training_columns = joblib.load('training_columns.pkl')

st.title("Local Wi-Fi Network Intrusion Detection")

threshold = st.slider(
    label="Adjust detection threshold",
    min_value=0.0,
    max_value=1.0,
    value=0.5,
    step=0.01,
    help="Lower threshold detects more attacks (higher false positives), higher threshold is stricter."
)

uploaded_file = st.file_uploader("Upload your network traffic CSV file", type=["csv"])

if uploaded_file:
    data = pd.read_csv(uploaded_file)
    st.write("Raw data preview:")
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

    st.write(f"Normal packets detected: {normal_count}")
    st.write(f"Attack packets detected: {attack_count}")

    if safe_percentage > 80:
        status_msg = "✅ Your network is SAFE"
    elif safe_percentage > 50:
        status_msg = "⚠️ Your network is RISKY"
    else:
        status_msg = "🚨 Your network is AT HIGH RISK"

    st.markdown(f"## Network Status: {status_msg}")
    st.markdown(f"## Safe Traffic Percentage: {safe_percentage:.2f}%")

    pred_counts = pd.DataFrame({'Prediction': ['Attack', 'Normal'], 'Count': [attack_count, normal_count]})
    st.write(pred_counts)
