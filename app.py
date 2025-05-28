import streamlit as st
import pandas as pd
import joblib

# Load your pre-trained model, scaler, and feature columns
model = joblib.load('trained_model.pkl')
scaler = joblib.load('scaler.pkl')
training_columns = joblib.load('training_columns.pkl')

st.title("Local Wi-Fi Network Intrusion Detection")

uploaded_file = st.file_uploader("Upload your network traffic CSV file", type=["csv"])

if uploaded_file:
    # Read uploaded CSV file
    data = pd.read_csv(uploaded_file)

    st.write("### Raw data preview:")
    st.dataframe(data.head())

    # Preprocess uploaded data to match model's expected features
    for col in training_columns:
        if col not in data.columns:
            data[col] = 0

    data = data[training_columns]

    # Scale features
    scaled_data = scaler.transform(data)

    # Predict
    predictions = model.predict(scaled_data)
    data['Prediction'] = predictions

    # Summarize predictions
    normal_count = sum(predictions == 0)
    attack_count = sum(predictions == 1)
    total = normal_count + attack_count
    safe_percentage = (normal_count / total) * 100 if total > 0 else 0

    st.write(f"Normal packets detected: {normal_count}")
    st.write(f"Attack packets detected: {attack_count}")

    # Determine network status based on safe traffic percentage
    if safe_percentage > 80:
        status_msg = "✅ Your network is SAFE"
    elif safe_percentage > 50:
        status_msg = "⚠️ Your network is RISKY"
    else:
        status_msg = "🚨 Your network is AT HIGH RISK"

    st.markdown(f"## Network Status: {status_msg}")
    st.markdown(f"## Safe Traffic Percentage: {safe_percentage:.2f}%")

    # Optionally show prediction counts table
    pred_counts = pd.DataFrame({'Prediction': ['Attack', 'Normal'], 'Count': [attack_count, normal_count]})
    st.write(pred_counts)
