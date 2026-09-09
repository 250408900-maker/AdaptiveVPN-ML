from pathlib import Path
import subprocess

import pandas as pd
import streamlit as st

import adaptive_selector
import monitor
import vpn_controller


DATA_FILE = Path("network_data.csv")

st.set_page_config(
    page_title="AdaptiveVPN-ML",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AdaptiveVPN-ML")
st.caption("AI-assisted VPN monitoring and adaptive protocol selection")

try:
    detected_protocol, detection_message = monitor.detect_protocol_state()
except Exception as error:
    detected_protocol = "Unknown"
    detection_message = str(error)

status_col, protocol_col, records_col = st.columns(3)

status_col.metric("System Status", "Online")
protocol_col.metric("Detected Protocol", str(detected_protocol).upper())

if DATA_FILE.exists():
    data = pd.read_csv(DATA_FILE)
    records_col.metric("Measurements", len(data))
else:
    data = pd.DataFrame()
    records_col.metric("Measurements", 0)

st.info(detection_message)

st.subheader("🤖 ML Protocol Recommendation")

if st.button("Generate Recommendation", type="primary"):
    try:
        protocol, scores, explanation = adaptive_selector.recommend_protocol(
    "network_data.csv",
    "model/adaptive_selector_state.json",

        )
        st.session_state["recommended_protocol"] = protocol
        st.success(f"Recommended protocol: {str(protocol).upper()}")
        st.write(explanation)

        if scores:
            st.json(scores)
    except Exception as error:
        st.error(f"Recommendation failed: {error}")

recommended = st.session_state.get("recommended_protocol")

if recommended:
    if st.button(f"Activate {str(recommended).upper()}"):
        try:
            success, message = vpn_controller.activate_protocol(recommended)

            if success:
                st.success(message)
            else:
                st.warning(message)
        except Exception as error:
            st.error(f"Controller failed: {error}")

st.subheader("📊 Network Measurements")

if data.empty:
    st.warning("No network measurements are available yet.")
else:
    st.dataframe(data.tail(20), use_container_width=True)

    numeric_columns = data.select_dtypes(include="number").columns.tolist()

    if numeric_columns:
        selected_metric = st.selectbox("Chart metric", numeric_columns)
        st.line_chart(data[selected_metric])

st.subheader("📄 ML Report")

if st.button("Generate Final Report"):
    result = subprocess.run(
        ["python", "generate_ml_report.py"],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        st.success("ML report generated successfully.")
        st.code(result.stdout or "Report files updated.")
    else:
        st.error(result.stderr or result.stdout)

if st.button("Refresh Dashboard"):
    st.rerun()