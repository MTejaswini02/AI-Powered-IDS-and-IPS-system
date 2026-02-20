import streamlit as st
import pandas as pd
import joblib
import numpy as np
import plotly.express as px

# ✅ Page settings
st.set_page_config(page_title="AI IDS Dashboard", layout="wide")

# ✅ Custom CSS Styling
st.markdown("""
    <style>
        .main {
            background-color: #0f172a;
            color: white;
        }
        .stButton>button {
            width: 200px;
            background-color: #3b82f6;
            color: white;
            border-radius: 8px;
            height: 45px;
            border: none;
            font-size: 16px;
        }
        .title {
            font-size: 32px;
            font-weight: bold;
            color: #38bdf8;
        }
        .subtitle {
            font-size: 18px;
            color: #a5f3fc;
        }
    </style>
""", unsafe_allow_html=True)

# ✅ Load trained model and scaler
model = joblib.load("ids_model.pkl")
scaler = joblib.load("scaler.pkl")

# ✅ Header
st.markdown('<h1 class="title">🚨 AI-Powered Intrusion Detection System</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Real-time Attack Classification Dashboard</p>', unsafe_allow_html=True)
st.write("---")

# ✅ Upload CSV
uploaded_file = st.file_uploader("📌 Upload Network Traffic CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Check if label exists
    if "Label" in df.columns:
        X = df.drop("Label", axis=1)
    else:
        X = df

    # ✅ Transform using trained scaler
    X_scaled = scaler.transform(X)

    # ✅ Predictions
    predictions = model.predict(X_scaled)
    df["Prediction"] = predictions

    label_map = {0: "DoS", 1: "Probe", 2: "R2L", 3: "U2R"}
    df["Attack Type"] = df["Prediction"].map(label_map)

    st.success("✅ Prediction Completed Successfully!")
    st.write("---")

    # ✅ Tabs for better UX
    tab1, tab2, tab3 = st.tabs(["📊 Graph View", "📋 Table View", "📌 Summary"])

    with tab1:
        attack_counts = df["Attack Type"].value_counts()
        fig = px.bar(
            attack_counts,
            title="Attack Type Distribution",
            text_auto=True,
            color=attack_counts.index,
            color_discrete_sequence=px.colors.qualitative.Vivid
        )
        st.plotly_chart(fig, config={"displayModeBar": False})


    with tab2:
        st.dataframe(df, width='stretch')

    with tab3:
        st.metric("🛑 Total Attacks Detected", len(df))
        st.metric("🚨 Unique Attack Types", df["Attack Type"].nunique())

        for attack_name in df["Attack Type"].unique():
            st.write(f"✅ {attack_name}: {df[df['Attack Type'] == attack_name].shape[0]}")

    st.write("---")
    st.subheader("⚙️ Extra Options")

    # ✅ Attack Filter
    attack_types = df["Attack Type"].unique()
    selected = st.multiselect("🔍 Filter by Attack Type", attack_types, default=list(attack_types))
    filtered_df = df[df["Attack Type"].isin(selected)]

    st.write(f"📌 Showing {len(filtered_df)} Selected Records")
    st.dataframe(filtered_df, width='stretch')

    # ✅ Download CSV Output
    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download Results CSV",
        data=csv_data,
        file_name="Attack_Detection_Results.csv",
        mime="text/csv"
    )

    st.write("---")
    st.subheader("🚨 Threat Assessment")

    # ✅ Threat level logic
    if "DoS" in filtered_df["Attack Type"].values:
        st.error("🛑 HIGH THREAT: DoS Attacks Detected")
    elif "U2R" in filtered_df["Attack Type"].values:
        st.warning("⚠️ MEDIUM THREAT: U2R Exploits Attempted")
    else:
        st.success("✅ LOW THREAT: No Critical Attacks Detected")

else:
    st.info("📂 Please upload a CSV file to analyze attacks!")

st.write("---")
st.caption("🔐 Secure ML System | Random Forest | NSL-KDD Inspired Dataset")




# ================= IDS → IPS PREVENTION (Same Uploaded File) =================

from backend.stream_processor import stream_csv

st.write("---")
st.subheader("🛡️ Intrusion Prevention System")

if 'uploaded_file' in locals() and uploaded_file is not None:

    if st.button("Start Prevention"):

        st.info("IPS Active — Monitoring traffic...")

        blocked_count = 0
        allowed_count = 0
        total_events = 0

        # Status panel placeholders
        status_panel = st.empty()
        event_panel = st.empty()
        message_box = st.empty()

        # Save uploaded file
        temp_path = "temp_stream.csv"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        blocked_count = 0
        allowed_count = 0
        total_events = 0

        attack_counts = {"DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
        pie_chart_box = st.empty()

        for result in stream_csv(temp_path, delay=0.2):

            attack = result["attack"]
            action = result["action"]
            total_events += 1

            if action == "BLOCKED":
                blocked_count += 1
                message_box.error(f"🚫 BLOCKED → {attack}")
            else:
                allowed_count += 1
                message_box.success(f"✅ ALLOWED → {attack}")

            # System status panel
            status_panel.info(
                f"IPS Status: ACTIVE | Last Attack: {attack}"
            )

            # Counters
            event_panel.write(
                f"Total Events: {total_events} | Blocked: {blocked_count} | Allowed: {allowed_count}"
            )
            # Update attack distribution
            if attack in attack_counts:
                attack_counts[attack] += 1

            # Draw live pie chart
            fig = px.pie(
                names=list(attack_counts.keys()),
                values=list(attack_counts.values()),
                title="Live Attack Distribution",
                 hole=0.4  # makes donut-style chart (professional look)
            )


            pie_chart_box.plotly_chart(
                fig,
                config={"displayModeBar": False}
            )

# ================= REAL-TIME LIVE NETWORK MODE =================

from backend.live_capture import live_packet_stream

st.write("---")
st.subheader("🌐 Real-Time Live Network Monitoring")
st.caption("Capture live packets from your system → Detect → Prevent")

# -------- Live control state --------
if "live_running" not in st.session_state:
    st.session_state.live_running = False

# -------- Start / Stop buttons --------
col1, col2 = st.columns(2)

if col1.button("Start Live Monitoring"):
    st.session_state.live_running = True

if col2.button("Stop Live Monitoring"):
    st.session_state.live_running = False


# -------- Live Monitoring --------
if st.session_state.live_running:

    st.info("Capturing live network traffic...")

    blocked_count = 0
    allowed_count = 0
    total_events = 0

    if "live_timeline" not in st.session_state:
        st.session_state.live_timeline = []

    live_chart_box = st.empty()
    live_status = st.empty()
    live_counter = st.empty()

    for result in live_packet_stream(packet_count=10):

        # Stop immediately if Stop button pressed
        if not st.session_state.live_running:
            break

        attack = result["attack"]
        action = result["action"]
        total_events += 1

        if action == "BLOCKED":
            blocked_count += 1
            live_status.error(f"🚫 BLOCKED → {attack}")
        else:
            allowed_count += 1
            live_status.success(f"✅ ALLOWED → {attack}")

        live_counter.info(
            f"Live Events: {total_events} | Blocked: {blocked_count} | Allowed: {allowed_count}"
        )

        # -------- Live Graph --------
        st.session_state.live_timeline.append({
            "event": total_events,
            "blocked": blocked_count,
            "allowed": allowed_count
        })

        timeline_df = pd.DataFrame(st.session_state.live_timeline)

        fig_live = px.line(
            timeline_df,
            x="event",
            y=["blocked", "allowed"],
            title="Live Network Activity"
        )

        live_chart_box.plotly_chart(fig_live, config={"displayModeBar": False})
# Show last graph even after stopping
if not st.session_state.live_running and "live_timeline" in st.session_state:
    if len(st.session_state.live_timeline) > 0:
        timeline_df = pd.DataFrame(st.session_state.live_timeline)

        fig_live = px.line(
            timeline_df,
            x="event",
            y=["blocked", "allowed"],
            title="Live Network Activity (Last Session)"
        )

        st.plotly_chart(fig_live, config={"displayModeBar": False})
